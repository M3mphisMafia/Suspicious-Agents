# AWS edge shield

```
          agent / attacker                              human user
                 |                                          |
                 v                                          v
     +-------------------- CloudFront ----------------------------+
     |  WAF: flagged IP/JA4 -> 429 Retry-After 9 (edge, $0 origin) |
     |       auth host-wide rate -> 429                             |
     |       decoy prefix -> label aa-ai:decoy                      |
     |       recon map reads -> label aa-ai:recon                   |
     +------+------------------------------+------------------------+
            | decoy prefix                 | everything else (+ JA4 header)
            v                              v
     S3 decoy bucket (OAC)          origin: ALB / API + aa_ai.Shield middleware
     empty pages, canaries          tarpit, masked errors, host-wide auth budget
            |                              |
            +------> WAF logs (CW Logs aws-waf-logs-aa-ai) <----+
                               |
                               v
                 scorer Lambda (aa_ai detectors)  ->  update FlaggedIps / FlaggedJa4
```

Template: [`infra/edge-shield.yaml`](../infra/edge-shield.yaml), deployed in **us-east-1**
(CloudFront WAF scope). The pipeline (`infra/pipeline.yaml`) deploys it as the stack `undertow-edge`.

## Go-live checklist

Each item below was a blocker found in review. The template and code now handle them, but
the items marked **you** live outside this stack.

1. **Custom domain.** Pass `DomainName` and an `AcmCertificateArn` in us-east-1. Without them the
   distribution answers only on `*.cloudfront.net`. The viewer `Host` header is forwarded,
   so **the origin's TLS certificate must also cover `DomainName`**.
2. **Origin lock (you).** CloudFront sends `X-Origin-Verify: <OriginVerifySecret>`. On the ALB:
   - a listener rule that forwards only when that header matches, with the default action
     a fixed 403 (ALB health checks are unaffected; they don't pass through listener rules);
   - a security group that admits only the `com.amazonaws.global.cloudfront.origin-facing`
     managed prefix list.

   In-app fallback: `Shield(app, origin_secret=...)` returns 403 without the header, except
   on `origin_exempt_paths` (default `/health`).
3. **Offices and VPNs behind one IP.**
   - The WAF login limit defaults to **100/min per IP** across all login routes.
   - The in-app budget is spent **only by failed** logins (401/403/422/429), so successful
     logins from a shared NAT never trip it.
   - Known offices, VPN egress, monitors and partners go in `AllowCidrs`. That feeds the
     `allow-list` rule, which is evaluated **before every other rule** and skips them all.
4. **Login-route matching.** Whole path segments only (`aa_ai.events.AUTH_REGEX`, mirrored
   byte-for-byte in WAF and enforced by a test). `/api/tokens` and `/cash-register` are not
   login routes.
5. **Real client IP behind proxies.** `Shield` trusts `CloudFront-Viewer-Address` only when the
   origin secret verified. Otherwise it uses the `X-Forwarded-For` entry `proxy_hops` from the
   right (1 = ALB). A spoofed CloudFront header on a direct hit can't choose an identity.
6. **Memory.** Idle actors are swept every 1,000 requests; at most `max_actors` (50k) are kept.
7. **No double responses.** A shield error before the app runs passes through; after the app
   starts answering, it is re-raised.
8. **Non-Python apps (you).** `Shield` is ASGI. For Java/Spring apps, only the edge layer (WAF
   + scorer) applies until a servlet-filter port exists.

## Dashboard

`https://<your domain>/_undertow/index.html` (stack output `DashboardUrl`).

- **Feed:** every minute the tick writes `data-1.json`, `data-6.json` and `data-24.json`
  into the private dashboard bucket. The page reloads them every minute and shows **Live**,
  or **Live · stale** if the newest file is over 5 minutes old.
- **Access:** the files include attacker IPs and the allow list. The `dashboard-admin-only`
  WAF rule runs before the allow list and answers **404** to anyone outside `AdminCidrs`. The
  default lets nobody in. This is an IP gate, not a login; put SSO in front if the dashboard
  goes beyond a fixed admin network.
- **Its own traffic is never scored:** the scorer skips `/_undertow/`.
- **Read-only:** Unblock copies the `aa_ai unblock` command, to run with your AWS credentials.
- **Publish the page:** the pipeline's Publish stage uploads it on every deploy.

What the numbers mean in live mode:

| Panel | Source |
| --- | --- |
| Requests inspected | WAF log records scored in the window (allow-listed and dashboard traffic excluded) |
| Agents flagged / ladder | Active `FLAG` items by verdict; watch = actors at 0.30–0.50 in the last hour |
| Allow (ladder) | **Approximate**: actors seen per log batch, summed per hour, minus the flagged |
| Attacker time burned | 429s sent × 9 s (the `Retry-After` its throttler honors). A floor, not an estimate of tarpit time |
| Decoy hits | Requests labeled `aa-ai:decoy` or under `DecoyPrefix`, kept 7 days |
| Detector accuracy | Detectors on each new flag (`fired`) vs. those on flags later unblocked (`fp`) |
| How they approach | Phase sequence from each top agent's last 6h of events |

## Unblocking a false positive

```bash
python -m aa_ai unblock 198.51.100.7 --stack aa-ai-edge-shield --ttl-hours 24 --reason "partner scanner"
```

This adds an `ALLOW` entry with a TTL, so the address isn't re-flagged during that window. It
also deletes every flag that includes the address, records each as a `LABEL` false positive
(with the signals that fired, for tuning), and rebuilds the WAF sets right away; allow lists are
written first. It works in observe mode too. For a permanent exemption, add the range to
`AllowCidrs`. In-app: `shield.unblock(ip)`.

## Why the edge

- The 429 + `Retry-After: 9` answer runs inside WAF, so the origin never sees the request and
  ARTEX's own governor pauses itself (see `using-its-design-against-it.md`).
- CloudFront supplies `CloudFront-Viewer-JA4-Fingerprint`, which is forwarded to the origin.
  It sharpens the actor key but is never used alone (see the scorer guardrails below).
- Lock the origin to CloudFront only (checklist item 2), or the agent simply skips the shield.

## S3 buckets as a decoy surface

The decoy bucket serves the unlinked decoy routes. Populate it with `python -m aa_ai decoys`,
which writes the files and prints canary credentials to `CANARIES.txt`. Merge the robots.txt and
OpenAPI fragments into the real ones, so the agent finds the decoys where it looks for its map.
Any hit is labeled `aa-ai:decoy` and counts as a certain detection.

## The buffer: take away its fast feedback loop

ARTEX checks every write by reading it back seconds later (`write_then_verify`) and corrects
itself from 422 detail. A buffered write path breaks both:

1. API Gateway (or the app) accepts state-changing calls into **SQS** and returns `202` with a
   ticket ID. No validation detail goes back synchronously.
2. A worker applies the write after a delay. Flagged actors get a longer delay, or are silently
   dropped to a quarantine queue for review.
3. Results are available only via the ticket, so the read-back loop gets nothing it can use for
   seconds to minutes, which runs into the agent's step and wall-clock budgets.

Real users barely notice async writes for most flows (profile, settings, uploads). Keep auth and
payment flows synchronous and protect them with the host-wide auth budget instead.

## Scorer Lambda (`aa_ai/scorer.py`)

Two functions from the same code package:

- **`ScorerFunction`** (`aa_ai.scorer.handler`, reserved concurrency 30): CloudWatch Logs
  subscriptions on `aws-waf-logs-aa-ai` and on the app's, the cell's and the verdict API's move
  lines. It stores events, rescores actors and, outside a surge, syncs the WAF sets and the cell
  right away so a confirmed agent is stopped within seconds.
- **`TickFunction`** (`aa_ai.scorer.tick_handler`, reserved concurrency 2, its own role and log
  group): the 1-minute `{"action":"snapshot"}` schedule. Flood mode, the authoritative WAF sync,
  auto-tune, the cost sample (at most hourly), the dashboard files, anomalies and the canary check.
  A tick that is throttled or fails is dropped, never queued behind the next one. It runs apart
  because in the first live flood test the log batches held all 30 slots of a shared function and
  the tick never ran, so flood mode never saw the surge.
- **Under load** the log batches are bounded by distinct sources, not requests:
  - while a surge is active, a source past `per_ip_rpm` this minute (across batches, from its
    `RATE` counter, or within the batch by request time) is counted in the stats and the per-IP rate
    but its further requests are neither stored nor rescored; flood mode judges it from the counters
    at the tick. Decoy and honey hits are always kept (up to 5 per source per batch). Outside a
    surge every request is scored: agents run at machine speed, far past `per_ip_rpm`, and the
    second live test showed a cap outside surges left them stuck at Watch;
  - while a surge is active, at most 50 actors are rescored per batch (decoy hits first, then the
    busiest) with at most 200 events read each, and the batch never runs its own WAF sync;
  - a batch stops rescoring 10 seconds before its Lambda deadline and leaves the sync to the tick,
    because a timed-out batch is retried and counted twice;
  - at most the 500 busiest sources per batch get a `RATE` counter.
  These limits are unmeasured starting points (`SURGE_MAX_RESCORE`, `SURGE_EVENTS`,
  `CERTAIN_PER_IP`, `DEADLINE_MARGIN` in `aa_ai/scorer.py`, `RATE_MAX_IPS` in `aa_ai/flood.py`).
- **State:** one DynamoDB table. Per-actor events are kept for 6h, and `FLAG` items expire
  after 1h (tarpit) or 24h (block) via TTL. Lambda batches are small, so a score builds up
  across many batches.
- **Out:** the WAF IPv4 / IPv6 / JA4 sets are **rebuilt** from unexpired flags on every
  change, never appended to, so a crashed or retried run can't leave a stale block. Lock
  conflicts are retried.
- **`ScorerMode=observe` is the default:** it logs `would_flag` lines and never touches WAF.
  Review a few days in Logs Insights, then switch to `enforce`.
- **Guardrails:** `AllowCidrs` are never flagged; at most `MAX_FLAGGED_IPS`.
  **JA4 blocking is off by default** (`FlagJa4`), because a JA4 is shared by every client on the
  same TLS stack, and every Chrome user shares one. Even when on, it only blocks
  decoy-confirmed actors at `block`, skips `PROTECTED_JA4`, and keeps at most 10 entries (the
  WAF regex-set limit).

Build and deploy:

```bash
infra/build_scorer.sh my-artifacts-bucket-us-east-1
```

Then pass `ScorerCodeBucket` / `ScorerCodeKey` (the content-hashed key the script prints) to
the stack.

### IP reputation

The scorer enriches every **unverified** event with *where* it came from (`aa_ai/reputation.py`),
as a **secondary** signal only. Agents rotate IPs and ride residential proxies, so a bad IP is
corroboration, not proof: the reputation detector is STYLE (capped below `tarpit` in scoring), it
never runs on verified requests, and it can only sharpen a verdict once a real intent signal is
already present. Categories, strongest first: `malicious` (threat-intel feed), `tor_exit`,
`datacenter` (cloud/hosting range), `scanner`.

Four feeds, two keyless and two keyed. **Every feed fails open** — a missing key, a timeout, or
unparseable data yields no category, never a false accusation:

| Feed | Default | Stack parameter | Notes |
| --- | --- | --- | --- |
| Datacenter / cloud ranges | **on** | `DatacenterRangesUrl` (default AWS `ip-ranges.json`), `DatacenterCidrs` (static CSV) | Fetched list cached 1h per container; static CIDRs always apply. No key, no egress needed if you set `DatacenterCidrs` |
| Tor exit nodes | **on** | `TorExitUrl` (default `check.torproject.org` bulk list) | Cached 1h per container |
| GreyNoise | off | `GreyNoiseKey` (`NoEcho`) | Bounded per batch; per-IP verdict cached in the table |
| AbuseIPDB | off | `AbuseIpdbKey` (`NoEcho`) | `abuseConfidenceScore ≥ 50` → `malicious`; cached in the table |

Per-IP results cache in the DynamoDB table (`REP` rows): 6h for a feed hit, 3h for "nothing
known." Toggle the whole feature and each feed from **Controls → Integrations** in the dashboard;
the keyed feeds stay dark until their key is set on the stack **and** enabled in policy. In a
NAT-less Lambda the HTTPS list fetches fail open and fall back to `DatacenterCidrs` — or point the
range URLs at `s3://…`, which the enricher reads through the VPC gateway endpoint with no NAT.

### Known gaps

- WAF logs carry **no origin status code**. `correct_and_retry` (needs 422) can't fire from WAF
  logs, and status-dependent detectors treat unknown as success. The in-app `Shield`
  middleware sees real statuses. Joining CloudFront standard logs on request ID would close this.
- WAF logs don't include the request body, so `distributed_spray` (needs the username) only
  works from app logs.
- An actor is /24 + UA (+ JA4). An agent that rotates across /24s shows up as new actors. Each
  one is caught again quickly (decoys, host-wide auth budget), but scores don't carry over.

## AWS anti-DDoS and IP reputation rules

Floods are handled in three layers, cheapest first:

1. **AWS Shield Standard**, on for every CloudFront distribution at no charge. It absorbs network
   and transport floods (SYN floods, UDP reflection) before there is any HTTP to inspect.
2. **AWS managed rule groups in the web ACL** (`infra/edge-shield.yaml`):
   - `aws-anti-ddos` (priority 17, `AWSManagedRulesAntiDDoSRuleSet`) learns the site's normal
     traffic. During a layer-7 flood it silently challenges suspect clients (sensitivity high) and
     blocks the worst (sensitivity low). API, dashboard and static-asset paths are exempt from the
     challenge, since those clients cannot run it.
   - `aws-ip-reputation` (priority 18, `AWSManagedRulesAmazonIpReputationList`) blocks addresses
     AWS threat intelligence has seen attacking, scanning or in DDoS botnets.
   - Both run after the allow list (2), the flagged-IP block (11) and the per-IP rate rule
     `ip-flood-rate` (16, 2,000 requests per 5 minutes), and before flood mode's live rule (19)
     and the protections below (20-24).
3. **Undertow flood mode** (below), for a flood spread so wide that no single IP trips a limit.

What they cost: the anti-DDoS rule group is $20 a month plus $0.15 per million requests, and the
requests it blocks are not billed as WAF requests. The IP reputation list is $1 a month.

Their stops appear in the WAF logs with `terminatingRuleId` `aws-anti-ddos` or
`aws-ip-reputation`. The scorer counts those requests but does not store them (see the cost guard
below). Do not move these rules or reuse priority 19.

## Flood mode

`aa_ai/flood.py`, run by the 1-minute tick (`TickFunction`) before the WAF sync. It decides from
counters only (`STATM`, `RATE`, `PROF`, `FLAG`), never from stored events, which a flood's skipped
requests are not. Statistics detect and
act; the LLM only advises one narrow rule and is never in the request path.

**Surge.** The tick judges the last complete minute (`STATM` requests) against the median of the
30 minutes before it. Minutes already judged part of a surge are left out of that median, so a long
flood cannot teach itself into the norm. A surge is `rpm >= max(multiplier x norm, floor_rpm)`. It
ends after 3 calm minutes in a row. One `flood` alert when it starts, one when it ends (30-minute
cooldown each), and a move on the board for each.

**Per IP.** Ingest adds one atomic counter per IP per log batch (`RATE#<minute>` / `<ip>`, 1h TTL),
skipping the dashboard path, allow-listed and verified traffic, and crawler claims it has not been
able to check yet. During a surge, every IP at or above `per_ip_rpm` in the last minute gets a
`FLAG` item (`flood:<ip>`, verdict `block`, `flood: True`, signal `flood: N requests/minute during a
surge`), for `ttl_minutes`, renewed at half-life while it keeps flooding, at most `max_ips`.
Allow-listed IPs are never flagged; an unblock clears one and keeps it clear. These flags go to the
**WAF block sets** (429 + Retry-After) in every edge mode, `cell` included: a flood is never routed
to the padded cell. Agents' IPs fill the set first, so a flood never crowds an agent out of the
10,000-address limit. Turning flood mode off (or `act: false`) releases them on the next sync.

**Cost guard.** While an IP holds a flood flag, and for any request a flood-layer rule already
stopped (`BLOCK` by `ip-flood-rate`, `aws-anti-ddos`, `aws-ip-reputation` or `flood-pattern`, or an
unsolved `flood-pattern` challenge), ingest counts the request in the stats and the per-IP rate but
stores no per-event item and rescores nothing. Edge stops by Undertow's other rules (the login rate
limit, the tool user-agent rule, flagged agents) are still stored: they are how
`ignores_retry_after`, `keeps_hammering` and `credential_spray` see an agent.

**Pattern.** When a surge has lasted 2 minutes and flood-flagged IPs carry under half of it, the tick
reads the last minute's profile (`PROF#<minute>`, written by ingest only during a surge, top 10
values per field per batch, only requests WAF let through): top user agents, JA4s, path prefixes
(first two segments) and hosts, each with its share. Values with at least half of that traffic are
the candidates. The judge's model picks at most one rule from a fixed schema
(`{field: user_agent | ja4 | path_prefix, value, action: challenge | block | none, minutes, why}`).
Code enforces, whatever it answers:

- the value must be one of the candidates (the schema also lists only them);
- Challenge is the default; Block only for a user agent that matches a plain script or HTTP
  library (curl, python, go-http-client, java, wget, libwww, okhttp, scrapy, headless and similar);
- never the path `/` alone; never longer than 60 minutes;
- on an error, timeout, refusal or bad answer: the top candidate, challenged, if it has 60% or more;
  otherwise nothing. A valid `none` is respected and asked again after 5 minutes.

At most one call per tick while surging and 10 an hour (`FLOODCOUNT/<hour>`), with a 20-second
timeout and no retries. The rule is `flood-pattern` at priority 19 in the live web ACL
(`acl.flood_rule`, `acl.apply_flood`): Challenge, or Block 429 with the `generic` body and the
policy's Retry-After, matching the `user-agent` header, the JA4 fingerprint or a URI path prefix, and
never `/_undertow/`. It is stored with its expiry in `FLOOD/state`, removed on the tick after it
expires or about 10 minutes after the surge ends, and re-applied idempotently every tick, so a
deploy that resets the ACL loses it for a minute at most. Dashboard edge-control changes keep it.

**Where the call runs.** In the 1-minute tick, not the judge Lambda: the surge state, the profile,
the guardrails and the ACL write live in one place, and the tick must hold the web ACL permission
anyway to re-apply the rule after a deploy. The tick gets the model SDK from the judge layer
(attached when `JudgeLayerKey` is set); without it, every pattern decision is the deterministic
fallback. Only the tick's role has `wafv2:GetWebACL` / `wafv2:UpdateWebACL` (web ACL and its IP
sets) and `bedrock-mantle:CreateInference`; its environment has `WEBACL_NAME`, `WEBACL_ID` and
`JUDGE_MODEL`. The log-batch scorer has neither.

**Modes.** `ScorerMode=observe` (or policy `mode: observe`): flood flags are recorded and every
decision is logged (`would_flood`), but nothing is written to WAF. Removing a rule left from enforce
only loosens, so it runs in any mode. `pattern: advise` asks the model and records its pick without
applying it; `off` skips the pattern step.

**Policy** (`set_policy` with a `flood` object; bounds enforced by the admin API). Every number is
an unmeasured starting guess:

| Key | Default | Bounds |
| --- | --- | --- |
| `enabled` | `true` | |
| `act` | `true` (flag and block IPs) | |
| `pattern` | `act` | `act`, `advise`, `off` |
| `multiplier` | 5 | 2-50 |
| `floor_rpm` | 600 | 60-1,000,000 |
| `per_ip_rpm` | 120 | 10-100,000 |
| `ttl_minutes` | 15 | 1-1,440 |
| `pattern_minutes` | 30 | 1-60 |
| `max_ips` | 5,000 | 0-5,000 (half a WAF IP set) |

Fixed in code, also guesses: 30-minute baseline, 3 calm minutes to end, 2 surge minutes before a
pattern, 50% spread and candidate share, 60% fallback share, 50 profiled requests minimum, 10 minutes
to remove after a surge, 5 minutes after a `none`, 10 calls an hour.

**Testing.** On a test stack in observe mode, lower `floor_rpm` (e.g. 60) and `per_ip_rpm` (e.g.
30), send steady requests from a few machines you control with a plain client for 3 minutes or more,
and watch the Flood mode card: the surge and the IPs within about two minutes, the rule two minutes
later. Switch to enforce to see the 429s and the rule. Keep it small: a full-scale flood is a DDoS
simulation, which AWS allows only through its approved testing partners.

**Cost.** No fixed fee. One DynamoDB write per IP per log batch, a few more each minute of a surge
(profile counters, flag writes at half-life, the state item), one `GetWebACL` a minute while a rule
is live, at most 10 model calls an hour during a surge, and the pattern rule bills as one more WAF
rule only while it exists.

**Limits.** The surge is measured across all traffic the engine sees, so a flood on one small app
behind a shared engine is judged against the combined norm. The verdict API (`aa_ai/verdict.py`)
looks up flags by actor, so gateways that use it do not see flood flags; apps behind the shared web
ACL do.

## More managed rules and the lead-form limit

Five more rules follow flood mode's slot (19) in the web ACL:

| Priority | Rule | What it does |
| --- | --- | --- |
| 20 | `aws-known-bad-inputs` (`AWSManagedRulesKnownBadInputsRuleSet`) | **Blocks** known exploit payloads (Log4j, Java deserialization and similar) |
| 21 | `aws-common` (`AWSManagedRulesCommonRuleSet`) | **Counts** (labels only) |
| 22 | `aws-sqli` (`AWSManagedRulesSQLiRuleSet`) | **Counts** (labels only) |
| 23 | `aws-anonymous-ip` (`AWSManagedRulesAnonymousIpList`) | **Counts** (labels only) |
| 24 | `form-rate` | **Blocks** with 429 + `Retry-After` after 10 `POST /api/lead` from one IP in 5 minutes |

- **Why count.** Undertow lets agents in to deceive them in the padded cell and drain their token
  budget. A generic signature blocked this early would stop the probe before its intent shows. The
  count-only labels (`awswaf:managed:aws:core-rule-set:*`, `sql-database:*`, `anonymous-ip-list:*`)
  stay in the WAF logs and the stored events, but never reach scoring or the judge
  (`aa_ai.events.COUNT_ONLY_LABELS`). Anonymous IPs are a source-reputation hint, never a gate.
- **Known bad inputs are evidence.** Their blocks are not flood-layer stops, so the scorer stores
  them and the detectors read them; a WAF block with no custom response reads as WAF's default 403.
- **`form-rate`** is in `acl.RETRY_RULES`, so the dashboard's Retry-After control covers it. There
  is no `/api/lead` route in the reference store; the rule matches nothing until an app behind the
  engine serves that form.
- **Capacity.** Live before these rules: 182 WCU (anti-DDoS 50 and IP reputation 25 included).
  Added: known bad inputs 200, core rule set 700, SQL injection 200, anonymous IP 50, `form-rate`
  about 6. Expected total **about 1,338 WCU**, up to about 1,370 while flood mode's pattern rule is
  live. That is under the 1,500 included with a CloudFront web ACL; above it AWS charges extra per
  request. A template test keeps the sum under 1,500.
- **Cost.** $1 a month each (the rule charge); none of these four groups has a fee of its own.

## Budget alarm

`CostBudget` in `infra/edge-shield.yaml` (created when `AlertEmail` is set): a monthly cost budget of
`MonthlyBudgetUsd` (default 100) on the services **AWS WAF** and **Amazon CloudFront**, the two that
carry most of the cost and that a flood inflates. It emails `AlertEmail` at 80% of actual spend and
when the month is forecast to pass 100%. The filter is **account-wide**: other web ACLs and
distributions in the account count toward it too.

## Budget page

The dashboard's **Budget** tab (`aa_ai/costs.py`).

- **Estimated hourly.** On the 1-minute tick, at most once an hour, one CloudWatch `GetMetricData`
  call reads the engine's own usage for every hour of the month not sampled yet (a first run
  backfills the month): its web ACL's requests (`aa-ai`) and anti-DDoS blocks, its CloudFront
  distributions (the engine's own plus every protected app on the same web ACL, found with
  `ListDistributionsByWebACLId`), its Lambda functions, its table, the `aws-waf-logs-aa-ai` log
  group and the dashboard API. The judge's and flood mode's token counts come from the table. Fixed
  charges (web ACL, rules counted from the live ACL, the anti-DDoS group, Secrets Manager secrets,
  the store's VPC endpoint hours, snapshot writes) are prorated by the hour. Each hour is a
  `COST/<hour>` row (400-day TTL); `COSTSUM/current` holds the page (month to date, daily series by
  service, run rate from the last 24 hours, month-end projection). A failed sample waits for the
  next hour.
- **Verified daily.** After 06:00 UTC, once a day, Cost Explorer `GetCostAndUsage` returns the bill
  by service for the month so far (on the 1st, the month before), compared with the estimate for
  the same days (`COSTV/<date>`: actual, estimate, ratio and accuracy per service). At most **2
  Cost Explorer calls a day** ($0.01 each), counted by a conditional write that fails closed:
  the check, plus one look-up or activation attempt for the tag.
- **Exact or account-wide.** Every Undertow stack is tagged `undertow=engine` (the template
  configuration files from `infra/stack_params.py`, `--tags` in `infra/publish.sh`). When the tag is
  an active cost allocation tag and has been the whole period, the check filters on it
  (**exact**); costs only carry a tag from activation on. Otherwise it filters on the same
  services across the account (**account-wide**), so other workloads count too. Once a day, if the
  tag exists but is inactive, the tick tries `UpdateCostAllocationTagsStatus` and fails quietly
  if denied (an AWS Organizations member account usually needs the management account). LLM
  calls are billed under the model's own name with no tag: estimated only.
- **Prices** are us-east-1 list prices in `aa_ai/costs.py`, with every number that is an assumption
  marked; the model's per-token prices are set by `MODEL_PRICE_IN_PER_M` and
  `MODEL_PRICE_OUT_PER_M`.
- **IAM.** The tick's role has `cloudwatch:GetMetricData`, `cloudfront:ListDistributionsByWebACLId`,
  `ce:GetCostAndUsage`, `ce:ListCostAllocationTags` and `ce:UpdateCostAllocationTagsStatus` on
  `"*"` (none of them supports resource-level permissions), and reads the web ACL. The page prices
  both functions (`COST_FUNCTIONS` on the tick lists the log-batch scorer).

## Still to build

- CloudTrail metric filter on the canary access key ID.
- Optional: AWS WAF Bot Control (targeted) as an additional signal, not a replacement.

## Sign-in (Cognito)

- **Invite-only.** The user pool `undertow-users` has public sign-up off. The first admin is the
  pipeline stack parameter `AdminEmail`. Every other account comes from **Users → Invite**.
- **Passwords.** Cognito emails a one-time temporary password, and the user sets their own at
  first sign-in: at least 12 characters, with upper and lower case, a number and a symbol.
  Nobody else, and no code here, ever sees a password.
- **Forgot password** on the sign-in page emails a 6-digit code. An admin can also trigger a reset
  from the Users tab. For someone who never signed in, that resends the invite.
- **Roles.**
  - **admin:** every action, policy, tuning, alerts and users.
  - **user:** read-only.
  - API Gateway rejects any request without a valid token, and the API checks the role, so
    hiding buttons in the page is a convenience, not the control.
- **Data.** Snapshots live under `data/` in the dashboard bucket, which CloudFront never serves.
  Signed-in users read them through `/_undertow/api/data/{1,6,24}`.
- **Lockout protection.** Cognito slows repeated failed sign-ins on its own. Its paid threat
  protection (adaptive authentication, compromised-credential checks) is not enabled.
- **MFA is not enabled yet.** TOTP is the next step for admin accounts.
- `RestrictDashboard=true` also limits the dashboard to `AdminCidrs`. It is off by default
  now that sign-in protects the data.
