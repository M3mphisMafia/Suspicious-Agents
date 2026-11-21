# Suspicious Agents 1.0: install handoff for Claude

This repo is **Suspicious Agents** 1.0, V1 of the **Undertow Security** platform, from
M3mphisMafia, under the Apache License 2.0. Undertow Security defends live web apps against
autonomous AI attack agents (ARTEX and its forks) and bot floods. It detects agents by how they
behave, deceives them with a fake copy of the app that answers slowly, and drains their token
budget. `README.md` covers what each part does. This file covers how it is deployed and how to
install it into an AWS account.

Defensive use only. Nothing here reaches back into attacker infrastructure.

Read this whole file before you deploy.

## What gets deployed

```
git push main -> CodeCommit "undertow" -> EventBridge -> CodePipeline "undertow"
  Source
  UpdatePipeline  CloudFormation redeploys infra/pipeline.yaml (the pipeline updates itself)
  Package         CodeBuild: zips the engine, builds the judge's SDK layer, writes cfn/store.json
                  and cfn/edge.json (infra/package.sh, infra/stack_params.py). Deploys nothing.
  Deploy          CloudFormation: stack undertow-store, then stack undertow-edge
  Publish         CodeBuild: dashboard pages, decoy files, bait files, extra apps (infra/publish.sh)
```

```
visitor -> CloudFront (AWS Shield Standard) + AWS WAF (undertow-edge)
             |   Undertow rules, flood mode's pattern rule, AWS anti-DDoS + IP reputation +
             |   known bad inputs (block), core rules + SQL injection + anonymous IPs (count),
             |   sign-up form rate limit
             |-- normal traffic  -> reference store (Lambda function URL, no-egress VPC, DynamoDB)
             |-- confirmed agent -> padded cell: a fake copy of the app plus the token sink
             |-- decoy paths     -> S3 decoy bucket (canary files)
             '-- /_undertow/     -> dashboard (Cognito sign-in), incl. the Budget page
WAF logs -> scorer Lambda -> DynamoDB state -> rebuilds the WAF IP/JA4 sets
                          -> flood mode: surge statistics, flood blocks, one pattern rule
                          -> dashboard snapshot every minute; cost estimate hourly, verified daily
                          -> LLM judge: Anthropic Claude Opus 5.5 on Amazon Bedrock
```

| Stack | Template | Holds |
|---|---|---|
| `undertow-pipeline` | `infra/pipeline.yaml` | CodeCommit repo, pipeline, CodeBuild projects (package, publish, attack sim), the CloudFormation role, SSM `/undertow/artex/level` |
| `undertow-store` | `infra/store-app.yaml` | Northwind Supply, the reference store the engine protects: Lambda, DynamoDB, VPC, Secrets Manager endpoint |
| `undertow-edge` | `infra/edge-shield.yaml` | CloudFront, WAF, scorer, padded cell, Cognito user pool, dashboard and decoy buckets, alerts topic, verdict API |
| `undertow-app-<name>` | `infra/protect-app.yaml` | One per entry in `infra/apps.json`: another app behind the same engine |

## Before you start

- **Region: us-east-1 only.** CloudFront's WAF lives there, and the scripts assume it.
- **One install per AWS account.** The names are fixed: repo and pipeline `undertow`, stacks
  `undertow-store` and `undertow-edge`, the Cognito pool `undertow-users`, SSM parameters under
  `/undertow/`.
- You need an identity that can create IAM roles (admin or close to it), AWS CLI v2, git, and
  Python 3.14+ for the local tests.
- **Cost: about $50 a month** in AWS charges for a typical install, most of it the firewall and its
  managed rules (the anti-DDoS rule group alone is $20 a month). A budget alarm emails `AlertEmail`
  at 80% of $100 actual spend and when the month is forecast past $100 (`MonthlyBudgetUsd`). It
  covers AWS WAF and CloudFront for the whole account. The dashboard's **Budget** page shows the
  running estimate by service and checks it against the real bill every 24 hours.
- **The model is Anthropic's Claude Opus.** Every LLM feature (the judge, the red-team agent, the
  decoy-data generator) uses `anthropic.claude-opus-5-5` on Amazon Bedrock, set once as
  `DEFAULT_MODEL` in `aa_ai/__init__.py`. Keep it. The account must be able to call that model on
  Bedrock in us-east-1; if it has never used Anthropic models there, open the Bedrock console once
  and complete any access or use-case prompt for Anthropic. No separate Anthropic API key is
  needed: calls go through Bedrock with the Lambda's IAM role.
- Decide three values:
  - `AdminCidrs` (required): the public IPv4 CIDRs of the people who run the dashboard.
    `curl -s https://checkip.amazonaws.com` prints yours; add `/32`.
  - `AdminEmail`: the first dashboard admin. Cognito emails them a temporary password.
  - `AlertEmail` (optional, recommended): where alerts and the budget alarm go.
- Optional, but quick: run the tests first.

  ```bash
  python3 -m venv .venv && .venv/bin/pip install -e '.[test,aws]'
  ```

  ```bash
  .venv/bin/pytest -q
  ```

## Install

1. Point at the account and confirm it is the right one.

   ```bash
   export AWS_PROFILE=<profile> AWS_REGION=us-east-1
   aws sts get-caller-identity
   ```

2. Bootstrap the pipeline stack. `ScorerMode` starts as `observe` (see step 9).

   ```bash
   aws cloudformation deploy --stack-name undertow-pipeline --template-file infra/pipeline.yaml --capabilities CAPABILITY_IAM --parameter-overrides AdminCidrs=<ip>/32 AdminEmail=<admin-email> AlertEmail=<alert-email>
   ```

   CodePipeline starts a run the moment it is created. That run fails at Source because the repo
   is still empty. Ignore it.

3. Make this folder a git repo. Commit as a brand or noreply identity, not a personal one.

   ```bash
   git init -b main
   git add -A
   git commit -m "Initial import"
   ```

4. Push to the new CodeCommit repo. The push starts the pipeline.

   ```bash
   git remote add codecommit "$(aws cloudformation describe-stacks --stack-name undertow-pipeline --query "Stacks[0].Outputs[?OutputKey=='CloneUrl'].OutputValue" --output text)"
   ```

   ```bash
   git -c credential.helper= -c credential.helper='!aws codecommit credential-helper $@' -c credential.UseHttpPath=true push codecommit main
   ```

   The empty `credential.helper=` matters on macOS: the keychain helper otherwise answers first
   with cached credentials, and CodeCommit says "repository not found" for a repo that exists.

5. Watch the run. The first one can take 20 minutes or more (CloudFront, WAF, Cognito, the VPC).

   ```bash
   aws codepipeline get-pipeline-state --name undertow --query "stageStates[].[stageName,latestExecution.status]" --output table
   ```

6. Get the address.

   ```bash
   aws cloudformation describe-stacks --stack-name undertow-edge --query "Stacks[0].Outputs[?OutputKey=='DistributionDomain'].OutputValue" --output text
   ```

   - Store: `https://<domain>/`
   - Dashboard: `https://<domain>/_undertow/login.html`

7. First sign-in. `AdminEmail` receives a temporary password from Cognito's default sender (look
   in spam). Sign in, set a password (12+ characters, upper and lower case, a number and a symbol),
   then set up an authenticator app. Admin actions are refused on the server until the admin has
   MFA. Invite everyone else from the dashboard's **Users** tab. Nobody, including you, ever sees
   a password.

8. If you set `AlertEmail`, click the confirmation link AWS sends. It expires after about 3 days.

9. Prove it works with the built-in attack simulator. It runs in CodeBuild, so it attacks from a
   fresh AWS IP, never yours.

   ```bash
   aws codebuild start-build --project-name undertow-attack-sim --environment-variables-override name=TARGET,value=https://<domain>
   ```

   Watch the dashboard. For a longer ramp, also pass `name=ARTEX_DURATION,value=1800` and change
   the intensity live (0 is idle, 6 is a 50-agent flood):

   ```bash
   aws ssm put-parameter --name /undertow/artex/level --type String --overwrite --value 4
   ```

## Observe, then enforce

The scorer starts in `observe` mode: it logs `would_flag` lines and never writes to WAF. Review a
few days of real traffic in CloudWatch Logs Insights on the scorer's log group. Then switch:

```bash
aws cloudformation deploy --stack-name undertow-pipeline --template-file infra/pipeline.yaml --capabilities CAPABILITY_IAM --parameter-overrides ScorerMode=enforce
```

```bash
aws codepipeline start-pipeline-execution --name undertow
```

`aws cloudformation deploy` keeps the other parameters' current values. The pipeline's
self-update passes its own parameters (`AdminCidrs`, `ScorerMode`, `DecoyPrefix`, `AlertEmail`,
`AdminEmail`) through on every push, so these survive.

## Protecting a real app

- The reference store is the app behind the edge out of the box. To put your own app behind the
  engine, copy `infra/apps.example.json` to `infra/apps.json` with one entry per app (`name`,
  `origin`, and optionally `domain` plus an ACM certificate ARN in us-east-1), then push. Publish
  deploys a stack `undertow-app-<name>` for each one: its own CloudFront distribution on the
  engine's WAF.
- Before real traffic, work through the go-live checklist in `docs/aws-edge-shield.md`. Most
  important: lock the origin so only CloudFront can reach it, and allow-list offices, VPNs,
  monitors and partners.
- Python ASGI apps can also run the engine in-app: `Shield(app)` from `aa_ai.shield`. Other stacks
  use `adapters/` (API Gateway authorizer, Envoy, nginx, Cloudflare Worker) against the verdict
  API (`VerdictApiUrl` output of `undertow-edge`).
- An app that already has its own CloudFront distribution (a static site, for example) can stay on
  it: attach the engine's web ACL (`WebAclArn`), add the cell router (`CellRouterArn`) as a
  viewer-request function, and add an origin with id `cell` pointing at `CellOriginDomain` with the
  `X-Origin-Verify` header the cell requires. Put the router's `__undertow_app` query marker in the
  cached behaviors' cache key, so a padded-cell answer is never cached for a real visitor. This is
  what `infra/protect-app.yaml` does, without a second distribution in front.

## Bot floods

A flood is not an AI agent: many machines sending volume, with no reasoning behind it. The layers:

1. **AWS Shield Standard** (free, automatic on CloudFront) absorbs network-level floods.
2. **AWS managed rules in the web ACL:** the anti-DDoS rule group challenges or blocks a web flood
   within seconds, and the IP reputation list blocks known attack sources. Known bad inputs are
   blocked; the core rule set, SQL injection and anonymous IP rules only count (label), because
   Undertow lets agents in to deceive and drain them, and blocking too early hides their intent.
   `form-rate` limits sign-up form posts to 10 per IP in 5 minutes.
3. **Flood mode** (`aa_ai/flood.py`): plain statistics spot a surge against the last 30 minutes,
   block the IPs driving it at the WAF (never the padded cell), and, for a widely spread flood, let
   the judge's model choose one narrow challenge rule (`flood-pattern`) from values it actually
   observed. The model never sees or answers live requests. Defaults are in
   `DEFAULT_POLICY["flood"]` in `aa_ai/scorer.py`.

## Costs and the Budget page

- A typical install costs **about $50 a month**, most of it AWS WAF (web ACL, rules, the $20
  anti-DDoS group) plus CloudFront, Lambda, DynamoDB, logs and the judge's model calls.
- **Budget alarm:** `MonthlyBudgetUsd` (default 100) in `infra/edge-shield.yaml`. It emails
  `AlertEmail` at 80% actual and 100% forecast, and covers AWS WAF and CloudFront account-wide.
- **Budget page:** an hourly estimate from CloudWatch usage and list prices (`aa_ai/costs.py`),
  checked once a day against Cost Explorer. Undertow stacks are tagged `undertow=engine`; when that
  cost allocation tag is active the check is exact, otherwise it is account-wide for the same
  services and the page says so.

## The LLM judge: Anthropic Claude Opus

The judge runs every 2 minutes beside the request path, never in it, and is on from the first
deploy. It calls **Anthropic's Claude Opus 5.5** (`anthropic.claude-opus-5-5`) on Amazon Bedrock
through the Anthropic SDK's `AnthropicBedrockMantle` client (`bedrock-mantle:CreateInference`).
You don't choose a model; Opus is the default. By default it only advises, at most 30 judgments an
hour, and every call is billed by Bedrock.

If Opus calls fail (look in the judge Lambda's log), the account can't reach the model on Bedrock
yet: fix access, don't switch models. The SSM parameter `/undertow/judge/model` overrides the model
only when someone deliberately asks for a different one.

## Traps

- **Never test your own install from your own IP.** Decoy paths, canary credentials, honey
  tokens and attack-tool user agents flag the source IP, which is then cut off or sent to the
  padded cell for up to 24 hours. Use `undertow-attack-sim`. If you flag yourself anyway:
  `.venv/bin/python -m aa_ai unblock <ip> --stack undertow-edge --reason "self-test"`.
- **An attack-sim IP stays blocked for 24 hours.** If the simulator refuses to start because the
  store answers 429, the build landed on an IP that already attacked. Run it again.
- **Edge settings the pipeline doesn't pass are reset on every deploy.** The Package stage writes
  only the edge parameters in `infra/stack_params.py`; CloudFormation sets every other one back to
  its template default. That includes `AllowCidrs`, `DomainName`, `AcmCertificateArn`, `FlagJa4`,
  `GreyNoiseKey` and `AbuseIpdbKey`. To set one permanently, add it to `stack_params.py` (secrets
  from Secrets Manager or SSM, never committed). A value set by hand on the stack lasts only until
  the next push.
- **Controls set from the dashboard are kept.** The login limit, `Retry-After`, and country and
  network blocks are saved in DynamoDB and read back into every deploy.
- **Lambda function URLs must be allowed.** The store and the padded cell are served through them.
  An organization policy that blocks function URLs breaks both.
- **Cognito's default email sender** has a low daily limit and often lands in spam.
- **It isn't free when idle.** WAF, the Secrets Manager VPC endpoint (billed hourly), the scorer's
  one-minute schedule, CloudFront and DynamoDB all cost money with no traffic, plus Bedrock for
  the judge's Opus calls. Expect about $50 a month; the $100 budget alarm is the safety net.
- **Count-mode rules don't block.** The core rule set, SQL injection and anonymous IP rules only
  label requests. Review their labels in the WAF logs before switching any of them to block.

## Remove it

Delete in this order. The pipeline stack goes last, because its CloudFormation role deploys the
other stacks.

1. Every `undertow-app-<name>` stack.
2. Empty the buckets `undertow-edge-dashboardbucket-*` and `undertow-edge-decoybucket-*`, then
   delete `undertow-edge`.
3. Delete `undertow-store`.
4. Empty the pipeline stack's artifacts bucket, then delete `undertow-pipeline`.
5. Kept on purpose, so delete them yourself if nothing needs them:
   - the Cognito user pool `undertow-users` (turn off deletion protection first, in the console);
   - the CodeCommit repo `undertow`;
   - the SSM parameter `/undertow/judge/model`, if you created it.
