# Changelog

## 1.1.0 (2026-11-21)

**The Dashboard tab: a live, full-screen scene of the edge.**
- Every request the edge sees can become a light: in from the internet, through the Undertow line,
  into your app's lanes. Allowed traffic flows in, challenges wait at the line, tarpits crawl,
  blocks and floods bounce off, decoy hits are diverted up, and agents in the padded cell are pulled
  down into it. Hover a light for its details.
- Drag app aspects and protected apps onto the scene as lanes, drag stat widgets anywhere, and
  highlight one class of traffic. The layout is saved per viewer. Full screen, keyboard reachable,
  a text view, and a still view for reduced motion.
- Fed by a small sample, not every request: each log batch keeps at most 40 requests (rare kinds
  first) in a 2-hour `LIVE` row, and the 1-minute tick writes the last 3 minutes to `data/live.json`.
  No Firehose. The feed carries IP addresses, so only admins receive it; everyone else sees labeled
  demo traffic.
- `infra/upload_dashboard.sh` publishes every dashboard file with its content type.

## 1.0.1 (2026-11-21)

Launch tidy-up.

- The attack simulator and the red-team agent only run against the Undertow reference store. The
  `ARTEX_FORCE` and `RED_FORCE` overrides are gone, and a generic 429/503 or an AWS WAF challenge no
  longer counts as proof of the target; only the store, the padded cell or Undertow's own edge
  response does.
- README: responsible use, the data the engine keeps and for how long, and badges.
- Third-party notices.
- The Python package is now `undertow-security` (the `aa_ai` import and the `aa-ai` command stay).

## 1.0.0 (2026-11-21)

First public release of Suspicious Agents, V1 of the Undertow Security platform.

**Detect, deceive, drain**
- Behavioral detectors for ARTEX-class agents, escalation scoring, and the rule that style alone
  never blocks: an intent signal is required.
- The padded cell (a slow, convincing fake of the app), the token sink, the LLM judge (advise by
  default, capped per hour), verified agents, campaigns, the mirrored cell, and the verdict API
  with gateway adapters.

**Bot floods**
- Flood mode: plain statistics detect a surge, the flooding IPs are blocked at the WAF (never sent
  to the padded cell), and for a spread-out flood the judge's model picks one narrow challenge rule
  from observed values. The model never sits in the request path.
- AWS managed rules in the web ACL: anti-DDoS, IP reputation and known bad inputs block; the core
  rule set, SQL injection and anonymous IP rules count only, so agents still reach the cell.
- A sign-up form rate limit (`form-rate`).

**Costs**
- About $50 a month in AWS charges for a typical install, with a budget alarm at $100.
- The Budget page: an hourly estimate by service, checked against the real bill every 24 hours.

**Platform**
- Other apps can be protected on their own CloudFront distributions with the engine's web ACL,
  cell router and padded cell.
- Every LLM feature defaults to one model setting, `aa_ai.DEFAULT_MODEL`.
- Python 3.14 for the Lambdas, the build images and the package.
- Apache License 2.0. Tests and the detection eval run on every pull request.
