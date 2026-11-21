# Changelog

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
