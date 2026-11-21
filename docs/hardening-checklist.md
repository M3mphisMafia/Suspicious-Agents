# Hardening checklist: what to fix in an app before Undertow protects it

Undertow shrinks the window and makes an agent's run expensive. But ARTEX-class agents don't
invent exploits; they chain weaknesses that already exist, quickly. **Removing the prize is the
biggest lever.** Work through this list for every app behind Undertow.

## 1. Don't hand it a map
- [ ] No public OpenAPI or Swagger docs, GraphQL introspection or source maps in production.
      Agents read these first. Undertow's personal decoy map works best when there is no real
      map to compare it with.
- [ ] No runtime config files (`config.json`, `env.js`) that list internal routes, client IDs or
      tokens. Undertow serves bait versions at `/.env`, `/config.json` and `/.aws/credentials`.
- [ ] `robots.txt` lists no sensitive paths except the decoy prefix.

## 2. Identity and access
- [ ] Authentication on **every** write and every non-public read, including dev and staging APIs.
- [ ] No answer that reveals whether an account exists: same response, same timing, for login,
      sign-up and reset.
- [ ] Rate limits on login, reset, sign-up and verification codes. Undertow adds one host-wide
      budget across all login routes, and an app-level limit still helps.
- [ ] Object-level authorization on every ID in a path or body (IDOR). Agents walk sequential IDs;
      use non-guessable IDs where possible.
- [ ] MFA for admin accounts. The Undertow dashboard requires an authenticator app for admins
- [ ] Federated identity: no local passwords for workforce accounts, and resets can't unlink SSO.

## 3. Containment (assume something gets through)
- [ ] The app runs with **least privilege**: no role that can create roles, keys or tokens.
- [ ] **No route to the internet** from the app, so no exfiltration or reverse shell. The demo shop
      runs in a VPC with no gateway or NAT, reaching Secrets Manager through a private endpoint only.
- [ ] Secrets in Secrets Manager, not environment variables or files; short-lived credentials.
- [ ] IMDSv2 required on any EC2 host.

## 4. Tripwires (know the moment it happens)
- [ ] **Canary AWS key** planted in decoys. Any use, even `sts:GetCallerIdentity`, raises a
      *breach* alert. IAM records last use with up to a few hours' lag.
- [ ] **Honey records**: fake rows whose IDs exist nowhere else (Opus 5.5 generated the corpus;
      our code stamps the IDs). A request carrying one is a certain detection, from any IP.
- [ ] Alerts on unusual data volume from read endpoints, and on first use of any credential from
      a new IP.

## 5. Edge posture
- [ ] Origin reachable **only** through CloudFront: the origin-verify header checked at the ALB or
      app, and an origin security group limited to the CloudFront prefix list.
- [ ] `AllowCidrs` lists offices, VPN exits, monitors and partners, so the login limit and
      Challenge never reach them.
- [ ] Browser apps that call APIs from JavaScript integrate the AWS WAF JS SDK before turning on
      `ChallengeSensitive`. Without it, their own API calls get the challenge.
- [ ] Start in **observe** mode, review a few days of `would_flag` lines and the Claude judge's
      advice, then move to enforce.

## 6. Operations
- [ ] Patch internet-facing software quickly. The gap between disclosure and agent exploitation
      is now days.
- [ ] Every deploy goes through the pipeline. No hand edits to WAF, except the dashboard's live
      controls, which the deploy carries forward.
- [ ] Someone receives the alerts (confirm the SNS email subscription) and knows the runbook:
      unblock false positives from the dashboard, and investigate *breach* alerts in CloudTrail.
