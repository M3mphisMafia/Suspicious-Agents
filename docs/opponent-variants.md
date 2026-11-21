# Opponent variants: what each ARTEX version does differently

Survey of 2026-11-19. Source was read through the GitHub API only and never built or run.
Line references are to the versions current on that date.

## The lineage

| Version | What it is | Pacing / 429 | When blocked | Untrusted-content framing | Notable for defenders |
| --- | --- | --- | --- | --- | --- |
| **Upstream v0.3.15** (Hinln/ARTEX backup, failsafe-security/artex) | The original, most likely what criminals run | **None.** A 429 or 503 only reaches the model | Try every bypass; the planner re-dispatches "deeper, more ruthless" | **None** | `norma/0.4`, `artex-enrich/1.0`, `spa-api-recon` UAs. failsafe documents a login backdoor in the v0.3.16 prebuilt image |
| **BaaRai/ARTEX** (English translation) | Adds safeguards | Noise profiles; honors `Retry-After` up to 10/30/60s; pauses the whole host | **Stops and asks the operator** (the only version that does) | Yes, and quotes injected text as a finding | Our `Retry-After: 9` and stall tricks work **only here** |
| **RuoJi6/ARTEX** (most active fork, v0.3.30) | Internationalized and extended | None on the target side | Same as upstream | None | **Random real browser User-Agent per request, from 20 strings; proxy pool rotating every 30s (3s minimum)**; optional OPSEC prompt, off by default; MCP server for remote control |
| **jiwoochris/artex-global** | Translation plus **defender** material | As upstream | As upstream | None | Includes Sigma/Suricata rules and IOCs (ports 8787/8788, mitmproxy CA) |
| **cskwork/scopeweaver** | English/Korean prompts | None | Softer wording, still no handoff | None | Still `norma/0.4` |
| **bdg9412/artex-ko-plus** | Korean, with defensive add-ons (Splunk hunting, IR) | As upstream | As upstream | None | Offensive engine unchanged |
| **AntiFox-AI/antifox** | Branched from ARTEX v0.1.1, actively developed | None on the target side | Retry with other encodings, methods and paths; keep several routes open | None | Workers send raw curl/python/node traffic; UA `norma/0.4` or the tool's default; one proxy, no rotation; memory across engagements (pgvector) |
| Ernket/CodeScan-Artex | Static code audit only | — | — | — | Never touches a live target: out of scope |
| IlyassCODEX/ARTEX | Unrelated Python scanner with the same name | Sleeps 1s | — | — | Chrome 91 / Firefox 89 UAs |

## What this changed in Undertow

1. **Fake browsers are detected, and keyed by TLS fingerprint.** RuoJi6 defeated the /24 + UA
   actor key: a new UA per request and a new IP every 30s. A client that claims a browser UA
   but sends none of the `Sec-Fetch-*` headers every modern browser sends is now:
   - flagged by `spoofed_browser` (0.45, watchlist on its own);
   - keyed by **JA4 only**, so the rotation collapses into one actor;
   - also flagged by `ua_churn` when one actor shows many browsers.
2. **ARTEX tooling fingerprints** (`tool_fingerprint`, 0.9): `norma/0.4`, `artex-enrich/`,
   `artex-egress-probe/`, `artex-selfupdate`, `spa-api-recon`; HeadlessChrome at a lower
   weight. `js_harvest_burst` (0.4) catches the api-recon skill's 20–24 parallel JS downloads.
3. **Hard blocks and tarpit over polite 429s.** Only BaaRai obeys `Retry-After`. Against
   upstream and the forks a 429 changes nothing and a block makes them try bypasses. What hurts
   them is time: each intent has a 600s budget by default, and the tarpit, decoys and honey
   sessions spend it. The edge still answers 429, which is harmless, and the escalation detectors
   (`ignores_retry_after`, `keeps_hammering`) turn their persistence into a block.
4. **Deception lands harder on the forks.** None of upstream, RuoJi6, AntiFox, scopeweaver or
   ko-plus frames target content as untrusted, so personal decoy maps and honey sessions are taken
   at face value.

## Leads not yet built

- **JA4 vs. User-Agent consistency** beyond the Sec-Fetch check: a Chrome UA with a Go or Python
  JA4. Needs a maintained browser-JA4 list.
- **Real-IP leak.** When a proxied WebFetch fails for a proxy reason, the norma library retries
  once **without the proxy**. A `norma/0.4` request from a new, non-proxy IP right after proxy
  errors is likely the operator's own address.
- **Bait on their checklist.** BaaRai's `api-security` skill hunts `/graphql` introspection and
  JWT weaknesses (alg:none, weak HMAC, kid injection). A decoy introspection response and JWT
  honeytokens would be walked straight into.
- **Use the defenders' rules.** artex-global's Sigma and Suricata rules and IOCs could be
  imported for host and network triage.
