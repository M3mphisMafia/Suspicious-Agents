# Flood test (2026-11-19T22:45Z) — 50 agents, fresh harness
| t | shopper home | shopper products | requests | block | tarpit | cell in | tokens burned | est $ |
|---|---|---|---|---|---|---|---|---|
| 22:45:26 | 200/1.365300s | 200/0.330149s | 4497 | 9 | 0 | 0 | 0 | $0.0 |
| 22:46:14 | 200/0.195746s | 200/0.289418s | 4497 | 9 | 0 | 0 | 0 | $0.0 |
| 22:47:00 | 200/0.360466s | 200/0.201697s | 4497 | 9 | 0 | 0 | 0 | $0.0 |
| 22:47:47 | 200/0.186749s | 200/0.237572s | 4497 | 9 | 0 | 0 | 0 | $0.0 |
| 22:48:33 | 200/0.256915s | 200/0.208127s | 5871 | 30 | 22 | 0 | 0 | $0.0 |
| 22:49:19 | 200/0.220821s | 200/0.334704s | 5871 | 30 | 22 | 0 | 0 | $0.0 |

## Flood waves
- == FLOOD: 50 agents ==
- == wave done: 50 agents (credential:8, idor:10, injection:7, mixed:9, recon:10, scrape:6), 1314 requests, 0 from the padded cell, 1314 throttled ==
- == FLOOD: 50 agents ==
- == wave done: 50 agents (credential:7, idor:11, injection:10, mixed:6, recon:9, scrape:7), 1182 requests, 0 from the padded cell, 1182 throttled ==
- == FLOOD: 50 agents ==

## Findings

**Defense held.**
- A real shopper stayed up the entire flood: HTTP 200 in ~0.2s throughout (one 1.36s cold start). Never degraded.
- The edge throttled **100% of the flood**: waves of 1,182 and 1,344 requests, all 429. From one source IP, the per-IP rate rule + flagged-IP block cut off every request before the origin.
- Technique variety worked: each wave mixed all six profiles (e.g. credential:7, idor:11, injection:10, mixed:6, recon:9, scrape:7).

**The flood was hard-blocked at the edge, so it never reached the padded cell** (cell_in=0, tokens=0). That is correct: you block a volumetric flood; you cell a confirmed single agent. The token sink is a separate scenario (edge mode `cell`, low volume).

**Finding — observability degrades under flood (fixed).** 50 agents generate enough WAF log events that the scorer's log-triggered invocations saturated its reserved concurrency (2,649 throttles) and starved the 1-minute snapshot publish, so the dashboard stopped updating mid-flood (and a deploy's snapshot call failed). Fix: scorer concurrency 5 -> 30, and the deploy's snapshot call is non-fatal. The defense itself was never affected.

**Gotcha confirmed.** A CodeBuild IP that already attacked is edge-blocked, so the harness's `is_store()` check got a 429 and refused to start. Fixed: it now also accepts Undertow's own 429 (generic body + Retry-After) as proof it has reached the protected store.
