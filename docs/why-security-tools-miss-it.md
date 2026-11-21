# Why most security stacks miss ARTEX-class agents

| Typical control | Why the agent walks past it | What works instead (this repo) |
| --- | --- | --- |
| IOC / signature feeds | Thousands of forks, no fixed binary, UA is `Go-http-client` or curl, and it is configurable (`ARTEX_TARGET_USER_AGENT`). IOCs rot in days. | Behavioral detectors keyed on the agent's *loop*, not its bytes. |
| IP blocklists | Blocked IPs replaced within minutes (Wiz). | Actor key = /24 + UA (+ JA4); decoys and the host-wide auth budget catch each new IP again in seconds; per-account spray view across all sources. |
| Per-endpoint rate limits | Throttled on `/login`, it moves to another auth route on the same host (Wiz). | One token bucket per actor across **every** auth route on the host. |
| Volume thresholds | Bursts of 1–14 requests, then a 25–31s think pause (Unit 42). Low average rate. | Detect the rhythm (`burst_pause_cadence`, `metronome`), not the volume. |
| WAF exploit rules | It mostly chains *existing* weaknesses with valid requests: OAuth state games, IDOR, leaked keys (Qualys). Nothing looks like a payload. | Sequence signals: spec→targeting, write→verify, 422→retry, canary values. |
| Alert-per-event SOC triage | Key Vault exfil in ~5 minutes; privileged access in under 3 hours (Microsoft). Humans can't keep up. | Automatic response at the edge, decided by score, in seconds. |
| Verbose errors | 400/422 detail is exactly what it needs to self-correct. | Uniform errors for flagged actors. |
| Lockouts | Spray spaced at a steady 1s across rotating sources stays under per-IP lockouts. | `distributed_spray` per account; host-wide auth budget. |

## The real gap

Tools judge **individual requests**. The agent can only be seen in the **shape of a session**:
read the map, probe with placeholders, act, verify, and adapt after each refusal. That shape is
far more regular than a human's and survives IP rotation, UA changes and forks, because it comes
from the agent's control loop itself.

## Phases we tag (`phases.py`)

`map -> probe -> enumerate -> identity -> act -> read`. The scan output prints the collapsed
phase sequence per actor, so an analyst sees *how* it is approaching, not just that it is.
