# ARTEX threat profile (as of 2026-11-19)

Open-source multi-agent LLM pentest framework (Go + Next.js, AGPL-3.0), published July 2026 by
"Autumn-27". Upstream later went closed. Forks are widespread (e.g. a translation fork with ~11k
stars, plus derivatives such as AntiFox). It carries no model of its own and drives external LLMs,
using MCP tool servers for nmap, nuclei, curl and Impacket. Used in real intrusions since late
August 2026 by several unrelated clusters. FBI FLASH alert issued.

## Behavioral indicators (what `detectors.py` encodes)

| Indicator | Source | Detector |
| --- | --- | --- |
| Bursts of 1–14 requests ~1s apart, then a 25–31s pause | Unit 42 | `burst_pause_cadence` |
| Polling every 48s for days; spray with a steady 1s gap | Unit 42, Wiz | `metronome` |
| Placeholder values: `evil[.]com`, `test@example[.]com`, `deadbeef…` | Unit 42 | `canary_inputs` |
| Routes from a downloaded OpenAPI spec / source map, hit almost immediately | Unit 42, Wiz | `spec_then_targeting` |
| GET of the same path after almost every write | Unit 42 | `write_then_verify` |
| 422 → adjusted → retried successfully | Unit 42 | `correct_and_retry` |
| Moves to another auth endpoint on the same host when throttled | Wiz | `auth_endpoint_hop` |
| Sessions of 24–30h | Wiz | `long_session` |
| Same account sprayed from rotating IPs | Wiz, Microsoft | `distributed_spray` |

## Host / cloud artifacts (for EDR and CloudTrail hunting, not this code)

Command lines containing `artx`/`artex`, cloud role names starting `artx`, admin comments starting
`art18-`, directory `ProgramData\artx5v` (CrowdStrike, via jwatte.com summary). Treat as leads only.

## Sources

- Unit 42: https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/
- Wiz (summary): https://toolnavs.com/article/2790-wiz-exposes-the-artex-attack-agent-it-hunts-login-doors-and-stays-for-30-hours
- Defender's guide: https://jwatte.com/blog/how-artex-agentic-pentest-framework-works-defense.md
- Qualys: https://blog.qualys.com/misc/2026/11/15/artex-moves-at-machine-speed-what-risk-owners-need-to-change
- Check Point (summary): https://letsdatascience.com/news/check-point-details-autonomous-artex-attacks-by-cybercrimina-9d8b6097
- FBI FLASH (summary): https://glitchwire.com/news/fbi-issues-flash-alert-on-artex-the-ai-agent-framework-automating-network-intrus/article.md
- Source read: https://github.com/BaaRai/ARTEX

Several of these are secondary write-ups; numbers should be re-checked against the primary reports.
