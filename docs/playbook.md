# The playbook: they play checkers, we play chess

An agent moves one route at a time and adapts to each answer. Undertow answers each
move with the counter that turns the agent's next move into a certain detection.

## Default stance

`edge: block`: only certain or near-certain agents (score ≥ block) are blocked at
the CloudFront edge. Suspects (watch and tarpit) **keep playing inside the app**, where
Shield can watch and deceive them. Flip the dashboard's **Edge: suspects** switch to
block tarpit-level actors at the edge too, which is the earlier, blunter behavior.

## Moves and counters

| Their move | Detector or trigger | Our counter |
| --- | --- | --- |
| Reads `openapi.json`, then walks routes within seconds | `map_then_walk` (0.5) | Next map read returns **routes only this agent is shown** (`<prefix>/t/<tag>/…`) |
| Walks a personal route | certain | Score 1.0. From a **new IP**, the tag links it back to the original agent (rotation tracking) |
| Tries to log in while suspected or challenged | Shield | Gets a **honey session token** (`hny_<tag>_…`) instead of the app's answer |
| Replays the honey token | certain | Score 1.0, linked to the agent the token was issued to |
| Probes with bad input | `canary_inputs`, `correct_and_retry` | Error detail masked, so there is nothing to self-correct from |
| Sends again before `Retry-After` expires | `ignores_retry_after` (0.5) | Escalates. Real clients back off, and so does ARTEX's own governor |
| Keeps going after refusals | `keeps_hammering` (0.45) | Escalates toward an edge block |

## Operator controls (dashboard)

All need a Cognito sign-in with the **admin** role (checked by API Gateway, then by role in the API). Each one is
written to the audit log, resynced to WAF and republished to the dashboard within seconds.

- **Challenge** an IP: WAF tags its requests (`x-amzn-waf-undertow-challenge`, valued with the
  origin secret so a client cannot forge it), and Shield plays the deception counters
  **without delaying it**. A safe way to test a suspect.
- **Tarpit / Block** an IP for a set time, or **Unblock** it. An unblock of a detector's
  flag is recorded as a false positive; an operator's own block is not.
- **Mode** (observe / enforce) and **Edge**: **cell** (default: confirmed agents are routed to
  the padded cell, a fake app that seems to work, see [padded-cell.md](padded-cell.md)),
  **certain** (429 at the edge), **suspects**, or **lockdown**.
- **Tuning**: watch / tarpit / block thresholds, and a 0–2× weight per detector (0 turns
  one off). The next scoring pass uses them.
- **Out of norm**: the last 5 minutes against 5-minute buckets from the previous 24 hours.
  Counts vary by about the square root of their mean, so z uses that as the floor.
  Clients never seen before this hour are listed. It needs about an hour of history first.

## Limits

- Personal maps and honey logins happen **in the app** (Shield, Python/ASGI). An app
  without Shield gets the edge layer only.
- A false positive that is suspected and logs in gets a honey token rather than a real
  session. Only actors already scored ≥ tarpit, or challenged, are exposed to that. Unblock
  fixes it and records the false positive.
- Linking rotated IPs needs the agent to replay something we gave it. An agent that
  never re-reads the map or logs in is caught by behavior alone.
