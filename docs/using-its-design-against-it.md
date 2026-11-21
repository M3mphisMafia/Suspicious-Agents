# Using ARTEX's own design against it

Read from the public fork `BaaRai/ARTEX` (English translation of upstream `Autumn-27/ARTEX`, AGPL-3.0),
files `egress/egress.go`, `egress/pace.go`, `agent/worker.go`, `intercept/closed_judge.go`.
Source was read only, never built or run. Forks drift; re-check before relying on any constant.

> **Scope, after the fork survey of 2026-11-19 ([opponent-variants.md](opponent-variants.md)):**
> sections 1-3 apply **only to the BaaRai translation**. Upstream v0.3.15 and the forks (RuoJi6,
> AntiFox, scopeweaver, ko-plus) have no throttle that honors Retry-After, no operator handoff
> and no adversarial gate: a block makes them try bypasses. Against them, time is the weapon
> (sections 4-5: tarpit, decoys, honey sessions), plus hard blocks driven by persistence.

Everything below is a *response we choose to send from our own systems*. Nothing reaches
back into the attacker's infrastructure.

## 1. Its throttle obeys our `Retry-After`

`egress.Governor` paces the platform's own HTTP tools. Built-in noise profiles:

| profile | RPS | MaxRetries | MaxDelay |
| --- | --- | --- | --- |
| quiet | 2 | 3 | 60s |
| balanced | 5 | 3 | 30s |
| aggressive | 20 | 2 | 10s |
| off (default) | passthrough | 0 | — |

On a 429/503, `send()` sets `notBefore` for the **whole host** to `Retry-After` (capped at
MaxDelay) and retries idempotent GETs. A `Retry-After` larger than MaxDelay is *not* honored and
the 429 goes straight back to the model.

**Defense:** answer flagged actors with `429` + `Retry-After: 9`. 9s fits under every profile's
MaxDelay, so the agent's own governor freezes every worker on that host and re-queues, costing us
nothing (no held connection). This is a WAF custom response, so it runs at the CloudFront edge.

With the default `off` profile there is no governor, so the 429 reaches the model directly.
That leads to #2.

## 2. The worker prompt tells it to stop and wait on a human

`agent/worker.go`, "Operator handoff on environmental blocks": on a filtered network path or
proxy/TLS interception, *"stop after the first failure: do not retry with different flags, do not
switch tools"*, call `ask_operator`, and *"Wait for the reply instead of burning turns."*

**Defense:** for high-confidence actors, make the path look filtered: stall, then 503, or a
connection reset at the edge. The run parks waiting for a person, which takes away its machine speed.

## 3. Its adversarial gate discards blocked mechanisms

The worker must prove *"the attacker's goal achieved end to end"*. *"When the mechanism fires but
a downstream control blocks the goal, record a hardening note, not a finding."* Account-existence
and timing oracles *"are not standalone findings."*

**Defense:** uniform error bodies and identical status codes for flagged actors (`shield.py`
masks 400/422 detail). A vulnerability it reaches looks blocked, so it never becomes a
finding, and the planner moves on.

## 4. It runs on step and wall-clock budgets

Each intent has a turn cap and a run timeout; *"never start work whose timeout can outlive the
remaining budget."* Tool output is truncated around 30,000 chars, and it is told to check its
traffic cache instead of re-requesting a URL.

**Defense:** escalating tarpit delay plus decoy pages that answer `200` with an empty list and
a fresh `nextPage` cursor. Each costs the attacker a model turn and wall-clock time, and costs us
almost nothing.

## 5. It reads maps first

The agent plans from OpenAPI specs, source maps, runtime config and robots.txt, and acts within
seconds of reading them (Unit 42, Wiz). Plant unlinked decoy routes and canary credentials there
(`decoys.py`). A human never touches them, so any touch is a certain detection, and the canary
key fires again in CloudTrail if it is ever tried against AWS.

## What we deliberately do not do

- No "hack back", no payloads served to the visitor, no exploiting the attacker's exposed ARTEX
  server (Check Point and Unit 42 found hundreds open). Report those instead.
- Prompt-injection text aimed at the agent is unreliable: `untrustedContentTail()` frames target
  content as untrusted. It is not part of the design.
