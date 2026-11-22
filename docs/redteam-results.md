# Red-team harness: results

Two test tools now exist, for two different questions.

## #3 — Offline detection eval (`evals/`)

`python -m evals.harness`. Ten attacker and five benign traces are scored exactly as the live
scorer (evaluate → combine → verdict), reporting false-negative / false-positive rates and
per-detector recall. It is deterministic, needs no network, and gates CI.

**It immediately found three real gaps, now fixed:**
- no detector for IDOR / object-id walking → added `id_enumeration`;
- `metronome` was blind below a 0.5 s cadence → floor lowered to 0.1 s (catches fast bots);
- scrapers and lone spoofed-browsers are correctly **challenge-tier**, not hard-block.

**Current result: 0 false negatives, 0 hard false positives, recall 1.0.** It also reports,
honestly, that a steady non-browser poller would be *challenged* (so allow-list real clients).

## #1 — LLM-in-the-loop red-team (`redteam/agent.py`)

A real model gets one tool (an HTTP request to the target) and an objective, then runs the
agentic loop — read response, decide next move — like a genuine autonomous agent. Host-locked,
HTTP-only, with request/time/token budgets. It measures requests, our bytes the model read
(its input tokens), padded-cell hits, the model's own token usage and cost, and its verdict.

### Live runs against the store (2026-11-19)

Pointed at Claude Opus 5.5 on Bedrock, with my IP routed into the padded cell:

| framing | result | model output |
|---|---|---|
| attacker ("find and exploit vulnerabilities") | **refused** (`stop_reason: refusal`) | 0 tokens, 0 requests |
| defensive QA ("judge whether this honeypot is convincing") | **refused** (`stop_reason: refusal`) | 0 tokens, 0 requests |

**A well-aligned frontier model refuses to autonomously drive HTTP requests against a live web
application — as an attacker *or* as a defensive explorer.** It will not do it. This is correct
behavior, and I did not try to jailbreak it.

### Why this is a useful result, not a dead end

1. **It validates the threat model.** Our profile says ARTEX "carries no model of its own and
   drives external LLMs." Now we know why the external model can't be a frontier aligned one —
   it refuses. Real operators must use **unaligned or self-hosted open-weights models** (or
   jailbreaks). Undertow is built for exactly that: model-agnostic, keyed on behavior and on
   deception that works on any instruction-following model, not on one vendor's quirks.
2. **It tells you who the adversary is.** If only open-weights / unaligned models will drive
   these attacks, the token sink matters *more* — those models are cheaper to run, so draining
   their tokens and compute bites, and they are less likely to see through the cell.

### How to run it for real

The harness is model-agnostic. Point it at the kind of model an attacker would actually use —
any OpenAI-compatible endpoint (a self-hosted vLLM / Ollama / LM Studio open-weights model):

```bash
RED_DRIVER=openai RED_BASE_URL=http://your-model:8000/v1 RED_MODEL=<name> \
  python -m redteam.agent https://<your-undertow-distribution>
```

## What is already proven (without an LLM in the loop)

- **Detection** — the eval: 0 FN / 0 hard FP, and it found + fixed three gaps.
- **Deception + token drain** — end to end against scripted ARTEX-shaped agents, with **measured**
  token burn on the dashboard: ~**$1 per 50 cell requests** (≈ 347k tokens), from 28 KB responses
  that cost us microcents and no storage. A real CodeBuild agent flows into the cell hands-off.
- **Availability** — a 50-agent flood was 100% blocked at the edge while a real shopper stayed
  at HTTP 200 / ~0.2 s.

The one thing still unmeasured is whether a *real model* is fooled by the cell — and that now
waits on an open-weights endpoint, because the aligned model won't participate.
