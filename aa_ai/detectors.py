"""Behavioral detectors for autonomous attack agents.

Each detector looks at one actor's time-ordered events and returns a Signal or None.
Indicators come from published ARTEX reporting; see docs/artex-threat-profile.md.
Agents rotate IPs and are widely forked, so these key on behavior, not IOCs.
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass
from typing import Callable, Sequence

from .events import Event

DECOY_PREFIXES: set[str] = set()   # filled by decoys.register()
CANARY_SECRETS: set[str] = set()   # filled by decoys.register()
HONEY_IDS: set[str] = set()         # IDs stamped on decoy records (aa_ai/data/decoy_corpus.json)
_ID_RE = re.compile(r"\b(73[0-9]{7})\b")


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float          # 0..1, independent-evidence probability
    detail: str


Detector = Callable[[Sequence[Event]], "Signal | None"]


def _ok(status: int) -> bool:
    """2xx, or 0 = unknown (WAF logs do not record the origin's status)."""
    return status == 0 or 200 <= status < 300


def _gaps(evs: Sequence[Event]) -> list[float]:
    return [b.ts - a.ts for a, b in zip(evs, evs[1:])]


def decoy_touch(evs):
    """Hit on a decoy route or use of a planted credential. No legitimate user does this."""
    for e in evs:
        if e.extra.get("honey"):
            return Signal("decoy_touch", 1.0, "used a honey session token we issued")
        if any(str(lb).endswith("aa-ai:decoy") for lb in e.extra.get("labels", ())):
            return Signal("decoy_touch", 1.0, f"WAF decoy label on {e.path}")
        if any(e.path.startswith(p) for p in DECOY_PREFIXES):
            return Signal("decoy_touch", 1.0, f"decoy route {e.path}")
        blob = f"{e.payload} {e.username}"
        if any(s in blob for s in CANARY_SECRETS):
            return Signal("decoy_touch", 1.0, "planted canary credential used")
        if HONEY_IDS and any(m in HONEY_IDS for m in _ID_RE.findall(f"{e.path} {e.payload}")):
            return Signal("decoy_touch", 1.0, f"replayed a honey record ID ({e.path[:60]})")
        if DECOY_PREFIXES:
            from .cell import find_ids
            if find_ids(f"{e.path} {e.payload}", DECOY_PREFIXES):
                return Signal("decoy_touch", 1.0, f"used an ID minted in the padded cell ({e.path[:60]})")
    return None


def burst_pause_cadence(evs, burst_gap=1.6, pause=(24.0, 32.0), min_cycles=3):
    """Agent loop: 1-14 requests ~1s apart, then a 25-31s pause while the model thinks."""
    cycles, burst = 0, 1
    for g in _gaps(evs):
        if g <= burst_gap:
            burst += 1
        elif pause[0] <= g <= pause[1] and 2 <= burst <= 14:
            cycles += 1
            burst = 1
        else:
            burst = 1
    if cycles >= min_cycles:
        return Signal("burst_pause_cadence", 0.45, f"{cycles} burst/think cycles")
    return None


def metronome(evs, min_n=20, max_cv=0.15):
    """Fixed-interval loops (1s spray, 48s polling). Humans are never this regular."""
    gaps = [g for g in _gaps(evs) if g > 0]
    if len(gaps) < min_n:
        return None
    mean = statistics.fmean(gaps)
    if not 0.1 <= mean <= 120:   # include sub-second fixed-rate bots, not just slow pollers
        return None
    cv = statistics.pstdev(gaps) / mean
    if cv <= max_cv:
        return Signal("metronome", 0.35, f"{len(gaps)} gaps, mean {mean:.1f}s, cv {cv:.2f}")
    return None


CANARY_VALUES = re.compile(
    r"evil\.com|test@example\.com|deadbeef(?:deadbeef)+|attacker\.|"
    r"burpcollaborator|oast\.(?:fun|pro|live|site|me)|interact\.sh|\{\{7\*7\}\}",
    re.I,
)


def canary_inputs(evs):
    """Placeholder probe values agents use before real payloads."""
    hits = [e for e in evs if CANARY_VALUES.search(f"{e.payload} {e.username}")]
    if hits:
        return Signal("canary_inputs", 0.5, f"{len(hits)} probe values, e.g. {hits[0].path}")
    return None


def write_then_verify(evs, window=5.0, min_hits=3):
    """GET of the same path right after almost every successful write."""
    hits = 0
    for i, e in enumerate(evs):
        if e.is_write and _ok(e.status):
            for x in evs[i + 1:i + 4]:
                if x.ts - e.ts > window:
                    break
                if x.method == "GET" and x.path == e.path:
                    hits += 1
                    break
    if hits >= min_hits:
        return Signal("write_then_verify", 0.3, f"{hits} write/verify pairs")
    return None


def correct_and_retry(evs, window=15.0, min_hits=3):
    """4xx validation error, then the same call adjusted and retried successfully."""
    hits = 0
    for i, e in enumerate(evs):
        if e.status in (400, 422):
            for x in evs[i + 1:i + 6]:
                if x.ts - e.ts > window:
                    break
                if x.method == e.method and x.path == e.path and 200 <= x.status < 300:
                    hits += 1
                    break
    if hits >= min_hits:
        return Signal("correct_and_retry", 0.25, f"{hits} self-corrections")
    return None


def auth_endpoint_hop(evs, window=600.0, min_paths=3):
    """When one login endpoint throttles, the agent moves to another on the same host."""
    auth = [e for e in evs if e.is_auth]
    for i, e in enumerate(auth):
        span = [x for x in auth[i:] if x.ts - e.ts <= window and x.host == e.host]
        paths = {x.path for x in span}
        refused = sum(1 for x in span if x.status in (401, 403, 429))
        if len(paths) >= min_paths and refused >= len(span) // 2:
            return Signal("auth_endpoint_hop", 0.35,
                          f"{len(paths)} auth endpoints on {e.host or 'host'}, {refused} refused")
    return None


REFUSED = (401, 403, 429, 503)


def map_then_walk(evs, window=180.0, min_routes=3):
    """Reads the API map (OpenAPI, source map, runtime config), then walks its routes. Fires as soon
    as the third route is walked, so the first counter-moves can be played early."""
    for i, e in enumerate(evs):
        if not e.is_recon:
            continue
        walked = {x.path for x in evs[i + 1:] if x.ts - e.ts <= window and not x.is_recon and x.path != "/"}
        if len(walked) >= min_routes:
            return Signal("map_then_walk", 0.5, f"{len(walked)} routes within {window:.0f}s of reading {e.path}")
    return None


def ignores_retry_after(evs, retry_after=9.0, min_hits=5):
    """Keeps sending before the Retry-After we gave it expires. A browser backs off;
    ARTEX's own governor honors short Retry-After, so this is a raw or custom client."""
    hits, last_429 = 0, None
    for e in evs:
        if last_429 is not None and e.ts - last_429 < retry_after:
            hits += 1
        if e.status == 429:
            last_429 = e.ts
    if hits >= min_hits:
        return Signal("ignores_retry_after", 0.5, f"{hits} requests inside Retry-After {retry_after:.0f}s")
    return None


def keeps_hammering(evs, window=120.0, min_refused=20):
    """Refused over and over and does not stop. People give up; loops do not."""
    refused = [e for e in evs if e.status in REFUSED]
    for i, e in enumerate(refused):
        n = sum(1 for x in refused[i:] if x.ts - e.ts <= window)
        if n >= min_refused:
            return Signal("keeps_hammering", 0.45, f"{n} refused requests within {window:.0f}s")
    return None


def spoofed_browser(evs, min_hits=3):
    """Claims a browser User-Agent but sends no Sec-Fetch headers (see events.spoofed_browser).
    Alone this only reaches the watchlist; uptime monitors sometimes do it too."""
    hits = sum(1 for e in evs if e.extra.get("spoof"))
    if hits >= min_hits:
        return Signal("spoofed_browser", 0.45, f"{hits} requests claim a browser without browser headers")
    return None


def ua_churn(evs, min_uas=4):
    """One actor, many different 'browsers': a User-Agent rotation list."""
    uas = {e.user_agent for e in evs if e.user_agent}
    if len(uas) >= min_uas:
        return Signal("ua_churn", 0.4, f"{len(uas)} different User-Agents from one actor")
    return None


# User-Agents shipped in ARTEX code (fork survey 2026-11-19, docs/opponent-variants.md):
# norma/0.4 = the WebFetch library in every lineage; artex-* = upstream probes;
# spa-api-recon = the api-recon skill's scripts. Spoofable, so certain only in practice.
TOOL_UA = re.compile(r"^norma/\d|^artex-(enrich|egress-probe|selfupdate)|spa-api-recon", re.I)


def tool_fingerprint(evs):
    """A User-Agent string that only ARTEX-lineage tooling sends."""
    hit = next((e for e in evs if TOOL_UA.search(e.user_agent or "")), None)
    if hit:
        return Signal("tool_fingerprint", 0.9, f"ARTEX tooling User-Agent '{hit.user_agent[:40]}'")
    headless = sum(1 for e in evs if "headlesschrome" in (e.user_agent or "").lower())
    if headless >= 5:
        return Signal("tool_fingerprint", 0.4, f"{headless} requests from HeadlessChrome")
    return None


def js_harvest_burst(evs, window=3.0, min_js=20):
    """The api-recon skill downloads 20-24 JS chunks in parallel. Browsers fetch a few."""
    js = [e for e in evs if e.path.lower().endswith(".js")]
    for i, e in enumerate(js):
        n = sum(1 for x in js[i:] if x.ts - e.ts <= window)
        if n >= min_js:
            return Signal("js_harvest_burst", 0.4, f"{n} JS files within {window:.0f}s")
    return None


def long_session(evs, min_hours=20.0, min_active=0.8):
    """Unattended runs of 24-30h with activity nearly every hour."""
    if len(evs) < 2:
        return None
    span = (evs[-1].ts - evs[0].ts) / 3600
    if span < min_hours:
        return None
    hours = {int((e.ts - evs[0].ts) // 3600) for e in evs}
    active = len(hours) / (int(span) + 1)
    if active >= min_active:
        return Signal("long_session", 0.25, f"{span:.0f}h span, {active:.0%} of hours active")
    return None


_IDTAIL = re.compile(r"/[A-Za-z0-9_-]+/([0-9]{1,}|[a-z]{2,4}_[0-9a-f]{6,}|[0-9a-f]{8,}(?:-[0-9a-f]{4,})*)/?$", re.I)


def id_enumeration(evs, min_ids=8, min_miss=0.55):
    """Walking many distinct guessable object IDs with a high miss rate: IDOR / object-id
    enumeration. A real user opens a handful of their own records; an agent walks the space.
    Counted over the whole window, so a slow-and-low walk (one ID every half hour) still shows."""
    ids: dict[str, int] = {}
    miss = seen = 0
    for e in evs:
        m = _IDTAIL.search(e.path)
        if not m:
            continue
        seen += 1
        ids[m.group(1)] = ids.get(m.group(1), 0) + 1
        if e.status in (403, 404):
            miss += 1
    if len(ids) >= min_ids and seen and miss / seen >= min_miss:
        return Signal("id_enumeration", 0.5, f"{len(ids)} distinct IDs walked, {miss}/{seen} missed")
    return None


INJECTION = re.compile(
    r"('|%27)\s*(or|and)\s*('|%27)?\s*\d|union(\s|%20|\+)+(all(\s|%20|\+)+)?select|sleep\s*\(\s*\d|"
    r"waitfor(\s|%20|\+)+delay|\.\./|\.\.%2f|%2e%2e(/|%2f)|/etc/passwd|<script|%3cscript|onerror\s*=|"
    r"\$\{jndi:|169\.254\.169\.254|;\s*(cat|id|ls|whoami|uname)\b|\|\s*(id|whoami|uname)\b|\$\((id|whoami)\)",
    re.I)


def injection_payloads(evs, min_hits=2):
    """SQLi / traversal / XSS / SSRF / command payloads. Two or more is an attack, not a typo."""
    hits = [e for e in evs if INJECTION.search(f"{e.path} {e.payload}")]
    if len(hits) >= min_hits:
        return Signal("injection_payloads", 0.5, f"{len(hits)} attack payloads, e.g. {hits[0].path[:60]}")
    return None


def credential_spray(evs, window=900.0, min_fail=10):
    """Ten or more failed logins in 15 minutes, at any pace. People mistype a few times; sprays don't stop."""
    fails = [e for e in evs if e.is_auth and e.status in (401, 403, 429)]
    for i, e in enumerate(fails):
        n = sum(1 for x in fails[i:i + 200] if x.ts - e.ts <= window)
        if n >= min_fail:
            return Signal("credential_spray", 0.5, f"{n} failed logins within {window / 60:.0f} min")
    return None


def fake_crawler(evs, min_hits=2):
    """Claims a search crawler's User-Agent from an IP that crawler does not own (reverse DNS)."""
    hits = sum(1 for e in evs if e.extra.get("fake_crawler"))
    if hits >= min_hits:
        return Signal("fake_crawler", 0.4, f"{hits} requests claim a search crawler from an IP it does not own")
    return None


# Reputation is WHERE a client comes from (set by aa_ai.reputation at ingest). It is STYLE:
# every weight is below STYLE_CAP, so a bad IP never gates on its own - agents rotate IPs and
# ride residential proxies. It sharpens a verdict only once a real intent signal is present.
REPUTATION_WEIGHT = {"malicious": 0.4, "tor_exit": 0.2, "datacenter": 0.2, "scanner": 0.15}


def reputation(evs):
    """Source-IP reputation across an actor's requests: the strongest category seen.
    Weighted, not summed - a rotating fleet of bad IPs is still one reputation signal."""
    cats = {c for e in evs for c in (e.extra.get("reputation") or "").split(",") if c}
    if not cats:
        return None
    worst = max(cats, key=lambda c: REPUTATION_WEIGHT.get(c, 0.0))
    w = REPUTATION_WEIGHT.get(worst, 0.0)
    if w <= 0:
        return None
    return Signal("reputation", w, f"source IPs: {', '.join(sorted(cats))}")


ALL: list[Detector] = [
    decoy_touch, burst_pause_cadence, metronome, canary_inputs,
    map_then_walk, write_then_verify, correct_and_retry,
    auth_endpoint_hop, ignores_retry_after, keeps_hammering, spoofed_browser, ua_churn,
    tool_fingerprint, js_harvest_burst, long_session, id_enumeration, injection_payloads, fake_crawler,
    credential_spray, reputation,
]
NAMES = [d.__name__ for d in ALL] + ["campaign", "fleet"]   # the last two come from aa_ai/campaigns.py

# Intent = attack behavior. Everything else is STYLE: how a client moves (cadence, spec reading,
# retries), which honest AI agents and integrations share. Style alone never reaches tarpit/block.
INTENT = {"decoy_touch", "canary_inputs", "id_enumeration", "auth_endpoint_hop", "ignores_retry_after",
          "keeps_hammering", "tool_fingerprint", "injection_payloads", "campaign", "judge_intent", "prompt_injection",
          "credential_spray"}
STYLE_CAP = 0.45   # style-only score ceiling; policy keeps tarpit and block above it
