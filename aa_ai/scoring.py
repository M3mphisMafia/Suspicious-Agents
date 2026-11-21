"""Group events by actor, run detectors, combine into a verdict."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from . import detectors
from .detectors import Signal
from .events import Event

WATCH, TARPIT, BLOCK = 0.30, 0.50, 0.80


def actor_key(e: Event) -> str:
    """/24 (/48 v6) + UA (+ JA4). Never JA4 alone for real browsers: every Chrome user shares
    one JA4. A client that FAKES a browser (no Sec-Fetch headers) is keyed by its TLS
    fingerprint only, so a fork rotating User-Agents and proxy IPs stays one actor."""
    if e.extra.get("spoof") and e.tls_fp:
        return f"spoof|tls:{e.tls_fp}"
    try:
        ip = ipaddress.ip_address(e.src_ip)
        net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False)
    except ValueError:
        net = e.src_ip
    key = f"net:{net}|ua:{e.user_agent[:80]}"
    return f"{key}|tls:{e.tls_fp}" if e.tls_fp else key


def combine(signals: Sequence[Signal]) -> float:
    """1 - prod(1 - w). Without an intent signal the score caps at STYLE_CAP: looking like an
    AI agent is never enough to slow or block one; attacking is."""
    p = 1.0
    for s in signals:
        p *= 1 - s.weight
    score = round(1 - p, 3)
    if signals and not any(s.name in detectors.INTENT for s in signals):
        score = min(score, detectors.STYLE_CAP)
    return score


def verdict(score: float, thresholds: dict | None = None) -> str:
    t = thresholds or {}
    if score >= t.get("block", BLOCK):
        return "block"
    if score >= t.get("tarpit", TARPIT):
        return "tarpit"
    if score >= t.get("watch", WATCH):
        return "watch"
    return "allow"


@dataclass
class ActorReport:
    key: str
    events: int
    first: float
    last: float
    ips: set[str] = field(default_factory=set)
    signals: list[Signal] = field(default_factory=list)

    @property
    def score(self) -> float:
        return combine(self.signals)

    @property
    def verdict(self) -> str:
        return verdict(self.score)


def evaluate(evs: Sequence[Event], dets=None, weights: dict | None = None) -> list[Signal]:
    """weights: per-detector multiplier from the operator policy (0 disables one).
    decoy_touch stays certain unless it is switched off entirely. Verified requests
    (integration key, signed agent, real crawler) feed intent detectors only."""
    out = []
    unverified = [e for e in evs if not e.extra.get("verified")]
    for d in dets or detectors.ALL:
        src = evs if d.__name__ in detectors.INTENT else unverified
        s = d(src) if src else None
        if not s:
            continue
        m = float((weights or {}).get(s.name, 1.0))
        if m <= 0:
            continue
        w = s.weight if s.weight >= 1.0 else min(0.99, s.weight * m)
        out.append(Signal(s.name, round(w, 3), s.detail))
    return out


def analyze(events: Iterable[Event]) -> list[ActorReport]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        groups[actor_key(e)].append(e)
    reports = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.ts)
        reports.append(ActorReport(key, len(evs), evs[0].ts, evs[-1].ts,
                                   {e.src_ip for e in evs}, evaluate(evs)))
    reports.sort(key=lambda r: r.score, reverse=True)
    return reports


def distributed_spray(events: Iterable[Event], window=3600.0, min_attempts=10, min_sources=3):
    """Same account hit from many rotating sources: the per-target view IP blocking misses."""
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.is_auth and e.username and e.status in (400, 401, 403, 429):
            by_user[e.username.lower()].append(e)
    out = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e.ts)
        for i, e in enumerate(evs):
            span = [x for x in evs[i:] if x.ts - e.ts <= window]
            srcs = {x.src_ip for x in span}
            if len(span) >= min_attempts and len(srcs) >= min_sources:
                out.append((user, len(span), len(srcs)))
                break
    return out
