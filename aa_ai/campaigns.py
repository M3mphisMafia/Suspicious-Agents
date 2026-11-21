"""Campaigns: one operator behind many IPs and User-Agents.

Actors that share a client fingerprint (TLS JA4 + header order + Accept headers) and walk the
same routes from 3+ networks are one campaign. Intent detectors then run on their POOLED
requests, so 50 IPs doing 3 requests each still show up as one ID walk or one credential spray.
Real browsers are never linked: every Chrome user shares a fingerprint.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Sequence

from . import detectors
from .detectors import Signal
from .events import Event

MIN_NETS, MIN_ROTATED, CORE_SHARE, MAX_MEMBERS = 3, 4, 0.5, 60
_SEG_ID = re.compile(r"^(\d+|[0-9a-f]{8,}|[a-z]{2,4}_[0-9a-z]{6,}|[0-9a-f-]{16,})$", re.I)


def route(path: str) -> str:
    return "/" + "/".join("{id}" if _SEG_ID.match(s) else s.lower() for s in path.split("?")[0].split("/") if s)


def client_fp(e: Event) -> str:
    """'' for real browsers and for clients we know nothing about."""
    if e.extra.get("browser"):
        return ""
    h = e.extra.get("hfp", "")
    return f"{e.tls_fp}|{h}" if (e.tls_fp or h) else ""


def actor_fp(evs: Sequence[Event]) -> str:
    fps = [client_fp(e) for e in evs]
    fps = [f for f in fps if f]
    return max(set(fps), key=fps.count) if fps else ""


def net_of(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False))
    except ValueError:
        return ip


def qualify(routes: dict[str, set], nets: dict[str, str]) -> list[str]:
    """Members whose routes are mostly ones another member also walked, if they span 3+ networks
    or are 4+ actors (one network, many User-Agents, one tool: a User-Agent rotation list)."""
    seen: dict[str, int] = {}
    for rs in routes.values():
        for r in rs:
            seen[r] = seen.get(r, 0) + 1
    core = {r for r, n in seen.items() if n >= 2}
    q = [k for k, rs in routes.items() if rs and len(rs & core) / len(rs) >= CORE_SHARE]
    return q if len({nets[k] for k in q}) >= MIN_NETS or len(q) >= MIN_ROTATED else []


POOLED = [d for d in detectors.ALL if d.__name__ in detectors.INTENT and d.__name__ != "decoy_touch"]


def link(members: dict[str, list[Event]], confirmed: set[str] = frozenset(), weights: dict | None = None) -> dict[str, Signal]:
    """members: actor key -> its events, all sharing one client fingerprint. Returns a campaign
    signal per linked member: 'campaign' (intent) when the pool attacks or a member is a confirmed
    attacker, else 'fleet' (style: many networks running one tool down one path)."""
    routes = {k: {route(e.path) for e in evs} for k, evs in members.items()}
    nets = {k: net_of(evs[0].src_ip) if evs else k for k, evs in members.items()}
    q = qualify(routes, nets)
    if not q:
        return {}
    w = weights or {}
    pool = sorted((e for k in q for e in members[k]), key=lambda e: e.ts)
    hit = [s for s in (d(pool) for d in POOLED) if s]
    sure = {k for k in q if k in confirmed or detectors.decoy_touch(members[k])}
    detail = f"{len(q)} actors on {len({nets[k] for k in q})} networks share one client fingerprint"
    if sure:
        sig = Signal("campaign", 0.6, f"{detail}; {len(sure)} confirmed attacker(s) among them")
    elif hit:
        sig = Signal("campaign", max(0.5, max(s.weight for s in hit)),
                     f"{detail}; together: {', '.join(s.name for s in hit)}")
    else:
        sig = Signal("fleet", 0.3, detail)
    m = float(w.get(sig.name, 1.0))
    if m <= 0:
        return {}
    sig = Signal(sig.name, round(min(0.99, sig.weight * m), 3), sig.detail)
    return {k: sig for k in q}
