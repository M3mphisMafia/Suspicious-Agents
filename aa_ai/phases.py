"""Tag each request with the agent's working phase, to show HOW it is approaching."""
from __future__ import annotations

from typing import Sequence

from .detectors import CANARY_VALUES
from .events import Event


def phase(e: Event) -> str:
    if e.is_recon:
        return "map"            # specs, source maps, runtime config
    if CANARY_VALUES.search(f"{e.payload} {e.username}"):
        return "probe"          # placeholder values before real payloads
    if e.is_auth:
        return "identity"       # login, reset, OAuth, sign-up
    if e.is_write:
        return "act"
    if e.status in (401, 403, 404):
        return "enumerate"
    return "read"


def timeline(evs: Sequence[Event]) -> list[str]:
    """Collapsed phase sequence, e.g. ['map', 'enumerate', 'identity', 'act', 'read']."""
    out: list[str] = []
    for e in evs:
        p = phase(e)
        if not out or out[-1] != p:
            out.append(p)
    return out[:20]
