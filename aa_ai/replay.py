"""One agent, replayed: every request it made in the window, what answered it, and why we decided."""
from __future__ import annotations

import base64
import time

from . import campaigns, detectors
from .moves import PLAYBOOK
from .phases import phase
from .scorer import WINDOW, _events_of, camp_members
from .snapshot import _plain, cell_view

CELL_ENTRY = {"entered_cell", "edge_cell"}
MAX_ROWS = 300


def key_from_path(path: str) -> str:
    """/_undertow/api/actor/<base64url(actor key)>: the API path forwards no query string."""
    seg = path.rsplit("/actor/", 1)[-1].strip("/")
    if not seg or not all(c.isalnum() or c in "-_" for c in seg):   # the decoder would silently drop junk
        raise ValueError("bad agent id")
    key = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8", "strict")[:600]
    if not key:
        raise ValueError("bad agent id")
    return key


def _marks(e) -> list[str]:
    out = []
    if e.extra.get("honey"):
        out.append("honey token")
    if any(str(lb).endswith("aa-ai:decoy") for lb in e.extra.get("labels", ())) or \
            any(e.path.startswith(p) for p in detectors.DECOY_PREFIXES):
        out.append("decoy")
    if detectors.INJECTION.search(f"{e.path} {e.payload}"):
        out.append("attack payload")
    if detectors.CANARY_VALUES.search(f"{e.payload} {e.username}"):
        out.append("probe value")
    if e.extra.get("verified"):
        out.append(f"verified {e.extra['verified']}")
    if e.extra.get("fake_crawler"):
        out.append("fake crawler")
    return out


def timeline(table, key: str, now: float | None = None) -> dict:
    now = now or time.time()
    evs = _events_of(table, key, now)
    flag = table.get_item(Key={"pk": "FLAG", "sk": key}).get("Item") or \
        table.get_item(Key={"pk": "WATCH", "sk": key}).get("Item") or {}
    r = table.query(KeyConditionExpression="pk = :k AND sk >= :s",
                    ExpressionAttributeValues={":k": "MOVE", ":s": f"{now - WINDOW:017.3f}"})
    mine = [m for m in r.get("Items", []) if m.get("actor") == key]
    cell_at = min((float(m["sk"].split("#", 1)[0]) for m in mine if m.get("move") in CELL_ENTRY), default=None)
    rows = []
    for e in evs[-MAX_ROWS:]:
        served = "edge" if e.status in (429, 403) else "cell" if cell_at is not None and e.ts >= cell_at else "app"
        rows.append({"ts": e.ts, "m": e.method, "path": e.path[:200], "q": e.payload[:120], "status": e.status,
                     "ip": e.src_ip, "phase": phase(e), "served": served, "marks": _marks(e)})
    fp = campaigns.actor_fp(evs) if evs else ""
    camp = None
    if fp:
        ms = camp_members(table, fp, now)
        camp = {"fp": fp[:40], "actors": len(ms), "nets": len({m.get("net") for m in ms})} if len(ms) > 1 else None
    signals = [str(s) for s in flag.get("signals", [])]
    return _plain({
        "actor": key, "ips": sorted({e.src_ip for e in evs})[-20:] or list(flag.get("ips", [])),
        "uas": sorted({e.user_agent for e in evs})[:5], "verdict": flag.get("verdict", "watch" if flag else "allow"),
        "score": flag.get("score", 0), "signals": signals, "labeled": flag.get("labeled", ""),
        "first": evs[0].ts if evs else None, "last": evs[-1].ts if evs else None, "requests": len(evs),
        "served": {k: sum(1 for x in rows if x["served"] == k) for k in ("app", "edge", "cell")},
        "events": rows, "campaign": camp,
        "moves": [{"ts": float(m["sk"].split("#", 1)[0]), "move": m.get("move", ""), "side": m.get("side", "us"),
                   "detail": m.get("detail", ""), "play": PLAYBOOK.get(m.get("move", ""), "")}
                  for m in sorted(mine, key=lambda m: m["sk"])][-80:],
        "cell": (cell_view(mine, now)["agents"] or [None])[0],
    })
