"""The Dashboard tab's live feed: a small, bounded sample of what the edge sees.

  ingest   each log batch keeps a stratified reservoir of at most PER_BATCH requests (rare first:
           decoys, known agents, challenges, verified clients; then floods; then the rest). That is
           a few CPU steps per request and no I/O; the batch writes ONE LIVE#<minute> row (2-hour
           TTL), and none once that minute already holds PER_MINUTE sampled requests
  tick     the last WINDOW_MIN minutes become data/live.json: at most CAP events, newest first,
           balanced across classes so rare ones still show, plus per-class and per-aspect counts
           for the last full minute (the sample's weighted mix times that minute's real requests)

Not Firehose: the scene needs a few hundred representative lights a minute, not every request.
Keeping or replaying every request is what would need Firehose (or WAF logs to S3).
"""
from __future__ import annotations

import json
import random
import re
import time
import uuid
from collections import Counter

from . import detectors, flood, moves
from .events import decoy_tag
from .scoring import actor_key

CLASSES = ("allow", "verified", "watch", "challenge", "tarpit", "cell", "block", "flood", "decoy")
ASPECTS = ("login", "api", "search", "checkout", "admin", "decoys", "static", "other")
FIELDS = ("t", "c", "app", "z", "m", "p", "cc", "a", "ip")
# unmeasured starting points
CAPS = {"rare": 16, "flood": 8, "other": 16}     # per batch: PER_BATCH = 40
PER_BATCH = sum(CAPS.values())
PER_MINUTE = 400        # sampled requests stored per minute, across all batches
LIVE_TTL = 2 * 3600
WINDOW_MIN = 3          # minutes the scene replays
CAP = 300               # events in live.json

_ACCOUNT = re.compile(r"(^|/)(account|accounts|profile|session|sessions|logout|me)(/|$)")
_CHECKOUT = re.compile(r"(^|/)(cart|carts|basket|checkout|orders?|payments?|pay|billing|invoices?)([-_.][a-z0-9_.-]*)?(/|$)")
_ADMIN = re.compile(r"(^|/)(admin|administrator|wp-admin|manage|management|console|internal|staff)(/|$)")
_SEARCH = re.compile(r"(^|/)(search|find|query|lookup)([-_.][a-z0-9_.-]*)?(/|$)")


def _decoy(e) -> bool:
    return (bool(e.extra.get("honey")) or bool(decoy_tag(e.path))
            or any(str(lb).endswith("aa-ai:decoy") for lb in e.extra.get("labels", ()))
            or any(e.path.startswith(p) for p in detectors.DECOY_PREFIXES))


def aspect(e) -> str:
    """Which part of the app a request is for, from its path."""
    p = (e.path or "/").split("?", 1)[0].lower()
    if _decoy(e):
        return "decoys"
    if e.is_auth or _ACCOUNT.search(p):
        return "login"
    if _CHECKOUT.search(p):
        return "checkout"
    if _ADMIN.search(p):
        return "admin"
    if _SEARCH.search(p):
        return "search"
    if p.startswith("/api") or "/graphql" in p or e.is_recon:
        return "api"
    if (e.method or "GET").upper() in ("GET", "HEAD"):
        return "static"       # pages and assets
    return "other"


def stratum(e, guarded: bool, agent_ips) -> str:
    """Cheap, at ingest: which reservoir a request competes in."""
    if (_decoy(e) or e.src_ip in agent_ips or e.extra.get("verified")
            or e.extra.get("action") in ("CHALLENGE", "CAPTCHA")):
        return "rare"
    return "flood" if guarded else "other"


def classify(e, guarded: bool, verdict: str = "", watched: bool = False, cell_ips=frozenset()) -> str:
    """What Undertow did, or decided, about one request."""
    action = e.extra.get("action", "")
    if _decoy(e):
        return "decoy"
    if guarded or (e.extra.get("rule") in flood.FLOOD_RULES and action in ("BLOCK", "CHALLENGE")):
        return "flood"
    if e.src_ip in cell_ips:
        return "cell"
    if action == "BLOCK" or verdict == "block":
        return "block"
    if action in ("CHALLENGE", "CAPTCHA"):
        return "challenge"
    if verdict == "tarpit":
        return "tarpit"
    if watched or verdict == "watch":
        return "watch"
    if e.extra.get("verified"):
        return "verified"
    return "allow"


class Sampler:
    """Per-batch stratified reservoir: O(1) per request, at most PER_BATCH kept."""

    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random()
        self.res: dict[str, list] = {k: [] for k in CAPS}
        self.n: Counter = Counter()

    def offer(self, s: str, item):
        self.n[s] += 1
        r, cap = self.res[s], CAPS[s]
        if len(r) < cap:
            r.append(item)
        else:
            j = self.rng.randrange(self.n[s])
            if j < cap:
                r[j] = item

    def __len__(self):
        return sum(len(r) for r in self.res.values())

    def items(self):
        """(item, weight): each kept request stands for weight requests of its stratum."""
        for s, r in self.res.items():
            for it in r:
                yield it, self.n[s] / len(r)


def compact(e, cls: str, weight: float) -> list:
    return [round(e.ts, 1), cls, (e.host or "").lower().split(":")[0][:60], aspect(e), (e.method or "")[:7],
            (e.path or "/").split("?", 1)[0][:60], str(e.extra.get("country", ""))[:2],
            moves.tag(actor_key(e)), e.src_ip, round(weight, 2)]


def row(sample: list[list], now: float, minute: str) -> dict:
    return {"pk": f"LIVE#{minute}", "sk": f"{now:017.3f}#{uuid.uuid4().hex[:8]}",
            "ev": json.dumps(sample, separators=(",", ":")), "exp": int(now + LIVE_TTL)}


# ---------- the tick: data/live.json ----------

def assemble(rows: list[dict], req: dict[str, int], now: float, policy: dict | None = None,
             minute_key=None) -> dict:
    """Rows -> the scene's feed. req: requests per minute key (STATM)."""
    from .scorer import minute_key as mk
    minute_key = minute_key or mk
    evs = []
    for r in rows:
        try:
            evs += [(r["pk"].split("#", 1)[1], x) for x in json.loads(r.get("ev") or "[]")]
        except (ValueError, IndexError):
            continue
    evs.sort(key=lambda mx: -mx[1][0])
    by: dict[str, list] = {c: [] for c in CLASSES}
    for _, x in evs:
        by.setdefault(x[1], []).append(x)
    picked, i = [], 0
    while len(picked) < CAP and any(i < len(v) for v in by.values()):
        for c in CLASSES:             # round robin, newest first within each class
            if i < len(by[c]) and len(picked) < CAP:
                picked.append(by[c][i])
        i += 1
    picked.sort(key=lambda x: -x[0])
    last = minute_key((int(now // 60) - 1) * 60)
    wc, wz = Counter(), Counter()
    for m, x in evs:
        if m == last:
            wc[x[1]] += x[9]
            wz[x[3]] += x[9]
    total, n = sum(wc.values()), int(req.get(last, 0))
    p = policy or {}
    return {
        "generated": int(now), "mode": p.get("mode", "observe"), "edge": p.get("edge", "cell"),
        "window": [evs[-1][1][0], evs[0][1][0]] if evs else None,
        "delay": round(now - evs[0][1][0]) if evs else None,
        "classes": list(CLASSES), "aspects": list(ASPECTS),
        "apps": sorted({x[2] for _, x in evs if x[2]} | set((p.get("apps") or {}).keys()))[:50],
        "events": [dict(zip(FIELDS, x[:9])) for x in picked],
        "counts": {"minute": last, "requests": n,
                   "class": {c: round(n * wc[c] / total) if total else 0 for c in CLASSES},
                   "aspect": {z: round(n * wz[z] / total) if total else 0 for z in ASPECTS}},
    }


def publish(table, s3, bucket: str, policy: dict, now: float | None = None, prefix: str = "data/") -> str:
    """Write data/live.json from the last WINDOW_MIN minutes of samples. Returns the key."""
    from .scorer import _active, minute_key
    now = now or time.time()
    cur = int(now // 60)
    rows, req = [], {}
    for m in range(cur - WINDOW_MIN, cur + 1):
        k = minute_key(m * 60)
        rows += _active(table, f"LIVE#{k}", now)
        s = table.get_item(Key={"pk": "STATM", "sk": k}).get("Item") or {}
        req[k] = int(s.get("req", 0))
    body = json.dumps(assemble(rows, req, now, policy), separators=(",", ":"))
    key = f"{prefix}live.json"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode(), ContentType="application/json", CacheControl="no-store")
    return key
