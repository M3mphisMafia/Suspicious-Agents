"""Build the dashboard's data-{1,6,24}.json from scorer state and publish them to S3.

Runs on the scorer's 1-minute schedule ({"action": "snapshot"}). The files carry
attacker IPs and the allow list, so they live under data/, which CloudFront does not
serve; the dashboard reads them through the API, which requires a Cognito sign-in.
"""
from __future__ import annotations

import json
import os
import re
import time
from decimal import Decimal

from . import costs, flood
from .detectors import NAMES as DETECTOR_NAMES
from .moves import PLAYBOOK
from .phases import timeline
from .scorer import MAX_EVENTS, WINDOW, _active, _event, hour_key, minute_key

WINDOWS = (1, 6, 24)
DATA_PREFIX = "data/"   # NOT under _undertow/: CloudFront cannot serve it; signed-in users read it via the API
TOP_PHASES = 6
RETRY_AFTER_S = 9
CELL_MOVES = {"entered_cell", "edge_cell", "rabbit_hole", "fake_write", "polled_forever", "cell_summary"}
CELL_QUIET_S = 600     # no cell activity for 10 minutes: it stopped
# what an agent pays per turn, at representative list prices (their bill, not ours):
# input = our bytes it reads (~4 bytes a token, measured); output = its reasoning + tool call (estimated)
IN_PRICE, OUT_PRICE, OUT_PER_TURN = 3.0, 15.0, 150


def agent_cost(bytes_: int, turns: int) -> tuple[int, float]:
    tokens = bytes_ // 4
    return tokens, round(tokens / 1e6 * IN_PRICE + turns * OUT_PER_TURN / 1e6 * OUT_PRICE, 2)


def cell_view(moves: list[dict], now: float) -> dict:
    """Who is in the padded cell, how much it has absorbed, and who went quiet."""
    agents: dict[str, dict] = {}
    for m in sorted(moves, key=lambda m: m["sk"]):
        if m.get("move") not in CELL_MOVES:
            continue
        ts = float(m["sk"].split("#", 1)[0])
        a = agents.setdefault(m.get("actor", ""), {"actor": m.get("actor", ""), "ip": m.get("ip", ""), "first": ts,
                                                   "last": ts, "requests": 0, "depth": 0, "seconds": 0, "marks": []})
        a["last"], a["ip"] = max(a["last"], ts), m.get("ip") or a["ip"]
        if m["move"] == "cell_summary":
            kv = dict(re.findall(r"(\w+)=(\d+)", m.get("detail", "")))
            a["requests"] = max(a["requests"], int(kv.get("requests", 0)))
            a["depth"] = max(a["depth"], int(kv.get("depth", 0)))
            a["seconds"] = max(a["seconds"], int(kv.get("seconds", 0)))
            a["bytes"] = max(a.get("bytes", 0), int(kv.get("bytes", 0)))
        elif m["move"] in ("rabbit_hole", "fake_write", "polled_forever") and m["move"] not in a["marks"]:
            a["marks"].append(m["move"])
    for a in agents.values():
        a["seconds"] = max(a["seconds"], int(a["last"] - a["first"]))
        a["status"] = "in" if now - a["last"] < CELL_QUIET_S else "quiet"
        a["tokens"], a["cost"] = agent_cost(a.get("bytes", 0), a["requests"])
    rows = sorted(agents.values(), key=lambda a: (a["status"] != "in", -a["last"]))
    served = sum(a.get("bytes", 0) for a in rows)
    tokens, cost = agent_cost(served, sum(a["requests"] for a in rows))
    return {"agents": rows, "requests": sum(a["requests"] for a in rows),
            "minutes": round(sum(a["seconds"] for a in rows) / 60, 1),
            "bytes": served, "tokens": tokens, "cost": cost}


def campaign_view(items: list[dict], flags: list[dict]) -> list[dict]:
    """Campaigns from the CAMP membership rows: one tool, one path, 3+ networks."""
    from collections import Counter, defaultdict

    from .campaigns import qualify
    by: dict[str, list[dict]] = defaultdict(list)
    for i in items:
        by[i.get("fp", "")].append(i)
    fl = {f["sk"]: f for f in flags}
    out = []
    for fp, ms in by.items():
        q = set(qualify({m["actor"]: set(m.get("routes", [])) for m in ms}, {m["actor"]: m.get("net", "") for m in ms}))
        if not q:
            continue
        qm = [m for m in ms if m["actor"] in q]
        sigs = [s for k in q for s in (fl.get(k) or {}).get("signals", [])]
        ips = sorted({ip for m in qm for ip in m.get("ips", [])})
        out.append({"fp": fp[:40], "actors": len(q), "nets": len({m.get("net") for m in qm}), "ips": ips[:8],
                    "ip_count": len(ips), "routes": [r for r, _ in Counter(r for m in qm for r in m.get("routes", [])).most_common(5)],
                    "status": "confirmed" if any((fl.get(k) or {}).get("confirmed") for k in q)
                    else "attacking" if any(str(s).startswith("campaign") for s in sigs)
                    or any((fl.get(k) or {}).get("verdict") in ("tarpit", "block") for k in q) else "fleet",
                    "blocked": sum(1 for k in q if (fl.get(k) or {}).get("verdict") == "block"),
                    "last": max(int(m.get("last", 0)) for m in qm), "members": sorted(q)[:20]})
    return sorted(out, key=lambda c: (c["status"] == "fleet", -c["actors"]))[:10]


def apps_view(stath: list[dict], flags: list[dict], conf: dict, lo: str) -> list[dict]:
    """Each app behind the engine: its traffic in the window and agents flagged against it."""
    req: dict[str, int] = {}
    for s in stath:
        hour, _, host = s["sk"].partition("#")
        if hour >= lo and host:
            req[host] = req.get(host, 0) + int(s.get("req", 0))
    hosts = set(req) | set(conf)
    return sorted(({"host": h, "name": (conf.get(h) or {}).get("name", ""), "origin": (conf.get(h) or {}).get("origin", ""),
                    "requests": req.get(h, 0), "flagged": sum(1 for f in flags if f.get("app") == h),
                    "custom": bool((conf.get(h) or {}).get("thresholds") or (conf.get(h) or {}).get("weights"))}
                   for h in hosts), key=lambda a: -a["requests"])[:50]


def _all(table, pk: str) -> list[dict]:
    items, kw = [], {"KeyConditionExpression": "pk = :f", "ExpressionAttributeValues": {":f": pk}}
    while True:
        r = table.query(**kw)
        items += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            return items
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _plain(o):
    if isinstance(o, Decimal):
        return int(o) if o == int(o) else float(o)
    if isinstance(o, dict):
        return {k: _plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_plain(v) for v in o]
    return o


def _phases(table, key: str, now: float) -> list[str]:
    r = table.query(KeyConditionExpression="pk = :k AND sk >= :s",
                    ExpressionAttributeValues={":k": key, ":s": f"{now - WINDOW:017.3f}"},
                    ScanIndexForward=False, Limit=MAX_EVENTS)
    return timeline(sorted((_event(i) for i in r.get("Items", [])), key=lambda e: e.ts))


METRICS = ("req", "refused", "auth", "recon", "decoy")
BUCKET_MIN = 5


def anomalies(statm: list[dict], now: float) -> dict:
    """Last 5 minutes against 5-minute buckets from the previous 24h (z-score).
    Needs ~1h of history before it judges; until then it says it is learning."""
    by_min = {s["sk"]: s for s in statm}
    cur_min = int(now // 60)

    def bucket(end_min: int) -> dict:
        out = {m: 0 for m in METRICS}
        for i in range(BUCKET_MIN):
            s = by_min.get(minute_key((end_min - i) * 60), {})
            for m in METRICS:
                out[m] += int(s.get(m, 0))
        return out

    now_b = bucket(cur_min)
    base = [bucket(cur_min - BUCKET_MIN * k) for k in range(12, 24 * 12)]   # skip the last hour
    base = [b for b in base if any(b.values())] or []
    series = [int(by_min.get(minute_key((cur_min - i) * 60), {}).get("req", 0)) for i in range(59, -1, -1)]
    out = {"learning": len(base) < 12, "series": series, "flags": [], "now": now_b}
    if out["learning"]:
        return out
    for m in METRICS:
        vals = [b[m] for b in base]
        mean = sum(vals) / len(vals)
        sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
        z = (now_b[m] - mean) / max(sd, mean ** 0.5, 1.0)   # counts vary ~sqrt(mean) even when steady
        if z >= 3 and now_b[m] >= 5:
            out["flags"].append({"metric": m, "now": now_b[m], "baseline": round(mean, 1), "z": round(z, 1)})
    return out


def build(table, policy, hours: int, now: float | None = None, _cache=None) -> dict:
    now = now or time.time()
    if isinstance(policy, str):          # older callers passed just the mode
        policy = {"mode": policy}
    c = _cache if _cache is not None else {}
    if "flags" not in c:
        allflags = _plain(_active(table, "FLAG", now))
        # flood IPs get their own card: thousands of them would bury the agents in every agent view
        c["flags"] = sorted((f for f in allflags if not f.get("flood")), key=lambda f: -f["score"])
        c["flood_flagged"] = len(allflags) - len(c["flags"])
        c["flood"] = table.get_item(Key=flood.STATE).get("Item") or {}
        c["floodcount"] = _plain(_active(table, "FLOODCOUNT", now))
        c["budget"] = costs.view(table.get_item(Key={"pk": "COSTSUM", "sk": "current"}).get("Item"))
        c["watch"] = sorted(_plain(_active(table, "WATCH", now)), key=lambda w: -w["score"])
        c["stats"] = _plain(_active(table, "STAT", now))
        c["statm"] = _plain(_active(table, "STATM", now))
        c["decoys"] = _plain(_active(table, "DECOY", now))
        c["labels"] = _all(table, "LABEL")
        c["det"] = _plain(_all(table, "DET"))
        c["uas"] = _plain(_active(table, "UA", now))
        c["allmoves"] = _plain(_active(table, "MOVE", now))
        c["moves"] = sorted((m for m in c["allmoves"] if m.get("move") != "cell_summary"),
                            key=lambda m: m["sk"], reverse=True)[:80]
        c["audit"] = sorted(_plain(_active(table, "AUDIT", now)), key=lambda m: m["sk"], reverse=True)[:30]
        c["challenges"] = _plain(_active(table, "CHALLENGE", now))
        c["allows"] = _plain(_active(table, "ALLOW", now))
        c["alerts"] = sorted(_plain(_active(table, "ALERT", now)), key=lambda a: a["sk"], reverse=True)[:20]
        c["judge"] = sorted(_plain(_active(table, "JUDGE", now)), key=lambda a: a["sk"], reverse=True)[:25]
        c["judgecount"] = _plain(_active(table, "JUDGECOUNT", now))
        c["campaigns"] = campaign_view(_plain(_active(table, "CAMP", now)), c["flags"])
        c["stath"] = _plain(_active(table, "STATH", now))
        c.setdefault("subs", [])
        c["phases"] = {f["sk"]: _phases(table, f["sk"], now) for f in c["flags"][:TOP_PHASES]}
    since = now - hours * 3600
    lo = hour_key(since)
    stats = [s for s in c["stats"] if s["sk"] >= lo]
    req = sum(s.get("req", 0) for s in stats)
    seen = sum(s.get("actors", 0) for s in stats)
    r429 = sum(s.get("r429", 0) for s in stats)
    verified = sum(s.get("verified", 0) for s in stats)
    reputation = sum(s.get("reputation", 0) for s in stats)

    flags = c["flags"]
    block = sum(f["verdict"] == "block" for f in flags)
    tarpit = sum(f["verdict"] == "tarpit" for f in flags)
    watch = len(c["watch"])
    actors = [{
        "key": f["sk"], "ips": f["ips"], "score": f["score"], "verdict": f["verdict"],
        "signals": [s.split(":", 1)[0] for s in f.get("signals", [])],
        "exp": f["exp"], "manual": bool(f.get("manual")), "tag": f.get("tag", ""), "labeled": f.get("labeled", ""),
        "app": f.get("app", ""),
        "series": [p for p in f.get("history", []) if p[0] >= since] or [[int(now), f["score"]]],
        "phases": c["phases"].get(f["sk"], []),
    } for f in flags[:20]]
    weights = policy.get("weights", {})
    det_stats = {d["sk"]: d for d in c["det"]}
    chal_ips = {ch["sk"] for ch in c["challenges"]}
    decoys = sorted(({"ts": float(d["sk"].split("#", 1)[0]), "path": d["path"], "ip": d["ip"], "replay": False}
                     for d in c["decoys"]), key=lambda d: -d["ts"])
    decoys = [d for d in decoys if d["ts"] >= since]
    fp7 = sum(1 for lb in c["labels"] if float(lb["sk"].split("#", 1)[0]) >= now - 7 * 86400)
    from .scorer import AUTOTUNE_PROTECT, suggested_weights
    stats = {n: {k: int(det_stats.get(n, {}).get(k, 0)) for k in ("fired", "fp", "tp")} for n in DETECTOR_NAMES}
    sugg = suggested_weights(stats, weights)
    dets = []
    for n in DETECTOR_NAMES:
        s = stats[n]
        if n in AUTOTUNE_PROTECT:         # a certain detector is its own ground truth: catches minus unblocks
            tp, denom = max(0, s["fired"] - s["fp"]), s["fired"]
        else:                              # behavioral: co-fires with a certain catch vs false positives
            tp, denom = s["tp"], s["tp"] + s["fp"]
        prec = round(tp / denom, 2) if denom else None
        dets.append({"name": n, "confirmed": tp, "fired": s["fired"], "fp": s["fp"], "precision": prec,
                     "weight": float(weights.get(n, 1.0)), "suggested": sugg.get(n)})
    dets.sort(key=lambda d: -(d["confirmed"] + d["fp"]))
    new_agents = sorted(({"ua": u["sk"], "first": u.get("first", 0), "n": u.get("n", 0)}
                         for u in c["uas"] if u.get("first", 0) >= now - 3600), key=lambda u: -u["n"])[:15]
    board = [{"ts": float(m["sk"].split("#", 1)[0]), "side": m.get("side", "us"), "move": m.get("move", ""),
              "actor": m.get("actor", ""), "ip": m.get("ip", ""), "detail": m.get("detail", ""),
              "play": PLAYBOOK.get(m.get("move", ""), "")} for m in c["moves"]]
    board = [b for b in board if b["ts"] >= since]

    return {
        "live": True, "mode": policy.get("mode", "observe"), "generated": int(now), "hours": hours,
        "policy": {k: policy.get(k) for k in ("mode", "edge", "thresholds", "weights", "flag_hours",
                                               "ja4", "edge_controls", "alerts", "judge", "autotune", "verified",
                                               "reputation", "apps", "flood")},
        "judge": {
            "recent": [{"ts": float(j["sk"].split("#", 1)[0]), "actor": j.get("actor", ""), "ips": j.get("ips", []),
                        "answer": json.loads(j["answer"]) if j.get("answer") else None, "stop": j.get("stop", ""),
                        "mode": j.get("mode", ""), "applied": j.get("applied", [])} for j in c["judge"]],
            "calls_24h": sum(int(x.get("calls", 0)) for x in c["judgecount"]),
            "tokens_in_24h": sum(int(x.get("tokens_in", 0)) for x in c["judgecount"]),
            "tokens_out_24h": sum(int(x.get("tokens_out", 0)) for x in c["judgecount"]),
        },
        "alerting": {"subscriptions": c["subs"],
                     "recent": [{"ts": float(a["sk"].split("#", 1)[0]), "kind": a.get("kind"), "subject": a.get("subject"),
                                 "sent": bool(a.get("sent"))} for a in c["alerts"]]},
        "actors": actors, "decoys": decoys[:30],
        # allow is approximate: actors seen per batch summed per hour, minus the flagged
        "ladder": {"allow": max(0, seen - block - tarpit - watch), "watch": watch, "tarpit": tarpit, "block": block},
        "kpis": {"requests": req, "decoyHits": len(decoys), "burnedSec": r429 * RETRY_AFTER_S,
                 "r429": r429, "fp7d": fp7, "verified": verified, "reputation": reputation},
        "detectors": dets,
        "anomalies": anomalies(c["statm"], now),
        "newAgents": new_agents,
        "watchlist": [{"key": w["sk"], "score": w["score"], "ips": w.get("ips", []), "signals": w.get("signals", []),
                       "challenged": any(ip in chal_ips for ip in w.get("ips", []))} for w in c["watch"][:15]],
        "challenges": [{"ip": ch["sk"], "actor": ch.get("actor", ""), "exp": ch["exp"]} for ch in c["challenges"]],
        "allows": [{"cidr": a["sk"], "exp": a["exp"], "reason": a.get("reason", "")} for a in c["allows"]],
        "board": board[:60],
        "campaigns": c["campaigns"],
        "verdict_url": os.environ.get("VERDICT_URL", ""),
        "apps": apps_view(c["stath"], flags, policy.get("apps") or {}, lo),
        "cell": cell_view([m for m in c["allmoves"] if float(m["sk"].split("#", 1)[0]) >= since], now),
        "flood": flood.view(c["flood"], c["flood_flagged"], c["allmoves"], c["floodcount"], policy),
        **({"budget": c["budget"]} if c["budget"] else {}),   # absent until the first hourly sample
        "audit": [{"ts": float(a["sk"].split("#", 1)[0]), "action": a.get("action"), "who": a.get("who"),
                   "body": a.get("body", "")} for a in c["audit"]],
    }


def publish(table, s3, bucket: str, policy, now: float | None = None, prefix=DATA_PREFIX) -> list[str]:
    from .alerts import subscriptions

    now = now or time.time()
    cache: dict = {"subs": subscriptions()}
    keys = []
    for h in WINDOWS:
        body = json.dumps(build(table, policy, h, now, cache), separators=(",", ":"))
        key = f"{prefix}data-{h}.json"
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode(), ContentType="application/json",
                      CacheControl="no-store")
        keys.append(key)
    return keys
