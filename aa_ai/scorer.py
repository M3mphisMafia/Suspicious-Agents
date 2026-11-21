"""Scorer Lambda: WAF logs and Shield moves in; flags, links and WAF sets out.

Triggers:
  * CloudWatch Logs subscription on aws-waf-logs-aa-ai (WAF request records)
  * CloudWatch Logs subscription on the app's log group ("undertow_move" lines from Shield)
  * EventBridge 1-minute tick {"action": "snapshot"}: authoritative WAF sync + dashboard files

DynamoDB (pk, sk, exp TTL):
  <actor key> / <ts>#<req>   compact event, WINDOW seconds
  FLAG / <actor>             verdict, score, ips, signals, history, tag
  WATCH / <actor>            near-threshold actors (dashboard only)
  TAG / <tag>                actor a personal decoy / honey token was issued to
  MOVE / <ts>#<actor>#<n>    the board: their moves and our counters
  ALLOW / <cidr>             operator allow (unblock); LABEL = recorded false positive
  CHALLENGE / <ip>           operator challenge: WAF inserts a header, Shield plays deception
  POLICY / current           operator policy: mode, edge verdicts, thresholds, detector weights

Edge "cell" (the default): confirmed agents are not blocked, they are routed to the sandbox
origin (the padded cell) by a CloudFront Function that reads a KeyValueStore of their IPs.
A block is something it can route around; a fake app that seems to work is not.
  STAT / <hour>, STATM / <minute>, UA / <user agent>, DET / <detector>, DECOY / <ts>
  RATE#<minute>, PROF#<minute>, FLOOD / state   flood mode (aa_ai/flood.py)

The WAF sets are always REBUILT from current state, and sets already correct are not
written (WAF's change API is rate-limited).
"""
from __future__ import annotations

import base64
import gzip
import ipaddress
import json
import logging
import os
import random
import time
from collections import Counter, defaultdict
from decimal import Decimal

from . import alerts, campaigns, detectors, flood, moves
from .events import Event, decoy_tag, honey_token, parse_waf
from .scoring import BLOCK, TARPIT, WATCH, actor_key, combine, evaluate, verdict

log = logging.getLogger()
log.setLevel(logging.INFO)

WINDOW = int(os.environ.get("WINDOW_SECONDS", 6 * 3600))
MAX_EVENTS = 600
MEDIA = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf")
MAX_JA4 = 10            # WAF regex pattern sets hold at most 10 patterns
KVS_BATCH = 50          # keys per KeyValueStore UpdateKeys call, puts and deletes together (assumption)
# log batches under load (assumptions, unmeasured): bounded by sources, never by requests
SURGE_MAX_RESCORE = 50  # actors rescored per batch while a surge is active
SURGE_EVENTS = 200      # events read per actor while a surge is active
CERTAIN_PER_IP = 5      # decoy and honey hits stored per flooding source per batch
DEADLINE_MARGIN = 10.0  # seconds left when a batch stops rescoring and leaves the sync to the tick
WAF_IPSET_MAX = 10000   # addresses per WAF IP set: agents and flood IPs share it
JA4_PLACEHOLDER = "^aa-ai-placeholder-never-matches$"
DASHBOARD_PATH = "/_undertow/"
STAT_TTL, DECOY_TTL, WATCH_TTL, HISTORY_MAX = 26 * 3600, 7 * 86400, 3600, 120
TAG_TTL, MOVE_TTL, UA_TTL = 7 * 86400, 7 * 86400, 7 * 86400

DEFAULT_POLICY = {
    # "cell": confirmed (block-level) agents are routed to the padded cell at the edge;
    # verdicts blocked at the edge: "block"; "tarpit" (= tarpit + block);
    # "lockdown" (= watch + tarpit + block: anything suspicious is stopped at the edge)
    "edge": "cell",
    "thresholds": {"watch": WATCH, "tarpit": TARPIT, "block": BLOCK},
    "weights": {},              # detector -> multiplier (0 disables, up to 2)
    "flag_hours": {"block": 24, "tarpit": 1},
    "ja4": None,                # None = the stack's FlagJa4 parameter
    "edge_controls": {"auth_rate": 100, "retry_after": 9, "geo": [], "asn": []},
    "alerts": {"edge_block": True, "decoy": True, "anomaly": True, "admin": True, "breach": True, "flood": True},
    # auto-tuning: learn each detector's weight from ground truth (certain catches vs false positives)
    "autotune": False,
    # LLM judge: "advise" records verdicts only; "act" lets them escalate
    "judge": {"enabled": True, "act": "advise", "max_per_hour": 30},
    # verified agents: real search crawlers (reverse DNS) and Web Bot Auth signers from these directories
    "verified": {"crawlers": True, "directories": []},
    # IP reputation: WHERE a client comes from, a secondary (style) signal that never gates alone.
    # datacenter/tor need no secret; greynoise/abuseipdb read a key from the Lambda env when enabled.
    "reputation": {"enabled": True, "feeds": {"datacenter": True, "tor": True, "greynoise": False, "abuseipdb": False}},
    # several apps behind one engine: host -> {name, origin (for the cell's mirror), thresholds, weights}
    "apps": {},
    # flood mode (aa_ai/flood.py); pattern: act | advise | off. Unmeasured starting guesses, not tuned.
    "flood": {"enabled": True, "act": True, "pattern": "act", "multiplier": 5, "floor_rpm": 600, "per_ip_rpm": 120,
              "ttl_minutes": 15, "pattern_minutes": 30, "max_ips": 5000},
}


class Config:
    def __init__(self, env=os.environ):
        self.env = env
        self.mode = env.get("MODE", "observe")
        self.table = env.get("TABLE_NAME", "")
        self.ip4 = (env.get("IPSET4_NAME", ""), env.get("IPSET4_ID", ""))
        self.ip6 = (env.get("IPSET6_NAME", ""), env.get("IPSET6_ID", ""))
        self.ja4 = (env.get("JA4SET_NAME", ""), env.get("JA4SET_ID", ""))
        self.allow4 = (env.get("ALLOW4_NAME", ""), env.get("ALLOW4_ID", ""))
        self.allow6 = (env.get("ALLOW6_NAME", ""), env.get("ALLOW6_ID", ""))
        self.chal4 = (env.get("CHALLENGE4_NAME", ""), env.get("CHALLENGE4_ID", ""))
        self.sus4 = (env.get("SUSPECT4_NAME", ""), env.get("SUSPECT4_ID", ""))
        self.acl = (env.get("WEBACL_NAME", ""), env.get("WEBACL_ID", ""))
        self.kvs = env.get("CELL_KVS_ARN", "")
        self.flag_ja4 = env.get("FLAG_JA4", "false").lower() == "true"
        self.allow = [ipaddress.ip_network(c.strip(), strict=False)
                      for c in env.get("ALLOW_CIDRS", "").split(",") if c.strip()]
        self.protected_ja4 = {j.strip() for j in env.get("PROTECTED_JA4", "").split(",") if j.strip()}
        self.max_ips = int(env.get("MAX_FLAGGED_IPS", 5000))
        if env.get("DECOY_PREFIX"):
            detectors.DECOY_PREFIXES.add(env["DECOY_PREFIX"].rstrip("/"))
        for c in filter(None, env.get("CANARY_VALUES", "").split(",")):
            detectors.CANARY_SECRETS.add(c.strip())
        from .decoys import honey_markers
        detectors.HONEY_IDS.update(honey_markers())


def load_policy(table, cfg: Config) -> dict:
    """DEFAULT_POLICY, the deployed MODE, then the operator's saved overrides."""
    p = json.loads(json.dumps(DEFAULT_POLICY))
    p["mode"] = cfg.mode
    try:
        saved = table.get_item(Key={"pk": "POLICY", "sk": "current"}).get("Item")
    except Exception:  # noqa: BLE001 - a missing or unreadable policy never stops scoring
        saved = None
    if saved:
        for k in ("mode", "edge"):
            if saved.get(k):
                p[k] = saved[k]
        for k in ("thresholds", "weights", "flag_hours"):
            p[k].update({n: float(v) for n, v in (saved.get(k) or {}).items()})
        if saved.get("ja4") is not None:
            p["ja4"] = bool(saved["ja4"])
        ec = saved.get("edge_controls") or {}
        for n in ("auth_rate", "retry_after"):
            if n in ec:
                p["edge_controls"][n] = int(ec[n])
        if "geo" in ec:
            p["edge_controls"]["geo"] = [str(c) for c in ec["geo"]]
        if "asn" in ec:
            p["edge_controls"]["asn"] = [int(a) for a in ec["asn"]]
        p["alerts"].update({n: bool(v) for n, v in (saved.get("alerts") or {}).items()})
        j = saved.get("judge") or {}
        if "enabled" in j:
            p["judge"]["enabled"] = bool(j["enabled"])
        if j.get("act") in ("advise", "act"):
            p["judge"]["act"] = j["act"]
        if "max_per_hour" in j:
            p["judge"]["max_per_hour"] = int(j["max_per_hour"])
        if "autotune" in saved:
            p["autotune"] = bool(saved["autotune"])
        v = saved.get("verified") or {}
        if "crawlers" in v:
            p["verified"]["crawlers"] = bool(v["crawlers"])
        if "directories" in v:
            p["verified"]["directories"] = [str(d) for d in v["directories"]]
        rep = saved.get("reputation") or {}
        if "enabled" in rep:
            p["reputation"]["enabled"] = bool(rep["enabled"])
        if isinstance(rep.get("feeds"), dict):
            p["reputation"]["feeds"].update({n: bool(x) for n, x in rep["feeds"].items()
                                             if n in p["reputation"]["feeds"]})
        fl = saved.get("flood") or {}     # policies saved before flood mode have none: defaults apply
        p["flood"].update({n: bool(fl[n]) for n in ("enabled", "act") if n in fl})
        if fl.get("pattern") in ("act", "advise", "off"):
            p["flood"]["pattern"] = fl["pattern"]
        p["flood"].update({n: float(fl[n]) if n == "multiplier" else int(fl[n]) for n in flood.LIMITS if n in fl})
        p["apps"] = {str(h): {"name": str(a.get("name", "")), "origin": str(a.get("origin", "")),
                              "thresholds": {n: float(x) for n, x in (a.get("thresholds") or {}).items()},
                              "weights": {n: float(x) for n, x in (a.get("weights") or {}).items()}}
                     for h, a in (saved.get("apps") or {}).items()}
    return p


def app_of(evs) -> str:
    """The app an actor works against: the Host it sends most."""
    hosts = [e.host.lower().split(":")[0] for e in evs if e.host]
    return max(set(hosts), key=hosts.count) if hosts else ""


def app_policy(policy: dict, app: str) -> tuple[dict, dict]:
    """(thresholds, weights) for one app: its overrides on top of the global policy."""
    a = (policy.get("apps") or {}).get(app) or {}
    return {**policy["thresholds"], **a.get("thresholds", {})}, {**policy["weights"], **a.get("weights", {})}


# ---------- event <-> item ----------

def _item(key: str, e: Event, now: float) -> dict:
    return {
        "pk": key, "sk": f"{e.ts:017.3f}#{e.extra.get('request_id', '')}",
        "exp": int(now + WINDOW),
        "e": json.dumps([e.ts, e.src_ip, e.method, e.path, e.status, e.user_agent[:200],
                         e.host, e.payload[:500], e.tls_fp, e.extra.get("labels", []), e.extra.get("honey", ""),
                         bool(e.extra.get("spoof")), e.extra.get("verified", ""), bool(e.extra.get("fake_crawler")),
                         e.extra.get("hfp", ""), bool(e.extra.get("browser")), e.extra.get("reputation", "")]),
    }


def _event(item: dict) -> Event:
    v = json.loads(item["e"]) + [None] * 7      # older items are shorter
    ts, ip, m, p, st, ua, host, pl, fp, labels = v[:10]
    return Event(ts, ip, m, p, st, ua, host, payload=pl, tls_fp=fp,
                 extra={"labels": labels, "honey": v[10] or "", "spoof": bool(v[11]),
                        "verified": v[12] or "", "fake_crawler": bool(v[13]),
                        "hfp": v[14] or "", "browser": bool(v[15]), "reputation": v[16] or ""})


def _events_of(table, key: str, now: float, limit: int = MAX_EVENTS) -> list[Event]:
    resp = table.query(
        KeyConditionExpression="pk = :k AND sk >= :s",
        ExpressionAttributeValues={":k": key, ":s": f"{now - WINDOW:017.3f}"},
        ScanIndexForward=False, Limit=limit)
    return sorted((_event(i) for i in resp.get("Items", [])), key=lambda e: e.ts)


def _camp_put(table, fp: str, key: str, evs: list[Event], now: float):
    table.put_item(Item={"pk": "CAMP", "sk": f"{fp}#{key}"[:1000], "fp": fp, "actor": key,
                         "net": campaigns.net_of(evs[-1].src_ip), "last": int(evs[-1].ts),
                         "routes": sorted({campaigns.route(e.path) for e in evs})[:40],
                         "ips": sorted({e.src_ip for e in evs})[-10:], "exp": int(now + WINDOW)})


def camp_members(table, fp: str, now: float) -> list[dict]:
    r = table.query(KeyConditionExpression="pk = :k AND begins_with(sk, :s)",
                    ExpressionAttributeValues={":k": "CAMP", ":s": f"{fp}#"})
    return [i for i in r.get("Items", []) if i["sk"].startswith(f"{fp}#") and int(i.get("exp", 0)) > now]


def _campaign_signals(table, fps, active: dict, weights: dict, now: float, limit: int = 200) -> dict:
    """actor -> (campaign Signal, its events) for every linked member of the touched campaigns."""
    out = {}
    for fp in fps:
        items = camp_members(table, fp, now)
        routes = {i["actor"]: set(i.get("routes", [])) for i in items}
        nets = {i["actor"]: i.get("net", "") for i in items}
        last = {i["actor"]: int(i.get("last", 0)) for i in items}
        q = sorted(campaigns.qualify(routes, nets), key=lambda k: -last[k])[:campaigns.MAX_MEMBERS]
        if not q:
            continue
        members = {k: _events_of(table, k, now, limit=limit) for k in q}
        sure = {k for k in q if (active.get(k) or {}).get("confirmed") or (active.get(k) or {}).get("decoy")}
        for k, sig in campaigns.link({k: v for k, v in members.items() if v}, sure, weights).items():
            out[k] = (sig, members[k])
    return out


def decode_logs(event: dict) -> tuple[list[Event], list[dict]]:
    """WAF request records -> events; Shield 'undertow_move' lines -> moves."""
    data = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    evs, mvs = [], []
    is_waf = str(data.get("logGroup", "aws-waf-logs")).startswith("aws-waf-logs")
    for le in data.get("logEvents", []):
        msg = le.get("message", "")
        if not is_waf:
            i = msg.find('{"undertow_move"')
            if i >= 0:
                try:
                    mvs.append(json.loads(msg[i:]))
                except ValueError:
                    pass
            j = msg.find('{"undertow_event"')    # requests a gateway sent to the verdict API
            if j >= 0:
                try:
                    d = json.loads(msg[j:])
                    e = parse_waf(d["undertow_event"])
                    e.extra.update({k: v for k, v in (d.get("extra") or {}).items() if k in ("honey", "bearer") and v})
                    if not e.path.lower().endswith(MEDIA):
                        evs.append(e)
                except (ValueError, KeyError, TypeError):
                    pass
            continue
        try:
            e = parse_waf(json.loads(msg))
        except (ValueError, KeyError) as exc:
            log.warning("skip unparseable WAF record: %s", exc)
            continue
        if not e.path.lower().endswith(MEDIA):
            evs.append(e)
    return evs, mvs


# ---------- helpers ----------

def hour_key(ts: float) -> str:
    return time.strftime("%Y%m%d%H", time.gmtime(ts))


def minute_key(ts: float) -> str:
    return time.strftime("%Y%m%d%H%M", time.gmtime(ts))


def _add(table, pk: str, sk: str, exp: int | None = None, ret: bool = False, **counts):
    """Atomic counters (DynamoDB ADD). ret=True returns the counters after the add."""
    names = {f"#{k}": k for k in counts}
    vals = {f":{k}": v for k, v in counts.items()}
    expr = "ADD " + ", ".join(f"#{k} :{k}" for k in counts)
    if exp is not None:
        names["#exp"], vals[":exp"] = "exp", exp
        expr += " SET #exp = :exp"
    r = table.update_item(Key={"pk": pk, "sk": sk}, UpdateExpression=expr, ExpressionAttributeNames=names,
                          ExpressionAttributeValues=vals, **({"ReturnValues": "UPDATED_NEW"} if ret else {}))
    return (r or {}).get("Attributes", {}) if ret else None


def _seen_ua(table, ua: str, n: int, now: float):
    table.update_item(
        Key={"pk": "UA", "sk": ua[:200] or "(none)"},
        UpdateExpression="ADD #n :n SET #last = :now, #exp = :exp, #first = if_not_exists(#first, :now)",
        ExpressionAttributeNames={"#n": "n", "#last": "last", "#exp": "exp", "#first": "first"},
        ExpressionAttributeValues={":n": n, ":now": int(now), ":exp": int(now + UA_TTL)})


def _is_decoy(e: Event) -> bool:
    return (any(str(lb).endswith("aa-ai:decoy") for lb in e.extra.get("labels", ()))
            or any(e.path.startswith(p) for p in detectors.DECOY_PREFIXES))


def _allowed(cfg: Config, ip: str, extra=()) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in (*cfg.allow, *extra))


def _in(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _active(table, pk: str, now: float) -> list[dict]:
    items, kw = [], {"KeyConditionExpression": "pk = :f", "ExpressionAttributeValues": {":f": pk}}
    while True:
        r = table.query(**kw)
        items += [i for i in r.get("Items", []) if int(i.get("exp", 0)) > now]  # TTL deletes lazily
        if "LastEvaluatedKey" not in r:
            return items
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _active_flags(table, now: float) -> list[dict]:
    return _active(table, "FLAG", now)


def _active_allows(table, now: float) -> list:
    nets = []
    for i in _active(table, "ALLOW", now):
        try:
            nets.append(ipaddress.ip_network(i["sk"], strict=False))
        except ValueError:
            pass
    return nets


_move_seq = 0


def record_move(table, now: float, move: str, actor: str, ip: str, detail: str = "", side: str = "us"):
    global _move_seq
    _move_seq += 1
    table.put_item(Item={"pk": "MOVE", "sk": f"{now:017.3f}#{actor[:120]}#{_move_seq}", "move": move,
                         "side": side, "actor": actor, "ip": ip, "detail": detail[:300],
                         "exp": int(now + MOVE_TTL)})


def _remember_tag(table, actor: str, now: float):
    table.put_item(Item={"pk": "TAG", "sk": moves.tag(actor), "actor": actor, "exp": int(now + TAG_TTL)})


def _tag_owner(table, tag: str) -> str:
    try:
        item = table.get_item(Key={"pk": "TAG", "sk": tag}).get("Item")
    except Exception:  # noqa: BLE001
        return ""
    return item.get("actor", "") if item else ""


# ---------- ingest ----------

def ingest_moves(mvs: list[dict], table, now: float):
    for m in mvs:
        actor, ip, move = m.get("actor", ""), m.get("ip", ""), m.get("undertow_move", "")
        ts = float(m.get("ts", now))
        record_move(table, ts, move, actor, ip, m.get("detail", ""), m.get("side", "us"))
        if move == "read_map" and m.get("side") == "us":
            _remember_tag(table, actor, now)


def _link(table, owner: str, ip: str, via: str, now: float):
    """A rotated IP replayed something we gave another actor: fold it into that actor."""
    item = table.get_item(Key={"pk": "FLAG", "sk": owner}).get("Item") if owner else None
    if not item:
        return
    ips = sorted(set(item.get("ips", [])) | {ip})[-50:]
    if ips != sorted(item.get("ips", [])):
        item["ips"] = ips
        item["verdict"], item["score"] = "block", Decimal("1")
        item["exp"] = max(int(item["exp"]), int(now + 24 * 3600))
        table.put_item(Item=item)
        record_move(table, now, "linked_rotation", owner, ip, f"via {via}")


def _late(deadline: float | None) -> bool:
    return deadline is not None and time.time() > deadline


def ingest(events: list[Event], table, cfg: Config, now: float | None = None,
           policy: dict | None = None, deadline: float | None = None, report: dict | None = None) -> list[dict]:
    """Store events, rescore every touched actor, write FLAG items. Returns flags written.
    Work is bounded by distinct sources, not requests: a source past per_ip_rpm this minute is
    counted in the stats but not stored or rescored (flood mode judges it from the counters at the
    tick); rescoring is capped while a surge is active; and it stops at `deadline` rather than
    time out, because a timed-out batch is retried and counted twice."""
    now = now or time.time()
    policy = policy or load_policy(table, cfg)
    report = report if report is not None else {}
    allows = _active_allows(table, now)
    touched: dict[str, list[Event]] = defaultdict(list)
    stat = defaultdict(int)
    uas: dict[str, int] = defaultdict(int)
    hosts: dict[str, int] = defaultdict(int)
    links = []
    decoy_hits: dict[str, Event] = {}
    from .reputation import Reputation
    from .verify import Verifier
    ver = Verifier(table, policy, now)
    rep = Reputation(policy, now, table, env=getattr(cfg, "env", os.environ))
    active = {f["sk"]: f for f in _active_flags(table, now)}
    fp_ = flood.settings(policy)
    fl = fp_["enabled"]                          # off: ingest behaves exactly as before flood mode
    flooding = flood.held(active.values()) if fl else set()
    surge = bool(fl and flood.surging(table))
    rate: Counter = Counter()
    prof: Counter | None = Counter() if surge else None
    kept = []
    for e in events:          # pass 1: counters only, one cheap step per request
        if e.path.startswith(DASHBOARD_PATH) or _allowed(cfg, e.src_ip, allows):
            continue
        e.extra["verified"] = ver.check(e)
        stat["verified"] += bool(e.extra["verified"])
        guarded = fl and (e.src_ip in flooding or flood.stopped_by_flood_rule(e))
        counted = fl and flood.counts(e, ver.crawlers)
        if counted:
            rate[e.src_ip] += 1
            if prof is not None:
                flood.tally(prof, e)
        stat["req"] += 1
        stat["r429"] += e.status == 429 and not guarded   # "attacker time burned" is agents', not a flood's
        stat["refused"] += e.status in detectors.REFUSED
        stat["auth"] += e.is_auth
        stat["recon"] += e.is_recon
        uas[e.user_agent] += 1
        hosts[(e.host or "").lower().split(":")[0][:100]] += 1
        kept.append((e, guarded, counted))
    totals = flood.record(table, now, rate, prof) if rate else {}
    per_ip = int(fp_["per_ip_rpm"])
    # During a surge only: a source past per_ip_rpm this minute is counted, not stored again.
    # Outside a surge every request is scored: agents run at machine speed, well past per_ip_rpm.
    hot = {ip for ip, n in rate.items() if int(totals.get(ip, n)) - n >= per_ip} if surge else set()
    seen: Counter = Counter()        # per source and request minute, within this batch
    extra_certain: Counter = Counter()
    skipped = 0
    with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as bw:
        for e, guarded, counted in kept:          # pass 2: storage, bounded by distinct sources
            if counted:
                seen[(e.src_ip, int(e.ts // 60))] += 1
            over = counted and surge and (e.src_ip in hot or seen[(e.src_ip, int(e.ts // 60))] > per_ip)
            if guarded or over:
                # a decoy or honey hit is a certain detection: kept even from a flooding source, a few per batch
                certain = _is_decoy(e) or bool(e.extra.get("honey")) or bool(decoy_tag(e.path))
                if not certain or extra_certain[e.src_ip] >= CERTAIN_PER_IP:
                    skipped += 1
                    continue
                extra_certain[e.src_ip] += 1
            if not e.extra["verified"]:          # verified identity is not reputation-scored
                stat["reputation"] += bool(rep.check(e))
            k = actor_key(e)
            touched[k].append(e)
            bw.put_item(Item=_item(k, e, now))
            if _is_decoy(e) or e.extra.get("honey"):
                stat["decoy"] += 1
                decoy_hits.setdefault(k, e)
                bw.put_item(Item={"pk": "DECOY", "sk": f"{e.ts:017.3f}#{e.extra.get('request_id', '')}",
                                  "path": e.path[:300], "ip": e.src_ip, "actor": k,
                                  "exp": int(now + DECOY_TTL)})
            for t, via in ((decoy_tag(e.path), "personal decoy route"), (e.extra.get("honey", ""), "honey token")):
                if t and t != moves.tag(k):
                    links.append((t, e.src_ip, via))
    for k, e in decoy_hits.items():
        what = "replayed a honey token" if e.extra.get("honey") else "touched a decoy route"
        alerts.send(table, policy, "decoy", k, f"certain detection: {what} ({e.src_ip})",
                    [f"Agent: {k}", f"IP: {e.src_ip}", f"Request: {e.method} {e.path}",
                     "No legitimate user does this. The agent is scored 1.0."], now)
    if stat["req"]:
        _add(table, "STAT", hour_key(now), int(now + STAT_TTL), req=stat["req"], actors=len(touched), r429=stat["r429"],
             verified=stat["verified"], reputation=stat["reputation"])
        _add(table, "STATM", minute_key(now), int(now + STAT_TTL), **{k: v for k, v in stat.items()})
        for ua, n in list(uas.items())[:50]:
            _seen_ua(table, ua, n, now)
        for host, n in sorted(hosts.items(), key=lambda h: -h[1])[:20]:   # per-app traffic for the dashboard
            if host:
                _add(table, "STATH", f"{hour_key(now)}#{host}", int(now + STAT_TTL), req=n)

    thr, weights, hours = policy["thresholds"], policy["weights"], policy["flag_hours"]
    flags = []
    scored, fps = [], set()
    order, deferred, stopped = list(touched.items()), 0, False
    if surge and len(order) > SURGE_MAX_RESCORE:
        # decoy hits first, then the busiest; the rest are rescored with their next batch
        order.sort(key=lambda kv: (kv[0] not in decoy_hits, -len(kv[1])))
        deferred, order = len(order) - SURGE_MAX_RESCORE, order[:SURGE_MAX_RESCORE]
    limit = SURGE_EVENTS if surge else MAX_EVENTS
    for i, (key, fresh) in enumerate(order):
        if _late(deadline):
            deferred, stopped = deferred + len(order) - i, True
            break
        prev = active.get(key)
        if prev and prev["verdict"] == "block" and int(prev["exp"]) > now + 1800 and not prev.get("manual"):
            # already blocked: skip the rescore, but a NEW IP for the same agent must join the block
            new_ips = sorted({e.src_ip for e in fresh} - set(prev.get("ips", [])))
            if new_ips or "app" not in prev:
                prev["ips"] = sorted(set(prev.get("ips", [])) | set(new_ips))[-50:]
                prev.setdefault("app", app_of(fresh))
                table.put_item(Item=prev)
            if new_ips:
                record_move(table, now, "linked_rotation", key, new_ips[0],
                            f"same agent from a new IP ({', '.join(new_ips[:3])})")
                flags.append(prev)
            # still a campaign member: its siblings must learn a confirmed attacker runs their tool
            fp = campaigns.actor_fp(fresh)
            if fp:
                fps.add(fp)
                if not table.get_item(Key={"pk": "CAMP", "sk": f"{fp}#{key}"[:1000]}).get("Item"):
                    _camp_put(table, fp, key, _events_of(table, key, now, limit=200) or fresh, now)
            continue
        evs = _events_of(table, key, now, limit=limit)
        fp = campaigns.actor_fp(evs) if evs else ""
        if fp:
            _camp_put(table, fp, key, evs, now)
            fps.add(fp)
        scored.append((key, prev, evs))
    # second pass: actors running one tool down one path from 3+ networks are one campaign
    camp = _campaign_signals(table, fps, active, weights, now, limit=limit // 3) if fps and not _late(deadline) else {}
    have = {k for k, _, _ in scored}
    for key, (sig, evs) in camp.items():
        prev = active.get(key)
        if key not in have and evs and sig.name == "campaign" and not (prev and (prev.get("manual") or prev["verdict"] == "block")):
            scored.append((key, prev, evs))   # a sibling that sent nothing new: escalate it now
    for j, (key, prev, evs) in enumerate(scored):
        if _late(deadline):
            deferred, stopped = deferred + len(scored) - j, True
            break
        if not evs:
            continue
        app = app_of(evs)
        thr, w_app = app_policy(policy, app)
        sigs = evaluate(evs, weights=w_app)
        if key in camp:
            sigs.append(camp[key][0])
            if camp[key][0].name == "campaign" and not any(str(s).startswith("campaign") for s in (prev or {}).get("signals", [])):
                record_move(table, now, "joined_campaign", key, evs[-1].src_ip, camp[key][0].detail, side="them")
        score = combine(sigs)
        v = verdict(score, thr)
        if v not in ("tarpit", "block"):
            if v == "watch":  # dashboard only; never reaches the WAF block sets
                table.put_item(Item={"pk": "WATCH", "sk": key, "score": Decimal(str(score)), "app": app,
                                     "ips": sorted({e.src_ip for e in evs})[-10:],
                                     "signals": [s.name for s in sigs], "exp": int(now + WATCH_TTL)})
                _remember_tag(table, key, now)
            continue
        if prev and prev.get("manual"):
            continue  # an operator decision outranks the score
        ja4 = next((e.tls_fp for e in reversed(evs) if e.tls_fp), "")
        flag = {
            "pk": "FLAG", "sk": key, "verdict": v, "score": Decimal(str(score)),
            "ips": sorted({e.src_ip for e in evs} | set(prev.get("ips", []) if prev else []))[-50:],
            "ja4": ja4, "tag": moves.tag(key), "app": app,
            "decoy": any(s.name == "decoy_touch" for s in sigs),
            "signals": [f"{s.name}: {s.detail}" for s in sigs],
            "exp": int(now + hours.get(v, 1) * 3600),
        }
        if prev and int(prev["exp"]) > flag["exp"]:
            flag["exp"] = int(prev["exp"])  # never shorten an existing flag
        flag["first"] = prev.get("first", int(now)) if prev else int(now)
        flag["history"] = (list(prev.get("history", [])) if prev else [])[-(HISTORY_MAX - 1):] + \
            [[int(now), Decimal(str(score))]]
        before = {s.split(":", 1)[0] for s in (prev.get("signals", []) if prev else [])}
        if not prev:  # a new detection: count it once per detector for the accuracy panel
            for s in sigs:
                _add(table, "DET", s.name, fired=1)
        # ground truth for auto-tuning: a decoy/honey/cell/canary hit is a CERTAIN attacker.
        # count, once per actor, which behavioral detectors fired alongside that certainty.
        flag["confirmed"] = bool(flag["decoy"]) or bool(prev and prev.get("confirmed"))
        if flag["decoy"] and not (prev and prev.get("confirmed")):
            for s in sigs:
                if s.name != "decoy_touch":
                    _add(table, "DET", s.name, tp=1)
        for s in sigs:  # escalations show on the board
            mv = {"ignores_retry_after": "ignored_retry_after", "keeps_hammering": "hammering"}.get(s.name)
            if mv and s.name not in before:
                record_move(table, now, mv, key, evs[-1].src_ip, s.detail, side="them")
        if v in edge_verdicts(policy) and (not prev or prev["verdict"] not in edge_verdicts(policy)):
            cell = policy.get("edge") == "cell"
            record_move(table, now, "edge_cell" if cell else "edge_block", key, evs[-1].src_ip,
                        f"{v} {score:.2f}" + ("" if policy.get("mode") == "enforce" else " (observe: not applied)"))
            what = "moved into the padded cell" if cell else "blocked at the edge"
            alerts.send(table, policy, "edge_block", key,
                        f"agent {what} ({evs[-1].src_ip})" if policy.get("mode") == "enforce"
                        else f"agent would be {what} ({evs[-1].src_ip}, observe mode)",
                        [f"Agent: {key}", f"IPs: {', '.join(sorted({e.src_ip for e in evs})[-10:])}",
                         f"Verdict: {v} ({score:.2f})", "Signals:", *[f"  - {s.name}: {s.detail}" for s in sigs]], now)
        table.put_item(Item=flag)
        _remember_tag(table, key, now)
        flags.append(flag)
        log.info(json.dumps({"event": "would_flag" if policy.get("mode") != "enforce" else "flag",
                             "actor": key, "score": score, "verdict": v,
                             "signals": flag["signals"], "ips": flag["ips"][:10]}))
    for t, ip, via in links:
        _link(table, _tag_owner(table, t), ip, via, now)
    report.update(surge=surge, skipped=skipped, deferred=deferred, stopped=stopped)
    if skipped or deferred:
        log.info(json.dumps({"event": "ingest_bounded", **report}))
    return flags


# ---------- desired WAF state ----------

def edge_verdicts(policy: dict) -> tuple[str, ...]:
    return {"tarpit": ("tarpit", "block"), "lockdown": ("watch", "tarpit", "block")}.get(policy.get("edge"), ("block",))


def compute_desired(table, cfg: Config, policy: dict, now: float) -> dict:
    allows = _active_allows(table, now)
    active = _active_flags(table, now)
    # flood IPs are blocked at the edge in every edge mode: a flood is never routed to the padded cell
    fl = flood.held(active) if flood.blocking(policy) else set()
    flags = [f for f in active if f["verdict"] in edge_verdicts(policy) and not f.get("flood")]
    cell_ips: set[str] = set()
    if policy.get("edge") == "cell":
        # confirmed agents go to the sandbox origin instead of the WAF block sets
        for f in flags:
            cell_ips.update(ip for ip in f.get("ips", []) if not _allowed(cfg, ip, allows) and _ip_ok(ip) and ip not in fl)
        flags = []
    if "watch" in edge_verdicts(policy):   # lockdown: near-threshold actors are stopped too
        flags += [{**w, "verdict": "watch"} for w in _active(table, "WATCH", now)]
    flag_ja4 = cfg.flag_ja4 if policy.get("ja4") is None else bool(policy["ja4"])
    v4, v6, ja4 = set(), set(), {}
    for f in sorted(flags, key=lambda f: float(f["score"]), reverse=True):
        for ip in f.get("ips", []):
            if _allowed(cfg, ip, allows):
                continue
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            (v4 if a.version == 4 else v6).add(f"{a}/{32 if a.version == 4 else 128}")
        # JA4 is shared by every client built on the same TLS stack: opt-in, BLOCK + decoy only
        j = f.get("ja4", "")
        if (flag_ja4 and j and j not in cfg.protected_ja4 and f["verdict"] == "block"
                and f.get("decoy") and len(ja4) < MAX_JA4):
            ja4[j] = None
    a4, a6 = set(), set()
    for n in (*cfg.allow, *allows):
        (a4 if n.version == 4 else a6).add(str(n))
    chal = set()
    for c in _active(table, "CHALLENGE", now):
        try:
            a = ipaddress.ip_address(c["sk"])
        except ValueError:
            continue
        if a.version == 4 and not _allowed(cfg, c["sk"], allows):
            chal.add(f"{a}/32")
    f4, f6 = set(), set()
    for ip in fl:
        if _allowed(cfg, ip, allows):
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        (f4 if a.version == 4 else f6).add(f"{a}/{32 if a.version == 4 else 128}")
    # suspects not already blocked at the edge get WAF's silent Challenge there instead of a Lambda tarpit
    blocked = set(v4) | f4
    sus = set()
    for s in [*_active_flags(table, now), *[{**w, "verdict": "watch"} for w in _active(table, "WATCH", now)]]:
        if s.get("verdict") in ("watch", "tarpit") and s.get("verdict") not in edge_verdicts(policy):
            for ip in s.get("ips", []):
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if a.version == 4 and not _allowed(cfg, ip, allows) and f"{a}/32" not in blocked:
                    sus.add(f"{a}/32")
    ip4, ip6 = sorted(v4)[: cfg.max_ips], sorted(v6)[: cfg.max_ips]
    # agents first: flood IPs fill what is left of the set, so a flood never crowds an agent out
    ip4 = sorted(ip4 + sorted(f4 - set(ip4))[: max(0, WAF_IPSET_MAX - len(ip4))])
    ip6 = sorted(ip6 + sorted(f6 - set(ip6))[: max(0, WAF_IPSET_MAX - len(ip6))])
    return {"allow4": sorted(a4), "allow6": sorted(a6), "chal4": sorted(chal), "sus4": sorted(sus)[: cfg.max_ips],
            "ip4": ip4, "ip6": ip6, "ja4": list(ja4),
            "cell": sorted(cell_ips)[: cfg.max_ips], "flood": sorted(fl)}


def _ip_ok(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sync_cell(kvs, arn: str, ips: list[str]) -> int:
    """Make the CloudFront KeyValueStore hold exactly ip:<addr> for each agent in the cell.
    The edge function routes those IPs to the sandbox origin within seconds. Returns writes."""
    if not (kvs and arn):
        return 0
    have, kw = set(), {"KvsARN": arn, "MaxResults": 50}
    while True:
        r = kvs.list_keys(**kw)
        have |= {i["Key"] for i in r.get("Items", [])}
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
    want = {f"ip:{ip}" for ip in ips}
    puts = [{"Key": k, "Value": "1"} for k in sorted(want - have)]
    dels = [{"Key": k} for k in sorted(have - want) if k.startswith("ip:")]
    ops = [("Puts", x) for x in puts] + [("Deletes", x) for x in dels]
    writes, etag = 0, None
    for i in range(0, len(ops), KVS_BATCH):
        req: dict[str, list] = {}
        for kind, x in ops[i:i + KVS_BATCH]:
            req.setdefault(kind, []).append(x)    # an empty Puts or Deletes list is never sent
        for attempt in range(3):
            if etag is None:
                etag = kvs.describe_key_value_store(KvsARN=arn)["ETag"]
            try:
                etag = kvs.update_keys(KvsARN=arn, IfMatch=etag, **req).get("ETag")
                break
            except Exception as exc:  # noqa: BLE001
                etag = None               # a concurrent writer moved the ETag: read it again
                if _code(exc) != "ConflictException" or attempt == 2:
                    raise
        writes += 1
    return writes


RETRYABLE = {"WAFOptimisticLockException", "ThrottlingException", "WAFUnavailableEntityException"}


def _code(exc) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def sync_waf(waf, cfg: Config, desired: dict, retries=8, blocks=True) -> int:
    """Make each WAF set equal the desired list. Sets already correct are not written.
    Allow and challenge sets only loosen or deceive, so they sync in every mode; block
    sets only when blocks=True (enforce). Returns the number of writes."""
    writes = 0

    def update(kind, name_id, payload):
        nonlocal writes
        name, sid = name_id
        if not sid:
            return
        if kind == "regex":
            payload = [f"^{j}$" for j in payload] or [JA4_PLACEHOLDER]
        for attempt in range(retries):
            try:
                if kind == "ip":
                    cur = waf.get_ip_set(Name=name, Scope="CLOUDFRONT", Id=sid)
                    if sorted(cur.get("IPSet", {}).get("Addresses", [])) == sorted(payload):
                        return
                    waf.update_ip_set(Name=name, Scope="CLOUDFRONT", Id=sid,
                                      Addresses=list(payload), LockToken=cur["LockToken"])
                else:
                    cur = waf.get_regex_pattern_set(Name=name, Scope="CLOUDFRONT", Id=sid)
                    have = [r["RegexString"] for r in cur.get("RegexPatternSet", {}).get("RegularExpressionList", [])]
                    if sorted(have) == sorted(payload):
                        return
                    waf.update_regex_pattern_set(Name=name, Scope="CLOUDFRONT", Id=sid,
                                                 RegularExpressionList=[{"RegexString": r} for r in payload],
                                                 LockToken=cur["LockToken"])
                writes += 1
                return
            except Exception as exc:  # noqa: BLE001
                if _code(exc) not in RETRYABLE or attempt == retries - 1:
                    raise
                time.sleep(min(8.0, 0.25 * 2 ** attempt) * (0.5 + random.random()))

    update("ip", cfg.allow4, desired["allow4"])   # allow first: an unblock lands before the block clears
    update("ip", cfg.allow6, desired["allow6"])
    update("ip", cfg.chal4, desired["chal4"])
    if blocks:
        update("ip", cfg.sus4, desired.get("sus4", []))
        update("ip", cfg.ip4, desired["ip4"])
        update("ip", cfg.ip6, desired["ip6"])
        update("regex", cfg.ja4, desired["ja4"])
    return writes


_kvs = None


def _kvs_client():
    """CloudFront KeyValueStore needs SigV4A (awscrt, shipped in the judge layer). None if absent."""
    global _kvs
    if _kvs is None:
        try:
            import awscrt  # noqa: F401
            import boto3
            _kvs = boto3.client("cloudfront-keyvaluestore", region_name="us-east-1")
        except Exception as exc:  # noqa: BLE001
            log.warning(json.dumps({"event": "cell_kvs_unavailable", "error": str(exc)[:200]}))
            _kvs = False
    return _kvs or None


def sync(table, waf, cfg: Config, now: float | None = None, policy: dict | None = None, kvs=None) -> dict:
    now = now or time.time()
    policy = policy or load_policy(table, cfg)
    d = compute_desired(table, cfg, policy, now)
    enforce = policy.get("mode") == "enforce"
    writes = sync_waf(waf, cfg, d, blocks=enforce)
    if cfg.kvs:
        try:   # the cell never blocks scoring: Shield's in-app cell covers until the edge catches up
            writes += sync_cell(kvs if kvs is not None else _kvs_client(), cfg.kvs, d["cell"] if enforce else [])
        except Exception as exc:  # noqa: BLE001
            log.warning(json.dumps({"event": "cell_sync_failed", "error": _code(exc), "message": str(exc)[:300]}))
    return {"writes": writes, "mode": policy.get("mode"), **{k: len(v) for k, v in d.items()}}


# ---------- operator actions (CLI and admin API) ----------

def unblock(target: str, table, waf, cfg: Config, *, ttl=24 * 3600, reason="", by="",
            now: float | None = None) -> dict:
    """Allow an IP/CIDR for ttl, drop flags and challenges that include it, record a
    false-positive label for detector tuning, then resync WAF (even in observe mode)."""
    now = now or time.time()
    net = ipaddress.ip_network(target, strict=False)
    table.put_item(Item={"pk": "ALLOW", "sk": str(net), "exp": int(now + ttl),
                         "reason": reason, "by": by, "at": int(now)})
    cleared = []
    for f in _active_flags(table, now):
        if any(_in(ip, net) for ip in f["ips"]):
            table.delete_item(Key={"pk": "FLAG", "sk": f["sk"]})
            if not f.get("manual"):
                for s in [] if f.get("flood") else f.get("signals", []):   # flood is statistics, not a detector to tune
                    _add(table, "DET", s.split(":", 1)[0], fp=1)
                table.put_item(Item={"pk": "LABEL", "sk": f"{now:017.3f}#{f['sk']}",
                                     "outcome": "false_positive", "actor": f["sk"],
                                     "score": f["score"], "signals": f.get("signals", []),
                                     "reason": reason, "by": by})
            cleared.append(f["sk"])
    for c in _active(table, "CHALLENGE", now):
        if _in(c["sk"], net):
            table.delete_item(Key={"pk": "CHALLENGE", "sk": c["sk"]})
    record_move(table, now, "unblocked", cleared[0] if cleared else str(net), str(net), reason or "operator")
    out = sync(table, waf, cfg, now)
    log.info(json.dumps({"event": "unblock", "target": str(net), "cleared": cleared, "by": by}))
    return {"allowed": str(net), "cleared": cleared, "expires": int(now + ttl), "sync": out}


def label(table, waf, cfg: Config, actor: str, outcome: str, *, by="", reason="", now: float | None = None) -> dict:
    """Operator ground truth for one actor. 'attacker': hold it at block and count each behavior
    signal it carries as a true positive. 'person': clear it, allow its IPs 24h, count each signal
    as a false positive. Auto-tune learns from both. Counted once per actor and outcome."""
    now = now or time.time()
    if outcome not in ("attacker", "person"):
        raise ValueError("outcome is attacker or person")
    flag = table.get_item(Key={"pk": "FLAG", "sk": actor}).get("Item")
    watch = table.get_item(Key={"pk": "WATCH", "sk": actor}).get("Item")
    src = flag or watch
    if not src:
        raise ValueError("that agent is not flagged or watched any more")
    sigs = [str(s).split(":", 1)[0] for s in src.get("signals", [])]
    ips = list(src.get("ips", []))
    seen = table.get_item(Key={"pk": "LABELED", "sk": actor}).get("Item")
    fresh = not seen or seen.get("outcome") != outcome
    if fresh:
        for s in sigs:
            if s not in AUTOTUNE_PROTECT and s != "manual":
                _add(table, "DET", s, **({"tp": 1} if outcome == "attacker" else {"fp": 1}))
        table.put_item(Item={"pk": "LABELED", "sk": actor, "outcome": outcome, "by": by, "exp": int(now + 30 * 86400)})
        table.put_item(Item={"pk": "LABEL", "sk": f"{now:017.3f}#{actor}",
                             "outcome": "true_positive" if outcome == "attacker" else "false_positive",
                             "actor": actor, "score": src.get("score", Decimal("0")), "signals": src.get("signals", []),
                             "reason": reason, "by": by})
    if outcome == "attacker":
        exp = max(int(src.get("exp", 0)), int(now + 24 * 3600))
        table.put_item(Item={**(flag or {}), "pk": "FLAG", "sk": actor, "verdict": "block", "score": Decimal("1"),
                             "manual": True, "confirmed": True, "labeled": "attacker", "ips": ips,
                             "signals": list(src.get("signals", [])), "tag": moves.tag(actor), "exp": exp,
                             "first": int(src.get("first", now)),
                             "history": [*(flag or {}).get("history", []), [int(now), Decimal("1")]][-HISTORY_MAX:]})
        if watch:
            table.delete_item(Key={"pk": "WATCH", "sk": actor})
    else:
        for pk in ("FLAG", "WATCH"):
            table.delete_item(Key={"pk": pk, "sk": actor})
        for ip in ips:
            table.put_item(Item={"pk": "ALLOW", "sk": f"{ip}/{32 if ':' not in ip else 128}", "exp": int(now + 24 * 3600),
                                 "reason": f"labeled a person{': ' + reason if reason else ''}", "by": by, "at": int(now)})
            table.delete_item(Key={"pk": "CHALLENGE", "sk": ip})
    record_move(table, now, f"labeled_{outcome}", actor, ips[0] if ips else "", reason or by)
    return {"actor": actor, "outcome": outcome, "counted": fresh, "signals": sigs, "sync": sync(table, waf, cfg, now)}


def run(event: dict, table, waf, cfg: Config, now: float | None = None, deadline: float | None = None) -> dict:
    now = now or time.time()
    policy = load_policy(table, cfg)
    new, rep = [], {}
    if "awslogs" in event:
        evs, mvs = decode_logs(event)
        if mvs:
            ingest_moves(mvs, table, now)
        new = ingest(evs, table, cfg, now, policy, deadline=deadline, report=rep) if evs else []
    if not new and event.get("action") != "sync":
        return {"flags": 0, "synced": False, **rep}
    if "awslogs" in event and (rep.get("surge") or _late(deadline)):
        # under a surge (or out of time) the 1-minute tick syncs: never one WAF sync per batch
        log.info(json.dumps({"event": "sync_deferred", "reason": "surge" if rep.get("surge") else "time"}))
        return {"flags": len(new), "synced": False, "writes": 0, **rep}
    try:
        out = sync(table, waf, cfg, now, policy)
    except Exception as exc:  # noqa: BLE001
        if "awslogs" not in event:
            raise
        # never fail a log batch over WAF: a retried batch would double-count; the 1-minute tick converges
        log.warning(json.dumps({"event": "sync_deferred", "error": _code(exc)}))
        out = {"writes": -1}
    log.info(json.dumps({"event": "sets", **out}))
    return {"flags": len(new), "synced": policy.get("mode") == "enforce", **out, **rep}


def check_canary(table, iam, policy: dict, now: float | None = None) -> dict | None:
    """The canary AWS key (zero permissions, planted in decoy .env/config) has been used.
    IAM records last use even for calls that are denied, including sts:GetCallerIdentity,
    with a lag of up to a few hours. A NEW last-use time means someone holds the key."""
    user = os.environ.get("CANARY_USER", "")
    if not user:
        return None
    now = now or time.time()
    for k in iam.list_access_keys(UserName=user).get("AccessKeyMetadata", []):
        last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
        when = last.get("LastUsedDate")
        if not when:
            continue
        ts = when.timestamp() if hasattr(when, "timestamp") else float(when)
        seen = table.get_item(Key={"pk": "TRIPWIRE", "sk": k["AccessKeyId"]}).get("Item") or {}
        if ts <= float(seen.get("last", 0)):
            continue
        table.put_item(Item={"pk": "TRIPWIRE", "sk": k["AccessKeyId"], "last": Decimal(str(ts)),
                             "service": last.get("ServiceName", ""), "region": last.get("Region", ""),
                             "exp": int(now + 365 * 86400)})
        record_move(table, now, "canary_key_used", "breach-tripwire", "",
                    f"{last.get('ServiceName', '?')} in {last.get('Region', '?')}", side="them")
        alerts.send(table, policy, "breach", k["AccessKeyId"], "BREACH TRIPWIRE: the canary AWS key was used",
                    ["Someone used the AWS access key planted in Undertow's decoy files.",
                     f"Key: {k['AccessKeyId']} (user {user}, no permissions)",
                     f"Last used: {when} via {last.get('ServiceName', '?')} in {last.get('Region', '?')}",
                     "The key can do nothing, but whoever holds it read a decoy file: treat the app as probed",
                     "and check CloudTrail for the caller's source IP."], now)
        return {"key": k["AccessKeyId"], "service": last.get("ServiceName"), "at": ts}
    return None


AUTOTUNE_MIN = 8          # need this many ground-truth observations before trusting a detector's rate
AUTOTUNE_PROTECT = {"decoy_touch"}   # certain detectors are ground truth, never tuned


def det_stats(table, now: float | None = None) -> dict:
    """Per detector: fired, fp (false positives from unblocks), tp (co-fires with a certain catch).
    DET counters carry no TTL, so they are read in full, not filtered by expiry."""
    out, kw = {}, {"KeyConditionExpression": "pk = :f", "ExpressionAttributeValues": {":f": "DET"}}
    while True:
        r = table.query(**kw)
        for d in r.get("Items", []):
            out[d["sk"]] = {k: int(d.get(k, 0)) for k in ("fired", "fp", "tp")}
        if "LastEvaluatedKey" not in r:
            return out
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def suggested_weights(stats: dict, weights: dict, min_samples: int = AUTOTUNE_MIN) -> dict:
    """Learn each detector's weight from ground truth. precision = tp / (tp + fp); a detector that
    co-fires with certain attackers and rarely on false positives earns a higher weight. Bounded
    to [0.5, 1.5] so one noisy run can never disable a detector or let it dominate."""
    out = {}
    for name, s in stats.items():
        if name in AUTOTUNE_PROTECT:
            continue
        tp, fp = s.get("tp", 0), s.get("fp", 0)
        if tp + fp < min_samples:
            continue
        precision = tp / (tp + fp)
        mult = round(min(1.5, max(0.5, 0.5 + precision)), 2)
        if abs(mult - float(weights.get(name, 1.0))) >= 0.05:   # only suggest a real change
            out[name] = mult
    return out


def apply_autotune(table, cfg: Config, now: float | None = None) -> dict:
    """When autotune is on, fold the suggested weights into the saved policy. Conservative by
    construction: bounded, needs AUTOTUNE_MIN samples, and leaves certain detectors alone."""
    now = now or time.time()
    policy = load_policy(table, cfg)
    if not policy.get("autotune"):
        return {}
    sugg = suggested_weights(det_stats(table, now), policy.get("weights", {}))
    if not sugg:
        return {}
    item = table.get_item(Key={"pk": "POLICY", "sk": "current"}).get("Item") or {"pk": "POLICY", "sk": "current"}
    item["weights"] = {**(item.get("weights") or {}), **{k: Decimal(str(v)) for k, v in sugg.items()}}
    item["autotune"] = True
    table.put_item(Item=item)
    record_move(table, now, "autotuned", "auto-tuner", "",
                ", ".join(f"{k}->{v}" for k, v in sorted(sugg.items()))[:300])
    table.put_item(Item={"pk": "AUDIT", "sk": f"{now:017.3f}#autotune", "action": "autotune",
                         "who": "auto-tuner", "body": json.dumps(sugg)[:500], "exp": int(now + 90 * 86400)})
    log.info(json.dumps({"event": "autotune", "weights": sugg}))
    return sugg


def check_anomalies(table, policy: dict, now: float | None = None) -> list[dict]:
    from .snapshot import anomalies

    now = now or time.time()
    a = anomalies(_active(table, "STATM", now), now)
    names = {"req": "requests", "refused": "refusals", "auth": "login traffic", "recon": "API-map reads", "decoy": "decoy hits"}
    for f in a["flags"]:
        alerts.send(table, policy, "anomaly", f["metric"],
                    f"{names.get(f['metric'], f['metric'])} out of norm (x{f['now'] / max(1, f['baseline']):.1f})",
                    [f"Last 5 minutes: {f['now']}", f"Usual for 5 minutes: {f['baseline']}", f"z-score: {f['z']}"], now)
    return a["flags"]


def _deadline(context) -> float | None:
    """When to stop: the invocation's remaining time minus a margin (None outside Lambda)."""
    try:
        return time.time() + context.get_remaining_time_in_millis() / 1000 - DEADLINE_MARGIN
    except AttributeError:
        return None


def _clients():
    import boto3  # provided by the Lambda runtime
    from botocore.config import Config as BotoConfig

    cfg = Config()
    table = boto3.resource("dynamodb").Table(cfg.table)
    waf = boto3.client("wafv2", region_name="us-east-1",
                       config=BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"}))
    return boto3, cfg, table, waf


def handler(event, context=None):
    """The log-batch function: WAF logs and the app's and cell's move lines. The 1-minute tick
    has its own function (tick_handler) so it never waits behind ingestion in a flood."""
    if event.get("action") == "snapshot":
        log.warning(json.dumps({"event": "tick_ignored", "why": "the schedule must target the tick function"}))
        return {"ignored": "snapshot"}
    _, cfg, table, waf = _clients()
    return run(event, table, waf, cfg, deadline=_deadline(context))


def tick_handler(event, context=None):
    """The 1-minute tick, in its own function: flood mode, the authoritative WAF sync, auto-tune,
    the cost sample, the dashboard snapshot, anomalies and the canary check."""
    from .snapshot import publish

    boto3, cfg, table, waf = _clients()
    deadline = _deadline(context)
    try:   # before the sync, so a surge's blocks land this tick; flood mode never breaks the tick
        flood.tick(table, waf, cfg, load_policy(table, cfg))
    except Exception as exc:  # noqa: BLE001
        log.warning(json.dumps({"event": "flood_tick_failed", "error": str(exc)[:200]}))
    # the authoritative WAF sync: a batch that deferred or failed its sync converges within a minute
    synced = run({"action": "sync"}, table, waf, cfg)
    if int(time.time() // 60) % 10 == 0 and not _late(deadline):   # re-tune at most every 10 minutes
        try:
            apply_autotune(table, cfg)
        except Exception as exc:  # noqa: BLE001 - tuning must never break the tick
            log.warning(json.dumps({"event": "autotune_failed", "error": str(exc)[:200]}))
    if not _late(deadline):
        try:   # Budget page: a usage sample at most once an hour, a bill check at most once a day
            from . import costs
            costs.tick(table, waf, cfg, client=lambda name: boto3.client(name, region_name="us-east-1"))
        except Exception as exc:  # noqa: BLE001 - costs never break the tick
            log.warning(json.dumps({"event": "costs_failed", "error": str(exc)[:200]}))
    policy = load_policy(table, cfg)
    bucket = os.environ.get("DASHBOARD_BUCKET", "")
    files = publish(table, boto3.client("s3"), bucket, policy) if bucket else []
    check_anomalies(table, policy)
    trip = None
    if int(time.time() // 60) % 5 == 0 and not _late(deadline):   # every 5 minutes
        try:
            trip = check_canary(table, boto3.client("iam"), policy)
        except Exception as exc:  # noqa: BLE001
            log.warning(json.dumps({"event": "canary_check_failed", "error": str(exc)[:200]}))
    return {"sync": synced, "snapshot": files, "tripwire": trip}
