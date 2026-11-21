"""Dashboard API at /_undertow/api/ (API Gateway HTTP API with a Cognito JWT authorizer).

The gateway rejects any request without a valid Undertow sign-in. Here, roles decide:
  user  -> read: snapshot data, policy, who am I
  admin -> also every action, the policy, and user management
Every write goes to the AUDIT log with who and from where, then WAF is resynced and
the dashboard snapshot republished so the change shows within seconds.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import time
from decimal import Decimal

from . import acl, alerts, detectors, flood, moves, scorer, users

MAX_HOURS = 24 * 7
ACTIONS = ("block", "tarpit", "challenge", "release", "unblock", "set_policy", "test_alert",
           "create_key", "revoke_key", "label", "add_destination", "remove_destination", "test_destination")
NO_SYNC = ("unblock", "test_alert", "create_key", "revoke_key", "label", "add_destination", "remove_destination",
           "test_destination")
KEY_KINDS = ("client", "verdict")   # client = a verified integration's traffic; verdict = may call the verdict API


def create_key(table, name: str, kind: str, who: str, now: float) -> dict:
    """A new key, returned once. Only its SHA-256 is stored."""
    import secrets

    from .verify import KEY_PREFIX, key_hash
    name = str(name or "").strip()[:60]
    if not name or kind not in KEY_KINDS:
        raise ValueError(f"give a name and a kind ({', '.join(KEY_KINDS)})")
    token = KEY_PREFIX + secrets.token_hex(20)
    table.put_item(Item={"pk": "IKEY", "sk": key_hash(token), "name": name, "kind": kind,
                         "prefix": token[:9], "by": who, "at": int(now)})
    return {"key": token, "name": name, "kind": kind, "prefix": token[:9],
            "note": "copy it now: it is not shown again"}


def list_keys(table) -> list[dict]:
    items, kw = [], {"KeyConditionExpression": "pk = :f", "ExpressionAttributeValues": {":f": "IKEY"}}
    while True:
        r = table.query(**kw)
        items += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            break
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
    return [{"id": i["sk"][:16], "name": i.get("name", ""), "kind": i.get("kind", "client"),
             "prefix": i.get("prefix", ""), "at": int(i.get("at", 0)), "revoked": bool(i.get("revoked"))}
            for i in sorted(items, key=lambda i: -int(i.get("at", 0)))]


def revoke_key(table, key_id: str, who: str, now: float) -> dict:
    key_id = str(key_id or "").strip().lower()
    if len(key_id) < 12:
        raise ValueError("give the key id from the list")
    hits = [i for i in table.query(KeyConditionExpression="pk = :f",
                                   ExpressionAttributeValues={":f": "IKEY"}).get("Items", [])
            if i["sk"].startswith(key_id)]
    if len(hits) != 1:
        raise ValueError("no single key matches that id")
    item = {**hits[0], "revoked": True, "revoked_by": who, "revoked_at": int(now)}
    table.put_item(Item=item)
    return {"revoked": item.get("name", ""), "prefix": item.get("prefix", "")}


class Denied(Exception):
    pass


def _ips(targets) -> list[str]:
    out = []
    for t in targets if isinstance(targets, list) else [targets]:
        ip = ipaddress.ip_address(str(t).strip())   # raises on garbage: no CIDR-wide blocks from the UI
        out.append(str(ip))
    if not out or len(out) > 50:
        raise ValueError("give 1-50 IPs")
    return out


def _hours(v, default) -> float:
    h = float(v if v not in (None, "") else default)
    if not 0 < h <= MAX_HOURS:
        raise ValueError(f"hours must be in (0, {MAX_HOURS}]")
    return h


def act(body: dict, table, waf, cfg: scorer.Config, who: str, now: float | None = None) -> dict:
    now = now or time.time()
    action = body.get("action")
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    reason = str(body.get("reason", ""))[:200]
    result: dict

    if action in ("block", "tarpit"):
        ips = _ips(body.get("targets"))
        hours = _hours(body.get("hours"), 24 if action == "block" else 1)
        actor = body.get("actor") or f"manual:{ips[0]}"
        table.put_item(Item={
            "pk": "FLAG", "sk": actor, "verdict": action, "manual": True,
            "score": Decimal("1") if action == "block" else Decimal("0.6"),
            "ips": ips, "signals": [f"manual: {reason or 'operator ' + action}"], "tag": moves.tag(actor),
            "exp": int(now + hours * 3600), "first": int(now), "history": [[int(now), Decimal("1")]],
        })
        scorer.record_move(table, now, "edge_block" if action == "block" else "operator_tarpit",
                           actor, ips[0], f"operator {action} {hours:g}h: {reason}")
        result = {"flagged": actor, "ips": ips, "hours": hours}

    elif action == "challenge":
        ips = _ips(body.get("targets"))
        hours = _hours(body.get("hours"), 1)
        for ip in ips:
            table.put_item(Item={"pk": "CHALLENGE", "sk": ip, "actor": body.get("actor", ""), "by": who,
                                 "reason": reason, "exp": int(now + hours * 3600)})
        scorer.record_move(table, now, "challenged", body.get("actor") or ips[0], ips[0],
                           f"operator challenge {hours:g}h: deception on, no delay")
        result = {"challenged": ips, "hours": hours}

    elif action == "release":
        ips = _ips(body.get("targets"))
        for ip in ips:
            table.delete_item(Key={"pk": "CHALLENGE", "sk": ip})
        result = {"released": ips}

    elif action == "unblock":
        ip = _ips(body.get("targets"))[0]
        hours = _hours(body.get("hours"), 24)
        result = scorer.unblock(ip, table, waf, cfg, ttl=int(hours * 3600), reason=reason or "dashboard", by=who, now=now)

    elif action == "test_alert":
        sent = alerts.send(table, scorer.load_policy(table, cfg), "admin", "test", "test alert",
                           [f"Sent from the dashboard by {who}.", "If you can read this, alerts work."], now, force=True)
        result = {"sent": sent}

    elif action == "create_key":
        result = create_key(table, body.get("name"), body.get("kind", "client"), who, now)

    elif action == "revoke_key":
        result = revoke_key(table, body.get("id"), who, now)

    elif action == "label":
        result = scorer.label(table, waf, cfg, str(body.get("actor", ""))[:400], body.get("outcome", ""),
                              by=who, reason=reason, now=now)

    elif action in ("add_destination", "remove_destination", "test_destination"):
        from . import sinks
        if action == "add_destination":
            result = sinks.add(table, body, who, now)
        elif action == "remove_destination":
            table.delete_item(Key={"pk": "DEST", "sk": str(body.get("id", ""))[:40]})
            result = {"removed": body.get("id")}
        else:
            n = sinks.deliver(table, "admin", "test", "test from the dashboard",
                              [f"Sent by {who}.", "If you can read this, this destination works."], now, only=str(body.get("id", "")))
            result = {"delivered": n}
        body = {k: v for k, v in body.items() if k not in ("token", "url")}    # keep secrets out of the audit

    else:  # set_policy
        change = body.get("policy") or {}
        pol = set_policy(table, cfg, change, who, now)
        result = {"policy": pol}
        if "edge_controls" in change:
            result["acl_written"] = acl.apply(waf, cfg.acl[0], cfg.acl[1], pol["edge_controls"])

    table.put_item(Item={"pk": "AUDIT", "sk": f"{now:017.3f}#{action}", "action": action, "who": who,
                         "body": json.dumps(body)[:1000], "exp": int(now + 90 * 86400)})
    if action != "test_alert":
        alerts.send(table, scorer.load_policy(table, cfg), "admin", action, f"console: {action} by {who}",
                    [f"Action: {action}", f"From: {who}", f"Request: {json.dumps(body)[:500]}"], now)
    if action not in NO_SYNC:   # these already synced, or touch nothing at the edge
        result["sync"] = scorer.sync(table, waf, cfg, now)
    return result


def set_policy(table, cfg, change: dict, who: str, now: float) -> dict:
    cur = scorer.load_policy(table, cfg)
    if "mode" in change:
        if change["mode"] not in ("observe", "enforce"):
            raise ValueError("mode is observe or enforce")
        cur["mode"] = change["mode"]
    if "edge" in change:
        if change["edge"] not in ("cell", "block", "tarpit", "lockdown"):
            raise ValueError("edge is cell, block, tarpit or lockdown")
        cur["edge"] = change["edge"]
    if "ja4" in change:
        cur["ja4"] = None if change["ja4"] is None else bool(change["ja4"])
    if "edge_controls" in change:
        cur["edge_controls"] = {**cur["edge_controls"], **acl.validate(change["edge_controls"])}
    if "judge" in change:
        j = change["judge"]
        if "enabled" in j:
            cur["judge"]["enabled"] = bool(j["enabled"])
        if "act" in j:
            if j["act"] not in ("advise", "act"):
                raise ValueError("judge mode is advise or act")
            cur["judge"]["act"] = j["act"]
        if "max_per_hour" in j:
            v = int(j["max_per_hour"])
            if not 0 <= v <= 500:
                raise ValueError("judge cap is 0-500 calls an hour")
            cur["judge"]["max_per_hour"] = v
    if "alerts" in change:
        for k, v in change["alerts"].items():
            if k not in alerts.KINDS:
                raise ValueError(f"unknown alert kind {k}")
            cur["alerts"][k] = bool(v)
    if "thresholds" in change:
        t = {**cur["thresholds"], **{k: float(v) for k, v in change["thresholds"].items()
                                       if k in ("watch", "tarpit", "block")}}
        if not 0.05 <= t["watch"] < t["tarpit"] < t["block"] <= 1.0:
            raise ValueError("need 0.05 <= watch < tarpit < block <= 1")
        if t["tarpit"] <= detectors.STYLE_CAP:
            raise ValueError(f"tarpit must be above {detectors.STYLE_CAP}: behavior that only looks automated "
                             "never slows or blocks anyone")
        cur["thresholds"] = t
    if "apps" in change:
        apps = dict(cur.get("apps") or {})
        for host, a in (change["apps"] or {}).items():
            host = str(host).lower().strip()
            if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
                raise ValueError(f"app host {host!r} is not a hostname")
            if a is None:
                apps.pop(host, None)
                continue
            origin = str(a.get("origin", "")).lower().strip()
            if origin and not re.fullmatch(r"[a-z0-9.-]{1,253}", origin):
                raise ValueError("origin is a hostname, no scheme or path")
            thr = {k: float(v) for k, v in (a.get("thresholds") or {}).items() if k in ("watch", "tarpit", "block")}
            full = {**cur["thresholds"], **thr}
            if thr and not (0.05 <= full["watch"] < full["tarpit"] < full["block"] <= 1.0 and full["tarpit"] > detectors.STYLE_CAP):
                raise ValueError(f"{host}: need 0.05 <= watch < tarpit < block <= 1 and tarpit above {detectors.STYLE_CAP}")
            w = {k: float(v) for k, v in (a.get("weights") or {}).items()}
            if any(k not in detectors.NAMES or not 0 <= v <= 2 for k, v in w.items()):
                raise ValueError(f"{host}: weights must be detector names with 0..2")
            apps[host] = {"name": str(a.get("name", ""))[:60], "origin": origin, "thresholds": thr, "weights": w}
        if len(apps) > 50:
            raise ValueError("up to 50 apps")
        cur["apps"] = apps
    if "verified" in change:
        v = change["verified"]
        if "crawlers" in v:
            cur["verified"]["crawlers"] = bool(v["crawlers"])
        if "directories" in v:
            dirs = [str(d).strip().rstrip("/") for d in v["directories"] if str(d).strip()]
            if len(dirs) > 20 or not all(d.startswith("https://") and " " not in d for d in dirs):
                raise ValueError("directories: up to 20 https:// origins")
            cur["verified"]["directories"] = dirs
    if "reputation" in change:
        r = change["reputation"]
        if "enabled" in r:
            cur["reputation"]["enabled"] = bool(r["enabled"])
        for n, x in (r.get("feeds") or {}).items():
            if n not in cur["reputation"]["feeds"]:
                raise ValueError(f"reputation feed {n} is not one of {list(cur['reputation']['feeds'])}")
            cur["reputation"]["feeds"][n] = bool(x)
    if "weights" in change:
        for k, v in change["weights"].items():
            if k not in detectors.NAMES or not 0 <= float(v) <= 2:
                raise ValueError(f"weight {k} must be a detector name with 0..2")
            cur["weights"][k] = float(v)
    if "flag_hours" in change:
        for k, v in change["flag_hours"].items():
            if k in ("block", "tarpit"):
                cur["flag_hours"][k] = _hours(v, 1)
    if "autotune" in change:
        cur["autotune"] = bool(change["autotune"])
    if "flood" in change:
        cur["flood"] = {**cur["flood"], **flood.validate(change["flood"] or {})}
    ec = cur["edge_controls"]
    item = {"pk": "POLICY", "sk": "current", "mode": cur["mode"], "edge": cur["edge"], "by": who, "at": int(now),
            **{k: {n: Decimal(str(x)) for n, x in cur[k].items()} for k in ("thresholds", "weights", "flag_hours")},
            "edge_controls": {"auth_rate": int(ec["auth_rate"]), "retry_after": int(ec["retry_after"]),
                              "geo": list(ec["geo"]), "asn": [int(a) for a in ec["asn"]]},
            "alerts": {k: bool(v) for k, v in cur["alerts"].items()},
            "judge": {"enabled": bool(cur["judge"]["enabled"]), "act": cur["judge"]["act"],
                      "max_per_hour": int(cur["judge"]["max_per_hour"])},
            "autotune": bool(cur.get("autotune", False)),
            "verified": {"crawlers": bool(cur["verified"]["crawlers"]), "directories": list(cur["verified"]["directories"])},
            "reputation": {"enabled": bool(cur["reputation"]["enabled"]),
                           "feeds": {n: bool(x) for n, x in cur["reputation"]["feeds"].items()}},
            "flood": flood.stored(cur["flood"]),   # the item is rewritten whole: omit it and it is lost
            "apps": {h: {"name": a["name"], "origin": a["origin"],
                         "thresholds": {n: Decimal(str(x)) for n, x in a["thresholds"].items()},
                         "weights": {n: Decimal(str(x)) for n, x in a["weights"].items()}}
                     for h, a in (cur.get("apps") or {}).items()}}
    if cur.get("ja4") is not None:
        item["ja4"] = bool(cur["ja4"])
    table.put_item(Item=item)
    return cur


# ---------- API Gateway (HTTP API, Cognito JWT authorizer) ----------

def _resp(status: int, body) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, default=lambda o: float(o) if isinstance(o, Decimal) else str(o))}


def claims_of(event: dict) -> dict:
    """Claims the gateway already verified. cognito:groups arrives as a list or as '[admin user]'."""
    c = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {}
    g = c.get("cognito:groups", [])
    if isinstance(g, str):
        g = [x for x in g.strip("[]").replace(",", " ").split() if x]
    return {"sub": c.get("sub", ""), "username": c.get("cognito:username", c.get("sub", "")),
            "email": c.get("email", ""), "groups": list(g)}


def role_of(claims: dict) -> str:
    return "admin" if "admin" in claims["groups"] else "user" if "user" in claims["groups"] else ""


_MFA_CACHE: dict[str, float] = {}


def _mfa_ok(cog, pool: str, username: str) -> bool:
    """Admin actions need an authenticator app on the account. Fails closed: an error is a no."""
    if _MFA_CACHE.get(username, 0) > time.time():
        return True
    try:
        ok = users.has_mfa(cog, pool, username)
    except Exception:  # noqa: BLE001
        return False
    if ok:
        _MFA_CACHE[username] = time.time() + 300
    return ok


def handle(event: dict, table, waf, cfg, publish=None, read_data=None, cog=None, pool: str = "") -> dict:
    claims = claims_of(event)
    role = role_of(claims)
    if not claims["sub"] or not role:
        return _resp(403, {"error": "sign in with an Undertow account"})
    method = event["requestContext"]["http"]["method"]
    path = event.get("rawPath", "")
    hdrs = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    ip = hdrs.get("cloudfront-viewer-address", "").rsplit(":", 1)[0] or event["requestContext"]["http"].get("sourceIp", "")
    who = f"{claims['email'] or claims['username']} ({ip})"

    # ---- any signed-in user ----
    if method == "GET" and path.endswith("/me"):
        mfa = None
        if cog and pool:
            try:
                mfa = users.has_mfa(cog, pool, claims["username"])
            except Exception:  # noqa: BLE001
                mfa = None
        return _resp(200, {"email": claims["email"], "role": role, "mfa": mfa})
    if method == "GET" and "/data/" in path:
        h = path.rsplit("/", 1)[-1]
        if h not in ("1", "6", "24") or not read_data:
            return _resp(404, {"error": "not found"})
        body = read_data(h)
        return {"statusCode": 200, "headers": {"content-type": "application/json", "cache-control": "no-store"},
                "body": body} if body else _resp(404, {"error": "no snapshot yet"})
    if method == "GET" and path.endswith("/policy"):
        return _resp(200, scorer.load_policy(table, cfg))
    if method == "GET" and (path.endswith("/indicators") or path.endswith("/indicators.stix")):
        from .sinks import indicators, stix
        now = time.time()
        inds = indicators(scorer._active(table, "FLAG", now), now)
        return _resp(200, stix(inds, now) if path.endswith(".stix") else {"generated": int(now), "indicators": inds})
    if method == "GET" and "/actor/" in path:
        from .replay import key_from_path, timeline
        try:
            key = key_from_path(path)
        except (ValueError, UnicodeDecodeError):
            return _resp(400, {"error": "bad agent id"})
        return _resp(200, timeline(table, key))

    # ---- admins only (enforced here, not just hidden in the page) ----
    if role != "admin":
        return _resp(403, {"error": "admins only"})
    if os.environ.get("REQUIRE_ADMIN_MFA", "true") == "true" and cog and pool and not _mfa_ok(cog, pool, claims["username"]):
        return _resp(403, {"error": "mfa_required: set up an authenticator app (sign out, then sign in again)"})
    raw = event.get("body") or ""
    try:
        body = json.loads(base64.b64decode(raw) if event.get("isBase64Encoded") else raw or "{}") if method == "POST" else {}
        if method == "GET" and path.endswith("/users"):
            return _resp(200, {"users": users.list_users(cog, pool)})
        if method == "GET" and path.endswith("/keys"):
            return _resp(200, {"keys": list_keys(table)})
        if method == "GET" and path.endswith("/destinations"):
            from .sinks import masked
            return _resp(200, {"destinations": masked(table)})
        if method == "POST" and path.endswith("/users"):
            result = users.manage(cog, pool, body.get("op", ""), body, claims["username"])
            table.put_item(Item={"pk": "AUDIT", "sk": f"{time.time():017.3f}#users.{body.get('op')}",
                                 "action": f"users.{body.get('op')}", "who": who,
                                 "body": json.dumps({k: v for k, v in body.items() if k != "password"})[:500],
                                 "exp": int(time.time() + 90 * 86400)})
            alerts.send(table, scorer.load_policy(table, cfg), "admin", f"users.{body.get('op')}",
                        f"console: users {body.get('op')} by {claims['email']}", [f"Request: {json.dumps(body)[:300]}"])
            return _resp(200, result)
        if method != "POST" or not path.endswith("/action"):
            return _resp(404, {"error": "not found"})
        result = act(body, table, waf, cfg, who)
    except (ValueError, TypeError) as exc:
        return _resp(400, {"error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - the dashboard gets a reason, the log gets the trace
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("UsernameExistsException", "UserNotFoundException", "InvalidParameterException"):
            return _resp(400, {"error": getattr(exc, "response", {}).get("Error", {}).get("Message", code)})
        import logging
        logging.getLogger().exception("admin action failed")
        return _resp(500, {"error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    if publish:
        publish()
    return _resp(200, result)


def handler(event, _context):
    import boto3
    from botocore.config import Config as BotoConfig

    from .snapshot import DATA_PREFIX, publish

    cfg = scorer.Config()
    table = boto3.resource("dynamodb").Table(cfg.table)
    waf = boto3.client("wafv2", region_name="us-east-1",
                       config=BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"}))
    bucket = os.environ.get("DASHBOARD_BUCKET", "")
    s3 = boto3.client("s3")

    def _publish():
        if bucket:
            publish(table, s3, bucket, scorer.load_policy(table, cfg))

    def _read(h: str) -> str:
        try:
            return s3.get_object(Bucket=bucket, Key=f"{DATA_PREFIX}data-{h}.json")["Body"].read().decode()
        except Exception:  # noqa: BLE001
            return ""

    return handle(event, table, waf, cfg, _publish, _read, boto3.client("cognito-idp"), os.environ.get("USER_POOL_ID", ""))
