"""Verdict API: any gateway, proxy or appliance asks Undertow what to do with a request.

POST /_undertow/v1/verdict   Authorization: Bearer uk_... (a "verdict" key from the dashboard)
  {"ip": "203.0.113.7", "method": "GET", "path": "/api/orders/42", "query": "a=1",
   "headers": {"user-agent": "...", ...} (in the order received), "ja4": "...", "status": 0}
-> {"verdict": "allow|challenge|tarpit|cell|block", "score": 0.0, "actor": "...", "reasons": [...], "ttl": 30}

The answer is read from current state (fast). Learning happens asynchronously: each request is
logged as an "undertow_event" line, and the log subscription batches those into the scorer,
exactly like WAF logs. Auth fails closed: unknown, revoked or unreadable key = no verdict.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import time
import uuid

from . import detectors
from .cell import find_ids
from .events import honey_token, parse_waf
from .scoring import actor_key
from .verify import KEY_PREFIX, bearer_of, key_hash

log = logging.getLogger()
TTL = {"allow": 30, "challenge": 60, "tarpit": 60, "cell": 300, "block": 300}
REDACT = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


def authorize(table, authorization: str) -> tuple[str | None, int]:
    """(key name, 0) or (None, http status). Fails closed."""
    tok = bearer_of(authorization)
    if not tok.startswith(KEY_PREFIX):
        return None, 401
    try:
        item = table.get_item(Key={"pk": "IKEY", "sk": key_hash(tok)}).get("Item")
    except Exception:  # noqa: BLE001 - could not verify = no verdict
        return None, 503
    if not item or item.get("revoked") or item.get("kind") != "verdict" or \
            not hmac.compare_digest(item["sk"], key_hash(tok)):
        return None, 401
    return item.get("name", "gateway"), 0


def waf_record(body: dict, now: float) -> tuple[dict, dict]:
    """The request as a WAF-shaped log record (secrets redacted) plus what we computed from the
    secrets before redacting them (honey token, bearer hash)."""
    ip = str(ipaddress.ip_address(str(body.get("ip", "")).strip()))
    path = str(body.get("path", "/"))[:2000]
    if not path.startswith("/"):
        raise ValueError("path must start with /")
    raw = body.get("headers") or {}
    hdrs = list(raw.items()) if isinstance(raw, dict) else [tuple(h) for h in raw]
    low = {str(k).lower(): str(v) for k, v in hdrs}
    extra = {"honey": honey_token(" ".join([str(body.get("query", "")), low.get("authorization", ""), low.get("cookie", "")]))}
    tok = bearer_of(low.get("authorization", ""))
    if tok and not extra["honey"]:
        extra["bearer"] = key_hash(tok)
    rec = {"timestamp": int(float(body.get("ts") or now) * 1000), "action": "ALLOW", "ja4Fingerprint": str(body.get("ja4", ""))[:64],
           "responseCodeSent": int(body.get("status") or 0) or None,
           "httpRequest": {"clientIp": ip, "httpMethod": str(body.get("method", "GET")).upper()[:10], "uri": path,
                           "args": str(body.get("query", ""))[:2000], "requestId": f"v{uuid.uuid4().hex[:16]}",
                           "headers": [{"name": str(k)[:100], "value": "[redacted]" if str(k).lower() in REDACT else str(v)[:1000]}
                                       for k, v in hdrs[:60]]}}
    return rec, extra


def decide(table, cfg, policy: dict, e, now: float) -> dict:
    from .scorer import _active, _active_allows, _allowed
    key = actor_key(e)
    cell = policy.get("edge") == "cell"
    out = lambda v, score=0.0, why=(): {"verdict": v, "score": float(score), "actor": key,   # noqa: E731
                                        "reasons": list(why)[:5], "ttl": TTL[v]}
    if _allowed(cfg, e.src_ip, _active_allows(table, now)):
        return out("allow", 0, ["allow list"])
    certain = e.extra.get("honey") or any(e.path.startswith(p) for p in detectors.DECOY_PREFIXES) \
        or (detectors.DECOY_PREFIXES and find_ids(f"{e.path} {e.payload}", detectors.DECOY_PREFIXES)) \
        or any(s in f"{e.payload}" for s in detectors.CANARY_SECRETS)
    if certain:
        return out("cell" if cell else "block", 1, ["replayed something only Undertow hands out"])
    f = table.get_item(Key={"pk": "FLAG", "sk": key}).get("Item")
    if f and int(f.get("exp", 0)) > now:
        v = f.get("verdict", "tarpit")
        v = ("cell" if cell else "block") if v == "block" else v
        return out(v, f.get("score", 0), [str(s).split(":", 1)[0] for s in f.get("signals", [])])
    if any(c["sk"] == e.src_ip for c in _active(table, "CHALLENGE", now)):
        return out("challenge", 0, ["operator challenge"])
    w = table.get_item(Key={"pk": "WATCH", "sk": key}).get("Item")
    if w and int(w.get("exp", 0)) > now:
        return out("challenge", w.get("score", 0), list(w.get("signals", [])))
    return out("allow")


def _resp(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body)}


def handle(event: dict, table, cfg, policy_loader, now: float | None = None) -> dict:
    now = now or time.time()
    hdrs = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    who, status = authorize(table, hdrs.get("authorization", ""))
    if not who:
        return _resp(status, {"error": "a verdict key is required" if status == 401 else "could not verify the key"})
    try:
        raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            import base64
            raw = base64.b64decode(raw)
        body = json.loads(raw)
        many = body.get("requests") if isinstance(body.get("requests"), list) else [body]
        if not 1 <= len(many) <= 50:
            raise ValueError("send 1-50 requests")
        policy = policy_loader()
        answers = []
        for b in many:
            rec, extra = waf_record(b, now)
            e = parse_waf(rec)
            e.extra.update(extra)
            answers.append(decide(table, cfg, policy, e, now))
            # the learning path: batched into the scorer by the log subscription
            print(json.dumps({"undertow_event": rec, "extra": extra, "via": who}), flush=True)
    except (ValueError, TypeError, KeyError) as exc:
        return _resp(400, {"error": str(exc)[:200]})
    return _resp(200, answers[0] if "requests" not in body else {"verdicts": answers})


def handler(event, _context):
    import boto3

    from .scorer import Config, load_policy
    cfg = Config()
    table = boto3.resource("dynamodb").Table(cfg.table)
    return handle(event, table, cfg, lambda: load_policy(table, cfg))
