"""Outbound: every alert to webhooks, Slack, Teams and SIEMs (Splunk HEC), as OCSF findings.

Destinations live in the table (DEST/<id>). Webhooks are signed: X-Undertow-Signature:
t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>. Destinations must be https and resolve
to public addresses only (checked when added and again before each send). Delivery never
raises: a dead destination must not break scoring.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
import time
import urllib.parse
import urllib.request
import uuid

log = logging.getLogger()
TYPES = ("webhook", "slack", "teams", "splunk_hec")
SEVERITY = {"breach": 5, "decoy": 4, "edge_block": 3, "flood": 3, "anomaly": 2, "admin": 1}
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b(?!/)")    # an address, not a network (203.0.113.0/24)


def public_https(url: str) -> str:
    """The host if url is https and every address it resolves to is public, else raise."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("destinations must be https://host/... with no credentials in the URL")
    for info in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP):
        a = ipaddress.ip_address(info[4][0])
        if not a.is_global:
            raise ValueError("destinations must resolve to public addresses")
    return u.hostname


def ocsf(kind: str, key: str, subject: str, lines: list[str], now: float) -> dict:
    """OCSF 1.1 Detection Finding (class 2004)."""
    ip = next(iter(_IP.findall(" ".join([*lines, key]))), "")
    f = {"class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
         "activity_id": 1, "activity_name": "Create", "type_uid": 200401, "status_id": 1,
         "severity_id": SEVERITY.get(kind, 1), "time": int(now * 1000), "message": subject,
         "finding_info": {"uid": hashlib.sha256(f"{kind}|{key}|{int(now)}".encode()).hexdigest()[:32], "title": subject,
                          "desc": "\n".join(lines)[:4000], "types": [kind]},
         "metadata": {"version": "1.1.0", "product": {"name": "Undertow", "vendor_name": "Undertow"}},
         "unmapped": {"actor": key[:300]}}
    if ip:
        f["src_endpoint"] = {"ip": ip}
    return f


def render(dest: dict, kind: str, key: str, subject: str, lines: list[str], now: float) -> tuple[bytes, dict]:
    t = dest["type"]
    if t == "slack":
        body = {"text": f"*Undertow: {subject}*\n```" + "\n".join(lines)[:2800] + "```"}
    elif t == "teams":
        body = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "body": [{"type": "TextBlock", "weight": "Bolder", "wrap": True, "text": f"Undertow: {subject}"},
                     {"type": "TextBlock", "wrap": True, "fontType": "Monospace", "text": "\n\n".join(lines)[:3000]}]}}]}
    elif t == "splunk_hec":
        body = {"time": now, "source": "undertow", "sourcetype": "undertow:finding", "event": ocsf(kind, key, subject, lines, now)}
    else:
        body = {"kind": kind, "subject": subject, "lines": lines, "ts": now, "actor": key, "finding": ocsf(kind, key, subject, lines, now)}
    raw = json.dumps(body).encode()
    hdrs = {"content-type": "application/json", "user-agent": "undertow-sinks/1"}
    if t == "splunk_hec":
        hdrs["authorization"] = f"Splunk {dest.get('token', '')}"
    if t == "webhook" and dest.get("secret"):
        ts = str(int(now))
        sig = hmac.new(dest["secret"].encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
        hdrs["x-undertow-signature"] = f"t={ts},v1={sig}"
    return raw, hdrs


def destinations(table) -> list[dict]:
    try:
        return table.query(KeyConditionExpression="pk = :f", ExpressionAttributeValues={":f": "DEST"}).get("Items", [])
    except Exception:  # noqa: BLE001
        return []


def deliver(table, kind: str, key: str, subject: str, lines: list[str], now: float | None = None,
            only: str = "", opener=None, check=None) -> int:
    """Send to every destination that wants this kind. Returns how many accepted it."""
    now, sent, check = now or time.time(), 0, check or public_https
    for d in destinations(table):
        if (only and d["sk"] != only) or (not only and kind not in d.get("kinds", list(SEVERITY))):
            continue
        status = "error"
        try:
            check(d["url"])
            raw, hdrs = render(d, kind, key, subject, lines, now)
            req = urllib.request.Request(d["url"], data=raw, method="POST", headers=hdrs)
            with (opener or urllib.request.urlopen)(req, timeout=3) as r:   # noqa: S310 - https, public, operator-set
                status = str(r.status)
            sent += 1
        except Exception as exc:  # noqa: BLE001
            status = f"error: {type(exc).__name__}"
            log.warning(json.dumps({"event": "sink_failed", "dest": d.get("name", ""), "error": str(exc)[:200]}))
        try:
            table.put_item(Item={**d, "last_status": status, "last_at": int(now)})
        except Exception:  # noqa: BLE001
            pass
    return sent


def add(table, body: dict, who: str, now: float, check=None) -> dict:
    check = check or public_https
    t = body.get("type")
    if t not in TYPES:
        raise ValueError(f"type is one of {', '.join(TYPES)}")
    url, name = str(body.get("url", "")).strip(), str(body.get("name", "")).strip()[:60] or t
    host = check(url)
    if t == "splunk_hec" and not body.get("token"):
        raise ValueError("Splunk HEC needs its token")
    kinds = [k for k in (body.get("kinds") or list(SEVERITY)) if k in SEVERITY] or list(SEVERITY)
    did = uuid.uuid4().hex[:12]
    item = {"pk": "DEST", "sk": did, "type": t, "name": name, "url": url, "host": host, "kinds": kinds,
            "by": who, "at": int(now)}
    if t == "splunk_hec":
        item["token"] = str(body["token"])[:200]
    out = {"id": did, "name": name, "type": t, "host": host}
    if t == "webhook":
        item["secret"] = out["secret"] = secrets.token_hex(24)
        out["note"] = "verify X-Undertow-Signature with this secret; it is not shown again"
    table.put_item(Item=item)
    return out


def masked(table) -> list[dict]:
    return [{"id": d["sk"], "name": d.get("name", ""), "type": d.get("type", ""), "host": d.get("host", ""),
             "kinds": d.get("kinds", []), "last_status": d.get("last_status", ""), "last_at": int(d.get("last_at", 0))}
            for d in destinations(table)]


# ---------- shared indicators (other deployments, a TIP, a firewall) ----------

def indicators(flags: list[dict], now: float) -> list[dict]:
    """Confirmed and blocked agents as indicators: IPs, JA4s, tool User-Agents."""
    out, seen = [], set()
    for f in flags:
        if not (f.get("confirmed") or f.get("verdict") == "block") or f.get("labeled") == "person":
            continue
        if f.get("flood"):    # a flood IP is held for minutes, not an agent worth sharing
            continue
        conf = 100 if f.get("confirmed") else int(float(f.get("score", 0)) * 100)
        base = {"verdict": f.get("verdict"), "confidence": conf, "first": int(f.get("first", now)), "until": int(f.get("exp", now))}
        vals = [("ipv4" if "." in ip else "ipv6", ip) for ip in f.get("ips", [])]
        if f.get("ja4"):
            vals.append(("ja4", f["ja4"]))
        ua = (f["sk"].split("|ua:")[1].split("|tls:")[0] if "|ua:" in f["sk"] else "")
        if ua and not ua.lower().startswith("mozilla/"):
            vals.append(("user_agent", ua))
        for typ, v in vals:
            if (typ, v) not in seen:
                seen.add((typ, v))
                out.append({"type": typ, "value": v, **base})
    return out


def stix(inds: list[dict], now: float) -> dict:
    when = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now))
    pat = {"ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "user_agent": "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"}
    objs = []
    for i in inds:
        if i["type"] not in pat:
            continue
        val = i["value"].replace("\\", "\\\\").replace("'", "\\'")
        objs.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, i['type'] + ':' + i['value'])}",
                     "created": when, "modified": when, "valid_from": when,
                     "valid_until": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(max(i["until"], now + 60))),
                     "name": f"Undertow: autonomous attack agent ({i['type']})", "pattern_type": "stix",
                     "pattern": f"[{pat[i['type']]} = '{val}']", "confidence": i["confidence"], "labels": ["malicious-activity"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}
