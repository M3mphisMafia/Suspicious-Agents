"""Normalized request events and log parsers."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator
from urllib.parse import urlsplit

# Whole path segment, optionally suffixed ("reset-password", "login.php"); never a
# substring, so /api/tokens and /cash-register are not auth. Mirrored in the WAF rule.
AUTH_REGEX = (
    r"(^|/)(login|signin|sign-in|logon|auth|oauth|oauth2|authorize|token|saml|saml2|sso|"
    r"password|reset|recover|forgot|signup|sign-up|register|verify|mfa|otp|2fa)"
    r"([-_.][a-z0-9_.-]*)?(/|$)"
)
_AUTH = re.compile(AUTH_REGEX)

RECON_MARKERS = (
    "openapi", "swagger", "api-docs", ".js.map", "/config.json", "runtime-config",
    "/.env", "/env.js", "graphql", "/.well-known/openid-configuration",
)

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# labels from the managed groups that only count (core rules, SQL injection, anonymous IPs):
# kept in the logs and stored events, never fed to scoring or the judge
COUNT_ONLY_LABELS = ("awswaf:managed:aws:core-rule-set:", "awswaf:managed:aws:sql-database:",
                     "awswaf:managed:aws:anonymous-ip-list:")


@dataclass
class Event:
    ts: float
    src_ip: str
    method: str
    path: str
    status: int
    user_agent: str = ""
    host: str = ""
    username: str = ""
    payload: str = ""      # query string / body sample, for canary-value checks
    tls_fp: str = ""       # JA3/JA4 if the edge provides it
    extra: dict = field(default_factory=dict)

    @property
    def is_auth(self) -> bool:
        return bool(_AUTH.search(self.path.lower()))

    @property
    def is_recon(self) -> bool:
        p = self.path.lower()
        return any(m in p for m in RECON_MARKERS)

    @property
    def is_write(self) -> bool:
        return self.method.upper() in WRITE_METHODS


def _ts(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()


def parse_jsonl(lines: Iterable[str]) -> Iterator[Event]:
    """One JSON object per line with keys matching Event fields (ts may be ISO-8601)."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        known = {k: d.pop(k) for k in list(d) if k in Event.__dataclass_fields__}
        known["ts"] = _ts(known["ts"])
        known["status"] = int(known.get("status", 0))
        yield Event(**known, extra=d)


def parse_waf(rec: dict) -> Event:
    """One AWS WAF log record. The origin's status is not logged: only WAF's own
    custom response code (e.g. our 429) is known, everything else is 0."""
    req = rec.get("httpRequest", {})
    hdrs = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
    extra = {"labels": [lb.get("name", "") for lb in rec.get("labels") or []],
             "request_id": req.get("requestId", ""), "action": rec.get("action", ""),
             "rule": rec.get("terminatingRuleId", ""),     # which web ACL rule stopped it (flood cost guard)
             "honey": honey_token(" ".join([req.get("args", ""), hdrs.get("authorization", ""),
                                            hdrs.get("cookie", "")])),
             "spoof": spoofed_browser(hdrs)}
    ordered = [(h.get("name", ""), h.get("value", "")) for h in req.get("headers", [])]
    extra["hfp"] = header_fp(ordered)
    extra["browser"] = is_browser(hdrs)
    tok = _bearer(hdrs.get("authorization", ""))
    if tok and not extra["honey"]:
        extra["bearer"] = hashlib.sha256(tok.encode()).hexdigest()   # never the raw token
    if hdrs.get("signature-input"):
        extra["sig"] = {k: hdrs.get(k, "") for k in ("host", "signature", "signature-input", "signature-agent")}
    return Event(
        ts=rec.get("timestamp", 0) / 1000,
        src_ip=req.get("clientIp", ""),
        method=req.get("httpMethod", ""),
        path=req.get("uri", "/"),
        # a silent Challenge a script can't solve is a refusal; browsers solve it and come back.
        # A block with no custom response (a managed rule's) is WAF's default 403.
        status=403 if rec.get("action") in ("CHALLENGE", "CAPTCHA") and not rec.get("challengeResponse", {}).get("solveTimestamp")
        else int(rec.get("responseCodeSent") or (403 if rec.get("action") == "BLOCK" else 0)),
        user_agent=hdrs.get("user-agent", ""),
        host=hdrs.get("host", ""),
        payload=req.get("args", ""),
        tls_fp=rec.get("ja4Fingerprint", ""),
        extra=extra,
    )


def _bearer(authorization: str) -> str:
    m = re.match(r"^\s*bearer\s+(\S+)", authorization or "", re.I)
    return m.group(1) if m else ""


BROWSER_UA = re.compile(r"^Mozilla/5\.0 .*(Chrome|Firefox|Safari|Edg)/\d", re.I)
VOLATILE = {"cookie", "authorization", "content-length", "content-type", "referer", "origin", "x-amzn-trace-id",
            "signature", "signature-input", "signature-agent", "if-none-match", "if-modified-since", "x-forwarded-for"}


def header_fp(headers: list[tuple[str, str]]) -> str:
    """Header ORDER plus Accept values: set by the client library, not by the request."""
    names = [n.lower() for n, _ in headers if n.lower() not in VOLATILE]
    vals = {n.lower(): v for n, v in headers}
    blob = ",".join(names) + "|" + "|".join(vals.get(k, "") for k in ("accept", "accept-language", "accept-encoding"))
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def is_browser(hdrs: dict) -> bool:
    """A real browser sends Sec-Fetch-*. Every Chrome user shares a fingerprint, so these are never linked."""
    return bool(BROWSER_UA.search(hdrs.get("user-agent", ""))) and any(k.startswith("sec-fetch-") for k in hdrs)


def spoofed_browser(hdrs: dict) -> bool:
    """Claims to be a modern browser but sends none of the Sec-Fetch-* headers every modern
    Chrome, Edge, Firefox and Safari sends. RuoJi6's ARTEX fork rotates 20 real browser
    User-Agents per request from plain Go/Python clients, which gives exactly this."""
    ua = hdrs.get("user-agent", "")
    return bool(BROWSER_UA.search(ua)) and not any(k.startswith("sec-fetch-") for k in hdrs)


HONEY_RE = re.compile(r"hny_([0-9a-f]{10})_[0-9a-f]+")


def honey_token(text: str) -> str:
    """The actor tag inside a honey session token we issued, or ''."""
    m = HONEY_RE.search(text or "")
    return m.group(1) if m else ""


TOKEN_PATH_RE = re.compile(r"/t/([0-9a-f]{10})(/|$)")


def decoy_tag(path: str) -> str:
    """The actor tag inside a personalized decoy route (<prefix>/t/<tag>/...), or ''."""
    m = TOKEN_PATH_RE.search(path or "")
    return m.group(1) if m else ""


def parse_alb(lines: Iterable[str]) -> Iterator[Event]:
    """AWS ALB access log lines."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        f = shlex.split(line)
        if len(f) < 13:
            continue
        method, url, *_ = f[12].split(" ") + ["", ""]
        u = urlsplit(url)
        yield Event(
            ts=_ts(f[1]),
            src_ip=f[3].rsplit(":", 1)[0],
            method=method,
            path=u.path or "/",
            status=int(f[8]) if f[8].isdigit() else 0,
            user_agent=f[13] if len(f) > 13 else "",
            host=u.hostname or "",
            payload=u.query,
        )
