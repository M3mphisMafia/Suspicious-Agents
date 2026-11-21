"""API Gateway (HTTP API, payload 2.0, simple responses) Lambda authorizer backed by Undertow.

Env: UNDERTOW_VERDICT_URL, UNDERTOW_KEY (a verdict key), UNDERTOW_CELL_AS (block|allow, default block:
API Gateway cannot reroute to the cell). Turn authorizer caching OFF so every request is judged.
The verdict reaches your integration as $context.authorizer.undertow.
"""
from __future__ import annotations

import os

try:
    from .undertow_client import Undertow
except ImportError:            # deployed as a flat Lambda zip
    from undertow_client import Undertow

_ut = None


def decide(verdict: str, cell_as: str = "block") -> bool:
    """Is the request let through? block always stops; cell stops unless told otherwise."""
    if verdict == "block":
        return False
    if verdict == "cell":
        return cell_as == "allow"
    return True


def handler(event, _context):
    global _ut
    if _ut is None:
        _ut = Undertow(os.environ["UNDERTOW_VERDICT_URL"], os.environ["UNDERTOW_KEY"])
    http = (event.get("requestContext") or {}).get("http") or {}
    v = _ut.verdict(http.get("sourceIp", ""), http.get("method", "GET"), event.get("rawPath", "/"),
                    event.get("rawQueryString", ""), event.get("headers") or {})
    return {"isAuthorized": decide(v["verdict"], os.environ.get("UNDERTOW_CELL_AS", "block")),
            "context": {"undertow": v["verdict"], "undertowScore": str(v.get("score", 0))}}
