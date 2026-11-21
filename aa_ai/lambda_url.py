"""Lambda function URL (payload v2) -> ASGI, plus the sandbox origin's handler."""
from __future__ import annotations

import asyncio
import base64
import os


def serve(app, event: dict) -> dict:
    http = event["requestContext"]["http"]
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": http["method"], "path": event.get("rawPath", "/"),
        "query_string": (event.get("rawQueryString") or "").encode(),
        "headers": [(k.lower().encode(), v.encode()) for k, v in (event.get("headers") or {}).items()],
        "client": (http.get("sourceIp", ""), 0),
    }
    sent = {"status": 500, "headers": [], "body": b""}

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            sent["status"], sent["headers"] = msg["status"], msg.get("headers", [])
        elif msg["type"] == "http.response.body":
            sent["body"] += msg.get("body", b"")

    asyncio.run(app(scope, receive, send))
    return {
        "statusCode": sent["status"],
        "headers": {k.decode(): v.decode() for k, v in sent["headers"]},
        "body": base64.b64encode(sent["body"]).decode(),
        "isBase64Encoded": True,
    }


def origin_secret() -> str | None:
    if os.environ.get("ORIGIN_SECRET"):
        return os.environ["ORIGIN_SECRET"]
    arn = os.environ.get("ORIGIN_SECRET_ARN")
    if not arn:
        return None
    import boto3  # Lambda runtime

    return boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]


_cells: dict[str, tuple] = {}      # app origin -> (Cell, ASGI app)
_secret, _table, _apps = None, None, (0.0, {})


def _app_origin(host: str) -> str:
    """Which app this agent was attacking (x-undertow-app, set by the edge router) -> its origin.
    Apps and their origins come from the policy row, the only non-cell row the cell may read."""
    global _apps
    import time
    if _table is not None and _apps[0] < time.time():
        try:
            item = _table.get_item(Key={"pk": "POLICY", "sk": "current"}).get("Item") or {}
            _apps = (time.time() + 300, {h: a.get("origin", "") for h, a in (item.get("apps") or {}).items()})
        except Exception:  # noqa: BLE001
            _apps = (time.time() + 60, _apps[1])
    return _apps[1].get((host or "").lower().split(":")[0]) or os.environ.get("APP_ORIGIN", "")


def cell_handler(event, _context):
    """The sandbox origin: CloudFront sends confirmed agents here. It serves only the cell, shaped
    like the app the agent was attacking and remembering each agent's writes (CELL# rows)."""
    global _secret, _table
    import hmac
    from urllib.parse import parse_qsl, urlencode

    from .cell import Cell, DdbState, MemState, make_app
    from .mirror import Mirror

    if _secret is None:
        _secret = origin_secret() or ""
        if os.environ.get("TABLE_NAME"):
            import boto3
            _table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    hdrs = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if _secret and not hmac.compare_digest(hdrs.get("x-origin-verify", ""), _secret):
        # refuse before anything else: a direct call must not even make the cell learn
        return {"statusCode": 403, "headers": {"content-type": "application/json"},
                "body": '{"error":"request could not be processed"}'}
    # the edge router names the app it attacked (__undertow_app); the cell answers without it
    qs = parse_qsl(event.get("rawQueryString") or "", keep_blank_values=True)
    app = next((v for k, v in qs if k == "__undertow_app"), hdrs.get("x-undertow-app", ""))
    event = {**event, "rawQueryString": urlencode([(k, v) for k, v in qs if k != "__undertow_app"])}
    origin = _app_origin(app)
    hit = _cells.get(origin)
    if hit is None:
        key = os.environ.get("DECOY_PREFIX", "/api/v1/internal/ops").rstrip("/")
        mirror = Mirror(f"https://{origin}", _secret or None, decoy_prefix=key).learn() if origin else None
        cell = Cell(key, title=os.environ.get("CELL_TITLE", "Customer portal"), mirror=mirror,
                    state=DdbState(_table) if _table is not None else MemState(), notice=os.environ.get("CELL_NOTICE", "body"))
        hit = _cells[origin] = (cell, make_app(cell, _secret or None))
    elif hit[0].mirror is not None and hit[0].mirror.stale():
        hit[0].mirror.learn()          # the real app changed shape: follow it
    return serve(hit[1], event)
