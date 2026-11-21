"""Email alerts through SNS, rate-limited per subject so a busy attacker cannot flood you.

Kinds (each switchable in the dashboard policy):
  edge_block  an agent was blocked at the edge        once per agent per hour
  decoy       a decoy, personal route or honey token  once per agent per hour
  anomaly     traffic went out of norm                once per metric per 30 minutes
  admin       someone used the admin console          every action
  flood       a surge started, or ended               once each per 30 minutes
"""
from __future__ import annotations

import json
import logging
import os
import time

log = logging.getLogger()

KINDS = ("edge_block", "decoy", "anomaly", "admin", "breach", "flood")
COOLDOWN = {"edge_block": 3600, "decoy": 3600, "anomaly": 1800, "admin": 0, "breach": 3600, "flood": 1800}
DEFAULT = {k: True for k in KINDS}
_publisher = None


def _publish(subject: str, message: str) -> bool:
    global _publisher
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return False
    if _publisher is None:
        import boto3
        _publisher = boto3.client("sns")
    _publisher.publish(TopicArn=topic, Subject=subject[:99], Message=message)
    return True


def send(table, policy: dict, kind: str, key: str, subject: str, lines: list[str], now: float | None = None,
         force: bool = False) -> bool:
    """True if an alert went out. Never raises: an alert must not break scoring."""
    now = now or time.time()
    try:
        if not force and not (policy.get("alerts") or DEFAULT).get(kind, True):
            return False
        cd = COOLDOWN.get(kind, 0)
        if cd and not force:
            item = table.get_item(Key={"pk": "ALERTED", "sk": f"{kind}#{key}"}).get("Item")
            if item and int(item.get("exp", 0)) > now:
                return False
            table.put_item(Item={"pk": "ALERTED", "sk": f"{kind}#{key}", "exp": int(now + cd)})
        dash = os.environ.get("DASHBOARD_URL", "")
        body = "\n".join([*lines, "", f"Dashboard: {dash}" if dash else "", "", "Undertow"])
        sent = _publish(f"Undertow: {subject}", body)
        from .sinks import deliver   # webhooks, Slack, Teams, SIEM: same alert, same cooldown
        sent = deliver(table, kind, key, subject, [*lines, *([f"Dashboard: {dash}"] if dash else [])], now) > 0 or sent
        table.put_item(Item={"pk": "ALERT", "sk": f"{now:017.3f}#{kind}", "kind": kind, "subject": subject,
                             "sent": sent, "exp": int(now + 7 * 86400)})
        return sent
    except Exception as exc:  # noqa: BLE001
        log.warning(json.dumps({"event": "alert_failed", "kind": kind, "error": str(exc)[:200]}))
        return False


def subscriptions() -> list[dict]:
    """Masked endpoints and their confirmation state, for the dashboard."""
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return []
    try:
        import boto3
        subs = boto3.client("sns").list_subscriptions_by_topic(TopicArn=topic).get("Subscriptions", [])
    except Exception:  # noqa: BLE001
        return []
    out = []
    for s in subs:
        ep = s.get("Endpoint", "")
        if "@" in ep:
            user, dom = ep.split("@", 1)
            ep = f"{user[:1]}***@{dom}"
        pending = s.get("SubscriptionArn", "") in ("PendingConfirmation", "Deleted")
        out.append({"endpoint": ep, "protocol": s.get("Protocol", ""), "status": "pending" if pending else "confirmed"})
    return out
