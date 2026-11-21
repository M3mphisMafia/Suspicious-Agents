"""The playbook: which counter-move answers which agent move.

Shield plays these in the app; the scorer records them (from the app's log lines
and from WAF logs) so the dashboard can show the board.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time

log = logging.getLogger("aa_ai.moves")

# their move -> our counter, as shown on the dashboard
PLAYBOOK = {
    "read_map": "served a personal decoy map (routes only this agent was shown)",
    "login_attempt": "issued a honey session token",
    "used_honey": "certain: it replayed our honey token",
    "used_honey_record": "certain: it used an ID that exists only in our fake data",
    "followed_personal_decoy": "certain: it walked a route only it was shown",
    "linked_rotation": "linked a new IP to the agent that was shown the route",
    "probe_errors": "masked error detail so it cannot self-correct",
    "ignored_retry_after": "escalated: it ignores Retry-After",
    "hammering": "escalated: it keeps going after refusal",
    "challenged": "operator challenge: deception on, no delay",
    "edge_block": "blocked at the CloudFront edge (429 Retry-After 9)",
    "canary_key_used": "BREACH TRIPWIRE: the planted AWS key was used",
    "entered_cell": "moved into the padded cell: a fake app that seems to work",
    "edge_cell": "routed to the sandbox origin at the CloudFront edge",
    "rabbit_hole": "it is walking routes that exist only in the cell",
    "fake_write": "accepted its write; nothing was stored",
    "polled_forever": "its export job sits at almost done, forever",
    "cell_summary": "time and requests it has spent in the cell",
    "autotuned": "auto-tuned detector weights from confirmed catches",
    "joined_campaign": "linked to other IPs running the same tool down the same path",
    "labeled_attacker": "operator confirmed: an attacker (held at block; teaches auto-tune)",
    "labeled_person": "operator: this was a person (cleared, allowed 24h; teaches auto-tune)",
    "flood_surge": "flood mode on: traffic surged far past its norm",
    "flood_block": "blocked the flooding IPs at the edge (429), never the padded cell",
    "flood_pattern": "one edge rule against what the flood has in common",
    "flood_pattern_removed": "flood rule removed from the edge",
    "flood_over": "flood mode off: traffic is back near its norm",
}


def tag(actor_key: str) -> str:
    """Stable 10-hex tag for an actor, embedded in personal decoys and honey tokens."""
    return hashlib.sha256(actor_key.encode()).hexdigest()[:10]


def emit(move: str, actor: str, ip: str, detail: str = "", side: str = "us"):
    """One structured line; the scorer subscribes to these in the app's log group."""
    print(json.dumps({"undertow_move": move, "side": side, "actor": actor, "ip": ip,
                      "detail": detail[:300], "ts": time.time()}), flush=True)
