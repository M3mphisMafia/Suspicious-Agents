"""Shield counter-moves: personal decoy map, honey login, rotation linking, escalations."""
import asyncio
import json

import pytest

from aa_ai import moves
from aa_ai.decoys import DecoySet
from aa_ai.events import Event
from aa_ai.scoring import actor_key
from aa_ai.shield import Shield

SPEC = json.dumps({"openapi": "3.0.3", "paths": {"/api/v2/orders/{id}": {}}}).encode()


async def shop(scope, receive, send):
    if scope["path"] == "/openapi.json":
        body, status = SPEC, 200
    elif scope["path"] == "/login":
        body, status = b'{"error":"invalid"}', 401
    else:
        body, status = b"{}", 200
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def nosleep(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", nosleep)
    emitted = []
    monkeypatch.setattr(moves, "emit", lambda move, actor, ip, detail="", side="us": emitted.append((side, move, ip)))
    return emitted


def call(sh, path, method="GET", ip="203.0.113.9", headers=None):
    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": b""}

    hdrs = [(k.encode(), v.encode()) for k, v in {"user-agent": "Go-http-client/1.1", **(headers or {})}.items()]
    asyncio.run(sh({"type": "http", "method": method, "path": path, "headers": hdrs, "client": (ip, 1)}, receive, send))
    body = b"".join(m.get("body", b"") for m in out if m["type"] == "http.response.body")
    return out[0]["status"], body


def key_for(ip):
    return actor_key(Event(0, ip, "", "", 0, "Go-http-client/1.1"))


def sh():
    return Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), proxy_hops=0)


def test_normal_visitor_gets_the_real_map(fast):
    s = sh()
    status, body = call(s, "/openapi.json", ip="198.51.100.4")
    assert status == 200 and "/t/" not in body.decode() and not fast


def test_suspect_gets_a_personal_map_and_walking_it_is_certain(fast):
    s = sh()
    k = key_for("203.0.113.9")
    s.score[k] = 0.35
    _, body = call(s, "/openapi.json")
    mine = [p for p in json.loads(body)["paths"] if "/t/" in p]
    assert mine and all(moves.tag(k) in p for p in mine)
    assert ("us", "read_map", "203.0.113.9") in fast
    call(s, mine[0])
    assert s.score[k] == 1.0 and ("them", "followed_personal_decoy", "203.0.113.9") in fast


def test_rotated_ip_walking_anothers_route_is_linked(fast):
    s = sh()
    k = key_for("203.0.113.9")
    s.score[k] = 0.35
    _, body = call(s, "/openapi.json")
    route = next(p for p in json.loads(body)["paths"] if "/t/" in p)
    call(s, route, ip="192.0.2.77")                     # same agent, new IP
    assert ("us", "linked_rotation", "192.0.2.77") in fast
    assert s.score[key_for("192.0.2.77")] == 1.0


def test_suspect_login_gets_honey_and_replay_is_certain(fast):
    s = sh()
    k = key_for("203.0.113.9")
    s.score[k] = 0.55
    status, body = call(s, "/login", "POST")
    token = json.loads(body)["token"]
    assert status == 200 and token.startswith(f"hny_{moves.tag(k)}_")
    status, _ = call(s, "/api/v2/orders/1", headers={"authorization": f"Bearer {token}"}, ip="192.0.2.78")
    assert s.score[key_for("192.0.2.78")] == 1.0
    assert ("them", "used_honey", "192.0.2.78") in fast and ("us", "linked_rotation", "192.0.2.78") in fast


def test_innocent_login_is_untouched(fast):
    s = sh()
    assert call(s, "/login", "POST", ip="198.51.100.4")[0] == 401


def test_challenge_header_only_counts_from_cloudfront(fast):
    s = Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), origin_secret="x" * 32, proxy_hops=0)
    # a client sending the header itself (WAF passes it through) proves nothing
    spoof = {"x-origin-verify": "x" * 32, "x-amzn-waf-undertow-challenge": "1"}
    assert call(s, "/login", "POST", headers=spoof)[0] == 401
    ok = {"x-origin-verify": "x" * 32, "x-amzn-waf-undertow-challenge": "x" * 32}
    status, body = call(s, "/login", "POST", headers=ok)
    assert status == 200 and b"hny_" in body                # challenged: honey login, no delay needed
    assert ("us", "challenged", "203.0.113.9") in fast


def test_edge_unblock_header_clears_shield_memory(fast):
    s = Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), origin_secret="x" * 32, proxy_hops=0)
    k = key_for("203.0.113.9")
    s.score[k] = 1.0
    ok = {"x-origin-verify": "x" * 32}
    assert call(s, "/api/v2/orders/1", headers=ok)[0] in (429, 503)
    # an attacker sending the allow header itself is NOT unblocked
    assert call(s, "/api/v2/orders/1", headers={**ok, "x-amzn-waf-undertow-allow": "1"})[0] in (429, 503)
    # WAF's insert carries the origin secret (a client copy may ride along, comma-joined)
    assert call(s, "/api/v2/orders/1", headers={**ok, "x-amzn-waf-undertow-allow": "1, " + "x" * 32})[0] == 200
    assert k not in s.score
    # without the origin secret the header is ignored
    s.score[k] = 1.0
    s.temp_allow.clear()
    assert call(s, "/api/v2/orders/1", headers={"x-amzn-waf-undertow-allow": "1"})[0] == 403


def test_ignoring_retry_after_escalates(fast):
    s = Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), proxy_hops=0, rescore_every=1)
    k = key_for("203.0.113.9")
    s.score[k] = 0.85                                        # blocked: half 429s, half stalls
    for _ in range(30):
        call(s, "/api/v2/orders/1")
    assert ("them", "ignored_retry_after", "203.0.113.9") in fast or ("them", "hammering", "203.0.113.9") in fast


def test_honey_replay_is_one_move_per_agent(fast):
    s = sh()
    k = key_for("203.0.113.9")
    s.score[k] = 0.55
    token = json.loads(call(s, "/login", "POST")[1])["token"]
    for _ in range(10):
        call(s, "/api/v2/orders/1", headers={"authorization": f"Bearer {token}"})
    assert sum(1 for side, mv, _ in fast if mv == "used_honey") == 1


def test_tarpit_never_holds_more_than_the_cap(monkeypatch):
    """A tarpit must not become a way to exhaust OUR capacity."""
    slept = []

    async def fake_sleep(s):
        slept.append(s)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    s = Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), proxy_hops=0, tarpit_max=1.5, max_held=0)
    s.score[key_for("203.0.113.9")] = 0.7
    assert call(s, "/api/v2/orders/1")[0] == 429 and not slept      # no room: instant answer, no hold
    s2 = Shield(shop, DecoySet(prefix="/api/v1/internal/ops"), proxy_hops=0, tarpit_max=1.5)
    s2.score[key_for("203.0.113.9")] = 0.95
    for _ in range(6):
        call(s2, "/api/v2/orders/1")
    assert slept == [] or max(slept) <= 1.5                          # every hold bounded by tarpit_max


def test_decoys_serve_consistent_paged_fake_data_and_ids_are_honey(fast):
    from aa_ai.decoys import corpus
    s = sh()
    k = key_for("203.0.113.9")
    s.score[k] = 0.35
    _, body = call(s, "/openapi.json")
    route = next(p for p in json.loads(body)["paths"] if p.endswith("/admin/users"))
    status, page1 = call(s, route)
    p1 = json.loads(page1)
    assert status == 200 and len(p1["items"]) == 10 and p1["total"] == len(corpus()["routes"]["admin/users"])
    assert all(i["email"].endswith(".example") for i in p1["items"])          # never a real person
    # the agent chains a record ID into an IDOR probe from a fresh IP: certain detection
    hid = p1["items"][3]["id"]
    assert call(s, f"/api/v2/orders/{hid}", ip="192.0.2.200")[0] == 404
    assert s.score[key_for("192.0.2.200")] == 1.0
    assert ("them", "used_honey_record", "192.0.2.200") in fast


def test_honey_ids_detected_by_the_scorer_from_waf_logs():
    from aa_ai.decoys import corpus
    from aa_ai.detectors import decoy_touch
    from aa_ai.events import Event
    from aa_ai.scorer import Config
    Config({})
    hid = corpus()["markers"][0]
    assert decoy_touch([Event(1, "1.2.3.4", "GET", f"/api/v2/orders/{hid}", 0)]).weight == 1.0
    assert decoy_touch([Event(1, "1.2.3.4", "GET", "/api/v2/orders/731000000999", 0)]) is None   # not a stamped id
