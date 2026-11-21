"""Agent replay: every request, what answered it, and why."""
import base64
import json

from test_console import _ev
from test_scorer import NOW, FakeTable, FakeWaf, awslogs, cfg, waf_records

from aa_ai import admin, scorer
from aa_ai.events import Event
from aa_ai.replay import key_from_path, timeline


def _seed():
    t, w = FakeTable(), FakeWaf()
    evs = [Event(NOW - 300 + i * 7, "203.0.113.7", "GET", "/api/products", 0, "Go-http-client/1.1",
                 payload="q=' OR '1'='1" if i in (2, 4) else "") for i in range(8)]
    evs.append(Event(NOW - 200, "203.0.113.7", "GET", "/api/products", 429, "Go-http-client/1.1"))
    scorer.run(awslogs(waf_records(evs)), t, w, cfg(), now=NOW - 100)
    key = next(sk for (pk, sk) in t.items if pk == "FLAG")
    scorer.record_move(t, NOW - 280, "entered_cell", key, "203.0.113.7", "tag x")
    return t, key


def test_timeline_marks_who_answered_and_why():
    t, key = _seed()
    r = timeline(t, key, NOW)
    assert r["requests"] == 9 and r["verdict"] == "tarpit" and any("injection_payloads" in s for s in r["signals"])
    served = {e["ts"]: e["served"] for e in r["events"]}
    assert served[NOW - 300] == "app" and served[NOW - 200] == "edge" and served[NOW - 300 + 7 * 7] == "cell"
    assert sum("attack payload" in e["marks"] for e in r["events"]) == 2
    assert any(m["move"] == "entered_cell" for m in r["moves"])


def test_replay_through_the_api_for_any_signed_in_user():
    t, key = _seed()
    enc = base64.urlsafe_b64encode(key.encode()).decode().rstrip("=")
    assert key_from_path(f"/_undertow/api/actor/{enc}") == key
    out = admin.handle(_ev("GET", f"/_undertow/api/actor/{enc}", ["user"]), t, FakeWaf(), cfg())
    assert out["statusCode"] == 200 and json.loads(out["body"])["actor"] == key
    bad = admin.handle(_ev("GET", "/_undertow/api/actor/!!!", ["user"]), t, FakeWaf(), cfg())
    assert bad["statusCode"] == 400
