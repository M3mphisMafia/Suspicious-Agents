"""Operator console: policy, challenges, rotation links, the board, admin API, anomalies."""
import base64
import gzip
import json

import pytest

from aa_ai import admin, moves, scorer
from aa_ai.snapshot import anomalies, build
from aa_ai.scorer import minute_key, run
from test_scorer import NOW, FakeTable, FakeWaf, _agent_waf_view, awslogs, cfg, waf_records

C = dict(ALLOW4_NAME="a4", ALLOW4_ID="a4", CHALLENGE4_NAME="c4", CHALLENGE4_ID="c4")


def tarpit_only_view():
    """One intent signal and nothing else (two injection probes, irregular pace): tarpit, not block.
    The agent's style-only run would now stop at watch: looking automated never slows anyone."""
    from aa_ai.events import Event
    t, evs = NOW - 300, []
    for i, (p, q) in enumerate([("/api/products", ""), ("/api/products", "q=' OR '1'='1"), ("/api/cart", ""),
                                ("/api/products", "q=1 UNION SELECT password FROM users"), ("/", ""), ("/api/me", "")]):
        evs.append(Event(t, "203.0.113.7", "GET", p, 0, "Go-http-client/1.1", payload=q))
        t += 4 + i * 3.7
    return evs


def test_style_only_agent_is_watched_not_slowed():
    t, w = FakeTable(), FakeWaf()
    run(awslogs(waf_records([e for e in _agent_waf_view() if not e.is_auth][:30])), t, w, cfg(**C), now=NOW)
    assert not any(pk == "FLAG" for (pk, _) in t.items) and any(pk == "WATCH" for (pk, _) in t.items)


def test_default_edge_policy_keeps_tarpit_in_app():
    t, w = FakeTable(), FakeWaf()
    out = run(awslogs(waf_records(tarpit_only_view())), t, w, cfg(**C), now=NOW)
    flag = next(v for (pk, _), v in t.items.items() if pk == "FLAG")
    assert flag["verdict"] == "tarpit" and out["ip4"] == 0     # suspects keep playing inside the app


def test_edge_policy_tarpit_blocks_suspects_too():
    t, w = FakeTable(), FakeWaf()
    admin.set_policy(t, cfg(**C), {"edge": "tarpit"}, "test", NOW)
    run(awslogs(waf_records(tarpit_only_view())), t, w, cfg(**C), now=NOW)
    assert w.sets["v4"] == ["203.0.113.7/32"]


def test_weights_and_thresholds_change_the_verdict():
    t, w = FakeTable(), FakeWaf()
    admin.set_policy(t, cfg(**C), {"weights": {"burst_pause_cadence": 0,
                                               "map_then_walk": 0, "canary_inputs": 0, "injection_payloads": 0,
                                               "write_then_verify": 0, "correct_and_retry": 0}}, "test", NOW)
    run(awslogs(waf_records(tarpit_only_view())), t, w, cfg(**C), now=NOW)
    assert not any(pk == "FLAG" for (pk, _) in t.items)


def test_bad_policy_is_refused():
    t = FakeTable()
    with pytest.raises(ValueError):
        admin.set_policy(t, cfg(), {"thresholds": {"watch": 0.9, "tarpit": 0.5}}, "test", NOW)
    with pytest.raises(ValueError):
        admin.set_policy(t, cfg(), {"weights": {"not_a_detector": 1}}, "test", NOW)


def test_challenge_syncs_in_observe_and_release_clears():
    t, w = FakeTable(), FakeWaf()
    c = cfg(MODE="observe", **C)
    admin.act({"action": "challenge", "targets": ["198.51.100.20"], "hours": 1}, t, w, c, "op", NOW)
    assert w.sets["c4"] == ["198.51.100.20/32"] and "v4" not in w.sets
    admin.act({"action": "release", "targets": ["198.51.100.20"]}, t, w, c, "op", NOW + 5)
    assert w.sets["c4"] == []
    audit = [v for (pk, _), v in t.items.items() if pk == "AUDIT"]
    assert {a["action"] for a in audit} == {"challenge", "release"} and all(a["who"] == "op" for a in audit)


def test_manual_block_and_unblock():
    t, w = FakeTable(), FakeWaf()
    c = cfg(**C)
    admin.act({"action": "block", "targets": ["192.0.2.50"], "hours": 2, "reason": "saw it in logs"}, t, w, c, "op", NOW)
    assert w.sets["v4"] == ["192.0.2.50/32"]
    admin.act({"action": "unblock", "targets": ["192.0.2.50"]}, t, w, c, "op", NOW + 5)
    assert w.sets["v4"] == [] and w.sets["a4"] == ["192.0.2.50/32"]
    assert not any(pk == "LABEL" for (pk, _) in t.items)   # an operator's own block is not a detector false positive


def test_admin_refuses_cidrs_and_garbage():
    t, w = FakeTable(), FakeWaf()
    for bad in (["10.0.0.0/8"], ["nope"], []):
        with pytest.raises(ValueError):
            admin.act({"action": "block", "targets": bad}, t, w, cfg(), "op", NOW)


def _ev(method, path, groups, body=None):
    claims = {"sub": "u-1", "cognito:username": "u-1", "email": "op@example.com"}
    if groups is not None:
        claims["cognito:groups"] = groups
    return {"headers": {}, "rawPath": path, "body": json.dumps(body) if body is not None else "",
            "requestContext": {"http": {"method": method, "sourceIp": "9.9.9.9"},
                               "authorizer": {"jwt": {"claims": claims}}}}


def test_api_roles_are_enforced_server_side():
    t, w = FakeTable(), FakeWaf()
    act = {"action": "release", "targets": ["1.2.3.4"]}
    assert admin.handle(_ev("POST", "/_undertow/api/action", None, act), t, w, cfg())["statusCode"] == 403
    assert admin.handle(_ev("POST", "/_undertow/api/action", "[user]", act), t, w, cfg())["statusCode"] == 403
    assert admin.handle(_ev("GET", "/_undertow/api/me", "[user]"), t, w, cfg())["statusCode"] == 200
    assert admin.handle(_ev("GET", "/_undertow/api/data/6", "[user]"), t, w, cfg(), read_data=lambda h: '{"ok":1}')["body"] == '{"ok":1}'
    assert admin.handle(_ev("GET", "/_undertow/api/data/../x", "[user]"), t, w, cfg(), read_data=lambda h: "x")["statusCode"] == 404
    assert admin.handle(_ev("POST", "/_undertow/api/action", "[admin]", act), t, w, cfg())["statusCode"] == 200
    assert admin.handle(_ev("POST", "/_undertow/api/action", ["admin"], {"action": "drop_tables"}), t, w, cfg())["statusCode"] == 400
    audit = [v for (pk, _), v in t.items.items() if pk == "AUDIT"]
    assert audit and audit[0]["who"].startswith("op@example.com")


def test_rotated_ip_replaying_a_honey_token_is_linked_to_its_owner():
    t, w = FakeTable(), FakeWaf()
    run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(**C), now=NOW)
    owner = next(sk for (pk, sk) in t.items if pk == "FLAG")
    tag = moves.tag(owner)
    rec = waf_records([_agent_waf_view()[0]])[0]
    rec["httpRequest"]["clientIp"] = "192.0.2.99"
    rec["httpRequest"]["headers"].append({"name": "Authorization", "value": f"Bearer hny_{tag}_abcdef"})
    run(awslogs([rec]), t, w, cfg(**C), now=NOW + 60)
    assert "192.0.2.99" in t.items[("FLAG", owner)]["ips"]
    assert "192.0.2.99/32" in w.sets["v4"]
    assert any(v.get("move") == "linked_rotation" for (pk, _), v in t.items.items() if pk == "MOVE")


def test_shield_moves_from_app_logs_land_on_the_board():
    t, w = FakeTable(), FakeWaf()
    line = json.dumps({"undertow_move": "read_map", "side": "us", "actor": "net:a|ua:b", "ip": "1.2.3.4",
                       "detail": "tag x", "ts": NOW})
    body = {"logGroup": "/aws/lambda/undertow-demo-app-App", "logEvents": [{"id": "1", "timestamp": 0,
            "message": f"2026-11-19T00:00:00Z abc INFO {line}"}]}
    run({"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(body).encode())).decode()}},
        t, w, cfg(**C), now=NOW)
    assert ("TAG", moves.tag("net:a|ua:b")) in t.items
    snap = build(t, scorer.load_policy(t, cfg()), 6, now=NOW + 1)
    assert snap["board"][0]["move"] == "read_map" and "personal decoy map" in snap["board"][0]["play"]


def test_anomaly_spike_against_baseline():
    now = NOW
    statm = [{"sk": minute_key(now - m * 60), "req": 10, "refused": 0, "auth": 1, "recon": 0, "decoy": 0}
             for m in range(60, 24 * 60)]
    statm += [{"sk": minute_key(now - m * 60), "req": 12, "refused": 40, "auth": 1, "recon": 3, "decoy": 0}
              for m in range(0, 5)]
    a = anomalies(statm, now)
    assert not a["learning"]
    assert {f["metric"] for f in a["flags"]} >= {"refused", "recon"}
    assert "req" not in {f["metric"] for f in a["flags"]}
    assert anomalies([], now)["learning"]


def test_suspects_get_the_edge_challenge_not_a_lambda_tarpit():
    t, w = FakeTable(), FakeWaf()
    c = cfg(SUSPECT4_NAME="s4", SUSPECT4_ID="s4", **C)
    run(awslogs(waf_records(tarpit_only_view())), t, w, c, now=NOW)
    assert w.sets["s4"] == ["203.0.113.7/32"]          # tarpit verdict -> silent Challenge at the edge
    assert "v4" not in w.sets or w.sets["v4"] == []      # ... and not a block
    admin.set_policy(t, c, {"edge": "tarpit"}, "op", NOW)
    scorer.sync(t, w, c, NOW + 1)
    assert w.sets["v4"] == ["203.0.113.7/32"] and w.sets["s4"] == []   # now blocked instead


def test_challenged_request_counts_as_refused():
    from aa_ai.events import parse_waf
    rec = {"timestamp": 1, "action": "CHALLENGE", "httpRequest": {"clientIp": "1.2.3.4", "uri": "/x", "headers": []}}
    assert parse_waf(rec).status == 403
    rec["challengeResponse"] = {"solveTimestamp": 2}
    assert parse_waf(rec).status != 403
