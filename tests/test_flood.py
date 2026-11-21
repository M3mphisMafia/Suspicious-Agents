"""Flood mode: surge math, per-IP flags, the cost guard, the pattern rule's guardrails and its life
in the live web ACL. In-memory stand-ins only; the model is replaced and never called."""
import copy
import re
from pathlib import Path

import pytest

from aa_ai import acl, admin, flood, scorer
from aa_ai.scorer import minute_key, run
from test_controls import RULES, AclWaf
from test_scorer import NOW, FakeTable, awslogs, cfg

C = dict(ALLOW4_NAME="a4", ALLOW4_ID="a4", WEBACL_NAME="aa-ai-edge-shield", WEBACL_ID="acl")
CUR = int(NOW // 60) - 1                     # the last complete minute: what the tick judges
CURL = "curl/8.9.1"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
MANAGED = [{"Name": "aws-anti-ddos", "Priority": 17, "OverrideAction": {"None": {}}, "Statement": {}, "VisibilityConfig": {}},
           {"Name": "aws-ip-reputation", "Priority": 18, "OverrideAction": {"None": {}}, "Statement": {}, "VisibilityConfig": {}}]


class LiveAcl(AclWaf):
    """Shaped like the live ACL: the managed groups at 17-18, and SearchString handed back as bytes."""

    def __init__(self):
        super().__init__()
        self.acl["Rules"] = copy.deepcopy(RULES + MANAGED)

    def update_web_acl(self, Name, Scope, Id, Rules, LockToken, **kw):
        def as_bytes(o):
            if isinstance(o, dict):
                return {k: (v.encode() if k == "SearchString" and isinstance(v, str) else as_bytes(v)) for k, v in o.items()}
            return [as_bytes(v) for v in o] if isinstance(o, list) else o
        super().update_web_acl(Name, Scope, Id, as_bytes(Rules), LockToken, **kw)

    def rule(self):
        return next((r for r in self.acl["Rules"] if r["Name"] == acl.FLOOD_RULE), None)


def traffic(t, norm=100, rpm=5000, cur=CUR):
    for k in range(1, flood.BASELINE_MINUTES + 1):
        t.put_item(Item={"pk": "STATM", "sk": minute_key((cur - k) * 60), "req": norm, "exp": NOW + 99999})
    t.put_item(Item={"pk": "STATM", "sk": minute_key(cur * 60), "req": rpm, "exp": NOW + 99999})


def rates(t, ips: dict, cur=CUR):
    for ip, n in ips.items():
        t.put_item(Item={"pk": f"RATE#{minute_key(cur * 60)}", "sk": ip, "n": n, "exp": NOW + 99999})


def profile(t, rows: dict, total: int, cur=CUR):
    pk = f"PROF#{minute_key(cur * 60)}"
    t.put_item(Item={"pk": pk, "sk": "total", "n": total, "exp": NOW + 99999})
    for (f, v), n in rows.items():
        t.put_item(Item={"pk": pk, "sk": f"{f}#{v}", "n": n, "exp": NOW + 99999})


def policy(t, c=None, mode=None, **over):
    c = c or cfg(**C)
    change = {**({"flood": over} if over else {}), **({"mode": mode} if mode else {})}
    if change:
        admin.set_policy(t, c, change, "op", NOW)
    return scorer.load_policy(t, c)


def flood_flags(t):
    return {v["ips"][0]: v for (pk, _), v in t.items.items() if pk == "FLAG" and v.get("flood")}


def kinds(t, pk):
    return [v for (p, _), v in t.items.items() if p == pk]


class _Never:
    """Stands in where the model must not be called. choose() swallows a raising model (that is the
    fallback path), so raising alone proves nothing: calls are counted and checked after each test."""
    calls = 0

    def __call__(self, ev):
        _Never.calls += 1
        raise RuntimeError("the model must not be called")


never = _Never()


@pytest.fixture(autouse=True)
def model_never_reached_through_never():
    _Never.calls = 0
    yield
    assert _Never.calls == 0, "the model was called where it must not be"


def answer(a, seen=None):
    def ask(ev):
        if seen is not None:
            seen.append(ev)
        return a, {"in": 900, "out": 60, "stop": "end_turn"}
    return ask


def surge_for(t, minutes=2, cur=CUR):
    """A surge already this many minutes old (started at cur - minutes + 1)."""
    t.put_item(Item={**flood.STATE, "active": True, "since": (cur - minutes + 1) * 60, "calm": 0,
                     "minutes": list(range(cur - minutes + 1, cur)), "baseline": 100})


# ---------- surge math ----------

def test_surge_math():
    fp = scorer.DEFAULT_POLICY["flood"]
    series = {m: 100 for m in range(70, 100)} | {100: 5000}
    assert flood.baseline(series, 100) == 100
    assert flood.threshold(100, fp) == 600                  # the floor wins over 5 x 100
    assert flood.threshold(1000, fp) == 5000                # 5 x the norm wins over the floor
    # a long flood does not teach itself into the norm: surge minutes are left out
    long = {m: 100 for m in range(70, 85)} | {m: 9000 for m in range(85, 100)}
    assert flood.baseline(long, 100) > 4000                  # a plain median has already learned the flood
    assert flood.baseline(long, 100, skip=set(range(85, 100))) == 100
    assert flood.baseline(long, 100, skip=set(range(70, 100)), fallback=120) == 120   # all surge: keep the start norm


def test_a_surge_starts_and_ends_with_one_alert_each():
    t, w = FakeTable(), LiveAcl()
    traffic(t, norm=100, rpm=5000)
    out = flood.tick(t, w, cfg(**C), policy(t), now=NOW, ask=never)
    assert out["active"] and out["threshold"] == 600 and out["baseline"] == 100
    for i in range(1, 4):   # still surging: no repeat alert
        traffic(t, norm=100, rpm=5000, cur=CUR + i)
        flood.tick(t, w, cfg(**C), policy(t), now=NOW + 60 * i, ask=never)
    starts = [a for a in kinds(t, "ALERT") if a["kind"] == "flood"]
    assert len(starts) == 1 and "flood:" in starts[0]["subject"]
    for i in range(4, 4 + flood.CALM_MINUTES):   # calm minutes in a row end it
        traffic(t, norm=100, rpm=90, cur=CUR + i)
        out = flood.tick(t, w, cfg(**C), policy(t), now=NOW + 60 * i, ask=never)
    assert not out["active"]
    subjects = [a["subject"] for a in kinds(t, "ALERT") if a["kind"] == "flood"]
    assert len(subjects) == 2 and subjects[-1].startswith("flood over")
    assert {m["move"] for m in kinds(t, "MOVE")} >= {"flood_surge", "flood_over"}


# ---------- per-IP flags ----------

def test_no_flags_outside_a_surge():
    t, w = FakeTable(), LiveAcl()
    rates(t, {f"198.51.100.{i}": 500 for i in range(10)})
    traffic(t, norm=100, rpm=450)                            # above 4x the norm, under the 600 floor
    assert not flood.tick(t, w, cfg(**C), policy(t), now=NOW, ask=never)["active"]
    t2 = FakeTable()
    rates(t2, {f"198.51.100.{i}": 500 for i in range(10)})
    traffic(t2, norm=1000, rpm=4900)                         # busy site: under 5 x its own norm
    assert not flood.tick(t2, w, cfg(**C), policy(t2), now=NOW, ask=never)["active"]
    assert not flood_flags(t) and not flood_flags(t2) and w.acl_writes == 0


def test_flags_respect_allow_list_and_max_ips():
    t, w = FakeTable(), LiveAcl()
    c = cfg(**C, ALLOW_CIDRS="203.0.113.0/24")
    traffic(t)
    t.put_item(Item={"pk": "ALLOW", "sk": "192.0.2.50/32", "exp": NOW + 3600})       # an operator unblock
    rates(t, {**{f"198.51.100.{i}": 300 + i for i in range(10)}, "203.0.113.9": 999, "192.0.2.50": 999,
              "198.51.100.200": 119, "not-an-ip": 999})
    out = flood.tick(t, w, c, policy(t, c, max_ips=4), now=NOW, ask=never)
    got = flood_flags(t)
    assert sorted(got) == ["198.51.100.6", "198.51.100.7", "198.51.100.8", "198.51.100.9"]   # heaviest four
    f = got["198.51.100.9"]
    assert f["verdict"] == "block" and f["flood"] is True and f["exp"] == int(NOW + 15 * 60)
    assert f["signals"] == ["flood: 309 requests/minute during a surge"]
    assert out["new"] and len([m for m in kinds(t, "MOVE") if m["move"] == "flood_block"]) == 1   # one move, not one per IP


def test_flags_renew_at_half_life_while_the_ip_keeps_flooding():
    t, w = FakeTable(), LiveAcl()
    traffic(t)
    rates(t, {"198.51.100.7": 900, "198.51.100.8": 900})
    for ip, left in (("198.51.100.7", 60), ("198.51.100.8", 800)):       # ttl is 900s: renew under 450s left
        t.put_item(Item={"pk": "FLAG", "sk": f"flood:{ip}", "verdict": "block", "score": 1, "ips": [ip], "flood": True,
                         "signals": ["flood: 500 requests/minute during a surge"], "exp": int(NOW + left)})
    out = flood.tick(t, w, cfg(**C), policy(t), now=NOW, ask=never)
    f = flood_flags(t)
    assert out["renewed"] == 1 and f["198.51.100.7"]["exp"] == int(NOW + 900) and f["198.51.100.8"]["exp"] == int(NOW + 800)


def test_unblocking_a_flood_ip_clears_it_and_keeps_it_clear():
    t, w = FakeTable(), LiveAcl()
    c = cfg(**C)
    traffic(t)
    rates(t, {"198.51.100.7": 900})
    flood.tick(t, w, c, policy(t, c), now=NOW, ask=never)
    assert "198.51.100.7" in flood_flags(t)
    scorer.unblock("198.51.100.7", t, w, c, reason="partner load test", now=NOW + 5)
    assert not flood_flags(t) and ("DET", "flood") not in t.items       # statistics, not a detector to tune
    assert kinds(t, "LABEL")[0]["outcome"] == "false_positive"
    flood.tick(t, w, c, policy(t, c), now=NOW + 10, ask=never)
    assert not flood_flags(t)                                            # the allow entry holds


def test_flood_ips_are_not_shared_as_indicators():
    from aa_ai.sinks import indicators
    flags = [{"sk": "flood:198.51.100.7", "verdict": "block", "score": 1, "ips": ["198.51.100.7"], "flood": True, "exp": NOW + 900},
             {"sk": "net:203.0.113.0/24|ua:curl/8", "verdict": "block", "score": 1, "ips": ["203.0.113.7"], "exp": NOW + 900}]
    assert [i["value"] for i in indicators(flags, NOW) if i["type"] == "ipv4"] == ["203.0.113.7"]


def test_verified_traffic_never_counts_toward_a_flood():
    from aa_ai.verify import key_hash
    t = FakeTable()
    token = "uk_" + "a" * 40
    t.put_item(Item={"pk": "IKEY", "sk": key_hash(token), "name": "partner-sync", "kind": "client"})
    recs = [rec("198.51.100.20", ts=NOW - 30 + i * 0.1, auth=f"Bearer {token}") for i in range(200)]
    recs += [rec("198.51.100.21", ts=NOW - 30 + i * 0.1) for i in range(200)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    counted = {v["sk"]: v["n"] for (pk, _), v in t.items.items() if pk.startswith("RATE#")}
    assert counted == {"198.51.100.21": 200}                 # the verified partner is not counted


def rec(ip, ts=NOW - 30, ua=CURL, path="/api/v2/search", action="ALLOW", rule="", status=None, auth=None, ja4="t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb"):
    hdrs = [{"name": "User-Agent", "value": ua}, {"name": "Host", "value": "shop.example"}]
    if auth:
        hdrs.append({"name": "Authorization", "value": auth})
    r = {"timestamp": int(ts * 1000), "action": action, "terminatingRuleId": rule, "ja4Fingerprint": ja4,
         "httpRequest": {"clientIp": ip, "uri": path, "args": "", "httpMethod": "GET", "requestId": f"r{ip}{ts}",
                         "headers": hdrs}, "labels": []}
    if status:
        r["responseCodeSent"] = status
    return r


def test_the_scheduled_tick_flags_before_it_syncs(monkeypatch):
    """The real handler, AWS clients replaced: a surge's blocks reach the WAF set in the same tick."""
    import boto3
    t, w = FakeTable(), LiveAcl()
    traffic(t)
    rates(t, {"198.51.100.7": 900, "198.51.100.8": 20})
    env = {"MODE": "enforce", "TABLE_NAME": "T", "IPSET4_NAME": "v4", "IPSET4_ID": "v4", "IPSET6_NAME": "v6",
           "IPSET6_ID": "v6", "WEBACL_NAME": "aa-ai-edge-shield", "WEBACL_ID": "acl"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for k in ("DASHBOARD_BUCKET", "ALERT_TOPIC_ARN", "CANARY_USER", "CELL_KVS_ARN", "ALLOW_CIDRS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("time.time", lambda: NOW)
    monkeypatch.setattr(flood, "_ask", never)
    monkeypatch.setattr(boto3, "resource", lambda name, **kw: type("R", (), {"Table": lambda self, n: t})())
    monkeypatch.setattr(boto3, "client", lambda name, **kw: w)
    out = scorer.tick_handler({"action": "snapshot"}, None)
    assert out["sync"]["synced"] and w.sets["v4"] == ["198.51.100.7/32"]


@pytest.mark.cell_edge
def test_flood_flags_go_to_the_block_sets_even_in_cell_mode():
    from test_cell import FakeKvs
    t, w, kvs = FakeTable(), LiveAcl(), FakeKvs()
    c = cfg(**C, CELL_KVS_ARN="arn:kvs")
    assert scorer.load_policy(t, c)["edge"] == "cell"
    t.put_item(Item={"pk": "FLAG", "sk": "agent", "verdict": "block", "score": 1, "ips": ["192.0.2.1", "192.0.2.2"],
                     "exp": NOW + 999})
    for ip in ("192.0.2.2", "198.51.100.7", "2001:db8::7"):  # .2 is an agent AND flooding: the flood wins
        t.put_item(Item={"pk": "FLAG", "sk": f"flood:{ip}", "verdict": "block", "score": 1, "ips": [ip], "flood": True,
                         "exp": NOW + 999})
    scorer.sync(t, w, c, NOW, kvs=kvs)
    assert w.sets["v4"] == ["192.0.2.2/32", "198.51.100.7/32"] and w.sets["v6"] == ["2001:db8::7/128"]
    assert set(kvs.keys) == {"ip:192.0.2.1"}                 # never routed to the padded cell
    # flood mode off releases its blocks at once; the agent stays in the cell
    admin.set_policy(t, c, {"flood": {"enabled": False}}, "op", NOW)
    scorer.sync(t, w, c, NOW + 1, kvs=kvs)
    assert w.sets["v4"] == [] and set(kvs.keys) == {"ip:192.0.2.1", "ip:192.0.2.2"}


def test_flood_ips_never_crowd_agents_out_of_the_block_set(monkeypatch):
    monkeypatch.setattr(scorer, "WAF_IPSET_MAX", 3)
    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": "agent", "verdict": "block", "score": 1, "ips": ["203.0.113.250"], "exp": NOW + 999})
    for i in range(5):
        t.put_item(Item={"pk": "FLAG", "sk": f"flood:198.51.100.{i}", "verdict": "block", "score": 1,
                         "ips": [f"198.51.100.{i}"], "flood": True, "exp": NOW + 999})
    d = scorer.compute_desired(t, cfg(), scorer.load_policy(t, cfg()), NOW)
    assert "203.0.113.250/32" in d["ip4"] and len(d["ip4"]) == 3


# ---------- the cost guard ----------

def test_cost_guard_counts_a_flood_but_stores_nothing():
    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": "flood:198.51.100.7", "verdict": "block", "score": 1,
                     "ips": ["198.51.100.7"], "flood": True, "exp": NOW + 900})
    recs = [rec("198.51.100.7", ts=NOW - 30 + i * 0.1, action="BLOCK", rule="flagged-ip", status=429) for i in range(100)]
    recs += [rec("198.51.100.8", ts=NOW - 30 + i * 0.1, action="BLOCK", rule="aws-anti-ddos", status=403) for i in range(50)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    stored = [pk for (pk, _) in t.items if pk.startswith("net:")]
    assert stored == []                                      # no per-event items, nothing rescored
    assert t.items[("STATM", minute_key(NOW))]["req"] == 150  # but every request is counted
    counted = {v["sk"]: v["n"] for (pk, _), v in t.items.items() if pk.startswith("RATE#")}
    assert counted == {"198.51.100.7": 100, "198.51.100.8": 50}   # and still drives the flood


def test_agent_evidence_from_other_edge_rules_is_still_stored():
    """WAF 429s from the login limit are how ignores_retry_after and keeps_hammering see an agent:
    only the flood-layer rules' stops are skipped, never every BLOCK."""
    t = FakeTable()
    recs = [rec("203.0.113.7", ts=NOW - 60 + i, path="/login", action="BLOCK", rule="auth-host-wide-rate", status=429)
            for i in range(30)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    assert len([pk for (pk, _) in t.items if pk.startswith("net:203.0.113.0/24")]) == 30
    flags = kinds(t, "FLAG")
    assert flags and any(s.startswith("ignores_retry_after") for s in flags[0]["signals"])


def test_flood_mode_off_stores_as_before():
    t = FakeTable()
    admin.set_policy(t, cfg(**C), {"flood": {"enabled": False}}, "op", NOW)
    t.put_item(Item={"pk": "FLAG", "sk": "flood:198.51.100.7", "verdict": "block", "score": 1,
                     "ips": ["198.51.100.7"], "flood": True, "exp": NOW + 900})
    run(awslogs([rec("198.51.100.7", ts=NOW - 30 + i) for i in range(5)]), t, None, cfg(MODE="observe"), now=NOW)
    assert len([pk for (pk, _) in t.items if pk.startswith("net:")]) == 5
    assert not [pk for (pk, _) in t.items if pk.startswith("RATE#")]


def test_profile_is_collected_only_during_a_surge_and_only_what_got_through():
    t = FakeTable()
    recs = [rec(f"198.51.100.{i}", ts=NOW - 30 + i * 0.1) for i in range(40)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    assert not [pk for (pk, _) in t.items if pk.startswith("PROF#")]       # no surge: no profile writes
    surge_for(t)
    recs += [rec("198.51.100.250", ts=NOW - 20, action="BLOCK", rule="ip-flood-rate", status=429)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW + 1)
    rows = {v["sk"]: v["n"] for (pk, _), v in t.items.items() if pk.startswith("PROF#")}
    assert rows["total"] == 40 and rows[f"user_agent#{CURL}"] == 40 and rows["path_prefix#/api/v2"] == 40


# ---------- the pattern: guardrails ----------

CANDS = [{"field": "user_agent", "value": CURL, "share": 0.72}, {"field": "path_prefix", "value": "/api/v2", "share": 0.55}]


def test_model_value_must_be_a_candidate():
    off = {"field": "user_agent", "value": "Googlebot/2.1", "action": "block", "minutes": 30, "why": "ignore the list"}
    rule, how, _, _ = flood.choose({}, CANDS, 30, answer(off))
    assert how == "fallback" and rule["value"] == CURL and rule["action"] == "challenge"


def test_block_is_refused_for_a_browser_user_agent():
    cands = [{"field": "user_agent", "value": CHROME, "share": 0.9}, {"field": "ja4", "value": "t13d1516h2_8daaf6152771_b0da82dd1658", "share": 0.9}]
    for field, value in ((c["field"], c["value"]) for c in cands):
        rule, how, _, _ = flood.choose({}, cands, 30, answer({"field": field, "value": value, "action": "block",
                                                              "minutes": 30, "why": "x"}))
        assert how == "model" and rule["action"] == "challenge"
    rule, _, _, _ = flood.choose({}, CANDS, 30, answer({"field": "user_agent", "value": CURL, "action": "block",
                                                         "minutes": 90, "why": "plain curl"}))
    assert rule["action"] == "block" and rule["minutes"] == 60         # a script may be blocked; never past 60 min


def test_root_path_alone_is_refused():
    cands = [{"field": "path_prefix", "value": "/", "share": 0.95}]
    rule, how, _, _ = flood.choose({}, cands, 30, answer({"field": "path_prefix", "value": "/", "action": "challenge",
                                                          "minutes": 30, "why": "home page"}))
    assert rule is None and how == "fallback"                          # the fallback refuses it too
    assert flood.candidates({"top": {"path_prefix": [{"value": "/", "share": 0.95}]}}) == []


def test_fallback_when_the_model_fails():
    def boom(ev):
        raise TimeoutError("read timed out")
    rule, how, meta, _ = flood.choose({}, CANDS, 30, boom)
    assert how == "fallback" and rule["value"] == CURL and rule["action"] == "challenge" and meta["error"] == "TimeoutError"
    weak = [{"field": "user_agent", "value": CURL, "share": 0.55}]
    for bad in (boom, answer(None), answer({"field": "user_agent"}), answer("block everything")):
        assert flood.choose({}, weak, 30, bad)[0] is None                # under 60%: nothing
    assert flood.choose({}, CANDS, 30, None)[1] == "fallback"           # hourly cap: no call, same fallback


def test_the_models_none_is_a_veto():
    rule, how, _, veto = flood.choose({}, CANDS, 30, answer({"field": "user_agent", "value": CURL, "action": "none",
                                                              "minutes": 5, "why": "looks like a partner's sync job"}))
    assert rule is None and how == "model" and veto["why"].startswith("looks like")


def test_untrusted_values_never_become_candidates():
    top = {"user_agent": [{"value": "<script>x</script>", "share": 0.9}, {"value": "bad\x00ua", "share": 0.8}],
           "ja4": [{"value": "t13d$(id)", "share": 0.9}], "path_prefix": [{"value": "/api/v2", "share": 0.49}]}
    assert flood.candidates({"total": 100, "top": top}) == []


# ---------- the pattern in the tick and the live web ACL ----------

def spread_flood(t, cur=CUR):
    """A surge 2 minutes old from 300 IPs at 20/min each: per-IP flags cannot catch it."""
    traffic(t, cur=cur, rpm=6000)
    rates(t, {f"10.{i // 250}.{i % 250}.1": 20 for i in range(300)}, cur=cur)
    profile(t, {("user_agent", CURL): 4300, ("user_agent", CHROME): 900, ("path_prefix", "/api/v2"): 5200,
                ("path_prefix", "/"): 400, ("ja4", "t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb"): 4400,
                ("host", "shop.example"): 6000}, total=6000, cur=cur)


def test_pattern_rule_is_applied_kept_and_removed():
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    surge_for(t, minutes=2)
    seen = []
    pick = {"field": "user_agent", "value": CURL, "action": "block", "minutes": 20, "why": "one HTTP library, 72%"}
    out = flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW, ask=answer(pick, seen))
    assert len(seen) == 1   # the model chooses among observed values only; "/" and the 15% browser are not on the menu
    assert {c["value"] for c in seen[0]["candidates"]} == {CURL, "/api/v2", "t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb"}
    assert out["share"] < flood.SPREAD and out["pattern"]["applied"]
    r = w.rule()
    assert r["Priority"] == 19 and r["Action"]["Block"]["CustomResponse"]["ResponseCode"] == 429
    assert r["Action"]["Block"]["CustomResponse"]["CustomResponseBodyKey"] == "generic"
    assert r["Statement"]["AndStatement"]["Statements"][0]["ByteMatchStatement"]["SearchString"] == CURL.encode()
    assert [x["Priority"] for x in w.acl["Rules"]] == sorted(x["Priority"] for x in w.acl["Rules"])
    assert {x["Name"] for x in w.acl["Rules"]} >= {"aws-anti-ddos", "aws-ip-reputation", "flagged-ip"}
    writes = w.acl_writes
    # next tick: still surging, rule unchanged -> no write, no second model call
    spread_flood(t, cur=CUR + 1)
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW + 60, ask=answer(pick, seen))
    assert w.acl_writes == writes and len(seen) == 1
    # an edge-control change keeps it; a block's Retry-After follows the policy
    admin.act({"action": "set_policy", "policy": {"edge_controls": {"geo": ["KP"], "retry_after": 5}}},
              t, w, cfg(**C), "op", NOW + 70)
    assert w.rule()["Action"]["Block"]["CustomResponse"]["ResponseHeaders"][0]["Value"] == "5"
    # a deploy resets the rules: the next tick puts it back
    w.acl["Rules"] = copy.deepcopy(RULES + MANAGED)
    spread_flood(t, cur=CUR + 2)
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW + 120, ask=answer(pick, seen))
    assert w.rule() is not None
    # the tick after it expires removes it, and only it
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW + 20 * 60 + 1, ask=answer(pick, seen))
    assert w.rule() is None and {x["Name"] for x in w.acl["Rules"]} >= {"flagged-ip", "aws-anti-ddos", "aws-ip-reputation"}
    assert "flood_pattern_removed" in {m["move"] for m in kinds(t, "MOVE")}


def test_pattern_rule_goes_about_ten_minutes_after_the_surge_ends():
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    surge_for(t, minutes=2)
    pick = {"field": "path_prefix", "value": "/api/v2", "action": "challenge", "minutes": 60, "why": "one route"}
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW, ask=answer(pick))
    assert w.rule()["Action"] == {"Challenge": {}}
    st = t.items[("FLOOD", "state")]
    t.put_item(Item={**st, "active": False, "ended": int(NOW + 60)})
    traffic(t, cur=CUR + 2, rpm=90)
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW + 120, ask=never)
    assert w.rule() is not None                              # 1 minute after: kept
    traffic(t, cur=CUR + 11, rpm=90)
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW + 60 + flood.REMOVE_AFTER, ask=never)
    assert w.rule() is None


def test_no_pattern_when_per_ip_flags_already_cover_the_surge():
    t, w = FakeTable(), LiveAcl()
    traffic(t, rpm=6000)
    rates(t, {f"198.51.100.{i}": 400 for i in range(15)})    # 15 x 400 = all of it
    profile(t, {("user_agent", CURL): 6000}, total=6000)
    surge_for(t, minutes=3)
    out = flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW, ask=never)
    assert out["share"] >= flood.SPREAD and out["pattern"] is None and w.rule() is None


def test_model_calls_are_capped_per_hour():
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    surge_for(t, minutes=2)
    t.put_item(Item={"pk": "FLOODCOUNT", "sk": scorer.hour_key(NOW), "calls": flood.MAX_CALLS_PER_HOUR})
    out = flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW, ask=never)
    assert out["pattern"]["by"] == "fallback" and out["pattern"]["action"] == "challenge"


def test_observe_mode_writes_nothing_to_waf():
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    rates(t, {"198.51.100.7": 900})
    surge_for(t, minutes=2)
    pick = {"field": "user_agent", "value": CURL, "action": "block", "minutes": 20, "why": "curl"}
    c = cfg(**C, MODE="observe")
    out = flood.tick(t, w, c, policy(t, c), now=NOW, ask=answer(pick))
    assert scorer.load_policy(t, c)["mode"] == "observe"
    assert out["pattern"] and not out["pattern"]["applied"] and "198.51.100.7" in flood_flags(t)
    scorer.sync(t, w, c, NOW)
    assert w.acl_writes == 0 and "v4" not in w.sets and "v6" not in w.sets
    assert any("(observe: not applied)" in m["detail"] for m in kinds(t, "MOVE") if m["move"] == "flood_pattern")


def test_advise_mode_records_but_never_applies():
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    surge_for(t, minutes=2)
    pick = {"field": "user_agent", "value": CURL, "action": "challenge", "minutes": 20, "why": "curl"}
    out = flood.tick(t, w, cfg(**C), policy(t, mode="enforce", pattern="advise"), now=NOW, ask=answer(pick))
    assert out["pattern"]["value"] == CURL and w.acl_writes == 0


# ---------- acl ----------

def test_edge_controls_keep_a_live_flood_rule():
    challenge = acl.flood_rule("ja4", "t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb", "challenge")
    out = acl.patch_rules(RULES + MANAGED + [challenge], {"geo": ["IR"], "retry_after": 4})
    assert next(r for r in out if r["Name"] == acl.FLOOD_RULE) == challenge     # untouched
    block = acl.flood_rule("user_agent", CURL, "block", 9)
    out = acl.patch_rules(RULES + [block], {"retry_after": 4})
    assert next(r for r in out if r["Name"] == acl.FLOOD_RULE)["Action"] == acl._block(429, 4)


def test_apply_flood_is_idempotent_and_refuses_a_taken_priority():
    w = LiveAcl()
    rule = acl.flood_rule("user_agent", CURL, "challenge")
    rule["Statement"]["AndStatement"]["Statements"][0]["ByteMatchStatement"]["SearchString"] = CURL   # str in, bytes back
    assert acl.apply_flood(w, "aa-ai-edge-shield", "acl", rule) is True
    assert acl.apply_flood(w, "aa-ai-edge-shield", "acl", rule) is False                # same rule: no write
    assert acl.apply_flood(w, "aa-ai-edge-shield", "acl", None) is True and w.rule() is None
    assert acl.apply_flood(w, "aa-ai-edge-shield", "acl", None) is False
    with pytest.raises(ValueError):
        acl.apply_flood(w, "aa-ai-edge-shield", "acl", {**rule, "Priority": 17})


def test_console_path_is_exempt_from_the_flood_rule():
    stmts = acl.flood_rule("ja4", "t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb", "challenge")["Statement"]["AndStatement"]["Statements"]
    assert stmts[1]["NotStatement"]["Statement"]["ByteMatchStatement"]["SearchString"] == b"/_undertow/"


def test_template_leaves_priority_19_free_and_grants_the_scorer_the_acl():
    t = (Path(__file__).parent.parent / "infra" / "edge-shield.yaml").read_text()
    prios = {int(p) for p in re.findall(r"^\s+Priority: (\d+)$", t, re.M)}
    assert acl.FLOOD_PRIORITY not in prios and {18, 20} <= prios     # free, between the managed groups
    role = t.split("\n  TickRole:", 1)[1].split("\n  TickFunction:", 1)[0]
    assert "wafv2:UpdateWebACL" in role and "bedrock-mantle:CreateInference" in role
    fn = t.split("\n  TickFunction:", 1)[1].split("\n  TickInvokeConfig:", 1)[0]
    assert "WEBACL_ID: !GetAtt WebAcl.Id" in fn and "Layers: !If [HasJudge, [!Ref JudgeLayer]" in fn


# ---------- policy and dashboard ----------

def test_flood_policy_is_validated_and_survives_other_edits():
    t = FakeTable()
    for bad in ({"multiplier": 1}, {"per_ip_rpm": 5}, {"pattern": "always"}, {"max_ips": 9000},
                {"pattern_minutes": 120}, {"surprise": 1}, "on"):
        with pytest.raises(ValueError):
            admin.set_policy(t, cfg(), {"flood": bad}, "op", NOW)
    admin.set_policy(t, cfg(), {"flood": {"multiplier": 2.5, "per_ip_rpm": 200, "pattern": "advise"}}, "op", NOW)
    admin.set_policy(t, cfg(), {"judge": {"enabled": False}}, "op", NOW + 1)        # an unrelated save
    fp = scorer.load_policy(t, cfg())["flood"]
    assert (fp["multiplier"], fp["per_ip_rpm"], fp["pattern"], fp["floor_rpm"]) == (2.5, 200, "advise", 600)


def test_snapshot_has_a_flood_card_and_keeps_flood_ips_out_of_the_agent_views():
    from aa_ai.snapshot import build
    t, w = FakeTable(), LiveAcl()
    spread_flood(t)
    rates(t, {"198.51.100.7": 900})
    surge_for(t, minutes=2)
    pick = {"field": "user_agent", "value": CURL, "action": "challenge", "minutes": 20, "why": "curl"}
    flood.tick(t, w, cfg(**C), policy(t, mode="enforce"), now=NOW, ask=answer(pick))
    d = build(t, scorer.load_policy(t, cfg(**C)), 1, now=NOW + 5)
    f = d["flood"]
    assert f["active"] and f["rpm"] == 6000 and f["baseline"] == 100 and f["flagged"] == 1
    assert f["pattern"]["value"] == CURL and f["pattern"]["applied"] and f["calls_24h"] == 1
    assert {e["move"] for e in f["events"]} >= {"flood_block", "flood_pattern"}
    assert d["ladder"]["block"] == 0 and not d["actors"]                  # not an agent
    import json
    json.dumps(d)


def test_parse_waf_carries_the_terminating_rule():
    from aa_ai.events import parse_waf
    e = parse_waf(rec("198.51.100.7", action="BLOCK", rule="aws-anti-ddos", status=403))
    assert e.extra["rule"] == "aws-anti-ddos" and e.extra["action"] == "BLOCK" and flood.stopped_by_flood_rule(e)
    assert not flood.stopped_by_flood_rule(parse_waf(rec("1.2.3.4", action="BLOCK", rule="tool-ua", status=403)))
