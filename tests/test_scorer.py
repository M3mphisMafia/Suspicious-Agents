"""Scorer Lambda against in-memory DynamoDB and WAF stand-ins (no AWS)."""
import base64
import gzip
import json
import random
import re
from contextlib import contextmanager

from aa_ai import detectors
from aa_ai.scorer import Config, JA4_PLACEHOLDER, run
from test_detection import agent_trace, human_trace

GO_JA4 = "t13d190900_9dc949149365_97f8aa674fd9"


class FakeTable:
    def __init__(self):
        self.items = {}

    @contextmanager
    def batch_writer(self, overwrite_by_pkeys=None):
        yield self

    def put_item(self, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def delete_item(self, Key):
        self.items.pop((Key["pk"], Key["sk"]), None)

    def get_item(self, Key):
        it = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(it)} if it else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues, ReturnValues=None):
        """Enough of DynamoDB's 'ADD #a :a, ... SET #x = :x, #y = if_not_exists(#y, :v)'."""
        item = self.items.setdefault((Key["pk"], Key["sk"]), dict(Key))
        names, vals = ExpressionAttributeNames, ExpressionAttributeValues
        add, _, sets = UpdateExpression.partition(" SET ")
        for clause in add.removeprefix("ADD ").split(", "):
            n, v = clause.split(" ")
            item[names[n]] = item.get(names[n], 0) + vals[v]
        for clause in filter(None, [c.strip() for c in re.split(r", (?=#)", sets)] if sets else []):
            n, v = (s.strip() for s in clause.split("=", 1))
            if v.startswith("if_not_exists("):
                _, dflt = v[len("if_not_exists("):-1].split(", ")
                item.setdefault(names[n], vals[dflt])
            else:
                item[names[n]] = vals[v]
        if ReturnValues:
            return {"Attributes": {k: v for k, v in item.items() if k not in ("pk", "sk")}}

    def query(self, KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward=True,
              Limit=None, ExclusiveStartKey=None):
        pk = ExpressionAttributeValues.get(":k", ExpressionAttributeValues.get(":f"))
        lo = ExpressionAttributeValues.get(":s", "")
        rows = sorted((v for (p, s), v in self.items.items() if p == pk and s >= lo),
                      key=lambda i: i["sk"], reverse=not ScanIndexForward)
        return {"Items": rows[:Limit] if Limit else rows}


class FakeWaf:
    class exceptions:
        class WAFOptimisticLockException(Exception):
            pass

    def __init__(self, lock_failures=0):
        self.sets = {}
        self.lock_failures = lock_failures
        self.calls = 0

    def get_ip_set(self, Name, Scope, Id):
        assert Scope == "CLOUDFRONT"
        return {"LockToken": "t", "IPSet": {"Addresses": list(self.sets.get(Id, []))}}

    def get_regex_pattern_set(self, Name, Scope, Id):
        assert Scope == "CLOUDFRONT"
        return {"LockToken": "t", "RegexPatternSet": {"RegularExpressionList": [
            {"RegexString": r} for r in self.sets.get(Id, [JA4_PLACEHOLDER])]}}

    def _upd(self, Id, value):
        self.calls += 1
        if self.lock_failures:
            self.lock_failures -= 1
            raise self.exceptions.WAFOptimisticLockException()
        self.sets[Id] = value

    def update_ip_set(self, Name, Scope, Id, Addresses, LockToken):
        self._upd(Id, Addresses)

    def update_regex_pattern_set(self, Name, Scope, Id, RegularExpressionList, LockToken):
        self._upd(Id, [r["RegexString"] for r in RegularExpressionList])


def cfg(**over):
    env = {"MODE": "enforce", "IPSET4_NAME": "v4", "IPSET4_ID": "v4", "IPSET6_NAME": "v6",
           "IPSET6_ID": "v6", "JA4SET_NAME": "ja4", "JA4SET_ID": "ja4",
           "DECOY_PREFIX": "/api/v1/internal/ops"}
    env.update(over)
    return Config(env)


def waf_records(events, ja4=GO_JA4, decoy_label_paths=()):
    recs = []
    for e in events:
        r = {"timestamp": int(e.ts * 1000), "action": "ALLOW", "ja4Fingerprint": ja4,
             "httpRequest": {"clientIp": e.src_ip, "uri": e.path, "args": e.payload,
                             "httpMethod": e.method, "requestId": f"r{e.ts}",
                             "headers": [{"name": "User-Agent", "value": e.user_agent},
                                         {"name": "Host", "value": e.host or "app.example"}]},
             "labels": []}
        if e.status == 429:
            r["action"], r["responseCodeSent"] = "BLOCK", 429
        if e.path in decoy_label_paths:
            r["labels"] = [{"name": "awswaf:111:webacl:aa-ai-edge-shield:aa-ai:decoy"}]
        recs.append(r)
    return recs


def awslogs(recs):
    body = {"logEvents": [{"id": str(i), "timestamp": r["timestamp"], "message": json.dumps(r)}
                          for i, r in enumerate(recs)]}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(body).encode())).decode()}}


def _agent_waf_view():
    """What WAF actually sees: no origin status, so strip it (except WAF's own 429s)."""
    random.seed(11)
    evs = agent_trace()
    for e in evs:
        if e.status != 429:
            e.status = 0
    return evs


NOW = 1_800_000_000.0 + 600


def test_observe_mode_never_touches_waf():
    t, w = FakeTable(), FakeWaf()
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(MODE="observe"), now=NOW)
    assert out["flags"] == 1 and out["synced"] is False
    assert w.calls == 0


def test_agent_from_waf_logs_is_blocked_human_is_not():
    t, w = FakeTable(), FakeWaf()
    random.seed(4)
    human = human_trace()
    for e in human:
        e.status = 0
    recs = waf_records(_agent_waf_view()) + waf_records(human, ja4="t13d1516h2_8daaf6152771_b0da82dd1658")
    out = run(awslogs(recs), t, w, cfg(), now=NOW)
    assert out["flags"] == 1
    assert w.sets["v4"] == ["203.0.113.7/32"]
    assert w.sets.get("ja4", [JA4_PLACEHOLDER]) == [JA4_PLACEHOLDER]      # JA4 flagging is opt-in


def test_allowlisted_cidr_never_flagged():
    t, w = FakeTable(), FakeWaf()
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(ALLOW_CIDRS="203.0.113.0/24"), now=NOW)
    assert out["flags"] == 0 and w.calls == 0


def test_ja4_only_for_decoy_confirmed_block_and_not_protected():
    evs = _agent_waf_view()
    decoy = "/api/v1/internal/ops/export"
    evs[5].path = decoy
    recs = waf_records(evs, decoy_label_paths={decoy})
    t, w = FakeTable(), FakeWaf()
    run(awslogs(recs), t, w, cfg(FLAG_JA4="true"), now=NOW)
    assert w.sets.get("ja4", [JA4_PLACEHOLDER]) == [f"^{GO_JA4}$"]
    t, w = FakeTable(), FakeWaf()
    run(awslogs(recs), t, w, cfg(FLAG_JA4="true", PROTECTED_JA4=GO_JA4), now=NOW)
    assert w.sets.get("ja4", [JA4_PLACEHOLDER]) == [JA4_PLACEHOLDER]


def test_sync_drops_expired_flags():
    t, w = FakeTable(), FakeWaf()
    run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW)
    assert w.sets["v4"]
    run({"action": "sync"}, t, w, cfg(), now=NOW + 2 * 86400)
    assert w.sets["v4"] == []


def test_lock_conflict_is_retried():
    t, w = FakeTable(), FakeWaf(lock_failures=2)
    run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW)
    assert w.sets["v4"] == ["203.0.113.7/32"]


def test_unchanged_sets_are_not_rewritten():
    """WAF's change API is rate-limited (ThrottlingException live): a resync with nothing new writes nothing."""
    t, w = FakeTable(), FakeWaf()
    run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW)
    first = w.calls
    assert first >= 1
    out = run({"action": "sync"}, t, w, cfg(), now=NOW + 5)
    assert out["writes"] == 0 and w.calls == first


def test_throttled_log_batch_is_not_failed(monkeypatch):
    class Throttle(Exception):
        response = {"Error": {"Code": "ThrottlingException"}}

    t, w = FakeTable(), FakeWaf()
    monkeypatch.setattr("aa_ai.scorer.time.sleep", lambda s: None)

    def boom(**_):
        raise Throttle()

    w.update_ip_set = boom
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW)
    assert out["flags"] == 1 and out["writes"] == -1   # deferred to the 1-minute tick, batch not failed


def test_state_accumulates_across_batches():
    """The agent's run arrives over many small log batches; the score must still build."""
    evs = _agent_waf_view()
    t, w = FakeTable(), FakeWaf()
    flagged = 0
    for i in range(0, len(evs), 5):
        flagged += run(awslogs(waf_records(evs[i:i + 5])), t, w, cfg(), now=NOW)["flags"]
    assert flagged >= 1 and w.sets["v4"] == ["203.0.113.7/32"]


def test_unblock_clears_flag_labels_false_positive_and_stays_unblocked():
    from aa_ai.scorer import unblock

    t, w = FakeTable(), FakeWaf()
    c = cfg(ALLOW4_NAME="a4", ALLOW4_ID="a4", ALLOW6_NAME="a6", ALLOW6_ID="a6")
    evs = _agent_waf_view()
    run(awslogs(waf_records(evs)), t, w, c, now=NOW)
    assert w.sets["v4"] == ["203.0.113.7/32"]

    res = unblock("203.0.113.7", t, w, c, reason="partner scanner", by="arn:test", now=NOW + 10)
    assert res["cleared"] and w.sets["v4"] == [] and w.sets["a4"] == ["203.0.113.7/32"]
    labels = [v for (pk, _), v in t.items.items() if pk == "LABEL"]
    assert labels[0]["outcome"] == "false_positive" and labels[0]["signals"]

    # the same traffic again does not re-flag while the allow entry lives
    def replay(shift):
        return [type(e)(e.ts + shift, *[getattr(e, f) for f in ("src_ip", "method", "path", "status",
                                                                  "user_agent")]) for e in evs]

    assert run(awslogs(waf_records(replay(60))), t, w, c, now=NOW + 120)["flags"] == 0
    # ...and fresh attack traffic can flag it again once the allow entry expires
    assert run(awslogs(waf_records(replay(2 * 86400))), t, w, c, now=NOW + 2 * 86400)["flags"] == 1


def test_observe_mode_keeps_allow_list_current_but_never_blocks():
    t, w = FakeTable(), FakeWaf()
    c = cfg(MODE="observe", ALLOW4_NAME="a4", ALLOW4_ID="a4", ALLOW_CIDRS="198.51.100.0/24")
    run(awslogs(waf_records(_agent_waf_view())), t, w, c, now=NOW)
    assert w.sets.get("a4") == ["198.51.100.0/24"]
    assert "v4" not in w.sets and "ja4" not in w.sets


def test_stack_config_reads_outputs():
    from aa_ai.__main__ import stack_config

    class Cfn:
        def describe_stacks(self, StackName):
            outs = {"ScorerTableName": "T", "FlaggedIpSetId": "f4", "FlaggedIp6SetId": "f6",
                    "FlaggedJa4SetId": "j", "AllowedIpSetId": "a4", "AllowedIp6SetId": "a6"}
            return {"Stacks": [{"Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in outs.items()],
                                "Parameters": [{"ParameterKey": "ScorerMode", "ParameterValue": "enforce"}]}]}

    c = stack_config(Cfn(), "s")
    assert (c.table, c.mode, c.ip6[1], c.allow4[1]) == ("T", "enforce", "f6", "a4")


def teardown_function(_):
    detectors.DECOY_PREFIXES.clear()


def test_new_ip_of_an_already_blocked_agent_joins_the_block():
    """Live 11-19: the same agent came back from .221 while .219 was blocked; the skip
    path for blocked agents dropped the new IP, so the edge never blocked it."""
    t, w = FakeTable(), FakeWaf()
    evs = _agent_waf_view()
    run(awslogs(waf_records(evs)), t, w, cfg(), now=NOW)
    assert w.sets["v4"] == ["203.0.113.7/32"]
    again = [type(e)(e.ts + 120, "203.0.113.8", e.method, e.path, e.status, e.user_agent) for e in evs[:5]]
    run(awslogs(waf_records(again)), t, w, cfg(), now=NOW + 120)
    assert w.sets["v4"] == ["203.0.113.7/32", "203.0.113.8/32"]
    assert any(v.get("move") == "linked_rotation" for (pk, _), v in t.items.items() if pk == "MOVE")


def test_rotating_fork_collapses_to_one_actor():
    """RuoJi6/ARTEX: random real browser UA per request + proxy pool rotation, Go TLS,
    no Sec-Fetch headers. Must stay ONE actor (by JA4) and be flagged."""
    uas = [f"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/15{i}.0 Safari/537.36" for i in range(6)]
    recs = []
    for i, e in enumerate(_agent_waf_view()[:40]):
        r = waf_records([e], ja4="t13d1312h2_goclient_x")[0]
        r["httpRequest"]["clientIp"] = f"198.51.{100 + i % 7}.{i}"
        r["httpRequest"]["headers"] = [{"name": "User-Agent", "value": uas[i % 6]}, {"name": "Host", "value": "app.example"}]
        recs.append(r)
    t, w = FakeTable(), FakeWaf()
    run(awslogs(recs), t, w, cfg(), now=NOW)
    flags = [v for (pk, _), v in t.items.items() if pk == "FLAG"]
    assert len(flags) == 1 and flags[0]["sk"] == "spoof|tls:t13d1312h2_goclient_x"
    names = {s.split(":")[0] for s in flags[0]["signals"]}
    assert {"spoofed_browser", "ua_churn"} <= names and len(flags[0]["ips"]) >= 7


def test_real_browser_is_not_spoofed():
    from aa_ai.events import spoofed_browser
    chrome = {"user-agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/156.0 Safari/537.36",
              "sec-fetch-mode": "navigate", "sec-fetch-site": "none"}
    assert not spoofed_browser(chrome)
    assert spoofed_browser({"user-agent": chrome["user-agent"]})
    assert not spoofed_browser({"user-agent": "curl/8.9.1"})          # honest tools are not "spoofed"
