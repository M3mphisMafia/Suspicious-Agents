"""Live edge controls (WAF ACL patching, lockdown, JA4 switch) and alerts."""
import copy

import pytest

from aa_ai import acl, admin, alerts, scorer
from aa_ai.scorer import run
from test_scorer import NOW, FakeTable, FakeWaf, _agent_waf_view, awslogs, cfg, waf_records

C = dict(ALLOW4_NAME="a4", ALLOW4_ID="a4", CHALLENGE4_NAME="c4", CHALLENGE4_ID="c4",
         WEBACL_NAME="aa-ai-edge-shield", WEBACL_ID="acl")

RULES = [
    {"Name": "allow-list", "Priority": 2, "Action": {"Allow": {}}, "Statement": {}, "VisibilityConfig": {}},
    {"Name": "flagged-ip", "Priority": 5, "Action": acl._block(429, 9), "Statement": {}, "VisibilityConfig": {}},
    {"Name": "auth-host-wide-rate", "Priority": 7, "Action": acl._block(429, 9),
     "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}}, "VisibilityConfig": {}},
]


class AclWaf(FakeWaf):
    def __init__(self):
        super().__init__()
        # shaped like the live get_web_acl response, including the empty Description it returns
        self.acl = {"Name": "aa-ai-edge-shield", "Description": "", "Rules": copy.deepcopy(RULES), "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {"MetricName": "aa-ai"}, "CustomResponseBodies": {"generic": {}}}
        self.acl_writes = 0

    def get_web_acl(self, Name, Scope, Id):
        return {"WebACL": copy.deepcopy(self.acl), "LockToken": "t"}

    def update_web_acl(self, Name, Scope, Id, Rules, LockToken, **kw):
        assert kw["DefaultAction"] and kw["CustomResponseBodies"]   # never dropped on update
        assert all(v not in ("", [], {}) for v in kw.values())     # live WAF rejects empty Description
        self.acl["Rules"] = Rules
        self.acl_writes += 1


@pytest.fixture
def sent(monkeypatch):
    out = []
    monkeypatch.setattr(alerts, "_publish", lambda subject, message: out.append((subject, message)) or True)
    return out


def test_edge_controls_patch_the_live_acl(sent):
    t, w = FakeTable(), AclWaf()
    admin.act({"action": "set_policy", "policy": {"edge_controls": {"auth_rate": 300, "retry_after": 5,
                                                                    "geo": ["kp", "IR"], "asn": [64512]}}},
              t, w, cfg(**C), "op", NOW)
    rules = {r["Name"]: r for r in w.acl["Rules"]}
    assert rules["auth-host-wide-rate"]["Statement"]["RateBasedStatement"]["Limit"] == 300
    assert rules["flagged-ip"]["Action"]["Block"]["CustomResponse"]["ResponseHeaders"][0]["Value"] == "5"
    assert rules["geo-block"]["Statement"]["GeoMatchStatement"]["CountryCodes"] == ["IR", "KP"]
    assert rules["asn-block"]["Statement"]["AsnMatchStatement"]["AsnList"] == [64512]
    assert [r["Priority"] for r in w.acl["Rules"]] == sorted(r["Priority"] for r in w.acl["Rules"])
    # saved, so the next deploy passes the same values
    assert scorer.load_policy(t, cfg())["edge_controls"]["geo"] == ["IR", "KP"]
    assert acl.stack_params(scorer.load_policy(t, cfg())["edge_controls"])["GeoBlockCountries"] == "IR,KP"
    # clearing geo removes the rule; an unchanged policy does not rewrite the ACL
    admin.act({"action": "set_policy", "policy": {"edge_controls": {"geo": []}}}, t, w, cfg(**C), "op", NOW + 1)
    assert "geo-block" not in {r["Name"] for r in w.acl["Rules"]}
    n = w.acl_writes
    admin.act({"action": "set_policy", "policy": {"edge_controls": {"geo": []}}}, t, w, cfg(**C), "op", NOW + 2)
    assert w.acl_writes == n


def test_edge_controls_refuse_bad_values(sent):
    t, w = FakeTable(), AclWaf()
    for bad in ({"auth_rate": 5}, {"retry_after": 0}, {"geo": ["USA"]}, {"asn": ["x"]}):
        with pytest.raises((ValueError, TypeError)):
            admin.act({"action": "set_policy", "policy": {"edge_controls": bad}}, t, w, cfg(**C), "op", NOW)


def test_lockdown_blocks_watch_level_actors_at_the_edge(sent):
    t, w = FakeTable(), AclWaf()
    t.put_item(Item={"pk": "WATCH", "sk": "net:192.0.2.0/24|ua:x", "score": 0.35, "ips": ["192.0.2.40"], "exp": NOW + 600})
    out = scorer.sync(t, w, cfg(**C), NOW)
    assert out["ip4"] == 0
    admin.act({"action": "set_policy", "policy": {"edge": "lockdown"}}, t, w, cfg(**C), "op", NOW)
    assert w.sets["v4"] == ["192.0.2.40/32"]


def test_ja4_switch_overrides_the_stack_parameter(sent):
    t, w = FakeTable(), AclWaf()
    evs = _agent_waf_view()
    evs[5].path = "/api/v1/internal/ops/export"
    run(awslogs(waf_records(evs, decoy_label_paths={evs[5].path})), t, w, cfg(**C), now=NOW)
    assert w.sets.get("ja4", [scorer.JA4_PLACEHOLDER]) == [scorer.JA4_PLACEHOLDER]
    admin.act({"action": "set_policy", "policy": {"ja4": True}}, t, w, cfg(**C), "op", NOW + 1)
    assert w.sets["ja4"] != [scorer.JA4_PLACEHOLDER]


def test_alerts_fire_once_per_agent_and_respect_switches(sent):
    t, w = FakeTable(), AclWaf()
    evs = _agent_waf_view()
    evs[5].path = "/api/v1/internal/ops/export"
    recs = waf_records(evs, decoy_label_paths={evs[5].path})
    run(awslogs(recs), t, w, cfg(**C), now=NOW)
    kinds = [s for s, _ in sent]
    assert any("certain detection" in s for s in kinds) and any("blocked at the edge" in s for s in kinds)
    n = len(sent)
    run(awslogs(recs), t, w, cfg(**C), now=NOW + 60)        # same agent again within the hour: quiet
    assert len(sent) == n
    admin.act({"action": "set_policy", "policy": {"alerts": {"admin": False}}}, t, w, cfg(**C), "op", NOW + 70)
    m = len(sent)
    admin.act({"action": "release", "targets": ["1.2.3.4"]}, t, w, cfg(**C), "op", NOW + 80)
    assert len(sent) == m                                    # admin alerts switched off
    admin.act({"action": "test_alert"}, t, w, cfg(**C), "op", NOW + 90)
    assert "test alert" in sent[-1][0]                       # a test always goes out


def test_alert_failure_never_breaks_scoring(monkeypatch):
    def boom(subject, message):
        raise RuntimeError("sns down")
    monkeypatch.setattr(alerts, "_publish", boom)
    t, w = FakeTable(), AclWaf()
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(**C), now=NOW)
    assert out["flags"] == 1


def test_anomaly_alert(sent):
    from aa_ai.scorer import check_anomalies, minute_key
    t = FakeTable()
    for m in range(60, 24 * 60):
        t.put_item(Item={"pk": "STATM", "sk": minute_key(NOW - m * 60), "req": 10, "refused": 0, "exp": NOW + 99999})
    for m in range(0, 5):
        t.put_item(Item={"pk": "STATM", "sk": minute_key(NOW - m * 60), "req": 10, "refused": 50, "exp": NOW + 99999})
    flags = check_anomalies(t, scorer.load_policy(t, cfg()), NOW)
    assert flags and "refusals out of norm" in sent[-1][0]


def test_canary_key_use_fires_one_breach_alert(sent, monkeypatch):
    from datetime import datetime, timezone
    monkeypatch.setenv("CANARY_USER", "svc-inventory-sync")

    class Iam:
        used = None

        def list_access_keys(self, UserName):
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIACANARY"}]}

        def get_access_key_last_used(self, AccessKeyId):
            return {"AccessKeyLastUsed": {"LastUsedDate": self.used, "ServiceName": "sts", "Region": "us-east-1"}
                    if self.used else {}}

    t, iam = FakeTable(), Iam()
    assert scorer.check_canary(t, iam, scorer.load_policy(t, cfg()), NOW) is None      # never used: quiet
    iam.used = datetime.fromtimestamp(NOW, timezone.utc)
    assert scorer.check_canary(t, iam, scorer.load_policy(t, cfg()), NOW + 60)["service"] == "sts"
    assert "BREACH TRIPWIRE" in sent[-1][0]
    n = len(sent)
    assert scorer.check_canary(t, iam, scorer.load_policy(t, cfg()), NOW + 120) is None  # same use: no repeat
    assert len(sent) == n


def test_autotune_learns_weights_from_ground_truth(sent):
    from aa_ai import scorer
    from aa_ai.scorer import apply_autotune, suggested_weights
    t = FakeTable()
    # a precise detector: co-fired with 10 certain catches, never a false positive
    t.put_item(Item={"pk": "DET", "sk": "map_then_walk", "fired": 10, "tp": 10, "fp": 0, "exp": NOW + 99999})
    # a noisy one: mostly false positives
    t.put_item(Item={"pk": "DET", "sk": "metronome", "fired": 10, "tp": 2, "fp": 8, "exp": NOW + 99999})
    # too few samples: no suggestion
    t.put_item(Item={"pk": "DET", "sk": "long_session", "fired": 3, "tp": 1, "fp": 1, "exp": NOW + 99999})
    sug = suggested_weights(scorer.det_stats(t, NOW), {})
    assert sug["map_then_walk"] == 1.5 and sug["metronome"] == 0.7 and "long_session" not in sug
    assert "decoy_touch" not in sug                      # ground truth is never tuned
    # off by default: nothing applied
    assert apply_autotune(t, cfg(**C), NOW) == {}
    t.put_item(Item={"pk": "POLICY", "sk": "current", "autotune": True})
    applied = apply_autotune(t, cfg(**C), NOW)
    assert applied["map_then_walk"] == 1.5
    saved = scorer.load_policy(t, cfg(**C))["weights"]
    assert saved["map_then_walk"] == 1.5 and saved["metronome"] == 0.7


def test_autotune_counts_confirmed_cofires(sent):
    from aa_ai.scorer import det_stats, run
    t, w = FakeTable(), AclWaf()
    evs = _agent_waf_view()
    evs[5].path = "/api/v1/internal/ops/export"          # a decoy hit: certain
    run(awslogs(waf_records(evs, decoy_label_paths={evs[5].path})), t, w, cfg(**C), now=NOW)
    s = det_stats(t, NOW)
    assert s["decoy_touch"]["fired"] >= 1                 # the certainty itself fired
    assert any(v.get("tp", 0) >= 1 for k, v in s.items() if k != "decoy_touch")  # a behavioral detector co-fired
