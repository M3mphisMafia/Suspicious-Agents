"""One-click labels: ground truth that auto-tune learns from."""
from decimal import Decimal

import pytest
from test_scorer import NOW, FakeTable, FakeWaf, cfg

from aa_ai import admin, scorer

A = "net:203.0.113.0/24|ua:Go-http-client/1.1"


def _flag(t, verdict="tarpit"):
    t.put_item(Item={"pk": "FLAG", "sk": A, "verdict": verdict, "score": Decimal("0.6"), "ips": ["203.0.113.7"],
                     "signals": ["map_then_walk: 5 routes", "injection_payloads: 2 payloads"], "exp": int(NOW + 3600)})


def _det(t, name):
    return t.items.get(("DET", name), {})


def test_attacker_holds_at_block_and_teaches_true_positives_once():
    t, w = FakeTable(), FakeWaf()
    _flag(t)
    out = scorer.label(t, w, cfg(), A, "attacker", by="ops", now=NOW)
    f = t.items[("FLAG", A)]
    assert out["counted"] and f["verdict"] == "block" and f["manual"] and f["confirmed"] and f["labeled"] == "attacker"
    assert _det(t, "map_then_walk")["tp"] == 1 and _det(t, "injection_payloads")["tp"] == 1
    assert not scorer.label(t, w, cfg(), A, "attacker", by="ops", now=NOW + 5)["counted"]
    assert _det(t, "map_then_walk")["tp"] == 1
    assert any(v.get("outcome") == "true_positive" for (pk, _), v in t.items.items() if pk == "LABEL")


def test_person_clears_allows_and_teaches_false_positives():
    t, w = FakeTable(), FakeWaf()
    t.put_item(Item={"pk": "WATCH", "sk": A, "score": Decimal("0.4"), "ips": ["203.0.113.7"],
                     "signals": ["burst_pause_cadence", "metronome"], "exp": int(NOW + 600)})
    t.put_item(Item={"pk": "CHALLENGE", "sk": "203.0.113.7", "exp": int(NOW + 600)})
    scorer.label(t, w, cfg(), A, "person", by="ops", reason="our QA bot", now=NOW)
    assert ("WATCH", A) not in t.items and ("CHALLENGE", "203.0.113.7") not in t.items
    assert t.items[("ALLOW", "203.0.113.7/32")]["reason"].startswith("labeled a person")
    assert _det(t, "burst_pause_cadence")["fp"] == 1 and _det(t, "metronome")["fp"] == 1


def test_labels_feed_the_auto_tuner():
    t, w = FakeTable(), FakeWaf()
    for i in range(9):
        a = f"net:203.0.{i}.0/24|ua:x"
        t.put_item(Item={"pk": "FLAG", "sk": a, "verdict": "tarpit", "score": Decimal("0.6"), "ips": [f"203.0.{i}.7"],
                         "signals": ["metronome: steady"], "exp": int(NOW + 3600)})
        scorer.label(t, w, cfg(), a, "person", now=NOW)
    sugg = scorer.suggested_weights(scorer.det_stats(t), {})
    assert sugg["metronome"] == 0.5          # wrong every time: weight it down


def test_label_through_the_admin_api_and_bad_input():
    t, w = FakeTable(), FakeWaf()
    _flag(t)
    out = admin.act({"action": "label", "actor": A, "outcome": "attacker"}, t, w, cfg(), "ops (1.2.3.4)", NOW)
    assert out["outcome"] == "attacker"
    with pytest.raises(ValueError):
        admin.act({"action": "label", "actor": A, "outcome": "maybe"}, t, w, cfg(), "ops", NOW)
    with pytest.raises(ValueError):
        admin.act({"action": "label", "actor": "nobody", "outcome": "person"}, t, w, cfg(), "ops", NOW)
