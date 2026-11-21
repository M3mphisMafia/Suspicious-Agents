"""The detection eval: attackers meet their target verdict, no benign is hard-blocked."""
from evals.harness import run
from evals import scenarios
from aa_ai import detectors


def test_eval_has_no_false_negatives_or_hard_false_positives():
    res = run()
    assert res["misses"] == [], f"attacks missed: {res['misses']}"
    assert res["hard_fp"] == [], f"benign hard-blocked: {res['hard_fp']}"
    assert res["recall"] == 1.0


def test_idor_detector_catches_id_walking():
    detectors.DECOY_PREFIXES.add("/api/v1/internal/ops")
    sig = detectors.id_enumeration(scenarios.idor_walk())
    assert sig and sig.name == "id_enumeration" and sig.weight == 0.5


def test_benign_shopper_is_not_flagged():
    from aa_ai.scoring import combine, evaluate, verdict
    assert verdict(combine(evaluate(scenarios.real_shopper()))) == "allow"
