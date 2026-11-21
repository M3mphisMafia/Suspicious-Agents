"""Ingestion under a flood: bounded by sources, not requests. A source past per_ip_rpm is counted
but not stored or rescored, rescoring is capped during a surge, a batch stops before its deadline
and leaves the sync to the tick, flood mode runs from counters only, and the cell's KeyValueStore
updates stay within the API's shape."""
import logging
import random
import time

import pytest

from aa_ai import flood, scorer
from aa_ai.scorer import minute_key, run
from test_cell import FakeKvs
from test_flood import rec, traffic, rates
from test_scorer import NOW, FakeTable, FakeWaf, _agent_waf_view, awslogs, cfg, waf_records

FLOODER = "198.51.100.7"


def stored(t, net):
    return [k for (pk, k) in t.items if pk.startswith(f"net:{net}")]


def surging(t):
    t.put_item(Item={**flood.STATE, "active": True, "since": int(NOW) - 300, "calm": 0})


class Counting(FakeTable):
    """Records which actor partitions were read, and with what limit."""

    def __init__(self):
        super().__init__()
        self.reads = []

    def query(self, KeyConditionExpression, ExpressionAttributeValues, **kw):
        pk = ExpressionAttributeValues.get(":k", "")
        if pk.startswith(("net:", "spoof|")):
            self.reads.append((pk, kw.get("Limit")))
        return super().query(KeyConditionExpression, ExpressionAttributeValues, **kw)


# ---------- the per-source fast path ----------

def test_a_fast_agent_outside_a_surge_is_fully_scored():
    # machine-speed agents send far more than per_ip_rpm; without a surge none of it is skipped
    t = FakeTable()
    out = run(awslogs([rec(FLOODER, ts=NOW - 50 + i * 0.1) for i in range(400)]), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert out["skipped"] == 0 and len(stored(t, "198.51.100.0/24")) == 400


def test_a_flooding_source_is_counted_not_stored_and_others_are_unchanged():
    flood_recs = [rec(FLOODER, ts=NOW - 50 + i * 0.1) for i in range(400)]    # 400 in one minute
    alone, mixed = FakeTable(), FakeTable()
    surging(alone)
    surging(mixed)
    run(awslogs(waf_records(_agent_waf_view())), alone, FakeWaf(), cfg(MODE="observe"), now=NOW)
    out = run(awslogs(waf_records(_agent_waf_view()) + flood_recs), mixed, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert len(stored(mixed, "198.51.100.0/24")) == 120 and out["skipped"] == 280
    assert mixed.items[("STATM", minute_key(NOW))]["req"] == alone.items[("STATM", minute_key(NOW))]["req"] + 400
    assert mixed.items[(f"RATE#{minute_key(NOW)}", FLOODER)]["n"] == 400          # flood mode still sees all of it
    agent = "net:203.0.113.0/24"
    assert sorted(stored(mixed, agent)) == sorted(stored(alone, agent))          # the agent's evidence: untouched
    fa = [v for (pk, k), v in alone.items.items() if pk == "FLAG"]
    fm = [v for (pk, k), v in mixed.items.items() if pk == "FLAG" and k.startswith(agent)]
    assert [(f["verdict"], f["signals"]) for f in fa] == [(f["verdict"], f["signals"]) for f in fm]


def test_a_source_already_past_its_minute_is_not_stored_again():
    t = FakeTable()
    surging(t)
    t.put_item(Item={"pk": f"RATE#{minute_key(NOW)}", "sk": FLOODER, "n": 130, "exp": NOW + 3600})
    out = run(awslogs([rec(FLOODER, ts=NOW - 5 + i * 0.1) for i in range(10)]), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert stored(t, "198.51.100.0/24") == [] and out["skipped"] == 10
    assert t.items[(f"RATE#{minute_key(NOW)}", FLOODER)]["n"] == 140


def test_a_decoy_hit_from_a_flooding_source_is_still_kept():
    recs = [rec(FLOODER, ts=NOW - 50 + i * 0.1) for i in range(300)]
    recs[250]["httpRequest"]["uri"] = "/api/v1/internal/ops/export"
    t = FakeTable()
    surging(t)
    run(awslogs(recs), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert any(pk == "DECOY" for (pk, _) in t.items) and len(stored(t, "198.51.100.0/24")) == 121


# ---------- caps and the deadline ----------

def test_rescoring_is_capped_while_a_surge_is_active():
    def burst(t):
        recs = []
        for a in range(80):          # 80 distinct actors (one /24 each)
            recs += [rec(f"10.{a}.0.1", ts=NOW - 30 + i, path=f"/api/v2/items/{i}") for i in range(3)]
        return run(awslogs(recs), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    calm, hot = Counting(), Counting()
    assert burst(calm)["deferred"] == 0 and len({pk for pk, _ in calm.reads}) == 80
    surging(hot)
    out = burst(hot)
    assert out["surge"] and out["deferred"] == 30
    assert len({pk for pk, _ in hot.reads}) == scorer.SURGE_MAX_RESCORE
    assert max(lim for _, lim in hot.reads) == scorer.SURGE_EVENTS          # no actor read past the surge limit
    assert hot.items[("STATM", minute_key(NOW))]["req"] == 240                      # stats still whole


def test_a_batch_stops_before_its_deadline_and_skips_its_sync():
    t, w = FakeTable(), FakeWaf()
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW, deadline=time.time() - 1)
    assert out["stopped"] and out["deferred"] >= 1 and out["synced"] is False and w.calls == 0
    assert not [pk for (pk, _) in t.items if pk in ("FLAG", "WATCH")]                # nothing rescored
    assert t.items[("STATM", minute_key(NOW))]["req"] > 0 and stored(t, "203.0.113.0/24")   # counted and stored


def test_the_deadline_comes_from_the_lambda_context():
    class Ctx:
        def get_remaining_time_in_millis(self):
            return 30_000
    d = scorer._deadline(Ctx())
    assert d == pytest.approx(time.time() + 30 - scorer.DEADLINE_MARGIN, abs=1) and scorer._deadline(None) is None


def test_no_waf_sync_per_batch_during_a_surge():
    t, w = FakeTable(), FakeWaf()
    surging(t)
    out = run(awslogs(waf_records(_agent_waf_view())), t, w, cfg(), now=NOW)
    assert out["flags"] == 1 and out["synced"] is False and w.calls == 0           # flagged; the tick will sync
    t2, w2 = FakeTable(), FakeWaf()
    assert run(awslogs(waf_records(_agent_waf_view())), t2, w2, cfg(), now=NOW)["synced"] and w2.sets["v4"]


def test_the_log_function_never_runs_the_tick(monkeypatch):
    import boto3
    monkeypatch.setattr(boto3, "resource", lambda *a, **k: pytest.fail("the log function touched AWS for a tick"))
    assert scorer.handler({"action": "snapshot"}, None) == {"ignored": "snapshot"}


# ---------- flood mode runs from counters ----------

class Trap(FakeTable):
    """Fails on any read of per-event rows (actor partitions)."""

    def query(self, KeyConditionExpression, ExpressionAttributeValues, **kw):
        pk = ExpressionAttributeValues.get(":k", ExpressionAttributeValues.get(":f", ""))
        assert not pk.startswith(("net:", "spoof|")), f"flood mode read per-event rows: {pk}"
        return super().query(KeyConditionExpression, ExpressionAttributeValues, **kw)

    def get_item(self, Key):
        assert not Key["pk"].startswith(("net:", "spoof|")), "flood mode read a per-event row"
        return super().get_item(Key)


def test_flood_mode_decides_from_counters_only():
    t = Trap()
    traffic(t, rpm=6000)
    rates(t, {FLOODER: 900, "198.51.100.8": 900})
    out = flood.tick(t, FakeWaf(), cfg(), scorer.load_policy(t, cfg()), now=NOW, ask=lambda ev: (None, {}))
    assert out["active"] and sorted(out["new"]) == [FLOODER, "198.51.100.8"]


# ---------- the cell's KeyValueStore ----------

def test_cell_updates_never_send_an_empty_list_and_stay_within_50_keys():
    kvs = FakeKvs()
    kvs.keys = {f"ip:192.0.2.{i}": "1" for i in range(30)}              # 30 to remove
    sent = []
    real = kvs.update_keys

    def spy(KvsARN, IfMatch, **req):
        sent.append({k: len(v) for k, v in req.items()})
        return real(KvsARN=KvsARN, IfMatch=IfMatch, **req)
    kvs.update_keys = spy
    ips = [f"198.51.100.{i}" for i in range(120)]                      # 120 to add
    writes = scorer.sync_cell(kvs, "arn:kvs", ips)
    assert set(kvs.keys) == {f"ip:{ip}" for ip in ips} and writes == len(sent) == 3
    assert all(sum(r.values()) <= scorer.KVS_BATCH and all(r.values()) for r in sent)   # no empty list, ever
    assert sent == [{"Puts": 50}, {"Puts": 50}, {"Puts": 20, "Deletes": 30}]


def test_a_concurrent_cell_writer_is_retried_with_a_fresh_etag():
    kvs = FakeKvs()
    kvs.conflicts = 1
    assert scorer.sync_cell(kvs, "arn:kvs", ["192.0.2.1"]) == 1 and kvs.keys == {"ip:192.0.2.1": "1"}


@pytest.mark.cell_edge
def test_a_cell_sync_failure_logs_the_message(caplog):
    class Broken(FakeKvs):
        def update_keys(self, KvsARN, IfMatch, **req):
            raise FakeKvs.ValidationException("1 validation error detected: Value at 'puts' failed to satisfy constraint")
    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": "agent", "verdict": "block", "score": 1, "ips": ["192.0.2.9"], "exp": NOW + 999})
    with caplog.at_level(logging.WARNING):
        scorer.sync(t, FakeWaf(), cfg(CELL_KVS_ARN="arn:kvs"), NOW, kvs=Broken())
    msg = next(r.getMessage() for r in caplog.records if "cell_sync_failed" in r.getMessage())
    assert "ValidationException" in msg and "failed to satisfy constraint" in msg
