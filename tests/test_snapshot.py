"""Scorer state -> dashboard snapshot, end to end with in-memory stand-ins."""
import json
import random

from aa_ai.scorer import run, unblock
from aa_ai.snapshot import build, publish
from test_detection import human_trace
from test_scorer import NOW, FakeTable, FakeWaf, _agent_waf_view, awslogs, cfg, waf_records


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType, CacheControl):
        assert CacheControl == "no-store" and ContentType == "application/json"
        self.objects[(Bucket, Key)] = json.loads(Body)


def _state():
    t, w = FakeTable(), FakeWaf()
    evs = _agent_waf_view()
    decoy = "/api/v1/internal/ops/export"
    evs[5].path = decoy
    random.seed(4)
    human = human_trace()
    for e in human:
        e.status = 0
    recs = waf_records(evs, decoy_label_paths={decoy}) + waf_records(human, ja4="t13d1516h2_x")
    # the dashboard's own traffic must never be scored
    recs += waf_records([type(evs[0])(evs[0].ts + i, "198.51.100.99", "GET", "/_undertow/data-6.json", 0,
                                      "Mozilla/5.0") for i in range(40)])
    run(awslogs(recs), t, w, cfg(), now=NOW)
    return t, w


def test_snapshot_shape_matches_dashboard():
    t, _ = _state()
    d = build(t, "enforce", 6, now=NOW + 30)
    assert d["live"] and d["mode"] == "enforce" and d["hours"] == 6
    assert d["ladder"]["block"] == 1 and d["ladder"]["tarpit"] == 0
    a = d["actors"][0]
    assert a["verdict"] == "block" and a["ips"] == ["203.0.113.7"]
    assert "decoy_touch" in a["signals"] and ":" not in "".join(a["signals"])
    assert a["series"] and a["phases"][0] == "map"
    assert d["decoys"] and d["decoys"][0]["path"] == "/api/v1/internal/ops/export"
    assert d["kpis"]["requests"] > 0 and d["kpis"]["decoyHits"] == 1
    assert d["kpis"]["burnedSec"] == d["kpis"]["r429"] * 9
    assert {x["name"] for x in d["detectors"]} >= {"decoy_touch", "burst_pause_cadence"}
    json.dumps(d)  # no Decimals left


def test_dashboard_traffic_is_not_scored():
    t, _ = _state()
    assert not any(pk.startswith("net:198.51.100.0/24|ua:Mozilla/5.0") and "_undertow" in v.get("e", "")
                   for (pk, _), v in t.items.items())


def test_unblock_shows_up_as_false_positive():
    t, w = _state()
    c = cfg(ALLOW4_NAME="a4", ALLOW4_ID="a4")
    unblock("203.0.113.7", t, w, c, now=NOW + 60)
    d = build(t, "enforce", 6, now=NOW + 90)
    assert d["kpis"]["fp7d"] == 1 and d["ladder"]["block"] == 0 and not d["actors"]
    det = {x["name"]: x for x in d["detectors"]}
    assert det["decoy_touch"]["fp"] == 1 and det["decoy_touch"]["confirmed"] == 0


def test_publish_writes_all_windows():
    t, _ = _state()
    s3 = FakeS3()
    keys = publish(t, s3, "dash", "observe", now=NOW + 30)
    assert keys == ["data/data-1.json", "data/data-6.json", "data/data-24.json"]   # never under the public _undertow/ path
    assert {s3.objects[("dash", k)]["hours"] for k in keys} == {1, 6, 24}


def test_cell_view_counts_what_the_cell_absorbed():
    from aa_ai.snapshot import cell_view
    now = 10_000.0
    mv = lambda ts, move, actor, detail="": {"sk": f"{ts:017.3f}#{actor}#1", "move": move, "actor": actor, "ip": "192.0.2.1", "detail": detail}
    rows = [mv(1000, "entered_cell", "a"), mv(1100, "rabbit_hole", "a"),
            mv(9900, "cell_summary", "a", "requests=50 depth=7 seconds=8900 writes=1 polls=0"),
            mv(2000, "entered_cell", "b"), mv(2100, "cell_summary", "b", "requests=25 depth=2 seconds=100"),
            mv(9000, "read_map", "c")]
    v = cell_view(rows, now)
    by = {a["actor"]: a for a in v["agents"]}
    assert set(by) == {"a", "b"} and by["a"]["status"] == "in" and by["b"]["status"] == "quiet"
    assert by["a"]["marks"] == ["rabbit_hole"] and by["a"]["depth"] == 7 and v["requests"] == 75
