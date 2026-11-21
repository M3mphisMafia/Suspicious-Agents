"""The token sink: sized per agent, shaped like the real app, and it burns turns."""
import json

from test_mirror import KEY, _cell, _get

from aa_ai.cell import SINK_TARGET, Cell, find_ids
from aa_ai.snapshot import agent_cost, cell_view

NOW = 1_800_000_000.0


def _quiet():
    return Cell(KEY, emit=lambda *a, **k: None)


def test_fill_is_fixed_even_for_agents_that_repeat_themselves():
    # an adaptive size read repeat polling as truncation and starved the sink in a live run
    c = _quiet()
    sizes = [len(c.respond("GET", "/api/v2/orders", "", b"", {}, actor="a", ip="1.2.3.4", now=NOW + i)[2]) for i in range(5)]
    assert min(sizes) > SINK_TARGET * 0.9


def test_mirrored_lists_fill_with_real_shaped_records_only():
    c, _ = _cell(notice="header")
    st, h, body = _get(c, "GET", "/api/orders")
    size = len(json.dumps(body))
    assert set(body) == {"orders"} and SINK_TARGET * 0.6 < size < SINK_TARGET * 1.4
    keys = {frozenset(r) for r in body["orders"]}
    assert len(keys) == 1 and "activity" not in body


def test_writes_need_a_confirm_step_then_a_job_that_never_ends():
    c = _quiet()
    st, _, out = c.respond("POST", "/api/v2/orders", "", b"{}", {}, actor="a", ip="1.2.3.4", now=NOW)
    first = json.loads(out)
    assert st == 202 and first["status"] == "pending_confirmation"
    st, _, out = c.respond("POST", first["confirm"]["href"], "", b"{}", {}, actor="a", ip="1.2.3.4", now=NOW + 1)
    job = json.loads(out)["job"]
    st, _, out = c.respond("GET", job["status_url"], "", b"", {}, actor="a", ip="1.2.3.4", now=NOW + 99999)
    assert json.loads(out)["progress"] < 100


def test_objects_point_at_more_objects():
    c = _quiet()
    _, _, out = c.respond("GET", "/api/v2/orders/12345", "", b"", {}, actor="a", ip="1.2.3.4", now=NOW)
    rel = json.loads(out)["related"]
    assert len(rel) == 3 and all(find_ids(r["id"], [KEY]) == [r["id"]] for r in rel)


def test_cost_per_agent():
    assert agent_cost(400_000, 0) == (100_000, 0.3)
    assert agent_cost(0, 1000) == (0, 2.25)
    moves = [{"sk": f"{NOW:017.3f}#a#1", "move": "cell_summary", "actor": "a", "ip": "1.2.3.4",
              "detail": "requests=10 depth=3 seconds=60 writes=0 polls=0 bytes=280000"}]
    a = cell_view(moves, NOW)["agents"][0]
    assert a["tokens"] == 70000 and a["cost"] == 0.23
