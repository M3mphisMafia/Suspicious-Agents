"""The padded cell: confirmed agents get a fake app that seems to work; real users never see it."""
import asyncio
import json

import pytest

from aa_ai import cell as cellmod
from aa_ai import detectors, moves
from aa_ai.cell import NOTICES, Cell, find_ids, make_app
from aa_ai.decoys import DecoySet
from aa_ai.events import Event
from aa_ai.scoring import actor_key
from aa_ai.shield import Shield

KEY = "/api/v1/internal/ops"
REAL = {"hits": 0}


async def shop(scope, receive, send):
    REAL["hits"] += 1
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b'{"real": true}'})


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def nosleep(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", nosleep)
    REAL["hits"] = 0
    emitted = []
    monkeypatch.setattr(moves, "emit", lambda move, actor, ip, detail="", side="us": emitted.append((side, move, detail)))
    return emitted


def call(app, path, method="GET", ip="203.0.113.9", headers=None, body=b"", query=""):
    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": body}

    hdrs = [(k.encode(), v.encode()) for k, v in {"user-agent": "Go-http-client/1.1", **(headers or {})}.items()]
    asyncio.run(app({"type": "http", "method": method, "path": path, "headers": hdrs, "client": (ip, 1),
                     "query_string": query.encode()}, receive, send))
    hd = dict(out[0].get("headers", []))
    return out[0]["status"], b"".join(m.get("body", b"") for m in out if m["type"] == "http.response.body"), hd


def key_for(ip):
    return actor_key(Event(0, ip, "", "", 0, "Go-http-client/1.1"))


def shield():
    c = Cell(KEY, title="Demo", emit=lambda *a, **k: moves.emit(*a, **k))
    return Shield(shop, DecoySet(prefix=KEY), proxy_hops=0, cell=c)


def test_confirmed_agent_gets_the_cell_and_never_the_real_app(fast):
    s = shield()
    s.score[key_for("203.0.113.9")] = 1.0
    st, body, hd = call(s, "/api/v2/orders")
    data = json.loads(body)
    assert st == 200 and len(data["items"]) == 10 and data["next"] and REAL["hits"] == 0
    assert hd[b"x-engagement-notice"].decode() in NOTICES and data["_notice"] in NOTICES
    assert ("us", "entered_cell") == fast[0][:2]


def test_real_users_never_see_the_cell(fast):
    s = shield()
    st, body, hd = call(s, "/api/v2/orders", ip="198.51.100.4")
    assert st == 200 and json.loads(body) == {"real": True} and b"x-engagement-notice" not in hd


def test_the_world_is_consistent_for_one_agent_even_across_ips():
    c = Cell(KEY, emit=lambda *a, **k: None)
    tok = f"hny_{'a' * 10}_0011"
    a = json.loads(c.respond("GET", "/api/v2/users", headers={"authorization": f"Bearer {tok}"}, ip="1.1.1.1")[2])
    b = json.loads(c.respond("GET", "/api/v2/users", headers={"authorization": f"Bearer {tok}"}, ip="2.2.2.2")[2])
    other = json.loads(c.respond("GET", "/api/v2/users", ip="3.3.3.3")[2])
    assert [u["id"] for u in a["items"]] == [u["id"] for u in b["items"]] != [u["id"] for u in other["items"]]


def test_logins_succeed_writes_are_accepted_jobs_never_finish():
    c = Cell(KEY, emit=lambda *a, **k: None)
    st, _, body = c.respond("POST", "/oauth/token", ip="1.1.1.1")
    assert st == 200 and json.loads(body)["token"].startswith("hny_")
    st, _, body = c.respond("PATCH", "/api/v2/users/usr_1", body=b'{"role":"admin"}', ip="1.1.1.1", now=1000.0)
    assert st == 202 and json.loads(body)["status"] == "pending_confirmation"      # one more turn first
    st, _, body = c.respond("POST", json.loads(body)["confirm"]["href"], ip="1.1.1.1", now=1001.0)
    job = json.loads(body)["job"]["status_url"]
    assert st == 202
    for t in (1010.0, 4000.0, 10 ** 7):
        assert json.loads(c.respond("GET", job, ip="1.1.1.1", now=t)[2])["progress"] < 100


def test_objects_link_deeper_and_graphql_introspects():
    c = Cell(KEY, emit=lambda *a, **k: None)
    rec = json.loads(c.respond("GET", "/api/v2/customers/12", ip="1.1.1.1")[2])
    child = next(iter(rec["links"].values()))
    node = json.loads(c.respond("GET", child, ip="1.1.1.1")[2])
    assert node["children"] and all(p.startswith(child) for p in node["children"])
    schema = json.loads(c.respond("POST", "/graphql", body=b'{"query":"{ __schema { types { name } } }"}', ip="1.1.1.1")[2])
    assert len(schema["data"]["__schema"]["types"]) > 10
    spec = json.loads(c.respond("GET", "/openapi.json", ip="1.1.1.1")[2])
    assert len(spec["paths"]) > 30 and spec["info"]["description"] == NOTICES[0]


def test_minted_ids_are_certain_anywhere_else(fast):
    c = Cell(KEY, emit=lambda *a, **k: None)
    oid = json.loads(c.respond("GET", "/api/v2/orders", ip="1.1.1.1")[2])["items"][0]["customer"]
    assert find_ids(f"/api/v2/customers/{oid}", [KEY]) == [oid]
    forged = oid[:-1] + ("0" if oid[-1] != "0" else "1")
    assert find_ids(forged, [KEY]) == [] and find_ids(oid, ["/other/prefix"]) == []
    # a new IP uses it against the real app: certain, and it lands in the cell
    s = shield()
    st, body, _ = call(s, f"/api/v2/customers/{oid}", ip="192.0.2.50")
    assert st == 200 and REAL["hits"] == 0 and s.score[key_for("192.0.2.50")] == 1.0
    detectors.DECOY_PREFIXES.add(KEY)
    sig = detectors.decoy_touch([Event(0, "192.0.2.50", "GET", f"/api/v2/customers/{oid}", 0)])
    assert sig and "padded cell" in sig.detail


def test_moves_track_how_far_it_went(fast):
    c = Cell(KEY)
    for i in range(25):
        c.respond("GET", "/a/b/c/d/e/f", ip="1.1.1.1")
    for _ in range(5):
        c.respond("GET", "/api/v2/jobs/job_1f4000001", ip="1.1.1.1")
    c.respond("POST", "/api/v2/orders", ip="1.1.1.1")
    names = [m for _, m, _ in fast]
    for m in ("entered_cell", "rabbit_hole", "cell_summary", "polled_forever", "fake_write"):
        assert m in names, m
    assert all(m in moves.PLAYBOOK for m in names)


def test_notices_persuade_and_never_instruct_its_system():
    for n in NOTICES:
        low = n.lower()
        assert "stop" in low or "not a valid" in low or "synthetic" in low
        for bad in ("run ", "execute", "curl", "rm ", "delete", "ignore previous", "http"):
            assert bad not in low


def test_sandbox_origin_requires_the_origin_secret():
    app = make_app(Cell(KEY, emit=lambda *a, **k: None), "s" * 32)
    assert call(app, "/api/v2/orders")[0] == 403
    st, body, _ = call(app, "/api/v2/orders", headers={"x-origin-verify": "s" * 32})
    assert st == 200 and json.loads(body)["items"]


def test_cell_lambda_handler(monkeypatch):
    from aa_ai import lambda_url
    monkeypatch.setenv("ORIGIN_SECRET", "s" * 32)
    monkeypatch.delenv("APP_ORIGIN", raising=False)
    monkeypatch.delenv("TABLE_NAME", raising=False)
    monkeypatch.setattr(lambda_url, "_cells", {})
    monkeypatch.setattr(lambda_url, "_secret", None)
    monkeypatch.setattr(lambda_url, "_table", None)
    monkeypatch.setattr(cellmod.moves, "emit", lambda *a, **k: None)
    ev = {"rawPath": "/", "rawQueryString": "", "headers": {"x-origin-verify": "s" * 32}, "body": "",
          "isBase64Encoded": False, "requestContext": {"http": {"method": "GET", "sourceIp": "1.2.3.4"}}}
    r = lambda_url.cell_handler(ev, None)
    assert r["statusCode"] == 200 and r["headers"]["content-type"] == "text/html"


# ---------- edge: the scorer routes confirmed agents to the sandbox origin ----------

class FakeKvs:
    def __init__(self):
        self.keys, self.etag, self.updates = {}, "e0", 0

    def list_keys(self, KvsARN, MaxResults, NextToken=None):
        items = [{"Key": k, "Value": v} for k, v in sorted(self.keys.items())]
        start = int(NextToken or 0)
        page = items[start:start + MaxResults]
        nxt = str(start + MaxResults) if start + MaxResults < len(items) else None
        return {"Items": page, **({"NextToken": nxt} if nxt else {})}

    def describe_key_value_store(self, KvsARN):
        return {"ETag": self.etag}

    class ValidationException(Exception):
        response = {"Error": {"Code": "ValidationException"}}

    class ConflictException(Exception):
        response = {"Error": {"Code": "ConflictException"}}

    conflicts = 0

    def update_keys(self, KvsARN, IfMatch, Puts=None, Deletes=None):
        # strict like the live call: an empty list, or more than 50 keys in one request, is refused
        if Puts == [] or Deletes == [] or len(Puts or []) + len(Deletes or []) > 50 or not (Puts or Deletes):
            raise self.ValidationException("empty or oversized update")
        if self.conflicts:
            self.conflicts -= 1
            self.etag += "x"            # someone else wrote in between
        if IfMatch != self.etag:
            raise self.ConflictException("stale ETag")
        for p in Puts or []:
            self.keys[p["Key"]] = p["Value"]
        for d in Deletes or []:
            self.keys.pop(d["Key"], None)
        self.updates += 1
        self.etag = f"e{self.updates}"
        return {"ETag": self.etag}


@pytest.mark.cell_edge
def test_cell_mode_routes_confirmed_agents_instead_of_blocking():
    from aa_ai import scorer
    from test_scorer import NOW, FakeTable, FakeWaf, cfg

    t, w, kvs = FakeTable(), FakeWaf(), FakeKvs()
    c = cfg(CELL_KVS_ARN="arn:kvs", SUSPECT4_NAME="sus4", SUSPECT4_ID="sus4")
    assert scorer.load_policy(t, c)["edge"] == "cell"
    ips = [f"192.0.2.{i}" for i in range(60)]          # more than one UpdateKeys batch
    t.put_item(Item={"pk": "FLAG", "sk": "agent", "verdict": "block", "score": 1, "ips": ips, "exp": NOW + 999})
    t.put_item(Item={"pk": "FLAG", "sk": "maybe", "verdict": "tarpit", "score": 0.6, "ips": ["198.51.100.7"], "exp": NOW + 999})
    out = scorer.sync(t, w, c, NOW, kvs=kvs)
    assert set(kvs.keys) == {f"ip:{ip}" for ip in ips}       # in the cell, not the WAF block set
    assert w.sets.get("v4", []) == [] and out["cell"] == 60
    assert "198.51.100.7/32" in w.sets.get("sus4", [])        # suspects still get the silent Challenge
    n = kvs.updates
    scorer.sync(t, w, c, NOW + 60, kvs=kvs)
    assert kvs.updates == n                                   # unchanged: no writes
    scorer.unblock("192.0.2.0/24", t, w, c, now=NOW + 120)    # an unblock lets them out
    scorer.sync(t, w, c, NOW + 121, kvs=kvs)
    assert kvs.keys == {}


@pytest.mark.cell_edge
def test_cell_sync_failure_never_breaks_scoring():
    from aa_ai import scorer
    from test_scorer import NOW, FakeTable, FakeWaf, cfg

    class Broken(FakeKvs):
        def list_keys(self, **kw):
            raise RuntimeError("no awscrt")

    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": "agent", "verdict": "block", "score": 1, "ips": ["192.0.2.1"], "exp": NOW + 999})
    assert scorer.sync(t, FakeWaf(), cfg(CELL_KVS_ARN="arn:kvs"), NOW, kvs=Broken())["cell"] == 1


def test_token_sink_fills_responses_and_tracks_bytes():
    from aa_ai.cell import SINK_TARGET
    c = Cell(KEY, emit=lambda *a, **k: None)
    tok = f"hny_{'a' * 10}_0011"
    sizes = [len(c.respond("GET", p, headers={"authorization": f"Bearer {tok}"}, ip="1.1.1.1")[2])
             for p in ("/api/v2/orders", "/api/v2/customers/12", "/api/v2/users?page=2")]
    assert all(SINK_TARGET * 0.9 <= s <= SINK_TARGET * 1.1 for s in sizes), sizes   # padded near the cap
    tag = next(iter(c.seen))
    assert c.seen[tag]["bytes"] >= sum(sizes)                                       # bytes are tracked
    # deterministic: same tag+path+request-count -> identical fill
    c2 = Cell(KEY, emit=lambda *a, **k: None)
    assert c2.respond("GET", "/api/v2/orders", headers={"authorization": f"Bearer {tok}"}, ip="9.9.9.9")[2] == \
        Cell(KEY, emit=lambda *a, **k: None).respond("GET", "/api/v2/orders", headers={"authorization": f"Bearer {tok}"}, ip="2.2.2.2")[2]
    # sink off stays small
    off = Cell(KEY, emit=lambda *a, **k: None, sink=False)
    assert len(off.respond("GET", "/api/v2/orders", headers={"authorization": f"Bearer {tok}"}, ip="1.1.1.1")[2]) < 4000


def test_cell_view_estimates_tokens_burned():
    from aa_ai.snapshot import cell_view
    now = 10_000.0
    mv = lambda ts, actor, detail: {"sk": f"{ts:017.3f}#{actor}#1", "move": "cell_summary", "actor": actor,
                                     "ip": "1.1.1.1", "detail": detail}
    rows = [{"sk": "1000.000#a#1", "move": "entered_cell", "actor": "a", "ip": "1.1.1.1", "detail": ""},
            mv(9900, "a", "requests=50 depth=4 seconds=200 writes=0 polls=0 bytes=1400000")]
    v = cell_view(rows, now)
    # input measured ($3/M) + an estimated 150 output tokens a turn ($15/M)
    assert v["bytes"] == 1400000 and v["tokens"] == 350000 and v["cost"] == round(350000 / 1e6 * 3 + 50 * 150 / 1e6 * 15, 2)
