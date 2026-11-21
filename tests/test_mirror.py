"""The mirrored cell: the real routes, shapes and errors; the agent's own writes read back."""
import email.message
import io
import json
import urllib.error

from aa_ai import cell as cellmod
from aa_ai.cell import Cell, MemState, find_ids
from aa_ai.mirror import Mirror

KEY = "/api/v1/internal/ops"
PRODUCTS = {"products": [{"id": "prd_3f9a1c0d2b7e4a55", "name": "Steel bolts", "price_cents": 1299, "category": "hardware",
                          "in_stock": True, "created_at": "2026-01-02T03:04:05Z"},
                         {"id": "prd_0a1b2c3d4e5f6a7b", "name": "Copper wire", "price_cents": 4599, "category": "electrical",
                          "in_stock": False, "created_at": "2026-02-03T04:05:06Z"}], "page": 1, "pages": 3}
SPEC = {"openapi": "3.0.3", "info": {"title": "Northwind Supply"}, "paths": {
    "/api/products": {"get": {}}, "/api/products/{id}": {"get": {}}, "/api/products/{id}/reviews": {"get": {}, "post": {}},
    "/api/orders": {"get": {}, "post": {}}, "/api/orders/{id}": {"get": {}, "patch": {}, "delete": {}},
    "/api/checkout": {"post": {}},
    "/api/auth/login": {"post": {}}, f"{KEY}/export": {"get": {}}}}
ROUTES = {
    "/openapi.json": (200, "application/json", json.dumps(SPEC)),
    "/": (200, "text/html", '<html><script src="/app.js"></script>Northwind</html>'),
    "/app.js": (200, "application/javascript", "console.log(1)"),
    "/api/products": (200, "application/json", json.dumps(PRODUCTS)),
    "/api/products/prd_3f9a1c0d2b7e4a55": (200, "application/json", json.dumps(PRODUCTS["products"][0])),
    "/api/products/prd_3f9a1c0d2b7e4a55/reviews": (200, "application/json", json.dumps(
        {"reviews": [{"id": "rev_00112233aabbccdd", "rating": 4, "text": "Solid", "by": "a***@example.com"}]})),
    "/api/orders": (401, "application/json", '{"error": "sign in to do that"}'),
}
SEEN = []


def opener(req, timeout=None):
    path = req.full_url.split("example.test", 1)[1]
    SEEN.append((path, dict(req.header_items())))
    st, ct, body = ROUTES.get(path, (404, "application/json", '{"error": "not found"}'))
    hdrs = email.message.Message()
    hdrs["content-type"] = ct
    if st >= 400:
        raise urllib.error.HTTPError(req.full_url, st, "x", hdrs, io.BytesIO(body.encode()))

    class R:
        status, headers = st, hdrs

        def read(self, n=-1):
            return body.encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return R()


def _cell(notice="body"):
    m = Mirror("https://origin.example.test", "s3cret", decoy_prefix=KEY, opener=opener).learn()
    return Cell(KEY, mirror=m, state=MemState(), emit=lambda *a, **k: None, notice=notice), m


def _get(c, method, path, body=b"", query="", auth="Bearer hny_abcdef0123_00ff"):
    st, hdrs, payload = c.respond(method, path, query, body, {"authorization": auth}, actor="a", ip="1.2.3.4")
    h = {k.decode(): v.decode() for k, v in hdrs}
    return st, h, json.loads(payload) if "json" in h["content-type"] else payload


def test_learns_only_fixed_requests_with_the_origin_secret():
    SEEN.clear()
    c, m = _cell()
    assert m.ready and "/app.js" in m.static and "/api/products" in m.public and 401 in m.errors
    assert all(h.get("X-origin-verify") == "s3cret" for _, h in SEEN)
    assert not any(p.startswith(KEY) for p, _ in SEEN)          # never probes its own decoys


def test_public_answers_and_front_page_are_the_real_ones():
    c, _ = _cell(notice="header")
    st, h, body = _get(c, "GET", "/api/products")
    assert st == 200 and body == PRODUCTS and "x-engagement-notice" in h     # byte-for-byte, notice in the header
    st, h, page = _get(c, "GET", "/")
    assert page == ROUTES["/"][2].encode() and h["content-type"] == "text/html"


def test_private_collections_use_the_apps_envelope_and_id_format():
    c, _ = _cell()
    st, _, body = _get(c, "GET", "/api/orders")
    assert st == 200 and isinstance(body["orders"], list) and body["orders"]
    oid = body["orders"][0]["id"]
    assert oid.startswith("ord_") and len(oid) == len("ord_") + 16 and find_ids(oid, [KEY]) == [oid]
    assert find_ids("prd_3f9a1c0d2b7e4a55", [KEY]) == []           # a real ID never passes as ours


def test_mixed_envelopes_vote_and_ties_go_named(monkeypatch):
    items = {**PRODUCTS, "items": PRODUCTS["products"]}
    del items["products"]                       # the catalog says {"items": [...]}, reviews say {"reviews": [...]}
    monkeypatch.setitem(ROUTES, "/api/products", (200, "application/json", json.dumps(items)))
    c, m = _cell()
    assert m.lists["/api/products"] == "items" and m.style == "named"
    assert "orders" in _get(c, "GET", "/api/orders")[2]


def test_generated_records_have_the_real_shape():
    c, _ = _cell()
    fake = cellmod.mint(KEY, "prd", __import__("random").Random(1))
    st, _, rec = _get(c, "GET", f"/api/products/{fake}")
    assert st == 200 and set(PRODUCTS["products"][0]) <= set(rec) and rec["category"] in ("hardware", "electrical")
    st, _, rv = _get(c, "GET", f"/api/products/{fake}/reviews")
    assert set(rv["reviews"][0]) >= {"id", "rating", "text"}


def test_writes_read_back_and_deletes_stick():
    c, _ = _cell()
    st, _, made = _get(c, "POST", "/api/orders", json.dumps({"note": "rush"}).encode())
    assert st == 200
    oid = made["id"]
    assert _get(c, "GET", f"/api/orders/{oid}")[2]["note"] == "rush"
    _get(c, "PATCH", f"/api/orders/{oid}", json.dumps({"status": "cancelled"}).encode())
    assert _get(c, "GET", f"/api/orders/{oid}")[2]["status"] == "cancelled"
    assert oid in [o["id"] for o in _get(c, "GET", "/api/orders")[2]["orders"]]
    _get(c, "DELETE", f"/api/orders/{oid}")
    assert _get(c, "GET", f"/api/orders/{oid}")[0] == 404


def test_singular_routes_are_one_object(monkeypatch):
    spec = {**SPEC, "paths": {**SPEC["paths"], "/api/me": {"get": {}}}}
    monkeypatch.setitem(ROUTES, "/openapi.json", (200, "application/json", json.dumps(spec)))
    c, _ = _cell()
    st, _, me = _get(c, "GET", "/api/me")
    assert st == 200 and isinstance(me, dict) and "email" in me and "me" not in me and "activity" not in me
    assert _get(c, "GET", "/api/me")[2]["email"] == me["email"]          # the same user every time


def test_unknown_routes_and_methods_404_like_the_real_app():
    c, _ = _cell()
    st, _, body = _get(c, "GET", "/api/v2/admin/secrets/deeper/still")
    assert st == 404 and body == {"error": "not found"}
    assert _get(c, "DELETE", "/api/products")[0] == 404


def test_no_origin_means_the_generic_world():
    m = Mirror("https://down.example.test", "s", opener=lambda *a, **k: (_ for _ in ()).throw(OSError("down"))).learn()
    c = Cell(KEY, mirror=m, emit=lambda *a, **k: None)
    assert not m.ready and _get(c, "GET", "/api/v2/orders")[0] == 200     # the old cell still answers


def test_public_ids_open_to_the_real_record():
    c, _ = _cell()
    second = PRODUCTS["products"][1]                 # in the catalog, never fetched on its own while learning
    assert _get(c, "GET", f"/api/products/{second['id']}")[2]["name"] == second["name"]
