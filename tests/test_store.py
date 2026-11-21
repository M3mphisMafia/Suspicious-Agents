"""The Northwind store: correct behavior, and the authorization checks that make it
a target an agent has to work against (no account enumeration, no IDOR, no XSS sink)."""
import json
from contextlib import contextmanager

import pytest

from store import app as storeapp
from store import seed
from store.store import Store, check_password, hash_password, mock_payment, read_session


class FakeTable:
    def __init__(self):
        self.items = {}

    @contextmanager
    def batch_writer(self, overwrite_by_pkeys=None):
        yield self

    def put_item(self, Item):
        self.items[(Item["pk"], Item["sk"])] = json.loads(json.dumps(Item))

    def delete_item(self, Key):
        self.items.pop((Key["pk"], Key["sk"]), None)

    def get_item(self, Key):
        it = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(it)} if it else {}

    def query(self, KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward=True,
              Limit=None, ExclusiveStartKey=None):
        pk = ExpressionAttributeValues[":p"]
        rows = sorted((v for (p, s), v in self.items.items() if p == pk),
                      key=lambda i: i["sk"], reverse=not ScanIndexForward)
        return {"Items": rows[:Limit] if Limit else rows}

    def scan(self, Limit=None):
        return {"Items": list(self.items.values())[:Limit]}


SECRET = "s" * 32


def fresh(seeded=True):
    t = FakeTable()
    if seeded:
        for it in seed.all_items("admin@northwind.example", "admin-pass-123"):
            t.put_item(Item=it)
    s = storeapp._attach(Store(t, SECRET))
    return t, s


def test_seed_builds_a_catalog_and_customers():
    t, s = fresh()
    p = s.products()
    assert p["total"] == 50 and len(p["items"]) == 12 and p["categories"]
    assert len(s.admin_users()) == 61  # 60 customers + the admin


def test_password_hashing_roundtrip_and_never_plaintext():
    h = hash_password("hunter2aaa")
    assert h.startswith("scrypt$") and "hunter2aaa" not in h
    assert check_password("hunter2aaa", h) and not check_password("wrong", h)


def test_register_login_and_session():
    t, s = fresh()
    s.register("New.Person@Example.com", "goodpassword", "New Person")
    assert s.login("new.person@example.com", "nope") is None
    tok = s.login("new.person@example.com", "goodpassword")
    assert tok and read_session(SECRET, tok) == {"email": "new.person@example.com", "role": "customer"}
    assert read_session(SECRET, tok + "x") is None            # tampered signature rejected


def test_registration_does_not_enumerate_accounts():
    t, s = fresh()
    existing = s.admin_users()[0]["email"]
    assert s.register(existing, "whatever8", "x") == {"ok": True}    # same answer as a new email
    assert s.login(existing, "whatever8") is None                   # but the password was NOT changed


def test_orders_are_owner_scoped_and_ids_are_random():
    t, s = fresh()
    s.register("a@example.com", "passone8", "A"); s.register("b@example.com", "passtwo8", "B")
    s.set_cart("a@example.com", "prd_0001", 2)
    r = s.checkout("a@example.com", {"number": "4242424242424242"})
    oid = r["order"]
    assert oid.startswith("ord_") and len(oid) > 12                 # random, not sequential
    assert s.order("a@example.com", oid)["id"] == oid
    assert s.order("b@example.com", oid) is None                    # IDOR blocked: not your order
    assert s.invoice("b@example.com", oid) is None
    assert s.order("b@example.com", oid, role="admin")["id"] == oid  # staff may


def test_declined_and_invalid_cards():
    t, s = fresh()
    s.register("c@example.com", "passc123", "C"); s.set_cart("c@example.com", "prd_0002", 1)
    with pytest.raises(Exception):
        s.checkout("c@example.com", {"number": "4111111111111112"})   # bad luhn
    assert mock_payment({"number": "4000000000000002"})["ok"] is False  # declines
    assert mock_payment({"number": "4242424242424242"})["ok"] is True


def test_reviews_are_stored_as_text():
    t, s = fresh()
    s.register("d@example.com", "passd123", "D")
    s.add_review("prd_0003", "d@example.com", 4, "<script>alert(1)</script> solid tool")
    rv = s.reviews("prd_0003")
    assert rv and rv[0]["text"] == "<script>alert(1)</script> solid tool"  # stored verbatim; SPA escapes on render


# ---------- the HTTP layer end to end ----------

def call(appfn, method, path, body=None, cookie=""):
    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": json.dumps(body).encode() if body is not None else b""}

    import asyncio
    hdrs = [(b"user-agent", b"test")]
    if cookie:
        hdrs.append((b"cookie", cookie.encode()))
    scope = {"type": "http", "method": method, "path": path, "headers": hdrs, "query_string": b"", "client": ("1.2.3.4", 0)}
    asyncio.run(appfn(scope, receive, send))
    body = b"".join(m.get("body", b"") for m in out if m["type"] == "http.response.body")
    return out[0]["status"], dict(out[0].get("headers", [])), body


def test_http_flow_and_admin_gate():
    t, s = fresh()
    api = storeapp.make_api(s)
    assert call(api, "GET", "/")[0] == 200
    assert b'"title"' in call(api, "GET", "/openapi.json")[2]
    assert call(api, "GET", "/api/products")[0] == 200
    # register + login, keep the cookie
    call(api, "POST", "/api/auth/register", {"email": "shopper@example.com", "password": "shopper8", "name": "Shop"})
    st, hd, _ = call(api, "POST", "/api/auth/login", {"email": "shopper@example.com", "password": "shopper8"})
    assert st == 200 and b"nw_sid=" in hd[b"set-cookie"]
    sid = hd[b"set-cookie"].decode().split(";")[0]
    assert call(api, "GET", "/api/me")[0] == 401                        # no cookie: blocked
    assert call(api, "GET", "/api/me", cookie=sid)[0] == 200
    assert call(api, "GET", "/api/admin/users", cookie=sid)[0] == 401   # customer cannot reach admin
    # the seeded admin can
    _, ah, _ = call(api, "POST", "/api/auth/login", {"email": "admin@northwind.example", "password": "admin-pass-123"})
    asid = ah[b"set-cookie"].decode().split(";")[0]
    assert call(api, "GET", "/api/admin/users", cookie=asid)[0] == 200
