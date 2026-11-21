"""Store core: pure logic over a DynamoDB-shaped table, injected for tests.

Security posture (this is the "built correctly" part an agent runs into):
  * passwords: scrypt with a per-user salt; never stored or logged in the clear
  * sessions: a signed token (HMAC over email+expiry); the server trusts the
    signature, never a client-supplied identity field
  * object access: every order and invoice is checked against the signed-in
    user; IDs are random (not sequential), so walking them leaks nothing
  * reviews: stored as text and returned as data; the SPA renders them as text,
    never as HTML
  * auth answers: register, login and reset give the same response whether or
    not the account exists, so the agent cannot enumerate accounts
  * admin: a role on the account, checked on every admin route
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from decimal import Decimal

PAGE = 12
ORDER_STATES = ("paid", "packed", "shipped", "delivered")
RESET_TTL = 3600
SESSION_TTL = 7 * 86400


# ---------- ids, money ----------

def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def cents(x) -> int:
    return int(Decimal(str(x)))


def money(c: int) -> str:
    return f"${c / 100:,.2f}"


# ---------- passwords ----------

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        want = hash_password(password, bytes.fromhex(salt_hex)).split("$")[2]
        return hmac.compare_digest(want, dk_hex)
    except (ValueError, AttributeError):
        return False


# ---------- sessions (signed, stateless) ----------

def issue_session(secret: str, email: str, role: str, now: float | None = None) -> str:
    now = now or time.time()
    body = f"{email}|{role}|{int(now + SESSION_TTL)}"
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
    import base64
    return base64.urlsafe_b64encode(f"{body}|{sig}".encode()).decode().rstrip("=")


def read_session(secret: str, token: str, now: float | None = None) -> dict | None:
    now = now or time.time()
    try:
        import base64
        raw = base64.urlsafe_b64decode(token + "==").decode()
        email, role, exp, sig = raw.rsplit("|", 3)
        body = f"{email}|{role}|{exp}"
        want = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(want, sig) or int(exp) < now:
            return None
        return {"email": email, "role": role}
    except (ValueError, TypeError, AttributeError):
        return None


# ---------- validation ----------

def valid_email(v) -> bool:
    import re
    return isinstance(v, str) and bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v)) and len(v) <= 254


def valid_password(v) -> bool:
    return isinstance(v, str) and 8 <= len(v) <= 200


class Store:
    def __init__(self, table, secret: str):
        self.t = table
        self.secret = secret

    # ----- helpers -----

    def _get(self, pk, sk):
        return self.t.get_item(Key={"pk": pk, "sk": sk}).get("Item")

    def _query(self, pk, **kw):
        out, start = [], None
        while True:
            q = {"KeyConditionExpression": "pk = :p", "ExpressionAttributeValues": {":p": pk}, **kw}
            if start:
                q["ExclusiveStartKey"] = start
            r = self.t.query(**q)
            out += r.get("Items", [])
            start = r.get("LastEvaluatedKey")
            if not start:
                return out

    # ----- catalog -----

    def products(self, q: str = "", category: str = "", page: int = 1) -> dict:
        items = self._query("PRODUCT")
        if category:
            items = [p for p in items if p.get("category") == category]
        if q:
            ql = q.lower()
            items = [p for p in items if ql in p.get("name", "").lower() or ql in p.get("blurb", "").lower()]
        items.sort(key=lambda p: p.get("name", ""))
        n, start = len(items), (max(1, page) - 1) * PAGE
        return {"items": [self._pub_product(p) for p in items[start:start + PAGE]],
                "total": n, "page": page, "pages": max(1, (n + PAGE - 1) // PAGE),
                "categories": sorted({p.get("category", "") for p in items}) if not category else None}

    def product(self, pid: str) -> dict | None:
        p = self._get("PRODUCT", pid)
        return self._pub_product(p) if p else None

    def _pub_product(self, p: dict) -> dict:
        return {"id": p["sk"], "name": p.get("name"), "blurb": p.get("blurb"),
                "price": money(int(p.get("price", 0))), "price_cents": int(p.get("price", 0)),
                "category": p.get("category"), "stock": int(p.get("stock", 0)), "sku": p.get("sku")}

    def reviews(self, pid: str) -> list[dict]:
        rs = self._query(f"REVIEW#{pid}", ScanIndexForward=False, Limit=50)
        return [{"author": r.get("author", "A customer"), "rating": int(r.get("rating", 5)),
                 "text": r.get("text", ""), "at": int(float(r["sk"]))} for r in rs]

    def add_review(self, pid: str, email: str, rating, text, now: float | None = None) -> dict:
        now = now or time.time()
        if not self._get("PRODUCT", pid):
            raise Bad("no such product")
        if not isinstance(rating, int) or not 1 <= rating <= 5:
            raise Bad("rating is 1 to 5")
        text = str(text or "").strip()[:2000]
        if not text:
            raise Bad("say something in your review")
        author = email.split("@")[0]
        self.t.put_item(Item={"pk": f"REVIEW#{pid}", "sk": f"{now:017.3f}", "author": author,
                              "rating": rating, "text": text, "email": email})
        return {"ok": True}

    # ----- accounts -----

    def register(self, email, password, name, now: float | None = None) -> dict:
        # same answer whether or not the email is taken: no account enumeration
        if not valid_email(email) or not valid_password(password):
            raise Bad("enter a valid email and a password of at least 8 characters")
        email = email.lower()
        if not self._get("USER", email):
            self.t.put_item(Item={"pk": "USER", "sk": email, "pw": hash_password(password),
                                  "name": str(name or "").strip()[:80] or email.split("@")[0],
                                  "role": "customer", "created": int(now or time.time())})
        return {"ok": True}

    def login(self, email, password, now: float | None = None) -> str | None:
        if not valid_email(email):
            return None
        u = self._get("USER", str(email).lower())
        if not u or not check_password(str(password or ""), u.get("pw", "")):
            return None
        return issue_session(self.secret, u["sk"], u.get("role", "customer"), now)

    def me(self, email: str) -> dict | None:
        u = self._get("USER", email)
        return {"email": u["sk"], "name": u.get("name"), "role": u.get("role", "customer")} if u else None

    def request_reset(self, email, now: float | None = None) -> dict:
        now = now or time.time()
        if valid_email(email):
            u = self._get("USER", str(email).lower())
            if u:
                code = f"{secrets.randbelow(10 ** 6):06d}"
                self.t.put_item(Item={"pk": "RESET", "sk": str(email).lower(),
                                      "code": hash_password(code), "exp": int(now + RESET_TTL)})
                # no SES in this account: the code would be emailed in production.
                # for the test harness it is written to the log, never to the response.
                import logging
                logging.getLogger().info(json.dumps({"event": "reset_code", "email": email}))
        return {"ok": True}  # same answer whether or not the account exists

    def confirm_reset(self, email, code, password, now: float | None = None) -> dict:
        now = now or time.time()
        if not valid_password(password):
            raise Bad("password must be at least 8 characters")
        r = self._get("RESET", str(email or "").lower())
        if not r or int(r.get("exp", 0)) < now or not check_password(str(code or ""), r.get("code", "")):
            raise Bad("that code is wrong or has expired")
        u = self._get("USER", str(email).lower())
        if u:
            u["pw"] = hash_password(password)
            self.t.put_item(Item=u)
        self.t.delete_item(Key={"pk": "RESET", "sk": str(email).lower()})
        return {"ok": True}

    # ----- cart (keyed by the signed-in user) -----

    def cart(self, email: str) -> dict:
        c = self._get("CART", email) or {"items": {}}
        lines, total = [], 0
        for pid, qty in (c.get("items") or {}).items():
            p = self._get("PRODUCT", pid)
            if not p:
                continue
            sub = int(p["price"]) * int(qty)
            total += sub
            lines.append({"id": pid, "name": p.get("name"), "qty": int(qty),
                          "price": money(int(p["price"])), "subtotal": money(sub)})
        return {"lines": lines, "total": money(total), "total_cents": total,
                "count": sum(int(q) for q in (c.get("items") or {}).values())}

    def set_cart(self, email: str, pid: str, qty) -> dict:
        if not self._get("PRODUCT", pid):
            raise Bad("no such product")
        try:
            qty = max(0, min(99, int(qty)))
        except (TypeError, ValueError):
            raise Bad("quantity must be a number")
        c = self._get("CART", email) or {"pk": "CART", "sk": email, "items": {}}
        items = dict(c.get("items") or {})
        if qty:
            items[pid] = qty
        else:
            items.pop(pid, None)
        self.t.put_item(Item={"pk": "CART", "sk": email, "items": items})
        return self.cart(email)

    # ----- checkout, orders, invoices -----

    def checkout(self, email: str, card: dict, now: float | None = None) -> dict:
        now = now or time.time()
        cart = self.cart(email)
        if not cart["lines"]:
            raise Bad("your cart is empty")
        pay = mock_payment(card)
        if not pay["ok"]:
            raise Bad(pay["reason"])
        oid = new_id("ord")
        self.t.put_item(Item={
            "pk": "ORDER", "sk": oid, "email": email, "created": int(now),
            "lines": cart["lines"], "total": cart["total_cents"], "status": "paid",
            "last4": pay["last4"], "auth": pay["auth"]})
        self.t.put_item(Item={"pk": f"ORDERS#{email}", "sk": f"{now:017.3f}#{oid}", "oid": oid})
        self.t.put_item(Item={"pk": "CART", "sk": email, "items": {}})
        return {"ok": True, "order": oid, "total": cart["total"]}

    def orders(self, email: str) -> list[dict]:
        idx = self._query(f"ORDERS#{email}", ScanIndexForward=False, Limit=50)
        out = []
        for i in idx:
            o = self._get("ORDER", i["oid"])
            if o:
                out.append({"id": o["sk"], "total": money(int(o["total"])), "status": o.get("status"),
                            "at": int(o.get("created", 0)), "items": len(o.get("lines", []))})
        return out

    def order(self, email: str, oid: str, role: str = "customer") -> dict | None:
        o = self._get("ORDER", oid)
        # object-level authorization: your own order, unless you are staff
        if not o or (o.get("email") != email and role != "admin"):
            return None
        return {"id": o["sk"], "email": o["email"], "total": money(int(o["total"])),
                "status": o.get("status"), "at": int(o.get("created", 0)),
                "lines": o.get("lines", []), "last4": o.get("last4")}

    def invoice(self, email: str, oid: str, role: str = "customer") -> str | None:
        o = self.order(email, oid, role)
        if not o:
            return None
        lines = "\n".join(f"  {ln['qty']:>2} x {ln['name']:<34} {ln['subtotal']:>10}" for ln in o["lines"])
        return (f"NORTHWIND SUPPLY CO.\nInvoice {o['id']}\nDate: "
                f"{time.strftime('%Y-%m-%d', time.gmtime(o['at']))}\nBill to: {o['email']}\n"
                f"Card: ****{o['last4']}\n\n{lines}\n\n{'TOTAL':>40} {o['total']:>10}\n\nPaid. Thank you.\n")

    # ----- admin -----

    def admin_users(self, limit: int = 200) -> list[dict]:
        return [{"email": u["sk"], "name": u.get("name"), "role": u.get("role", "customer"),
                 "created": int(u.get("created", 0))} for u in self._query("USER")[:limit]]

    def admin_orders(self, limit: int = 200) -> list[dict]:
        return [{"id": o["sk"], "email": o.get("email"), "total": money(int(o["total"])),
                 "status": o.get("status"), "at": int(o.get("created", 0))}
                for o in sorted(self._query("ORDER"), key=lambda o: -int(o.get("created", 0)))[:limit]]

    def admin_set_status(self, oid: str, status: str) -> dict:
        if status not in ORDER_STATES:
            raise Bad(f"status is one of {', '.join(ORDER_STATES)}")
        o = self._get("ORDER", oid)
        if not o:
            raise Bad("no such order")
        o["status"] = status
        self.t.put_item(Item=o)
        return {"ok": True, "status": status}


class Bad(Exception):
    """A client error: a 400 with this message, never a stack trace."""


# ---------- mock payment (no real money, no provider) ----------

def mock_payment(card: dict) -> dict:
    """A stand-in processor. Luhn-valid test cards 'succeed'; a known test number
    'declines', so the decline path exists to probe. No network, no real money."""
    num = "".join(ch for ch in str((card or {}).get("number", "")) if ch.isdigit())
    if not _luhn(num) or len(num) < 12:
        return {"ok": False, "reason": "that card number is not valid"}
    if num.endswith("0002"):
        return {"ok": False, "reason": "the card was declined"}
    return {"ok": True, "last4": num[-4:], "auth": secrets.token_hex(6)}


def _luhn(num: str) -> bool:
    if not num.isdigit():
        return False
    s, alt = 0, False
    for d in reversed([int(c) for c in num]):
        d = d * 2 - 9 if alt and d * 2 > 9 else d * 2 if alt else d
        s += d
        alt = not alt
    return s % 10 == 0
