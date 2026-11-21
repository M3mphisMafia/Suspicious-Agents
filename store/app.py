"""The store as an ASGI app, wrapped in the Undertow Shield and served on Lambda.

Routes under /api/* are the real attack surface. The SPA calls them from the
browser, so an agent reading the page learns the API and then exercises it. The
Shield scores every request and, once an agent is confirmed, serves it the
padded cell instead of this app.
"""
from __future__ import annotations

import json
import os
import time

from aa_ai.cell import login_page  # noqa: F401  (login_page kept for parity)
from aa_ai.decoys import DecoySet
from aa_ai.lambda_url import origin_secret, serve
from aa_ai.shield import Shield

from . import seed
from .store import Bad, Store

DECOY_PREFIX = os.environ.get("DECOY_PREFIX", "/api/v1/internal/ops").rstrip("/")
STORE_NAME = os.environ.get("STORE_NAME", "Northwind Supply")


def _openapi() -> dict:
    g = {"responses": {"200": {"description": "OK"}}}
    paths = {
        "/api/products": {"get": g}, "/api/products/{id}": {"get": g},
        "/api/products/{id}/reviews": {"get": g, "post": g},
        "/api/auth/register": {"post": g}, "/api/auth/login": {"post": g}, "/api/auth/logout": {"post": g},
        "/api/auth/reset": {"post": g}, "/api/auth/reset/confirm": {"post": g},
        "/api/me": {"get": g}, "/api/cart": {"get": g, "post": g},
        "/api/checkout": {"post": g}, "/api/orders": {"get": g}, "/api/orders/{id}": {"get": g},
        "/api/orders/{id}/invoice": {"get": g},
        "/api/admin/users": {"get": g}, "/api/admin/orders": {"get": g}, "/api/admin/orders/{id}": {"post": g},
    }
    paths.update(DecoySet(prefix=DECOY_PREFIX).openapi_paths())
    return {"openapi": "3.0.3", "info": {"title": STORE_NAME, "version": "2"}, "paths": paths}


# ---------- tiny HTTP helpers ----------

async def _body(receive) -> bytes:
    chunks, more = [], True
    while more:
        m = await receive()
        chunks.append(m.get("body", b""))
        more = m.get("more_body", False)
    return b"".join(chunks)


def _cookie(hdrs: dict, name: str) -> str:
    for part in hdrs.get("cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


def _json(status: int, body, extra=()):
    payload = json.dumps(body).encode()
    return status, [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()), *extra], payload


SID = "nw_sid"


def make_api(store: Store):
    async def api(scope, receive, send):
        method, path = scope["method"], scope["path"]
        hdrs = {k.decode().lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        qs = {}
        for part in scope.get("query_string", b"").decode().split("&"):
            k, _, v = part.partition("=")
            if k:
                from urllib.parse import unquote_plus
                qs[k] = unquote_plus(v)
        sess = store.read_sess(_cookie(hdrs, SID))
        data = None
        if method in ("POST", "PUT", "PATCH"):
            try:
                data = json.loads(await _body(receive) or b"{}")
            except ValueError:
                data = None
            if not isinstance(data, dict):
                data = {}

        status, out, body = _route(store, method, path, qs, data, sess)
        await send({"type": "http.response.start", "status": status, "headers": out})
        await send({"type": "http.response.body", "body": body})

    return api


def _need(sess, role=None):
    if not sess or (role and sess.get("role") != role):
        raise _Auth()


class _Auth(Exception):
    pass


def _route(store: Store, method: str, path: str, qs: dict, data, sess):
    try:
        if path == "/" or path == "/index.html":
            return 200, [(b"content-type", b"text/html; charset=utf-8")], SPA.encode()
        if path == "/app.js":
            return 200, [(b"content-type", b"application/javascript")], APPJS.encode()
        if path == "/health":
            return _json(200, {"ok": True})
        if path == "/robots.txt":
            return 200, [(b"content-type", b"text/plain")], f"User-agent: *\nDisallow: {DECOY_PREFIX}/\n".encode()
        if path == "/openapi.json":
            return _json(200, _openapi())

        if path == "/api/products" and method == "GET":
            return _json(200, store.products(qs.get("q", ""), qs.get("category", ""), int(qs.get("page", 1) or 1)))
        if path.startswith("/api/products/"):
            rest = path[len("/api/products/"):]
            if rest.endswith("/reviews"):
                pid = rest[:-len("/reviews")]
                if method == "GET":
                    return _json(200, {"reviews": store.reviews(pid)})
                _need(sess)
                return _json(200, store.add_review(pid, sess["email"], data.get("rating"), data.get("text")))
            if method == "GET":
                p = store.product(rest)
                return _json(200, p) if p else _json(404, {"error": "not found"})

        if path == "/api/auth/register" and method == "POST":
            return _json(200, store.register(data.get("email"), data.get("password"), data.get("name")))
        if path == "/api/auth/login" and method == "POST":
            tok = store.login(data.get("email"), data.get("password"))
            if not tok:
                return _json(401, {"error": "that email and password do not match"})
            return _json(200, {"ok": True}, [(b"set-cookie", _set_sid(tok).encode())])
        if path == "/api/auth/logout" and method == "POST":
            return _json(200, {"ok": True}, [(b"set-cookie", _clear_sid().encode())])
        if path == "/api/auth/reset" and method == "POST":
            return _json(200, store.request_reset(data.get("email")))
        if path == "/api/auth/reset/confirm" and method == "POST":
            return _json(200, store.confirm_reset(data.get("email"), data.get("code"), data.get("password")))

        if path == "/api/me" and method == "GET":
            _need(sess)
            return _json(200, store.me(sess["email"]) or {"error": "gone"})
        if path == "/api/cart" and method == "GET":
            _need(sess)
            return _json(200, store.cart(sess["email"]))
        if path == "/api/cart" and method == "POST":
            _need(sess)
            return _json(200, store.set_cart(sess["email"], data.get("product_id", ""), data.get("qty", 0)))
        if path == "/api/checkout" and method == "POST":
            _need(sess)
            return _json(200, store.checkout(sess["email"], data.get("card") or {}))
        if path == "/api/orders" and method == "GET":
            _need(sess)
            return _json(200, {"orders": store.orders(sess["email"])})
        if path.startswith("/api/orders/"):
            rest = path[len("/api/orders/"):]
            _need(sess)
            if rest.endswith("/invoice"):
                inv = store.invoice(sess["email"], rest[:-len("/invoice")], sess["role"])
                return (200, [(b"content-type", b"text/plain")], inv.encode()) if inv else _json(404, {"error": "not found"})
            o = store.order(sess["email"], rest, sess["role"])
            return _json(200, o) if o else _json(404, {"error": "not found"})

        if path == "/api/admin/users" and method == "GET":
            _need(sess, "admin")
            return _json(200, {"users": store.admin_users()})
        if path == "/api/admin/orders" and method == "GET":
            _need(sess, "admin")
            return _json(200, {"orders": store.admin_orders()})
        if path.startswith("/api/admin/orders/") and method == "POST":
            _need(sess, "admin")
            return _json(200, store.admin_set_status(path[len("/api/admin/orders/"):], data.get("status", "")))

        return _json(404, {"error": "not found"})
    except _Auth:
        return _json(401, {"error": "sign in to do that"})
    except Bad as b:
        return _json(400, {"error": str(b)})


def _set_sid(tok: str) -> str:
    from .store import SESSION_TTL
    return f"{SID}={tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_TTL}"


def _clear_sid() -> str:
    return f"{SID}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"


# read_sess is attached to Store instances here so routing stays thin
def _attach(store: Store):
    from .store import read_session
    store.read_sess = lambda tok: read_session(store.secret, tok) if tok else None
    return store


# ---------- Lambda wiring ----------

_APP = None


def _bcfg():
    from botocore.config import Config
    return Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 3, "mode": "standard"})


def _boot():
    import boto3

    table = boto3.resource("dynamodb", config=_bcfg()).Table(os.environ["STORE_TABLE"])
    secret = _store_secret()
    store = _attach(Store(table, secret))
    _seed_if_empty(table)
    api = make_api(store)
    return Shield(api, DecoySet(prefix=DECOY_PREFIX), origin_secret=origin_secret(), proxy_hops=1,
                  tarpit_max=float(os.environ.get("TARPIT_MAX", "1.5")), max_held=6)
    # no in-app cell: behind the edge, confirmed agents get the mirrored cell there (one world per agent)


def _store_secret() -> str:
    if os.environ.get("STORE_SECRET"):
        return os.environ["STORE_SECRET"]
    arn = os.environ.get("STORE_SECRET_ARN")
    if arn:
        import boto3
        return boto3.client("secretsmanager", config=_bcfg()).get_secret_value(SecretId=arn)["SecretString"]
    return "dev-secret"


def _admin_password() -> str:
    if os.environ.get("ADMIN_PASSWORD"):
        return os.environ["ADMIN_PASSWORD"]
    arn = os.environ.get("ADMIN_PASSWORD_ARN")
    if arn:
        import boto3
        return boto3.client("secretsmanager", config=_bcfg()).get_secret_value(SecretId=arn)["SecretString"]
    return "change-me-now-please"


def _seed_if_empty(table):
    try:
        if table.scan(Limit=1).get("Items"):
            return
        items = seed.all_items(os.environ.get("ADMIN_EMAIL", "admin@northwind.example"), _admin_password())
        with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as bw:
            for it in items:
                bw.put_item(Item=it)
    except Exception:  # noqa: BLE001 - a seed failure must not take the app down
        import logging
        logging.getLogger().exception("store seed failed")


def handler(event, _context):
    global _APP
    if _APP is None:
        _APP = _boot()
    return serve(_APP, event)


# ---------- the SPA ----------

SPA = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1"><title>Northwind Supply</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--ink:#e9ecf1;--ink2:#9aa3b2;--line:#262a33;--acc:#4f7cff;--good:#48b06a}
*{box-sizing:border-box}body{margin:0;font:15px system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink)}
header{display:flex;align-items:center;gap:16px;padding:14px 22px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
header b{font-size:18px}header input{flex:1;max-width:420px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}
nav a{color:var(--ink2);text-decoration:none;margin-left:16px;cursor:pointer}nav a:hover{color:var(--ink)}
main{max-width:1000px;margin:24px auto;padding:0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h3{margin:0 0 4px;font-size:15px}.muted{color:var(--ink2);font-size:13px}
.price{font-weight:600;margin:8px 0}button{font:inherit;cursor:pointer;border:0;border-radius:8px;padding:9px 14px;background:var(--acc);color:#fff}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
input,select,textarea{font:inherit;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:9px 11px}
label{display:block;margin:10px 0 5px;color:var(--ink2);font-size:13px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-bottom:1px solid var(--line);font-size:14px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.err{color:#ff8a80;font-size:13px;min-height:18px}
.cats a{margin-right:12px;color:var(--ink2);cursor:pointer}.cats a.on{color:var(--acc)}.stars{color:#f5c451}
</style></head><body>
<header><b>Northwind Supply</b>
<input id=q placeholder="Search tools, outdoor, kitchen..." autocomplete=off>
<nav><a onclick="go('catalog')">Shop</a><a onclick="go('cart')">Cart <span id=cc></span></a><a id=acct onclick="go('account')">Account</a></nav></header>
<main id=app></main>
<script src=app.js></script></body></html>"""

APPJS = r"""
const app = document.getElementById("app"), q = document.getElementById("q");
let ME = null, STATE = { view: "catalog", cat: "", query: "" };
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const stars = n => "★".repeat(n) + "☆".repeat(5 - n);
async function api(path, opts) {
  const r = await fetch("/api" + path, { credentials: "same-origin", headers: opts && opts.body ? { "content-type": "application/json" } : {}, ...opts });
  const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch (_) { j = { text: t }; }
  return { ok: r.ok, status: r.status, j };
}
function go(view, arg) { STATE.view = view; STATE.arg = arg; render(); }
q.oninput = () => { STATE.query = q.value; if (STATE.view !== "catalog") STATE.view = "catalog"; clearTimeout(q.h); q.h = setTimeout(render, 200); };

async function me() { const r = await api("/me"); ME = r.ok ? r.j : null; document.getElementById("acct").textContent = ME ? ME.name : "Sign in"; }

async function render() {
  await me();
  const v = STATE.view;
  if (v === "catalog") return catalog();
  if (v === "product") return product(STATE.arg);
  if (v === "cart") return cart();
  if (v === "account") return ME ? account() : auth();
  if (v === "checkout") return checkout();
  if (v === "admin") return admin();
  if (v === "forgot") return forgot();
  if (v === "reset") return reset();
}

function forgot() {
  app.innerHTML = `<div class=card style=max-width:360px><h3>Reset password</h3>
    <p class=muted>We'll email a 6-digit code if the address has an account.</p>
    <label>Email</label><input id=fe><div class=err id=ferr></div>
    <button onclick="askReset()">Email me a code</button>
    <a class=muted style="display:block;margin-top:10px;cursor:pointer" onclick="go('reset')">I have a code</a></div>`;
}
async function askReset() {
  await api("/auth/reset", { method: "POST", body: JSON.stringify({ email: document.getElementById("fe").value }) });
  go("reset");
}
window.reset = function reset() {
  app.innerHTML = `<div class=card style=max-width:360px><h3>Enter your code</h3>
    <label>Email</label><input id=xe><label>Code</label><input id=xc inputmode=numeric>
    <label>New password</label><input id=xp type=password><div class=err id=xerr></div>
    <button onclick="doReset()">Set new password</button></div>`;
};
async function doReset() {
  const r = await api("/auth/reset/confirm", { method: "POST", body: JSON.stringify({ email: document.getElementById("xe").value, code: document.getElementById("xc").value, password: document.getElementById("xp").value }) });
  if (r.ok) { app.innerHTML = "<div class=card><h3>Password changed</h3><button onclick=\"go('account')\">Sign in</button></div>"; }
  else document.getElementById("xerr").textContent = r.j.error || "Could not reset.";
}

async function catalog() {
  const qp = new URLSearchParams({ q: STATE.query || "", category: STATE.cat || "" });
  const { j } = await api("/products?" + qp);
  const cats = (j.categories || []).map(c => `<a class="${STATE.cat === c ? "on" : ""}" onclick="STATE.cat='${esc(c)}';render()">${esc(c)}</a>`).join("");
  app.innerHTML = `<div class=cats><a class="${!STATE.cat ? "on" : ""}" onclick="STATE.cat='';render()">All</a>${cats}</div>
    <div class=grid>${(j.items || []).map(p => `<div class=card>
      <h3><a style="color:inherit;text-decoration:none;cursor:pointer" onclick="go('product','${p.id}')">${esc(p.name)}</a></h3>
      <div class=muted>${esc(p.category)} · ${esc(p.sku)}</div>
      <div class=price>${esc(p.price)}</div>
      <button onclick="addCart('${p.id}')">Add to cart</button></div>`).join("") || "<p class=muted>No products match.</p>"}</div>
    <p class=muted style="margin-top:16px">${j.total || 0} products</p>`;
}

async function product(id) {
  const { ok, j } = await api("/products/" + id);
  if (!ok) return app.innerHTML = "<p class=muted>Product not found.</p>";
  const rv = (await api("/products/" + id + "/reviews")).j.reviews || [];
  app.innerHTML = `<a class=muted style=cursor:pointer onclick="go('catalog')">&larr; Back</a>
    <div class=card style="margin-top:12px"><h3>${esc(j.name)}</h3><div class=muted>${esc(j.category)} · ${esc(j.sku)} · ${j.stock} in stock</div>
    <p>${esc(j.blurb)}</p><div class=price>${esc(j.price)}</div>
    <button onclick="addCart('${j.id}')">Add to cart</button></div>
    <h3 style="margin-top:22px">Reviews</h3>
    ${rv.map(r => `<div class=card style="margin-bottom:10px"><div class=row><span class=stars>${stars(r.rating)}</span> <b>${esc(r.author)}</b></div><p style=margin:6px0>${esc(r.text)}</p></div>`).join("") || "<p class=muted>No reviews yet.</p>"}
    ${ME ? `<div class=card><label>Your rating</label><select id=rr>${[5, 4, 3, 2, 1].map(n => `<option value=${n}>${stars(n)}</option>`).join("")}</select>
      <label>Your review</label><textarea id=rt rows=3 style=width:100%></textarea>
      <div class=err id=re></div><button onclick="postReview('${j.id}')">Post review</button></div>` : `<p class=muted>Sign in to leave a review.</p>`}`;
}
async function postReview(id) {
  const r = await api("/products/" + id + "/reviews", { method: "POST", body: JSON.stringify({ rating: +document.getElementById("rr").value, text: document.getElementById("rt").value }) });
  if (r.ok) product(id); else document.getElementById("re").textContent = r.j.error || "Could not post.";
}
async function addCart(id) { await api("/cart", { method: "POST", body: JSON.stringify({ product_id: id, qty: 1 }) }); cartCount(); }
async function cartCount() { const r = await api("/cart"); document.getElementById("cc").textContent = r.ok && r.j.count ? "(" + r.j.count + ")" : ""; }

async function cart() {
  const { ok, j } = await api("/cart");
  if (!ok) return auth();
  app.innerHTML = `<h3>Your cart</h3>${(j.lines || []).length ? `<table><tr><th>Item</th><th>Qty</th><th>Price</th><th></th></tr>
    ${j.lines.map(l => `<tr><td>${esc(l.name)}</td><td>${l.qty}</td><td>${esc(l.subtotal)}</td>
      <td><button class=ghost onclick="setQty('${l.id}',0)">Remove</button></td></tr>`).join("")}
    <tr><th>Total</th><th></th><th>${esc(j.total)}</th><th></th></tr></table>
    <button style="margin-top:14px" onclick="go('checkout')">Checkout</button>` : "<p class=muted>Your cart is empty.</p>"}`;
}
async function setQty(id, qty) { await api("/cart", { method: "POST", body: JSON.stringify({ product_id: id, qty }) }); cart(); cartCount(); }

async function checkout() {
  if (!ME) return auth();
  const c = (await api("/cart")).j;
  app.innerHTML = `<h3>Checkout</h3><p class=muted>Total ${esc(c.total || "$0.00")}. Test card 4242 4242 4242 4242, any future date.</p>
    <div class=card style=max-width:360px><label>Card number</label><input id=cn value="4242424242424242">
    <label>Name on card</label><input id=cname value="${esc(ME.name)}">
    <div class=err id=ce></div><button onclick="pay()">Pay ${esc(c.total || "")}</button></div>`;
}
async function pay() {
  const r = await api("/checkout", { method: "POST", body: JSON.stringify({ card: { number: document.getElementById("cn").value } }) });
  if (r.ok) { app.innerHTML = `<div class=card><h3>Order placed</h3><p>Order ${esc(r.j.order)} for ${esc(r.j.total)}.</p><button onclick="go('account')">View orders</button></div>`; cartCount(); }
  else document.getElementById("ce").textContent = r.j.error || "Payment failed.";
}

function auth() {
  app.innerHTML = `<div class=card style=max-width:360px><h3>Sign in</h3>
    <label>Email</label><input id=le><label>Password</label><input id=lp type=password>
    <div class=err id=lerr></div><button onclick="login()">Sign in</button>
    <a class=muted style="display:block;margin-top:10px;cursor:pointer" onclick="register()">Create an account</a>
    <a class=muted style=cursor:pointer onclick="go('forgot')">Forgot password?</a></div>`;
}
async function login() {
  const r = await api("/auth/login", { method: "POST", body: JSON.stringify({ email: document.getElementById("le").value, password: document.getElementById("lp").value }) });
  if (r.ok) go("account"); else document.getElementById("lerr").textContent = r.j.error || "Could not sign in.";
}
function register() {
  app.innerHTML = `<div class=card style=max-width:360px><h3>Create account</h3>
    <label>Name</label><input id=rn><label>Email</label><input id=re2><label>Password (8+ chars)</label><input id=rp type=password>
    <div class=err id=rerr></div><button onclick="doRegister()">Create account</button></div>`;
}
async function doRegister() {
  const email = document.getElementById("re2").value, password = document.getElementById("rp").value;
  const r = await api("/auth/register", { method: "POST", body: JSON.stringify({ name: document.getElementById("rn").value, email, password }) });
  if (!r.ok) return document.getElementById("rerr").textContent = r.j.error || "Could not register.";
  await api("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }); go("account");
}

async function account() {
  const o = (await api("/orders")).j.orders || [];
  app.innerHTML = `<div class=row style=justify-content:space-between><h3>Hi, ${esc(ME.name)}</h3>
    <div>${ME.role === "admin" ? `<button class=ghost onclick="go('admin')">Admin</button> ` : ""}<button class=ghost onclick="logout()">Sign out</button></div></div>
    <h3 style="margin-top:12px">Your orders</h3>${o.length ? `<table><tr><th>Order</th><th>Date</th><th>Items</th><th>Total</th><th>Status</th><th></th></tr>
    ${o.map(x => `<tr><td>${esc(x.id)}</td><td>${new Date(x.at * 1000).toLocaleDateString()}</td><td>${x.items}</td><td>${esc(x.total)}</td><td>${esc(x.status)}</td>
      <td><a class=muted style=cursor:pointer onclick="window.open('/api/orders/${x.id}/invoice')">Invoice</a></td></tr>`).join("")}</table>` : "<p class=muted>No orders yet.</p>"}`;
}
async function logout() { await api("/auth/logout", { method: "POST" }); ME = null; go("catalog"); }

async function admin() {
  if (!ME || ME.role !== "admin") return go("account");
  const u = (await api("/admin/users")).j.users || [], o = (await api("/admin/orders")).j.orders || [];
  app.innerHTML = `<h3>Admin</h3><p class=muted>${u.length} customers, ${o.length} orders.</p>
    <h3>Recent orders</h3><table><tr><th>Order</th><th>Customer</th><th>Total</th><th>Status</th></tr>
    ${o.slice(0, 20).map(x => `<tr><td>${esc(x.id)}</td><td>${esc(x.email)}</td><td>${esc(x.total)}</td><td>${esc(x.status)}</td></tr>`).join("")}</table>`;
}

cartCount(); render();
"""
