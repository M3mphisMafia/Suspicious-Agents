"""Labeled traces: realistic attacker and benign actors as event sequences.

Each scenario is (name, is_attack, events). Attacker traces SHOULD reach tarpit/block;
benign traces should NOT. The benign set is deliberately adversarial to the detectors
(a steady poller, an office behind one NAT, a crawler) so the eval surfaces false
positives instead of hiding them.
"""
from __future__ import annotations

import random

from aa_ai.events import Event

UA_GO = "Go-http-client/1.1"
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_TOOL = "norma/0.4"
BROWSER_HDRS = {"sec-fetch-mode": "navigate"}   # a real browser sends Sec-Fetch-*


def _e(t, ip, method, path, status=200, ua=UA_GO, extra=None, payload=""):
    return Event(ts=t, src_ip=ip, method=method, path=path, status=status,
                 user_agent=ua, host="shop", payload=payload, extra=extra or {})


# ---------- attackers (should flag) ----------

def recon_then_walk(t0=1000.0):
    ip, evs, t = "203.0.113.10", [], t0
    evs += [_e(t, ip, "GET", "/openapi.json"), _e(t + 0.3, ip, "GET", "/robots.txt")]
    t += 1
    for _ in range(4):                                  # burst/think cycles
        for _ in range(5):
            evs.append(_e(t, ip, "GET", f"/api/v2/orders/{random.randint(1, 40)}"))
            t += 1.0
        t += 27.0                                        # the model 'thinking'
    return evs


def idor_walk(t0=1000.0):
    ip, evs, t = "203.0.113.11", [], t0
    evs.append(_e(t, ip, "POST", "/api/auth/login", 200)); t += 1
    for i in range(16):
        evs.append(_e(t, ip, "GET", f"/api/v2/orders/ord_{i:08d}", 404)); t += 0.5
    return evs


def credential_stuffing(t0=1000.0):
    ip, evs, t = "203.0.113.12", [], t0
    routes = ["/api/auth/login", "/oauth/token", "/api/auth/reset", "/login"]
    for i in range(22):
        evs.append(_e(t, ip, "POST", routes[i % len(routes)], 401)); t += 0.3
    return evs


def injection_fuzz(t0=1000.0):
    ip, evs, t = "203.0.113.13", [], t0
    inj = ["<script>alert(1)</script>", "' OR '1'='1", "{{7*7}}", "../../etc/passwd", "A" * 3000]
    for i in range(14):
        evs.append(_e(t, ip, "POST", "/api/v2/profile", 422, payload=inj[i % len(inj)])); t += 0.4
    return evs


def scrape_flood(t0=1000.0):
    ip, evs, t = "203.0.113.14", [], t0
    for _ in range(40):
        evs.append(_e(t, ip, "GET", "/api/products")); t += 0.2       # metronome: fixed interval
    return evs


def retry_after_ignorer(t0=1000.0):
    ip, evs, t = "203.0.113.15", [], t0
    for _ in range(30):
        evs.append(_e(t, ip, "GET", "/api/v2/orders/1", 429)); t += 1.5   # keeps hitting through 429s
    return evs


def spoofed_browser(t0=1000.0):
    ip, evs, t = "203.0.113.16", [], t0
    for _ in range(12):
        evs.append(_e(t, ip, "GET", "/api/products", 200, ua=UA_CHROME, extra={"spoof": True})); t += 1.0
    return evs


def tool_fingerprint(t0=1000.0):
    ip, evs, t = "203.0.113.17", [], t0
    for _ in range(6):
        evs.append(_e(t, ip, "GET", "/api/products", 200, ua=UA_TOOL)); t += 1.0
    return evs


def decoy_touch(t0=1000.0, prefix="/api/v1/internal/ops"):
    ip, evs, t = "203.0.113.18", [], t0
    evs.append(_e(t, ip, "GET", "/openapi.json")); t += 1
    evs.append(_e(t, ip, "GET", f"{prefix}/export"))   # a decoy route: certain
    return evs


def honey_replay(t0=1000.0, tag="abcdef0123"):
    ip, evs, t = "203.0.113.19", [], t0
    evs.append(_e(t, ip, "GET", "/api/v2/orders/1", 200, extra={"honey": tag}))
    return evs


# ---------- benign (should NOT flag) ----------

def real_shopper(t0=1000.0):
    ip, evs, t = "198.51.100.5", [], t0
    for p in ("/", "/api/products", "/api/products/prd_0003", "/api/products/prd_0003/reviews",
              "/api/products/prd_0012", "/api/cart", "/api/checkout", "/api/orders"):
        evs.append(_e(t, ip, "GET" if p != "/api/checkout" else "POST", p, 200, ua=UA_CHROME, extra={}))
        t += random.uniform(6, 20)                       # human pace, with reading pauses
    return evs


def office_nat(t0=1000.0):
    # many people behind one NAT + one shared browser UA, diverse paths, successful logins
    ip, evs, t = "198.51.100.6", [], t0
    paths = ["/", "/api/products", "/api/products/prd_0007", "/api/cart", "/api/orders",
             "/api/auth/login", "/api/me", "/api/products/prd_0021"]
    for i in range(28):
        p = random.choice(paths)
        st = 200
        evs.append(_e(t, ip, "POST" if "login" in p else "GET", p, st, ua=UA_CHROME, extra={}))
        t += random.uniform(2, 9)
    return evs


def steady_api_client(t0=1000.0):
    # a legitimate integration polling one endpoint every 60s with auth (metronome-shaped)
    ip, evs, t = "198.51.100.7", [], t0
    for _ in range(25):
        evs.append(_e(t, ip, "GET", "/api/orders", 200, ua="acme-sync/2.1", extra={}))
        t += 60.0
    return evs


def search_crawler(t0=1000.0):
    ip, evs, t = "198.51.100.8", [], t0
    evs.append(_e(t, ip, "GET", "/robots.txt", 200, ua=UA_BOT)); t += 3
    for i in range(12):
        evs.append(_e(t, ip, "GET", f"/api/products?page={i + 1}", 200, ua=UA_BOT)); t += random.uniform(8, 15)
    return evs


def health_monitor(t0=1000.0):
    ip, evs, t = "198.51.100.9", [], t0
    for _ in range(30):
        evs.append(_e(t, ip, "GET", "/health", 200, ua="UptimeBot/1.0", extra={})); t += 30.0
    return evs


# ---------- evasion-aware attackers: they adapt to the detectors ----------

TOOL = {"tls": "t13d1715h2_5b57614c22b0_3d5424432f57", "hfp": "7e1c0a9d2b33"}   # one tool stack


def _t(t, ip, method, path, status=200, ua=UA_GO, payload="", fp=TOOL):
    return Event(ts=t, src_ip=ip, method=method, path=path, status=status, user_agent=ua, host="shop",
                 payload=payload, tls_fp=fp["tls"], extra={"hfp": fp["hfp"]})


def _oid():
    return f"ord_{random.getrandbits(64):016x}"


def human_paced_idor(t0=1000.0):
    ip, evs, t = "203.0.113.21", [], t0
    for _ in range(14):                                  # 15-45 s between guesses, never a rhythm
        evs.append(_t(t, ip, "GET", f"/api/orders/{_oid()}", 404)); t += random.uniform(15, 45)
    return evs


def slow_and_low_idor(t0=1000.0):
    ip, evs, t = "203.0.113.22", [], t0
    for i in range(11):                                  # one guess every 20-40 minutes, ~5 hours
        evs.append(_t(t, ip, "GET", f"/api/orders/{_oid()}", 200 if i % 5 == 0 else 404)); t += random.uniform(1200, 2400)
    return evs


def jittered_credential_spray(t0=1000.0):
    ip, evs, t = "203.0.113.23", [], t0
    routes = ["/api/auth/login", "/oauth/token", "/api/auth/reset", "/login"]
    for _ in range(16):                                  # random gaps: no metronome to catch
        evs.append(_t(t, ip, "POST", random.choice(routes), 401)); t += random.uniform(2, 50)
    return evs


def ua_rotating_idor(t0=1000.0):
    ip, evs, t = "203.0.113.24", [], t0
    uas = [f"python-requests/2.{20 + i}.0" for i in range(6)] + [f"okhttp/4.{i}.0" for i in range(6)] + \
          [f"Go-http-client/{1 + i % 2}.{i}" for i in range(6)]
    for i in range(16):                                  # a new User-Agent every request: 16 one-shot "actors"
        evs.append(_t(t, ip, "GET", f"/api/orders/{_oid()}", 404, ua=uas[i])); t += random.uniform(1, 6)
    return evs


def distributed_idor(t0=1000.0):
    evs = []
    for n in range(20):                                  # 20 networks, 3 guesses each: none alone is a walk
        ip, t = f"198.18.{n}.7", t0 + n * 13
        for _ in range(3):
            evs.append(_t(t, ip, "GET", f"/api/orders/{_oid()}", 404, ua="python-httpx/0.27")); t += random.uniform(5, 30)
    return evs


def distributed_injection(t0=1000.0):
    probes = ["q=' OR '1'='1", "q=1 UNION SELECT 1,2", "f=../../etc/passwd", "u=http://169.254.169.254/latest/",
              "q=<script>alert(1)</script>", "c=;cat /etc/passwd"]
    evs = []
    for n in range(12):                                  # the edge's view: no origin status, one probe per IP
        ip, t = f"198.19.{n}.9", t0 + n * 11
        evs.append(_t(t, ip, "GET", "/api/products", 0, ua="Go-http-client/2.0", payload=probes[n % len(probes)]))
        evs.append(_t(t + random.uniform(3, 9), ip, "GET", "/api/products", 0, ua="Go-http-client/2.0"))
    return evs


def jittered_injection(t0=1000.0):
    ip, evs, t = "203.0.113.25", [], t0
    for p in ["q=' OR '1'='1", "", "q=1 UNION SELECT password FROM users", "", "", "id=1;cat /etc/passwd", "", ""]:
        evs.append(_t(t, ip, "GET", "/api/products", 200, payload=p)); t += random.uniform(8, 40)
    return evs


# ---------- honest automation: must never be slowed ----------

def ai_shopping_agent(t0=1000.0):
    """A customer's AI agent driving a real browser: bursty, model pauses, buys one thing."""
    ip, evs, t = "198.51.100.20", [], t0
    pages = ["/", "/api/products", "/api/products?page=2", "/api/products/prd_a1b2c3d4e5f60718",
             "/api/products/prd_a1b2c3d4e5f60718/reviews", "/api/products/prd_0f1e2d3c4b5a6978", "/api/cart",
             "/api/checkout", "/api/orders"]
    for c in range(4):
        for p in pages[c * 2: c * 2 + 3]:
            evs.append(_e(t, ip, "POST" if p == "/api/checkout" else "GET", p, 200, ua=UA_CHROME, extra={"browser": True}))
            t += random.uniform(0.4, 1.4)
        t += random.uniform(24, 31)
    return evs


def partner_fleet(t0=1000.0):
    """A partner's four sync servers on four networks: one library, one path, every minute."""
    evs = []
    for n in range(4):
        ip, t = f"192.0.{2 + n}.10", t0 + n * 3
        for i in range(20):
            evs.append(_t(t, ip, "GET", "/api/orders" if i % 2 else "/api/products", 200, ua=f"acme-sync/2.1 (node-{n})"))
            t += 60.0
    return evs


def signed_ai_agent(t0=1000.0):
    """A Web Bot Auth agent that reads the API map and walks it fast. Verified: style is not held against it."""
    ip, evs, t, v = "198.51.100.30", [], t0, {"verified": "signed:agent.example"}
    evs.append(_e(t, ip, "GET", "/openapi.json", 200, ua="ExampleAgent/1.0", extra=dict(v))); t += 1
    for _ in range(4):
        for _ in range(5):
            evs.append(_e(t, ip, "GET", f"/api/products/prd_{random.getrandbits(64):016x}", 200, ua="ExampleAgent/1.0",
                          extra=dict(v)))
            t += 1.0
        t += 27
    return evs


def login_typos_and_old_orders(t0=1000.0):
    """Three bad passwords, then in; over a day opens nine past orders, two long gone."""
    ip, evs, t, b = "198.51.100.32", [], t0, {"browser": True}
    for st in (401, 401, 401, 200):
        evs.append(_e(t, ip, "POST", "/api/auth/login", st, ua=UA_CHROME, extra=dict(b))); t += random.uniform(5, 15)
    for i in range(9):
        evs.append(_e(t, ip, "GET", f"/api/orders/{_oid()}", 404 if i in (2, 6) else 200, ua=UA_CHROME, extra=dict(b)))
        t += random.uniform(600, 2400)
    return evs


ATTACKS = [recon_then_walk, idor_walk, credential_stuffing, injection_fuzz, scrape_flood,
           retry_after_ignorer, spoofed_browser, tool_fingerprint, decoy_touch, honey_replay,
           human_paced_idor, slow_and_low_idor, jittered_credential_spray, ua_rotating_idor,
           distributed_idor, distributed_injection, jittered_injection]
BENIGN = [real_shopper, office_nat, steady_api_client, search_crawler, health_monitor,
          ai_shopping_agent, partner_fleet, signed_ai_agent, login_typos_and_old_orders]


def all_scenarios(seed: int = 0):
    """Deterministic list of (name, is_attack, events)."""
    random.seed(seed)
    out = []
    for f in ATTACKS:
        out.append((f.__name__, True, f()))
    for f in BENIGN:
        out.append((f.__name__, False, f()))
    return out
