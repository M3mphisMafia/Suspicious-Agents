import asyncio
import random
import time

from aa_ai.decoys import DecoySet
from aa_ai.events import Event
from aa_ai.scoring import analyze, distributed_spray
from aa_ai.shield import Shield


def agent_trace(t0=1_800_000_000.0, ip="203.0.113.7"):
    """Synthetic ARTEX-shaped run: map, burst/think loop, canaries, write-verify, auth hop."""
    evs, t = [], t0
    evs.append(Event(t, ip, "GET", "/openapi.json", 200, "Go-http-client/1.1"))
    for cycle in range(6):
        t += random.uniform(25, 31)
        for i in range(random.randint(3, 9)):
            t += random.uniform(0.8, 1.2)
            evs.append(Event(t, ip, "GET", f"/api/v2/orders/{cycle}{i}", 404, "Go-http-client/1.1"))
    evs.append(Event(t + 1, ip, "POST", "/api/v2/profile", 422, "Go-http-client/1.1",
                     payload="email=test@example.com"))
    for i in range(4):
        t += 3
        evs.append(Event(t, ip, "POST", "/api/v2/profile", 422, "Go-http-client/1.1"))
        evs.append(Event(t + 1, ip, "POST", "/api/v2/profile", 200, "Go-http-client/1.1"))
        evs.append(Event(t + 1.5, ip, "GET", "/api/v2/profile", 200, "Go-http-client/1.1"))
    for p in ("/login", "/oauth/token", "/password/reset", "/signup/verify"):
        t += 1
        evs.append(Event(t, ip, "POST", p, 429, "Go-http-client/1.1", host="app.example"))
    return evs


def human_trace(t0=1_800_000_000.0, ip="198.51.100.20"):
    evs, t = [], t0
    ua = "Mozilla/5.0 (Macintosh) Safari/605.1.15"
    for p in ["/", "/login", "/dashboard", "/api/v2/orders", "/api/v2/orders/12", "/settings"]:
        t += random.expovariate(1 / 20)
        evs.append(Event(t, ip, "GET", p, 200, ua))
    evs.append(Event(t + 40, ip, "POST", "/api/v2/profile", 422, ua))
    evs.append(Event(t + 95, ip, "POST", "/api/v2/profile", 200, ua))
    return evs


def test_agent_flagged_human_allowed():
    random.seed(7)
    reports = {r.key.split("|")[0]: r for r in analyze(agent_trace() + human_trace())}
    agent = reports["net:203.0.113.0/24"]
    human = reports["net:198.51.100.0/24"]
    assert agent.verdict == "block", agent.signals
    names = {s.name for s in agent.signals}
    assert {"burst_pause_cadence", "canary_inputs", "write_then_verify", "auth_endpoint_hop"} <= names
    assert human.verdict == "allow", human.signals


def test_decoy_is_certain():
    d = DecoySet().register()
    r = analyze([Event(1.0, "192.0.2.1", "GET", d.routes[0], 200)])[0]
    assert r.score == 1.0


def test_distributed_spray_across_rotating_ips():
    evs = [Event(1000 + i, f"192.0.2.{i % 6}", "POST", "/login", 401, username="cfo@corp")
           for i in range(12)]
    assert distributed_spray(evs) == [("cfo@corp", 12, 6)]


async def _app(scope, receive, send):
    status = 422 if scope["path"] == "/bad" else 200
    await send({"type": "http.response.start", "status": status, "headers": []})
    await send({"type": "http.response.body", "body": b'{"detail":"field x must be int"}'})


def _call(shield, path, method="GET", ip="203.0.113.9"):
    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": method, "path": path, "headers": [], "client": (ip, 1)}
    asyncio.run(shield(scope, receive, send))
    return out


def test_shield_decoy_and_masking(monkeypatch):
    async def nosleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", nosleep)
    s = Shield(_app)
    assert _call(s, "/ok")[0]["status"] == 200
    out = _call(s, s.decoys.routes[0])
    assert out[0]["status"] == 200
    # actor now scored 1.0: every later request is throttled or stalled
    later = _call(s, "/ok")
    assert later[0]["status"] in (429, 503)


def test_shield_masks_validation_detail_for_watched_actor():
    s = Shield(_app)
    s.score["net:203.0.113.0/24|ua:"] = 0.35
    out = _call(s, "/bad")
    assert out[0]["status"] == 400
    assert b"field x" not in out[-1]["body"]


async def _auth_app(scope, receive, send):
    status = 401 if scope["path"].endswith("-bad") else 200
    await send({"type": "http.response.start", "status": status, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def test_failed_logins_share_one_budget_across_auth_routes():
    s = Shield(_auth_app, auth_failure_burst=3, auth_failures_per_min=0)
    paths = ("/login-bad", "/oauth/token-bad", "/reset-bad", "/signin")
    assert [_call(s, p, "POST")[0]["status"] for p in paths] == [401, 401, 401, 429]


def test_office_behind_one_nat_logging_in_successfully_is_never_throttled():
    s = Shield(_auth_app, auth_failure_burst=3, auth_failures_per_min=0)
    codes = {_call(s, "/login", "POST", ip="198.51.100.10")[0]["status"] for _ in range(200)}
    assert codes == {200}


def test_allow_cidr_bypasses_everything():
    s = Shield(_app, allow_cidrs=["203.0.113.0/24"])
    s.score["net:203.0.113.0/24|ua:"] = 1.0
    assert _call(s, "/ok")[0]["status"] == 200


def test_unblock_clears_score_and_exempts(monkeypatch):
    async def nosleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", nosleep)
    s = Shield(_app)
    _call(s, s.decoys.routes[0])
    assert _call(s, "/ok")[0]["status"] in (429, 503)
    s.unblock("203.0.113.9")
    assert _call(s, "/ok")[0]["status"] == 200
    assert "net:203.0.113.0/24|ua:" not in s.score


def _call_h(shield, path, headers, ip="10.0.0.5"):
    out = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "GET", "path": path, "client": (ip, 1),
             "headers": [(k.encode(), v.encode()) for k, v in headers.items()]}
    asyncio.run(shield(scope, receive, send))
    return out


def test_origin_secret_rejects_bypass_but_keeps_health_checks():
    s = Shield(_app, origin_secret="s3cret")
    assert _call_h(s, "/ok", {})[0]["status"] == 403
    assert _call_h(s, "/health", {})[0]["status"] == 200
    assert _call_h(s, "/ok", {"x-origin-verify": "s3cret"})[0]["status"] == 200


def test_client_ip_behind_alb_and_cloudfront():
    s = Shield(_app, origin_secret="s3cret", proxy_hops=1)
    ok = {"x-origin-verify": "s3cret"}
    _call_h(s, "/ok", {**ok, "cloudfront-viewer-address": "198.51.100.7:443",
                       "x-forwarded-for": "6.6.6.6, 198.51.100.7, 130.176.0.1"})
    assert any(k.startswith("net:198.51.100.0/24") for k in s.history)
    s2 = Shield(_app, proxy_hops=1)  # ALB only: rightmost XFF is what ALB saw
    _call_h(s2, "/ok", {"x-forwarded-for": "6.6.6.6, 192.0.2.44"})
    assert any(k.startswith("net:192.0.2.0/24") for k in s2.history)
    # an unverified request cannot pick its identity with a spoofed CloudFront header
    s3 = Shield(_app, proxy_hops=0)
    _call_h(s3, "/ok", {"cloudfront-viewer-address": "1.2.3.4:1"}, ip="10.0.0.5")
    assert any(k.startswith("net:10.0.0.0/24") for k in s3.history)


def test_error_after_app_started_is_not_answered_twice():
    calls = []

    async def app(scope, receive, send):
        calls.append(1)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("boom")

    s = Shield(app)
    try:
        _call(s, "/ok")
    except RuntimeError:
        pass
    assert len(calls) == 1


def test_idle_actors_are_swept():
    s = Shield(_app, window=60, max_actors=10)
    for i in range(50):
        _call(s, "/ok", ip=f"10.{i}.0.1")
    s._sweep(time.time() + 3600)
    assert not s.history and not s.score and not s.last_seen
    for i in range(50):
        _call(s, "/ok", ip=f"10.{i}.0.1")
    s._sweep(time.time())
    assert len(s.last_seen) <= 10


def test_artex_tool_fingerprints():
    from aa_ai.detectors import js_harvest_burst, tool_fingerprint
    for ua in ("norma/0.4", "artex-enrich/1.0", "Mozilla/5.0 (spa-api-recon spider)"):
        assert tool_fingerprint([Event(1, "1.2.3.4", "GET", "/", 200, ua)]).weight == 0.9
    assert tool_fingerprint([Event(1, "1.2.3.4", "GET", "/", 200, "Mozilla/5.0 (Macintosh) Safari/605")]) is None
    burst = [Event(1 + i * 0.05, "1.2.3.4", "GET", f"/static/chunk-{i}.js", 200, "x") for i in range(22)]
    assert js_harvest_burst(burst)
    page = [Event(1 + i * 0.3, "1.2.3.4", "GET", f"/static/app-{i}.js", 200, "x") for i in range(6)]
    assert js_harvest_burst(page) is None
