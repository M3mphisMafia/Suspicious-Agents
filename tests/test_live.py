"""The Dashboard tab's live feed: a bounded per-batch sample (rare kinds first, no per-request I/O),
classes and aspects decided server-side, data/live.json assembly, the admin-only route, and the
dashboard assets the pipeline publishes."""
import json
import os
import random
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from aa_ai import admin, flood, live, scorer
from aa_ai.events import Event, parse_waf
from aa_ai.scorer import minute_key, run
from test_console import _ev
from test_flood import rec
from test_scorer import NOW, FakeTable, FakeWaf, _agent_waf_view, awslogs, cfg, waf_records
from test_snapshot import FakeS3

ROOT = Path(__file__).parent.parent
FLOODER = "198.51.100.7"


def rows(t):
    return [v for (pk, _), v in t.items.items() if pk.startswith("LIVE#")]


def sampled(t):
    return [x for r in rows(t) for x in json.loads(r["ev"])]


# ---------- the sample: bounded per batch, rare kinds first ----------

def test_the_reservoir_keeps_at_most_40_and_weights_add_up():
    s = live.Sampler(random.Random(3))
    for i in range(10_000):
        s.offer("other" if i % 10 else "flood", i)
    for i in range(7):
        s.offer("rare", -i)
    kept = list(s.items())
    assert len(s) == len(kept) == 16 + 8 + 7 <= live.PER_BATCH
    assert sum(w for _, w in kept) == pytest.approx(10_007)                  # each kept item stands for its stratum
    assert {it for it, _ in kept if it <= 0} == {0, -1, -2, -3, -4, -5, -6}   # every rare one kept


def test_one_row_per_batch_and_a_decoy_survives_a_flood():
    t = FakeTable()
    t.put_item(Item={"pk": "FLAG", "sk": f"flood:{FLOODER}", "verdict": "block", "score": 1, "ips": [FLOODER],
                     "flood": True, "exp": NOW + 900})
    recs = [rec(FLOODER, ts=NOW - 50 + i * 0.01) for i in range(3000)]
    recs[1500]["httpRequest"]["uri"] = "/api/v1/internal/ops/export"         # one decoy hit in the flood
    run(awslogs(recs), t, FakeWaf(), cfg(MODE="observe", DECOY_PREFIX="/api/v1/internal/ops"), now=NOW)
    ev = sampled(t)
    assert len(rows(t)) == 1 and len(ev) <= live.PER_BATCH
    assert sum(1 for x in ev if x[1] == "decoy") == 1 and {x[1] for x in ev} == {"decoy", "flood"}


def test_the_sample_stays_bounded_during_a_surge():
    t = FakeTable()
    t.put_item(Item={**flood.STATE, "active": True, "since": int(NOW) - 300, "calm": 0})
    recs = [rec(f"10.{i % 40}.0.{i % 200}", ts=NOW - 50 + i * 0.01) for i in range(4000)]
    run(awslogs(recs), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert len(rows(t)) == 1 and len(sampled(t)) <= live.PER_BATCH


def test_no_per_request_writes_for_the_sample():
    class Puts(FakeTable):
        def __init__(self):
            super().__init__()
            self.live_puts = 0

        def put_item(self, Item):
            self.live_puts += Item["pk"].startswith("LIVE#")
            super().put_item(Item)
    for n in (5, 5000):
        t = Puts()
        run(awslogs([rec(f"10.0.{i % 50}.1", ts=NOW - 50 + i * 0.01) for i in range(n)]), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
        assert t.live_puts == 1


def test_a_full_minute_writes_no_more_rows():
    t = FakeTable()
    t.put_item(Item={"pk": "STATM", "sk": minute_key(NOW), "req": 9000, "live": live.PER_MINUTE, "exp": NOW + 999})
    run(awslogs([rec("10.0.0.1", ts=NOW - 5)]), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    assert rows(t) == [] and t.items[("STATM", minute_key(NOW))]["req"] == 9001     # still counted


# ---------- classes and aspects ----------

def ev(path="/", method="GET", action="ALLOW", rule="", status=None, verified="", ip="10.0.0.1", **extra):
    r = rec(ip, ts=NOW - 5, path=path, action=action, rule=rule, status=status)
    r["httpRequest"]["httpMethod"] = method
    e = parse_waf(r)
    e.extra.update(verified=verified, **extra)
    return e


@pytest.mark.parametrize("e,kw,want", [
    (lambda: ev(), {}, "allow"),
    (lambda: ev(verified="crawler:googlebot.com"), {}, "verified"),
    (lambda: ev(), {"watched": True}, "watch"),
    (lambda: ev(action="CHALLENGE", rule="challenge"), {}, "challenge"),
    (lambda: ev(), {"verdict": "tarpit"}, "tarpit"),
    (lambda: ev(ip="192.0.2.9"), {"verdict": "block", "cell_ips": {"192.0.2.9"}}, "cell"),
    (lambda: ev(action="BLOCK", rule="flagged-ip", status=429), {"verdict": "block"}, "block"),
    (lambda: ev(action="BLOCK", rule="tool-ua", status=403), {}, "block"),
    (lambda: ev(action="BLOCK", rule="aws-anti-ddos"), {}, "flood"),
    (lambda: ev(action="CHALLENGE", rule="flood-pattern"), {}, "flood"),
    (lambda: ev(), {"guarded": True}, "flood"),
    (lambda: ev(honey="ab12cd34ef"), {"guarded": True, "verdict": "block"}, "decoy"),      # certainty wins
])
def test_each_class(e, kw, want):
    kw = {"guarded": False, **kw}
    assert live.classify(e(), kw.pop("guarded"), **kw) == want


def test_classes_from_a_real_batch():
    """Flags and modes decide: a confirmed agent is 'block' at the edge, 'cell' when the edge routes to the cell."""
    for edge, want in (("block", "block"), ("cell", "cell")):
        t = FakeTable()
        t.put_item(Item={"pk": "POLICY", "sk": "current", "edge": edge})
        t.put_item(Item={"pk": "FLAG", "sk": "net:203.0.113.0/24|ua:x", "verdict": "block", "score": 1,
                         "ips": ["203.0.113.7"], "exp": NOW + 999})
        run(awslogs([rec("203.0.113.7", ts=NOW - 5)]), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
        assert [x[1] for x in sampled(t)] == [want]


@pytest.mark.parametrize("path,method,want", [
    ("/login", "POST", "login"), ("/account/settings", "GET", "login"), ("/api/auth/token", "POST", "login"),
    ("/cart", "GET", "checkout"), ("/api/v2/orders/12", "GET", "checkout"), ("/checkout/pay", "POST", "checkout"),
    ("/admin/users", "GET", "admin"), ("/search", "GET", "search"), ("/api/v2/search?q=x", "GET", "search"),
    ("/api/v2/products", "GET", "api"), ("/openapi.json", "GET", "api"), ("/graphql", "POST", "api"),
    ("/", "GET", "static"), ("/products/7", "GET", "static"), ("/assets/app.js", "GET", "static"),
    ("/contact", "POST", "other"), ("/api/v1/internal/ops/export", "GET", "decoys"),
])
def test_aspects(path, method, want):
    from aa_ai import detectors
    detectors.DECOY_PREFIXES.add("/api/v1/internal/ops")
    try:
        assert live.aspect(Event(NOW, "10.0.0.1", method, path, 0)) == want
    finally:
        detectors.DECOY_PREFIXES.discard("/api/v1/internal/ops")


def test_compact_fields_and_no_raw_actor_key():
    e = ev(path="/api/v2/orders/12?token=secret", method="POST")
    e.extra["country"] = "DE"
    x = live.compact(e, "allow", 2.5)
    out = dict(zip(live.FIELDS, x[:9]))
    assert out["p"] == "/api/v2/orders/12" and out["cc"] == "DE" and out["z"] == "checkout" and len(out["a"]) == 10
    assert "|ua:" not in json.dumps(x) and x[9] == 2.5
    assert parse_waf({**rec("10.0.0.1"), "httpRequest": {**rec("10.0.0.1")["httpRequest"], "country": "NL"}}).extra["country"] == "NL"


# ---------- data/live.json ----------

def test_assembly_caps_balances_and_counts():
    last = minute_key(NOW - 60)
    many = [[NOW - 70 + i * 0.01, "allow", "shop.example", "static", "GET", "/", "US", "a" * 10, "10.0.0.1", 2.0] for i in range(900)]
    rare = [[NOW - 65 + i, c, "shop.example", "decoys" if c == "decoy" else "api", "GET", "/x", "", "b" * 10, "10.0.0.2", 1.0]
            for i, c in enumerate(["decoy", "cell", "flood", "verified"])]
    rws = [{"pk": f"LIVE#{last}", "ev": json.dumps(many[:450] + rare)}, {"pk": f"LIVE#{last}", "ev": json.dumps(many[450:])}]
    f = live.assemble(rws, {last: 2000}, NOW, {"mode": "enforce", "edge": "cell", "apps": {"billing.example": {}}})
    assert len(f["events"]) == live.CAP
    assert {"decoy", "cell", "flood", "verified"} <= {e["c"] for e in f["events"]}     # rare classes still show
    assert [e["t"] for e in f["events"]] == sorted((e["t"] for e in f["events"]), reverse=True)
    assert set(f["events"][0]) == set(live.FIELDS)
    c = f["counts"]
    assert c["minute"] == last and c["requests"] == 2000 and sum(c["class"].values()) == pytest.approx(2000, abs=4)
    assert c["class"]["allow"] > c["class"]["decoy"] > 0 and c["aspect"]["static"] > 0
    assert f["mode"] == "enforce" and f["apps"] == ["billing.example", "shop.example"]


def test_the_tick_writes_live_json_no_store():
    t, s3 = FakeTable(), FakeS3()
    run(awslogs(waf_records(_agent_waf_view())), t, FakeWaf(), cfg(MODE="observe"), now=NOW)
    key = live.publish(t, s3, "dash", scorer.load_policy(t, cfg()), now=NOW + 60)
    f = s3.objects[("dash", key)]
    assert key == "data/live.json" and f["events"] and f["counts"]["requests"] > 0   # FakeS3 asserts no-store + JSON


# ---------- the route: admins only ----------

def test_live_feed_is_for_admins_only(monkeypatch):
    t, w = FakeTable(), FakeWaf()
    read = lambda h: '{"live":1}' if h == "live" else '{"snap":1}'
    path = "/_undertow/api/data/live"
    assert admin.handle(_ev("GET", path, None), t, w, cfg(), read_data=read)["statusCode"] == 403
    assert admin.handle(_ev("GET", path, "[user]"), t, w, cfg(), read_data=read)["statusCode"] == 403
    assert admin.handle(_ev("GET", "/_undertow/api/data/6", "[user]"), t, w, cfg(), read_data=read)["body"] == '{"snap":1}'
    monkeypatch.setattr(admin, "_mfa_ok", lambda cog, pool, u: False)
    r = admin.handle(_ev("GET", path, "[admin]"), t, w, cfg(), read_data=read, cog=object(), pool="p")
    assert r["statusCode"] == 403 and "mfa_required" in r["body"]
    monkeypatch.setattr(admin, "_mfa_ok", lambda cog, pool, u: True)
    r = admin.handle(_ev("GET", path, "[admin]"), t, w, cfg(), read_data=read, cog=object(), pool="p")
    assert r["statusCode"] == 200 and r["body"] == '{"live":1}' and r["headers"]["cache-control"] == "no-store"
    assert admin.handle(_ev("GET", path, "[admin]"), t, w, cfg(), read_data=lambda h: "")["statusCode"] == 404


# ---------- the pipeline publishes every dashboard file; IAM covers live.json ----------

def test_every_dashboard_file_is_published_with_its_type(tmp_path):
    fake = tmp_path / "aws"
    fake.write_text(f'#!/usr/bin/env bash\necho "$@" >> "{tmp_path}/calls"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    subprocess.run(["bash", str(ROOT / "infra" / "upload_dashboard.sh"), "dash-bucket"], env=env, check=True, capture_output=True)
    calls = (tmp_path / "calls").read_text().splitlines()
    want = {"index.html": "text/html", "login.html": "text/html", "live.js": "text/javascript", "live.css": "text/css"}
    for name, ctype in want.items():
        line = next(c for c in calls if f"s3://dash-bucket/_undertow/{name} " in c)
        assert f"--content-type {ctype}" in line and "--cache-control no-store" in line
    assert len(calls) == len([f for f in (ROOT / "dashboard").iterdir() if f.is_file() and " 2." not in f.name])
    assert 'bash infra/upload_dashboard.sh "$DASH"' in (ROOT / "infra" / "publish.sh").read_text()


def test_live_json_permissions():
    from test_template import _tpl
    r = _tpl()["Resources"]

    def grants(role, action):
        out = []
        for st in r[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]:
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if action in acts:
                res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                out += [x.get("Fn::Sub", x) if isinstance(x, dict) else x for x in res]
        return out
    assert "${DashboardBucket.Arn}/data/live.json" in grants("TickRole", "s3:PutObject")
    assert "${DashboardBucket.Arn}/data/live.json" in grants("AdminRole", "s3:GetObject")
    assert grants("ScorerRole", "s3:PutObject") == []                          # the log scorer never publishes


def test_the_scene_script_parses():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    subprocess.run([node, "--check", str(ROOT / "dashboard" / "live.js")], check=True)
    html = (ROOT / "dashboard" / "index.html").read_text()
    assert '<script src="live.js" defer></script>' in html and '<link rel="stylesheet" href="live.css">' in html
    assert html.index('id="tab-dashboard"') < html.index('id="tab-overview"')          # the first tab


def test_the_console_opens_on_the_dashboard_and_can_refresh():
    html = (ROOT / "dashboard" / "index.html").read_text()
    assert 'id="tab-dashboard" aria-selected="true"' in html and 'id="tab-overview" aria-selected="false"' in html
    assert 'id="view-dashboard" class="view"' in html and 'id="view-overview" class="view hidden"' in html
    assert '(h || "dashboard").split("/")' in html                                       # no hash, no session: Dashboard
    assert 'sessionStorage.setItem("undertow-tab"' in html                               # a reload comes back to the tab
    assert 'id="refresh-now"' in html and 'new CustomEvent("undertow:refresh")' in html
    js = (ROOT / "dashboard" / "live.js").read_text()
    assert 'id="lv-refresh"' in js and '"undertow:refresh"' in js
