"""Campaigns: many IPs, one operator, judged together."""
from test_scorer import NOW, FakeTable, FakeWaf, awslogs, cfg, waf_records

from aa_ai import campaigns
from aa_ai.events import Event, parse_waf
from aa_ai.scorer import run
from aa_ai.snapshot import build

FP = {"hfp": "abc123abc123"}


def _member(n, paths, status=404, payloads=()):
    ip = f"198.{51 + n}.100.{10 + n}"     # a different /24 each
    return [Event(NOW + n * 7 + i * 2.3, ip, "GET", p, status, "python-httpx/0.27", tls_fp="t13d_x",
                  payload=payloads[i] if i < len(payloads) else "", extra=dict(FP)) for i, p in enumerate(paths)]


def test_pooled_id_walk_across_networks_is_one_campaign():
    members = {f"a{n}": _member(n, [f"/api/orders/ord_{n:02d}{i:014x}" for i in range(3)]) for n in range(4)}
    for evs in members.values():                         # alone, each is three requests: nothing
        assert not any(s for s in (d(evs) for d in campaigns.POOLED))
    out = campaigns.link(members)
    assert set(out) == set(members) and {s.name for s in out.values()} == {"campaign"}
    assert "id_enumeration" in next(iter(out.values())).detail


def test_same_tool_same_path_without_attack_is_a_fleet():
    members = {f"a{n}": _member(n, ["/api/orders", "/api/products"], status=200) for n in range(3)}
    assert {s.name for s in campaigns.link(members).values()} == {"fleet"}


def test_two_networks_or_different_paths_do_not_link():
    two = {f"a{n}": _member(n, ["/api/orders"]) for n in range(2)}
    assert campaigns.link(two) == {}
    apart = {f"a{n}": _member(n, [f"/route{n}/x"]) for n in range(4)}
    assert campaigns.link(apart) == {}


def test_real_browsers_are_never_linked():
    rec = {"timestamp": 1, "httpRequest": {"clientIp": "1.2.3.4", "uri": "/", "headers": [
        {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0 Safari/537.36"},
        {"name": "Sec-Fetch-Mode", "value": "navigate"}]}}
    assert campaigns.client_fp(parse_waf(rec)) == ""


def test_scorer_flags_every_member_of_an_attacking_campaign():
    t, w = FakeTable(), FakeWaf()
    probes = ["q=' OR '1'='1", "q=1 UNION SELECT 1", "id=../../etc/passwd", "u=http://169.254.169.254/"]
    evs = []
    for n in range(4):   # each actor sends ONE probe: alone that is not enough
        evs += [Event(NOW - 100 + n * 5 + i, f"203.{n}.113.9", "GET", p, 0, "python-httpx/0.27",
                      payload=probes[n] if p == "/api/search" else "") for i, p in enumerate(["/api/search", "/api/products"])]
    run(awslogs(waf_records(evs)), t, w, cfg(), now=NOW)
    flags = {sk: v for (pk, sk), v in t.items.items() if pk == "FLAG"}
    assert len(flags) == 4 and all(any(s.startswith("campaign") for s in f["signals"]) for f in flags.values())
    cs = build(t, {"mode": "enforce"}, 6, NOW)["campaigns"]
    assert cs[0]["actors"] == 4 and cs[0]["nets"] == 4 and cs[0]["status"] == "attacking"


def test_quiet_sibling_is_escalated_when_the_campaign_attacks():
    t, w = FakeTable(), FakeWaf()
    calm = [Event(NOW - 200 + n * 3 + j, f"203.{n}.113.9", "GET", p, 0, "python-httpx/0.27")
            for n in range(3) for j, p in enumerate(("/api/search", "/api/products"))]
    run(awslogs(waf_records(calm)), t, w, cfg(), now=NOW - 150)
    assert not any(pk == "FLAG" for (pk, _) in t.items)
    hot = [Event(NOW - 50 + i, "203.9.113.9", "GET", "/api/search", 0, "python-httpx/0.27", payload=q)
           for i, q in enumerate(["q=' OR '1'='1", "q=1 UNION SELECT 1"])]
    run(awslogs(waf_records(hot)), t, w, cfg(), now=NOW)
    flagged = {sk.split("|")[0] for (pk, sk) in t.items if pk == "FLAG"}
    assert {"net:203.0.113.0/24", "net:203.1.113.0/24", "net:203.2.113.0/24"} <= flagged


def test_blocked_members_still_link_their_siblings():
    t, w = FakeTable(), FakeWaf()
    hot = [Event(NOW - 200 + i, "203.7.113.9", "GET", "/api/search", 0, "python-httpx/0.27", payload=q)
           for i, q in enumerate(["q=' OR '1'='1", "q=1 UNION SELECT 1", "q=1;cat /etc/passwd"])]
    run(awslogs(waf_records(hot)), t, w, cfg(), now=NOW - 190)
    k = next(sk for (pk, sk) in t.items if pk == "FLAG")
    t.items[("FLAG", k)].update({"verdict": "block", "exp": int(NOW + 86400)})          # held at block
    t.items = {key: v for key, v in t.items.items() if key[0] != "CAMP"}               # as if blocked before campaigns existed
    calm = [Event(NOW - 100 + n * 3 + j, f"203.{n}.113.9", "GET", p, 0, "python-httpx/0.27")
            for n in range(3) for j, p in enumerate(("/api/search", "/api/products"))]
    calm.append(Event(NOW - 50, "203.7.113.9", "GET", "/api/search", 0, "python-httpx/0.27"))
    run(awslogs(waf_records(calm)), t, w, cfg(), now=NOW)
    assert any(pk == "CAMP" and k in sk for (pk, sk) in t.items) and t.items[("FLAG", k)].get("app")


def test_a_campaign_of_blocked_agents_reads_as_attacking():
    from aa_ai.snapshot import campaign_view
    rows = [{"fp": "f", "actor": f"a{i}", "net": "n1", "routes": ["/api/auth/login", "/api/auth/reset"], "ips": [f"1.2.3.{i}"], "last": 1}
            for i in range(4)]
    assert campaign_view(rows, [])[0]["status"] == "fleet"
    assert campaign_view(rows, [{"sk": "a0", "verdict": "block", "signals": ["keeps_hammering: x"]}])[0]["status"] == "attacking"
