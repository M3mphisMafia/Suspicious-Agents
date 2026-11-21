"""IP reputation: a secondary signal that never gates alone."""
import json

from test_scorer import NOW, FakeTable, FakeWaf, awslogs, cfg, waf_records

from aa_ai import detectors, reputation
from aa_ai.events import Event
from aa_ai.scorer import run
from aa_ai.scoring import combine, evaluate
from aa_ai.detectors import Signal


def _reset_lists():
    reputation._RANGES.update(exp=0.0, v4={}, v6=[], src="")
    reputation._TOR.update(exp=0.0, set=frozenset(), src="")


def _pol(**feeds):
    f = {"datacenter": True, "tor": True, "greynoise": False, "abuseipdb": False}
    f.update(feeds)
    return {"reputation": {"enabled": True, "feeds": f}}


def _ev(ip, path="/", payload=""):
    return Event(NOW, ip, "GET", path, 0, "python-httpx/0.27", "app.example", payload=payload, extra={})


# ---- the enricher ----

def test_datacenter_cidr_from_env_tags_datacenter():
    _reset_lists()
    r = reputation.Reputation(_pol(), NOW, FakeTable(),
                              env={"DATACENTER_CIDRS": "45.33.0.0/16"})
    assert r.check(_ev("45.33.32.9")) == "datacenter"
    assert r.check(_ev("44.0.0.9")) == ""               # outside the range


def test_private_and_bad_ips_are_never_scored():
    _reset_lists()
    r = reputation.Reputation(_pol(), NOW, FakeTable(),
                              env={"DATACENTER_CIDRS": "10.0.0.0/8"})
    assert r.check(_ev("10.1.2.3")) == ""                # RFC1918 is never global
    assert r.check(_ev("not-an-ip")) == ""


def test_tor_exit_list_is_matched_and_cached_per_container():
    _reset_lists()
    calls = []

    def fetch(url, headers=None, timeout=4.0, cap=0):
        calls.append(url)
        return b"# comment\n45.33.32.9\n45.33.32.10\n"

    env = {"TOR_EXIT_URL": "https://exits.example/list"}
    r = reputation.Reputation(_pol(datacenter=False), NOW, FakeTable(), env=env, fetch=fetch)
    assert r.check(_ev("45.33.32.9")) == "tor_exit"
    assert r.check(_ev("45.33.32.11")) == ""
    assert len(calls) == 1                               # list fetched once, then cached


def test_keyed_feed_is_bounded_and_cached_in_the_table():
    _reset_lists()
    t = FakeTable()
    seen = []

    def fetch(url, headers=None, timeout=4.0, cap=0):
        seen.append(url)
        return json.dumps({"classification": "malicious"}).encode()

    env = {"GREYNOISE_KEY": "gn", "DATACENTER_CIDRS": ""}
    r = reputation.Reputation(_pol(datacenter=False, tor=False, greynoise=True), NOW, t, env=env, fetch=fetch, budget=1)
    assert r.check(_ev("45.33.32.5")) == "malicious"
    # a second IP exceeds the batch budget -> no live call, no false accusation
    assert r.check(_ev("45.33.32.6")) == ""
    assert len(seen) == 1
    assert t.items[("REP", "45.33.32.5")]["cats"] == "malicious"
    # a fresh batch reads the cache, not the network
    r2 = reputation.Reputation(_pol(datacenter=False, tor=False, greynoise=True), NOW, t, env=env, fetch=fetch, budget=5)
    assert r2.check(_ev("45.33.32.5")) == "malicious"
    assert len(seen) == 1


def test_feed_failure_fails_open():
    _reset_lists()
    def boom(*a, **k):
        raise OSError("timeout")
    r = reputation.Reputation(_pol(greynoise=True), NOW, FakeTable(),
                              env={"GREYNOISE_KEY": "gn", "DATACENTER_RANGES_URL": "https://x/y"}, fetch=boom)
    assert r.check(_ev("45.33.32.5")) == ""            # nothing known, never an error


def test_disabled_reputation_tags_nothing():
    _reset_lists()
    pol = {"reputation": {"enabled": False, "feeds": {"datacenter": True}}}
    r = reputation.Reputation(pol, NOW, FakeTable(), env={"DATACENTER_CIDRS": "45.33.0.0/16"})
    assert r.check(_ev("45.33.32.9")) == ""


# ---- the detector ----

def test_detector_reports_the_strongest_category_and_is_style():
    malicious = [Event(NOW, "1.2.3.4", "GET", "/", 0, "x", extra={"reputation": "datacenter,malicious"})]
    s = detectors.reputation(malicious)
    assert s and s.name == "reputation" and s.weight == 0.4
    assert "reputation" not in detectors.INTENT          # never an intent signal
    assert s.weight < detectors.STYLE_CAP                # can never gate alone


def test_reputation_alone_never_passes_watch_cap():
    # strongest reputation + two style detectors still capped below tarpit
    sigs = [Signal("reputation", 0.4, "malicious"), Signal("metronome", 0.35, "x"), Signal("spoofed_browser", 0.45, "y")]
    assert combine(sigs) <= detectors.STYLE_CAP


def test_reputation_sharpens_a_real_intent_signal():
    # two intent signals land at tarpit; a malicious-IP reputation tips the same actor to block
    intent = [Signal("injection_payloads", 0.5, "sqli"), Signal("id_enumeration", 0.5, "walk")]
    with_rep = intent + [Signal("reputation", 0.4, "malicious")]
    assert combine(intent) < 0.8 <= combine(with_rep)    # corroboration crosses the block line


def test_verified_request_is_not_reputation_scored():
    # a verified crawler from a datacenter IP: style detectors (reputation included) skip it
    evs = [Event(NOW, "1.2.3.4", "GET", "/", 0, "Googlebot",
                 extra={"reputation": "datacenter", "verified": "crawler:googlebot.com"})]
    assert not any(s.name == "reputation" for s in evaluate(evs))


# ---- end to end through the scorer ----

def test_scorer_persists_reputation_and_escalates_a_datacenter_attacker():
    _reset_lists()
    t, w = FakeTable(), FakeWaf()
    # an injection walk (intent) from a datacenter IP: reputation is recorded as a corroborating signal
    evs = [Event(NOW - 50 + i, "45.33.32.9", "GET", "/api/search", 0, "python-httpx/0.27",
                 "app.example", payload=p)
           for i, p in enumerate(["q=' OR '1'='1", "q=1 UNION SELECT 1", "id=../../etc/passwd"])]
    c = cfg(DATACENTER_CIDRS="45.33.0.0/16", DATACENTER_RANGES_URL="", TOR_EXIT_URL="")
    run(awslogs(waf_records(evs)), t, w, c, now=NOW)
    flag = next(v for (pk, sk), v in t.items.items() if pk == "FLAG")
    assert flag["verdict"] in ("tarpit", "block")
    assert float(flag["score"]) > 0.5                     # above injection alone
    assert any(s.startswith("reputation:") for s in flag["signals"])
    # the enrichment is persisted on the stored events
    assert any(pk != "FLAG" and "datacenter" in str(v.get("e", "")) for (pk, sk), v in t.items.items())
