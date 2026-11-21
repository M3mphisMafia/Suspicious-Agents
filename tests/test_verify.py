"""Verified agents: Ed25519, Web Bot Auth, crawler reverse DNS, integration keys, and the style cap."""
import base64
import json
import socket

import pytest
from test_scorer import FakeTable

from aa_ai import admin, detectors, scorer, verify
from aa_ai.detectors import Signal
from aa_ai.events import Event, parse_waf
from aa_ai.scoring import combine, evaluate, verdict

crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
NOW = 1_800_000_000.0


def _jwk(pub: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(pub).decode().rstrip("=")}


def test_ed25519_matches_a_real_implementation():
    sk = crypto.Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    for msg in (b"", b"undertow", bytes(range(200))):
        sig = sk.sign(msg)
        assert verify.ed25519_verify(pub, msg, sig)
        assert not verify.ed25519_verify(pub, msg + b"x", sig)
        assert not verify.ed25519_verify(pub, msg, sig[:-1] + bytes([sig[-1] ^ 1]))


def _signed(sk, host="shop.example", agent="https://agent.example", created=NOW - 10, expires=NOW + 300, tamper=False):
    jwk = _jwk(sk.public_key().public_bytes_raw())
    kid = verify.jwk_thumbprint(jwk)
    params = (f'("@authority" "signature-agent");created={int(created)};keyid="{kid}";alg="ed25519";'
              f'expires={int(expires)};nonce="n1";tag="web-bot-auth"')
    hdrs = {"host": host, "signature-agent": f'"{agent}"', "signature-input": f"sig1={params}"}
    base = verify.signature_base(["@authority", "signature-agent"], hdrs, params)
    sig = sk.sign(base + (b"!" if tamper else b""))
    hdrs["signature"] = "sig1=:" + base64.b64encode(sig).decode() + ":"
    return hdrs, {kid: base64.urlsafe_b64decode(jwk["x"] + "=")}


def test_web_bot_auth_verifies_only_trusted_valid_signatures():
    sk = crypto.Ed25519PrivateKey.generate()
    hdrs, keys = _signed(sk)
    fetch = lambda origin: keys if origin == "https://agent.example" else {}   # noqa: E731
    assert verify.verify_web_bot_auth(hdrs, ["https://agent.example"], NOW, fetch) == "agent.example"
    assert verify.verify_web_bot_auth(hdrs, ["https://other.example"], NOW, fetch) == ""     # not trusted
    assert verify.verify_web_bot_auth(hdrs, ["https://agent.example"], NOW + 3600, fetch) == ""   # expired
    bad, _ = _signed(sk, tamper=True)
    assert verify.verify_web_bot_auth(bad, ["https://agent.example"], NOW, fetch) == ""
    moved = {**hdrs, "host": "evil.example"}                      # replayed against another host
    assert verify.verify_web_bot_auth(moved, ["https://agent.example"], NOW, fetch) == ""
    assert verify.verify_web_bot_auth(hdrs, ["https://agent.example"], NOW, lambda o: 1 / 0) == ""   # fails closed


def test_crawler_reverse_dns():
    good = lambda ip: ("crawl-66-249-66-1.googlebot.com", ["66.249.66.1"])   # noqa: E731
    assert verify.verify_crawler("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1)", good) == "googlebot.com"
    lies = lambda ip: ("crawl.googlebot.com.evil.example", ["66.249.66.1"])  # noqa: E731
    assert verify.verify_crawler("66.249.66.1", "Googlebot/2.1", lies) == ""
    forward_mismatch = lambda ip: ("crawl.googlebot.com", ["1.2.3.4"])       # noqa: E731
    assert verify.verify_crawler("66.249.66.1", "Googlebot/2.1", forward_mismatch) == ""

    def no_ptr(ip):
        raise socket.herror("no PTR")

    def transient(ip):
        raise TimeoutError

    assert verify.verify_crawler("5.6.7.8", "Googlebot/2.1", no_ptr) == ""
    assert verify.verify_crawler("5.6.7.8", "Googlebot/2.1", transient) is None   # unknown, never "fake"
    assert verify.verify_crawler("5.6.7.8", "curl/8", good) == ""


def test_verifier_marks_keys_crawlers_and_fake_crawlers():
    t = FakeTable()
    out = admin.create_key(t, "acme-sync", "client", "ops", NOW)
    assert out["key"].startswith("uk_") and all(out["key"] not in json.dumps(v) for v in t.items.values())
    rec = {"timestamp": NOW * 1000, "httpRequest": {"clientIp": "198.51.100.7", "httpMethod": "GET", "uri": "/api/orders",
           "headers": [{"name": "Authorization", "value": f"Bearer {out['key']}"}, {"name": "User-Agent", "value": "acme/1"}]}}
    e = parse_waf(rec)
    assert "bearer" in e.extra and out["key"] not in json.dumps(e.extra)
    v = verify.Verifier(t, scorer.DEFAULT_POLICY, NOW, resolve=lambda ip: ("x.example", [ip]))
    assert v.check(e) == "key:acme-sync"
    bot = Event(NOW, "5.6.7.8", "GET", "/", 200, user_agent="Googlebot/2.1")
    assert v.check(bot) == "" and bot.extra.get("fake_crawler")
    admin.revoke_key(t, admin.list_keys(t)[0]["id"], "ops", NOW)
    assert verify.Verifier(t, scorer.DEFAULT_POLICY, NOW).check(e) == ""


def test_style_alone_never_reaches_tarpit():
    style = [Signal("burst_pause_cadence", 0.45, ""), Signal("metronome", 0.35, ""), Signal("map_then_walk", 0.5, "")]
    assert combine(style) == detectors.STYLE_CAP and verdict(combine(style)) == "watch"
    assert verdict(combine(style + [Signal("id_enumeration", 0.5, "")])) == "block"


def test_verified_requests_feed_intent_detectors_only():
    evs = [Event(NOW + i * 0.5, "198.51.100.7", "GET", f"/api/orders/ord_{i:016x}", 404,
                 user_agent=f"ua{i % 5}", extra={"verified": "key:acme"}) for i in range(12)]
    names = {s.name for s in evaluate(evs)}
    assert "id_enumeration" in names and "ua_churn" not in names


def test_injection_payloads_needs_two():
    one = [Event(NOW, "1.2.3.4", "GET", "/api/products", 200, payload="q=' OR '1'='1")]
    assert detectors.injection_payloads(one) is None
    two = one + [Event(NOW + 1, "1.2.3.4", "GET", "/files/../../etc/passwd", 404)]
    assert detectors.injection_payloads(two).name == "injection_payloads"


def test_policy_keeps_tarpit_above_the_style_cap():
    t = FakeTable()
    with pytest.raises(ValueError, match="tarpit must be above"):
        admin.set_policy(t, scorer.Config({}), {"thresholds": {"tarpit": 0.4}}, "ops", NOW)
    with pytest.raises(ValueError, match="https"):
        admin.set_policy(t, scorer.Config({}), {"verified": {"directories": ["http://x"]}}, "ops", NOW)
    p = admin.set_policy(t, scorer.Config({}), {"verified": {"directories": ["https://agent.example/"]}}, "ops", NOW)
    assert scorer.load_policy(t, scorer.Config({}))["verified"]["directories"] == ["https://agent.example"] == p["verified"]["directories"]
