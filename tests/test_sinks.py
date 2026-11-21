"""Outbound destinations, OCSF findings, signed webhooks, shared indicators."""
import hashlib
import hmac
import json
from decimal import Decimal

import pytest
from test_scorer import NOW, FakeTable, FakeWaf, cfg

from aa_ai import admin, alerts, sinks

OK = lambda url: "hooks.example"   # noqa: E731 - skip DNS in tests


class Post:
    def __init__(self, status=200, fail=False):
        self.status, self.fail, self.sent = status, fail, []

    def __call__(self, req, timeout=None):
        self.sent.append((req.full_url, dict(req.header_items()), json.loads(req.data)))
        if self.fail:
            raise ConnectionError("down")
        st = self.status

        class R:
            status = st

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return R()


def test_only_public_https_destinations():
    for bad in ("http://8.8.8.8/x", "https://127.0.0.1/x", "https://10.1.2.3/x", "https://u:p@8.8.8.8/x",
                "https://169.254.169.254/latest"):
        with pytest.raises(ValueError):
            sinks.public_https(bad)
    assert sinks.public_https("https://8.8.8.8/hook") == "8.8.8.8"


def test_formats():
    lines = ["Agent: net:203.0.113.0/24|ua:x", "IP: 203.0.113.7"]
    raw, h = sinks.render({"type": "splunk_hec", "token": "T"}, "decoy", "k", "certain detection", lines, NOW)
    ev = json.loads(raw)["event"]
    assert h["authorization"] == "Splunk T" and ev["class_uid"] == 2004 and ev["severity_id"] == 4
    assert ev["src_endpoint"]["ip"] == "203.0.113.7"
    raw, h = sinks.render({"type": "webhook", "secret": "s3"}, "breach", "k", "tripwire", lines, NOW)
    t, v1 = (p.split("=", 1)[1] for p in h["x-undertow-signature"].split(","))
    assert hmac.compare_digest(v1, hmac.new(b"s3", t.encode() + b"." + raw, hashlib.sha256).hexdigest())
    assert "attachments" in json.loads(sinks.render({"type": "teams"}, "anomaly", "k", "s", lines, NOW)[0])
    assert json.loads(sinks.render({"type": "slack"}, "anomaly", "k", "s", lines, NOW)[0])["text"].startswith("*Undertow")


def test_deliver_filters_by_kind_and_never_raises():
    t = FakeTable()
    a = sinks.add(t, {"type": "slack", "name": "soc", "url": "https://hooks.example/a", "kinds": ["breach"]}, "ops", NOW, check=OK)
    sinks.add(t, {"type": "webhook", "name": "siem", "url": "https://hooks.example/b"}, "ops", NOW, check=OK)
    post = Post()
    assert sinks.deliver(t, "decoy", "k", "s", ["x"], NOW, opener=post, check=OK) == 1      # slack wants breach only
    assert sinks.deliver(t, "breach", "k", "s", ["x"], NOW, opener=post, check=OK) == 2
    assert sinks.deliver(t, "breach", "k", "s", ["x"], NOW, opener=Post(fail=True), check=OK) == 0
    assert t.items[("DEST", a["id"])]["last_status"].startswith("error")


def test_alerts_fan_out_to_destinations(monkeypatch):
    t, post = FakeTable(), Post()
    sinks.add(t, {"type": "webhook", "name": "siem", "url": "https://8.8.8.8/hook"}, "ops", NOW)
    monkeypatch.setattr(sinks.urllib.request, "urlopen", post)
    assert alerts.send(t, {"alerts": {}}, "decoy", "agent-1", "certain detection", ["IP: 203.0.113.7"], NOW)
    assert post.sent and post.sent[0][2]["finding"]["class_uid"] == 2004


def test_admin_keeps_secrets_out_of_the_audit():
    t = FakeTable()
    monkey = sinks.public_https
    sinks.public_https = OK
    try:
        out = admin.act({"action": "add_destination", "type": "splunk_hec", "url": "https://hec.example/services/collector/event",
                         "token": "HEC-SECRET"}, t, FakeWaf(), cfg(), "ops", NOW)
    finally:
        sinks.public_https = monkey
    audit = [v for (pk, _), v in t.items.items() if pk == "AUDIT"]
    assert out["id"] and audit and "HEC-SECRET" not in json.dumps(audit) and "hec.example" not in audit[0]["body"]
    assert all("HEC-SECRET" not in json.dumps(d) for d in sinks.masked(t))


def test_indicators_and_stix():
    flags = [{"sk": "net:203.0.113.0/24|ua:python-httpx/0.27|tls:t13d", "verdict": "block", "confirmed": True,
              "ips": ["203.0.113.7"], "ja4": "t13d1715h2_x", "score": Decimal("1"), "exp": NOW + 600, "first": NOW - 60},
             {"sk": "net:198.51.100.0/24|ua:Mozilla/5.0", "verdict": "tarpit", "ips": ["198.51.100.9"], "score": Decimal("0.6"), "exp": NOW + 60},
             {"sk": "x", "verdict": "block", "labeled": "person", "ips": ["192.0.2.1"], "score": Decimal("1"), "exp": NOW + 60}]
    inds = sinks.indicators(flags, NOW)
    assert {(i["type"], i["value"]) for i in inds} == {("ipv4", "203.0.113.7"), ("ja4", "t13d1715h2_x"), ("user_agent", "python-httpx/0.27")}
    b = sinks.stix(inds, NOW)
    pats = [o["pattern"] for o in b["objects"]]
    assert b["type"] == "bundle" and "[ipv4-addr:value = '203.0.113.7']" in pats and len(pats) == 2
