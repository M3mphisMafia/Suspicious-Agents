"""Many apps, one engine: per-app lines, per-app traffic, the cell copies the right app."""
import pytest
from test_scorer import NOW, FakeTable, FakeWaf, awslogs, cfg, waf_records

from aa_ai import admin, lambda_url, scorer
from aa_ai.events import Event
from aa_ai.snapshot import build

PROBES = ["q=' OR '1'='1", "q=1 UNION SELECT 1"]


def _probe(host, ip):
    return [Event(NOW - 100 + i * 9, ip, "GET", "/api/search", 0, "Go-http-client/1.1", host=host, payload=p)
            for i, p in enumerate(PROBES)]


def test_each_app_keeps_its_own_lines():
    t, w = FakeTable(), FakeWaf()
    admin.set_policy(t, cfg(), {"apps": {"billing.example": {"name": "Billing", "thresholds": {"tarpit": 0.46, "block": 0.5}}}},
                     "ops", NOW)
    scorer.run(awslogs(waf_records(_probe("billing.example", "203.0.113.7") + _probe("shop.example", "198.51.100.7"))),
               t, w, cfg(), now=NOW)
    flags = {v["app"]: v for (pk, _), v in t.items.items() if pk == "FLAG"}
    assert flags["billing.example"]["verdict"] == "block" and flags["shop.example"]["verdict"] == "tarpit"
    d = build(t, scorer.load_policy(t, cfg()), 1, NOW)
    apps = {a["host"]: a for a in d["apps"]}
    assert apps["billing.example"]["name"] == "Billing" and apps["billing.example"]["requests"] == 2
    assert apps["shop.example"]["flagged"] == 1 and {a["app"] for a in d["actors"]} == {"billing.example", "shop.example"}


def test_app_policy_is_validated_and_removable():
    t = FakeTable()
    for bad in ({"Not A Host!": {}}, {"a.example": {"thresholds": {"tarpit": 0.4}}},
                {"a.example": {"origin": "https://x.example/path"}}, {"a.example": {"weights": {"nope": 1}}}):
        with pytest.raises(ValueError):
            admin.set_policy(t, cfg(), {"apps": bad}, "ops", NOW)
    admin.set_policy(t, cfg(), {"apps": {"a.example": {"origin": "abc.lambda-url.us-east-1.on.aws"}}}, "ops", NOW)
    assert scorer.load_policy(t, cfg())["apps"]["a.example"]["origin"] == "abc.lambda-url.us-east-1.on.aws"
    admin.set_policy(t, cfg(), {"apps": {"a.example": None}}, "ops", NOW)
    assert scorer.load_policy(t, cfg())["apps"] == {}


def test_cell_copies_the_app_the_agent_attacked(monkeypatch):
    t = FakeTable()
    admin.set_policy(t, cfg(), {"apps": {"billing.example": {"origin": "billing-origin.example"}}}, "ops", NOW)
    monkeypatch.setattr(lambda_url, "_table", t)
    monkeypatch.setattr(lambda_url, "_apps", (0.0, {}))
    monkeypatch.setenv("APP_ORIGIN", "shop-origin.example")
    assert lambda_url._app_origin("billing.example:443") == "billing-origin.example"
    assert lambda_url._app_origin("unknown.example") == "shop-origin.example"
