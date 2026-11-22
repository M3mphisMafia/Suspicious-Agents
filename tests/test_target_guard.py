"""The attack simulator and the red-team agent run only against the Undertow reference store.
A generic 429/503, an AWS WAF challenge or an environment variable must never unlock them."""
import email.message
import io
import json
import urllib.error

import pytest

from store import attack_sim
from store.attack_sim import EDGE_BODY, is_store


def _headers(**h):
    m = email.message.Message()
    for k, v in h.items():
        m[k.replace("_", "-")] = v
    return m


class _Resp:
    def __init__(self, body=b"", **headers):
        self.body, self.headers = body, _headers(**headers)

    def read(self):
        return self.body


def _serve(monkeypatch, outcome):
    def fake(url, timeout=15):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr(attack_sim.urllib.request, "urlopen", fake)
    monkeypatch.setattr(attack_sim.time, "sleep", lambda s: None)


def _http_error(code, body=b"", **headers):
    return urllib.error.HTTPError("https://x.example/openapi.json", code, "err", _headers(**headers), io.BytesIO(body))


def test_the_reference_store_is_recognized(monkeypatch):
    _serve(monkeypatch, _Resp(json.dumps({"info": {"title": "Northwind Supply"}}).encode()))
    assert is_store("https://store.example")


def test_the_padded_cell_is_recognized(monkeypatch):
    _serve(monkeypatch, _Resp(b"{}", x_engagement_notice="1"))
    assert is_store("https://store.example")


def test_undertows_own_edge_429_is_recognized(monkeypatch):
    _serve(monkeypatch, _http_error(429, EDGE_BODY, Retry_After="9"))
    assert is_store("https://store.example")


@pytest.mark.parametrize("outcome", [
    _http_error(429, b"Too Many Requests", Retry_After="30"),      # any rate-limited site
    _http_error(503, EDGE_BODY, Retry_After="9"),                  # 503 is never proof
    _http_error(429, EDGE_BODY),                                   # no Retry-After
    _Resp(b"<html>challenge</html>", x_amzn_waf_action="challenge"),   # any AWS WAF challenge
    _Resp(json.dumps({"info": {"title": "Somebody Else's API"}}).encode()),
    urllib.error.URLError("unreachable"),
])
def test_anyone_elses_site_is_refused(monkeypatch, outcome):
    _serve(monkeypatch, outcome)
    assert not is_store("https://someone-else.example")


@pytest.mark.parametrize("var", ["ARTEX_FORCE", "RED_FORCE"])
def test_no_environment_variable_unlocks_the_guard(monkeypatch, var):
    monkeypatch.setenv(var, "1")
    _serve(monkeypatch, _http_error(429, b"Too Many Requests", Retry_After="30"))
    assert not is_store("https://someone-else.example")


def test_the_red_team_agent_refuses_a_foreign_host(monkeypatch):
    from redteam import agent
    monkeypatch.setenv("RED_FORCE", "1")
    monkeypatch.setattr(agent, "is_store", lambda base: False)
    with pytest.raises(SystemExit, match="refusing"):
        agent.main("https://someone-else.example")
