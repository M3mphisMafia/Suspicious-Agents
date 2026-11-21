"""Verdict API: keys fail closed, answers come from state, learning rides the log subscription."""
import base64
import gzip
import json
from decimal import Decimal

from test_scorer import NOW, FakeTable, cfg

from adapters import apigw_authorizer, envoy_ext_authz
from adapters.undertow_client import Undertow
from aa_ai import admin, scorer, verdict
from aa_ai.scoring import actor_key
from aa_ai.events import Event

UA = "Go-http-client/1.1"


def _call(t, body, key=None, policy=None):
    ev = {"headers": {"authorization": f"Bearer {key}"} if key else {}, "body": json.dumps(body)}
    return verdict.handle(ev, t, cfg(), lambda: policy or scorer.load_policy(t, cfg()), now=NOW)


def _key(t, kind="verdict"):
    return admin.create_key(t, "edge-gw", kind, "ops", NOW)["key"]


def test_keys_fail_closed():
    t = FakeTable()
    assert _call(t, {"ip": "1.2.3.4", "path": "/"})["statusCode"] == 401
    assert _call(t, {"ip": "1.2.3.4", "path": "/"}, key=_key(t, "client"))["statusCode"] == 401   # wrong kind
    k = _key(t)
    from aa_ai.verify import key_hash
    admin.revoke_key(t, key_hash(k)[:16], "ops", NOW)       # this key, not whichever sorts first
    assert _call(t, {"ip": "1.2.3.4", "path": "/"}, key=k)["statusCode"] == 401

    class Broken(FakeTable):
        def get_item(self, Key):
            raise RuntimeError("throttled")
    assert _call(Broken(), {"ip": "1.2.3.4", "path": "/"}, key="uk_x")["statusCode"] == 503


def test_answers_from_state(capsys):
    t = FakeTable()
    k = _key(t)
    ok = json.loads(_call(t, {"ip": "198.51.100.5", "path": "/api/products", "headers": {"user-agent": UA}}, key=k)["body"])
    assert ok["verdict"] == "allow" and ok["ttl"] == 30
    a = actor_key(Event(0, "203.0.113.7", "GET", "/", 0, UA))
    t.put_item(Item={"pk": "FLAG", "sk": a, "verdict": "block", "score": Decimal("0.9"), "ips": ["203.0.113.7"],
                     "signals": ["injection_payloads: x"], "exp": int(NOW + 600)})
    hdr = {"user-agent": UA, "authorization": "Bearer secret-token-123", "cookie": "a=b"}
    cell = {"edge": "cell"}
    out = json.loads(_call(t, {"ip": "203.0.113.7", "path": "/api/orders", "headers": hdr}, key=k, policy=cell)["body"])
    assert out["verdict"] == "cell" and out["reasons"] == ["injection_payloads"]
    out = json.loads(_call(t, {"ip": "203.0.113.7", "path": "/x", "headers": hdr}, key=k, policy={"edge": "block"})["body"])
    assert out["verdict"] == "block"
    honey = json.loads(_call(t, {"ip": "9.9.9.9", "path": "/", "headers": {"cookie": "session=hny_abcdef0123_00ff"}},
                             key=k, policy=cell)["body"])
    assert honey["verdict"] == "cell" and honey["score"] == 1
    logged = [json.loads(line) for line in capsys.readouterr().out.splitlines() if "undertow_event" in line]
    assert logged and all("secret-token-123" not in json.dumps(x) and "a=b" not in json.dumps(x) for x in logged)
    assert any(x["extra"].get("bearer") for x in logged) and any(x["extra"].get("honey") for x in logged)


def test_batches_and_bad_input():
    t = FakeTable()
    k = _key(t)
    many = json.loads(_call(t, {"requests": [{"ip": "1.2.3.4", "path": "/a"}, {"ip": "1.2.3.5", "path": "/b"}]}, key=k)["body"])
    assert [v["verdict"] for v in many["verdicts"]] == ["allow", "allow"]
    assert _call(t, {"ip": "not-an-ip", "path": "/"}, key=k)["statusCode"] == 400
    assert _call(t, {"ip": "1.2.3.4", "path": "no-slash"}, key=k)["statusCode"] == 400


def test_scorer_learns_from_verdict_api_lines():
    rec, extra = verdict.waf_record({"ip": "203.0.113.9", "path": "/api/search", "query": "q=' OR '1'='1",
                                     "headers": {"user-agent": UA, "authorization": "Bearer uk_partner"}}, NOW)
    line = json.dumps({"undertow_event": rec, "extra": extra})
    body = {"logGroup": "/aws/lambda/undertow-edge-VerdictFunction", "logEvents": [{"id": "1", "timestamp": 1, "message": line}]}
    evs, mvs = scorer.decode_logs({"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(body).encode())).decode()}})
    assert len(evs) == 1 and evs[0].payload.startswith("q=") and evs[0].extra["bearer"] == extra["bearer"]


class FakeAPI:
    def __init__(self, answer=None, fail=False):
        self.answer, self.fail, self.calls = answer or {"verdict": "allow", "ttl": 30}, fail, []

    def __call__(self, req, timeout=None):
        self.calls.append(json.loads(req.data))
        if self.fail:
            raise TimeoutError
        out = json.dumps({"verdicts": [self.answer] * len(self.calls[-1]["requests"])} if "requests" in self.calls[-1] else self.answer)

        class R:
            def read(self):
                return out.encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return R()


def test_client_fails_open_and_still_reports_cached_requests():
    api = FakeAPI()
    ut = Undertow("https://v.example", "uk_x", opener=api)
    for i in range(3):
        ut.verdict("1.2.3.4", "GET", f"/p{i}", headers={"user-agent": UA}, now=NOW + i)
    assert len(api.calls) == 1 and len(ut.pending) == 2                         # two answered from cache
    ut.verdict("1.2.3.4", "GET", "/p3", headers={"user-agent": UA}, now=NOW + 60)   # cache expired
    assert len(api.calls[-1]["requests"]) == 3                                     # the cached two ride along
    assert Undertow("https://v.example", "uk_x", opener=FakeAPI(fail=True)).verdict("1.2.3.4", "GET", "/")["verdict"] == "allow"
    assert Undertow("https://v.example", "uk_x", fail_open=False, opener=FakeAPI(fail=True)).verdict("1.2.3.4", "GET", "/")["verdict"] == "block"


def test_adapter_mappings():
    assert apigw_authorizer.decide("allow") and apigw_authorizer.decide("tarpit")
    assert not apigw_authorizer.decide("block") and not apigw_authorizer.decide("cell")
    assert apigw_authorizer.decide("cell", cell_as="allow")
    assert envoy_ext_authz.respond("block")[0] == 403
    st, hdrs, _ = envoy_ext_authz.respond("tarpit")
    assert st == 429 and ("retry-after", "9") in hdrs
    assert envoy_ext_authz.respond("cell") == (200, [("x-undertow-verdict", "cell")], b"")
