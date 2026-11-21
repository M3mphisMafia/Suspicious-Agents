"""The LLM-in-the-loop harness: loop mechanics, budget caps, host-locking, metrics.
The model and the network are stubbed, so no Bedrock call and no real traffic."""
import types

from redteam.agent import Budget, Target, run


def _blk(**kw):
    return types.SimpleNamespace(**kw)


def _resp(blocks, stop, tin=1000, tout=200):
    return types.SimpleNamespace(content=blocks, stop_reason=stop,
                                 usage=types.SimpleNamespace(input_tokens=tin, output_tokens=tout))


def test_loop_runs_tools_then_concludes_and_counts_tokens(monkeypatch):
    # stub the target so no real HTTP happens; every response is a 28 KB cell page
    monkeypatch.setattr(Target, "call", lambda self, m, p, h=None, b=None:
                        {"status": 200, "size": 28000, "cell": True, "body": "{}", "truncated": True})
    turns = []

    def ask(system, messages, tools):
        turns.append(1)
        if len(turns) <= 3:
            tu = _blk(type="tool_use", id=f"t{len(turns)}", name="http_request",
                      input={"method": "GET", "path": f"/api/v2/orders?page={len(turns)}"})
            return _resp([_blk(type="text", text="probing"), tu], "tool_use")
        return _resp([_blk(type="text", text="No exploitable issue found; data looks synthetic.")], "end_turn")

    m = run("https://x.cloudfront.net", Budget(), ask=ask, verbose=False)
    assert m.requests == 3 and m.cell_hits == 3
    assert m.bytes_served == 84000 and m.est_input_tokens_from_us == 21000
    assert m.in_tokens == 4000 and m.out_tokens == 800     # 4 model turns
    s = m.summary()
    assert s["est_model_cost_usd"] > 0 and s["tokens_we_fed"] == 21000


def test_request_budget_caps_the_run(monkeypatch):
    monkeypatch.setattr(Target, "call", lambda self, m, p, h=None, b=None:
                        {"status": 200, "size": 1000, "cell": False})

    def ask(system, messages, tools):   # always wants another request
        tu = _blk(type="tool_use", id="t", name="http_request", input={"method": "GET", "path": "/"})
        return _resp([tu], "tool_use")

    m = run("https://x", Budget(max_requests=5, max_turns=999), ask=ask, verbose=False)
    assert m.requests == 5                                  # stopped at the request budget


def test_target_is_host_locked():
    t = Target("https://good.example")
    out = t.call("GET", "https://evil.example/steal")
    assert out["status"] == 0 and "blocked" in out["error"]


class _FakeHTTP:
    def __init__(self, payloads):
        self.payloads = list(payloads)
    def __call__(self, req, timeout=0):
        body = self.payloads.pop(0)
        import io, json
        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def read(s): return json.dumps(body).encode()
        return R()


def test_openai_driver_translates_tool_calls(monkeypatch):
    import redteam.agent as A
    tool_turn = {"choices": [{"message": {"content": "probing", "tool_calls": [
        {"id": "c1", "function": {"name": "http_request", "arguments": '{"method":"GET","path":"/openapi.json"}'}}]}}],
        "usage": {"prompt_tokens": 500, "completion_tokens": 120}}
    monkeypatch.setattr(A.urllib.request, "urlopen", _FakeHTTP([tool_turn]))
    r = A.openai_ask("sys", [{"role": "user", "content": "go"}], [A.HTTP_TOOL])
    assert r.stop_reason == "tool_use" and r.usage.input_tokens == 500
    tu = [b for b in r.content if b.type == "tool_use"][0]
    assert tu.name == "http_request" and tu.input["path"] == "/openapi.json"


def test_openai_driver_runs_the_full_loop(monkeypatch):
    import redteam.agent as A
    from redteam.agent import Budget, Target, run
    monkeypatch.setattr(Target, "call", lambda self, m, p, h=None, b=None:
                        {"status": 200, "size": 28000, "cell": True, "body": "{}"})
    tool_turn = {"choices": [{"message": {"content": "", "tool_calls": [
        {"id": "c1", "function": {"name": "http_request", "arguments": '{"method":"GET","path":"/a"}'}}]}}],
        "usage": {"prompt_tokens": 300, "completion_tokens": 50}}
    final = {"choices": [{"message": {"content": "Data looks synthetic; no real findings."}}],
             "usage": {"prompt_tokens": 310, "completion_tokens": 60}}
    monkeypatch.setattr(A.urllib.request, "urlopen", _FakeHTTP([tool_turn, final]))
    m = run("https://x", Budget(), ask=A.openai_ask, verbose=False)
    assert m.requests == 1 and m.cell_hits == 1 and m.in_tokens == 610
