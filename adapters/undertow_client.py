"""Ask Undertow for a verdict. Stdlib only: drops into a Lambda, a sidecar or a script.

    ut = Undertow(VERDICT_URL, VERDICT_KEY)
    v = ut.verdict(ip, "GET", "/api/orders/42", "a=1", headers)   # -> {"verdict": "allow", ...}

Availability first: any error or timeout answers "allow" (fail_open=True), because a defense
that takes the app down has done the attacker's work. Cached answers are reused for their
ttl, and the requests answered from cache ride along with the next real call, so Undertow
still learns from every request.
"""
from __future__ import annotations

import json
import time
import urllib.request

VERDICTS = ("allow", "challenge", "tarpit", "cell", "block")


class Undertow:
    def __init__(self, url: str, key: str, timeout: float = 1.0, fail_open: bool = True, cache: bool = True,
                 opener=None):
        self.url, self.key, self.timeout, self.fail_open, self.use_cache = url, key, timeout, fail_open, cache
        self.open = opener or urllib.request.urlopen
        self.cache: dict[tuple, tuple[float, dict]] = {}
        self.pending: list[dict] = []

    def verdict(self, ip: str, method: str, path: str, query: str = "", headers: dict | None = None,
                ja4: str = "", now: float | None = None) -> dict:
        now = now or time.time()
        headers = headers or {}
        req = {"ip": ip, "method": method, "path": path, "query": query, "headers": headers, "ja4": ja4, "ts": now}
        ck = (ip, next((v for k, v in headers.items() if k.lower() == "user-agent"), ""))
        hit = self.cache.get(ck) if self.use_cache else None
        if hit and hit[0] > now and len(self.pending) < 49:
            self.pending.append(req)                  # answered from cache, learned from on the next call
            return {**hit[1], "cached": True}
        batch, self.pending = self.pending + [req], []
        body = {"requests": batch} if len(batch) > 1 else req
        try:
            r = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST",
                                       headers={"authorization": f"Bearer {self.key}", "content-type": "application/json"})
            with self.open(r, timeout=self.timeout) as resp:      # noqa: S310 - the operator's own endpoint
                out = json.loads(resp.read())
            ans = out["verdicts"][-1] if "verdicts" in out else out
            if ans.get("verdict") not in VERDICTS:
                raise ValueError("bad verdict")
        except Exception as exc:  # noqa: BLE001
            return {"verdict": "allow" if self.fail_open else "block", "error": type(exc).__name__}
        if self.use_cache:
            if len(self.cache) > 10000:
                self.cache.clear()
            self.cache[ck] = (now + float(ans.get("ttl", 30)), ans)
        return ans
