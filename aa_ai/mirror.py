"""The real app's shape, learned so the padded cell looks like it.

Once per container the cell makes a FIXED set of requests to the real origin (its OpenAPI, its
front page and scripts, its public collections, one 404) and learns: the routes, the public
responses, each record's shape, the envelope style, the error bodies, and the response time.
It never forwards an agent's request to the real app: what it learned is replayed or used as
a template for generated data. If learning fails, the cell falls back to its generic world.
"""
from __future__ import annotations

import json
import random
import re
import secrets
import statistics
import time
import urllib.request

MAX_ASSETS, MAX_BYTES, TIMEOUT, REFRESH = 8, 512 * 1024, 3.0, 900
_ASSET = re.compile(r'(?:src|href)="(/[^"/][^"]*\.(?:js|css))"')
_DT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
_IDV = re.compile(r"^([a-z]{2,4})_[0-9a-f]{8,}$")


class Shape:
    """A record template learned from real records: each key's kind, range and seen values."""

    def __init__(self, records: list[dict]):
        self.keys: dict[str, dict] = {}
        for r in records[:50]:
            for k, v in r.items():
                s = self.keys.setdefault(k, {"types": set(), "vals": [], "lo": None, "hi": None})
                s["types"].add(type(v).__name__)
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    s["lo"] = v if s["lo"] is None else min(s["lo"], v)
                    s["hi"] = v if s["hi"] is None else max(s["hi"], v)
                elif isinstance(v, str) and len(s["vals"]) < 20 and v not in s["vals"]:
                    s["vals"].append(v)
                elif isinstance(v, list) and v and isinstance(v[0], dict):
                    s["child"] = Shape(v)

    def prefix(self) -> str:
        m = _IDV.match(str((self.keys.get("id") or {}).get("vals", [""])[0] if self.keys.get("id") else ""))
        return m.group(1) if m else ""

    def make(self, rng: random.Random, mint, oid: str | None = None) -> dict:
        out = {}
        for k, s in self.keys.items():
            t, vals = s["types"], s["vals"]
            v0 = vals[0] if vals else ""
            if k == "id":
                out[k] = oid or mint(self.prefix() or "obj", rng)
            elif "bool" in t:
                out[k] = rng.random() < 0.5
            elif "int" in t and s["lo"] is not None:
                out[k] = rng.randint(int(s["lo"]), max(int(s["lo"]), int(s["hi"])))
            elif "float" in t and s["lo"] is not None:
                out[k] = round(rng.uniform(s["lo"], s["hi"]), 2)
            elif "list" in t:
                c = s.get("child")
                out[k] = [c.make(rng, mint) for _ in range(rng.randint(1, 3))] if c else []
            elif "dict" in t:
                out[k] = {}
            elif _IDV.match(v0):
                out[k] = mint(_IDV.match(v0).group(1), rng)
            elif _DT.match(v0):
                out[k] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - rng.randint(3600, 300 * 86400)))
            elif "@" in v0:
                out[k] = f"{rng.choice(['ops', 'billing', 'j.ortiz', 'm.chen', 'a.patel'])}@{v0.split('@', 1)[1]}"
            elif vals:
                out[k] = rng.choice(vals)      # enums and catalog words seen in public data
            else:
                out[k] = None
        return out


class Mirror:
    def __init__(self, origin: str, secret: str | None = None, header: str = "x-origin-verify",
                 decoy_prefix: str = "", opener=None):
        self.origin, self.secret, self.header = origin.rstrip("/"), secret, header
        self.decoy_prefix, self.open = decoy_prefix, opener or urllib.request.urlopen
        self.ready, self.learned_at = False, 0.0
        self.spec: dict = {}
        self.static: dict[str, tuple[str, bytes]] = {}     # path -> (content-type, body), served as is
        self.public: dict[str, dict | list] = {}            # exact public JSON by path
        self.shapes: dict[str, Shape] = {}                   # route template -> record shape
        self.lists: dict[str, str] = {}                      # collection route -> list key ("" = bare list)
        self.envelopes: dict[str, str] = {}                  # every collection seen, empty ones too -> its list key
        self.by_id: dict[str, dict] = {}                     # public records by id: list and detail must agree
        self.errors: dict[int, bytes] = {}
        self.latency = 0.2
        self.style = "named"                                 # private collections: {"orders": [...]}

    # ---------- learning: fixed requests only ----------

    def _get(self, path: str):
        if time.time() > self._deadline:
            raise TimeoutError("learning budget spent")
        # the allow header tells the app's own Shield this is us, not an actor to score
        hdrs = {self.header: self.secret, "x-amzn-waf-undertow-allow": self.secret} if self.secret else {}
        req = urllib.request.Request(self.origin + path, headers={**hdrs, "user-agent": "undertow-mirror/1"})
        t0 = time.time()
        try:
            with self.open(req, timeout=TIMEOUT) as r:   # noqa: S310 - our own origin
                body, status, ctype = r.read(MAX_BYTES), r.status, r.headers.get("content-type", "")
        except urllib.error.HTTPError as e:
            body, status, ctype = e.read(MAX_BYTES), e.code, e.headers.get("content-type", "")
        self._lat.append(time.time() - t0)
        return status, ctype, body

    def learn(self, budget: float = 6.0) -> "Mirror":
        """Bounded: what is learned within budget seconds is kept; the rest stays generic."""
        self._lat: list[float] = []
        self._deadline = time.time() + budget
        self.learned_at = time.time()          # a failed learn still waits REFRESH before retrying
        try:
            st, _, body = self._get("/openapi.json")
            if st != 200:
                return self
            self.spec = json.loads(body)
            st, ct, home = self._get("/")
            if st == 200:
                self.static["/"] = (ct or "text/html", home)
                for a in _ASSET.findall(home.decode("utf-8", "replace"))[:MAX_ASSETS]:
                    s2, c2, b2 = self._get(a)
                    if s2 == 200:
                        self.static[a] = (c2, b2)
            paths = self.spec.get("paths", {})
            for p, ops in paths.items():
                if "get" not in ops or "{" in p or (self.decoy_prefix and p.startswith(self.decoy_prefix)):
                    continue
                st, ct, body = self._get(p)
                if st == 401 and 401 not in self.errors:
                    self.errors[401] = body
                if st != 200 or "json" not in ct:
                    continue
                data = json.loads(body)
                self.public[p] = data
                self._seen_lists(p, data)
                key, recs = _records(data)
                self.by_id.update({str(r["id"]): r for r in recs if r.get("id")})
                if recs:
                    self.lists[p], self.shapes[p + "/{id}"] = key, Shape(recs)
                    self._learn_item(p, recs[0], paths)
            # private collections follow the app's usual envelope: majority of what was seen, ties -> named
            votes = ["named" if k == p.rstrip("/").rsplit("/", 1)[-1] else "items" if k == "items" else "bare" if k == "" else "named"
                     for p, k in self.envelopes.items()]
            if votes:
                self.style = max(("named", "items", "bare"), key=votes.count)
            st, _, body = self._get(f"/api/undertow-probe-{secrets.token_hex(4)}")
            self.errors[404] = body if st == 404 else b'{"error": "not found"}'
            self.ready = True
        except Exception:  # noqa: BLE001 - any failure: keep what was learned, or the generic world
            self.ready = bool(self.spec)
        self.latency = min(1.5, statistics.median(self._lat)) if self._lat else 0.2
        self.errors.setdefault(404, b'{"error": "not found"}')
        print(json.dumps({"event": "mirror_learned", "origin": self.origin, "ready": self.ready,
                          "routes": len(self.spec.get("paths", {})), "public": sorted(self.public)[:20],
                          "shapes": sorted(self.shapes)[:20], "static": len(self.static),
                          "latency_ms": int(self.latency * 1000)}), flush=True)
        return self

    def _learn_item(self, coll: str, rec: dict, paths: dict):
        rid = rec.get("id")
        if not rid or f"{coll}/{{id}}" not in paths:
            return
        st, ct, body = self._get(f"{coll}/{rid}")
        if st == 200 and "json" in ct:
            one = json.loads(body)
            if isinstance(one, dict):
                self.shapes[coll + "/{id}"] = Shape([one, rec])
        for child in [p for p in paths if p.startswith(f"{coll}/{{id}}/") and "get" in paths[p]]:
            st, ct, body = self._get(child.replace("{id}", str(rid)))
            if st == 200 and "json" in ct:
                self._seen_lists(child, json.loads(body))
                k, recs = _records(json.loads(body))
                if recs:
                    self.lists[child], self.shapes[child + "/{id}"] = k, Shape(recs)

    def _seen_lists(self, path: str, data):
        """The envelope a collection uses, even when its list is empty ({"reviews": []} still says 'named')."""
        if isinstance(data, list):
            self.envelopes[path] = ""
        elif isinstance(data, dict):
            k = next((k for k, v in data.items() if isinstance(v, list)), None)
            if k is not None:
                self.envelopes[path] = k

    def stale(self) -> bool:
        return time.time() - self.learned_at > REFRESH

    # ---------- matching ----------

    def match(self, path: str) -> tuple[str, dict] | None:
        """The spec template for a concrete path, with its {params}."""
        segs = [s for s in path.split("/") if s]
        for tpl in self.spec.get("paths", {}):
            ts = [s for s in tpl.split("/") if s]
            if len(ts) != len(segs):
                continue
            params = {}
            for a, b in zip(ts, segs):
                if a.startswith("{"):
                    params[a.strip("{}")] = b
                elif a != b:
                    break
            else:
                return tpl, params
        return None

    def wrap(self, tpl: str, records: list, total: int, page: int) -> dict | list:
        key = self.lists.get(tpl)
        if key is None:
            key = {"items": "items", "bare": ""}.get(self.style, tpl.rstrip("/").rsplit("/", 1)[-1])
        if key == "":
            return records
        out = {key: records}
        pub = self.public.get(tpl)
        if isinstance(pub, dict):     # keep the real pagination fields
            for k in ("page", "pages", "total", "count", "per_page"):
                if k in pub:
                    out[k] = page if k == "page" else total if k in ("total", "count") else pub[k] if k == "per_page" \
                        else max(page, total // max(1, len(records) or 1))
        return out


def _records(data) -> tuple[str, list]:
    """(list key, records) for a collection response: {"orders": [...]} / {"items": [...]} / [...]."""
    if isinstance(data, list):
        return "", [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return k, v
    return "", []
