"""ASGI middleware: score each actor live, then slow it and starve it of feedback.

Responses are chosen against ARTEX's own control loop (docs/using-its-design-against-it.md):
  * 429 + Retry-After 9  -> its egress governor pauses the WHOLE host and re-queues
                            (9s <= MaxDelay of every built-in noise profile).
  * uniform errors       -> no 400/422 detail to self-correct from; its adversarial
                            gate files blocked mechanisms as "hardening", not findings.
  * stalls               -> read as an environmental block; its worker prompt says stop
                            after the first one and wait on a human operator.
  * decoys               -> plausible empty pages that burn steps and wall-clock budget.

Counter-moves for suspects (score >= watch, or an operator challenge):
  * it reads the API map -> it gets routes only it was shown; walking one is certain,
                            from any IP, which also links IP rotation back to it
  * it logs in           -> it gets a honey session token; replaying it is certain
  * it is confirmed     -> the padded cell (aa_ai/cell.py): a fake copy of the app that
                            seems to work, until CloudFront routes it to the sandbox origin
Every move is printed as an "undertow_move" line for the scorer and dashboard.

Safe for real users:
  * the login budget is spent only by FAILED auth responses, so an office of people
    behind one NAT logging in successfully never trips it
  * allow_cidrs and unblock() bypass everything
  * fails open: a shield error before the app runs passes the request through; an
    error after the app started answering is re-raised, never answered twice
  * idle actors are swept, memory is capped at max_actors
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import random
import secrets
import time
from collections import defaultdict, deque

from . import cell as cellmod
from . import detectors, moves
from .decoys import DecoySet
from .events import Event, decoy_tag, honey_token
from .scoring import BLOCK, TARPIT, WATCH, actor_key, combine, evaluate

MAP_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/robots.txt")
ESCALATIONS = {"ignores_retry_after": "ignored_retry_after", "keeps_hammering": "hammering"}

log = logging.getLogger("aa_ai.shield")

RETRY_AFTER = "9"
GENERIC_ERROR = json.dumps({"error": "request could not be processed"}).encode()
AUTH_FAILURE = {400, 401, 403, 422, 429}


class Shield:
    def __init__(self, app, decoys: DecoySet | None = None, *, window=6 * 3600,
                 max_events=600, max_actors=50_000, rescore_every=5,
                 auth_failures_per_min=6, auth_failure_burst=10, tarpit_max=15.0, max_held=50,
                 allow_cidrs=(), origin_secret: str | None = None,
                 origin_header="x-origin-verify", origin_exempt_paths=("/health",),
                 proxy_hops=1, cell: "cellmod.Cell | None" = None):
        self.app = app
        self.cell = cell
        self.decoys = (decoys or DecoySet()).register()
        self.window, self.rescore_every, self.tarpit_max = window, rescore_every, tarpit_max
        # a tarpit must cost them more than it costs us: never hold more than max_held
        # requests at once (in Lambda, also keep tarpit_max small: each held request is an instance)
        self.max_held, self._held = max_held, 0
        self.max_events, self.max_actors = max_events, max_actors
        self.history: dict[str, deque[Event]] = {}
        self.score: dict[str, float] = defaultdict(float)
        self.last_seen: dict[str, float] = {}
        self.auth_rate, self.auth_burst = auth_failures_per_min / 60, auth_failure_burst
        self.bucket: dict[str, list[float]] = {}
        self.allow = [ipaddress.ip_network(c, strict=False) for c in allow_cidrs]
        self.temp_allow: dict[str, float] = {}          # ip -> expiry
        self.origin_secret, self.origin_header = origin_secret, origin_header
        self.origin_exempt = tuple(origin_exempt_paths)
        self.proxy_hops = proxy_hops
        self._requests = 0
        self.challenged: set[str] = set()
        self.masked: set[str] = set()
        self.honey_seen: set[str] = set()
        self.escalated: dict[str, set[str]] = defaultdict(set)

    # ---------- operator controls ----------

    def unblock(self, ip: str, ttl=24 * 3600):
        """Clear an IP's actors and exempt it for ttl seconds."""
        self.temp_allow[ip] = time.time() + ttl
        net = actor_key(Event(0, ip, "", "", 0)).split("|")[0]
        for k in [k for k in self.score if k.startswith(net + "|")]:
            self.score.pop(k, None)
            self.bucket.pop(k, None)
            self.history.pop(k, None)
        log.warning("unblocked %s for %ss", ip, ttl)

    def _allowed(self, ip: str, now: float) -> bool:
        exp = self.temp_allow.get(ip)
        if exp and exp > now:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.allow)

    # ---------- internals ----------

    def _waf_says(self, hdrs, name: str) -> bool:
        """A header WAF inserted (x-amzn-waf-undertow-<name>). WAF passes a client's own copy
        through untouched, so the value must be the origin secret, which only WAF and
        CloudFront know; a client sending the header itself proves nothing."""
        v = hdrs.get(f"x-amzn-waf-undertow-{name}", "")
        return bool(self.origin_secret and v) and any(
            hmac.compare_digest(part.strip(), self.origin_secret) for part in v.split(","))

    def _client_ip(self, scope, hdrs, verified: bool) -> str:
        if verified and hdrs.get("cloudfront-viewer-address"):
            return hdrs["cloudfront-viewer-address"].rsplit(":", 1)[0].strip("[]")
        xff = [p.strip() for p in hdrs.get("x-forwarded-for", "").split(",") if p.strip()]
        if xff and self.proxy_hops:
            return xff[-min(self.proxy_hops, len(xff))]
        return (scope.get("client") or ("", 0))[0]

    def _auth_has_budget(self, key: str, now: float) -> bool:
        tokens, last = self.bucket.get(key, [self.auth_burst, now])
        tokens = min(self.auth_burst, tokens + (now - last) * self.auth_rate)
        self.bucket[key] = [tokens, now]
        return tokens >= 1

    def _spend_auth(self, key: str):
        if key in self.bucket:
            self.bucket[key][0] -= 1

    def _record(self, key: str, ev: Event):
        h = self.history.get(key)
        if h is None:
            h = self.history[key] = deque(maxlen=self.max_events)
        h.append(ev)
        self.last_seen[key] = ev.ts

    def _rescore(self, key: str, now: float):
        evs = self.history[key]
        while evs and evs[0].ts < now - self.window:
            evs.popleft()
        sigs = evaluate(list(evs))
        self.score[key] = max(self.score[key], combine(sigs))
        for s in sigs:
            move = ESCALATIONS.get(s.name)
            if move and move not in self.escalated[key]:
                self.escalated[key].add(move)
                ip = evs[-1].src_ip if evs else ""
                moves.emit(move, key, ip, s.detail, side="them")
                moves.emit(move, key, ip, f"score now {self.score[key]:.2f}")

    def _sweep(self, now: float):
        idle = [k for k, t in self.last_seen.items() if t < now - self.window]
        if len(self.last_seen) - len(idle) > self.max_actors:
            live = sorted((t, k) for k, t in self.last_seen.items() if t >= now - self.window)
            idle += [k for _, k in live[: len(live) - self.max_actors]]
        for k in idle:
            for d in (self.history, self.score, self.last_seen, self.bucket, self.escalated):
                d.pop(k, None)
            self.challenged.discard(k)
            self.masked.discard(k)
            self.honey_seen.discard(k)
        for ip in [ip for ip, exp in self.temp_allow.items() if exp <= now]:
            del self.temp_allow[ip]

    # ---------- ASGI ----------

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False

        def mark_started():
            nonlocal started
            started = True

        try:
            return await self._handle(scope, receive, send, mark_started)
        except Exception:  # noqa: BLE001
            if started:
                raise
            log.exception("shield error before the app ran, passing through")
            return await self.app(scope, receive, send)

    async def _handle(self, scope, receive, send, mark_started):
        now = time.time()
        self._requests += 1
        if self._requests % 1000 == 0:
            self._sweep(now)
        hdrs = {k.decode().lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}

        verified = False
        if self.origin_secret:
            verified = hmac.compare_digest(hdrs.get(self.origin_header, ""), self.origin_secret)
            if not verified and not scope["path"].startswith(self.origin_exempt):
                return await _respond(send, 403, GENERIC_ERROR)

        query = scope.get("query_string", b"").decode("latin-1")
        ev = Event(
            ts=now, src_ip=self._client_ip(scope, hdrs, verified),
            method=scope["method"], path=scope["path"], status=0,
            user_agent=hdrs.get("user-agent", ""), host=hdrs.get("host", ""),
            payload=query,
            tls_fp=hdrs.get("cloudfront-viewer-ja4-fingerprint", "") if verified else "",
            extra={"honey": honey_token(" ".join([query, hdrs.get("authorization", ""), hdrs.get("cookie", "")]))},
        )
        if verified and self._waf_says(hdrs, "allow"):
            # the edge allow list (AllowCidrs or an operator unblock) outranks what Shield remembers
            if ev.src_ip not in self.temp_allow:
                self.unblock(ev.src_ip, ttl=300)
            self.temp_allow[ev.src_ip] = now + 300
        if self._allowed(ev.src_ip, now):
            mark_started()
            return await self.app(scope, receive, send)
        key = actor_key(ev)
        me = moves.tag(key)
        # WAF inserts x-amzn-waf-undertow-challenge for IPs an operator challenged
        challenged = verified and self._waf_says(hdrs, "challenge")
        if challenged and key not in self.challenged:
            self.challenged.add(key)
            moves.emit("challenged", key, ev.src_ip, "deception on, no delay")

        # --- certain moves: they replay something only we handed out ---
        if ev.extra["honey"]:
            self.score[key] = 1.0
            self._record(key, ev)
            if key not in self.honey_seen:   # once per agent: every later request carries the same token
                self.honey_seen.add(key)
                moves.emit("used_honey", key, ev.src_ip, f"{ev.method} {ev.path}", side="them")
                if ev.extra["honey"] != me:
                    moves.emit("linked_rotation", key, ev.src_ip, f"honey token issued to tag {ev.extra['honey']}")
            if self.cell:
                return await self._cell(receive, send, ev, key, query, hdrs)
            return await self._decoy(send, ev.path, query)

        blob = f"{ev.path} {query}"
        replayed = [m for m in detectors._ID_RE.findall(blob) if m in detectors.HONEY_IDS] \
            or cellmod.find_ids(blob, [self.decoys.prefix])
        if replayed:
            self.score[key] = 1.0
            self._record(key, ev)
            if key not in self.honey_seen:
                self.honey_seen.add(key)
                moves.emit("used_honey_record", key, ev.src_ip, f"{ev.method} {ev.path}", side="them")
            if self.cell:
                return await self._cell(receive, send, ev, key, query, hdrs)
            return await _respond(send, 404, GENERIC_ERROR)   # looks like an ordinary miss

        if ev.path.startswith(self.decoys.prefix):
            self.score[key] = 1.0
            self._record(key, ev)
            owner = decoy_tag(ev.path)
            moves.emit("followed_personal_decoy" if owner else "read_decoy", key, ev.src_ip, ev.path, side="them")
            if owner and owner != me:
                moves.emit("linked_rotation", key, ev.src_ip, f"route was shown to tag {owner}")
            return await self._decoy(send, ev.path, query)

        if ev.is_auth and not self._auth_has_budget(key, now):
            ev.status = 429
            self._record(key, ev)
            return await _respond(send, 429, GENERIC_ERROR, [(b"retry-after", RETRY_AFTER.encode())])

        s = self.score[key]
        playing = challenged or s >= WATCH
        if s >= BLOCK and self.cell:
            self._record(key, ev)
            if len(self.history[key]) % self.rescore_every == 0:
                self._rescore(key, now)
            return await self._cell(receive, send, ev, key, query, hdrs)
        if s >= BLOCK:
            ev.status = 429 if random.random() < 0.5 else 503
            self._record(key, ev)
            if len(self.history[key]) % self.rescore_every == 0:
                self._rescore(key, now)                 # persistence still escalates and is recorded
            if ev.status == 429:
                return await _respond(send, 429, GENERIC_ERROR, [(b"retry-after", RETRY_AFTER.encode())])
            if not await self._hold(self.tarpit_max):   # looks like a filtered path
                return await _respond(send, 429, GENERIC_ERROR, [(b"retry-after", RETRY_AFTER.encode())])
            return await _respond(send, 503, GENERIC_ERROR)
        if s >= TARPIT:
            if not await self._hold(2 ** (s * 10 - 3) + random.uniform(0, 1.5)):
                ev.status = 429
                self._record(key, ev)
                return await _respond(send, 429, GENERIC_ERROR, [(b"retry-after", RETRY_AFTER.encode())])

        # --- counter-move: a suspect logging in gets a honey session instead ---
        if ev.is_auth and ev.method == "POST" and (challenged or s >= TARPIT):
            moves.emit("login_attempt", key, ev.src_ip, ev.path, side="them")
            moves.emit("login_attempt", key, ev.src_ip, "honey token issued")
            ev.status = 200
            self._record(key, ev)
            body = json.dumps({"token": f"hny_{me}_{secrets.token_hex(6)}", "token_type": "Bearer",
                               "expires_in": 3600}).encode()
            return await _respond(send, 200, body)

        personalize = playing and ev.method == "GET" and ev.path in MAP_PATHS
        captured = {"body": b""}

        async def send_wrapper(msg):
            if msg["type"] == "http.response.start":
                captured["status"] = msg["status"]
                captured["headers"] = msg.get("headers", [])
                if personalize and msg["status"] == 200:
                    captured["hold"] = True
                    return
                if s >= WATCH and 400 <= msg["status"] < 500:
                    captured["mask"] = True
                    msg = {**msg, "status": 400 if msg["status"] in (400, 422) else msg["status"],
                           "headers": [(b"content-type", b"application/json"),
                                       (b"content-length", str(len(GENERIC_ERROR)).encode())]}
            elif msg["type"] == "http.response.body":
                if captured.get("hold"):
                    captured["body"] += msg.get("body", b"")
                    if msg.get("more_body"):
                        return
                    body = self._personal_map(ev.path, captured["body"], me)
                    moves.emit("read_map", key, ev.src_ip, ev.path, side="them")
                    moves.emit("read_map", key, ev.src_ip, f"tag {me}")
                    hdr = [(k, v) for k, v in captured["headers"] if k.lower() != b"content-length"]
                    await send({"type": "http.response.start", "status": 200,
                                "headers": hdr + [(b"content-length", str(len(body)).encode())]})
                    await send({"type": "http.response.body", "body": body})
                    return
                if captured.get("mask"):
                    if msg.get("more_body"):
                        return
                    msg = {"type": "http.response.body", "body": GENERIC_ERROR}
            await send(msg)

        mark_started()
        await self.app(scope, receive, send_wrapper)
        ev.status = captured.get("status", 0)
        if captured.get("mask") and key not in self.masked:
            self.masked.add(key)
            moves.emit("probe_errors", key, ev.src_ip, f"{ev.status} on {ev.path}")
        if ev.is_auth and ev.status in AUTH_FAILURE:
            self._spend_auth(key)
        self._record(key, ev)
        if len(self.history[key]) % self.rescore_every == 0:
            self._rescore(key, now)

    async def _hold(self, seconds: float) -> bool:
        """Delay, bounded by tarpit_max and by how many requests we already hold.
        False = no room: answer fast instead of spending our own capacity."""
        if self._held >= self.max_held:
            return False
        self._held += 1
        try:
            await asyncio.sleep(max(0.0, min(self.tarpit_max, seconds)))
        finally:
            self._held -= 1
        return True

    async def _cell(self, receive, send, ev: Event, key: str, query: str, hdrs: dict):
        """Answer from the padded cell. The real app never sees the request."""
        body, more = b"", ev.method in ("POST", "PUT", "PATCH")
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
        status, headers, payload = self.cell.respond(ev.method, ev.path, query, body, hdrs, key, ev.src_ip)
        ev.status = status               # the event is already in the actor's history
        await self._hold(random.uniform(0.4, 1.6))     # a slow, but working, app
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _decoy(self, send, path: str, query: str = ""):
        status, body = self.decoys.decoy_response(path, query)
        await self._hold(random.uniform(3, 8))
        return await _respond(send, status, json.dumps(body).encode())

    def _personal_map(self, path: str, body: bytes, me: str) -> bytes:
        """Add routes only this actor is shown. Walking one later is certain, from any IP."""
        mine = [f"{self.decoys.prefix}/t/{me}/export", f"{self.decoys.prefix}/t/{me}/admin/users"]
        if path == "/robots.txt":
            return body.rstrip(b"\n") + f"\nDisallow: {self.decoys.prefix}/t/{me}/\n".encode()
        try:
            spec = json.loads(body)
            op = {"summary": "Internal", "security": [{"bearer": []}], "responses": {"200": {"description": "OK"}}}
            spec.setdefault("paths", {}).update({p: {"get": op} for p in mine})
            return json.dumps(spec).encode()
        except ValueError:
            return body


async def _respond(send, status, body, extra=()):
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()), *extra]})
    await send({"type": "http.response.body", "body": body})
