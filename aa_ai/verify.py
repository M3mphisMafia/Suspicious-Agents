"""Verified agents: prove WHO a client is, so behavior that merely looks automated is not punished.

Three proofs, all fail closed (any error = not verified):
  key      an integration key we issued (only its SHA-256 is stored)
  signed   Web Bot Auth: an HTTP Message Signature (RFC 9421, Ed25519) whose key is in a
           directory the operator trusts
  crawler  a search crawler whose IP reverse-resolves to its operator's domain and back

Verified proves identity, not innocence: style detectors skip verified requests, intent
detectors (decoys, injection, ID walking, credential hops) still see them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import time
import urllib.request

# ---------- Ed25519 verify (RFC 8032 section 6, stdlib only) ----------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _eq(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _L
    return _eq(_mul(s, _G), _add(R, _mul(h, A)))


# ---------- Web Bot Auth (HTTP Message Signatures) ----------

def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an OKP key: the keyid Web Bot Auth signs with."""
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"))
    return base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).decode().rstrip("=")


_MEMBER = re.compile(r'([a-z0-9_*.-]+)=(\([^)]*\)(?:;[^,]*)?)', re.I)
_PARAM = re.compile(r';([a-z0-9_*.-]+)=("(?:[^"\\]|\\.)*"|-?\d+)', re.I)


def parse_signature_input(value: str) -> dict:
    """label -> {components, params, raw}. raw is the exact @signature-params value."""
    out = {}
    for label, raw in _MEMBER.findall(value or ""):
        inner = raw[1:raw.index(")")]
        comps = re.findall(r'"([^"]+)"', inner)
        params = {k: (v[1:-1] if v.startswith('"') else int(v)) for k, v in _PARAM.findall(raw[raw.index(")"):])}
        out[label] = {"components": comps, "params": params, "raw": raw.strip()}
    return out


def _sig_bytes(value: str, label: str) -> bytes | None:
    m = re.search(rf'(?:^|,)\s*{re.escape(label)}=:([A-Za-z0-9+/=]+):', value or "")
    return base64.b64decode(m.group(1)) if m else None


def _agent_url(value: str, label: str) -> str:
    """Signature-Agent as an sf-string ("https://...") or a dictionary member (label="https://...")."""
    v = (value or "").strip()
    m = re.search(rf'(?:^|,)\s*{re.escape(label)}="([^"]+)"', v)
    if m:
        return m.group(1)
    return v[1:-1] if v.startswith('"') and v.endswith('"') else v


def signature_base(components: list[str], headers: dict, raw_params: str) -> bytes | None:
    lines = []
    for c in components:
        if c == "@authority":
            v = headers.get("host", "").lower()
        elif c.startswith("@"):
            return None                      # only @authority is needed for Web Bot Auth
        else:
            v = headers.get(c.lower())
        if not v:
            return None
        lines.append(f'"{c}": {v.strip()}')
    lines.append(f'"@signature-params": {raw_params}')
    return "\n".join(lines).encode()


_DIR_CACHE: dict[str, tuple[float, dict]] = {}
DIR_PATH = "/.well-known/http-message-signatures-directory"


def fetch_directory(origin: str, timeout: float = 3.0) -> dict:
    """origin -> {keyid: public key bytes}. Cached an hour per container; capped at 64 KB."""
    hit = _DIR_CACHE.get(origin)
    if hit and hit[0] > time.time():
        return hit[1]
    req = urllib.request.Request(origin.rstrip("/") + DIR_PATH, headers={"accept": "application/http-message-signatures-directory+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - origin is operator-trusted, https only
        doc = json.loads(r.read(65536))
    keys = {}
    for k in doc.get("keys", []):
        if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("x"):
            keys[jwk_thumbprint(k)] = _b64u(k["x"])
    _DIR_CACHE[origin] = (time.time() + 3600, keys)
    return keys


def _origin(url: str) -> str:
    m = re.match(r"^(https://[a-z0-9.-]+(?::\d+)?)(/|$)", (url or "").lower())
    return m.group(1) if m else ""


def verify_web_bot_auth(headers: dict, trusted: list[str], now: float | None = None,
                        fetch=fetch_directory) -> str:
    """The trusted agent origin that signed this request, or ''."""
    try:
        now = now or time.time()
        for label, m in parse_signature_input(headers.get("signature-input", "")).items():
            p = m["params"]
            if p.get("tag") != "web-bot-auth" or p.get("alg", "ed25519") != "ed25519":
                continue
            created, expires = int(p.get("created", 0)), int(p.get("expires", 0))
            if not (created - 60 <= now <= expires + 60) or expires - created > 86400:
                continue
            origin = _origin(_agent_url(headers.get("signature-agent", ""), label))
            if not origin or origin not in {_origin(t) for t in trusted}:
                continue
            sig = _sig_bytes(headers.get("signature", ""), label)
            key = fetch(origin).get(p.get("keyid", ""))
            base = signature_base(m["components"], headers, m["raw"])
            if sig and key and base and ed25519_verify(key, base, sig):
                return origin.removeprefix("https://")
    except Exception:  # noqa: BLE001 - fail closed
        return ""
    return ""


# ---------- search crawlers (reverse + forward DNS) ----------

CRAWLERS = (
    (re.compile(r"googlebot|google-inspectiontool|googleother|adsbot-google|mediapartners-google", re.I),
     (".googlebot.com", ".google.com", ".googleusercontent.com")),
    (re.compile(r"bingbot|msnbot|adidxbot|bingpreview", re.I), (".search.msn.com",)),
    (re.compile(r"applebot", re.I), (".applebot.apple.com",)),
    (re.compile(r"yandex(bot|images|mobilebot)", re.I), (".yandex.ru", ".yandex.net", ".yandex.com")),
)


def claimed_crawler(ua: str):
    return next((doms for rx, doms in CRAWLERS if rx.search(ua or "")), None)


def _resolve(ip: str) -> tuple[str, list[str]]:
    host = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    return host, socket.gethostbyname_ex(host)[2]


def verify_crawler(ip: str, ua: str, resolve=_resolve) -> str | None:
    """The crawler's domain if ip reverse-resolves into it and that name resolves back to ip.
    '' = checked and not theirs; None = could not check (transient), so never cached as fake."""
    doms = claimed_crawler(ua)
    if not doms:
        return ""
    try:
        host, addrs = resolve(ip)
    except (socket.herror, LookupError):    # no PTR / no such name: not their IP
        return ""
    except Exception:  # noqa: BLE001
        return None
    if ip in addrs and any(host.endswith(d) for d in doms):
        return next(d for d in doms if host.endswith(d)).lstrip(".")
    return ""


# ---------- integration keys ----------

KEY_PREFIX = "uk_"


def key_hash(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()


def bearer_of(authorization: str) -> str:
    m = re.match(r"^\s*bearer\s+(\S+)", authorization or "", re.I)
    return m.group(1) if m else ""


class Verifier:
    """Per-batch verifier: loads integration key hashes once, caches DNS results in the table.
    rdns_budget bounds new DNS lookups per batch so one batch can't stall on resolvers."""

    def __init__(self, table, policy: dict, now: float | None = None, resolve=_resolve,
                 fetch=fetch_directory, rdns_budget: int = 5):
        self.table, self.now = table, now or time.time()
        v = policy.get("verified") or {}
        self.crawlers = bool(v.get("crawlers", True))
        self.trusted = list(v.get("directories", []))
        self.resolve, self.fetch, self.budget = resolve, fetch, rdns_budget
        self.keys = self._load_keys()
        self._rdns: dict[str, str] = {}

    def _load_keys(self) -> dict:
        out, kw = {}, {"KeyConditionExpression": "pk = :f", "ExpressionAttributeValues": {":f": "IKEY"}}
        try:
            while True:
                r = self.table.query(**kw)
                for i in r.get("Items", []):
                    if not i.get("revoked") and i.get("kind", "client") == "client":
                        out[i["sk"]] = i.get("name", "integration")
                if "LastEvaluatedKey" not in r:
                    return out
                kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
        except Exception:  # noqa: BLE001 - no keys loaded = nothing verified by key
            return {}

    def _crawler(self, ip: str, ua: str) -> str | None:
        if ip in self._rdns:
            return self._rdns[ip]
        try:
            item = self.table.get_item(Key={"pk": "RDNS", "sk": ip}).get("Item")
        except Exception:  # noqa: BLE001
            item = None
        if item and int(item.get("exp", 0)) > self.now:
            self._rdns[ip] = item.get("domain", "")
            return self._rdns[ip]
        if self.budget <= 0:
            return None
        self.budget -= 1
        dom = verify_crawler(ip, ua, self.resolve)
        if dom is None:
            return None
        self._rdns[ip] = dom
        try:
            self.table.put_item(Item={"pk": "RDNS", "sk": ip, "domain": dom,
                                      "exp": int(self.now + (86400 if dom else 6 * 3600))})
        except Exception:  # noqa: BLE001
            pass
        return dom

    def check(self, e) -> str:
        """'key:<name>', 'signed:<agent>', 'crawler:<domain>' or ''. Sets e.extra['fake_crawler']."""
        b = e.extra.get("bearer", "")
        if b and b in self.keys:
            return f"key:{self.keys[b]}"
        sig = e.extra.get("sig")
        if sig and self.trusted:
            agent = verify_web_bot_auth(sig, self.trusted, self.now, self.fetch)
            if agent:
                return f"signed:{agent}"
        if self.crawlers and claimed_crawler(e.user_agent):
            dom = self._crawler(e.src_ip, e.user_agent)
            if dom:
                return f"crawler:{dom}"
            if dom == "":
                e.extra["fake_crawler"] = True
        return ""
