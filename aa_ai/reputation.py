"""IP reputation enrichment: WHERE a client comes from, as a SECONDARY signal.

Reputation never gates. Agents rotate IPs and ride residential proxies, so a bad
IP is corroboration, not proof. The reputation detector is STYLE (capped below
tarpit in scoring.combine), and on verified requests it does not run at all. It
sharpens a verdict once a real intent signal is present and slows nothing alone.

Categories (strongest first):
  malicious   a threat-intel feed calls this IP a known attacker/abuser
  tor_exit    a current Tor exit node
  datacenter  a cloud/hosting range (EC2, GCP, VPS) - not where shoppers browse
  scanner     a known internet-wide scanner (Shodan/Censys/GreyNoise benign)

Every provider fails OPEN: no data, a timeout, a missing key -> no category, never
a false accusation. Results are cached per IP in the table (REP rows) and per
container in RAM. Static ranges (DATACENTER_CIDRS) and a cached datacenter/Tor
list need no per-IP lookup; the keyed feeds are bounded per batch.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request

CATEGORIES = ("malicious", "tor_exit", "datacenter", "scanner")
REP_TTL_FEED = 6 * 3600          # keyed-feed verdicts for one IP
REP_TTL_NONE = 3 * 3600          # "nothing known" caches shorter: reputation changes
_LIST_TTL = 3600.0               # datacenter/Tor lists, per container

# container-lifetime caches, refreshed on expiry (fail-open keeps the last good copy)
_RANGES: dict = {"exp": 0.0, "v4": {}, "v6": [], "src": ""}
_TOR: dict = {"exp": 0.0, "set": frozenset(), "src": ""}


def _fetch(url: str, headers: dict | None = None, timeout: float = 4.0, cap: int = 8 << 20) -> bytes:
    """GET a public list/feed. s3://bucket/key reads through boto3 (works via a VPC
    gateway endpoint, no NAT). Raises on any failure; callers fail open."""
    if url.startswith("s3://"):
        import boto3
        bucket, _, key = url[5:].partition("/")
        return boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read(cap)
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - operator-configured feeds
        return r.read(cap)


def _nets(raw) -> list:
    out = []
    for c in raw:
        try:
            out.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            pass
    return out


def _index(nets: list) -> tuple[dict, list]:
    """v4 nets bucketed by first octet for fast membership; v6 kept flat."""
    v4: dict[int, list] = {}
    v6: list = []
    for n in nets:
        if n.version == 6:
            v6.append(n)
            continue
        lo, hi = int(n.network_address) >> 24, int(n.broadcast_address) >> 24
        for octet in range(lo, hi + 1):
            v4.setdefault(octet, []).append(n)
    return v4, v6


def _parse_ranges(body: bytes) -> list:
    """AWS ip-ranges.json, a bare JSON list of CIDRs, or newline-delimited CIDRs."""
    text = body.decode("utf-8", "replace").strip()
    if text[:1] in "{[":
        doc = json.loads(text)
        if isinstance(doc, dict):
            cidrs = [p.get("ip_prefix") for p in doc.get("prefixes", [])]
            cidrs += [p.get("ipv6_prefix") for p in doc.get("ipv6_prefixes", [])]
            return _nets([c for c in cidrs if c])
        return _nets(doc)
    return _nets(text.splitlines())


def _ranges(env, fetch) -> tuple[dict, list]:
    """Datacenter/cloud ranges: env CIDRs always, plus a fetched ranges doc when a URL
    is set and reachable. Cached per container; a fetch failure keeps the last copy."""
    url = env.get("DATACENTER_RANGES_URL", "")
    static = [c for c in env.get("DATACENTER_CIDRS", "").split(",") if c.strip()]
    now = time.time()
    if _RANGES["exp"] > now and _RANGES["src"] == url + "|" + ",".join(static):
        return _RANGES["v4"], _RANGES["v6"]
    nets = _nets(static)
    if url:
        try:
            nets += _parse_ranges(fetch(url))
        except Exception:  # noqa: BLE001 - fail open, keep env ranges
            if _RANGES["v4"] or _RANGES["v6"]:
                return _RANGES["v4"], _RANGES["v6"]
    v4, v6 = _index(nets)
    _RANGES.update(exp=now + _LIST_TTL, v4=v4, v6=v6, src=url + "|" + ",".join(static))
    return v4, v6


def _tor(env, fetch) -> frozenset:
    url = env.get("TOR_EXIT_URL", "")
    if not url:
        return frozenset()
    now = time.time()
    if _TOR["exp"] > now and _TOR["src"] == url:
        return _TOR["set"]
    try:
        body = fetch(url).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return _TOR["set"] if _TOR["src"] == url else frozenset()
    ips = {ln.strip() for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")}
    _TOR.update(exp=now + _LIST_TTL, set=frozenset(ips), src=url)
    return _TOR["set"]


class Reputation:
    """Per-batch enricher. check(e) tags e.extra['reputation'] with a comma-joined
    category string ('' when nothing is known) and returns it."""

    def __init__(self, policy: dict, now: float | None = None, table=None,
                 env=None, fetch=_fetch, budget: int = 20):
        rep = policy.get("reputation") or {}
        self.enabled = bool(rep.get("enabled", True))
        feeds = rep.get("feeds") or {}
        # datacenter + tor default on (no secret); keyed feeds default off (need a key)
        self.feeds = {n: bool(feeds.get(n, n in ("datacenter", "tor")))
                      for n in ("datacenter", "tor", "greynoise", "abuseipdb")}
        self.table = table
        self.now = now or time.time()
        self.env = env if env is not None else os.environ
        self.fetch = fetch
        self.budget = budget
        self._mem: dict[str, str] = {}

    # ---- static / cached lists (no budget) ----

    def _in_datacenter(self, addr) -> bool:
        v4, v6 = _ranges(self.env, self.fetch)
        if addr.version == 6:
            return any(addr in n for n in v6)
        return any(addr in n for n in v4.get(int(addr) >> 24, ()))

    def _is_tor(self, ip: str) -> bool:
        return ip in _tor(self.env, self.fetch)

    # ---- keyed feeds (bounded, cached in the table) ----

    def _cached(self, ip: str):
        if self.table is None:
            return None
        try:
            it = self.table.get_item(Key={"pk": "REP", "sk": ip}).get("Item")
        except Exception:  # noqa: BLE001
            return None
        if it and int(it.get("exp", 0)) > self.now:
            return {c for c in str(it.get("cats", "")).split(",") if c}
        return None

    def _cache(self, ip: str, cats: set):
        if self.table is None:
            return
        try:
            self.table.put_item(Item={"pk": "REP", "sk": ip, "cats": ",".join(sorted(cats)),
                                      "exp": int(self.now + (REP_TTL_FEED if cats else REP_TTL_NONE))})
        except Exception:  # noqa: BLE001
            pass

    def _greynoise(self, ip: str) -> set:
        key = self.env.get("GREYNOISE_KEY", "")
        if not key:
            return set()
        try:
            doc = json.loads(self.fetch(f"https://api.greynoise.io/v3/community/{ip}",
                                        {"key": key, "accept": "application/json"}, 4.0))
        except Exception:  # noqa: BLE001
            return set()
        if doc.get("classification") == "malicious":
            return {"malicious"}
        if doc.get("noise") or doc.get("classification") == "benign":
            return {"scanner"}
        return set()

    def _abuseipdb(self, ip: str) -> set:
        key = self.env.get("ABUSEIPDB_KEY", "")
        if not key:
            return set()
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            doc = json.loads(self.fetch(url, {"Key": key, "Accept": "application/json"}, 4.0))
            score = int(doc.get("data", {}).get("abuseConfidenceScore", 0))
        except Exception:  # noqa: BLE001
            return set()
        return {"malicious"} if score >= 50 else set()

    def _feeds(self, ip: str) -> set:
        cats: set = set()
        if self.feeds["greynoise"]:
            cats |= self._greynoise(ip)
        if self.feeds["abuseipdb"]:
            cats |= self._abuseipdb(ip)
        return cats

    # ---- public ----

    def _cats(self, ip: str) -> str:
        if ip in self._mem:
            return self._mem[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            self._mem[ip] = ""
            return ""
        if not addr.is_global:          # RFC1918, loopback, link-local: never reputation-scored
            self._mem[ip] = ""
            return ""
        cats: set = set()
        if self.feeds["datacenter"] and self._in_datacenter(addr):
            cats.add("datacenter")
        if self.feeds["tor"] and self._is_tor(ip):
            cats.add("tor_exit")
        if self.feeds["greynoise"] or self.feeds["abuseipdb"]:
            cached = self._cached(ip)
            if cached is not None:
                cats |= cached
            elif self.budget > 0:
                self.budget -= 1
                live = self._feeds(ip)
                self._cache(ip, live)
                cats |= live
        out = ",".join(sorted(cats))
        self._mem[ip] = out
        return out

    def check(self, e) -> str:
        if not self.enabled or not getattr(e, "src_ip", ""):
            return ""
        cats = self._cats(e.src_ip)
        if cats:
            e.extra["reputation"] = cats
        return cats
