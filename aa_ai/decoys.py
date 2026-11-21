"""Deception: decoy routes and canary credentials an agent will find and a human won't.

Agents read robots.txt, OpenAPI specs and runtime config to plan, then act within
seconds. Plant unlinked decoys there; any touch is a near-certain detection.
All decoy content is inert: no real data, no code, nothing that acts on the visitor.
"""
from __future__ import annotations

import base64
import functools
import json
import os
import re
import secrets
from dataclasses import dataclass, field

from . import detectors

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "decoy_corpus.json")
PAGE = 10


@functools.lru_cache(maxsize=1)
def corpus() -> dict:
    """Believable fake records (aa_ai/fakedata.py, Opus 5.5) stamped with honey IDs."""
    try:
        with open(CORPUS_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"routes": {}, "markers": []}


def honey_markers() -> set[str]:
    return set(corpus().get("markers", []))


@dataclass
class DecoySet:
    prefix: str = "/api/v1/internal/" + secrets.token_hex(3)
    canary_key: str = "AKIA" + secrets.token_hex(8).upper()
    canary_client_secret: str = secrets.token_urlsafe(24)
    routes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.routes:
            self.routes = [f"{self.prefix}/export", f"{self.prefix}/admin/users",
                           f"{self.prefix}/keys/rotate"]

    def register(self) -> "DecoySet":
        detectors.DECOY_PREFIXES.add(self.prefix)
        detectors.CANARY_SECRETS.update({self.canary_key, self.canary_client_secret})
        detectors.HONEY_IDS.update(honey_markers())
        return self

    def robots_lines(self) -> str:
        return f"Disallow: {self.prefix}/\n"

    def openapi_paths(self) -> dict:
        """Merge into your real (or a decoy) OpenAPI document."""
        op = {"summary": "Internal", "security": [{"bearer": []}],
              "responses": {"200": {"description": "OK"}}}
        return {r: {"get": op, "post": op} for r in self.routes}

    def runtime_config(self) -> str:
        """A config.json-shaped decoy. Alert on any use of these values (CloudTrail too)."""
        return json.dumps({
            "apiBase": self.prefix,
            "awsAccessKeyId": self.canary_key,
            "oauthClientSecret": self.canary_client_secret,
        }, indent=2)

    def decoy_response(self, path: str, query: str = "") -> tuple[int, dict]:
        """Believable, consistent, paginated fake records. The agent's model sees data that
        hangs together, keeps paging, and picks up honey IDs it will try next."""
        rel = re.sub(r"^.*?/t/[0-9a-f]{10}/", "", path) if "/t/" in path else path.removeprefix(self.prefix)
        route = next((r for r in corpus().get("routes", {}) if rel.strip("/").startswith(r)), None)
        records = corpus().get("routes", {}).get(route, []) if route else []
        m = re.search(r"cursor=([A-Za-z0-9_-]+)", query or "")
        try:
            offset = int(base64.urlsafe_b64decode(m.group(1) + "==").decode()) if m else 0
        except (ValueError, UnicodeDecodeError):
            offset = 0
        page = records[offset: offset + PAGE]
        nxt = offset + PAGE
        cursor = base64.urlsafe_b64encode(str(nxt).encode()).decode().rstrip("=")
        return 200, {"items": page, "total": len(records), "page_size": PAGE,
                     "nextPage": f"{path}?cursor={cursor}" if nxt < len(records) else None}
