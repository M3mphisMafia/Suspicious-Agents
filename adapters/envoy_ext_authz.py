"""Envoy HTTP ext_authz service backed by Undertow.

    UNDERTOW_VERDICT_URL=... UNDERTOW_KEY=uk_... python -m adapters.envoy_ext_authz --port 9002

Envoy (http_service) forwards the request's method, path and allowed headers here; set
allowed_upstream_headers to include x-undertow-verdict and route on it (cell -> your cell cluster).
  block  -> 403          tarpit -> 429 + Retry-After 9 (Envoy returns the denial to the client)
  cell / challenge / allow -> 200 with x-undertow-verdict
"""
from __future__ import annotations

import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from .undertow_client import Undertow
except ImportError:
    from undertow_client import Undertow

GENERIC = b'{"error":"request could not be processed"}'


def respond(verdict: str) -> tuple[int, list[tuple[str, str]], bytes]:
    if verdict == "block":
        return 403, [("content-type", "application/json")], GENERIC
    if verdict == "tarpit":
        return 429, [("content-type", "application/json"), ("retry-after", "9")], GENERIC
    return 200, [("x-undertow-verdict", verdict)], b""


def client_ip(headers) -> str:
    xff = headers.get("x-forwarded-for", "")
    return (xff.split(",")[0].strip() if xff else "") or headers.get("x-envoy-external-address", "")


def make_handler(ut: Undertow, prefix: str = ""):
    class H(BaseHTTPRequestHandler):
        def _any(self):
            path, _, query = self.path[len(prefix):].partition("?")
            v = ut.verdict(client_ip(self.headers), self.command, path or "/", query, dict(self.headers.items()))
            status, hdrs, body = respond(v["verdict"])
            self.send_response(status)
            for k, val in hdrs:
                self.send_header(k, val)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _any

        def log_message(self, *a):
            pass
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9002)
    ap.add_argument("--prefix", default="", help="path_prefix configured in Envoy's http_service")
    a = ap.parse_args()
    ut = Undertow(os.environ["UNDERTOW_VERDICT_URL"], os.environ["UNDERTOW_KEY"])
    ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(ut, a.prefix)).serve_forever()   # noqa: S104 - a sidecar


if __name__ == "__main__":
    main()
