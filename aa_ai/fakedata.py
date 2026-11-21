"""Generate the decoy corpus with a managed model (run once, commit the output).

    AWS_PROFILE=... python -m aa_ai.fakedata aa_ai/data/decoy_corpus.json

Agents' models check that data is consistent, so empty decoys eventually read as fake.
This asks the model for believable records shaped like the real API, then OUR code (not
the model) stamps every record with a honey ID: a distinctive 9-digit number no real
record uses. Agents chain IDs they find into their next requests (IDOR probing), so a
later request carrying one is a certain detection, from any IP.

All data is fictional. Emails use the reserved .example domain so nothing can belong
to a real person.
"""
from __future__ import annotations

import os

import json
import secrets
import sys

from . import DEFAULT_MODEL

MODEL = os.environ.get("FAKEDATA_MODEL") or DEFAULT_MODEL
DOMAIN = "northwind-retail.example"

ROUTES = {
    "export": {"what": "a customer account export from a B2B retail platform",
               "fields": {"account": "string", "email": "string", "plan": "string", "mrr_usd": "number",
                          "region": "string", "created_at": "string"}},
    "admin/users": {"what": "internal staff accounts in the platform's admin console",
                    "fields": {"email": "string", "name": "string", "role": "string", "last_login": "string",
                               "mfa_enabled": "boolean"}},
    "keys/rotate": {"what": "service API credentials scheduled for rotation (values are fake and visibly truncated)",
                    "fields": {"service": "string", "key_prefix": "string", "owner": "string",
                               "rotates_at": "string", "scope": "string"}},
}


def _schema(fields: dict) -> dict:
    props = {k: {"type": v} for k, v in fields.items()}
    return {"type": "object", "additionalProperties": False, "required": ["records"],
            "properties": {"records": {"type": "array", "items": {
                "type": "object", "additionalProperties": False, "required": list(fields), "properties": props}}}}


def generate(n: int = 40) -> dict:
    from anthropic import AnthropicBedrockMantle

    client = AnthropicBedrockMantle(aws_region="us-east-1")
    corpus, markers = {}, []
    for route, spec in ROUTES.items():
        msg = client.messages.create(
            model=MODEL, max_tokens=16000,
            output_config={"effort": "medium", "format": {"type": "json_schema", "schema": _schema(spec["fields"])}},
            system="You write realistic but entirely fictional test data for a security decoy. "
                   f"Every email address must use the domain {DOMAIN}. Never use real company, person or "
                   "product names you know. Dates are in 2026. No secrets: any key-like value is a short "
                   "prefix ending in '...'.",
            messages=[{"role": "user", "content":
                       f"Generate {n} consistent records for {spec['what']}. Vary them like real data: "
                       "a few outliers, realistic distributions, some recent and some old."}],
        )
        if msg.stop_reason != "end_turn":
            raise SystemExit(f"{route}: stopped with {msg.stop_reason}")
        records = json.loads(next(b.text for b in msg.content if b.type == "text"))["records"]
        for r in records:
            hid = str(731000000 + secrets.randbelow(999999))   # honey ID, stamped by us
            r["id"] = int(hid)
            markers.append(hid)
        corpus[route] = records
        print(f"{route}: {len(records)} records ({msg.usage.input_tokens} in / {msg.usage.output_tokens} out)",
              file=sys.stderr)
    return {"generated_by": MODEL, "domain": DOMAIN, "routes": corpus, "markers": sorted(set(markers))}


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "aa_ai/data/decoy_corpus.json"
    with open(out, "w") as f:
        json.dump(generate(), f, indent=1)
    print(out)
