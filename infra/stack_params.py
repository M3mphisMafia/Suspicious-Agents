"""Package stage: write each stack's CloudFormation parameters (template configuration files).

The pipeline's CloudFormation actions read cfn/store.json and cfn/edge.json; the edge also gets
the store's outputs (origin, origin secret, app log group) passed straight from that stage.
Edge controls set live from the dashboard are read from the saved policy, so a deploy keeps them.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aa_ai import DEFAULT_MODEL  # noqa: E402
from aa_ai.acl import stack_params  # noqa: E402

STORE_NAME = "Northwind Supply"
# stack-level tags reach every taggable resource; the Budget page verifies costs by this one
STACK_TAGS = {"undertow": "engine"}


def edge_controls(table: str) -> dict:
    if not table or table == "None":
        return {}
    try:
        import boto3
        item = boto3.resource("dynamodb").Table(table).get_item(Key={"pk": "POLICY", "sk": "current"}).get("Item") or {}
    except Exception as exc:  # noqa: BLE001 - first deploy, or unreadable: template defaults
        print(f"edge controls: defaults ({type(exc).__name__})")
        return {}
    ec = item.get("edge_controls") or {}
    return {k: v for k, v in {"auth_rate": int(ec["auth_rate"]) if "auth_rate" in ec else None,
                              "retry_after": int(ec["retry_after"]) if "retry_after" in ec else None,
                              "geo": [str(c) for c in ec.get("geo", [])],
                              "asn": [int(a) for a in ec.get("asn", [])]}.items() if v is not None}


def main():
    e = os.environ
    dom = e.get("DOM", "")
    store = {"CodeBucket": e["ARTIFACT_BUCKET"], "CodeKey": e["KEY"], "DecoyPrefix": e["DECOY_PREFIX"],
             "StoreName": STORE_NAME, "DynamoPrefixListId": e["DDB_PL"]}
    edge = {"OriginForwardsHost": "false", "ScorerCodeBucket": e["ARTIFACT_BUCKET"], "ScorerCodeKey": e["KEY"],
            "ScorerMode": e["SCORER_MODE"], "AdminCidrs": e["ADMIN_CIDRS"], "DecoyPrefix": e["DECOY_PREFIX"],
            "AlertEmail": e.get("ALERT_EMAIL", ""), "AdminEmail": e.get("ADMIN_EMAIL", ""),
            "LoginUrl": f"https://{dom}/_undertow/login.html" if dom and dom != "None" else "",
            "JudgeLayerKey": e.get("JUDGE_LAYER", ""), "JudgeModel": e.get("JUDGE_MODEL") or DEFAULT_MODEL, "CellTitle": STORE_NAME,
            **stack_params(edge_controls(e.get("TABLE", "")))}
    os.makedirs("cfn", exist_ok=True)
    for name, params in (("store", store), ("edge", edge)):
        with open(f"cfn/{name}.json", "w") as f:
            json.dump({"Parameters": params, "Tags": STACK_TAGS}, f, indent=1)
    print("edge controls:", {k: edge[k] for k in ("AuthRatePer60s", "RetryAfter", "GeoBlockCountries", "AsnBlock")})


if __name__ == "__main__":
    main()
