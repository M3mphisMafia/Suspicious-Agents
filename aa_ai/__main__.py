"""python -m aa_ai scan <log> [--format jsonl|alb]"""
from __future__ import annotations

import argparse
import gzip
import sys
from datetime import datetime, timezone

from .events import parse_alb, parse_jsonl
from .phases import timeline
from .scoring import actor_key, analyze, distributed_spray


def _open(p):
    return gzip.open(p, "rt") if p.endswith(".gz") else open(p)


def write_decoys(prefix: str, out: str) -> int:
    import json
    from pathlib import Path

    from .decoys import DecoySet

    d = DecoySet(prefix=prefix.rstrip("/"))
    root = Path(out)
    for r in d.routes:   # S3 keys mirror the decoy routes served by the CloudFront behavior
        p = root / r.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d.decoy_response(r)[1]))
    (root / "robots.txt.fragment").write_text(d.robots_lines())
    (root / "openapi-paths.fragment.json").write_text(json.dumps(d.openapi_paths(), indent=2))
    (root / "config.decoy.json").write_text(d.runtime_config())
    (root / "CANARIES.txt").write_text(
        f"Alert on any use of these (app logs AND CloudTrail):\n{d.canary_key}\n{d.canary_client_secret}\n")
    print(f"decoys written to {root}/ - keep CANARIES.txt out of git")
    return 0


def stack_config(cfn, stack: str):
    from .scorer import Config

    s = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    out = {o["OutputKey"]: o["OutputValue"] for o in s.get("Outputs", [])}
    params = {p["ParameterKey"]: p.get("ParameterValue", "") for p in s.get("Parameters", [])}
    if "ScorerTableName" not in out:
        raise SystemExit(f"{stack} has no scorer deployed (ScorerTableName output missing)")
    return Config({
        "MODE": params.get("ScorerMode", "observe"), "TABLE_NAME": out["ScorerTableName"],
        "IPSET4_NAME": "aa-ai-flagged-ips", "IPSET4_ID": out["FlaggedIpSetId"],
        "IPSET6_NAME": "aa-ai-flagged-ips6", "IPSET6_ID": out["FlaggedIp6SetId"],
        "JA4SET_NAME": "aa-ai-flagged-ja4", "JA4SET_ID": out["FlaggedJa4SetId"],
        "ALLOW4_NAME": "aa-ai-allowed-ips", "ALLOW4_ID": out["AllowedIpSetId"],
        "ALLOW6_NAME": "aa-ai-allowed-ips6", "ALLOW6_ID": out["AllowedIp6SetId"],
        "CHALLENGE4_NAME": "aa-ai-challenge-ips", "CHALLENGE4_ID": out.get("ChallengeIpSetId", ""),
        "SUSPECT4_NAME": "aa-ai-suspect-ips", "SUSPECT4_ID": out.get("SuspectIpSetId", ""),
        "ALLOW_CIDRS": params.get("AllowCidrs", ""), "FLAG_JA4": params.get("FlagJa4", "false"),
    })


def run_unblock(a) -> int:
    import boto3  # pip install 'aa-ai[aws]'
    from botocore.config import Config as BotoConfig

    from .scorer import unblock

    cfg = stack_config(boto3.client("cloudformation", region_name="us-east-1"), a.stack)
    who = boto3.client("sts").get_caller_identity()["Arn"]
    res = unblock(a.target, boto3.resource("dynamodb", region_name="us-east-1").Table(cfg.table),
                  boto3.client("wafv2", region_name="us-east-1",
                               config=BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"})), cfg,
                  ttl=int(a.ttl_hours * 3600), reason=a.reason, by=who)
    print(f"allowed {res['allowed']} until {datetime.fromtimestamp(res['expires'], timezone.utc):%Y-%m-%d %H:%M} UTC; "
          f"cleared {len(res['cleared'])} flag(s), recorded as false positives")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aa_ai")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("logs", nargs="+")
    sc.add_argument("--format", choices=["jsonl", "alb"], default="jsonl")
    sc.add_argument("--min-score", type=float, default=0.3)
    dc = sub.add_parser("decoys", help="write decoy files for the S3 decoy bucket")
    dc.add_argument("--prefix", default="/api/v1/internal/ops")
    dc.add_argument("--out", default="decoy-site")
    ub = sub.add_parser("unblock", help="allow an IP/CIDR, clear its flags, resync WAF")
    ub.add_argument("target", help="IP or CIDR")
    ub.add_argument("--stack", required=True, help="edge-shield stack name (us-east-1)")
    ub.add_argument("--ttl-hours", type=float, default=24)
    ub.add_argument("--reason", default="")
    a = ap.parse_args(argv)

    if a.cmd == "decoys":
        return write_decoys(a.prefix, a.out)
    if a.cmd == "unblock":
        return run_unblock(a)

    parse = parse_alb if a.format == "alb" else parse_jsonl
    events = [e for p in a.logs for e in parse(_open(p))]
    reports = analyze(events)
    flagged = [r for r in reports if r.score >= a.min_score]
    print(f"{len(events)} events, {len(reports)} actors, {len(flagged)} flagged\n")
    by_key = {}
    for e in events:
        by_key.setdefault(actor_key(e), []).append(e)
    for r in flagged:
        t0 = datetime.fromtimestamp(r.first, timezone.utc).isoformat(timespec="seconds")
        print(f"[{r.verdict.upper():6}] {r.score:.2f}  {r.key}  ({r.events} req, {len(r.ips)} IPs, from {t0})")
        for s in r.signals:
            print(f"           - {s.name}: {s.detail}")
        print(f"           phases: {' -> '.join(timeline(sorted(by_key[r.key], key=lambda e: e.ts)))}")
    for user, n, srcs in distributed_spray(events):
        print(f"[SPRAY ] account {user!r}: {n} failures from {srcs} sources in 1h")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
