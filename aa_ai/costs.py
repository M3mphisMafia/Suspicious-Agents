"""Cost: an hourly estimate of what the engine costs, checked once a day against the bill.

  estimate  on the 1-minute tick, at most once an hour: one CloudWatch GetMetricData call covers
            every hour of the month not sampled yet (a first run backfills the month for the same
            price), priced at the list prices below
  verify    once a day: month-to-date by service from Cost Explorer. By the undertow=engine cost
            allocation tag when it has been active the whole period ("exact"), else the same
            services account-wide ("account-wide"). At most CE_CALLS_PER_DAY calls ($0.01 each),
            counted by a conditional write that fails closed

DynamoDB (pk / sk):
  COST / <hour>       one hour's usage and cost by service, ~400 days TTL
  COSTS / state       last hour sampled, last attempt (a failed sample is not retried within the hour)
  COSTSUM / current   the Budget page, rebuilt after each sample and each check
  COSTV / <date>      verified actual vs estimate by service, scope and ratio
  COSTTAG / undertow  the cost allocation tag as last seen
  CECALLS / <date>    Cost Explorer calls made that day
"""
from __future__ import annotations

import calendar
import json
import logging
import os
import time
from datetime import datetime, timezone
from decimal import Decimal

log = logging.getLogger()

# us-east-1 list prices, USD. Source: AWS public pricing pages, as known on 2026-11-21; not fetched
# live, so check them before relying on the numbers. (A) marks a number that is an assumption.
PRICES = {
    "waf_acl_month": 5.00, "waf_rule_month": 1.00, "waf_per_million": 0.60,
    "anti_ddos_month": 20.00, "anti_ddos_per_million": 0.15,         # (A) from the rollout brief
    "cf_per_million": 1.00,          # HTTPS requests, US/Europe ($0.0100 per 10,000)
    "cf_per_gb": 0.085,              # data out to the internet, first 10 TB, US/Europe
    "cf_free_requests": 10_000_000, "cf_free_gb": 1024,              # always free per account; (A) 1 TB = 1,024 GB
    "cf_function_per_million": 0.10, "cf_function_free": 2_000_000,  # the cell router runs on every request
    "cf_kvs_per_million": 0.03,      # (A) KeyValueStore reads, one per request
    "lambda_per_million": 0.20, "lambda_gb_s_x86": 0.0000166667, "lambda_gb_s_arm": 0.0000133334,
    "ddb_read_per_million": 0.125, "ddb_write_per_million": 0.625,  # (A) on-demand, after the late-2024 cut
    "logs_ingest_per_gb": 0.50,      # (A) vended logs (WAF), first 10 TB
    "cw_metrics_per_1000": 0.01,     # GetMetricData, per metric requested
    "secret_month": 0.40,
    "vpce_hour_per_az": 0.01,        # interface endpoint; data processed ($0.01/GB) left out (A)
    "apigw_per_million": 1.00,       # HTTP API, first 300 million
    "s3_put_per_1000": 0.005,
    "ce_per_call": 0.01,
    # (A) the judge's model, per million tokens; set MODEL_PRICE_IN_PER_M / MODEL_PRICE_OUT_PER_M
    "model_in_per_million": float(os.environ.get("MODEL_PRICE_IN_PER_M", 4.0)),
    "model_out_per_million": float(os.environ.get("MODEL_PRICE_OUT_PER_M", 20.0)),
}
SECRETS = 4                  # (A) the canary key in the edge stack + 3 in the store
VPC_ENDPOINT_AZS = 1         # the store's Secrets Manager endpoint sits in one subnet
SNAPSHOT_PUTS_PER_HOUR = 180  # three dashboard files every minute
GB = 1024 ** 3
TYPICAL_MONTH = 50           # what a typical install costs, for the page's note
CE_CALLS_PER_DAY = 2
VERIFY_AFTER_HOUR = 6        # (A) UTC; Cost Explorer has usually caught up on yesterday by then
COST_TTL = 400 * 86400
TAG_KEY, TAG_VALUE = "undertow", "engine"
WAF_METRIC, DDOS_METRIC = "aa-ai", "aa-ai-anti-ddos"   # (A) WAF metrics are keyed by metric name
WAF_LOG_GROUP = "aws-waf-logs-aa-ai"

# key, label, Cost Explorer SERVICE, chart group. The model is billed under its own product name and
# carries no tag, so it is estimated, never verified.
SERVICES = [
    ("waf", "AWS WAF", "AWS WAF", "firewall"),
    ("cloudfront", "CloudFront", "Amazon CloudFront", "cdn"),
    ("lambda", "Lambda", "AWS Lambda", "compute"),
    ("dynamodb", "DynamoDB", "Amazon DynamoDB", "compute"),
    ("cloudwatch", "CloudWatch", "AmazonCloudWatch", "compute"),
    ("apigateway", "API Gateway", "Amazon API Gateway", "compute"),
    ("s3", "S3", "Amazon Simple Storage Service", "compute"),
    ("sns", "SNS", "Amazon Simple Notification Service", "compute"),
    ("cognito", "Cognito", "Amazon Cognito", "compute"),
    ("vpc", "VPC endpoint", "Amazon Virtual Private Cloud", "other"),   # (A) service name for endpoint hours
    ("secrets", "Secrets Manager", "AWS Secrets Manager", "other"),
    ("costexplorer", "Cost Explorer API", "AWS Cost Explorer", "other"),
    ("model", "LLM calls", None, "other"),
]
KEYS = [s[0] for s in SERVICES]
GROUPS = [("firewall", "Firewall (WAF)"), ("cdn", "CloudFront"), ("compute", "Compute, data and logs"),
          ("other", "Endpoint, secrets, LLM, other")]
NOTES = {"cognito": "free tier", "sns": "free tier", "model": "estimate only: billed under the model's name, untagged",
         "s3": "snapshot writes", "cloudfront": "after the always-free 10M requests and 1 TB"}
BY_CE = {s[2]: s[0] for s in SERVICES if s[2]}


# ---------- pure: time and prices ----------

def hour_key(h: int) -> str:
    return time.strftime("%Y%m%d%H", time.gmtime(h * 3600))


def month_of(ts: float) -> tuple[int, int, int]:
    """(first hour of the month, first hour of the next, days in the month), UTC."""
    t = time.gmtime(ts)
    days = calendar.monthrange(t.tm_year, t.tm_mon)[1]
    start = int(datetime(t.tm_year, t.tm_mon, 1, tzinfo=timezone.utc).timestamp()) // 3600
    return start, start + days * 24, days


def cf_cost(requests: float, gb: float, p=PRICES) -> float:
    """CloudFront for a month's cumulative usage, after the always-free allowances."""
    return (max(0.0, requests - p["cf_free_requests"]) * p["cf_per_million"] / 1e6
            + max(0.0, gb - p["cf_free_gb"]) * p["cf_per_gb"]
            + max(0.0, requests - p["cf_function_free"]) * p["cf_function_per_million"] / 1e6
            + requests * p["cf_kvs_per_million"] / 1e6)


def hour_cost(u: dict, hours_in_month: int, p=PRICES) -> dict:
    """One hour's usage -> cost by service. CloudFront is left at 0 here: its free allowance runs
    across the month, so summarize() prices it with the hours in order."""
    m = float(hours_in_month)
    req = float(u.get("waf_requests", 0))
    # anti-DDoS: assume every request reaches it (an upper bound); its own blocks are not WAF requests
    ddos = (p["anti_ddos_month"] / m + req * p["anti_ddos_per_million"] / 1e6) if u.get("anti_ddos", True) else 0.0
    billed = max(0.0, req - float(u.get("ddos_blocked", 0)))
    lam = 0.0
    for inv, ms, mb, arch in u.get("lambda", {}).values():
        rate = p["lambda_gb_s_arm"] if arch == "arm64" else p["lambda_gb_s_x86"]
        lam += float(inv) * p["lambda_per_million"] / 1e6 + float(ms) / 1000 * float(mb) / 1024 * rate
    return {
        "waf": (p["waf_acl_month"] + float(u.get("rules", 0)) * p["waf_rule_month"]) / m
        + billed * p["waf_per_million"] / 1e6 + ddos,
        "cloudfront": 0.0,
        "lambda": lam,
        "dynamodb": float(u.get("ddb_read", 0)) * p["ddb_read_per_million"] / 1e6
        + float(u.get("ddb_write", 0)) * p["ddb_write_per_million"] / 1e6,
        "cloudwatch": float(u.get("logs_bytes", 0)) / GB * p["logs_ingest_per_gb"]
        + float(u.get("metrics", 0)) * p["cw_metrics_per_1000"] / 1000,
        "apigateway": float(u.get("apigw", 0)) * p["apigw_per_million"] / 1e6,
        "s3": SNAPSHOT_PUTS_PER_HOUR * p["s3_put_per_1000"] / 1000,
        "sns": 0.0, "cognito": 0.0,
        "vpc": VPC_ENDPOINT_AZS * p["vpce_hour_per_az"],
        "secrets": SECRETS * p["secret_month"] / m,
        "costexplorer": 0.0,
        "model": float(u.get("tokens_in", 0)) * p["model_in_per_million"] / 1e6
        + float(u.get("tokens_out", 0)) * p["model_out_per_million"] / 1e6,
    }


def priced(rows: list[dict]) -> list[tuple[dict, dict]]:
    """(row, cost by service) for one month's rows in hour order, CloudFront's allowance applied."""
    out, req, gb = [], 0.0, 0.0
    for r in sorted(rows, key=lambda r: int(r["h"])):
        c = {k: float(v) for k, v in (r.get("c") or {}).items()}
        dr, dg = float(r["u"].get("cf_requests", 0)), float(r["u"].get("cf_bytes", 0)) / GB
        c["cloudfront"] = cf_cost(req + dr, gb + dg) - cf_cost(req, gb)
        req, gb = req + dr, gb + dg
        out.append((r, c))
    return out


def estimate(rows: list[dict], start_h: int, end_h: int) -> dict:
    """Estimated cost by service for hours [start_h, end_h) of one month."""
    ms, _, _ = month_of(start_h * 3600)
    tot = {k: 0.0 for k in KEYS}
    for r, c in priced([r for r in rows if ms <= int(r["h"]) < end_h]):
        if int(r["h"]) >= start_h:
            for k, v in c.items():
                tot[k] = tot.get(k, 0.0) + v
    return tot


def summarize(rows: list[dict], now: float, budget: float = 100.0, verified: dict | None = None,
              ce_calls: int = 0) -> dict:
    """The Budget page: month to date, daily series by service, run rate and month-end projection."""
    ms, me, ndays = month_of(now)
    mine = priced([r for r in rows if ms <= int(r["h"]) < me])
    days: dict[str, dict] = {}
    mtd = {k: 0.0 for k in KEYS}
    for r, c in mine:
        d = days.setdefault(time.strftime("%Y-%m-%d", time.gmtime(int(r["h"]) * 3600)), {k: 0.0 for k in KEYS})
        for k, v in c.items():
            d[k] = d.get(k, 0.0) + v
            mtd[k] = mtd.get(k, 0.0) + v
    if ce_calls:
        mtd["costexplorer"] += ce_calls * PRICES["ce_per_call"]
        if days:
            days[max(days)]["costexplorer"] += ce_calls * PRICES["ce_per_call"]
    total = sum(mtd.values())
    last = mine[-24:]
    rate = sum(sum(c.values()) for _, c in last) / len(last) if last else 0.0
    left = max(0, me - (int(mine[-1][0]["h"]) + 1)) if mine else max(0, me - int(now // 3600))
    projection = total + rate * left
    v = verified or {}
    vby = v.get("by") or {}
    services = [{"key": k, "name": n, "group": g, "estimate": round(mtd.get(k, 0.0), 4),
                 "actual": (vby.get(k) or {}).get("actual"), "verified_estimate": (vby.get(k) or {}).get("estimate"),
                 "ratio": (vby.get(k) or {}).get("ratio"), "note": NOTES.get(k, "")}
                for k, n, _, g in SERVICES]
    return {
        "month": time.strftime("%Y-%m", time.gmtime(now)), "days_in_month": ndays, "generated": int(now),
        "limit": float(budget), "typical": TYPICAL_MONTH, "pace_per_day": round(float(budget) / ndays, 4),
        "mtd": round(total, 4), "run_rate_hour": round(rate, 5), "projection": round(projection, 2),
        "hours": len(mine), "groups": [{"key": k, "name": n} for k, n in GROUPS],
        "days": [{"date": d, "by": {k: round(x, 5) for k, x in by.items() if x}, "total": round(sum(by.values()), 4)}
                 for d, by in sorted(days.items())],
        "services": sorted(services, key=lambda s: -s["estimate"]),
        "verified": {k: v.get(k) for k in ("date", "scope", "period", "actual", "estimate", "accuracy", "other")} if v else None,
        "note": f"A typical install costs about ${TYPICAL_MONTH} a month, mostly the firewall and its managed rules.",
    }


def compare(actual: dict, est: dict) -> dict:
    """Per service: actual, estimate, ratio (actual / estimate), and the overall accuracy."""
    by = {}
    for k, _, ce_name, _ in SERVICES:
        if not ce_name:
            continue                  # never on the bill under our names: estimate only
        a, e = actual.get(k, 0.0), est.get(k, 0.0)    # a service the bill does not list cost nothing
        by[k] = {"actual": round(a, 4), "estimate": round(e, 4), "ratio": round(a / e, 3) if e else None}
    act = sum(x["actual"] for x in by.values()) + actual.get("other", 0.0)
    ests = sum(x["estimate"] for x in by.values())
    acc = round(max(0.0, 100 * (1 - abs(ests - act) / act)), 1) if act else None
    return {"by": by, "actual": round(act, 4), "estimate": round(ests, 4), "accuracy": acc,
            "other": round(actual.get("other", 0.0), 4)}


def parse_ce(resp: dict) -> dict:
    """GetCostAndUsage grouped by SERVICE -> {service key: USD}; services we do not model go to 'other'."""
    out: dict[str, float] = {}
    for res in resp.get("ResultsByTime", []):
        for g in res.get("Groups", []):
            k = BY_CE.get(g["Keys"][0], "other")
            out[k] = out.get(k, 0.0) + float(g["Metrics"]["UnblendedCost"]["Amount"])
    return out


def verify_period(now: float) -> tuple[int, int]:
    """[start hour, end hour) to check: the month so far up to today 00:00 UTC; on the 1st, last month."""
    today = int(now // 86400) * 24
    ms, _, _ = month_of(now)
    return (month_of((ms - 1) * 3600)[0], ms) if today == ms else (ms, today)


def scope(tag: dict, start_h: int) -> str:
    """Exact only if the tag was active the whole period: Cost Explorer does not tag costs backward."""
    return "exact" if tag.get("status") == "Active" and int(tag.get("active_since", 1 << 62)) <= start_h * 3600 \
        else "account-wide"


def functions(env=os.environ) -> dict[str, tuple[int, str]]:
    """Lambda functions to price: name -> (memory MB, architecture)."""
    out = {}
    me = env.get("AWS_LAMBDA_FUNCTION_NAME", "")
    if me:
        out[me] = (int(env.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", 512)), "x86_64")
    for part in filter(None, (s.strip() for s in env.get("COST_FUNCTIONS", "").split(","))):
        name, _, rest = part.partition(":")
        mb, _, arch = rest.partition(":")
        out[name] = (int(mb or 128), arch or "x86_64")
    return out


def queries(env, dists: list[str], fns: dict) -> list[tuple[dict, tuple]]:
    """One GetMetricData request: (query, what it measures). Sum per hour for every metric."""
    out = []

    def q(ns, name, dims, what):
        out.append(({"Id": f"m{len(out)}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": ns, "MetricName": name, "Dimensions": [{"Name": k, "Value": v} for k, v in dims]},
            "Period": 3600, "Stat": "Sum"}}, what))
    for name in ("AllowedRequests", "BlockedRequests", "ChallengeRequests", "CaptchaRequests"):
        q("AWS/WAFV2", name, [("WebACL", WAF_METRIC), ("Rule", "ALL")], ("waf_requests",))
    q("AWS/WAFV2", "BlockedRequests", [("WebACL", WAF_METRIC), ("Rule", DDOS_METRIC)], ("ddos_blocked",))
    for d in dists:
        q("AWS/CloudFront", "Requests", [("DistributionId", d), ("Region", "Global")], ("cf_requests",))
        q("AWS/CloudFront", "BytesDownloaded", [("DistributionId", d), ("Region", "Global")], ("cf_bytes",))
    for fn in fns:
        q("AWS/Lambda", "Invocations", [("FunctionName", fn)], ("lambda", fn, 0))
        q("AWS/Lambda", "Duration", [("FunctionName", fn)], ("lambda", fn, 1))
    if env.get("TABLE_NAME"):
        q("AWS/DynamoDB", "ConsumedReadCapacityUnits", [("TableName", env["TABLE_NAME"])], ("ddb_read",))
        q("AWS/DynamoDB", "ConsumedWriteCapacityUnits", [("TableName", env["TABLE_NAME"])], ("ddb_write",))
    q("AWS/Logs", "IncomingBytes", [("LogGroupName", WAF_LOG_GROUP)], ("logs_bytes",))
    if env.get("API_ID"):
        q("AWS/ApiGateway", "Count", [("ApiId", env["API_ID"])], ("apigw",))
    return out


def usage_by_hour(results: list[dict], what: dict, fns: dict) -> dict[int, dict]:
    """GetMetricData results -> {hour: usage}."""
    out: dict[int, dict] = {}
    for res in results:
        w = what[res["Id"]]
        for t, v in zip(res.get("Timestamps", []), res.get("Values", [])):
            h = int((t.timestamp() if hasattr(t, "timestamp") else float(t)) // 3600)
            u = out.setdefault(h, {"lambda": {}})
            if w[0] == "lambda":
                cell = u["lambda"].setdefault(w[1], [0.0, 0.0, fns[w[1]][0], fns[w[1]][1]])
                cell[w[2]] += float(v)
            else:
                u[w[0]] = u.get(w[0], 0.0) + float(v)
    return out


# ---------- I/O: the tick ----------

def _dec(o):
    if isinstance(o, float):
        return Decimal(str(round(o, 8)))
    if isinstance(o, dict):
        return {k: _dec(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_dec(v) for v in o]
    return o


def _num(o):
    if isinstance(o, Decimal):
        return int(o) if o == int(o) else float(o)
    if isinstance(o, dict):
        return {k: _num(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_num(v) for v in o]
    return o


def _code(exc) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _get(table, pk, sk) -> dict:
    return _num(table.get_item(Key={"pk": pk, "sk": sk}).get("Item") or {})


def month_rows(table, now: float) -> list[dict]:
    ms, _, _ = month_of(now)
    rows, kw = [], {"KeyConditionExpression": "pk = :k AND sk >= :s",
                    "ExpressionAttributeValues": {":k": "COST", ":s": hour_key(ms)}}
    while True:
        r = table.query(**kw)
        rows += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            return [_num(x) for x in rows]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def reserve(table, day: str, now: float) -> bool:
    """Count one Cost Explorer call against today's cap. Fails closed: any doubt means no call."""
    try:
        table.update_item(Key={"pk": "CECALLS", "sk": day}, UpdateExpression="ADD #n :one SET #exp = :exp",
                          ConditionExpression="attribute_not_exists(#n) OR #n < :cap",
                          ExpressionAttributeNames={"#n": "calls", "#exp": "exp"},
                          ExpressionAttributeValues={":one": 1, ":cap": CE_CALLS_PER_DAY, ":exp": int(now + 40 * 86400)})
        return True
    except Exception as exc:  # noqa: BLE001 - the cap reached, or an error: either way, no call
        log.info(json.dumps({"event": "cost_explorer_call_refused", "reason": _code(exc)}))
        return False


def sample(table, waf, cfg, now: float, client, env=os.environ) -> list[int]:
    """Price every hour not sampled yet this month. Returns the hours written."""
    st = _get(table, "COSTS", "state")
    cur = int(now // 3600)
    ms, _, _ = month_of(now)
    start = max(ms, int(st.get("last", ms - 1)) + 1)
    if start >= cur:
        return []
    rules, anti_ddos = int(st.get("rules", 25)), bool(st.get("anti_ddos", True))   # (A) until the ACL is read
    try:
        got = waf.get_web_acl(Name=cfg.acl[0], Scope="CLOUDFRONT", Id=cfg.acl[1])["WebACL"]["Rules"]
        rules = len(got)
        anti_ddos = any((r.get("Statement", {}).get("ManagedRuleGroupStatement") or {}).get("Name")
                        == "AWSManagedRulesAntiDDoSRuleSet" for r in got)
    except Exception as exc:  # noqa: BLE001
        log.warning(json.dumps({"event": "cost_rules_unread", "error": _code(exc)}))
    dists = [d for d in [env.get("DISTRIBUTION_ID", "")] if d]
    try:   # protected apps' distributions share the engine's web ACL
        r = client("cloudfront").list_distributions_by_web_acl_id(WebACLId=env.get("WEBACL_ARN", ""))
        dists = sorted(set(dists) | {i["Id"] for i in (r.get("DistributionList") or {}).get("Items", [])})
    except Exception as exc:  # noqa: BLE001
        log.warning(json.dumps({"event": "cost_distributions_unread", "error": _code(exc)}))
    fns = functions(env)
    qs = queries(env, dists, fns)
    what = {q["Id"]: w for q, w in qs}
    results, kw = [], {"MetricDataQueries": [q for q, _ in qs], "StartTime": datetime.fromtimestamp(start * 3600, timezone.utc),
                       "EndTime": datetime.fromtimestamp(cur * 3600, timezone.utc), "ScanBy": "TimestampAscending"}
    cw = client("cloudwatch")
    while True:
        r = cw.get_metric_data(**kw)
        results += r.get("MetricDataResults", [])
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
    by_hour = usage_by_hour(results, what, fns)
    first = int(st["last"]) + 1 if "last" in st else min(by_hour, default=cur - 1)
    hours = list(range(max(start, first), cur))
    _, _, ndays = month_of(now)
    for h in hours:
        u = {**by_hour.get(h, {"lambda": {}}), "rules": rules, "anti_ddos": anti_ddos}
        if h >= cur - 25:   # the engine's per-hour model counters live 26 hours
            for pk in ("JUDGECOUNT", "FLOODCOUNT"):
                c = _get(table, pk, hour_key(h))
                u["tokens_in"] = u.get("tokens_in", 0) + int(c.get("tokens_in", 0))
                u["tokens_out"] = u.get("tokens_out", 0) + int(c.get("tokens_out", 0))
        if h == cur - 1:
            u["metrics"] = len(qs)    # this call's own price lands on the newest hour
        u["lambda"] = {k: list(v) for k, v in u["lambda"].items()}
        table.put_item(Item={"pk": "COST", "sk": hour_key(h), "h": h, "u": _dec(u),
                             "c": _dec(hour_cost(u, ndays * 24)), "exp": int(now + COST_TTL)})
    table.put_item(Item={"pk": "COSTS", "sk": "state", "last": cur - 1, "tried": cur, "rules": rules,
                         "anti_ddos": anti_ddos, "dists": dists})
    return hours


def manage_tag(table, ce, now: float) -> dict:
    """At most one call a day: look the tag up, or try to activate it. Quiet on any refusal."""
    tag = _get(table, "COSTTAG", TAG_KEY) or {"pk": "COSTTAG", "sk": TAG_KEY, "status": "unknown"}
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    if tag.get("tried") == day or (tag.get("status") == "Active" and now - int(tag.get("checked", 0)) < 7 * 86400):
        return tag
    if not reserve(table, day, now):
        return tag
    tag["tried"] = day
    try:
        if tag.get("status") == "Inactive":
            r = ce.update_cost_allocation_tags_status(CostAllocationTagsStatus=[{"TagKey": TAG_KEY, "Status": "Active"}])
            if r.get("Errors"):
                tag["error"] = str(r["Errors"][0].get("Code", "refused"))[:80]
            else:
                tag.update(status="Active", active_since=int(now), checked=int(now), error="")
        else:
            r = ce.list_cost_allocation_tags(TagKeys=[TAG_KEY], Type="UserDefined")
            hit = next((t for t in r.get("CostAllocationTags", []) if t.get("TagKey") == TAG_KEY), None)
            tag["checked"] = int(now)
            if not hit:
                tag["status"] = "missing"     # appears about a day after the first tagged resource
            else:
                if hit.get("Status") == "Active" and tag.get("status") != "Active":
                    since = hit.get("LastUpdatedDate") or ""
                    try:
                        tag["active_since"] = int(datetime.fromisoformat(str(since).replace("Z", "+00:00")).timestamp())
                    except ValueError:
                        tag["active_since"] = int(now)
                tag["status"] = hit.get("Status", "unknown")
    except Exception as exc:  # noqa: BLE001 - denied in a member account, throttled: try again tomorrow
        tag["error"] = _code(exc)[:80]
    table.put_item(Item={**tag, "pk": "COSTTAG", "sk": TAG_KEY})
    return tag


def verify(table, ce, now: float) -> dict | None:
    """Once a day: the bill so far, by service, against the estimate for the same days."""
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    if time.gmtime(now).tm_hour < VERIFY_AFTER_HOUR or _get(table, "COSTV", day):
        return None
    start, end = verify_period(now)
    rows = month_rows(table, start * 3600)
    if not [r for r in rows if start <= int(r["h"]) < end]:
        return None                               # nothing estimated yet: nothing to check, no call
    tag = _get(table, "COSTTAG", TAG_KEY)
    sc = scope(tag, start)
    services = {"Dimensions": {"Key": "SERVICE", "Values": sorted(BY_CE)}}
    flt = {"Tags": {"Key": TAG_KEY, "Values": [TAG_VALUE], "MatchOptions": ["EQUALS"]}} if sc == "exact" else services
    item = {"pk": "COSTV", "sk": day, "scope": sc, "period": [hour_key(start)[:8], hour_key(end)[:8]],
            "at": int(now), "exp": int(now + COST_TTL)}
    if not reserve(table, day, now):
        return None
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": time.strftime("%Y-%m-%d", time.gmtime(start * 3600)),
                        "End": time.strftime("%Y-%m-%d", time.gmtime(end * 3600))},
            Granularity="MONTHLY", Metrics=["UnblendedCost"], GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}], Filter=flt)
        item.update(compare(parse_ce(resp), estimate(rows, start, end)))
    except Exception as exc:  # noqa: BLE001 - recorded, so the day's check is not retried every minute
        item["error"] = _code(exc)[:80]
        log.warning(json.dumps({"event": "cost_verify_failed", "error": item["error"]}))
    table.put_item(Item=_dec(item))
    manage_tag(table, ce, now)
    return _num(_dec(item))


def last_verified(table, now: float) -> dict | None:
    r = table.query(KeyConditionExpression="pk = :k AND sk >= :s",
                    ExpressionAttributeValues={":k": "COSTV", ":s": time.strftime("%Y-%m-%d", time.gmtime(now - 40 * 86400))})
    ok = [i for i in r.get("Items", []) if "actual" in i and not i.get("error")]
    if not ok:
        return None
    v = _num(max(ok, key=lambda i: i["sk"]))
    return {**v, "date": v["sk"]}


def rebuild(table, now: float, env=os.environ) -> dict:
    ms, _, _ = month_of(now)
    calls = sum(int(i.get("calls", 0)) for i in table.query(
        KeyConditionExpression="pk = :k AND sk >= :s",
        ExpressionAttributeValues={":k": "CECALLS", ":s": time.strftime("%Y-%m-%d", time.gmtime(ms * 3600))}).get("Items", []))
    s = summarize(month_rows(table, now), now, float(env.get("MONTHLY_BUDGET_USD", 100) or 100),
                  last_verified(table, now), calls)
    table.put_item(Item={"pk": "COSTSUM", "sk": "current", **_dec(s)})
    return s


def tick(table, waf, cfg, now: float | None = None, client=None, env=os.environ) -> dict:
    """On the 1-minute tick: a usage sample at most once an hour, a bill check at most once a day."""
    now = now or time.time()
    out = {}
    cur = int(now // 3600)
    st = _get(table, "COSTS", "state")
    if int(st.get("tried", -1)) < cur and int(st.get("last", -1)) < cur - 1:
        # marked first: a failing sample is retried next hour, never every minute
        table.put_item(Item={**st, "pk": "COSTS", "sk": "state", "tried": cur})
        out["sampled"] = sample(table, waf, cfg, now, client, env)
        out["summary"] = rebuild(table, now, env)
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    if time.gmtime(now).tm_hour >= VERIFY_AFTER_HOUR and int(_get(table, "COSTS", "verify").get("tried", -1)) < cur \
            and not _get(table, "COSTV", day):
        table.put_item(Item={"pk": "COSTS", "sk": "verify", "tried": cur})   # at most one attempt an hour
        out["verified"] = verify(table, client("ce"), now)
        if out["verified"]:
            out["summary"] = rebuild(table, now, env)
    return out


def view(item: dict | None) -> dict | None:
    """COSTSUM/current -> the snapshot's budget object (None until the first sample)."""
    if not item:
        return None
    return {k: v for k, v in _num(item).items() if k not in ("pk", "sk")}
