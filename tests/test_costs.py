"""Costs: price math, projection, the hourly sample and daily check cadence, the Cost Explorer call
cap, exact vs account-wide scope, and the Budget page's snapshot. AWS clients are stand-ins."""
import json
from datetime import datetime, timezone

import pytest

from aa_ai import costs
from test_flood import LiveAcl
from test_scorer import FakeTable, cfg

GB = costs.GB
JAN15 = datetime(2027, 1, 15, 8, 10, tzinfo=timezone.utc).timestamp()   # 08:10 UTC, after the check hour
C = dict(WEBACL_NAME="aa-ai-edge-shield", WEBACL_ID="acl")
ENV = {"TABLE_NAME": "T", "API_ID": "api1", "DISTRIBUTION_ID": "E1ENGINE", "WEBACL_ARN": "arn:acl",
       "AWS_LAMBDA_FUNCTION_NAME": "scorer", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "512",
       "COST_FUNCTIONS": "cell:256,admin:256,verdict:256,judge:512", "MONTHLY_BUDGET_USD": "100"}


class CostTable(FakeTable):
    """FakeTable plus the one conditional write the call cap relies on."""

    class Refused(Exception):
        response = {"Error": {"Code": "ConditionalCheckFailedException"}}

    def __init__(self):
        super().__init__()
        self.puts = {}

    def put_item(self, Item):
        self.puts[Item["pk"]] = self.puts.get(Item["pk"], 0) + 1
        super().put_item(Item)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues,
                    ConditionExpression=None, **kw):
        if ConditionExpression:
            have = (self.items.get((Key["pk"], Key["sk"])) or {}).get("calls")
            if have is not None and not have < ExpressionAttributeValues[":cap"]:
                raise self.Refused()
        return super().update_item(Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues, **kw)


class CW:
    """GetMetricData: every metric reports `per_hour` for each hour asked, in one page."""

    def __init__(self, per_hour=1000.0, fail=False):
        self.calls, self.per_hour, self.fail = [], per_hour, fail

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, ScanBy, NextToken=None):
        self.calls.append((StartTime, EndTime, len(MetricDataQueries)))
        if self.fail:
            raise RuntimeError("AccessDenied")
        hours = range(int(StartTime.timestamp()) // 3600, int(EndTime.timestamp()) // 3600)
        return {"MetricDataResults": [{"Id": q["Id"], "Timestamps": [datetime.fromtimestamp(h * 3600, timezone.utc) for h in hours],
                                       "Values": [self.per_hour] * len(hours)} for q in MetricDataQueries]}


class CE:
    def __init__(self, tag=None, deny_update=False):
        self.calls, self.tag, self.deny_update = [], tag, deny_update

    def get_cost_and_usage(self, TimePeriod, Granularity, Metrics, GroupBy, Filter):
        self.calls.append(("usage", Filter, TimePeriod))
        return {"ResultsByTime": [{"Groups": [
            {"Keys": ["AWS WAF"], "Metrics": {"UnblendedCost": {"Amount": "20.00", "Unit": "USD"}}},
            {"Keys": ["Amazon CloudFront"], "Metrics": {"UnblendedCost": {"Amount": "0.50", "Unit": "USD"}}},
            {"Keys": ["Amazon Elastic Compute Cloud - Compute"], "Metrics": {"UnblendedCost": {"Amount": "1.00", "Unit": "USD"}}}]}]}

    def list_cost_allocation_tags(self, TagKeys, Type):
        self.calls.append(("list",))
        return {"CostAllocationTags": [self.tag] if self.tag else []}

    def update_cost_allocation_tags_status(self, CostAllocationTagsStatus):
        self.calls.append(("update",))
        if self.deny_update:
            raise type("AccessDenied", (Exception,), {"response": {"Error": {"Code": "AccessDeniedException"}}})()
        return {"Errors": []}


class CF:
    def list_distributions_by_web_acl_id(self, WebACLId):
        assert WebACLId == "arn:acl"
        return {"DistributionList": {"Items": [{"Id": "E1ENGINE"}, {"Id": "E2BILLING"}]}}


def clients(cw=None, ce=None):
    got = {"cloudwatch": cw or CW(), "ce": ce or CE(), "cloudfront": CF()}
    return got, (lambda name: got[name])


def tick(t, now, cl, waf=None):
    return costs.tick(t, waf or LiveAcl(), cfg(**C), now=now, client=cl, env=ENV)


# ---------- price math ----------

def test_hour_cost_prices_each_line():
    u = {"waf_requests": 1_000_000, "ddos_blocked": 200_000, "rules": 20, "anti_ddos": True,
         "lambda": {"f": [1_000_000, 100_000_000, 512, "x86_64"]}, "ddb_read": 2e6, "ddb_write": 1e6,
         "logs_bytes": GB, "apigw": 1e6, "tokens_in": 1e6, "tokens_out": 1e5, "metrics": 1000}
    c = costs.hour_cost(u, 720)
    assert c["waf"] == pytest.approx(25 / 720 + 0.8 * 0.60 + 20 / 720 + 0.15)   # its blocks are not WAF requests
    assert c["lambda"] == pytest.approx(0.20 + 100_000 * 0.5 * 0.0000166667)
    assert c["dynamodb"] == pytest.approx(2 * 0.125 + 0.625)
    assert c["cloudwatch"] == pytest.approx(0.50 + 0.01)
    assert c["apigateway"] == pytest.approx(1.0) and c["model"] == pytest.approx(4.0 + 2.0)
    assert c["vpc"] == pytest.approx(0.01) and c["secrets"] == pytest.approx(4 * 0.40 / 720)
    assert c["s3"] == pytest.approx(180 * 0.005 / 1000) and c["cloudfront"] == 0.0
    arm = costs.hour_cost({**u, "lambda": {"f": [0, 100_000_000, 512, "arm64"]}}, 720)["lambda"]
    assert arm == pytest.approx(100_000 * 0.5 * 0.0000133334)
    # a month of fixed WAF charges with no traffic: web ACL + 20 rules + the anti-DDoS group
    assert sum(costs.hour_cost({"rules": 20}, 720)["waf"] for _ in range(720)) == pytest.approx(45.0)


def test_cloudfront_free_allowance_runs_across_the_month():
    h0 = costs.month_of(JAN15)[0]
    rows = [{"h": h0 + i, "u": {"cf_requests": 4_000_000, "cf_bytes": 400 * GB}, "c": {}} for i in range(4)]
    cf = [c["cloudfront"] for _, c in costs.priced(rows)]
    kvs = 4_000_000 * 0.03 / 1e6
    assert cf[0] == pytest.approx(kvs + 2_000_000 * 0.10 / 1e6)           # requests and 1 TB still free
    assert cf[2] == pytest.approx(kvs + 2.0 + 4_000_000 * 0.10 / 1e6 + (1200 - 1024) * 0.085)   # crosses both
    assert cf[3] == pytest.approx(kvs + 4.0 + 0.4 + 400 * 0.085)


def test_projection_from_the_last_day():
    h0, h_end, days = costs.month_of(JAN15)
    rows = [{"h": h0 + i, "u": {}, "c": {"waf": 0.05, "lambda": 0.01}} for i in range(24 * 14)]   # Jan 1-14
    s = costs.summarize(rows, JAN15, budget=100)
    assert s["mtd"] == pytest.approx(0.06 * 24 * 14) and s["run_rate_hour"] == pytest.approx(0.06)
    assert s["projection"] == pytest.approx(0.06 * 24 * days, abs=0.01)
    assert s["pace_per_day"] == pytest.approx(100 / 31, abs=1e-4) and len(s["days"]) == 14
    assert s["days"][0]["by"]["waf"] == pytest.approx(1.2) and s["services"][0]["key"] == "waf"


def test_compare_ratio_and_accuracy():
    v = costs.compare({"waf": 20.0, "cloudfront": 0.5, "other": 1.0}, {"waf": 19.0, "cloudfront": 0.5, "model": 3.0, "s3": 0.1})
    assert v["by"]["waf"]["ratio"] == pytest.approx(20 / 19, abs=0.001) and v["by"]["s3"]["actual"] == 0.0
    assert "model" not in v["by"]                       # never on the bill under our names
    assert v["actual"] == pytest.approx(21.5) and v["estimate"] == pytest.approx(19.6)
    assert v["accuracy"] == pytest.approx(100 * (1 - 1.9 / 21.5), abs=0.1)


# ---------- cadence ----------

def test_hourly_sample_cadence_and_backfill():
    t, (got, cl) = CostTable(), clients()
    out = tick(t, JAN15, cl)
    cw = got["cloudwatch"]
    assert len(cw.calls) == 1                           # the first run backfills the month in one call
    start, end, n = cw.calls[0]
    assert start == datetime(2027, 1, 1, tzinfo=timezone.utc) and end == datetime(2027, 1, 15, 8, tzinfo=timezone.utc)
    assert n == 4 + 1 + 2 * 2 + 2 * 5 + 2 + 1 + 1     # WAF, anti-DDoS, 2 distributions, 5 functions, table, logs, API
    assert len(out["sampled"]) == 14 * 24 + 8
    rebuilt = t.puts["COSTSUM"]
    for m in range(1, 50):                               # the rest of the hour: no calls, no month re-read
        tick(t, JAN15 + m * 60, cl)
    assert len(cw.calls) == 1 and t.puts["COSTSUM"] == rebuilt
    tick(t, JAN15 + 3600, cl)                            # next hour: one call for one hour
    assert len(cw.calls) == 2 and cw.calls[1][1] - cw.calls[1][0] == (end - end.replace(hour=7))
    row = t.items[("COST", "2027011508")]
    assert row["u"]["rules"] == len(LiveAcl().acl["Rules"]) and row["u"]["metrics"] == n


def test_a_failing_sample_is_not_retried_within_the_hour():
    t, (got, cl) = CostTable(), clients(cw=CW(fail=True))
    for m in range(0, 30):
        try:
            tick(t, JAN15 + m * 60, cl)
        except RuntimeError:
            pass
    assert len(got["cloudwatch"].calls) == 1
    got["cloudwatch"].fail = False
    tick(t, JAN15 + 3600, cl)
    assert len(got["cloudwatch"].calls) == 2 and ("COST", "2027011508") in t.items


def test_daily_check_cadence_and_the_call_cap():
    t, (got, cl) = CostTable(), clients()
    early = datetime(2027, 1, 15, 5, 10, tzinfo=timezone.utc).timestamp()
    tick(t, early, cl)
    assert got["ce"].calls == []                         # before 06:00 UTC: no check
    for m in range(0, 120):
        tick(t, JAN15 + m * 60, cl)
    assert [c[0] for c in got["ce"].calls] == ["usage", "list"]     # two calls, then quiet all day
    assert t.items[("CECALLS", "2027-01-15")]["calls"] == 2
    v = t.items[("COSTV", "2027-01-15")]
    assert v["period"] == ["20270101", "20270115"] and v["scope"] == "account-wide"
    assert float(v["by"]["waf"]["actual"]) == 20.0 and float(v["other"]) == 1.0
    tick(t, JAN15 + 86400, cl)
    assert len(got["ce"].calls) == 4                     # the next day: two more


def test_the_cap_holds_whatever_else_happens():
    t, (got, cl) = CostTable(), clients()
    t.put_item(Item={"pk": "CECALLS", "sk": "2027-01-15", "calls": 2})
    tick(t, JAN15, cl)
    assert got["ce"].calls == []
    plain, (got2, cl2) = FakeTable(), clients()          # a table that cannot do the conditional write
    costs.tick(plain, LiveAcl(), cfg(**C), now=JAN15, client=cl2, env=ENV)
    assert got2["ce"].calls == []                         # fails closed: no call


# ---------- scope and the tag ----------

def test_exact_scope_only_when_the_tag_was_active_all_period():
    jan1 = costs.month_of(JAN15)[0]
    assert costs.scope({"status": "Active", "active_since": jan1 * 3600 - 86400}, jan1) == "exact"
    assert costs.scope({"status": "Active", "active_since": jan1 * 3600 + 86400}, jan1) == "account-wide"
    assert costs.scope({"status": "Inactive"}, jan1) == "account-wide" and costs.scope({}, jan1) == "account-wide"
    t, (got, cl) = CostTable(), clients()
    t.put_item(Item={"pk": "COSTTAG", "sk": "undertow", "status": "Active", "active_since": jan1 * 3600 - 86400,
                     "checked": int(JAN15)})
    tick(t, JAN15, cl)
    flt = got["ce"].calls[0][1]
    assert flt == {"Tags": {"Key": "undertow", "Values": ["engine"], "MatchOptions": ["EQUALS"]}}
    assert t.items[("COSTV", "2027-01-15")]["scope"] == "exact" and len(got["ce"].calls) == 1   # active: no tag call
    t2, (got2, cl2) = CostTable(), clients()
    tick(t2, JAN15, cl2)
    assert got2["ce"].calls[0][1]["Dimensions"]["Key"] == "SERVICE"
    assert set(got2["ce"].calls[0][1]["Dimensions"]["Values"]) >= {"AWS WAF", "Amazon CloudFront"}


def test_tag_lookup_then_activation_that_fails_quietly():
    ce = CE(tag={"TagKey": "undertow", "Type": "UserDefined", "Status": "Inactive"}, deny_update=True)
    t, (got, cl) = CostTable(), clients(ce=ce)
    tick(t, JAN15, cl)                                    # day 1: check + look the tag up
    assert t.items[("COSTTAG", "undertow")]["status"] == "Inactive"
    tick(t, JAN15 + 86400, cl)                            # day 2: check + try to activate: denied, no error raised
    tag = t.items[("COSTTAG", "undertow")]
    assert [c[0] for c in ce.calls] == ["usage", "list", "usage", "update"]
    assert tag["status"] == "Inactive" and tag["error"] == "AccessDeniedException"
    ce.deny_update = False
    tick(t, JAN15 + 2 * 86400, cl)                        # day 3: activation allowed
    tag = t.items[("COSTTAG", "undertow")]
    assert tag["status"] == "Active" and tag["active_since"] == int(JAN15 + 2 * 86400)
    assert costs.scope(costs._num(tag), costs.month_of(JAN15)[0]) == "account-wide"   # exact from next month


# ---------- snapshot ----------

def test_snapshot_budget_shape_and_absent_before_the_first_sample():
    from aa_ai.snapshot import build
    t = CostTable()
    assert "budget" not in build(t, {"mode": "observe"}, 1, now=JAN15)
    _, cl = clients()
    tick(t, JAN15, cl)
    b = build(t, {"mode": "observe"}, 1, now=JAN15 + 5)["budget"]
    assert b["limit"] == 100 and b["typical"] == 50 and b["month"] == "2027-01" and b["days_in_month"] == 31
    assert b["mtd"] > 0 and b["projection"] >= b["mtd"] and len(b["days"]) == 15
    assert {g["key"] for g in b["groups"]} == {"firewall", "cdn", "compute", "other"}
    svc = {s["key"]: s for s in b["services"]}
    assert svc["waf"]["actual"] == 20.0 and svc["waf"]["ratio"] and svc["model"]["actual"] is None
    assert b["verified"]["scope"] == "account-wide" and b["verified"]["date"] == "2027-01-15"
    assert 0 <= b["verified"]["accuracy"] <= 100
    json.dumps(b)


def test_lambda_memory_in_the_env_matches_the_template():
    from pathlib import Path

    import cfnlint.decode
    tpl, _ = cfnlint.decode.decode_str((Path(__file__).parent.parent / "infra" / "edge-shield.yaml").read_text())
    res = tpl["Resources"]
    env = res["TickFunction"]["Properties"]["Environment"]["Variables"]["COST_FUNCTIONS"]["Fn::Join"][1]
    text = env[0]["Fn::Sub"] + env[1]["Fn::If"][1]["Fn::Sub"]
    assert "${ScorerFunction}" in text                   # the tick prices itself and the log-batch scorer
    for part in text.split(","):
        name, mem = part.split(":")
        assert res[name.strip("${}")]["Properties"]["MemorySize"] == int(mem), name
    assert not any("Architectures" in r.get("Properties", {}) for r in res.values() if r["Type"] == "AWS::Lambda::Function")
    names = {r["VisibilityConfig"]["MetricName"] for r in res["WebAcl"]["Properties"]["Rules"] if "Name" in r}
    assert res["WebAcl"]["Properties"]["VisibilityConfig"]["MetricName"] == costs.WAF_METRIC and costs.DDOS_METRIC in names
