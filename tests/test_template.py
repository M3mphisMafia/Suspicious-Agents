"""Keep the CloudFormation template and the Python code in agreement."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aa_ai.events import AUTH_REGEX

TEMPLATE = Path(__file__).parent.parent / "infra" / "edge-shield.yaml"


def test_waf_auth_regex_matches_python():
    m = re.search(r'RegexString: "(\(\^\|/\)\(login[^"]+)"', TEMPLATE.read_text())
    assert m and m.group(1) == AUTH_REGEX
    assert len(AUTH_REGEX) <= 200  # WAF regex length limit


def test_template_lints_clean():
    lint = Path(sys.executable).with_name("cfn-lint")
    r = subprocess.run([str(lint), str(TEMPLATE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_rule_order_dashboard_guard_then_allow_list():
    t = TEMPLATE.read_text()
    # the dashboard guard must run before the allow list, or an allow-listed office could read it
    assert (t.index("Name: dashboard-admin-allow") < t.index("Name: dashboard-admin-only") < t.index("Name: allow-list")
            < t.index("Name: decoy-touch") < t.index("Name: flagged-ip"))
    prios = [int(p) for p in re.findall(r"^          Priority: (\d+)$", t, re.M)]
    assert prios == sorted(set(prios)), "rule priorities must be unique and in file order"


def test_snapshot_data_is_not_on_the_public_path():
    t = TEMPLATE.read_text()
    assert '${DashboardBucket.Arn}/data/data-*.json' in t          # scorer/admin write here
    assert '${DashboardBucket.Arn}/_undertow/*' in t               # CloudFront may read only this prefix
    assert "_undertow/data-" not in t


def test_dashboard_api_requires_cognito_jwt():
    t = TEMPLATE.read_text()
    assert "AuthorizerType: JWT" in t and "AuthorizationType: JWT" in t
    assert "AllowAdminCreateUserOnly: true" in t                 # invite-only
    assert "AdminToken" not in t                                    # the old token is gone
    # the only function URL is the padded cell's sandbox origin, locked by the origin secret
    assert t.count("AWS::Lambda::Url") == 1 and "TargetFunctionArn: !GetAtt CellFunction.Arn" in t


def _router_code() -> str:
    t = TEMPLATE.read_text()
    block = t.split("FunctionCode: !Sub |", 1)[1].split("\n  CellRole:", 1)[0]
    return "\n".join(line[8:] for line in block.splitlines())


def test_cell_router_fails_open_and_routes_to_the_cell_origin():
    code = _router_code()
    assert "try {" in code and "catch (e)" in code and code.rstrip().endswith("}")
    assert "selectRequestOriginById('cell')" in code and "'ip:' + event.viewer.ip" in code
    t = TEMPLATE.read_text()
    assert "- Id: cell" in t and t.count("FunctionARN: !GetAtt CellRouter.FunctionMetadata.FunctionARN") == 2


def test_cell_router_is_valid_javascript(tmp_path):
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    f = tmp_path / "router.mjs"
    f.write_text(_router_code().replace("${CellStore.Id}", "kvs-id"))
    subprocess.run([node, "--check", str(f)], check=True)


def test_waf_inserted_headers_carry_the_origin_secret():
    t = TEMPLATE.read_text()
    for name in ("undertow-allow", "undertow-challenge"):
        after = t.split(f"Name: {name}", 1)[1].split("\n", 2)[1]
        assert "resolve:secretsmanager" in after and '"1"' not in after


def _tpl():
    import cfnlint.decode
    tpl, _ = cfnlint.decode.decode_str(TEMPLATE.read_text())
    return tpl


def _rules(tpl) -> list[dict]:
    """Web ACL rules, conditional ones included (their true branch)."""
    out = []
    for r in tpl["Resources"]["WebAcl"]["Properties"]["Rules"]:
        out.append(r["Fn::If"][1] if "Fn::If" in r else r)
    return out


NEW_RULES = {"aws-known-bad-inputs": (20, "None", "AWSManagedRulesKnownBadInputsRuleSet"),
             "aws-common": (21, "Count", "AWSManagedRulesCommonRuleSet"),
             "aws-sqli": (22, "Count", "AWSManagedRulesSQLiRuleSet"),
             "aws-anonymous-ip": (23, "Count", "AWSManagedRulesAnonymousIpList")}
# documented capacities of the AWS managed groups; an unknown group fails the capacity test below
MANAGED_WCU = {"AWSManagedRulesAntiDDoSRuleSet": 50, "AWSManagedRulesAmazonIpReputationList": 25,
               "AWSManagedRulesKnownBadInputsRuleSet": 200, "AWSManagedRulesCommonRuleSet": 700,
               "AWSManagedRulesSQLiRuleSet": 200, "AWSManagedRulesAnonymousIpList": 50}
LIVE_WCU_BEFORE = 182          # measured live before these rules, anti-DDoS 50 + IP reputation 25 included
FORM_RATE_WCU = 6              # estimate: rate-based 2 + two EXACTLY byte matches, no transformations
FLOOD_PATTERN_WCU = 30         # estimate, padded: two byte matches with LOWERCASE (24) when present


def test_five_protections_block_or_count_as_intended():
    from aa_ai import acl
    rules = {r["Name"]: r for r in _rules(_tpl())}
    for name, (prio, override, group) in NEW_RULES.items():
        r = rules[name]
        assert r["Priority"] == prio and list(r["OverrideAction"]) == [override], name
        assert r["Statement"]["ManagedRuleGroupStatement"] == {"VendorName": "AWS", "Name": group}
    prios = [r["Priority"] for r in _rules(_tpl())]
    assert len(prios) == len(set(prios)) and acl.FLOOD_PRIORITY not in prios
    f = rules["form-rate"]
    assert f["Priority"] == 24 and "form-rate" in acl.RETRY_RULES
    resp = f["Action"]["Block"]["CustomResponse"]
    assert resp["ResponseCode"] == 429 and resp["CustomResponseBodyKey"] == "generic"
    assert resp["ResponseHeaders"] == [{"Name": "retry-after", "Value": {"Ref": "RetryAfter"}}]
    rb = f["Statement"]["RateBasedStatement"]
    assert (rb["Limit"], rb["EvaluationWindowSec"], rb["AggregateKeyType"]) == (10, 300, "IP")
    path, method = rb["ScopeDownStatement"]["AndStatement"]["Statements"]
    assert path["ByteMatchStatement"]["SearchString"] == "/api/lead" and path["ByteMatchStatement"]["FieldToMatch"] == {"UriPath": {}}
    assert method["ByteMatchStatement"]["SearchString"] == "POST" and method["ByteMatchStatement"]["FieldToMatch"] == {"Method": {}}
    assert {s["ByteMatchStatement"]["PositionalConstraint"] for s in (path, method)} == {"EXACTLY"}


def test_web_acl_capacity_stays_under_1500():
    groups = [r["Statement"]["ManagedRuleGroupStatement"]["Name"] for r in _rules(_tpl())
              if "ManagedRuleGroupStatement" in r.get("Statement", {})]
    assert set(groups) <= set(MANAGED_WCU), "a managed group with no known capacity"
    custom_before = LIVE_WCU_BEFORE - MANAGED_WCU["AWSManagedRulesAntiDDoSRuleSet"] - MANAGED_WCU["AWSManagedRulesAmazonIpReputationList"]
    total = custom_before + sum(MANAGED_WCU[g] for g in groups) + FORM_RATE_WCU
    assert total == 1338 and total + FLOOD_PATTERN_WCU < 1500


def test_budget_alarm():
    tpl = _tpl()
    b = tpl["Resources"]["CostBudget"]
    assert b["Type"] == "AWS::Budgets::Budget" and tpl["Conditions"][b["Condition"]] == {"Fn::Not": [{"Fn::Equals": [{"Ref": "AlertEmail"}, ""]}]}
    p = b["Properties"]["Budget"]
    assert (p["BudgetType"], p["TimeUnit"]) == ("COST", "MONTHLY") and p["BudgetLimit"]["Amount"] == {"Ref": "MonthlyBudgetUsd"}
    assert tpl["Parameters"]["MonthlyBudgetUsd"]["Default"] == 100
    assert p["CostFilters"] == {"Service": ["AWS WAF", "Amazon CloudFront"]}
    n = {(x["Notification"]["NotificationType"], x["Notification"]["Threshold"]) for x in b["Properties"]["NotificationsWithSubscribers"]}
    assert n == {("ACTUAL", 80), ("FORECASTED", 100)}
    assert all(x["Subscribers"] == [{"SubscriptionType": "EMAIL", "Address": {"Ref": "AlertEmail"}}]
               for x in b["Properties"]["NotificationsWithSubscribers"])


def test_cost_permissions_and_tags():
    tpl = _tpl()
    stmts = tpl["Resources"]["TickRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    star = {a for s in stmts if s["Resource"] == "*" for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])}
    assert {"cloudwatch:GetMetricData", "ce:GetCostAndUsage", "ce:ListCostAllocationTags",
            "ce:UpdateCostAllocationTagsStatus", "cloudfront:ListDistributionsByWebACLId"} <= star
    assert not any(a.startswith(("ce:", "cloudwatch:")) and a not in star for s in stmts for a in s["Action"])
    root = Path(__file__).parent.parent
    assert "--tags undertow=engine" in (root / "infra" / "publish.sh").read_text()


def test_stack_parameter_files_carry_the_cost_tag(tmp_path, monkeypatch):
    import json
    import runpy
    env = {"ARTIFACT_BUCKET": "b", "KEY": "k", "DECOY_PREFIX": "/d", "DDB_PL": "pl-1", "SCORER_MODE": "observe",
           "ADMIN_CIDRS": "192.0.2.0/32", "TABLE": ""}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(Path(__file__).parent.parent / "infra" / "stack_params.py"), run_name="__main__")
    for name in ("store", "edge"):
        assert json.loads((tmp_path / "cfn" / f"{name}.json").read_text())["Tags"] == {"undertow": "engine"}


def test_the_tick_runs_in_its_own_function():
    import json
    r = _tpl()["Resources"]
    target = r["SnapshotSchedule"]["Properties"]["Targets"][0]
    assert target["Arn"] == {"Fn::GetAtt": ["TickFunction", "Arn"]} and json.loads(target["Input"]) == {"action": "snapshot"}
    assert r["SnapshotSchedulePermission"]["Properties"]["FunctionName"] == {"Ref": "TickFunction"}
    for sub in ("ScorerSubscription", "AppMovesSubscription", "CellMovesSubscription", "VerdictEventsSubscription"):
        assert r[sub]["Properties"]["DestinationArn"] == {"Fn::GetAtt": ["ScorerFunction", "Arn"]}, sub
    tick, scorer = r["TickFunction"]["Properties"], r["ScorerFunction"]["Properties"]
    assert (tick["Handler"], scorer["Handler"]) == ("aa_ai.scorer.tick_handler", "aa_ai.scorer.handler")
    assert tick["ReservedConcurrentExecutions"] >= 1 and scorer["ReservedConcurrentExecutions"] >= 1
    assert tick["Role"] == {"Fn::GetAtt": ["TickRole", "Arn"]} and scorer["Role"] == {"Fn::GetAtt": ["ScorerRole", "Arn"]}
    assert tick["Code"] == scorer["Code"] and tick["Layers"] == scorer["Layers"] and tick["Runtime"] == scorer["Runtime"]
    assert r["TickLogs"]["Properties"]["LogGroupName"] == {"Fn::Sub": "/aws/lambda/${TickFunction}"}
    assert r["TickLogs"]["Properties"]["RetentionInDays"] == 90
    inv = r["TickInvokeConfig"]["Properties"]
    assert inv["FunctionName"] == {"Ref": "TickFunction"} and (inv["MaximumRetryAttempts"], inv["MaximumEventAgeInSeconds"]) == (0, 60)
    env = tick["Environment"]["Variables"]
    assert {"DASHBOARD_BUCKET", "WEBACL_ID", "CANARY_USER", "COST_FUNCTIONS", "CELL_KVS_ARN", "VERDICT_URL"} <= set(env)
    # least privilege: the log-batch scorer cannot rewrite the web ACL, call the model, read the bill or publish
    def actions(role):
        out = set()
        for st in r[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]:
            out |= set(st["Action"] if isinstance(st["Action"], list) else [st["Action"]])
        return out
    tick_only = {"wafv2:UpdateWebACL", "bedrock-mantle:CreateInference", "ce:GetCostAndUsage", "s3:PutObject",
                 "iam:ListAccessKeys", "cloudwatch:GetMetricData", "sns:ListSubscriptionsByTopic"}
    assert not actions("ScorerRole") & tick_only and tick_only <= actions("TickRole")
