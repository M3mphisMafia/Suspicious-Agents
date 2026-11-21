"""Edge controls that live inside the WAF web ACL itself: login rate limit, Retry-After,
country and network (ASN) blocks.

The admin API applies them immediately with UpdateWebACL; the pipeline reads the same
saved policy on every deploy and passes it as stack parameters, so CloudFormation and
the running ACL agree (between deploys CloudFormation drift detection will show them).

Flood mode's pattern rule is not in the template: the scorer's tick adds it, keeps it there
(a deploy that resets the rules loses it for at most a minute) and removes it when it expires.
"""
from __future__ import annotations

import copy
import json
import re

RETRY_RULES = ("flagged-ip", "flagged-ja4", "auth-host-wide-rate", "form-rate")
GEO_RULE, ASN_RULE = "geo-block", "asn-block"
GEO_PRIORITY, ASN_PRIORITY = 14, 15
# flood mode's one live rule; 17-18 are the AWS managed groups, so 19 is the first free slot
FLOOD_RULE, FLOOD_PRIORITY = "flood-pattern", 19
ISO2 = re.compile(r"^[A-Z]{2}$")

DEFAULT_EDGE = {"auth_rate": 100, "retry_after": 9, "geo": [], "asn": []}


def validate(edge: dict) -> dict:
    out = {}
    if "auth_rate" in edge:
        v = int(edge["auth_rate"])
        if not 10 <= v <= 20000:
            raise ValueError("login limit must be 10-20000 per minute per IP")
        out["auth_rate"] = v
    if "retry_after" in edge:
        v = int(edge["retry_after"])
        if not 1 <= v <= 60:
            raise ValueError("Retry-After must be 1-60 seconds")
        out["retry_after"] = v
    if "geo" in edge:
        codes = sorted({str(c).strip().upper() for c in edge["geo"] if str(c).strip()})
        if any(not ISO2.match(c) for c in codes) or len(codes) > 50:
            raise ValueError("countries are 2-letter ISO codes, at most 50")
        out["geo"] = codes
    if "asn" in edge:
        asns = sorted({int(a) for a in edge["asn"] if str(a).strip()})
        if any(not 1 <= a <= 4294967295 for a in asns) or len(asns) > 100:
            raise ValueError("ASNs are numbers, at most 100")
        out["asn"] = asns
    return out


def _vis(name: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": f"aa-ai-{name}"}


def _block(code: int, retry_after: int | None = None) -> dict:
    resp = {"ResponseCode": code, "CustomResponseBodyKey": "generic"}
    if retry_after is not None:
        resp["ResponseHeaders"] = [{"Name": "retry-after", "Value": str(retry_after)}]
    return {"Block": {"CustomResponse": resp}}


def patch_rules(rules: list[dict], edge: dict) -> list[dict]:
    e = {**DEFAULT_EDGE, **edge}
    out = []
    for r in copy.deepcopy(rules):
        if r["Name"] in (GEO_RULE, ASN_RULE):
            continue                                   # rebuilt below from the policy
        if r["Name"] in RETRY_RULES:
            r["Action"] = _block(429, e["retry_after"])
        if r["Name"] == "auth-host-wide-rate":
            r["Statement"]["RateBasedStatement"]["Limit"] = int(e["auth_rate"])
        if r["Name"] == FLOOD_RULE and "Block" in r.get("Action", {}):
            r["Action"] = _block(429, e["retry_after"])   # kept as is; only a block's Retry-After follows policy
        out.append(r)
    if e["geo"]:
        out.append({"Name": GEO_RULE, "Priority": GEO_PRIORITY, "Action": _block(403),
                    "Statement": {"GeoMatchStatement": {"CountryCodes": list(e["geo"])}}, "VisibilityConfig": _vis(GEO_RULE)})
    if e["asn"]:
        out.append({"Name": ASN_RULE, "Priority": ASN_PRIORITY, "Action": _block(403),
                    "Statement": {"AsnMatchStatement": {"AsnList": [int(a) for a in e["asn"]]}}, "VisibilityConfig": _vis(ASN_RULE)})
    return sorted(out, key=lambda r: r["Priority"])


KEEP = ("DefaultAction", "Description", "VisibilityConfig", "CustomResponseBodies", "CaptchaConfig",
        "ChallengeConfig", "TokenDomains", "AssociationConfig", "DataProtectionConfig")


def _update(waf, name: str, acl_id: str, got: dict, rules: list[dict]):
    acl = got["WebACL"]
    # get_web_acl returns Description: "" which update_web_acl rejects (min length 1): drop empties
    kw = {k: acl[k] for k in KEEP if acl.get(k) not in (None, "", [], {})}
    waf.update_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, Rules=rules, LockToken=got["LockToken"], **kw)


def apply(waf, name: str, acl_id: str, edge: dict) -> bool:
    """Patch the live ACL to match the policy. Returns True if it wrote."""
    if not acl_id:
        return False
    got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
    acl = got["WebACL"]
    rules = patch_rules(acl["Rules"], edge)
    if rules == acl["Rules"]:
        return False
    _update(waf, name, acl_id, got, rules)
    return True


# ---------- flood mode's pattern rule ----------

_MATCH = {"user_agent": {"SingleHeader": {"Name": "user-agent"}},
          "ja4": {"JA4Fingerprint": {"FallbackBehavior": "NO_MATCH"}},
          "path_prefix": {"UriPath": {}}}


def _bytes(value: str, field_to_match: dict, constraint: str, transform: str = "NONE") -> dict:
    return {"ByteMatchStatement": {"SearchString": value.encode()[:200], "FieldToMatch": field_to_match,
                                   "TextTransformations": [{"Priority": 0, "Type": transform}],
                                   "PositionalConstraint": constraint}}


def flood_rule(field: str, value: str, action: str, retry_after: int = 9) -> dict:
    """The one rule flood mode may add: Challenge, or Block 429 with the generic body."""
    match = _bytes(value, _MATCH[field], "EXACTLY" if field == "ja4" else "STARTS_WITH",
                   "LOWERCASE" if field == "path_prefix" else "NONE")
    # operators must keep their console mid-flood: a challenge would break its API calls
    console = {"NotStatement": {"Statement": _bytes("/_undertow/", {"UriPath": {}}, "STARTS_WITH", "LOWERCASE")}}
    return {"Name": FLOOD_RULE, "Priority": FLOOD_PRIORITY,
            "Action": _block(429, retry_after) if action == "block" else {"Challenge": {}},
            "Statement": {"AndStatement": {"Statements": [match, console]}}, "VisibilityConfig": _vis(FLOOD_RULE)}


def _canon(rule) -> str:
    # get_web_acl returns SearchString as bytes; compare by content so an unchanged rule is never rewritten
    return json.dumps(rule, sort_keys=True, default=lambda b: b.decode("utf-8", "replace"))


def apply_flood(waf, name: str, acl_id: str, rule: dict | None) -> bool:
    """Put the live flood-pattern rule, or remove it (rule=None). Every other rule is left exactly
    as it is. Idempotent, so the tick can re-apply after a deploy resets the ACL. True if it wrote."""
    if not acl_id:
        return False
    got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
    have = got["WebACL"]["Rules"]
    if _canon(next((r for r in have if r["Name"] == FLOOD_RULE), None)) == _canon(rule):
        return False
    rules = [r for r in have if r["Name"] != FLOOD_RULE]
    if rule is not None:
        if any(r["Priority"] == rule["Priority"] for r in rules):
            raise ValueError(f"priority {rule['Priority']} is taken in the live web ACL")
        rules = sorted([*rules, rule], key=lambda r: r["Priority"])
    _update(waf, name, acl_id, got, rules)
    return True


def stack_params(edge: dict) -> dict:
    """Policy -> edge-shield.yaml parameters, used by infra/stack_params.py."""
    e = {**DEFAULT_EDGE, **edge}
    return {"AuthRatePer60s": str(e["auth_rate"]), "RetryAfter": str(e["retry_after"]),
            "GeoBlockCountries": ",".join(e["geo"]), "AsnBlock": ",".join(str(a) for a in e["asn"])}
