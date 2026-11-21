"""Dashboard user management on the Cognito user pool (admins only).

Invite-only: an invite makes Cognito email a temporary password; the user must set
their own at first sign-in. Nobody here, including the code, ever sees a password.
Guards: you cannot demote, disable or delete yourself, and the last admin stays.
"""
from __future__ import annotations

import re

ROLES = ("admin", "user")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")


class Refused(ValueError):
    pass


def _attr(u: dict, name: str) -> str:
    return next((a["Value"] for a in u.get("Attributes", u.get("UserAttributes", [])) if a["Name"] == name), "")


def _role(cog, pool: str, username: str) -> str:
    groups = [g["GroupName"] for g in cog.admin_list_groups_for_user(UserPoolId=pool, Username=username).get("Groups", [])]
    return "admin" if "admin" in groups else "user" if "user" in groups else "none"


def list_users(cog, pool: str) -> list[dict]:
    out, kw = [], {"UserPoolId": pool, "Limit": 60}
    while True:
        r = cog.list_users(**kw)
        for u in r.get("Users", []):
            out.append({"username": u["Username"], "email": _attr(u, "email"), "role": _role(cog, pool, u["Username"]),
                        "status": u.get("UserStatus", ""), "enabled": u.get("Enabled", True),
                        "created": u["UserCreateDate"].timestamp() if hasattr(u.get("UserCreateDate"), "timestamp")
                        else u.get("UserCreateDate", 0)})
        if not r.get("PaginationToken"):
            return sorted(out, key=lambda x: x["email"])
        kw["PaginationToken"] = r["PaginationToken"]


def _admins(cog, pool: str) -> set[str]:
    return {u["Username"] for u in cog.list_users_in_group(UserPoolId=pool, GroupName="admin").get("Users", [])
            if u.get("Enabled", True)}


def _get(cog, pool: str, username: str) -> dict:
    u = cog.admin_get_user(UserPoolId=pool, Username=username)
    return {"username": u["Username"], "email": _attr(u, "email"), "status": u.get("UserStatus", "")}


def manage(cog, pool: str, op: str, body: dict, me: str) -> dict:
    """me = the caller's Cognito username (sub)."""
    if op == "invite":
        email = str(body.get("email", "")).strip().lower()
        role = body.get("role", "user")
        if not EMAIL.match(email):
            raise Refused("enter a valid email address")
        if role not in ROLES:
            raise Refused("role is admin or user")
        u = cog.admin_create_user(UserPoolId=pool, Username=email, DesiredDeliveryMediums=["EMAIL"],
                                  UserAttributes=[{"Name": "email", "Value": email},
                                                  {"Name": "email_verified", "Value": "true"}])["User"]
        cog.admin_add_user_to_group(UserPoolId=pool, Username=u["Username"], GroupName=role)
        return {"invited": email, "role": role}

    username = str(body.get("username", ""))
    if not username:
        raise Refused("which user?")
    target = _get(cog, pool, username)
    username = target["username"]
    self_op = username == me

    if op == "role":
        role = body.get("role")
        if role not in ROLES:
            raise Refused("role is admin or user")
        if role == "user":
            if self_op:
                raise Refused("you cannot remove your own admin role")
            if _admins(cog, pool) <= {username}:
                raise Refused("keep at least one admin")
        cog.admin_add_user_to_group(UserPoolId=pool, Username=username, GroupName=role)
        other = "user" if role == "admin" else "admin"
        cog.admin_remove_user_from_group(UserPoolId=pool, Username=username, GroupName=other)
        return {"user": target["email"], "role": role}

    if op in ("disable", "delete"):
        if self_op:
            raise Refused(f"you cannot {op} yourself")
        if username in _admins(cog, pool) and _admins(cog, pool) <= {username}:
            raise Refused("keep at least one admin")
        if op == "disable":
            cog.admin_disable_user(UserPoolId=pool, Username=username)
            cog.admin_user_global_sign_out(UserPoolId=pool, Username=username)
        else:
            cog.admin_delete_user(UserPoolId=pool, Username=username)
        return {"user": target["email"], op + "d": True}

    if op == "enable":
        cog.admin_enable_user(UserPoolId=pool, Username=username)
        return {"user": target["email"], "enabled": True}

    if op in ("reset", "resend"):
        # an invited user who never signed in has no password to reset: send the invite again
        if op == "resend" or target["status"] == "FORCE_CHANGE_PASSWORD":
            cog.admin_create_user(UserPoolId=pool, Username=username, MessageAction="RESEND",
                                  DesiredDeliveryMediums=["EMAIL"])
            return {"user": target["email"], "resent_invite": True}
        cog.admin_reset_user_password(UserPoolId=pool, Username=username)
        return {"user": target["email"], "reset_code_sent": True}

    if op == "reset_mfa":
        # lost authenticator: turn it off; an admin is asked to set up a new one at next sign-in
        cog.admin_set_user_mfa_preference(UserPoolId=pool, Username=username,
                                          SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False})
        cog.admin_user_global_sign_out(UserPoolId=pool, Username=username)
        return {"user": target["email"], "mfa_reset": True}

    raise Refused(f"unknown user operation {op!r}")


def has_mfa(cog, pool: str, username: str) -> bool:
    u = cog.admin_get_user(UserPoolId=pool, Username=username)
    return "SOFTWARE_TOKEN_MFA" in (u.get("UserMFASettingList") or [])
