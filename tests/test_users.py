"""User management against an in-memory Cognito stand-in."""
import json
from datetime import datetime, timezone

import pytest

from aa_ai import admin, users
from test_scorer import FakeTable, FakeWaf, cfg


class Err(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code, "Message": code}}


class FakeCognito:
    def __init__(self):
        self.users = {}        # username -> dict
        self.groups = {"admin": set(), "user": set()}
        self.mail = []         # (kind, email): what Cognito would have emailed

    def _u(self, name):
        for u in self.users.values():
            if name in (u["Username"], u["email"]):
                return u
        raise Err("UserNotFoundException")

    def admin_create_user(self, UserPoolId, Username, DesiredDeliveryMediums=None, UserAttributes=None, MessageAction=None):
        if MessageAction == "RESEND":
            u = self._u(Username)
            self.mail.append(("invite", u["email"]))
            return {"User": u}
        if any(u["email"] == Username for u in self.users.values()):
            raise Err("UsernameExistsException")
        sub = f"sub-{len(self.users) + 1}"
        u = {"Username": sub, "email": Username, "UserStatus": "FORCE_CHANGE_PASSWORD", "Enabled": True,
             "UserCreateDate": datetime(2026, 11, 19, tzinfo=timezone.utc),
             "Attributes": [{"Name": "email", "Value": Username}]}
        self.users[sub] = u
        self.mail.append(("invite", Username))
        return {"User": u}

    def admin_get_user(self, UserPoolId, Username):
        u = self._u(Username)
        return {"Username": u["Username"], "UserStatus": u["UserStatus"], "UserAttributes": u["Attributes"],
                **({"UserMFASettingList": ["SOFTWARE_TOKEN_MFA"]} if u.get("mfa") else {})}

    def admin_set_user_mfa_preference(self, UserPoolId, Username, SoftwareTokenMfaSettings):
        self._u(Username)["mfa"] = SoftwareTokenMfaSettings["Enabled"]

    def admin_add_user_to_group(self, UserPoolId, Username, GroupName):
        self.groups[GroupName].add(self._u(Username)["Username"])

    def admin_remove_user_from_group(self, UserPoolId, Username, GroupName):
        self.groups[GroupName].discard(self._u(Username)["Username"])

    def admin_list_groups_for_user(self, UserPoolId, Username):
        n = self._u(Username)["Username"]
        return {"Groups": [{"GroupName": g} for g, m in self.groups.items() if n in m]}

    def list_users(self, UserPoolId, Limit, PaginationToken=None):
        return {"Users": list(self.users.values())}

    def list_users_in_group(self, UserPoolId, GroupName):
        return {"Users": [self.users[n] for n in self.groups[GroupName]]}

    def admin_disable_user(self, UserPoolId, Username):
        self._u(Username)["Enabled"] = False

    def admin_enable_user(self, UserPoolId, Username):
        self._u(Username)["Enabled"] = True

    def admin_user_global_sign_out(self, UserPoolId, Username):
        pass

    def admin_delete_user(self, UserPoolId, Username):
        n = self._u(Username)["Username"]
        del self.users[n]
        for m in self.groups.values():
            m.discard(n)

    def admin_reset_user_password(self, UserPoolId, Username):
        self.mail.append(("reset", self._u(Username)["email"]))


@pytest.fixture
def pool():
    cog = FakeCognito()
    me = users.manage(cog, "p", "invite", {"email": "owner@example.com", "role": "admin"}, me="")
    assert me["role"] == "admin"
    return cog


def me_of(cog):
    return next(u["Username"] for u in cog.users.values() if u["email"] == "owner@example.com")


def test_invite_sends_cognito_email_and_sets_role(pool):
    users.manage(pool, "p", "invite", {"email": "Analyst@Example.com", "role": "user"}, me_of(pool))
    listed = {u["email"]: u for u in users.list_users(pool, "p")}
    assert listed["analyst@example.com"]["role"] == "user"          # emails are lower-cased
    assert ("invite", "analyst@example.com") in pool.mail
    with pytest.raises(users.Refused):
        users.manage(pool, "p", "invite", {"email": "not-an-email", "role": "user"}, me_of(pool))
    with pytest.raises(users.Refused):
        users.manage(pool, "p", "invite", {"email": "x@example.com", "role": "root"}, me_of(pool))


def test_cannot_lock_yourself_out_or_remove_the_last_admin(pool):
    me = me_of(pool)
    for op in ("disable", "delete"):
        with pytest.raises(users.Refused):
            users.manage(pool, "p", op, {"username": me}, me)
    with pytest.raises(users.Refused):
        users.manage(pool, "p", "role", {"username": me, "role": "user"}, me)
    users.manage(pool, "p", "invite", {"email": "b@example.com", "role": "admin"}, me)
    other = next(u["Username"] for u in pool.users.values() if u["email"] == "b@example.com")
    users.manage(pool, "p", "role", {"username": other, "role": "user"}, me)    # two admins -> fine
    assert users._role(pool, "p", other) == "user"


def test_reset_for_never_signed_in_user_resends_the_invite(pool):
    me = me_of(pool)
    users.manage(pool, "p", "invite", {"email": "c@example.com", "role": "user"}, me)
    c = next(u for u in pool.users.values() if u["email"] == "c@example.com")
    assert users.manage(pool, "p", "reset", {"username": c["Username"]}, me) == {"user": "c@example.com", "resent_invite": True}
    c["UserStatus"] = "CONFIRMED"
    assert users.manage(pool, "p", "reset", {"username": c["Username"]}, me)["reset_code_sent"]
    assert pool.mail[-1] == ("reset", "c@example.com")


def test_users_api_is_admin_only_and_audited(pool):
    t, w = FakeTable(), FakeWaf()
    me = me_of(pool)

    def ev(method, groups, body=None):
        return {"headers": {}, "rawPath": "/_undertow/api/users", "body": json.dumps(body) if body else "",
                "requestContext": {"http": {"method": method, "sourceIp": "1.1.1.1"},
                                   "authorizer": {"jwt": {"claims": {"sub": me, "cognito:username": me,
                                                                     "email": "owner@example.com",
                                                                     "cognito:groups": groups}}}}}

    assert admin.handle(ev("GET", "[user]"), t, w, cfg(), cog=pool, pool="p")["statusCode"] == 403
    admin._MFA_CACHE.clear()
    r = admin.handle(ev("GET", "[admin]"), t, w, cfg(), cog=pool, pool="p")
    assert r["statusCode"] == 403 and "mfa_required" in r["body"]       # an admin without MFA can do nothing
    pool._u(me)["mfa"] = True
    r = admin.handle(ev("GET", "[admin]"), t, w, cfg(), cog=pool, pool="p")
    assert r["statusCode"] == 200 and json.loads(r["body"])["users"][0]["email"] == "owner@example.com"
    r = admin.handle(ev("POST", "[admin]", {"op": "invite", "email": "owner@example.com"}), t, w, cfg(), cog=pool, pool="p")
    assert r["statusCode"] == 400                                     # already exists: a clean message, not a 500
    r = admin.handle(ev("POST", "[admin]", {"op": "delete", "username": me}), t, w, cfg(), cog=pool, pool="p")
    assert r["statusCode"] == 400 and "yourself" in json.loads(r["body"])["error"]
    assert any(v.get("action") == "users.delete" for (pk, _), v in t.items.items() if pk == "AUDIT") is False


def test_admin_mfa_check_fails_closed_and_can_be_reset(pool):
    me = me_of(pool)
    admin._MFA_CACHE.clear()

    class Down:
        def admin_get_user(self, **kw):
            raise RuntimeError("cognito unreachable")
    assert admin._mfa_ok(Down(), "p", me) is False
    users.manage(pool, "p", "invite", {"email": "b@example.com", "role": "admin"}, me)
    b = next(u for u in pool.users.values() if u["email"] == "b@example.com")
    b["mfa"] = True
    assert users.manage(pool, "p", "reset_mfa", {"username": b["Username"]}, me)["mfa_reset"]
    assert not users.has_mfa(pool, "p", b["Username"])
