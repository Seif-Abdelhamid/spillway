import pytest

from spillway.iam import analyze_identity_policies, analyze_roles
from spillway.loader import parse_document
from tests.helpers import allow, plan, policy, res

GH = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"


def roles(trust: str, account_id=None, unknown=None):
    doc = plan(res("aws_iam_role.r", {"name": "r", "assume_role_policy": trust}, unknown=unknown))
    return analyze_roles(parse_document(doc).after, account_id)


def identity(doc: str, rtype="aws_iam_policy"):
    return analyze_identity_policies(parse_document(plan(res(f"{rtype}.p", {"policy": doc}))).after)


def assume(principal, **extra):
    return allow(principal=principal, action="sts:AssumeRole", resource=None, **extra) | {"Resource": None}


def trust_doc(*stmts):
    # Trust policies have no Resource element.
    return policy(*({k: v for k, v in s.items() if k != "Resource"} for s in stmts))


def test_trust_policy_open_to_everyone_is_critical():
    [f] = roles(trust_doc(assume("*")))
    assert (f.rule_id, f.severity) == ("SPW101", "critical")


def test_trust_policy_open_but_restricted_to_org_is_fine():
    assert roles(trust_doc(assume({"AWS": "*"}, Condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}))) == []


def test_trust_policy_with_undecidable_condition_is_high_and_conditional():
    [f] = roles(trust_doc(assume("*", Condition={"StringEquals": {"aws:PrincipalTag/team": "x"}})))
    assert (f.rule_id, f.severity) == ("SPW101", "high")
    assert "conditional" in f.message


def test_cross_account_trust_without_external_id():
    doc = trust_doc(assume({"AWS": "arn:aws:iam::999988887777:root"}))
    [f] = roles(doc, account_id="111122223333")
    assert (f.rule_id, f.severity, f.key) == ("SPW102", "medium", "999988887777")
    [f] = roles(doc)
    assert f.severity == "info"


def test_cross_account_trust_guarded_by_external_id_or_own_account():
    guarded = trust_doc(assume({"AWS": "999988887777"}, Condition={"StringEquals": {"sts:ExternalId": "abc"}}))
    assert roles(guarded, account_id="111122223333") == []
    own = trust_doc(assume({"AWS": "arn:aws:iam::111122223333:role/ci"}))
    assert roles(own, account_id="111122223333") == []


def oidc(condition):
    stmt = {"Sid": "GH", "Effect": "Allow", "Principal": {"Federated": GH}, "Action": "sts:AssumeRoleWithWebIdentity"}
    if condition:
        stmt["Condition"] = condition
    return policy(stmt)


@pytest.mark.parametrize(
    "condition",
    [
        None,
        {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
        {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}},
        {"StringLike": {"token.actions.githubusercontent.com:sub": "*"}},
        {"StringLike": {"token.actions.githubusercontent.com:sub": ["repo:my-org/app:*", "repo:*/app:*"]}},
    ],
)
def test_github_oidc_trust_not_pinned_to_a_repo_is_critical(condition):
    [f] = roles(oidc(condition))
    assert (f.rule_id, f.severity) == ("SPW103", "critical")


@pytest.mark.parametrize(
    "sub",
    ["repo:my-org/app:ref:refs/heads/main", "repo:my-org/app:environment:prod", "repo:my-org/*"],
)
def test_github_oidc_trust_pinned_to_an_owner_is_fine(sub):
    assert roles(oidc({"StringEquals": {"token.actions.githubusercontent.com:sub": sub}})) == []


def test_unknown_trust_policy_fails_closed():
    [f] = roles("", unknown={"assume_role_policy": True})
    assert f.rule_id == "SPW005"


def test_identity_policy_admin_wildcard():
    found = identity(policy(allow(principal=None, action="*", resource="*")))
    assert [f.rule_id for f in found] == ["SPW201"]


def test_identity_policy_service_wildcard_and_passrole():
    doc = policy(allow(principal=None, action=["s3:*", "iam:PassRole"], resource="*"))
    assert sorted(f.rule_id for f in identity(doc, "aws_iam_role_policy")) == ["SPW202", "SPW203"]


def test_passrole_via_iam_wildcard_is_caught():
    found = identity(policy(allow(principal=None, action="iam:*", resource="*")))
    assert sorted(f.rule_id for f in found) == ["SPW202", "SPW203"]


def test_scoped_identity_policy_is_clean():
    doc = policy(allow(principal=None, action=["s3:*", "iam:PassRole"], resource="arn:aws:s3:::b/*"))
    assert identity(doc) == []


def test_allow_with_not_action():
    doc = policy({"Sid": "N", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert [f.rule_id for f in identity(doc, "aws_iam_user_policy")] == ["SPW204"]


def test_malformed_identity_policy_fails_closed():
    assert [f.rule_id for f in identity("{")] == ["SPW005"]
