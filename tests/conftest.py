"""Shared test helpers.

The helpers here deliberately drive the *real* parse -> classify -> grade
pipeline rather than constructing model objects by hand. A test that builds an
``ExposureAssessment`` itself and asserts on it proves nothing; a test that
feeds in a trust policy and asserts on the grade proves the rubric.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

import pytest

# Make `src/` importable even when pytest is invoked from an unexpected rootdir.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from trustedge import analyzer  # noqa: E402
from trustedge.models import AnalysisResult, Finding  # noqa: E402
from trustedge.parser import parse_export  # noqa: E402

ACCOUNT = "111122223333"
EXTERNAL_ACCOUNT = "444455556666"
GITHUB_ISSUER = "token.actions.githubusercontent.com"
GITHUB_PROVIDER_ARN = (
    "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
)
EKS_ISSUER = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
EKS_PROVIDER_ARN = "arn:aws:iam::111122223333:oidc-provider/" + EKS_ISSUER
SAML_PROVIDER_ARN = "arn:aws:iam::111122223333:saml-provider/CorpDirectory"

FIXTURES = os.path.join(_ROOT, "fixtures")


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


@pytest.fixture(scope="session")
def sample_account_path() -> str:
    return fixture_path("sample-account.json")


@pytest.fixture(scope="session")
def malformed_path() -> str:
    return fixture_path("malformed-export.json")


@pytest.fixture(scope="session")
def minimal_path() -> str:
    return fixture_path("minimal-export.json")


@pytest.fixture(scope="session")
def authorization_details_path() -> str:
    return fixture_path("authorization-details-sample.json")


@pytest.fixture(scope="session")
def sample_result(sample_account_path: str) -> AnalysisResult:
    return analyzer.analyze_file(sample_account_path, include_internal=True)


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def build_export_document(
    statements: List[Dict[str, Any]],
    *,
    account_id: Optional[str] = ACCOUNT,
    role_name: str = "test-role",
    inline_policies: Optional[List[Dict[str, Any]]] = None,
    attached: Optional[List[Dict[str, Any]]] = None,
    managed_policies: Optional[List[Dict[str, Any]]] = None,
    **extra: Any
) -> Dict[str, Any]:
    """Build a one-role export document around the given trust statements."""
    role: Dict[str, Any] = {
        "role_name": role_name,
        "assume_role_policy_document": {
            "Version": "2012-10-17",
            "Statement": statements,
        },
    }
    if account_id:
        role["arn"] = "arn:aws:iam::%s:role/%s" % (account_id, role_name)
    if inline_policies is not None:
        role["inline_policies"] = inline_policies
    if attached is not None:
        role["attached_managed_policies"] = attached

    document: Dict[str, Any] = {"roles": [role]}
    if account_id:
        document["account_id"] = account_id
    if managed_policies is not None:
        document["managed_policies"] = managed_policies
    document.update(extra)
    return document


def analyze_statements(
    statements: List[Dict[str, Any]], **kwargs: Any
) -> AnalysisResult:
    """Run the whole pipeline over a synthetic one-role export."""
    document = build_export_document(statements, **kwargs)
    export, issues = parse_export(document, source="test")
    return analyzer.analyze(
        export, issues=issues, input_path="test", include_internal=True
    )


def only_finding(statements: List[Dict[str, Any]], **kwargs: Any) -> Finding:
    """Analyse and return the single expected finding."""
    result = analyze_statements(statements, **kwargs)
    assert len(result.findings) == 1, (
        "expected exactly one finding, got %d: %s"
        % (len(result.findings), [f.finding_id for f in result.findings])
    )
    return result.findings[0]


def weakness_codes(finding: Finding) -> List[str]:
    return [w.code for w in finding.exposure.weak_conditions]


def capability_codes(finding: Finding) -> List[str]:
    return [c.code for c in finding.blast_radius.capabilities]


# --------------------------------------------------------------------------
# Reusable permission policies
# --------------------------------------------------------------------------

ADMIN_INLINE = [
    {
        "policy_name": "admin",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
    }
]

HARMLESS_INLINE = [
    {
        "policy_name": "harmless",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:GetCallerIdentity",
                    "Resource": "*",
                }
            ],
        },
    }
]

SECRETS_INLINE = [
    {
        "policy_name": "secrets",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        },
    }
]


def github_statement(
    condition: Optional[Dict[str, Any]] = None,
    action: str = "sts:AssumeRoleWithWebIdentity",
    sid: str = "GitHub",
) -> Dict[str, Any]:
    statement: Dict[str, Any] = {
        "Sid": sid,
        "Effect": "Allow",
        "Principal": {"Federated": GITHUB_PROVIDER_ARN},
        "Action": action,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def github_sub_condition(sub: Any, operator: str = "StringEquals") -> Dict[str, Any]:
    """A GitHub condition block that always pins the audience, plus a subject."""
    condition: Dict[str, Any] = {
        "StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"}
    }
    if operator == "StringEquals":
        condition["StringEquals"][GITHUB_ISSUER + ":sub"] = sub
    else:
        condition[operator] = {GITHUB_ISSUER + ":sub": sub}
    return condition


def cross_account_statement(
    principal: str = "arn:aws:iam::444455556666:root",
    condition: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    statement: Dict[str, Any] = {
        "Effect": "Allow",
        "Principal": {"AWS": principal},
        "Action": "sts:AssumeRole",
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement
