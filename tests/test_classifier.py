"""Principal classification tests.

The load-bearing assertion in this file is the one that separates TrustEdge
from a permission scanner: classification depends only on the Principal
element, never on what the role is allowed to do.
"""

from __future__ import annotations

import pytest

from conftest import (
    ACCOUNT,
    EKS_PROVIDER_ARN,
    GITHUB_PROVIDER_ARN,
    SAML_PROVIDER_ARN,
    ADMIN_INLINE,
    HARMLESS_INLINE,
    analyze_statements,
    only_finding,
)
from trustedge.models import PrincipalClass, ProviderKind


def classify(principal, **kwargs):
    """Return the single classified principal for a trust statement."""
    statement = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "sts:AssumeRole",
    }
    finding = only_finding([statement], **kwargs)
    return finding.principal


class TestAwsPrincipals:
    def test_same_account_role_arn(self):
        principal = classify({"AWS": "arn:aws:iam::%s:role/Other" % ACCOUNT})
        assert principal.principal_class == PrincipalClass.SAME_ACCOUNT
        assert principal.account_id == ACCOUNT

    def test_same_account_root(self):
        principal = classify({"AWS": "arn:aws:iam::%s:root" % ACCOUNT})
        assert principal.principal_class == PrincipalClass.SAME_ACCOUNT
        assert "all principals" in principal.label

    def test_cross_account_root(self):
        principal = classify({"AWS": "arn:aws:iam::444455556666:root"})
        assert principal.principal_class == PrincipalClass.CROSS_ACCOUNT
        assert principal.account_id == "444455556666"

    def test_bare_account_id_is_the_account_root(self):
        principal = classify({"AWS": "444455556666"})
        assert principal.principal_class == PrincipalClass.CROSS_ACCOUNT
        assert "all principals" in principal.label

    def test_cross_account_role_arn_names_the_role(self):
        principal = classify({"AWS": "arn:aws:iam::444455556666:role/Integration"})
        assert principal.principal_class == PrincipalClass.CROSS_ACCOUNT
        assert "Integration" in principal.label

    def test_assumed_role_session_arn(self):
        principal = classify(
            {"AWS": "arn:aws:sts::444455556666:assumed-role/Role/session"}
        )
        assert principal.principal_class == PrincipalClass.CROSS_ACCOUNT
        assert any("session ARN" in note for note in principal.notes)

    def test_wildcard_string_principal(self):
        principal = classify("*")
        assert principal.principal_class == PrincipalClass.WILDCARD

    def test_wildcard_aws_principal(self):
        principal = classify({"AWS": "*"})
        assert principal.principal_class == PrincipalClass.WILDCARD
        assert principal.provider_kind == ProviderKind.ANY_AWS_PRINCIPAL

    def test_partial_wildcard_arn_is_unclassified_and_explained(self):
        principal = classify({"AWS": "arn:aws:iam::*:role/Deploy"})
        assert principal.principal_class == PrincipalClass.UNKNOWN
        assert any("partial wildcards" in note for note in principal.notes)

    def test_unknown_relationship_when_the_account_is_not_stated(self):
        principal = classify({"AWS": "arn:aws:iam::444455556666:root"}, account_id=None)
        assert principal.principal_class == PrincipalClass.UNKNOWN
        assert any("does not identify the account" in note for note in principal.notes)


class TestServicePrincipals:
    def test_generic_service(self):
        principal = classify({"Service": "delivery.logs.amazonaws.com"})
        assert principal.principal_class == PrincipalClass.AWS_SERVICE
        assert principal.provider_id == "delivery.logs.amazonaws.com"

    def test_roles_anywhere_gets_its_own_class(self):
        principal = classify({"Service": "rolesanywhere.amazonaws.com"})
        assert principal.principal_class == PrincipalClass.ROLES_ANYWHERE
        assert principal.provider_kind == ProviderKind.ROLES_ANYWHERE

    def test_eks_pod_identity_is_labelled(self):
        principal = classify({"Service": "pods.eks.amazonaws.com"})
        assert principal.provider_kind == ProviderKind.EKS_POD_IDENTITY

    def test_service_list_produces_one_principal_each(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "delivery.logs.amazonaws.com",
                            "vpc-flow-logs.amazonaws.com",
                        ]
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        )
        assert len(result.findings) == 2


class TestFederatedPrincipals:
    def test_github_oidc(self):
        principal = classify({"Federated": GITHUB_PROVIDER_ARN})
        assert principal.principal_class == PrincipalClass.OIDC
        assert principal.provider_kind == ProviderKind.GITHUB_ACTIONS
        assert principal.provider_id == "token.actions.githubusercontent.com"

    def test_eks_irsa_issuer_is_recognised_as_private(self):
        principal = classify({"Federated": EKS_PROVIDER_ARN})
        assert principal.provider_kind == ProviderKind.EKS_IRSA

    def test_saml_provider(self):
        principal = classify({"Federated": SAML_PROVIDER_ARN})
        assert principal.principal_class == PrincipalClass.SAML
        assert principal.provider_id == "CorpDirectory"

    def test_builtin_cognito_issuer(self):
        principal = classify({"Federated": "cognito-identity.amazonaws.com"})
        assert principal.principal_class == PrincipalClass.OIDC
        assert principal.provider_kind == ProviderKind.COGNITO

    def test_unknown_private_issuer(self):
        principal = classify(
            {
                "Federated": "arn:aws:iam::111122223333:oidc-provider/"
                "idp.internal.example.com"
            }
        )
        assert principal.provider_kind == ProviderKind.PRIVATE_OIDC
        assert any("shared-OIDC-provider list" in note for note in principal.notes)

    def test_bare_issuer_url_is_accepted_with_a_note(self):
        principal = classify({"Federated": "gitlab.com"})
        assert principal.principal_class == PrincipalClass.OIDC
        assert any("provider ARN" in note for note in principal.notes)

    def test_nonsense_federated_value_is_unclassified(self):
        principal = classify({"Federated": "not-a-provider"})
        assert principal.principal_class == PrincipalClass.UNKNOWN


class TestCanonicalUser:
    def test_canonical_user_is_not_guessed_at(self):
        principal = classify({"CanonicalUser": "abc123def456"})
        assert principal.principal_class == PrincipalClass.CANONICAL_USER


class TestPrincipalBlockRobustness:
    def test_unknown_principal_key_is_reported_and_skipped(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Robot": "beep",
                        "AWS": "arn:aws:iam::444455556666:root",
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        )
        assert len(result.findings) == 1
        assert "principal_key_unknown" in [i.code for i in result.issues]

    def test_wrong_case_principal_key_is_accepted_with_a_warning(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"aws": "arn:aws:iam::444455556666:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        )
        assert len(result.findings) == 1
        assert "principal_key_case" in [i.code for i in result.issues]

    def test_non_string_principal_value_is_skipped(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["ec2.amazonaws.com", 7]},
                    "Action": "sts:AssumeRole",
                }
            ]
        )
        assert "principal_value_malformed" in [i.code for i in result.issues]

    def test_missing_principal_is_reported(self):
        result = analyze_statements(
            [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        )
        assert result.findings == []
        assert "principal_missing" in [i.code for i in result.issues]

    def test_empty_principal_list_is_reported(self):
        result = analyze_statements(
            [{"Effect": "Allow", "Principal": {"AWS": []}, "Action": "sts:AssumeRole"}]
        )
        assert result.findings == []
        assert "principal_value_empty" in [i.code for i in result.issues]

    def test_non_wildcard_string_principal_is_rejected(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::444455556666:root",
                    "Action": "sts:AssumeRole",
                }
            ]
        )
        assert "principal_string_not_wildcard" in [i.code for i in result.issues]


class TestTrustIsNotPermissions:
    """The distinction the whole project rests on."""

    @pytest.mark.parametrize("policies", [ADMIN_INLINE, HARMLESS_INLINE])
    def test_classification_ignores_the_role_permissions(self, policies):
        principal = classify(
            {"AWS": "arn:aws:iam::444455556666:root"}, inline_policies=policies
        )
        assert principal.principal_class == PrincipalClass.CROSS_ACCOUNT

    def test_exposure_grade_ignores_the_role_permissions(self):
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
            "Action": "sts:AssumeRole",
        }
        admin = only_finding([statement], inline_policies=ADMIN_INLINE)
        harmless = only_finding([statement], inline_policies=HARMLESS_INLINE)
        assert admin.exposure.grade == harmless.exposure.grade
        # ...but the blast radius, and therefore the rank, must differ.
        assert admin.blast_radius.tier != harmless.blast_radius.tier
        assert admin.risk_score > harmless.risk_score
