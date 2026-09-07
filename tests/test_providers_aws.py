"""Cross-account, wildcard and service-principal rubric tests."""

from __future__ import annotations

import pytest

from conftest import (
    ACCOUNT,
    ADMIN_INLINE,
    EXTERNAL_ACCOUNT,
    HARMLESS_INLINE,
    SECRETS_INLINE,
    analyze_statements,
    cross_account_statement,
    only_finding,
    weakness_codes,
)
from trustedge.models import ExposureGrade
from trustedge.providers.aws import (
    COMPUTE_ATTACHMENT_SERVICES,
    EXTERNAL_ID_MIN_LENGTH,
)

STRONG_EXTERNAL_ID = "EXAMPLE-3f9a2c7b14d8e05f6a"
VENDOR_MAP = {EXTERNAL_ACCOUNT: {"vendor": "Example Corp"}}


def external_id_condition(value):
    return {"StringEquals": {"sts:ExternalId": value}}


class TestSameAccount:
    def test_same_account_is_graded_internal(self):
        finding = only_finding(
            [cross_account_statement("arn:aws:iam::%s:role/Other" % ACCOUNT)],
            inline_policies=ADMIN_INLINE,
        )
        assert finding.exposure.grade == ExposureGrade.INTERNAL

    def test_same_account_admin_role_is_low_not_critical(self):
        finding = only_finding(
            [cross_account_statement("arn:aws:iam::%s:root" % ACCOUNT)],
            inline_policies=ADMIN_INLINE,
        )
        assert finding.severity == "LOW"

    def test_account_root_delegation_is_explained(self):
        finding = only_finding(
            [cross_account_statement("arn:aws:iam::%s:root" % ACCOUNT)]
        )
        assert "identity-based policies" in " ".join(finding.exposure.reasoning)

    def test_internal_findings_are_suppressed_by_default(self, minimal_path):
        from trustedge import analyzer

        with_internal = analyzer.analyze_file(minimal_path, include_internal=True)
        without = analyzer.analyze_file(minimal_path, include_internal=False)
        assert len(without.findings) <= len(with_internal.findings)


class TestCrossAccount:
    def test_account_root_without_external_id_is_weak(self):
        finding = only_finding(
            [cross_account_statement()], vendor_accounts=VENDOR_MAP
        )
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "external_id_missing" in weakness_codes(finding)

    def test_named_role_without_external_id_is_moderate(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "arn:aws:iam::%s:role/Integration" % EXTERNAL_ACCOUNT
                )
            ],
            vendor_accounts=VENDOR_MAP,
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_strong_external_id_improves_the_grade(self):
        weak = only_finding([cross_account_statement()], vendor_accounts=VENDOR_MAP)
        strong = only_finding(
            [cross_account_statement(condition=external_id_condition(STRONG_EXTERNAL_ID))],
            vendor_accounts=VENDOR_MAP,
        )
        assert strong.exposure.grade == ExposureGrade.MODERATE
        assert weak.exposure.grade == ExposureGrade.WEAK

    def test_principal_arn_condition_pins_the_caller(self):
        finding = only_finding(
            [
                cross_account_statement(
                    condition={
                        "StringEquals": {
                            "aws:PrincipalArn": "arn:aws:iam::%s:role/Integration"
                            % EXTERNAL_ACCOUNT
                        }
                    }
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_principal_org_id_improves_the_grade(self):
        finding = only_finding(
            [
                cross_account_statement(
                    condition={
                        "StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}
                    }
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_declared_trusted_account_is_not_treated_as_a_third_party(self):
        finding = only_finding(
            [cross_account_statement("arn:aws:iam::222233334444:root")],
            trusted_account_ids=["222233334444"],
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "external_id_missing" not in weakness_codes(finding)

    def test_unrecognised_account_is_called_out_for_review(self):
        finding = only_finding([cross_account_statement("arn:aws:iam::999988887777:root")])
        assert "not listed in trusted_account_ids" in " ".join(
            finding.exposure.reasoning
        )

    def test_vendor_name_comes_with_an_explicit_disclaimer(self):
        finding = only_finding(
            [cross_account_statement()], vendor_accounts=VENDOR_MAP
        )
        assert "Example Corp" in " ".join(finding.exposure.reasoning)
        assert any(
            "does not verify" in item for item in finding.exposure.limitations
        )

    def test_cross_account_limitation_about_the_identity_policy_is_always_present(self):
        finding = only_finding([cross_account_statement()])
        assert any(
            "identity policy" in item for item in finding.exposure.limitations
        )

    def test_no_policy_is_rewritten_when_the_named_principal_is_unknowable(self):
        finding = only_finding(
            [cross_account_statement("arn:aws:iam::222233334444:root")],
            trusted_account_ids=["222233334444"],
        )
        assert finding.exposure.recommended_policy is None
        assert "cannot know which principal" in finding.exposure.recommendation


class TestExternalIdStrength:
    @pytest.mark.parametrize(
        "value",
        [
            "secret",
            "changeme",
            "test",
            EXTERNAL_ACCOUNT,
            ACCOUNT,
            "1234567890123456789",
            "short",
            "aaaaaaaaaaaaaaaaaaaaaaa",
        ],
    )
    def test_weak_values_are_flagged(self, value):
        finding = only_finding(
            [cross_account_statement(condition=external_id_condition(value))],
            vendor_accounts=VENDOR_MAP,
        )
        assert "external_id_weak_value" in weakness_codes(finding), value

    @pytest.mark.parametrize(
        "value", [STRONG_EXTERNAL_ID, "Zq7-Wm2p-Rt9x-Vb4d-Kn6s"]
    )
    def test_strong_values_are_not_flagged(self, value):
        finding = only_finding(
            [cross_account_statement(condition=external_id_condition(value))],
            vendor_accounts=VENDOR_MAP,
        )
        assert "external_id_weak_value" not in weakness_codes(finding), value

    def test_wildcard_external_id_is_flagged(self):
        finding = only_finding(
            [
                cross_account_statement(
                    condition={"StringLike": {"sts:ExternalId": "acme-*"}}
                )
            ],
            vendor_accounts=VENDOR_MAP,
        )
        assert "external_id_weak_value" in weakness_codes(finding)

    def test_external_id_derived_from_the_role_name_is_flagged(self):
        finding = only_finding(
            [
                cross_account_statement(
                    condition=external_id_condition("vendor-integration-role-id")
                )
            ],
            role_name="vendor-integration-role",
            vendor_accounts=VENDOR_MAP,
        )
        assert "external_id_weak_value" in weakness_codes(finding)

    def test_external_id_containing_the_vendor_name_is_flagged(self):
        finding = only_finding(
            [
                cross_account_statement(
                    condition=external_id_condition("acmewidgets-tenant-0001")
                )
            ],
            vendor_accounts={EXTERNAL_ACCOUNT: {"vendor": "Acme Widgets"}},
        )
        assert "external_id_weak_value" in weakness_codes(finding)

    def test_minimum_length_is_documented_in_code(self):
        assert EXTERNAL_ID_MIN_LENGTH >= 16

    def test_strong_external_id_still_carries_a_provenance_caveat(self):
        finding = only_finding(
            [cross_account_statement(condition=external_id_condition(STRONG_EXTERNAL_ID))],
            vendor_accounts=VENDOR_MAP,
        )
        assert "cannot verify that the third party generated it" in " ".join(
            finding.exposure.reasoning
        )


class TestWildcardPrincipal:
    def test_unconditioned_wildcard_is_open(self):
        finding = only_finding([cross_account_statement("*")])
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "wildcard_principal_unconditioned" in weakness_codes(finding)

    def test_unconditioned_wildcard_with_admin_is_critical(self):
        finding = only_finding(
            [cross_account_statement("*")], inline_policies=ADMIN_INLINE
        )
        assert finding.severity == "CRITICAL"
        assert finding.risk_score == 100

    def test_unconditioned_wildcard_with_no_real_permissions_is_not_critical(self):
        finding = only_finding(
            [cross_account_statement("*")], inline_policies=HARMLESS_INLINE
        )
        assert finding.severity == "MEDIUM"

    def test_external_id_alone_does_not_bound_a_wildcard(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*", condition=external_id_condition(STRONG_EXTERNAL_ID)
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "wildcard_principal_external_id_only" in weakness_codes(finding)
        # The finding must carry AWS's own words, not a paraphrase.
        assert "does not treat the external ID as a secret" in " ".join(
            finding.exposure.reasoning
        )

    def test_source_ip_alone_does_not_bound_a_wildcard(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*", condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "wildcard_principal_contextual_conditions_only" in weakness_codes(
            finding
        )

    def test_principal_org_id_bounds_a_wildcard_to_moderate(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*",
                    condition={
                        "StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}
                    },
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_principal_arn_bounds_a_wildcard_to_strong(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*",
                    condition={
                        "StringEquals": {
                            "aws:PrincipalArn": "arn:aws:iam::444455556666:role/Only"
                        }
                    },
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_if_exists_neutralises_an_org_id_bound(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*",
                    condition={
                        "StringEqualsIfExists": {
                            "aws:PrincipalOrgID": "o-exampleorgid"
                        }
                    },
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "if_exists_vacuous" in weakness_codes(finding)

    def test_unrecognised_conditions_are_not_credited_as_guards(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*",
                    condition={"StringEquals": {"acme:CustomKey": "value"}},
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert any(
            "not credited as guards" in item
            for item in finding.exposure.limitations
        )

    def test_principal_tag_is_only_a_weak_bound(self):
        finding = only_finding(
            [
                cross_account_statement(
                    "*",
                    condition={"StringEquals": {"aws:PrincipalTag/team": "platform"}},
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.WEAK


class TestServicePrincipals:
    def _service(self, service, condition=None, **kwargs):
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }
        if condition is not None:
            statement["Condition"] = condition
        return only_finding([statement], **kwargs)

    def test_no_source_condition_is_a_review_item_not_an_alarm(self):
        finding = self._service("delivery.logs.amazonaws.com")
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "service_principal_no_source_condition" in weakness_codes(finding)

    def test_the_finding_says_support_varies_by_service(self):
        finding = self._service("delivery.logs.amazonaws.com")
        assert any(
            "varies by service" in item for item in finding.exposure.limitations
        )

    def test_source_account_pinned_to_own_account_is_strong(self):
        finding = self._service(
            "delivery.logs.amazonaws.com",
            condition={"StringEquals": {"aws:SourceAccount": ACCOUNT}},
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_source_arn_pinned_to_own_account_is_strong(self):
        finding = self._service(
            "delivery.logs.amazonaws.com",
            condition={
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:logs:us-east-1:%s:log-group:app" % ACCOUNT
                }
            },
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_source_account_pointing_elsewhere_is_flagged_for_confirmation(self):
        finding = self._service(
            "delivery.logs.amazonaws.com",
            condition={"StringEquals": {"aws:SourceAccount": EXTERNAL_ACCOUNT}},
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "not this account" in " ".join(finding.exposure.reasoning)

    def test_wildcarded_source_arn_account_is_weak(self):
        finding = self._service(
            "delivery.logs.amazonaws.com",
            condition={"ArnEquals": {"aws:SourceArn": "arn:aws:logs:*:*:*"}},
        )
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "source_condition_too_broad" in weakness_codes(finding)

    def test_source_org_id_is_an_organisation_scoped_bound(self):
        finding = self._service(
            "delivery.logs.amazonaws.com",
            condition={"StringEquals": {"aws:SourceOrgID": "o-exampleorgid"}},
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    @pytest.mark.parametrize(
        "service", ["ec2.amazonaws.com", "lambda.amazonaws.com", "pods.eks.amazonaws.com"]
    )
    def test_compute_attachment_services_are_internal_not_findings(self, service):
        finding = self._service(service, inline_policies=ADMIN_INLINE)
        assert finding.exposure.grade == ExposureGrade.INTERNAL
        assert "service_principal_no_source_condition" not in weakness_codes(finding)

    def test_compute_attachment_recommendation_points_at_passrole(self):
        finding = self._service("lambda.amazonaws.com")
        assert "iam:PassRole" in finding.exposure.recommendation

    def test_compute_attachment_list_is_curated_not_open_ended(self):
        # A false-positive control has to be reviewable, so it lives in a
        # named table rather than a heuristic.
        assert "ec2.amazonaws.com" in COMPUTE_ATTACHMENT_SERVICES
        assert "delivery.logs.amazonaws.com" not in COMPUTE_ATTACHMENT_SERVICES

    def test_cognito_service_principal_without_conditions_is_open(self):
        finding = self._service("cognito-identity.amazonaws.com")
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "cognito_role_without_condition" in weakness_codes(finding)

    def test_implausible_service_principal_is_questioned(self):
        finding = self._service("not-a-service")
        assert "does not look like an AWS service principal" in " ".join(
            finding.exposure.reasoning
        )

    def test_tag_session_grant_is_noted(self):
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": "delivery.logs.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }
        finding = only_finding([statement])
        assert "session tags" in " ".join(finding.exposure.reasoning)


class TestNonAssumeStatements:
    def test_tag_session_only_statement_is_not_an_exposure(self):
        finding = only_finding(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::%s:root" % EXTERNAL_ACCOUNT},
                    "Action": "sts:TagSession",
                }
            ],
            inline_policies=ADMIN_INLINE,
        )
        assert finding.exposure.grade == ExposureGrade.NOT_APPLICABLE
        assert finding.risk_score == 0
        assert finding.severity == "INFO"

    def test_sts_wildcard_action_does_grant_assume(self):
        finding = only_finding(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::%s:root" % EXTERNAL_ACCOUNT},
                    "Action": "sts:*",
                }
            ]
        )
        assert finding.exposure.grade != ExposureGrade.NOT_APPLICABLE

    def test_deny_statements_are_not_reported_as_doors(self):
        result = analyze_statements(
            [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::%s:root" % EXTERNAL_ACCOUNT},
                    "Action": "sts:AssumeRole",
                },
            ]
        )
        assert len(result.findings) == 1
        assert any("Deny statement" in item for item in result.limitations)


class TestCanonicalUser:
    def test_canonical_user_is_not_graded(self):
        finding = only_finding(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"CanonicalUser": "abc123"},
                    "Action": "sts:AssumeRole",
                }
            ],
            inline_policies=SECRETS_INLINE,
        )
        assert finding.exposure.grade == ExposureGrade.NOT_DETERMINED
        # An ungradable door must not be allowed to shout.
        assert finding.severity in ("MEDIUM", "LOW", "INFO")
