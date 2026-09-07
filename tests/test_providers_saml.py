"""SAML federation rubric tests."""

from __future__ import annotations

from conftest import SAML_PROVIDER_ARN, only_finding, weakness_codes
from trustedge.models import ExposureGrade

AWS_ENDPOINT = "https://signin.aws.amazon.com/saml"


def saml_statement(condition=None, action="sts:AssumeRoleWithSAML"):
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": SAML_PROVIDER_ARN},
        "Action": action,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def saml_finding(condition=None, **kwargs):
    return only_finding([saml_statement(condition)], **kwargs)


class TestSamlGrading:
    def test_no_conditions_at_all_is_weak(self):
        finding = saml_finding(None)
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "saml_no_conditions" in weakness_codes(finding)

    def test_no_conditions_offers_the_baseline_policy(self):
        finding = saml_finding(None)
        policy = finding.exposure.recommended_policy
        assert policy is not None
        assert (
            policy["Statement"][0]["Condition"]["StringEquals"]["SAML:aud"]
            == AWS_ENDPOINT
        )

    def test_audience_only_is_moderate_and_says_why(self):
        finding = saml_finding({"StringEquals": {"SAML:aud": AWS_ENDPOINT}})
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "saml_no_subject_condition" in weakness_codes(finding)
        assert "does not restrict which user" in " ".join(finding.exposure.reasoning)

    def test_condition_key_case_does_not_matter(self):
        upper = saml_finding({"StringEquals": {"SAML:aud": AWS_ENDPOINT}})
        lower = saml_finding({"StringEquals": {"saml:aud": AWS_ENDPOINT}})
        assert upper.exposure.grade == lower.exposure.grade

    def test_subject_condition_is_strong(self):
        finding = saml_finding(
            {
                "StringEquals": {
                    "SAML:aud": AWS_ENDPOINT,
                    "saml:sub": "_cbb88bf52c2510eabe00c1642d4643f41430fe25e3",
                }
            }
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_group_attribute_condition_is_moderate(self):
        finding = saml_finding(
            {
                "StringEquals": {"SAML:aud": AWS_ENDPOINT},
                "ForAnyValue:StringEquals": {
                    "saml:edupersonaffiliation": "platform-admins"
                },
            }
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "group or affiliation attribute" in " ".join(
            finding.exposure.reasoning
        )

    def test_forallvalues_on_a_group_attribute_is_reported_as_vacuous(self):
        finding = saml_finding(
            {
                "StringEquals": {"SAML:aud": AWS_ENDPOINT},
                "ForAllValues:StringEquals": {
                    "saml:edupersonaffiliation": "platform-admins"
                },
            }
        )
        assert "forallvalues_vacuous" in weakness_codes(finding)
        # It must not be credited as a guard, so the grade falls back to
        # audience-only.
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "saml_no_subject_condition" in weakness_codes(finding)

    def test_transient_subject_type_is_called_out(self):
        finding = saml_finding(
            {
                "StringEquals": {
                    "SAML:aud": AWS_ENDPOINT,
                    "saml:sub_type": "transient",
                    "saml:sub": "whatever",
                }
            }
        )
        assert "different saml:sub value for each session" in " ".join(
            finding.exposure.reasoning
        )

    def test_persistent_subject_type_is_noted_as_usable(self):
        finding = saml_finding(
            {
                "StringEquals": {
                    "SAML:aud": AWS_ENDPOINT,
                    "saml:sub_type": "persistent",
                    "saml:sub": "whatever",
                }
            }
        )
        assert "stable between sessions" in " ".join(finding.exposure.reasoning)

    def test_non_standard_audience_is_questioned(self):
        finding = saml_finding(
            {"StringEquals": {"SAML:aud": "https://example.com/acs"}}
        )
        assert "not one of the standard AWS SAML endpoints" in " ".join(
            finding.exposure.reasoning
        )

    def test_wildcard_audience_is_flagged(self):
        finding = saml_finding(
            {"StringLike": {"SAML:aud": "https://signin.aws.amazon.com/*"}}
        )
        assert "saml_aud_wildcard" in weakness_codes(finding)

    def test_unknown_saml_provider_is_noted(self):
        finding = saml_finding(
            None,
            saml_providers=[
                {
                    "arn": "arn:aws:iam::111122223333:saml-provider/SomethingElse",
                    "name": "SomethingElse",
                }
            ],
        )
        assert "not in the export's saml_providers list" in " ".join(
            finding.exposure.reasoning
        )

    def test_known_saml_provider_is_not_flagged(self):
        finding = saml_finding(
            None,
            saml_providers=[{"arn": SAML_PROVIDER_ARN, "name": "CorpDirectory"}],
        )
        assert "not in the export's saml_providers list" not in " ".join(
            finding.exposure.reasoning
        )

    def test_limitations_state_that_the_idp_is_invisible(self):
        finding = saml_finding(None)
        joined = " ".join(finding.exposure.limitations)
        assert "cannot see the identity provider" in joined
        assert "onward role chaining" in joined
