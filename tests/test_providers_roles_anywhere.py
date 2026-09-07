"""IAM Roles Anywhere rubric tests."""

from __future__ import annotations

from conftest import ACCOUNT, only_finding, weakness_codes
from trustedge.models import ExposureGrade

TRUST_ANCHOR = (
    "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/"
    "11111111-2222-3333-4444-555555555555"
)
REQUIRED_ACTIONS = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]


def ra_statement(condition=None, actions=None):
    statement = {
        "Effect": "Allow",
        "Principal": {"Service": "rolesanywhere.amazonaws.com"},
        "Action": actions if actions is not None else list(REQUIRED_ACTIONS),
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def ra_finding(condition=None, actions=None, **kwargs):
    return only_finding([ra_statement(condition, actions)], **kwargs)


class TestRolesAnywhereGrading:
    def test_no_conditions_is_weak(self):
        finding = ra_finding(None)
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "roles_anywhere_unconditioned" in weakness_codes(finding)
        assert "any IAM Roles Anywhere trust anchor" in finding.exposure.who_can_assume

    def test_no_conditions_offers_a_two_sided_policy(self):
        finding = ra_finding(None)
        policy = finding.exposure.recommended_policy
        assert policy is not None
        condition = policy["Statement"][0]["Condition"]
        assert "aws:SourceArn" in condition["ArnEquals"]
        assert "aws:PrincipalTag/x509Subject/CN" in condition["StringEquals"]

    def test_trust_anchor_only_is_moderate(self):
        finding = ra_finding({"ArnEquals": {"aws:SourceArn": TRUST_ANCHOR}})
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "roles_anywhere_identity_not_pinned" in weakness_codes(finding)

    def test_certificate_condition_only_is_moderate_and_explains_ca_scoping(self):
        finding = ra_finding(
            {"StringEquals": {"aws:PrincipalTag/x509Subject/CN": "build-agent-01"}}
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "roles_anywhere_trust_anchor_not_pinned" in weakness_codes(finding)
        assert "only unique within a certificate authority" in " ".join(
            finding.exposure.reasoning
        )

    def test_both_halves_pinned_is_strong(self):
        finding = ra_finding(
            {
                "ArnEquals": {"aws:SourceArn": TRUST_ANCHOR},
                "StringEquals": {
                    "aws:PrincipalTag/x509Subject/CN": "build-agent-01"
                },
            }
        )
        assert finding.exposure.grade == ExposureGrade.STRONG
        assert "certificate revocation list" in finding.exposure.recommendation

    def test_source_identity_counts_as_an_identity_pin(self):
        finding = ra_finding(
            {
                "ArnEquals": {"aws:SourceArn": TRUST_ANCHOR},
                "StringEquals": {"sts:SourceIdentity": "CN=build-agent-01"},
            }
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_issuer_and_san_tags_are_recognised(self):
        for key in (
            "aws:PrincipalTag/x509Issuer/CN",
            "aws:PrincipalTag/x509SAN/DNS",
            "aws:PrincipalTag/x509SAN/Name/CN",
        ):
            finding = ra_finding(
                {
                    "ArnEquals": {"aws:SourceArn": TRUST_ANCHOR},
                    "StringEquals": {key: "value"},
                }
            )
            assert finding.exposure.grade == ExposureGrade.STRONG, key

    def test_wildcarded_trust_anchor_id_is_not_a_pin(self):
        finding = ra_finding(
            {
                "ArnLike": {
                    "aws:SourceArn": (
                        "arn:aws:rolesanywhere:us-east-1:%s:trust-anchor/*" % ACCOUNT
                    )
                },
                "StringEquals": {
                    "aws:PrincipalTag/x509Subject/CN": "build-agent-01"
                },
            }
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "roles_anywhere_trust_anchor_wildcarded" in weakness_codes(finding)

    def test_source_arn_pointing_at_the_wrong_service_is_flagged(self):
        finding = ra_finding(
            {
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:s3:::some-bucket"
                }
            }
        )
        assert "roles_anywhere_source_arn_wrong_service" in weakness_codes(finding)

    def test_broad_certificate_pattern_is_flagged(self):
        finding = ra_finding(
            {
                "ArnEquals": {"aws:SourceArn": TRUST_ANCHOR},
                "StringLike": {"aws:PrincipalTag/x509Subject/CN": "build-agent-*"},
            }
        )
        assert "roles_anywhere_certificate_pattern_broad" in weakness_codes(finding)

    def test_missing_required_actions_is_reported_as_fail_closed(self):
        finding = ra_finding(None, actions=["sts:AssumeRole"])
        joined = " ".join(finding.exposure.fail_closed_notes)
        assert "sts:TagSession" in joined
        assert "sts:SetSourceIdentity" in joined
        assert "fail-closed" in joined

    def test_all_required_actions_present_produces_no_fail_closed_note(self):
        finding = ra_finding(None)
        assert finding.exposure.fail_closed_notes == []

    def test_sts_wildcard_satisfies_the_required_actions(self):
        finding = ra_finding(None, actions=["sts:*"])
        assert finding.exposure.fail_closed_notes == []

    def test_limitations_cover_what_iam_cannot_show(self):
        finding = ra_finding(None)
        joined = " ".join(finding.exposure.limitations)
        assert "trust anchors" in joined
        assert "revocation list" in joined
        # The analyser must be honest that AWS's own documentation is ambiguous
        # here rather than asserting behaviour it did not verify.
        assert "immediately before" in joined
