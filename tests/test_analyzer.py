"""End-to-end analyser tests against the synthetic fixtures.

These are the tests that would catch a regression in how the pieces fit
together: a rubric change that quietly stops producing a finding, a ranking
change that buries the critical one, or a parser change that loses a role.
"""

from __future__ import annotations

import pytest

from conftest import ADMIN_INLINE, analyze_statements, cross_account_statement
from trustedge import analyzer
from trustedge.models import (
    BlastRadiusTier,
    ExposureGrade,
    Severity,
)


def by_role(result, role_name):
    return [f for f in result.findings if f.role_name == role_name]


def one(result, role_name, statement_index=None):
    matches = by_role(result, role_name)
    if statement_index is not None:
        matches = [f for f in matches if f.statement_index == statement_index]
    assert matches, "no finding for role %r" % role_name
    return matches[0]


class TestSampleAccountCoverage:
    def test_every_role_is_analysed(self, sample_result):
        assert sample_result.roles_analyzed >= 20
        assert sample_result.trust_statements_analyzed >= 22
        assert sample_result.principals_analyzed >= 22

    def test_the_export_parses_without_errors(self, sample_result):
        errors = [i for i in sample_result.issues if i.level == "error"]
        assert errors == [], [i.message for i in errors]

    def test_findings_are_ranked_worst_first(self, sample_result):
        scores = [f.risk_score for f in sample_result.findings]
        assert scores == sorted(scores, reverse=True)

    def test_severity_spread_exercises_the_whole_scale(self, sample_result):
        counts = sample_result.severity_counts()
        assert counts[Severity.CRITICAL] >= 1
        assert counts[Severity.HIGH] >= 1
        assert counts[Severity.MEDIUM] >= 1
        assert counts[Severity.LOW] >= 1

    def test_every_finding_has_an_explanation_and_a_recommendation(
        self, sample_result
    ):
        for finding in sample_result.findings:
            assert finding.exposure.reasoning, finding.finding_id
            assert finding.exposure.who_can_assume, finding.finding_id
            assert finding.exposure.recommendation, finding.finding_id
            assert finding.score_explanation, finding.finding_id

    def test_every_finding_carries_its_verbatim_trust_statement(self, sample_result):
        for finding in sample_result.findings:
            evidence = finding.evidence.get("trust_statement")
            assert isinstance(evidence, dict), finding.finding_id
            assert "Effect" in evidence, finding.finding_id

    def test_finding_ids_are_unique_and_stable(self, sample_account_path):
        first = analyzer.analyze_file(sample_account_path, include_internal=True)
        second = analyzer.analyze_file(sample_account_path, include_internal=True)
        ids = [f.finding_id for f in first.findings]
        assert len(ids) == len(set(ids))
        assert ids == [f.finding_id for f in second.findings]

    def test_global_limitations_are_always_attached(self, sample_result):
        joined = " ".join(sample_result.limitations)
        assert "no AWS API calls" in joined
        assert "IAM Access Analyzer" in joined
        assert "identity policy" in joined


class TestSampleAccountGrades:
    """Pins the rubric against the designed fixtures.

    Each assertion below is a claim about AWS semantics, not about the
    implementation. If one of these has to change, the reasoning in
    docs/methodology.md has to change with it.
    """

    def test_github_without_a_sub_condition_on_an_admin_role_is_critical(
        self, sample_result
    ):
        finding = one(sample_result, "gh-legacy-admin")
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert finding.blast_radius.tier == BlastRadiusTier.ADMIN
        assert finding.severity == Severity.CRITICAL

    def test_whole_external_account_on_an_admin_role_is_critical(self, sample_result):
        finding = one(sample_result, "partner-broad-access")
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert finding.severity == Severity.CRITICAL

    def test_org_wildcard_github_trust_is_weak(self, sample_result):
        finding = one(sample_result, "gh-org-wide-secrets")
        assert finding.exposure.grade == ExposureGrade.WEAK

    def test_repo_pinned_without_a_ref_is_moderate(self, sample_result):
        finding = one(sample_result, "gh-infra-any-branch")
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_fully_pinned_github_trust_is_strong(self, sample_result):
        finding = one(sample_result, "gh-deploy-payments-prod")
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_wildcard_in_the_org_segment_is_open(self, sample_result):
        finding = one(sample_result, "gh-legacy-subject-pattern")
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "if_exists_vacuous" in [
            w.code for w in finding.exposure.weak_conditions
        ]

    def test_weak_external_id_is_detected(self, sample_result):
        finding = one(sample_result, "vendor-log-shipper")
        codes = [w.code for w in finding.exposure.weak_conditions]
        assert "external_id_weak_value" in codes

    def test_missing_external_id_on_a_vendor_relationship_is_detected(
        self, sample_result
    ):
        finding = one(sample_result, "vendor-cost-optimiser")
        codes = [w.code for w in finding.exposure.weak_conditions]
        assert "external_id_missing" in codes
        assert "Example Corp" in " ".join(finding.exposure.reasoning)

    def test_strong_trust_with_admin_permissions_is_only_medium(self, sample_result):
        finding = one(sample_result, "partner-admin-pinned")
        assert finding.exposure.grade == ExposureGrade.STRONG
        assert finding.blast_radius.tier == BlastRadiusTier.ADMIN
        assert finding.severity == Severity.MEDIUM

    def test_broad_trust_with_no_real_permissions_is_only_medium(self, sample_result):
        finding = one(sample_result, "public-status-reader")
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert finding.blast_radius.tier == BlastRadiusTier.LOW
        assert finding.severity == Severity.MEDIUM

    def test_the_two_medium_findings_above_bracket_the_scale(self, sample_result):
        """Neither factor alone reaches HIGH, which is the whole thesis."""
        strong_door_admin = one(sample_result, "partner-admin-pinned")
        open_door_nothing = one(sample_result, "public-status-reader")
        weak_door_admin = one(sample_result, "partner-broad-access")
        assert weak_door_admin.risk_score > strong_door_admin.risk_score
        assert weak_door_admin.risk_score > open_door_nothing.risk_score

    def test_irsa_scoped_to_a_service_account_is_strong(self, sample_result):
        finding = one(sample_result, "irsa-payments-api")
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_irsa_cluster_wide_is_moderate_not_open(self, sample_result):
        finding = one(sample_result, "irsa-cluster-wide")
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_the_same_omission_grades_differently_by_issuer_type(self, sample_result):
        shared = one(sample_result, "gh-legacy-admin")
        private = one(sample_result, "irsa-cluster-wide")
        assert shared.exposure.grade == ExposureGrade.OPEN
        assert private.exposure.grade == ExposureGrade.MODERATE

    def test_roles_anywhere_without_conditions_is_weak(self, sample_result):
        finding = one(sample_result, "rolesanywhere-build-agent")
        assert finding.exposure.grade == ExposureGrade.WEAK

    def test_roles_anywhere_pinned_both_ways_is_strong(self, sample_result):
        finding = one(sample_result, "rolesanywhere-pinned")
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_service_principal_without_a_source_condition_is_moderate(
        self, sample_result
    ):
        finding = one(sample_result, "delivery-logs-writer")
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_lambda_role_is_internal_not_a_confused_deputy_finding(
        self, sample_result
    ):
        finding = one(sample_result, "lambda-report-generator")
        assert finding.exposure.grade == ExposureGrade.INTERNAL

    def test_unresolved_managed_policy_yields_unknown_blast_radius(
        self, sample_result
    ):
        finding = one(sample_result, "vendor-unresolved-permissions")
        assert finding.blast_radius.tier == BlastRadiusTier.UNKNOWN

    def test_string_equals_with_a_wildcard_is_reported_as_fail_closed(
        self, sample_result
    ):
        finding = one(sample_result, "gh-broken-exact-match")
        assert finding.exposure.fail_closed_notes

    def test_saml_with_only_an_audience_condition_is_moderate(self, sample_result):
        finding = one(sample_result, "corp-sso-operator")
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_escalation_primitives_are_surfaced(self, sample_result):
        finding = one(sample_result, "iam-automation")
        codes = [c.code for c in finding.blast_radius.capabilities]
        for expected in (
            "iam_create_policy_version",
            "iam_attach_role_policy",
            "iam_update_assume_role_policy",
        ):
            assert expected in codes

    def test_passrole_plus_compute_is_surfaced(self, sample_result):
        finding = one(sample_result, "gh-legacy-subject-pattern")
        codes = [c.code for c in finding.blast_radius.capabilities]
        assert "passrole_plus_compute" in codes


class TestMultipleStatements:
    def test_each_door_on_a_role_is_graded_separately(self, sample_result):
        findings = by_role(sample_result, "multi-door-artifacts")
        assert len(findings) == 3
        grades = {f.statement_index: f.exposure.grade for f in findings}
        assert grades[0] == ExposureGrade.STRONG
        assert grades[1] == ExposureGrade.WEAK
        assert grades[2] == ExposureGrade.NOT_APPLICABLE

    def test_the_weak_door_is_not_hidden_behind_the_strong_one(self, sample_result):
        findings = by_role(sample_result, "multi-door-artifacts")
        weak = next(f for f in findings if f.statement_index == 1)
        strong = next(f for f in findings if f.statement_index == 0)
        assert weak.risk_score > strong.risk_score

    def test_blast_radius_is_shared_across_a_role_doors(self, sample_result):
        findings = by_role(sample_result, "multi-door-artifacts")
        tiers = {f.blast_radius.tier for f in findings}
        assert len(tiers) == 1

    def test_role_summary_reports_the_worst_finding(self, sample_result):
        summary = next(
            s for s in sample_result.role_summaries
            if s.role_name == "multi-door-artifacts"
        )
        assert summary.highest_severity == Severity.HIGH
        assert summary.trust_statement_count == 3


class TestInternalSuppression:
    def test_internal_findings_are_omitted_by_default(self, sample_account_path):
        default = analyzer.analyze_file(sample_account_path)
        assert not [
            f for f in default.findings
            if f.exposure.grade == ExposureGrade.INTERNAL
        ]

    def test_suppression_is_disclosed_in_the_limitations(self, sample_account_path):
        default = analyzer.analyze_file(sample_account_path)
        assert any("INTERNAL and omitted" in item for item in default.limitations)

    def test_include_internal_shows_them(self, sample_account_path):
        included = analyzer.analyze_file(sample_account_path, include_internal=True)
        assert [
            f for f in included.findings
            if f.exposure.grade == ExposureGrade.INTERNAL
        ]

    def test_same_account_role_only_appears_with_the_flag(self, sample_account_path):
        default = analyzer.analyze_file(sample_account_path)
        included = analyzer.analyze_file(sample_account_path, include_internal=True)
        assert not by_role(default, "svc-internal-batch")
        assert by_role(included, "svc-internal-batch")


class TestMalformedFixtureEndToEnd:
    @pytest.fixture(scope="class")
    @classmethod
    def result(cls, malformed_path):
        return analyzer.analyze_file(malformed_path, include_internal=True)

    def test_analysis_completes(self, result):
        assert result.roles_analyzed >= 8

    def test_problems_are_reported_rather_than_hidden(self, result):
        codes = {i.code for i in result.issues}
        assert "trust_policy_unreadable" in codes
        assert "role_not_an_object" in codes
        assert "principal_key_unknown" in codes

    def test_the_url_encoded_role_is_still_graded(self, result):
        finding = one(result, "url-encoded-trust-policy")
        assert finding.blast_radius.tier == BlastRadiusTier.ADMIN
        assert finding.exposure.grade == ExposureGrade.WEAK

    def test_the_good_statement_in_a_broken_policy_is_graded(self, result):
        findings = by_role(result, "mixed-good-and-bad-statements")
        assert any(f.exposure.grade == ExposureGrade.OPEN for f in findings)

    def test_partial_wildcard_principal_is_reported_as_ungradable(self, result):
        findings = by_role(result, "odd-principal-forms")
        assert any(
            f.exposure.grade == ExposureGrade.NOT_DETERMINED for f in findings
        )

    def test_not_principal_role_is_flagged_for_manual_review(self, result):
        codes = {i.code for i in result.issues}
        assert "not_principal_unsupported" in codes


class TestEmptyAndDegenerateInputs:
    def test_no_roles_produces_an_honest_empty_result(self):
        from trustedge.parser import parse_export

        export, issues = parse_export({"account_id": "111122223333", "roles": []})
        result = analyzer.analyze(export, issues=issues)
        assert result.findings == []
        assert any("nothing was checked" in item for item in result.limitations)

    def test_account_id_absent_downgrades_confidence_rather_than_guessing(self):
        result = analyze_statements(
            [cross_account_statement("arn:aws:iam::444455556666:root")],
            account_id=None,
            inline_policies=ADMIN_INLINE,
        )
        finding = result.findings[0]
        assert finding.exposure.grade == ExposureGrade.NOT_DETERMINED
        assert finding.severity == Severity.MEDIUM

    def test_a_role_with_an_unusable_trust_policy_yields_no_findings(self):
        from trustedge.parser import parse_export

        export, issues = parse_export(
            {
                "account_id": "111122223333",
                "roles": [
                    {
                        "role_name": "broken",
                        "arn": "arn:aws:iam::111122223333:role/broken",
                        "assume_role_policy_document": "{not json",
                    }
                ],
            }
        )
        result = analyzer.analyze(export, issues=issues)
        assert result.findings == []
        assert result.roles_analyzed == 1
