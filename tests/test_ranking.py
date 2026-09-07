"""Ranking tests.

The property being defended: the score is a *product*, so neither exposure nor
blast radius can carry a finding to the top on its own. Tests below assert that
directly rather than asserting a table of numbers.
"""

from __future__ import annotations

import itertools

import pytest

from trustedge import ranking
from trustedge.models import (
    BlastRadius,
    BlastRadiusTier,
    ExposureAssessment,
    ExposureGrade,
    Finding,
    Severity,
    TrustPrincipal,
)

EXPOSURES = [
    ExposureGrade.OPEN,
    ExposureGrade.WEAK,
    ExposureGrade.MODERATE,
    ExposureGrade.STRONG,
    ExposureGrade.INTERNAL,
]
TIERS = [
    BlastRadiusTier.ADMIN,
    BlastRadiusTier.HIGH,
    BlastRadiusTier.MODERATE,
    BlastRadiusTier.LOW,
]


def make_finding(exposure, tier, role_name="r", statement_index=0, principal="p"):
    finding = Finding(
        finding_id="TE-%s-%s" % (exposure, tier),
        role_name=role_name,
        role_arn=None,
        statement_index=statement_index,
        statement_sid=None,
        principal=TrustPrincipal(block_key="AWS", raw=principal),
        exposure=ExposureAssessment(grade=exposure),
        blast_radius=BlastRadius(tier=tier),
    )
    return ranking.apply(finding)


class TestScoreShape:
    def test_the_worst_case_is_one_hundred(self):
        assert ranking.risk_score(ExposureGrade.OPEN, BlastRadiusTier.ADMIN) == 100

    def test_monotonic_in_exposure_for_a_fixed_blast_radius(self):
        scores = [
            ranking.risk_score(grade, BlastRadiusTier.ADMIN) for grade in EXPOSURES
        ]
        assert scores == sorted(scores, reverse=True)

    def test_monotonic_in_blast_radius_for_a_fixed_exposure(self):
        scores = [ranking.risk_score(ExposureGrade.OPEN, tier) for tier in TIERS]
        assert scores == sorted(scores, reverse=True)

    def test_a_strong_door_onto_admin_outranks_nothing_serious(self):
        strong_admin = ranking.risk_score(ExposureGrade.STRONG, BlastRadiusTier.ADMIN)
        open_admin = ranking.risk_score(ExposureGrade.OPEN, BlastRadiusTier.ADMIN)
        assert strong_admin < open_admin

    def test_an_open_door_onto_nothing_is_not_top_of_the_queue(self):
        open_low = ranking.risk_score(ExposureGrade.OPEN, BlastRadiusTier.LOW)
        weak_admin = ranking.risk_score(ExposureGrade.WEAK, BlastRadiusTier.ADMIN)
        assert open_low < weak_admin

    def test_the_product_property_holds_for_every_combination(self):
        for grade, tier in itertools.product(EXPOSURES, TIERS):
            expected = round(
                100 * ExposureGrade.score(grade) * BlastRadiusTier.score(tier)
            )
            assert ranking.risk_score(grade, tier) == expected

    def test_not_applicable_scores_zero(self):
        assert (
            ranking.risk_score(ExposureGrade.NOT_APPLICABLE, BlastRadiusTier.ADMIN)
            == 0
        )


class TestSeverityBands:
    @pytest.mark.parametrize(
        "exposure,tier,severity",
        [
            (ExposureGrade.OPEN, BlastRadiusTier.ADMIN, Severity.CRITICAL),
            (ExposureGrade.WEAK, BlastRadiusTier.ADMIN, Severity.CRITICAL),
            (ExposureGrade.WEAK, BlastRadiusTier.HIGH, Severity.HIGH),
            (ExposureGrade.MODERATE, BlastRadiusTier.ADMIN, Severity.HIGH),
            (ExposureGrade.MODERATE, BlastRadiusTier.MODERATE, Severity.MEDIUM),
            (ExposureGrade.STRONG, BlastRadiusTier.ADMIN, Severity.MEDIUM),
            (ExposureGrade.STRONG, BlastRadiusTier.LOW, Severity.INFO),
            (ExposureGrade.INTERNAL, BlastRadiusTier.ADMIN, Severity.LOW),
            (ExposureGrade.OPEN, BlastRadiusTier.LOW, Severity.MEDIUM),
        ],
    )
    def test_bands(self, exposure, tier, severity):
        assert ranking.severity_for(exposure, tier) == severity

    def test_not_determined_is_capped_at_medium(self):
        assert (
            ranking.severity_for(
                ExposureGrade.NOT_DETERMINED, BlastRadiusTier.ADMIN
            )
            == Severity.MEDIUM
        )

    def test_internal_is_capped_at_low(self):
        assert (
            ranking.severity_for(ExposureGrade.INTERNAL, BlastRadiusTier.ADMIN)
            == Severity.LOW
        )

    def test_not_applicable_is_capped_at_info(self):
        assert (
            ranking.severity_for(ExposureGrade.NOT_APPLICABLE, BlastRadiusTier.ADMIN)
            == Severity.INFO
        )

    def test_severity_ordering_helpers(self):
        assert Severity.rank(Severity.CRITICAL) < Severity.rank(Severity.HIGH)
        assert Severity.at_least(Severity.CRITICAL, Severity.HIGH)
        assert Severity.at_least(Severity.HIGH, Severity.HIGH)
        assert not Severity.at_least(Severity.MEDIUM, Severity.HIGH)

    def test_unknown_severity_sorts_last(self):
        assert Severity.rank("NONSENSE") > Severity.rank(Severity.INFO)


class TestExplanation:
    def test_explanation_shows_both_factors_and_the_result(self):
        text = ranking.explain(ExposureGrade.WEAK, BlastRadiusTier.HIGH)
        assert "WEAK" in text
        assert "HIGH" in text
        assert "0.75" in text
        assert str(ranking.risk_score(ExposureGrade.WEAK, BlastRadiusTier.HIGH)) in text

    def test_explanation_mentions_a_cap_when_one_applies(self):
        text = ranking.explain(ExposureGrade.NOT_DETERMINED, BlastRadiusTier.ADMIN)
        assert "capped" in text

    def test_apply_populates_the_finding(self):
        finding = make_finding(ExposureGrade.OPEN, BlastRadiusTier.ADMIN)
        assert finding.risk_score == 100
        assert finding.severity == Severity.CRITICAL
        assert finding.score_explanation


class TestSorting:
    def test_worst_first(self):
        findings = [
            make_finding(ExposureGrade.STRONG, BlastRadiusTier.LOW, role_name="a"),
            make_finding(ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="b"),
            make_finding(ExposureGrade.MODERATE, BlastRadiusTier.HIGH, role_name="c"),
        ]
        ordered = ranking.rank(findings)
        assert [f.role_name for f in ordered] == ["b", "c", "a"]

    def test_ties_are_broken_deterministically(self):
        first = make_finding(
            ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="zebra"
        )
        second = make_finding(
            ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="alpha"
        )
        assert [f.role_name for f in ranking.rank([first, second])] == [
            "alpha",
            "zebra",
        ]
        assert [f.role_name for f in ranking.rank([second, first])] == [
            "alpha",
            "zebra",
        ]

    def test_statement_index_breaks_ties_within_a_role(self):
        findings = [
            make_finding(
                ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="r", statement_index=2
            ),
            make_finding(
                ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="r", statement_index=0
            ),
        ]
        assert [f.statement_index for f in ranking.rank(findings)] == [0, 2]

    def test_ranking_does_not_mutate_the_input_order(self):
        findings = [
            make_finding(ExposureGrade.STRONG, BlastRadiusTier.LOW, role_name="a"),
            make_finding(ExposureGrade.OPEN, BlastRadiusTier.ADMIN, role_name="b"),
        ]
        original = list(findings)
        ranking.rank(findings)
        assert findings == original


class TestWeightsAreDocumentedTogether:
    def test_every_exposure_grade_has_a_weight(self):
        for name in dir(ExposureGrade):
            if name.isupper() and name != "SCORES":
                value = getattr(ExposureGrade, name)
                if isinstance(value, str):
                    assert value in ExposureGrade.SCORES, value

    def test_every_blast_radius_tier_has_a_weight(self):
        for name in dir(BlastRadiusTier):
            if name.isupper() and name != "SCORES":
                value = getattr(BlastRadiusTier, name)
                if isinstance(value, str):
                    assert value in BlastRadiusTier.SCORES, value
