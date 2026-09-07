"""Ranking: exposure x blast radius, with the arithmetic shown.

The whole point of TrustEdge is that neither half of the question is useful
alone. A wide-open door onto a role that can only call ``sts:GetCallerIdentity``
is a hygiene item. A perfectly locked door onto an administrator role is a
design smell, not an incident. The thing that should reach the top of a queue
is a weak door onto a role worth walking through.

So the score is a product, not a sum:

    risk = round(100 x exposure_weight x blast_weight)

A product has the property a sum does not: driving *either* factor to near zero
drives the risk to near zero. That matches how a reviewer actually triages, and
it means the score can always be explained in one sentence -
:func:`explain` produces exactly that sentence and it is stored on the finding.

Weights live in :class:`~trustedge.models.ExposureGrade` and
:class:`~trustedge.models.BlastRadiusTier` so the rubric and the arithmetic
cannot drift apart. They are documented in ``docs/methodology.md``.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .models import (
    BlastRadiusTier,
    ExposureGrade,
    Finding,
    Severity,
)

#: risk_score >= threshold -> severity. Ordered most severe first.
SEVERITY_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (60, Severity.CRITICAL),
    (35, Severity.HIGH),
    (15, Severity.MEDIUM),
    (5, Severity.LOW),
    (0, Severity.INFO),
)

#: TrustEdge refuses to assert a high severity on the back of a grade it could
#: not determine. An unclassifiable principal is a review item, not an alarm.
SEVERITY_CAPS = {
    ExposureGrade.NOT_DETERMINED: Severity.MEDIUM,
    ExposureGrade.INTERNAL: Severity.LOW,
    ExposureGrade.NOT_APPLICABLE: Severity.INFO,
}


def risk_score(exposure_grade: str, blast_tier: str) -> int:
    """The product score, 0-100."""
    return int(
        round(100.0 * ExposureGrade.score(exposure_grade) * BlastRadiusTier.score(blast_tier))
    )


def severity_for(exposure_grade: str, blast_tier: str) -> str:
    score = risk_score(exposure_grade, blast_tier)
    severity = Severity.INFO
    for threshold, candidate in SEVERITY_THRESHOLDS:
        if score >= threshold:
            severity = candidate
            break
    cap = SEVERITY_CAPS.get(exposure_grade)
    if cap is not None and Severity.rank(severity) < Severity.rank(cap):
        severity = cap
    return severity


def explain(exposure_grade: str, blast_tier: str) -> str:
    """One sentence a reviewer can check by hand."""
    exposure_weight = ExposureGrade.score(exposure_grade)
    blast_weight = BlastRadiusTier.score(blast_tier)
    score = risk_score(exposure_grade, blast_tier)
    severity = severity_for(exposure_grade, blast_tier)
    sentence = (
        "exposure %s (%.2f) x blast radius %s (%.2f) = %d, which falls in the "
        "%s band"
        % (exposure_grade, exposure_weight, blast_tier, blast_weight, score, severity)
    )
    cap = SEVERITY_CAPS.get(exposure_grade)
    if cap is not None:
        sentence += (
            "; severity is capped at %s because the exposure grade is %s"
            % (cap, exposure_grade)
        )
    return sentence


def apply(finding: Finding) -> Finding:
    """Fill in ``risk_score``, ``severity`` and ``score_explanation``."""
    exposure_grade = finding.exposure.grade
    blast_tier = finding.blast_radius.tier
    finding.risk_score = risk_score(exposure_grade, blast_tier)
    finding.severity = severity_for(exposure_grade, blast_tier)
    finding.score_explanation = explain(exposure_grade, blast_tier)
    return finding


def sort_key(finding: Finding) -> Tuple[int, int, str, int, str]:
    """Deterministic ordering: worst first, then stable by identity."""
    return (
        -finding.risk_score,
        Severity.rank(finding.severity),
        finding.role_name,
        finding.statement_index,
        finding.principal.raw,
    )


def rank(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(findings, key=sort_key)
