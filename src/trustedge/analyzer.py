"""Orchestration: export -> classified principals -> graded exposure -> ranked findings.

One finding is produced per (role, trust statement, principal) triple, because
that is the granularity at which a reviewer can act: a single role often has
several doors with very different guards on them, and collapsing them into one
"role finding" hides the weak one behind the strong ones.

Blast radius is computed once per role and shared across that role's findings -
the permissions do not change depending on which door you came through.
"""

from __future__ import annotations

import datetime
import re
from typing import Dict, List, Optional, Sequence

from . import blast_radius as blast_radius_module
from . import ranking
from .classifier import classify_statement_principals
from .conditions import ConditionSet
from .context import GradingContext
from .models import (
    AnalysisResult,
    Confidence,
    ExposureAssessment,
    ExposureGrade,
    Finding,
    IamExport,
    ParseIssue,
    Role,
    RoleSummary,
    Severity,
    TrustStatement,
)
from .parser import ExportFormatError, load_json_file, parse_export
from .providers import grade_principal
from .version import __version__ as TOOL_VERSION

TOOL_NAME = "TrustEdge"

_SLUG_RE = re.compile(r"[^A-Za-z0-9]+")

GLOBAL_LIMITATIONS = (
    "TrustEdge reads a static IAM export. It makes no AWS API calls and cannot "
    "observe runtime behaviour, so it reports reachable trust paths, never "
    "proven exploitation.",
    "A cross-account caller also needs sts:AssumeRole in an identity-based "
    "policy in their own account. AWS requires an Allow in both the identity "
    "policy and the resource-based policy for cross-account access, and "
    "TrustEdge only sees your side.",
    "Service control policies, resource control policies, permissions "
    "boundaries and session policies are not evaluated. Any of them can make "
    "effective access narrower than the blast radius reported here.",
    "TrustEdge does not verify who controls an external AWS account, an OIDC "
    "issuer or a SAML identity provider. Vendor names in findings come from "
    "the operator-supplied mapping in the export and are not checked.",
    "TrustEdge is not a replacement for IAM Access Analyzer. Access Analyzer "
    "uses automated reasoning over live resource policies across many resource "
    "types; TrustEdge grades condition strength on role trust policies offline "
    "and ranks it against blast radius. Run both.",
    "Same-account assume paths and full privilege-escalation graphs are out of "
    "scope. Tools built for intra-account escalation modelling cover that "
    "ground better.",
)


def analyze_file(
    path: str,
    include_internal: bool = False,
) -> AnalysisResult:
    """Load, parse and analyse an export file.

    Raises :class:`~trustedge.parser.ExportFormatError` only when the input is
    not an IAM export at all.
    """
    document = load_json_file(path)
    export, issues = parse_export(document, source=path)
    return analyze(export, issues=issues, input_path=path, include_internal=include_internal)


def analyze(
    export: IamExport,
    issues: Optional[Sequence[ParseIssue]] = None,
    input_path: Optional[str] = None,
    include_internal: bool = False,
) -> AnalysisResult:
    all_issues: List[ParseIssue] = list(issues or [])
    result = AnalysisResult(
        account_id=export.account_id,
        tool=TOOL_NAME,
        tool_version=TOOL_VERSION,
        generated_at=_utc_now(),
        input_path=input_path,
        issues=all_issues,
        limitations=list(GLOBAL_LIMITATIONS),
    )

    suppressed_internal = 0
    trust_policy_denies = 0

    for role in export.roles:
        result.roles_analyzed += 1
        radius = blast_radius_module.resolve(role, export)
        role_findings: List[Finding] = []
        principal_classes: List[str] = []

        # A role whose trust policy could not be read has no statements to walk,
        # so it contributes to roles_analyzed and to the role inventory but
        # produces no findings. The parse issue is what tells the reader why.
        for statement in role.trust_statements:
            result.trust_statements_analyzed += 1

            if statement.effect == "Deny":
                trust_policy_denies += 1
                continue

            principals = classify_statement_principals(
                statement, export, role, all_issues
            )
            conditions = ConditionSet.from_raw(statement.condition)
            for problem in conditions.problems:
                all_issues.append(
                    ParseIssue(
                        "warning",
                        "condition_problem",
                        "Role %s statement %d: %s"
                        % (role.role_name, statement.index, problem),
                        "role %s statement %d" % (role.role_name, statement.index),
                    )
                )

            for position, principal in enumerate(principals):
                result.principals_analyzed += 1
                principal_classes.append(principal.principal_class)

                ctx = GradingContext(
                    export=export,
                    role=role,
                    statement=statement,
                    principal=principal,
                    conditions=conditions,
                )
                assessment = grade_principal(ctx)

                if not statement.grants_assume:
                    assessment = _not_an_assume_door(statement, assessment)

                if statement.has_not_principal:
                    assessment.limitations.append(
                        "The statement also carries a NotPrincipal element, "
                        "which TrustEdge does not evaluate. The real allowed set "
                        "may differ from the grade shown."
                    )
                    assessment.confidence = Confidence.LOW

                for note in principal.notes:
                    assessment.add(note)

                finding = Finding(
                    finding_id=_finding_id(role, statement, position, principal.raw),
                    role_name=role.role_name,
                    role_arn=role.arn,
                    statement_index=statement.index,
                    statement_sid=statement.sid,
                    principal=principal,
                    exposure=assessment,
                    blast_radius=radius,
                    evidence=_evidence(role, statement, conditions),
                )
                finding.title = _title(finding)
                ranking.apply(finding)

                if (
                    assessment.grade == ExposureGrade.INTERNAL
                    and not include_internal
                ):
                    suppressed_internal += 1
                    continue

                role_findings.append(finding)

        result.findings.extend(role_findings)
        result.role_summaries.append(
            RoleSummary(
                role_name=role.role_name,
                role_arn=role.arn,
                trust_statement_count=len(role.trust_statements),
                blast_radius_tier=radius.tier,
                inbound_principal_classes=sorted(set(principal_classes)),
                highest_severity=(
                    min((f.severity for f in role_findings), key=Severity.rank)
                    if role_findings
                    else Severity.INFO
                ),
            )
        )

    result.findings = ranking.rank(result.findings)

    if suppressed_internal:
        result.limitations.append(
            "%d same-account or compute-attachment trust statement(s) were "
            "graded INTERNAL and omitted from the findings list. Re-run with "
            "--include-internal to see them." % suppressed_internal
        )
    if trust_policy_denies:
        result.limitations.append(
            "%d Deny statement(s) in role trust policies were not graded. "
            "TrustEdge does not compute how a trust-policy Deny narrows the "
            "Allow statements alongside it; review those statements by hand."
            % trust_policy_denies
        )
    if not export.roles:
        result.limitations.append(
            "The export contained no analysable roles, so an empty result here "
            "means 'nothing was checked', not 'nothing is wrong'."
        )

    return result


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _not_an_assume_door(
    statement: TrustStatement, assessment: ExposureAssessment
) -> ExposureAssessment:
    """Downgrade a statement that cannot authorise an assume-role call."""
    replacement = ExposureAssessment(
        grade=ExposureGrade.NOT_APPLICABLE,
        rubric=assessment.rubric + "+not_an_assume_action",
        who_can_assume="Nobody, through this statement",
        confidence=Confidence.HIGH,
        references=list(assessment.references),
    )
    replacement.add(
        "This statement's Action element (%s) contains no STS assume-role "
        "operation, so it cannot on its own let anyone become this role. It is "
        "reported for inventory and is not graded for exposure."
        % (", ".join(statement.actions) or "<absent>")
    )
    if statement.actions:
        replacement.add(
            "Statements like this usually accompany an assume-role statement - "
            "for example a separate sts:TagSession grant. Check the other "
            "statements in this trust policy."
        )
    replacement.recommendation = (
        "No action needed unless this statement was meant to grant "
        "sts:AssumeRole, sts:AssumeRoleWithWebIdentity or "
        "sts:AssumeRoleWithSAML."
    )
    replacement.weak_conditions = list(assessment.weak_conditions)
    replacement.limitations = list(assessment.limitations)
    return replacement


def _evidence(
    role: Role, statement: TrustStatement, conditions: ConditionSet
) -> Dict[str, object]:
    """The verbatim trust statement, so a reviewer can check the grade."""
    return {
        "role_name": role.role_name,
        "trust_statement": statement.raw,
        "actions": list(statement.actions),
        "effect": statement.effect,
        "conditions_parsed": conditions.to_dict(),
        "condition_keys_seen": sorted(conditions.keys),
    }


def _title(finding: Finding) -> str:
    grade = finding.exposure.grade
    label = finding.principal.label or finding.principal.raw
    if grade == ExposureGrade.OPEN:
        prefix = "Unguarded inbound trust"
    elif grade == ExposureGrade.WEAK:
        prefix = "Weakly guarded inbound trust"
    elif grade == ExposureGrade.MODERATE:
        prefix = "Partially guarded inbound trust"
    elif grade == ExposureGrade.STRONG:
        prefix = "Guarded inbound trust"
    elif grade == ExposureGrade.INTERNAL:
        prefix = "Internal trust"
    elif grade == ExposureGrade.NOT_APPLICABLE:
        prefix = "Non-assume trust statement"
    else:
        prefix = "Ungradable inbound trust"
    return "%s on %s from %s (blast radius: %s)" % (
        prefix,
        finding.role_name,
        label,
        finding.blast_radius.tier,
    )


def _finding_id(
    role: Role, statement: TrustStatement, position: int, principal_raw: str
) -> str:
    """A stable id: same input, same id, independent of ranking order."""
    return "TE-%s-S%d-P%d-%s" % (
        _slug(role.role_name)[:40],
        statement.index,
        position,
        _slug(principal_raw)[:32] or "principal",
    )


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value or "").strip("-")


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


__all__ = [
    "analyze",
    "analyze_file",
    "ExportFormatError",
    "TOOL_NAME",
    "TOOL_VERSION",
    "GLOBAL_LIMITATIONS",
]
