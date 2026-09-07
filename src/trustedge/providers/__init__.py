"""Provider-aware condition-strength rubrics.

Each module here answers one question for one class of principal: *given this
trust statement's conditions, how strongly is the door guarded against
identities outside the account?*

The rubrics are deliberately separate because the same missing condition means
very different things depending on who is on the other side of the door. A
trust policy with no ``sub`` condition is catastrophic for a **shared** OIDC
issuer such as ``token.actions.githubusercontent.com`` (every GitHub customer
mints tokens from it) and merely sloppy for a **private** issuer such as an EKS
cluster's own OIDC endpoint (only workloads in that cluster can mint tokens).
Collapsing those into one "condition missing" check is how a scanner earns a
reputation for false positives.
"""

from __future__ import annotations

from ..context import GradingContext
from ..models import ExposureAssessment, ExposureGrade, PrincipalClass
from . import aws, oidc, roles_anywhere, saml

__all__ = ["grade_principal", "aws", "oidc", "roles_anywhere", "saml"]


def grade_principal(ctx: GradingContext) -> ExposureAssessment:
    """Dispatch to the rubric that matches the principal's classification."""
    klass = ctx.principal.principal_class

    if klass == PrincipalClass.OIDC:
        return oidc.grade(ctx)
    if klass == PrincipalClass.SAML:
        return saml.grade(ctx)
    if klass == PrincipalClass.ROLES_ANYWHERE:
        return roles_anywhere.grade(ctx)
    if klass == PrincipalClass.AWS_SERVICE:
        return aws.grade_service(ctx)
    if klass == PrincipalClass.WILDCARD:
        return aws.grade_wildcard(ctx)
    if klass in (PrincipalClass.SAME_ACCOUNT, PrincipalClass.CROSS_ACCOUNT):
        return aws.grade_account(ctx)
    if klass == PrincipalClass.CANONICAL_USER:
        return aws.grade_canonical_user(ctx)

    assessment = ExposureAssessment(
        grade=ExposureGrade.NOT_DETERMINED,
        rubric="unsupported",
        who_can_assume="Unknown - TrustEdge could not classify this principal.",
        confidence="low",
    )
    assessment.add(
        "The Principal value %r does not match any principal form TrustEdge "
        "knows how to grade. Review this statement by hand."
        % ctx.principal.raw
    )
    assessment.limitations.append(
        "Unclassified principals are reported so they are not silently dropped, "
        "but no exposure grade is asserted."
    )
    assessment.recommendation = (
        "Review this trust statement manually and, if the principal form is a "
        "legitimate one TrustEdge should support, open an issue with a "
        "synthetic example."
    )
    return assessment
