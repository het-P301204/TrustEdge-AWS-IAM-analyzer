"""SAML 2.0 federation rubric.

The exposure question for a SAML role is narrower than it looks. The IAM SAML
provider pins *which* identity provider is trusted, so the door is already
bounded to whoever that IdP will issue an assertion for. What the trust policy
can add is a restriction on *which* of those identities may take this
particular role.

AWS's canonical SAML trust policy contains exactly one condition,
``SAML:aud`` equal to ``https://signin.aws.amazon.com/saml``. That pins the
assertion's intended recipient endpoint - it says nothing about the user. A
trust policy with only ``saml:aud`` therefore trusts every user the IdP will
authenticate, which is fine for a single-purpose IdP and much too broad for a
corporate directory.

TrustEdge grades on that distinction and is explicit that it cannot see the
IdP's own role-assignment rules, which in most real deployments are the
control that actually matters.
"""

from __future__ import annotations

from typing import List

from .. import references
from ..conditions import analyze_key
from ..context import GradingContext
from ..models import Confidence, ExposureAssessment, ExposureGrade, WeakCondition
from ..policy import has_wildcard

#: Condition keys that identify the individual behind the assertion, from
#: "Available keys for SAML-based AWS STS federation".
SAML_SUBJECT_KEYS = (
    "saml:sub",
    "saml:namequalifier",
    "saml:edupersonprincipalname",
    "saml:uid",
    "saml:mail",
    "saml:commonName",
    "saml:name",
    "saml:x500UniqueIdentifier",
)

#: Keys that identify a group or affiliation rather than one person.
SAML_GROUP_KEYS = (
    "saml:edupersonaffiliation",
    "saml:edupersonscopedaffiliation",
    "saml:edupersonprimaryaffiliation",
    "saml:edupersonentitlement",
    "saml:organizationStatus",
    "saml:primaryGroupSID",
    "saml:cn",
)

AWS_SAML_ENDPOINTS = (
    "https://signin.aws.amazon.com/saml",
    "https://signin.amazonaws-us-gov.com/saml",
    "https://signin.amazonaws.cn/saml",
)


def grade(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="saml.federation",
        confidence=Confidence.MEDIUM,
        references=[references.IAM_STS_CONDITION_KEYS],
    )
    provider_name = ctx.principal.provider_id or ctx.principal.raw
    conditions = ctx.conditions

    known = any(
        p.name == provider_name or (p.arn or "") == ctx.principal.raw
        for p in ctx.export.saml_providers
    )
    if ctx.export.saml_providers and not known:
        assessment.add(
            "The SAML provider %r is referenced by this trust policy but is not "
            "in the export's saml_providers list, so either the export is "
            "incomplete or the provider has been deleted." % provider_name
        )

    aud = analyze_key(conditions, "saml:aud")
    assessment.weak_conditions.extend(aud.weaknesses)

    subject_guards = []
    for key in SAML_SUBJECT_KEYS:
        guard = analyze_key(conditions, key)
        assessment.weak_conditions.extend(guard.weaknesses)
        if guard.guards and not guard.all_values_wildcard:
            subject_guards.append((key, guard))

    group_guards = []
    for key in SAML_GROUP_KEYS:
        guard = analyze_key(conditions, key)
        assessment.weak_conditions.extend(guard.weaknesses)
        if guard.guards and not guard.all_values_wildcard:
            group_guards.append((key, guard))

    if subject_guards:
        assessment.grade = ExposureGrade.STRONG
        assessment.who_can_assume = (
            "Users federated through %s whose assertion matches %s"
            % (
                provider_name,
                ", ".join(
                    "%s=%s" % (key, ", ".join(guard.patterns))
                    for key, guard in subject_guards
                ),
            )
        )
        assessment.add(
            "The statement pins the federated identity itself (%s), not just the "
            "assertion's recipient." % ", ".join(key for key, _ in subject_guards)
        )
        assessment.recommendation = (
            "Scoping is specific. Confirm the pinned subject values are stable: "
            "AWS notes that a saml:sub_type of 'transient' means saml:sub "
            "changes every session, so a transient subject cannot be pinned "
            "reliably."
        )
    elif group_guards:
        assessment.grade = ExposureGrade.MODERATE
        assessment.who_can_assume = (
            "Any user federated through %s whose assertion carries %s"
            % (
                provider_name,
                ", ".join(
                    "%s=%s" % (key, ", ".join(guard.patterns))
                    for key, guard in group_guards
                ),
            )
        )
        assessment.add(
            "Access is scoped by a group or affiliation attribute (%s). The "
            "boundary is only as good as the IdP's control over that attribute."
            % ", ".join(key for key, _ in group_guards)
        )
        assessment.recommendation = (
            "Group-based scoping is reasonable. Verify that the attribute is "
            "populated by the IdP and not settable by the user, and that the "
            "attribute is asserted with a ForAllValues set operator paired with "
            "a Null check if it is multi-valued."
        )
    elif aud.guards and not aud.all_values_wildcard:
        assessment.grade = ExposureGrade.MODERATE
        assessment.who_can_assume = (
            "Any user that %s will issue a SAML assertion for" % provider_name
        )
        assessment.add(
            "The only condition is saml:aud (%s), which pins the endpoint the "
            "assertion is addressed to. It does not restrict which user the "
            "assertion is about, so every identity the IdP federates can take "
            "this role as far as IAM is concerned."
            % ", ".join(aud.patterns)
        )
        assessment.weaken(
            WeakCondition(
                code="saml_no_subject_condition",
                key="saml:sub",
                operator=None,
                detail=(
                    "No condition on the federated identity. saml:aud restricts "
                    "the assertion's recipient, not its subject. If the IdP "
                    "federates a whole corporate directory, the trust policy "
                    "places no limit on which employee can assume this role."
                ),
            )
        )
        if not any(v in AWS_SAML_ENDPOINTS for v in aud.patterns):
            assessment.add(
                "The saml:aud value (%s) is not one of the standard AWS SAML "
                "endpoints; confirm it matches the Recipient your IdP sends."
                % ", ".join(aud.patterns)
            )
        assessment.recommendation = (
            "Add a condition on the identity: saml:sub for a named user, or a "
            "group attribute such as saml:edupersonaffiliation for a role "
            "assigned to a team. If the IdP is the authority for role "
            "assignment, document that decision - IAM is not enforcing it here."
        )
    else:
        assessment.grade = ExposureGrade.WEAK
        assessment.who_can_assume = (
            "Any user that %s will issue a SAML assertion for, with no "
            "restriction on the assertion's audience" % provider_name
        )
        assessment.add(
            "There is no effective condition on this SAML trust statement - not "
            "even saml:aud, which appears in every AWS SAML example."
        )
        assessment.weaken(
            WeakCondition(
                code="saml_no_conditions",
                key="saml:aud",
                operator=None,
                detail=(
                    "No saml:aud condition. AWS's documented SAML role trust "
                    "policy pins saml:aud to the AWS sign-in endpoint so an "
                    "assertion minted for a different relying party cannot be "
                    "replayed against AWS."
                ),
                vacuous=True,
            )
        )
        assessment.recommendation = (
            "At minimum add \"StringEquals\": "
            "{\"SAML:aud\": \"https://signin.aws.amazon.com/saml\"}, then a "
            "condition on the federated identity or its group membership."
        )
        assessment.recommended_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SamlFederation",
                    "Effect": "Allow",
                    "Principal": {"Federated": ctx.principal.raw},
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {
                        "StringEquals": {
                            "SAML:aud": "https://signin.aws.amazon.com/saml"
                        }
                    },
                }
            ],
        }

    _note_sub_type(ctx, assessment)
    _note_wildcards(assessment, aud.patterns)

    assessment.limitations.append(
        "TrustEdge cannot see the identity provider. Which users the IdP will "
        "issue an assertion for, and which AWS roles it advertises to them, are "
        "decided outside AWS and are usually the real access control for SAML "
        "federation."
    )
    assessment.limitations.append(
        "AWS states that only saml:namequalifier, saml:sub and saml:sub_type "
        "remain available after the initial IdP authentication response, so a "
        "condition on any other SAML key applies to the AssumeRoleWithSAML call "
        "alone and not to onward role chaining."
    )
    return assessment


def _note_sub_type(ctx: GradingContext, assessment: ExposureAssessment) -> None:
    guard = analyze_key(ctx.conditions, "saml:sub_type")
    assessment.weak_conditions.extend(guard.weaknesses)
    if not guard.guards:
        return
    values = [v.lower() for v in guard.patterns]
    if "transient" in values:
        assessment.add(
            "saml:sub_type is pinned to 'transient', which AWS documents as "
            "meaning the user has a different saml:sub value for each session. "
            "Any saml:sub condition alongside this cannot identify a person "
            "across sessions."
        )
    elif "persistent" in values:
        assessment.add(
            "saml:sub_type is pinned to 'persistent', so saml:sub is stable "
            "between sessions and is a usable identifier."
        )


def _note_wildcards(assessment: ExposureAssessment, values: List[str]) -> None:
    for value in values:
        if has_wildcard(value):
            assessment.weaken(
                WeakCondition(
                    code="saml_aud_wildcard",
                    key="saml:aud",
                    operator=None,
                    detail=(
                        "The saml:aud value %r contains a wildcard, so "
                        "assertions addressed to other relying parties may match."
                        % value
                    ),
                )
            )
