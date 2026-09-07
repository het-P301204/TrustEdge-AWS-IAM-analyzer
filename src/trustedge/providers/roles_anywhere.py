"""IAM Roles Anywhere rubric.

Roles Anywhere turns an X.509 certificate into AWS credentials. The trust
policy names the service principal ``rolesanywhere.amazonaws.com`` and, per the
AWS trust model documentation, "must grant the permissions: sts:AssumeRole,
sts:SetSourceIdentity, sts:TagSession".

The subtlety worth catching from a static export is that the certificate
attributes Roles Anywhere extracts - Subject, Issuer and SAN, exposed as
``aws:PrincipalTag/x509*`` - are only meaningful *relative to a certificate
authority*. A condition on ``aws:PrincipalTag/x509Subject/CN`` equal to
``deploy-agent`` is satisfied by a certificate with that common name issued by
**any** trust anchor configured in the account. AWS's guidance is to pin the
trust anchor as well:

    "it is strongly recommended that you use the aws:SourceArn or the
    aws:SourceAccount global condition keys or the sts:SourceIdentity condition
    key in your role trust policies. This combination of conditions implements
    least privilege permissions and prevents IAM Roles Anywhere from acting as a
    potential confused deputy. ... the aws:SourceArn and aws:SourceAccount will
    be set based on the ARN of the trust anchor specified in the call to
    CreateSession."

So certificate-attribute conditions without a trust-anchor condition are graded
as partial, not complete.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .. import references
from ..conditions import KeyGuard, analyze_key
from ..context import GradingContext
from ..models import Confidence, ExposureAssessment, ExposureGrade, WeakCondition
from ..policy import has_wildcard, parse_arn

#: The three actions AWS documents as required for a Roles Anywhere role.
REQUIRED_ACTIONS = ("sts:assumerole", "sts:setsourceidentity", "sts:tagsession")

#: Certificate-derived principal tags, from the trust model documentation.
X509_TAG_PREFIXES = (
    "aws:principaltag/x509subject/",
    "aws:principaltag/x509issuer/",
    "aws:principaltag/x509san/",
)


def grade(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="roles_anywhere",
        confidence=Confidence.MEDIUM,
        references=[references.ROLES_ANYWHERE_TRUST_MODEL, references.CONFUSED_DEPUTY],
    )
    conditions = ctx.conditions

    trust_anchor = _trust_anchor_guard(ctx)
    cert_guards = _certificate_guards(ctx)
    source_identity = analyze_key(conditions, "sts:SourceIdentity")
    assessment.weak_conditions.extend(source_identity.weaknesses)
    for _, guard in cert_guards:
        assessment.weak_conditions.extend(guard.weaknesses)
    assessment.weak_conditions.extend(trust_anchor["weaknesses"])

    identity_pinned = bool(cert_guards) or (
        source_identity.guards and not source_identity.all_values_wildcard
    )

    if trust_anchor["pinned"] and identity_pinned:
        assessment.grade = ExposureGrade.STRONG
        assessment.who_can_assume = (
            "A certificate issued under trust anchor %s whose attributes match "
            "%s" % (", ".join(trust_anchor["values"]), _describe(cert_guards, source_identity))
        )
        assessment.add(
            "Both halves of the guard are present: the trust anchor is pinned "
            "with aws:SourceArn and the certificate identity is pinned with %s."
            % _describe(cert_guards, source_identity)
        )
        assessment.recommendation = (
            "Guard looks complete. Keep the certificate revocation list "
            "imported and current - Roles Anywhere does not call CRL "
            "distribution points or OCSP endpoints, so revocation only takes "
            "effect for CRLs you import."
        )
    elif trust_anchor["pinned"]:
        assessment.grade = ExposureGrade.MODERATE
        assessment.who_can_assume = (
            "Any certificate that chains to trust anchor %s"
            % ", ".join(trust_anchor["values"])
        )
        assessment.add(
            "The trust anchor is pinned, so only certificates issued by that "
            "certificate authority can reach this role - but every certificate "
            "that CA issues can, regardless of which workload it belongs to."
        )
        assessment.weaken(
            WeakCondition(
                code="roles_anywhere_identity_not_pinned",
                key="aws:PrincipalTag/x509Subject/CN",
                operator=None,
                detail=(
                    "No condition on the certificate's subject, issuer or SAN, "
                    "and no sts:SourceIdentity condition. Any certificate the "
                    "pinned CA issues - including one issued for an unrelated "
                    "workload - can assume this role."
                ),
            )
        )
        assessment.recommendation = (
            "Add a condition on the certificate identity, for example "
            "\"StringEquals\": "
            "{\"aws:PrincipalTag/x509Subject/CN\": \"<workload-common-name>\"}."
        )
    elif identity_pinned:
        assessment.grade = ExposureGrade.MODERATE
        assessment.who_can_assume = (
            "Any certificate matching %s issued under any trust anchor "
            "configured in this account" % _describe(cert_guards, source_identity)
        )
        assessment.add(
            "The certificate identity is pinned but the trust anchor is not. A "
            "common name is only unique within a certificate authority, so a "
            "certificate with the same subject issued by any other trust anchor "
            "in this account satisfies this condition."
        )
        assessment.weaken(
            WeakCondition(
                code="roles_anywhere_trust_anchor_not_pinned",
                key="aws:SourceArn",
                operator=None,
                detail=(
                    "No aws:SourceArn condition on the trust anchor. AWS sets "
                    "aws:SourceArn from the trust anchor named in the "
                    "CreateSession call and strongly recommends pinning it to "
                    "prevent Roles Anywhere acting as a confused deputy. Without "
                    "it, adding a new trust anchor anywhere in the account "
                    "silently widens this role's trust."
                ),
            )
        )
        assessment.recommendation = (
            "Add \"ArnEquals\": {\"aws:SourceArn\": "
            "\"arn:aws:rolesanywhere:<region>:%s:trust-anchor/<id>\"} so the "
            "certificate identity is only accepted from the CA you intend."
            % (ctx.account_id or "<account-id>")
        )
    else:
        assessment.grade = ExposureGrade.WEAK
        assessment.who_can_assume = (
            "Any X.509 certificate that chains to any IAM Roles Anywhere trust "
            "anchor configured in this account"
        )
        assessment.add(
            "There is no condition on the trust anchor and none on the "
            "certificate identity, so this role is reachable by every "
            "certificate every configured trust anchor will accept."
        )
        assessment.weaken(
            WeakCondition(
                code="roles_anywhere_unconditioned",
                key=None,
                operator=None,
                detail=(
                    "The Roles Anywhere service principal is trusted with no "
                    "conditions. AWS's documentation states it is \"strongly "
                    "recommended\" to constrain these roles with aws:SourceArn, "
                    "aws:SourceAccount or sts:SourceIdentity."
                ),
                vacuous=True,
            )
        )
        assessment.recommendation = (
            "Pin both halves: ArnEquals on aws:SourceArn for the trust anchor, "
            "and StringEquals on aws:PrincipalTag/x509Subject/CN (or "
            "x509Issuer/CN, or x509SAN/DNS) for the workload."
        )
        assessment.recommended_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RolesAnywhere",
                    "Effect": "Allow",
                    "Principal": {"Service": "rolesanywhere.amazonaws.com"},
                    "Action": [
                        "sts:AssumeRole",
                        "sts:TagSession",
                        "sts:SetSourceIdentity",
                    ],
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": (
                                "arn:aws:rolesanywhere:<region>:%s:trust-anchor/<id>"
                                % (ctx.account_id or "<account-id>")
                            )
                        },
                        "StringEquals": {
                            "aws:PrincipalTag/x509Subject/CN": "<workload-common-name>"
                        },
                    },
                }
            ],
        }

    _check_required_actions(ctx, assessment)
    _check_wildcards(cert_guards, assessment)

    assessment.limitations.append(
        "TrustEdge cannot see the account's trust anchors, the CAs behind them, "
        "which certificates have been issued, or whether a certificate "
        "revocation list has been imported. A pinned trust anchor is only as "
        "trustworthy as the CA it points at."
    )
    assessment.limitations.append(
        "AWS's trust model page contains a statement that certificate-derived "
        "values \"cannot\" be used in policy conditions immediately before "
        "showing trust policies that use them in conditions. TrustEdge follows "
        "the worked examples; confirm current behaviour before relying on a "
        "certificate-attribute condition as your only control."
    )
    return assessment


def _trust_anchor_guard(ctx: GradingContext) -> Dict[str, object]:
    result: Dict[str, object] = {"pinned": False, "values": [], "weaknesses": []}
    weaknesses: List[WeakCondition] = []
    values: List[str] = []
    pinned = False

    for key in ("aws:SourceArn", "aws:SourceAccount"):
        guard = analyze_key(ctx.conditions, key)
        weaknesses.extend(guard.weaknesses)
        if not guard.guards or guard.all_values_wildcard:
            continue
        for value in guard.patterns:
            values.append(value)
            if key == "aws:SourceAccount":
                # Bounds the account but not the CA. Better than nothing.
                continue
            arn = parse_arn(value)
            if not arn:
                continue
            if arn["service"] != "rolesanywhere":
                weaknesses.append(
                    WeakCondition(
                        code="roles_anywhere_source_arn_wrong_service",
                        key=key,
                        operator=None,
                        detail=(
                            "aws:SourceArn is %r, which is not an IAM Roles "
                            "Anywhere trust-anchor ARN. Roles Anywhere sets "
                            "aws:SourceArn to the trust anchor used in "
                            "CreateSession, so this condition can never match."
                            % value
                        ),
                    )
                )
                continue
            if "trust-anchor/" in arn["resource"] and not has_wildcard(
                arn["resource"].split("trust-anchor/", 1)[1]
            ):
                pinned = True
            else:
                weaknesses.append(
                    WeakCondition(
                        code="roles_anywhere_trust_anchor_wildcarded",
                        key=key,
                        operator=None,
                        detail=(
                            "aws:SourceArn %r does not pin a single trust "
                            "anchor id, so any trust anchor matching the "
                            "pattern is accepted." % value
                        ),
                    )
                )

    result["pinned"] = pinned
    result["values"] = values
    result["weaknesses"] = weaknesses
    return result


def _certificate_guards(ctx: GradingContext) -> List[Tuple[str, KeyGuard]]:
    out: List[Tuple[str, KeyGuard]] = []
    for entry in ctx.conditions.entries:
        if not any(entry.key_lower.startswith(p) for p in X509_TAG_PREFIXES):
            continue
        guard = analyze_key(ctx.conditions, entry.key)
        if guard.guards and not guard.all_values_wildcard:
            if all(key != entry.key for key, _ in out):
                out.append((entry.key, guard))
    return out


def _describe(
    cert_guards: List[Tuple[str, KeyGuard]], source_identity: KeyGuard
) -> str:
    parts = [
        "%s=%s" % (key, ", ".join(guard.patterns)) for key, guard in cert_guards
    ]
    if source_identity.guards and not source_identity.all_values_wildcard:
        parts.append("sts:SourceIdentity=%s" % ", ".join(source_identity.patterns))
    return "; ".join(parts) if parts else "<nothing>"


def _check_required_actions(
    ctx: GradingContext, assessment: ExposureAssessment
) -> None:
    granted = {a.lower() for a in ctx.statement.actions}
    if "sts:*" in granted or "*" in granted:
        return
    missing = [a for a in REQUIRED_ACTIONS if a not in granted]
    if not missing:
        return
    assessment.fail_closed_notes.append(
        "This statement does not grant %s. AWS documents all of sts:AssumeRole, "
        "sts:SetSourceIdentity and sts:TagSession as required for a Roles "
        "Anywhere role, so CreateSession is likely to fail against it. That is "
        "a fail-closed defect, not exposure - but it also means any conditions "
        "here are not being exercised."
        % ", ".join(
            {
                "sts:assumerole": "sts:AssumeRole",
                "sts:setsourceidentity": "sts:SetSourceIdentity",
                "sts:tagsession": "sts:TagSession",
            }[m]
            for m in missing
        )
    )


def _check_wildcards(
    cert_guards: List[Tuple[str, KeyGuard]], assessment: ExposureAssessment
) -> None:
    for key, guard in cert_guards:
        for value in guard.patterns:
            if has_wildcard(value):
                assessment.weaken(
                    WeakCondition(
                        code="roles_anywhere_certificate_pattern_broad",
                        key=key,
                        operator=None,
                        detail=(
                            "%s is matched with the pattern %r, so any "
                            "certificate whose attribute matches is accepted."
                            % (key, value)
                        ),
                    )
                )
