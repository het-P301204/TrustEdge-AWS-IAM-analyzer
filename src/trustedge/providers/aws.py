"""Rubrics for AWS-native principals: accounts, wildcards and service principals.

Three distinct doors live in this module and they are graded separately because
they fail in different ways:

* **A specific external account** is bounded - only principals in that account
  can walk through - but it is bounded to an account you do not administer, and
  in a multi-tenant vendor that means every one of the vendor's customers is one
  configuration mistake away from your role. That is the confused deputy
  problem, and ``sts:ExternalId`` is the documented mitigation.
* **A wildcard principal** is not bounded at all. Only a condition can bound it,
  and only a condition on an *identity* key really does: AWS states plainly
  that "AWS does not treat the external ID as a secret", so ``Principal: "*"``
  plus ``sts:ExternalId`` is a weak guard, not a strong one.
* **An AWS service principal** is bounded to a service, but the service acts on
  behalf of *someone*, and the trust policy authorises the service rather than
  the person who configured it. ``aws:SourceAccount`` / ``aws:SourceArn`` /
  ``aws:SourceOrgID`` restore the missing half of that check.
"""

from __future__ import annotations

import re
import string
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import references
from ..conditions import analyze_key
from ..context import GradingContext
from ..models import (
    Confidence,
    ExposureAssessment,
    ExposureGrade,
    PrincipalClass,
    WeakCondition,
)
from ..policy import (
    ACCOUNT_ID_RE,
    has_wildcard,
    is_pure_wildcard,
    literal_prefix,
    parse_arn,
    principal_is_account_root,
)

#: Condition keys that bound *who* the caller is, as opposed to how or from
#: where they are calling. Only these can turn a wildcard principal into a
#: bounded one.
IDENTITY_BOUNDING_KEYS = (
    "aws:principalarn",
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalisawsservice",
    "aws:principalservicename",
    "aws:userid",
    "aws:principaltag",
    "aws:federatedprovider",
)

#: Keys that narrow the request but do not identify the caller.
CONTEXTUAL_KEYS = (
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:viaawsservice",
    "aws:securetransport",
    "aws:requestedregion",
    "aws:currenttime",
    "aws:epochtime",
    "aws:multifactorauthpresent",
    "aws:multifactorauthage",
    "sts:externalid",
    "sts:rolesessionname",
)

#: External ID values that provide no protection because anyone could guess them.
EXTERNAL_ID_DENYLIST = {
    "changeme",
    "external",
    "externalid",
    "external-id",
    "external_id",
    "secret",
    "password",
    "placeholder",
    "test",
    "testing",
    "todo",
    "tbd",
    "none",
    "null",
    "default",
    "aws",
    "vendor",
    "customer",
    "example",
    "12345",
    "123456",
    "0000",
}

#: Below this length an external ID is treated as guessable. AWS permits two
#: characters, which is why the minimum the API accepts is not a useful floor.
EXTERNAL_ID_MIN_LENGTH = 16

_SERVICE_PRINCIPAL_RE = re.compile(r"^[a-z0-9.\-]+\.amazonaws\.com(\.cn)?$")


# --------------------------------------------------------------------------
# Account principals (same-account and cross-account)
# --------------------------------------------------------------------------


def grade_account(ctx: GradingContext) -> ExposureAssessment:
    if ctx.principal.principal_class == PrincipalClass.SAME_ACCOUNT:
        return _grade_same_account(ctx)
    return _grade_cross_account(ctx)


def _grade_same_account(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        grade=ExposureGrade.INTERNAL,
        rubric="aws.same_account",
        confidence=Confidence.HIGH,
        references=[references.CROSS_ACCOUNT_RESOURCE_ACCESS],
    )
    root = principal_is_account_root(ctx.principal.raw)
    if root:
        assessment.who_can_assume = (
            "Any IAM principal in this account (%s) that also holds "
            "sts:AssumeRole permission on this role"
            % (ctx.principal.account_id or "same account")
        )
        assessment.add(
            "The principal is this account's root ARN, which delegates the "
            "decision to identity-based policies: any principal in the account "
            "whose own policy allows sts:AssumeRole on this role can assume it."
        )
        assessment.recommendation = (
            "If only a few principals should assume this role, name them in the "
            "trust policy instead of the account root, or add an "
            "aws:PrincipalArn condition. Relying solely on identity-based "
            "policies means a broad 'sts:AssumeRole on *' grant anywhere in the "
            "account reaches this role."
        )
    else:
        assessment.who_can_assume = "The named principal in this account: %s" % (
            ctx.principal.raw
        )
        assessment.add(
            "The principal is inside the account under analysis, so this "
            "statement is not an inbound trust boundary."
        )
        assessment.recommendation = "No inbound exposure from this statement."

    assessment.add(
        "TrustEdge reports same-account trust for completeness but does not "
        "treat it as inbound exposure; use --include-internal to rank it."
    )
    assessment.limitations.append(
        "Same-account assume paths are an internal privilege-escalation "
        "question. Tools that model intra-account escalation graphs (for "
        "example PMapper) answer that better than TrustEdge does."
    )
    return assessment


def _grade_cross_account(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="aws.cross_account",
        confidence=Confidence.HIGH,
        references=[
            references.THIRD_PARTY_ACCESS,
            references.CONFUSED_DEPUTY,
            references.CROSS_ACCOUNT_EVALUATION,
        ],
    )
    account_id = ctx.principal.account_id
    root = principal_is_account_root(ctx.principal.raw)
    declared_trusted = bool(
        account_id and account_id in (ctx.export.trusted_account_ids or [])
    )
    vendor = ctx.export.vendor_accounts.get(account_id or "")

    # -- baseline from how broad the named principal is --------------------
    if root:
        grade = ExposureGrade.WEAK
        assessment.who_can_assume = (
            "Any IAM principal in AWS account %s" % (account_id or "<unknown>")
        )
        assessment.add(
            "The principal is the account root ARN of external account %s, so "
            "every IAM user and role in that account is a candidate caller - "
            "not just the one the integration needs."
            % (account_id or "<unknown>")
        )
    else:
        grade = ExposureGrade.MODERATE
        assessment.who_can_assume = "The external principal %s" % ctx.principal.raw
        assessment.add(
            "The principal names a specific identity in external account %s "
            "rather than the whole account, which is the right shape."
            % (account_id or "<unknown>")
        )

    if vendor:
        assessment.add(
            "The operator's vendor mapping identifies %s as %s%s."
            % (
                account_id,
                vendor.vendor,
                (" (%s)" % vendor.notes) if vendor.notes else "",
            )
        )
        assessment.limitations.append(
            "The vendor name comes from the operator-supplied mapping in the "
            "export. TrustEdge performs no lookup and does not verify that "
            "account %s is still owned or operated by %s." % (account_id, vendor.vendor)
        )
    elif account_id and not declared_trusted:
        assessment.add(
            "Account %s is not listed in trusted_account_ids and has no vendor "
            "mapping entry, so TrustEdge cannot tell whether this relationship "
            "is still intended." % account_id
        )
        assessment.limitations.append(
            "Whether a cross-account relationship is still wanted is a business "
            "question. Populate vendor_accounts and trusted_account_ids in the "
            "export to turn this into a reviewable inventory."
        )

    if declared_trusted:
        assessment.add(
            "Account %s is declared in trusted_account_ids, so this is trust "
            "you own on both ends." % account_id
        )
        grade = ExposureGrade.MODERATE if root else ExposureGrade.STRONG

    # -- external ID -------------------------------------------------------
    external_id = _assess_external_id(ctx)
    assessment.weak_conditions.extend(external_id["weaknesses"])
    for note in external_id["notes"]:
        assessment.add(note)

    third_party = bool(vendor) or not declared_trusted

    if external_id["effective"] and external_id["strong"]:
        grade = _improve(grade)
        assessment.add(
            "That is the documented mitigation for the cross-account confused "
            "deputy problem, so the grade improves one step."
        )
    elif external_id["effective"]:
        assessment.add(
            "sts:ExternalId is required but the value itself is weak, so it "
            "raises the bar far less than it appears to."
        )
    elif third_party:
        assessment.weaken(
            WeakCondition(
                code="external_id_missing",
                key="sts:ExternalId",
                operator=None,
                detail=(
                    "No sts:ExternalId condition on a trust relationship with an "
                    "account you do not administer. If that account runs a "
                    "multi-tenant service, another of its customers can ask it to "
                    "assume this role by supplying your role ARN - the role ARN "
                    "is not a secret. AWS documents the external ID as the "
                    "mitigation and requires it to be generated by the third "
                    "party, one per customer."
                ),
            )
        )
        assessment.add(
            "There is no sts:ExternalId condition, so nothing ties a call from "
            "account %s to your tenancy specifically."
            % (account_id or "<unknown>")
        )

    # -- other identity-bounding conditions --------------------------------
    principal_arn = analyze_key(ctx.conditions, "aws:PrincipalArn")
    assessment.weak_conditions.extend(principal_arn.weaknesses)
    if principal_arn.guards and not principal_arn.all_values_wildcard:
        if all(not has_wildcard(v) for v in principal_arn.patterns):
            grade = ExposureGrade.STRONG
            assessment.add(
                "aws:PrincipalArn pins the caller to %s, which narrows the door "
                "past the account boundary." % ", ".join(principal_arn.patterns)
            )
        else:
            grade = _improve(grade)
            assessment.add(
                "aws:PrincipalArn narrows the caller with a pattern (%s)."
                % ", ".join(principal_arn.patterns)
            )

    org_id = analyze_key(ctx.conditions, "aws:PrincipalOrgID")
    assessment.weak_conditions.extend(org_id.weaknesses)
    if org_id.guards and not org_id.all_values_wildcard:
        grade = _improve(grade)
        assessment.add(
            "aws:PrincipalOrgID restricts callers to organisation %s."
            % ", ".join(org_id.patterns)
        )

    mfa = analyze_key(ctx.conditions, "aws:MultiFactorAuthPresent")
    if mfa.guards and any(v.lower() == "true" for v in mfa.patterns):
        assessment.add(
            "aws:MultiFactorAuthPresent is required, which is meaningful for "
            "human callers but is not satisfiable by a service integration."
        )

    assessment.grade = grade
    _add_cross_account_recommendation(ctx, assessment, external_id, root, third_party)
    assessment.limitations.append(
        "A cross-account caller also needs sts:AssumeRole in their own "
        "identity-based policy: AWS states that \"in cross account access, a "
        "principal needs an Allow in the identity policy and the resource-based "
        "policy\". TrustEdge only sees your side, so a finding here describes "
        "reachability from your account's perspective, not a proven path."
    )
    return assessment


def _add_cross_account_recommendation(
    ctx: GradingContext,
    assessment: ExposureAssessment,
    external_id: Dict[str, Any],
    root: bool,
    third_party: bool,
) -> None:
    steps: List[str] = []
    if root:
        steps.append(
            "replace the account root principal with the specific role ARN in "
            "that account that performs the integration"
        )
    if third_party and not (external_id["effective"] and external_id["strong"]):
        steps.append(
            "require sts:ExternalId with the unique, high-entropy value the "
            "third party generates for your tenancy (ask them for it; do not "
            "invent one yourself)"
        )
    if not steps:
        assessment.recommendation = (
            "The inbound guard on this relationship looks reasonable. Re-confirm "
            "periodically that the relationship is still contractually current."
        )
        return

    assessment.recommendation = (
        "Tighten this relationship: " + "; ".join(steps) + "."
    )
    # A safe rewrite is only possible when we are not inventing values.
    if root and not third_party:
        assessment.recommendation += (
            " TrustEdge does not emit a rewritten policy because it cannot know "
            "which principal in the trusted account should be named."
        )
    elif external_id["effective"] and not external_id["strong"]:
        assessment.recommendation += (
            " The existing external ID value is deliberately not reproduced in "
            "a suggested policy: replacing it requires coordinating with the "
            "third party so the new value is used on both sides."
        )
    else:
        assessment.recommended_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ThirdPartyAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            "arn:aws:iam::%s:role/<integration-role>"
                            % (ctx.principal.account_id or "<account-id>")
                        )
                        if root
                        else ctx.principal.raw
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "<value-supplied-by-the-third-party>"
                        }
                    },
                }
            ],
        }


# --------------------------------------------------------------------------
# Wildcard principals
# --------------------------------------------------------------------------


def grade_wildcard(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="aws.wildcard_principal",
        confidence=Confidence.HIGH,
        references=[
            references.GLOBAL_CONDITION_KEYS,
            references.CONDITION_OPERATORS,
            references.ACCESS_ANALYZER,
        ],
    )
    conditions = ctx.conditions

    if not conditions.entries:
        assessment.grade = ExposureGrade.OPEN
        assessment.who_can_assume = (
            "Any principal in any AWS account. This role's credentials are "
            "obtainable by anyone who knows the role ARN."
        )
        assessment.add(
            "The Principal is a wildcard and there is no Condition element at "
            "all, so nothing narrows who may call sts:AssumeRole on this role."
        )
        assessment.weaken(
            WeakCondition(
                code="wildcard_principal_unconditioned",
                key=None,
                operator=None,
                detail=(
                    "Principal '*' with no conditions. The role ARN is the only "
                    "thing standing between an arbitrary AWS caller and "
                    "credentials in this account, and role ARNs are not secrets."
                ),
                vacuous=True,
            )
        )
        assessment.recommendation = (
            "Replace the wildcard with the specific principals that need access. "
            "If the caller genuinely cannot be enumerated, bound it with "
            "aws:PrincipalOrgID (for your own organisation) or aws:PrincipalArn, "
            "and treat sts:ExternalId as an anti-confused-deputy measure rather "
            "than an authentication control."
        )
        return assessment

    identity_keys: List[str] = []
    contextual_keys: List[str] = []
    unknown_keys: List[str] = []
    effective_identity: List[Tuple[str, Any]] = []

    for entry in conditions.entries:
        key = entry.key_lower
        base = key.split("/", 1)[0]
        if base in IDENTITY_BOUNDING_KEYS:
            identity_keys.append(entry.key)
        elif base in CONTEXTUAL_KEYS:
            contextual_keys.append(entry.key)
        elif entry.is_null_check:
            continue
        else:
            unknown_keys.append(entry.key)

    neutralised_identity: List[str] = []
    for key in sorted(set(identity_keys)):
        guard = analyze_key(conditions, key)
        assessment.weak_conditions.extend(guard.weaknesses)
        if guard.guards and not guard.all_values_wildcard:
            effective_identity.append((key, guard))
        else:
            neutralised_identity.append(key)

    # Grade from the strongest *identity* bound that is actually evaluated.
    grade = ExposureGrade.OPEN
    for key, guard in effective_identity:
        base = key.lower().split("/", 1)[0]
        if base == "aws:principalarn" and all(
            not has_wildcard(v) for v in guard.patterns
        ):
            grade = _strongest(grade, ExposureGrade.STRONG)
            assessment.add(
                "aws:PrincipalArn pins the caller to %s." % ", ".join(guard.patterns)
            )
        elif base in ("aws:principalorgid", "aws:principalorgpaths"):
            grade = _strongest(grade, ExposureGrade.MODERATE)
            assessment.add(
                "%s bounds callers to organisation %s, so the wildcard is "
                "effectively 'anyone in that organisation'."
                % (key, ", ".join(guard.patterns))
            )
        elif base == "aws:principalaccount":
            grade = _strongest(grade, ExposureGrade.MODERATE)
            assessment.add(
                "aws:PrincipalAccount bounds callers to account %s."
                % ", ".join(guard.patterns)
            )
        elif base == "aws:principaltag":
            grade = _strongest(grade, ExposureGrade.WEAK)
            assessment.add(
                "%s bounds callers by a principal tag. Tags in the caller's own "
                "account are set by that account's administrators, so this is a "
                "weak boundary against an untrusted account." % key
            )
        else:
            grade = _strongest(grade, ExposureGrade.WEAK)
            assessment.add("%s narrows the caller partially." % key)

    external_id = _assess_external_id(ctx)
    assessment.weak_conditions.extend(external_id["weaknesses"])
    for note in external_id["notes"]:
        assessment.add(note)

    if not effective_identity:
        if external_id["effective"]:
            grade = ExposureGrade.WEAK
            assessment.add(
                "The only guard on this wildcard principal is sts:ExternalId. "
                "AWS states that \"AWS does not treat the external ID as a "
                "secret\" and that it \"can be seen by anyone with permission to "
                "view the role\", so it is a confused-deputy control, not an "
                "authentication control. Combined with Principal '*' it does not "
                "establish who the caller is."
            )
            assessment.weaken(
                WeakCondition(
                    code="wildcard_principal_external_id_only",
                    key="sts:ExternalId",
                    operator=None,
                    detail=(
                        "Principal '*' guarded only by sts:ExternalId. The "
                        "external ID is documented as non-secret, so anyone who "
                        "learns it - including from a read-only view of this "
                        "role - can assume the role from any AWS account."
                    ),
                )
            )
        elif contextual_keys:
            grade = ExposureGrade.WEAK
            assessment.add(
                "Conditions are present (%s) but none of them identify the "
                "caller, so any AWS principal that satisfies the contextual "
                "constraints can assume this role."
                % ", ".join(sorted(set(contextual_keys)))
            )
            assessment.weaken(
                WeakCondition(
                    code="wildcard_principal_contextual_conditions_only",
                    key=", ".join(sorted(set(contextual_keys))),
                    operator=None,
                    detail=(
                        "The conditions restrict how or from where the call is "
                        "made, not who makes it. Network-shaped controls such as "
                        "aws:SourceIp do not bound identity."
                    ),
                )
            )
        elif neutralised_identity:
            assessment.add(
                "An identity-bounding condition is written on this statement "
                "(%s) but it does not take effect - see the weak conditions "
                "below. The wildcard principal is therefore unguarded."
                % ", ".join(neutralised_identity)
            )
        else:
            assessment.add(
                "Conditions are present but TrustEdge does not recognise any of "
                "them as bounding the caller's identity: %s."
                % ", ".join(sorted(set(unknown_keys)) or ["<none readable>"])
            )
            assessment.confidence = Confidence.MEDIUM
            assessment.limitations.append(
                "Unrecognised condition keys are not credited as guards. If one "
                "of them does bound identity, the real exposure is lower than "
                "graded."
            )

    assessment.grade = grade
    if grade == ExposureGrade.OPEN:
        assessment.who_can_assume = "Any principal in any AWS account"
    elif not assessment.who_can_assume:
        assessment.who_can_assume = (
            "Any AWS principal satisfying: %s"
            % ", ".join(sorted({k for k, _ in effective_identity}) or ["<no identity bound>"])
        )

    if not assessment.recommendation:
        assessment.recommendation = (
            "A wildcard principal should be the last resort. Name the trusted "
            "accounts or roles explicitly; if you must keep the wildcard, add an "
            "identity-bounding condition (aws:PrincipalOrgID or "
            "aws:PrincipalArn) rather than relying on sts:ExternalId or network "
            "conditions."
        )
    return assessment


def grade_canonical_user(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        grade=ExposureGrade.NOT_DETERMINED,
        rubric="aws.canonical_user",
        confidence=Confidence.LOW,
        who_can_assume="The AWS account owning canonical user id %s"
        % ctx.principal.raw,
        references=[references.GLOBAL_CONDITION_KEYS],
    )
    assessment.add(
        "CanonicalUser identifies an account by its S3 canonical user id. "
        "TrustEdge cannot map a canonical user id to an account number offline, "
        "so it does not assert whether this is same-account or cross-account."
    )
    assessment.limitations.append(
        "Resolving a canonical user id to an AWS account requires an API call, "
        "which TrustEdge deliberately does not make."
    )
    assessment.recommendation = (
        "Replace the canonical user id with the account id or a role ARN so the "
        "relationship is readable, then re-run the analysis."
    )
    return assessment


# --------------------------------------------------------------------------
# AWS service principals
# --------------------------------------------------------------------------

# Not every Service principal is an inbound trust boundary, and treating them
# alike is the fastest way to bury a real finding under a hundred false ones.
#
# A *compute attachment* service principal exists so that your own workload -
# an EC2 instance, a Lambda function, a pod - can obtain the role's
# credentials. The role is only reachable by whoever can attach the role to, or
# execute code in, that workload, which is a same-account authorisation
# question that an IAM export cannot answer. TrustEdge grades these INTERNAL
# and says where the real control lives, instead of reporting "missing
# aws:SourceAccount" on every Lambda role in the account.
#
# Every other service principal is graded as a confused-deputy review item,
# because the trust policy authorises the service and not the person who
# configured the service.
COMPUTE_ATTACHMENT_SERVICES = {
    "ec2.amazonaws.com": (
        "An EC2 instance-profile role is reachable by whoever can launch an "
        "instance with this profile, or reach a running instance's instance "
        "metadata service. Neither is visible in an IAM export."
    ),
    "lambda.amazonaws.com": (
        "A Lambda execution role is reachable by whoever can create or update a "
        "function that uses it. The controlling permissions are lambda:* and "
        "iam:PassRole in this account, not this trust policy."
    ),
    "ecs-tasks.amazonaws.com": (
        "An ECS task role is reachable by whoever can register or run a task "
        "definition that references it."
    ),
    "pods.eks.amazonaws.com": (
        "EKS Pod Identity binds this role to a namespace and service account "
        "through a pod identity association, which is EKS configuration and is "
        "not present in an IAM export."
    ),
    "eks.amazonaws.com": (
        "An EKS cluster service role is used by the EKS control plane for the "
        "clusters it is attached to."
    ),
    "codebuild.amazonaws.com": (
        "A CodeBuild service role is reachable by whoever can create or update a "
        "build project that uses it - and by anyone who can influence what that "
        "project builds."
    ),
    "states.amazonaws.com": (
        "A Step Functions role is reachable by whoever can create or update a "
        "state machine that uses it."
    ),
    "glue.amazonaws.com": (
        "A Glue role is reachable by whoever can create or update a job or "
        "crawler that uses it."
    ),
    "sagemaker.amazonaws.com": (
        "A SageMaker role is reachable by whoever can create a notebook, "
        "training job or endpoint that uses it."
    ),
    "batch.amazonaws.com": (
        "A Batch role is reachable by whoever can submit a job definition that "
        "uses it."
    ),
    "apprunner.amazonaws.com": (
        "An App Runner role is reachable by whoever can create or update a "
        "service that uses it."
    ),
    "tasks.apprunner.amazonaws.com": (
        "An App Runner instance role is reachable by whoever can create or "
        "update a service that uses it."
    ),
    "build.apprunner.amazonaws.com": (
        "An App Runner build role is reachable by whoever can create or update "
        "a service that uses it."
    ),
    "ssm.amazonaws.com": (
        "An SSM automation role is reachable by whoever can start an automation "
        "execution that uses it."
    ),
    "cloudformation.amazonaws.com": (
        "A CloudFormation service role is reachable by whoever can create or "
        "update a stack that passes it - which effectively grants the role's "
        "permissions to that principal."
    ),
    "eks-nodegroup.amazonaws.com": (
        "An EKS node group role is used by the managed nodes it is attached to."
    ),
    "elasticmapreduce.amazonaws.com": (
        "An EMR role is reachable by whoever can create a cluster that uses it."
    ),
}


def grade_service(ctx: GradingContext) -> ExposureAssessment:
    service = (ctx.principal.provider_id or ctx.principal.raw).lower()
    assessment = ExposureAssessment(
        rubric="aws.service_principal",
        confidence=Confidence.MEDIUM,
        references=[references.CONFUSED_DEPUTY, references.GLOBAL_CONDITION_KEYS],
    )

    if not _SERVICE_PRINCIPAL_RE.match(service):
        assessment.add(
            "The Service principal %r does not look like an AWS service "
            "principal name. Verify it is spelled correctly - a service "
            "principal that does not exist means nothing can assume the role "
            "through this statement." % ctx.principal.raw
        )
        assessment.confidence = Confidence.LOW

    source_guards = {}
    for key in (
        "aws:SourceAccount",
        "aws:SourceArn",
        "aws:SourceOrgID",
        "aws:SourceOrgPaths",
    ):
        guard = analyze_key(ctx.conditions, key)
        assessment.weak_conditions.extend(guard.weaknesses)
        if guard.guards and not guard.all_values_wildcard:
            source_guards[key] = guard

    own_account = ctx.account_id
    pinned_to_own = False
    pinned_broadly = False
    other_account: Optional[str] = None

    for key, guard in source_guards.items():
        for value in guard.patterns:
            if key.lower() == "aws:sourcearn":
                arn = parse_arn(literal_prefix(value) if has_wildcard(value) else value)
                account = arn.get("account") if arn else None
                if not account or has_wildcard(account) or not ACCOUNT_ID_RE.match(account):
                    pinned_broadly = True
                elif own_account and account == own_account:
                    pinned_to_own = True
                else:
                    other_account = account
            elif key.lower() == "aws:sourceaccount":
                if has_wildcard(value):
                    pinned_broadly = True
                elif own_account and value == own_account:
                    pinned_to_own = True
                elif ACCOUNT_ID_RE.match(value):
                    other_account = value
                else:
                    pinned_broadly = True
            else:
                # Organisation-scoped: bounded, but to many accounts.
                pinned_to_own = pinned_to_own or False

    compute_note = COMPUTE_ATTACHMENT_SERVICES.get(service)

    if source_guards:
        assessment.add(
            "Confused-deputy conditions present: %s."
            % ", ".join(
                "%s=%s" % (key, ", ".join(guard.patterns))
                for key, guard in sorted(source_guards.items())
            )
        )
        if pinned_to_own:
            assessment.grade = ExposureGrade.STRONG
            assessment.who_can_assume = (
                "The %s service, only when acting on behalf of a resource in "
                "this account" % service
            )
            assessment.recommendation = (
                "Confused-deputy protection is in place. If aws:SourceAccount is "
                "used, consider aws:SourceArn as well so the role is tied to the "
                "specific resource rather than the whole account."
            )
        elif other_account:
            assessment.grade = ExposureGrade.MODERATE
            assessment.who_can_assume = (
                "The %s service, when acting on behalf of a resource in account "
                "%s" % (service, other_account)
            )
            assessment.add(
                "The source condition points at account %s, not this account "
                "(%s). That is legitimate for a deliberate cross-account "
                "integration and worth confirming."
                % (other_account, own_account or "<unknown>")
            )
            assessment.recommendation = (
                "Confirm that account %s is meant to drive this role, and pin "
                "aws:SourceArn to the specific resource rather than the account "
                "where possible." % other_account
            )
        elif pinned_broadly:
            assessment.grade = ExposureGrade.WEAK
            assessment.who_can_assume = (
                "The %s service on behalf of a broad set of sources" % service
            )
            assessment.weaken(
                WeakCondition(
                    code="source_condition_too_broad",
                    key=", ".join(sorted(source_guards)),
                    operator=None,
                    detail=(
                        "The source condition's account segment is wildcarded or "
                        "unparsable, so it does not restrict which account's "
                        "resources can drive the service into assuming this role."
                    ),
                )
            )
            assessment.recommendation = (
                "Pin the account segment of aws:SourceArn, or add "
                "aws:SourceAccount with your own account id."
            )
        else:
            assessment.grade = ExposureGrade.MODERATE
            assessment.who_can_assume = (
                "The %s service, bounded to the organisation named in the source "
                "condition" % service
            )
            assessment.recommendation = (
                "Organisation-scoped source conditions are a reasonable "
                "boundary; tighten to aws:SourceAccount or aws:SourceArn if the "
                "integration only ever runs in one account."
            )
    elif compute_note:
        assessment.grade = ExposureGrade.INTERNAL
        assessment.rubric = "aws.service_principal.compute_attachment"
        assessment.who_can_assume = (
            "The %s service, on behalf of whichever workloads in this account "
            "are configured to use this role" % service
        )
        assessment.add(compute_note)
        assessment.add(
            "This is a compute-attachment trust: the statement exists so your "
            "own workload can obtain credentials, not so an outside identity "
            "can. TrustEdge grades it INTERNAL rather than reporting a missing "
            "confused-deputy condition, because the control that matters is who "
            "can pass this role to the service (iam:PassRole) - see the blast "
            "radius of the roles that hold that permission."
        )
        assessment.confidence = Confidence.MEDIUM
        assessment.limitations.append(
            "Scoping for %s lives in service configuration, not IAM, so an "
            "IAM-only export cannot grade it. Reported for inventory." % service
        )
        assessment.recommendation = (
            "Nothing to fix in this trust policy. Audit instead which principals "
            "hold iam:PassRole for this role and %s:* in this account - that is "
            "the real path to these credentials." % service.split(".")[0]
        )
    else:
        assessment.grade = ExposureGrade.MODERATE
        assessment.who_can_assume = (
            "The %s service, with nothing in the trust policy tying the call to "
            "a resource or account you own" % service
        )
        assessment.weaken(
            WeakCondition(
                code="service_principal_no_source_condition",
                key=None,
                operator=None,
                detail=(
                    "No aws:SourceAccount, aws:SourceArn, aws:SourceOrgID or "
                    "aws:SourceOrgPaths condition. AWS recommends these keys "
                    "\"wherever an AWS service principal is granted permission to "
                    "access one of your resources\", because the policy "
                    "authorises the service rather than whoever configured it. "
                    "Whether this specific service populates those keys, and "
                    "whether it can be driven from another account at all, is "
                    "service-specific - check that service's documentation."
                ),
            )
        )
        assessment.add(
            "No source condition restricts on whose behalf %s may assume this "
            "role." % service
        )
        assessment.limitations.append(
            "AWS notes that support for aws:SourceArn / aws:SourceAccount / "
            "aws:SourceOrgID varies by service and that some integrations have "
            "their own confused-deputy protections. TrustEdge therefore reports "
            "the missing condition as a review item and does not claim this "
            "role is reachable from another account."
        )
        assessment.recommendation = (
            "Add a condition tying the call to your own resources, for example "
            "\"StringEquals\": {\"aws:SourceAccount\": \"%s\"} plus an "
            "ArnEquals condition on aws:SourceArn for the specific resource. "
            "Confirm in the %s documentation which keys it populates."
            % (own_account or "<your-account-id>", service)
        )

    if service == "cognito-identity.amazonaws.com" and not ctx.conditions.entries:
        assessment.grade = ExposureGrade.OPEN
        assessment.weaken(
            WeakCondition(
                code="cognito_role_without_condition",
                key="cognito-identity.amazonaws.com:aud",
                operator=None,
                detail=(
                    "AWS requires roles trusting the Amazon Cognito identity-pool "
                    "service principal to contain at least one condition key, and "
                    "warns that a policy trusting Cognito without an aud condition "
                    "\"creates a risk that a user from an unintended identity pool "
                    "can assume the role\"."
                ),
                vacuous=True,
            )
        )
        assessment.who_can_assume = (
            "Users of any Amazon Cognito identity pool, including pools in other "
            "AWS accounts"
        )
        assessment.recommendation = (
            "Add \"StringEquals\": "
            "{\"cognito-identity.amazonaws.com:aud\": \"<your-identity-pool-id>\"}."
        )

    _check_service_actions(ctx, assessment, service)
    return assessment


def _check_service_actions(
    ctx: GradingContext, assessment: ExposureAssessment, service: str
) -> None:
    """Note session-shaping actions granted alongside sts:AssumeRole."""
    lowered = [a.lower() for a in ctx.statement.actions]
    if any(a in ("sts:tagsession", "sts:*", "*") for a in lowered):
        assessment.add(
            "The statement also grants sts:TagSession, which lets the caller "
            "attach session tags. If any policy in this account authorises on "
            "aws:PrincipalTag, those tags become part of the trust decision."
        )
    if any(a in ("sts:setsourceidentity", "sts:*", "*") for a in lowered):
        assessment.add(
            "The statement grants sts:SetSourceIdentity, so the caller supplies "
            "the source identity recorded in CloudTrail for the session."
        )


# --------------------------------------------------------------------------
# External ID assessment
# --------------------------------------------------------------------------


def _assess_external_id(ctx: GradingContext) -> Dict[str, Any]:
    """Judge whether an ``sts:ExternalId`` condition actually raises the bar.

    AWS's requirements, quoted: the value "can be any string", must not be
    "something that can be guessed, like the name or phone number of the third
    party", "should be a random string generated by the third party", and one
    per customer account. It is explicitly **not** a secret.
    """
    guard = analyze_key(ctx.conditions, "sts:ExternalId")
    result: Dict[str, Any] = {
        "present": guard.present,
        "effective": guard.guards and not guard.all_values_wildcard,
        "strong": False,
        "weaknesses": list(guard.weaknesses),
        "notes": [],
        "values": list(guard.patterns),
    }
    if not result["effective"]:
        return result

    account_id = ctx.account_id or ""
    principal_account = ctx.principal.account_id or ""
    vendor = ctx.export.vendor_accounts.get(principal_account)
    role_name = ctx.role.role_name.lower()
    weak_reasons: List[str] = []

    for value in guard.patterns:
        lowered = value.strip().lower()
        if is_pure_wildcard(value):
            weak_reasons.append("the value is a bare wildcard")
            continue
        if has_wildcard(value):
            weak_reasons.append(
                "%r contains a wildcard, so any value matching the pattern is "
                "accepted" % value
            )
            continue
        if lowered in EXTERNAL_ID_DENYLIST:
            weak_reasons.append("%r is a placeholder value" % value)
            continue
        if lowered in (account_id, principal_account):
            weak_reasons.append(
                "%r is an AWS account id, which is not secret and is trivially "
                "guessable" % value
            )
            continue
        if lowered == role_name or (
            len(role_name) >= 4 and (lowered in role_name or role_name in lowered)
        ):
            weak_reasons.append(
                "%r is derived from the role name, which anyone who knows the "
                "role ARN already has" % value
            )
            continue
        if vendor and vendor.vendor and vendor.vendor.lower().replace(" ", "") in lowered.replace(
            " ", ""
        ):
            weak_reasons.append(
                "%r contains the vendor's name, which AWS explicitly warns "
                "against ('do not use something that can be guessed, like the "
                "name ... of the third party')" % value
            )
            continue
        if len(value) < EXTERNAL_ID_MIN_LENGTH:
            weak_reasons.append(
                "%r is only %d characters; a short value can be brute-forced or "
                "guessed" % (value, len(value))
            )
            continue
        if value.isdigit():
            weak_reasons.append(
                "%r is all digits, which suggests a sequential customer number "
                "rather than a random identifier" % value
            )
            continue
        if _character_classes(value) < 2:
            weak_reasons.append(
                "%r uses a single character class, so its entropy is much lower "
                "than its length suggests" % value
            )
            continue

    if weak_reasons:
        for reason in weak_reasons:
            result["weaknesses"].append(
                WeakCondition(
                    code="external_id_weak_value",
                    key="sts:ExternalId",
                    operator=None,
                    detail=(
                        "sts:ExternalId is required but %s. AWS requires the "
                        "external ID to be generated by the third party, unique "
                        "per customer, and not guessable." % reason
                    ),
                )
            )
        result["notes"].append(
            "sts:ExternalId is present but weak: %s." % "; ".join(weak_reasons)
        )
    else:
        result["strong"] = True
        result["notes"].append(
            "sts:ExternalId is required with a value that passes TrustEdge's "
            "guessability checks. TrustEdge cannot verify that the third party "
            "generated it or that it is unique to your tenancy."
        )
    return result


def _character_classes(value: str) -> int:
    classes = 0
    if any(c in string.ascii_lowercase for c in value):
        classes += 1
    if any(c in string.ascii_uppercase for c in value):
        classes += 1
    if any(c in string.digits for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


# --------------------------------------------------------------------------
# Grade arithmetic helpers
# --------------------------------------------------------------------------

_LADDER = [
    ExposureGrade.OPEN,
    ExposureGrade.WEAK,
    ExposureGrade.MODERATE,
    ExposureGrade.STRONG,
]


def _improve(grade: str) -> str:
    """Move one step towards STRONG."""
    if grade not in _LADDER:
        return grade
    index = _LADDER.index(grade)
    return _LADDER[min(index + 1, len(_LADDER) - 1)]


def _strongest(current: str, candidate: str) -> str:
    if current not in _LADDER:
        return candidate
    if candidate not in _LADDER:
        return current
    return _LADDER[max(_LADDER.index(current), _LADDER.index(candidate))]


def _weakest_grade(grades: Sequence[str]) -> str:
    known = [g for g in grades if g in _LADDER]
    if not known:
        return ExposureGrade.NOT_DETERMINED
    return _LADDER[min(_LADDER.index(g) for g in known)]
