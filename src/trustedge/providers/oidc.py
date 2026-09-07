"""OIDC / CI federation rubric.

Key research result that shapes this module: AWS classifies OIDC identity
providers as **private** or **shared**.

    "A private OIDC IdP can be owned and managed by a single organization or
    can be a tenant of a SaaS provider, with its OIDC Issuer URL serving as a
    unique identifier specific to that organization. In contrast, a shared OIDC
    IdP is utilized across multiple organizations, where the OIDC Issuer URL
    might be identical for all organizations using that shared identity
    provider."

For a shared issuer, the issuer URL proves nothing about *who* is on the other
end - every customer of that SaaS mints tokens from the same URL. The tenancy
claim in the token is the only thing separating your CI from a stranger's. So
an unconstrained tenancy claim on a shared issuer is an OPEN door, while the
same omission on a private issuer bounds the caller to that one organisation.

AWS now enforces this at policy-write time via *identity-provider controls*,
but explicitly grandfathers existing policies:

    "Identity-provider controls will not be evaluated by IAM for existing OIDC
    role trust policies."

which is precisely why an offline audit of what is already deployed is worth
running.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .. import references
from ..conditions import analyze_key, pinned_segments
from ..context import GradingContext
from ..models import (
    Confidence,
    ExposureAssessment,
    ExposureGrade,
    ProviderKind,
    WeakCondition,
)
from ..policy import has_wildcard, is_pure_wildcard, literal_prefix, normalize_issuer

# --------------------------------------------------------------------------
# Shared-issuer registry
#
# Source: "Identity-provider controls for shared OIDC providers" (AWS IAM User
# Guide). Each entry records the tenancy claim AWS requires a role trust policy
# to evaluate for that issuer. Keys are normalised issuers (no scheme, no
# trailing slash).
# --------------------------------------------------------------------------

SHARED_OIDC_PROVIDERS: Dict[str, Dict[str, str]] = {
    "cognito-identity.amazonaws.com": {
        "name": "Amazon Cognito identity pools",
        "tenancy_claim": "aud",
    },
    "sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d": {
        "name": "Microsoft Azure Sentinel",
        "tenancy_claim": "sts:RoleSessionName",
    },
    "agent.buildkite.com": {"name": "Buildkite", "tenancy_claim": "sub"},
    "oidc.codefresh.io": {"name": "Codefresh SaaS", "tenancy_claim": "sub"},
    "studio.datachain.ai/api": {"name": "DVC Studio", "tenancy_claim": "sub"},
    "token.actions.githubusercontent.com": {
        "name": "GitHub Actions",
        "tenancy_claim": "sub",
    },
    "oidc-configuration.audit-log.githubusercontent.com": {
        "name": "GitHub audit log streaming",
        "tenancy_claim": "sub",
    },
    "vstoken.actions.githubusercontent.com": {
        "name": "GitHub vstoken",
        "tenancy_claim": "sub",
    },
    "gitlab.com": {"name": "GitLab SaaS", "tenancy_claim": "sub"},
    "api.pulumi.com/oidc": {"name": "Pulumi Cloud", "tenancy_claim": "aud"},
    "sandboxes.cloud": {"name": "sandboxes.cloud", "tenancy_claim": "aud"},
    "scalr.io": {"name": "Scalr", "tenancy_claim": "sub"},
    "tokens.cloud.shisho.dev": {"name": "Shisho Cloud", "tenancy_claim": "sub"},
    "app.terraform.io": {"name": "HCP Terraform", "tenancy_claim": "sub"},
    "proidc.upbound.io": {"name": "Upbound", "tenancy_claim": "sub"},
    "oidc.vercel.com": {"name": "Vercel", "tenancy_claim": "aud"},
    "oidc.op1.openshiftapps.com/2f785sojlpb85i7402pk3qogugim5nfb": {
        "name": "IBM Turbonomic SaaS",
        "tenancy_claim": "sub",
    },
    "oidc.op1.openshiftapps.com/2c51blsaqa9gkjt0o9rt11mle8mmropu": {
        "name": "IBM Turbonomic SaaS",
        "tenancy_claim": "sub",
    },
}

for _turbo_id in (
    "22ejnvnnturfmt6km08idd0nt4hekbn7",
    "23e3sd27sju1hoou6ohfs68vbno607tr",
    "23ne21h005qjl3n33d8dui5dlrmv2tmg",
    "24jrf12m5dj7ljlfb4ta2frhrcoadm26",
):
    SHARED_OIDC_PROVIDERS["rh-oidc.s3.us-east-1.amazonaws.com/%s" % _turbo_id] = {
        "name": "IBM Turbonomic SaaS",
        "tenancy_claim": "sub",
    }

#: Issuers hosted by a shared CI vendor but *not* in AWS's controls table. The
#: URL is still shared across that vendor's customers, so the shared rubric
#: applies. Kept separate so the report can say which list a decision came from.
SHARED_BY_INSPECTION: Dict[str, Dict[str, str]] = {
    "oidc.circleci.com": {"name": "CircleCI", "tenancy_claim": "sub"},
    "accounts.google.com": {"name": "Google", "tenancy_claim": "aud"},
    "www.amazon.com": {"name": "Login with Amazon", "tenancy_claim": "app_id"},
    "graph.facebook.com": {"name": "Facebook", "tenancy_claim": "app_id"},
}

#: An EKS cluster's own OIDC endpoint. Unique per cluster, therefore private.
EKS_ISSUER_RE = re.compile(
    r"^oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[0-9A-Za-z]+$", re.IGNORECASE
)

#: Claims that a compliant OIDC ID token always carries, so an ``IfExists``
#: operator on them is untidy rather than vacuous.
ALWAYS_PRESENT_CLAIMS = ("sub", "aud", "iss", "exp", "iat")

# --------------------------------------------------------------------------
# GitHub Actions claim knowledge
#
# Source: "Available keys for AWS OIDC federation" -> GitHub tab. Only the
# claims in this table are documented by AWS as usable condition keys for the
# GitHub issuer.
# --------------------------------------------------------------------------

GITHUB_DOCUMENTED_CLAIMS = (
    "actor",
    "actor_id",
    "job_workflow_ref",
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "environment",
    "enterprise_id",
    # From the Default tab, which AWS says GitHub uses.
    "aud",
    "sub",
    "amr",
    "email",
    "oaud",
)

#: AWS: "Repository IDs are immutable and don't change even if the repository is
#: renamed"; "Actor IDs are generated by GitHub and are immutable"; "The
#: repository owner ID is a stable, unique identifier that does not change".
GITHUB_IMMUTABLE_CLAIMS = (
    "repository_id",
    "repository_owner_id",
    "actor_id",
    "enterprise_id",
)

#: Claims that identify a tenant by *name*. AWS: "On GitHub, repository,
#: organization, and user names can change. A name that is freed by renaming or
#: deletion can be claimed by a different account."
GITHUB_MUTABLE_NAME_CLAIMS = ("repository", "repository_owner", "actor", "workflow")


def issuer_profile(issuer: str) -> Optional[Dict[str, str]]:
    """Look up a shared-issuer record, or None if the issuer is not known shared."""
    key = normalize_issuer(issuer).lower()
    for table in (SHARED_OIDC_PROVIDERS, SHARED_BY_INSPECTION):
        for candidate, record in table.items():
            if candidate.lower() == key:
                out = dict(record)
                out["source"] = (
                    "aws_identity_provider_controls"
                    if table is SHARED_OIDC_PROVIDERS
                    else "shared_by_inspection"
                )
                return out
    return None


def classify_issuer(issuer: str) -> str:
    """Map an OIDC issuer URL to a :class:`ProviderKind`."""
    normalised = normalize_issuer(issuer)
    lowered = normalised.lower()
    if lowered in ("token.actions.githubusercontent.com", "vstoken.actions.githubusercontent.com"):
        return ProviderKind.GITHUB_ACTIONS
    if lowered == "gitlab.com":
        return ProviderKind.GITLAB
    if lowered == "app.terraform.io":
        return ProviderKind.TERRAFORM_CLOUD
    if lowered == "agent.buildkite.com":
        return ProviderKind.BUILDKITE
    if lowered == "oidc.circleci.com":
        return ProviderKind.CIRCLECI
    if lowered == "cognito-identity.amazonaws.com":
        return ProviderKind.COGNITO
    if lowered == "accounts.google.com":
        return ProviderKind.GOOGLE
    if EKS_ISSUER_RE.match(normalised):
        return ProviderKind.EKS_IRSA
    if issuer_profile(normalised):
        return ProviderKind.SHARED_OIDC
    return ProviderKind.PRIVATE_OIDC


# --------------------------------------------------------------------------
# Scope model
# --------------------------------------------------------------------------


class Scope:
    """Which dimensions of the caller's identity the conditions actually pin.

    ``tenant`` is the outer boundary (a GitHub org, a GitLab group, a Terraform
    organisation, a Kubernetes namespace). ``project`` is the repository or
    equivalent. ``workload`` is the branch, environment, workflow or service
    account. Grading is a pure function of these three plus the issuer type, so
    every grade is reproducible and arguable.
    """

    def __init__(self) -> None:
        self.tenant = False
        self.project = False
        self.workload = False
        #: Claim keys that contributed, for the evidence trail.
        self.sources: List[str] = []
        self.tenant_value: Optional[str] = None
        self.project_value: Optional[str] = None
        self.workload_value: Optional[str] = None

    def merge(self, other: "Scope") -> None:
        # Conditions in a Condition block are AND-ed, so the pinned dimensions
        # accumulate: the allowed caller set is the intersection.
        if other.tenant:
            self.tenant = True
            self.tenant_value = self.tenant_value or other.tenant_value
        if other.project:
            self.project = True
            self.project_value = self.project_value or other.project_value
        if other.workload:
            self.workload = True
            self.workload_value = self.workload_value or other.workload_value
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)

    @property
    def level(self) -> int:
        if self.project and self.workload:
            return 3
        if self.project:
            return 2
        if self.tenant:
            return 1
        return 0

    def describe(self) -> str:
        return "tenant=%s project=%s workload=%s" % (
            self.tenant,
            self.project,
            self.workload,
        )


LEVEL_TO_GRADE_SHARED = {
    0: ExposureGrade.OPEN,
    1: ExposureGrade.WEAK,
    2: ExposureGrade.MODERATE,
    3: ExposureGrade.STRONG,
}

#: For a private issuer only that organisation can mint tokens, so the floor is
#: MODERATE rather than OPEN even with no claim conditions at all.
LEVEL_TO_GRADE_PRIVATE = {
    0: ExposureGrade.MODERATE,
    1: ExposureGrade.MODERATE,
    2: ExposureGrade.MODERATE,
    3: ExposureGrade.STRONG,
}


# --------------------------------------------------------------------------
# GitHub subject parsing
# --------------------------------------------------------------------------


def parse_github_sub(pattern: str) -> Scope:
    """Turn one ``token.actions.githubusercontent.com:sub`` value into a Scope.

    The default GitHub subject format, as shown in AWS's own example, is
    ``repo:<org>/<repo>:ref:refs/heads/<branch>``. GitHub also allows the
    subject template to be customised per repository or organisation, so a
    value that does not start with ``repo:`` is reported as unrecognised rather
    than guessed at.
    """
    scope = Scope()
    if not isinstance(pattern, str) or is_pure_wildcard(pattern):
        return scope

    if not pattern.startswith("repo:"):
        # A customised subject claim template. If it is fully literal it pins
        # *something* exactly; we just cannot name the dimensions.
        if not has_wildcard(pattern):
            scope.tenant = scope.project = scope.workload = True
            scope.sources.append("sub (custom subject template, fully literal)")
        else:
            scope.sources.append("sub (custom subject template, contains wildcard)")
        return scope

    rest = pattern[len("repo:") :]
    if "/" not in rest:
        # e.g. "repo:acme*" - the organisation segment is not even terminated.
        return scope
    org, _, after = rest.partition("/")
    if not org or has_wildcard(org):
        return scope
    scope.tenant = True
    scope.tenant_value = org
    scope.sources.append("sub (organisation segment)")

    if ":" in after:
        repo, _, selector = after.partition(":")
    else:
        repo, selector = after, ""
    if not repo or has_wildcard(repo):
        return scope
    scope.project = True
    scope.project_value = repo
    scope.sources.append("sub (repository segment)")

    if not selector or is_pure_wildcard(selector) or has_wildcard(selector):
        return scope

    if selector == "pull_request":
        # Pinned to the pull_request context, which every pull request in the
        # repository satisfies - the repository is the real boundary.
        scope.sources.append("sub (pull_request context, not a specific workload)")
        return scope

    scope.workload = True
    scope.workload_value = selector
    scope.sources.append("sub (workload segment)")
    return scope


def _weakest(scopes: List[Scope]) -> Scope:
    """Combine alternative values for one claim by taking the weakest.

    Multiple values under one condition operator are OR-ed, so the caller set is
    the union: exposure is driven by the least restrictive value. Getting this
    backwards would let ``["repo:acme/app:ref:refs/heads/main", "repo:acme/*"]``
    grade as STRONG.
    """
    if not scopes:
        return Scope()
    out = Scope()
    out.tenant = all(s.tenant for s in scopes)
    out.project = all(s.project for s in scopes)
    out.workload = all(s.workload for s in scopes)
    for scope in scopes:
        for source in scope.sources:
            if source not in out.sources:
                out.sources.append(source)
    for scope in scopes:
        out.tenant_value = out.tenant_value or scope.tenant_value
        out.project_value = out.project_value or scope.project_value
        out.workload_value = out.workload_value or scope.workload_value
    if not out.tenant:
        out.tenant_value = None
    if not out.project:
        out.project_value = None
    if not out.workload:
        out.workload_value = None
    return out


def _scope_from_generic_sub(pattern: str) -> Scope:
    """Structural fallback: count fully pinned ``:``/``/``-delimited segments.

    Used for shared issuers TrustEdge has no bespoke subject grammar for. It is
    a heuristic and the finding says so.
    """
    scope = Scope()
    if not isinstance(pattern, str) or is_pure_wildcard(pattern):
        return scope
    segments = _pinned_segments_multi(pattern)
    scope.sources.append("sub (%d fully pinned segment(s))" % segments)
    if segments >= 1:
        scope.tenant = True
    if segments >= 3:
        scope.project = True
    if segments >= 5:
        scope.workload = True
    return scope


def _pinned_segments_multi(pattern: str) -> int:
    """Count complete ``:``- or ``/``-delimited segments before the first wildcard."""
    if not isinstance(pattern, str) or not pattern:
        return 0
    prefix = literal_prefix(pattern)
    if prefix == pattern:
        return len([s for s in re.split(r"[:/]", pattern) if s])
    parts = re.split(r"[:/]", prefix)
    return len([s for s in parts[:-1] if s])


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def grade(ctx: GradingContext) -> ExposureAssessment:
    kind = ctx.principal.provider_kind
    if kind == ProviderKind.GITHUB_ACTIONS:
        return _grade_github(ctx)
    if kind == ProviderKind.EKS_IRSA:
        return _grade_irsa(ctx)
    if kind == ProviderKind.COGNITO:
        return _grade_claim_registry(ctx, forced_claim="aud")
    return _grade_generic(ctx)


# --------------------------------------------------------------------------
# GitHub Actions
# --------------------------------------------------------------------------


def _grade_github(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="oidc.github_actions",
        confidence=Confidence.HIGH,
        references=[
            references.OIDC_ROLE_SETUP,
            references.IAM_STS_CONDITION_KEYS,
            references.OIDC_IDP_CONTROLS,
            references.CONDITION_OPERATORS,
        ],
    )
    conditions = ctx.conditions
    scope = Scope()

    # -- sub ---------------------------------------------------------------
    sub_key = ctx.condition_key("sub")
    sub_guard = analyze_key(conditions, sub_key, claim_always_present=True)
    assessment.weak_conditions.extend(sub_guard.weaknesses)

    if sub_guard.guards:
        sub_scope = _weakest([parse_github_sub(v) for v in sub_guard.patterns])
        scope.merge(sub_scope)
        if sub_scope.level == 0:
            assessment.add(
                "The %s condition does not pin a GitHub organisation: %s."
                % (sub_key, ", ".join(repr(v) for v in sub_guard.patterns))
            )
            assessment.weaken(
                WeakCondition(
                    code="github_sub_org_not_pinned",
                    key=sub_key,
                    operator=sub_guard.effective[0].raw_operator,
                    detail=(
                        "A wildcard appears at or before the organisation "
                        "segment, so workflows in organisations you do not "
                        "control match this subject pattern. GitHub "
                        "organisation names can also be re-registered after a "
                        "rename or deletion."
                    ),
                    vacuous=True,
                )
            )
        elif not sub_scope.project:
            assessment.add(
                "The %s condition pins organisation %r but leaves the "
                "repository wildcarded, so any repository in the organisation "
                "can assume this role."
                % (sub_key, sub_scope.tenant_value)
            )
        elif not sub_scope.workload:
            assessment.add(
                "The %s condition pins repository %s/%s but not a branch, tag "
                "or environment, so any ref in that repository - including a "
                "branch an attacker with write access can create - can assume "
                "this role."
                % (sub_key, sub_scope.tenant_value, sub_scope.project_value)
            )
        else:
            assessment.add(
                "The %s condition pins %s/%s and the workload segment %r."
                % (
                    sub_key,
                    sub_scope.tenant_value,
                    sub_scope.project_value,
                    sub_scope.workload_value,
                )
            )
    elif sub_guard.present:
        assessment.add(
            "A %s condition is present but does not restrict anything (see the "
            "weak conditions below)." % sub_key
        )
    else:
        assessment.add("There is no %s condition on this statement." % sub_key)

    # -- the other documented GitHub claims --------------------------------
    claim_scope, claim_notes, claim_weaknesses = _github_claim_scopes(ctx)
    scope.merge(claim_scope)
    for note in claim_notes:
        assessment.add(note)
    assessment.weak_conditions.extend(claim_weaknesses)

    # -- audience ----------------------------------------------------------
    aud_key = ctx.condition_key("aud")
    aud_guard = analyze_key(conditions, aud_key, claim_always_present=True)
    assessment.weak_conditions.extend(aud_guard.weaknesses)
    if not aud_guard.guards:
        assessment.weaken(
            WeakCondition(
                code="oidc_aud_not_pinned",
                key=aud_key,
                operator=None,
                detail=(
                    "No audience condition. AWS's documented GitHub trust policy "
                    "pins %s to 'sts.amazonaws.com'. This is hygiene rather than a "
                    "hole - STS also checks the audience against the IAM OIDC "
                    "provider's client ID list - but it should be present."
                    % aud_key
                ),
            )
        )

    # -- mutability --------------------------------------------------------
    _flag_mutable_identifiers(ctx, assessment)
    _flag_undocumented_claims(ctx, assessment, GITHUB_DOCUMENTED_CLAIMS)

    # -- grade -------------------------------------------------------------
    assessment.grade = LEVEL_TO_GRADE_SHARED[scope.level]
    assessment.who_can_assume = _github_who(scope)

    if scope.level == 0:
        if not sub_guard.guards:
            # The reasoning explains this, but a machine-readable weakness has
            # to name it too, or a consumer filtering on weak_conditions sees
            # an OPEN finding with nothing attached.
            assessment.weaken(
                WeakCondition(
                    code="github_tenancy_not_pinned",
                    key=sub_key,
                    operator=None,
                    detail=(
                        "No effective condition pins the GitHub organisation, "
                        "repository or workflow. AWS warns that without a %s "
                        "condition limited to a specific organisation or "
                        "repository, \"GitHub Actions from organizations or "
                        "repositories outside of your control are able to assume "
                        "roles associated with the GitHub IAM IdP in your AWS "
                        "account\"." % sub_key
                    ),
                    vacuous=True,
                )
            )
        assessment.add(
            "token.actions.githubusercontent.com is a shared issuer: every "
            "GitHub customer mints tokens signed by it, so without a tenancy "
            "condition the guard is the issuer's signature alone."
        )
        assessment.add(
            "AWS now refuses to create or update a GitHub OIDC role trust "
            "policy whose sub condition is missing or a bare wildcard, but "
            "identity-provider controls are not applied to trust policies that "
            "already exist - so a policy in this state can still be live."
        )

    if sub_guard.literal_wildcards:
        assessment.fail_closed_notes.append(
            "One or more %s values contain '*' under an exact-match operator, "
            "so they are compared literally and cannot match a real token. This "
            "statement is broken rather than permissive - but it also means the "
            "intended restriction is not in force anywhere." % sub_key
        )

    _add_recommendation_github(ctx, assessment, scope)
    return assessment


def _github_who(scope: Scope) -> str:
    if scope.level == 0:
        return (
            "Any GitHub Actions workflow, in any GitHub organisation, that can "
            "request an OIDC token for this AWS account"
        )
    if scope.level == 1:
        return (
            "Any workflow in any repository of GitHub organisation %s"
            % (scope.tenant_value or "<pinned by an id claim>")
        )
    if scope.level == 2:
        return (
            "Any workflow, on any branch or tag, in repository %s/%s"
            % (
                scope.tenant_value or "<org>",
                scope.project_value or "<repo>",
            )
        )
    return "Workflows in %s/%s matching %s" % (
        scope.tenant_value or "<org>",
        scope.project_value or "<repo>",
        scope.workload_value or "the pinned workload conditions",
    )


def _github_claim_scopes(
    ctx: GradingContext,
) -> Tuple[Scope, List[str], List[WeakCondition]]:
    """Read tenancy/project/workload pinning from GitHub's non-sub claims.

    AWS's own recommended "use immutable identifiers" example pins
    ``repository_owner_id``, ``repository_id``, ``actor_id``, ``ref`` and
    ``enterprise_id`` and has no ``sub`` condition at all. A rubric that looked
    only at ``sub`` would grade AWS's own guidance as an open door.

    Returns the combined scope, human notes, and any weaknesses found on these
    claims - the last of these matters because an ``IfExists`` operator on
    ``environment`` (a claim GitHub only issues when the job declares an
    environment) is the single most common way a CI trust policy looks
    restrictive while enforcing nothing.
    """
    combined = Scope()
    notes: List[str] = []
    weaknesses: List[WeakCondition] = []
    conditions = ctx.conditions
    inspected: List[str] = []

    def pinned_values(claim: str) -> Optional[List[str]]:
        key = ctx.condition_key(claim)
        guard = analyze_key(conditions, key, claim_always_present=False)
        if key not in inspected:
            inspected.append(key)
            weaknesses.extend(guard.weaknesses)
        if not guard.guards or guard.all_values_wildcard:
            return None
        return guard.patterns

    # tenant-level claims
    for claim in ("repository_owner_id", "enterprise_id", "repository_owner"):
        values = pinned_values(claim)
        if values and all(not has_wildcard(v) for v in values):
            combined.tenant = True
            combined.tenant_value = combined.tenant_value or values[0]
            combined.sources.append(claim)
            notes.append(
                "Organisation is pinned by the %s condition (%s)."
                % (claim, ", ".join(values))
            )

    # project-level claims
    for claim in ("repository", "repository_id"):
        values = pinned_values(claim)
        if not values:
            continue
        if all(not has_wildcard(v) for v in values):
            combined.tenant = True
            combined.project = True
            combined.sources.append(claim)
            if claim == "repository":
                first = values[0]
                if "/" in first:
                    combined.tenant_value = combined.tenant_value or first.split("/")[0]
                    combined.project_value = (
                        combined.project_value or first.split("/", 1)[1]
                    )
            notes.append(
                "Repository is pinned by the %s condition (%s)."
                % (claim, ", ".join(values))
            )
        else:
            # e.g. repository = "acme/*"
            prefixes = [literal_prefix(v) for v in values]
            if all("/" in p and p.split("/")[0] for p in prefixes):
                combined.tenant = True
                combined.tenant_value = combined.tenant_value or prefixes[0].split("/")[0]
                combined.sources.append(claim)
                notes.append(
                    "The %s condition pins the organisation but wildcards the "
                    "repository (%s)." % (claim, ", ".join(values))
                )

    # workload-level claims
    for claim in ("ref", "environment", "workflow", "actor_id", "actor"):
        values = pinned_values(claim)
        if values and all(not has_wildcard(v) for v in values):
            combined.workload = True
            combined.workload_value = combined.workload_value or values[0]
            combined.sources.append(claim)
            notes.append(
                "Workload is narrowed by the %s condition (%s)."
                % (claim, ", ".join(values))
            )

    values = pinned_values("job_workflow_ref")
    if values:
        prefixes = [literal_prefix(v) for v in values]
        if all(p.count("/") >= 2 for p in prefixes):
            combined.tenant = True
            combined.project = True
            combined.sources.append("job_workflow_ref")
            first = prefixes[0].split("/")
            combined.tenant_value = combined.tenant_value or first[0]
            combined.project_value = combined.project_value or first[1]
            notes.append(
                "job_workflow_ref pins the reusable workflow's owning "
                "repository (%s)." % ", ".join(values)
            )
        if all(not has_wildcard(v) for v in values):
            combined.workload = True
            combined.workload_value = combined.workload_value or values[0]

    return combined, notes, weaknesses


def _flag_mutable_identifiers(
    ctx: GradingContext, assessment: ExposureAssessment
) -> None:
    """Warn when the only pinning is by a renameable GitHub name."""
    conditions = ctx.conditions
    used_immutable = any(
        analyze_key(conditions, ctx.condition_key(claim)).guards
        for claim in GITHUB_IMMUTABLE_CLAIMS
    )
    if used_immutable:
        return

    name_based: List[str] = []
    for claim in GITHUB_MUTABLE_NAME_CLAIMS + ("sub",):
        if analyze_key(conditions, ctx.condition_key(claim)).guards:
            name_based.append(claim)
    if not name_based:
        return

    assessment.weaken(
        WeakCondition(
            code="github_mutable_identifiers_only",
            key=", ".join(ctx.condition_key(c) for c in name_based),
            operator=None,
            detail=(
                "Access is pinned only by name-based claims (%s). AWS documents "
                "that GitHub repository, organisation and user names can change, "
                "and \"a name that is freed by renaming or deletion can be "
                "claimed by a different account\". Add an immutable identifier "
                "such as repository_owner_id, repository_id or actor_id so a "
                "renamed or deleted org cannot be impersonated."
                % ", ".join(name_based)
            ),
        )
    )
    assessment.add(
        "Hardening gap: no immutable GitHub identifier (repository_id, "
        "repository_owner_id, actor_id, enterprise_id) is evaluated."
    )


def _flag_undocumented_claims(
    ctx: GradingContext,
    assessment: ExposureAssessment,
    documented: Tuple[str, ...],
) -> None:
    """Report condition keys on this issuer that AWS does not document.

    A condition on a context key AWS never populates fails *closed* under a
    normal operator, which is safe but means the author's intent is not being
    enforced. Under an ``IfExists`` operator the same condition is simply
    ignored, which is not safe. Both are worth saying out loud; neither is
    asserted as a definite bug, because AWS's mapping tables do change.
    """
    prefix = (ctx.issuer + ":").lower()
    documented_lower = {claim.lower() for claim in documented}
    for entry in ctx.conditions.entries:
        key_lower = entry.key_lower
        if not key_lower.startswith(prefix):
            continue
        claim = entry.key[len(ctx.issuer) + 1 :]
        if claim.lower() in documented_lower:
            continue
        vacuous = entry.if_exists or entry.set_operator == "ForAllValues"
        assessment.weaken(
            WeakCondition(
                code="undocumented_condition_key",
                key=entry.key,
                operator=entry.raw_operator,
                detail=(
                    "%r is not in AWS's documented claim-to-condition-key "
                    "mapping for this issuer. If AWS does not populate the key, "
                    "%s"
                    % (
                        entry.key,
                        (
                            "an IfExists/ForAllValues operator makes the "
                            "condition evaluate to true and enforce nothing."
                            if vacuous
                            else "the condition evaluates to false and the "
                            "statement can never match, so the intended "
                            "restriction is not what is enforced."
                        ),
                    )
                ),
                vacuous=vacuous,
            )
        )
        assessment.confidence = Confidence.MEDIUM
        assessment.limitations.append(
            "TrustEdge cannot confirm from a static export whether AWS "
            "populates the condition key %r; the documented mapping is used as "
            "the reference." % entry.key
        )


def _add_recommendation_github(
    ctx: GradingContext, assessment: ExposureAssessment, scope: Scope
) -> None:
    if scope.level >= 3:
        assessment.recommendation = (
            "Trust boundary looks appropriately narrow. Consider adding an "
            "immutable identifier (repository_id / repository_owner_id) "
            "alongside the name-based subject so a rename cannot be abused, and "
            "if a GitHub environment is used, attach deployment protection "
            "rules to it."
        )
        return

    org = scope.tenant_value
    repo = scope.project_value
    if org and repo:
        assessment.recommended_policy = _github_policy(
            ctx, "repo:%s/%s:ref:refs/heads/<branch>" % (org, repo)
        )
        assessment.recommendation = (
            "Pin the workload as well as the repository. Replace <branch> with "
            "the branch that is actually allowed to deploy, or use "
            "'repo:%s/%s:environment:<environment>' and attach deployment "
            "protection rules to that environment." % (org, repo)
        )
        return

    if org:
        assessment.recommendation = (
            "Organisation %s is pinned but the repository is not. Replace the "
            "wildcard with the specific repository, and then the specific branch "
            "or environment: "
            "\"token.actions.githubusercontent.com:sub\": "
            "\"repo:%s/<repo>:ref:refs/heads/<branch>\". TrustEdge does not "
            "generate the tightened policy here because it cannot know which "
            "repositories are meant to be trusted." % (org, org)
        )
        return

    assessment.recommendation = (
        "Add a tenancy condition before anything else. At minimum: "
        "\"StringEquals\": {\"%s\": \"sts.amazonaws.com\"} and "
        "\"StringLike\": {\"%s\": \"repo:<your-org>/<repo>:*\"}, then tighten "
        "the trailing segment to a specific branch or environment. TrustEdge "
        "does not emit a ready-made policy because the export contains no "
        "evidence of which organisation should be trusted."
        % (ctx.condition_key("aud"), ctx.condition_key("sub"))
    )


def _github_policy(ctx: GradingContext, sub_value: str) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GitHubActionsOIDC",
                "Effect": "Allow",
                "Principal": {"Federated": ctx.principal.raw},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        ctx.condition_key("aud"): "sts.amazonaws.com",
                        ctx.condition_key("sub"): sub_value,
                    }
                },
            }
        ],
    }


# --------------------------------------------------------------------------
# EKS IRSA
# --------------------------------------------------------------------------


def _grade_irsa(ctx: GradingContext) -> ExposureAssessment:
    assessment = ExposureAssessment(
        rubric="oidc.eks_irsa",
        confidence=Confidence.MEDIUM,
        references=[references.IRSA, references.IAM_STS_CONDITION_KEYS],
    )
    sub_key = ctx.condition_key("sub")
    aud_key = ctx.condition_key("aud")
    sub_guard = analyze_key(ctx.conditions, sub_key, claim_always_present=True)
    aud_guard = analyze_key(ctx.conditions, aud_key, claim_always_present=True)
    assessment.weak_conditions.extend(sub_guard.weaknesses)
    assessment.weak_conditions.extend(aud_guard.weaknesses)

    assessment.add(
        "The issuer %s belongs to one EKS cluster, so only workloads that can "
        "project a service-account token from that cluster reach this door. "
        "That is a private issuer in AWS's terms, which is why a missing "
        "subject condition here is graded lower than the same omission on a "
        "shared CI issuer." % ctx.issuer
    )

    scope = Scope()
    if sub_guard.guards:
        pinned = min(pinned_segments(v, ":") for v in sub_guard.patterns)
        namespaces = [v for v in sub_guard.patterns]
        if pinned >= 4:
            scope.tenant = scope.project = scope.workload = True
            assessment.add(
                "The subject condition pins a specific namespace and service "
                "account (%s)." % ", ".join(namespaces)
            )
        elif pinned == 3:
            scope.tenant = scope.project = True
            assessment.add(
                "The subject condition pins the namespace but wildcards the "
                "service account (%s): any service account in that namespace "
                "can assume the role." % ", ".join(namespaces)
            )
        else:
            scope.tenant = True
            assessment.add(
                "The subject condition does not pin a namespace (%s): any pod "
                "in the cluster that can project a token for this audience can "
                "assume the role." % ", ".join(namespaces)
            )
            assessment.weaken(
                WeakCondition(
                    code="irsa_subject_not_pinned",
                    key=sub_key,
                    operator=sub_guard.effective[0].raw_operator,
                    detail=(
                        "Expected a subject of the form "
                        "system:serviceaccount:<namespace>:<serviceaccount>. "
                        "Without both segments the role is reachable from any "
                        "namespace in the cluster."
                    ),
                )
            )
    else:
        assessment.weaken(
            WeakCondition(
                code="irsa_subject_missing",
                key=sub_key,
                operator=None,
                detail=(
                    "No subject condition, so every workload in the cluster that "
                    "can project a service-account token with this audience can "
                    "assume the role. IRSA's whole point is per-service-account "
                    "scoping."
                ),
                vacuous=True,
            )
        )
        assessment.add("There is no %s condition on this statement." % sub_key)

    if not aud_guard.guards:
        assessment.weaken(
            WeakCondition(
                code="irsa_audience_missing",
                key=aud_key,
                operator=None,
                detail=(
                    "No audience condition. IRSA tokens are projected with the "
                    "audience 'sts.amazonaws.com'; pinning it stops a token "
                    "minted for a different audience from being replayed here."
                ),
            )
        )

    assessment.grade = LEVEL_TO_GRADE_PRIVATE[scope.level]
    if scope.level >= 3:
        assessment.who_can_assume = (
            "The Kubernetes service account %s in this EKS cluster"
            % (scope.workload_value or "pinned by the subject condition")
        )
    elif scope.level == 2:
        assessment.who_can_assume = (
            "Any service account in the pinned namespace of this EKS cluster"
        )
    else:
        assessment.who_can_assume = (
            "Any pod in this EKS cluster that can project a service-account token"
        )

    assessment.limitations.append(
        "TrustEdge cannot see cluster RBAC, namespace membership or which "
        "workloads actually use the service account, so it cannot say whether a "
        "namespace boundary is enforced in practice."
    )
    if scope.level < 3:
        assessment.recommended_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EksIrsa",
                    "Effect": "Allow",
                    "Principal": {"Federated": ctx.principal.raw},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            aud_key: "sts.amazonaws.com",
                            sub_key: "system:serviceaccount:<namespace>:<serviceaccount>",
                        }
                    },
                }
            ],
        }
        assessment.recommendation = (
            "Pin both the namespace and the service account with StringEquals. "
            "Placeholders are left in the suggested policy because the export "
            "does not say which workload should hold this role."
        )
    else:
        assessment.recommendation = (
            "Scoping looks correct for IRSA. Confirm the namespace is not one "
            "where untrusted workloads can create pods."
        )
    return assessment


# --------------------------------------------------------------------------
# Registry-driven and generic issuers
# --------------------------------------------------------------------------


def _grade_claim_registry(
    ctx: GradingContext, forced_claim: Optional[str] = None
) -> ExposureAssessment:
    """Grade a shared issuer by whether its documented tenancy claim is pinned."""
    profile = issuer_profile(ctx.issuer) or {}
    claim = forced_claim or profile.get("tenancy_claim", "sub")
    name = profile.get("name", ctx.issuer)

    assessment = ExposureAssessment(
        rubric="oidc.shared_issuer",
        confidence=Confidence.MEDIUM,
        references=[references.OIDC_IDP_CONTROLS, references.IAM_STS_CONDITION_KEYS],
    )
    key = claim if ":" in claim else ctx.condition_key(claim)
    guard = analyze_key(ctx.conditions, key, claim_always_present=claim in ALWAYS_PRESENT_CLAIMS)
    assessment.weak_conditions.extend(guard.weaknesses)

    assessment.add(
        "%s is a shared OIDC issuer: AWS requires role trust policies for it to "
        "evaluate %s, because the issuer URL is identical for every customer of "
        "that provider." % (name, key)
    )

    if not guard.guards:
        assessment.grade = ExposureGrade.OPEN
        assessment.who_can_assume = (
            "Any tenant of %s that can obtain a token for this AWS account" % name
        )
        assessment.weaken(
            WeakCondition(
                code="shared_issuer_tenancy_claim_missing",
                key=key,
                operator=None,
                detail=(
                    "The tenancy claim AWS documents for this shared issuer is "
                    "not effectively evaluated, so another customer of %s can "
                    "assume this role." % name
                ),
                vacuous=True,
            )
        )
        assessment.recommendation = (
            "Add a StringEquals condition on %s that pins your own tenant "
            "identifier. TrustEdge cannot fill in the value because the export "
            "contains no record of which tenant should be trusted." % key
        )
        return assessment

    scope = _weakest([_scope_from_generic_sub(v) for v in guard.patterns])
    assessment.grade = LEVEL_TO_GRADE_SHARED[scope.level]
    assessment.add(
        "Structural grading of %s: %s (%s)."
        % (key, scope.describe(), ", ".join(repr(v) for v in guard.patterns))
    )
    assessment.who_can_assume = "Identities from %s matching %s" % (
        name,
        ", ".join(repr(v) for v in guard.patterns),
    )
    assessment.limitations.append(
        "TrustEdge has no bespoke grammar for this provider's %s claim, so the "
        "grade comes from counting fully pinned segments rather than from "
        "understanding the claim's meaning. Verify against the provider's own "
        "documentation." % claim
    )
    if scope.level < 3:
        assessment.recommendation = (
            "Tighten %s so it pins the specific project and workload, not just "
            "the tenant. Consult %s's OIDC documentation for the exact subject "
            "format." % (key, name)
        )
    else:
        assessment.recommendation = (
            "The tenancy claim is pinned to a fully literal value; no change "
            "required from an exposure standpoint."
        )
    return assessment


def _grade_generic(ctx: GradingContext) -> ExposureAssessment:
    """Shared-issuer registry hit, or a private/unknown issuer."""
    if issuer_profile(ctx.issuer):
        return _grade_claim_registry(ctx)

    assessment = ExposureAssessment(
        rubric="oidc.private_issuer",
        confidence=Confidence.LOW,
        references=[references.OIDC_IDP_CONTROLS, references.OIDC_ROLE_SETUP],
    )
    sub_key = ctx.condition_key("sub")
    aud_key = ctx.condition_key("aud")
    sub_guard = analyze_key(ctx.conditions, sub_key, claim_always_present=True)
    aud_guard = analyze_key(ctx.conditions, aud_key, claim_always_present=True)
    assessment.weak_conditions.extend(sub_guard.weaknesses)
    assessment.weak_conditions.extend(aud_guard.weaknesses)

    registered = any(
        normalize_issuer(p.url).lower() == normalize_issuer(ctx.issuer).lower()
        for p in ctx.export.oidc_providers
    )
    if ctx.export.oidc_providers and not registered:
        assessment.add(
            "The issuer %s is referenced by this trust policy but is not in the "
            "export's oidc_providers list. Either the export is incomplete or "
            "the IAM OIDC provider has been deleted, in which case no one can "
            "assume the role through it." % ctx.issuer
        )
        assessment.limitations.append(
            "Whether the IAM OIDC provider exists could not be confirmed from "
            "this export."
        )

    scope = Scope()
    if sub_guard.guards:
        scope = _weakest([_scope_from_generic_sub(v) for v in sub_guard.patterns])
        assessment.add(
            "Subject condition on %s: %s (%s)."
            % (sub_key, scope.describe(), ", ".join(repr(v) for v in sub_guard.patterns))
        )
    else:
        assessment.add(
            "No effective subject condition on %s. Every identity the issuer "
            "authenticates can assume this role." % sub_key
        )
        assessment.weaken(
            WeakCondition(
                code="private_issuer_subject_missing",
                key=sub_key,
                operator=None,
                detail=(
                    "No subject condition. Exposure is bounded only by who the "
                    "identity provider will issue a token to, which TrustEdge "
                    "cannot see."
                ),
            )
        )

    if not aud_guard.guards:
        assessment.weaken(
            WeakCondition(
                code="oidc_aud_not_pinned",
                key=aud_key,
                operator=None,
                detail=(
                    "No audience condition, so a token minted for a different "
                    "relying party could be replayed against this role if the "
                    "IAM OIDC provider registers more than one client ID."
                ),
            )
        )

    assessment.grade = LEVEL_TO_GRADE_PRIVATE[scope.level]
    assessment.who_can_assume = (
        "Identities authenticated by %s%s"
        % (
            ctx.issuer,
            ""
            if not sub_guard.guards
            else " whose subject matches %s"
            % ", ".join(repr(v) for v in sub_guard.patterns),
        )
    )
    assessment.limitations.append(
        "TrustEdge treats %s as a private issuer because it is not in AWS's "
        "shared-provider list. If it is in fact a multi-tenant SaaS issuer that "
        "AWS has not yet catalogued, the real exposure is higher than graded "
        "here - confirm who controls the issuer." % ctx.issuer
    )
    assessment.recommendation = (
        "Confirm who operates this issuer and whether its URL is unique to your "
        "organisation. Then pin the subject claim to the specific workload with "
        "StringEquals, and pin the audience."
    )
    return assessment
