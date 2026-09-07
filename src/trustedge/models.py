"""Data model for TrustEdge.

Everything here is a plain dataclass so the analyzer stays dependency-free and
so every finding can be serialised to JSON without a schema library.

Vocabulary used throughout the codebase:

* **Exposure** - how strongly the door (the ``AssumeRolePolicyDocument``) is
  guarded against an identity *outside* the account. Graded, not scored by
  vibes: see :mod:`trustedge.providers`.
* **Blast radius** - what an identity that gets through the door can then do,
  resolved from the role's attached/inline/managed permission policies.
* **Risk** - ``exposure x blast radius``. See :mod:`trustedge.ranking`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Enumerations (plain string constants: they serialise cleanly and compare
# cheaply, and callers can add their own without subclassing an Enum)
# --------------------------------------------------------------------------


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

    @classmethod
    def rank(cls, value: str) -> int:
        """Lower number == more severe. Unknown values sort last."""
        try:
            return cls.ORDER.index(value)
        except ValueError:
            return len(cls.ORDER)

    @classmethod
    def at_least(cls, value: str, threshold: str) -> bool:
        """True when ``value`` is as severe as, or more severe than, ``threshold``."""
        return cls.rank(value) <= cls.rank(threshold)


class ExposureGrade:
    """How weakly the trust statement is guarded against outside identities."""

    #: No meaningful restriction: effectively any identity that can reach the
    #: relevant STS API can pass through.
    OPEN = "OPEN"
    #: A restriction exists but leaves a large, attacker-reachable set.
    WEAK = "WEAK"
    #: Bounded to a real tenant/repo/account but not to a specific workload.
    MODERATE = "MODERATE"
    #: Pinned to a specific external identity with a non-guessable condition.
    STRONG = "STRONG"
    #: The principal is inside this account - not an inbound trust boundary.
    INTERNAL = "INTERNAL"
    #: TrustEdge cannot grade this from a static export (honest non-answer).
    NOT_DETERMINED = "NOT_DETERMINED"
    #: The statement is not an assume-role door at all, so exposure does not
    #: apply. Kept distinct from NOT_DETERMINED, which means "there is a door
    #: and TrustEdge could not grade it".
    NOT_APPLICABLE = "NOT_APPLICABLE"

    #: Multiplicative weights used by the ranking model. Documented in
    #: docs/methodology.md - do not change one without changing the other.
    SCORES = {
        OPEN: 1.00,
        WEAK: 0.75,
        MODERATE: 0.45,
        STRONG: 0.15,
        INTERNAL: 0.05,
        NOT_DETERMINED: 0.40,
        NOT_APPLICABLE: 0.00,
    }

    @classmethod
    def score(cls, grade: str) -> float:
        return cls.SCORES.get(grade, cls.SCORES[cls.NOT_DETERMINED])


class BlastRadiusTier:
    """What the assumed session can do once inside."""

    ADMIN = "ADMIN"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    #: No permission policy document was resolvable from the export.
    UNKNOWN = "UNKNOWN"

    SCORES = {
        ADMIN: 1.00,
        HIGH: 0.75,
        MODERATE: 0.45,
        LOW: 0.15,
        UNKNOWN: 0.40,
    }

    @classmethod
    def score(cls, tier: str) -> float:
        return cls.SCORES.get(tier, cls.SCORES[cls.UNKNOWN])


class PrincipalClass:
    SAME_ACCOUNT = "same_account"
    CROSS_ACCOUNT = "cross_account"
    WILDCARD = "wildcard"
    AWS_SERVICE = "aws_service"
    ROLES_ANYWHERE = "roles_anywhere"
    OIDC = "oidc"
    SAML = "saml"
    CANONICAL_USER = "canonical_user"
    UNKNOWN = "unknown"


class Confidence:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProviderKind:
    """Sub-classification of a federated or service principal."""

    GITHUB_ACTIONS = "github_actions"
    GITLAB = "gitlab"
    TERRAFORM_CLOUD = "terraform_cloud"
    BUILDKITE = "buildkite"
    CIRCLECI = "circleci"
    EKS_IRSA = "eks_irsa"
    EKS_POD_IDENTITY = "eks_pod_identity"
    COGNITO = "cognito"
    GOOGLE = "google"
    #: A shared OIDC issuer that AWS recognises but TrustEdge has no bespoke
    #: rubric for. Graded with the generic shared-issuer rubric.
    SHARED_OIDC = "shared_oidc"
    #: An issuer URL unique to one organisation (e.g. a self-hosted IdP).
    PRIVATE_OIDC = "private_oidc"
    SAML = "saml"
    ROLES_ANYWHERE = "roles_anywhere"
    AWS_SERVICE = "aws_service"
    AWS_ACCOUNT = "aws_account"
    ANY_AWS_PRINCIPAL = "any_aws_principal"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Parse diagnostics
# --------------------------------------------------------------------------


@dataclass
class ParseIssue:
    """A problem found while reading the export.

    TrustEdge never aborts on a single malformed statement: it records an issue
    and keeps analysing everything else. ``level`` is ``error`` when data was
    dropped and ``warning`` when data was kept but is suspect.
    """

    level: str
    code: str
    message: str
    location: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "location": self.location,
        }


# --------------------------------------------------------------------------
# Export objects
# --------------------------------------------------------------------------


@dataclass
class TrustPrincipal:
    """One concrete principal entry inside a trust statement's Principal block."""

    #: The Principal block key it came from: AWS / Service / Federated / CanonicalUser
    block_key: str
    #: The raw value exactly as written in the policy.
    raw: str
    principal_class: str = PrincipalClass.UNKNOWN
    provider_kind: str = ProviderKind.UNKNOWN
    #: Account id when derivable (12-digit string).
    account_id: Optional[str] = None
    #: OIDC issuer host/path, SAML provider name, or service principal name.
    provider_id: Optional[str] = None
    #: Human label, e.g. "GitHub Actions OIDC" or "vendor: Example Corp".
    label: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_key": self.block_key,
            "raw": self.raw,
            "principal_class": self.principal_class,
            "provider_kind": self.provider_kind,
            "account_id": self.account_id,
            "provider_id": self.provider_id,
            "label": self.label,
            "notes": list(self.notes),
        }


@dataclass
class TrustStatement:
    """A single normalised statement from an AssumeRolePolicyDocument."""

    index: int
    effect: str = "Allow"
    sid: Optional[str] = None
    actions: List[str] = field(default_factory=list)
    principals: List[TrustPrincipal] = field(default_factory=list)
    #: Raw Condition block (operator -> key -> value(s)) exactly as written.
    condition: Dict[str, Any] = field(default_factory=dict)
    #: True when the statement used NotPrincipal, which TrustEdge does not grade.
    has_not_principal: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def grants_assume(self) -> bool:
        """True when at least one action in the statement is an STS assume-role call.

        A trust statement that only allows e.g. ``sts:TagSession`` is not a door
        on its own, so it must not be reported as inbound exposure.
        """
        for action in self.actions:
            if is_assume_action(action):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "effect": self.effect,
            "sid": self.sid,
            "actions": list(self.actions),
            "principals": [p.to_dict() for p in self.principals],
            "condition": self.condition,
            "has_not_principal": self.has_not_principal,
        }


ASSUME_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithwebidentity",
    "sts:assumerolewithsaml",
)


def is_assume_action(action: str) -> bool:
    """Whether an Action string can authorise an STS assume-role call.

    Handles the wildcard forms that real policies use (``*``, ``sts:*``,
    ``sts:AssumeRole*``) without pulling in the full glob engine.
    """
    if not isinstance(action, str):
        return False
    a = action.strip().lower()
    if a in ("*", "sts:*"):
        return True
    if a.endswith("*"):
        prefix = a[:-1]
        return any(known.startswith(prefix) for known in ASSUME_ACTIONS)
    return a in ASSUME_ACTIONS


@dataclass
class PolicyRef:
    """A permission policy attached to a role, plus its document if resolvable."""

    name: str
    #: "inline", "attached_managed", or "permissions_boundary"
    source: str
    arn: Optional[str] = None
    document: Optional[Dict[str, Any]] = None
    #: Set when an attached managed policy's document was not present in the export.
    unresolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "arn": self.arn,
            "unresolved": self.unresolved,
        }


@dataclass
class Role:
    role_name: str
    arn: Optional[str] = None
    path: str = "/"
    account_id: Optional[str] = None
    description: Optional[str] = None
    create_date: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    trust_policy_raw: Optional[Any] = None
    trust_statements: List[TrustStatement] = field(default_factory=list)
    policies: List[PolicyRef] = field(default_factory=list)
    permissions_boundary_arn: Optional[str] = None
    #: True when the trust policy was missing or could not be parsed at all.
    trust_policy_unusable: bool = False


@dataclass
class VendorRecord:
    account_id: str
    vendor: str
    notes: str = ""
    #: Whether the operator asserts this vendor requires an external ID.
    requires_external_id: Optional[bool] = None


@dataclass
class OidcProviderRecord:
    arn: Optional[str]
    url: str
    client_id_list: List[str] = field(default_factory=list)
    thumbprint_list: List[str] = field(default_factory=list)


@dataclass
class SamlProviderRecord:
    arn: Optional[str]
    name: str


@dataclass
class IamExport:
    account_id: Optional[str] = None
    generated_at: Optional[str] = None
    source: Optional[str] = None
    roles: List[Role] = field(default_factory=list)
    managed_policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    oidc_providers: List[OidcProviderRecord] = field(default_factory=list)
    saml_providers: List[SamlProviderRecord] = field(default_factory=list)
    vendor_accounts: Dict[str, VendorRecord] = field(default_factory=dict)
    #: Organisation id, if the operator supplied it. Used to decide whether a
    #: cross-account principal is inside the same AWS organisation.
    organization_id: Optional[str] = None
    trusted_account_ids: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Analysis objects
# --------------------------------------------------------------------------


@dataclass
class WeakCondition:
    """A specific, named weakness in the guard on a trust statement."""

    code: str
    key: Optional[str]
    operator: Optional[str]
    detail: str
    #: Whether this weakness on its own makes the guard ineffective.
    vacuous: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "key": self.key,
            "operator": self.operator,
            "detail": self.detail,
            "vacuous": self.vacuous,
        }


@dataclass
class ExposureAssessment:
    """Result of grading one principal's guard on one trust statement."""

    grade: str = ExposureGrade.NOT_DETERMINED
    #: Short sentence answering "who can get in?"
    who_can_assume: str = ""
    #: Ordered, human-readable reasons for the grade.
    reasoning: List[str] = field(default_factory=list)
    weak_conditions: List[WeakCondition] = field(default_factory=list)
    #: Rubric identifier, e.g. "oidc.github_actions" - makes grades auditable.
    rubric: str = ""
    confidence: str = Confidence.MEDIUM
    limitations: List[str] = field(default_factory=list)
    #: Suggested tightened trust policy, when one can be produced safely.
    recommended_policy: Optional[Dict[str, Any]] = None
    #: Prose remediation when an automatic rewrite would be unsafe.
    recommendation: str = ""
    #: Documentation URLs backing the rubric.
    references: List[str] = field(default_factory=list)
    #: Set when the guard is broken in a fail-closed way (misconfiguration, not
    #: exposure) - e.g. StringEquals with a literal ``*``.
    fail_closed_notes: List[str] = field(default_factory=list)

    def add(self, reason: str) -> None:
        if reason not in self.reasoning:
            self.reasoning.append(reason)

    def weaken(self, weakness: WeakCondition) -> None:
        self.weak_conditions.append(weakness)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "score": ExposureGrade.score(self.grade),
            "who_can_assume": self.who_can_assume,
            "reasoning": list(self.reasoning),
            "weak_conditions": [w.to_dict() for w in self.weak_conditions],
            "rubric": self.rubric,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "fail_closed_notes": list(self.fail_closed_notes),
            "references": list(self.references),
        }


@dataclass
class Capability:
    """One security-relevant permission the role holds."""

    #: "admin", "escalation", or "data_plane"
    category: str
    code: str
    detail: str
    #: The policy statement that granted it, for evidence.
    source_policy: str
    action_pattern: str
    resource_patterns: List[str] = field(default_factory=list)
    conditioned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "detail": self.detail,
            "source_policy": self.source_policy,
            "action_pattern": self.action_pattern,
            "resource_patterns": list(self.resource_patterns),
            "conditioned": self.conditioned,
        }


@dataclass
class BlastRadius:
    tier: str = BlastRadiusTier.UNKNOWN
    capabilities: List[Capability] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    #: Names of attached managed policies whose documents were absent.
    unresolved_policies: List[str] = field(default_factory=list)
    #: Number of permission statements actually evaluated.
    statements_evaluated: int = 0
    has_permissions_boundary: bool = False
    #: Deny statements seen. TrustEdge only applies a narrow subset of them.
    deny_statements_seen: int = 0
    limitations: List[str] = field(default_factory=list)

    @property
    def admin_equivalent(self) -> bool:
        return any(c.category == "admin" for c in self.capabilities)

    @property
    def escalation_primitives(self) -> List[Capability]:
        return [c for c in self.capabilities if c.category == "escalation"]

    @property
    def data_plane(self) -> List[Capability]:
        return [c for c in self.capabilities if c.category == "data_plane"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "score": BlastRadiusTier.score(self.tier),
            "admin_equivalent": self.admin_equivalent,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "reasoning": list(self.reasoning),
            "unresolved_policies": list(self.unresolved_policies),
            "statements_evaluated": self.statements_evaluated,
            "deny_statements_seen": self.deny_statements_seen,
            "has_permissions_boundary": self.has_permissions_boundary,
            "limitations": list(self.limitations),
        }


@dataclass
class Finding:
    finding_id: str
    role_name: str
    role_arn: Optional[str]
    statement_index: int
    statement_sid: Optional[str]
    principal: TrustPrincipal
    exposure: ExposureAssessment
    blast_radius: BlastRadius
    severity: str = Severity.INFO
    risk_score: int = 0
    score_explanation: str = ""
    title: str = ""
    #: The exact trust statement, verbatim, so a reviewer can check our work.
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "score_explanation": self.score_explanation,
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "statement_index": self.statement_index,
            "statement_sid": self.statement_sid,
            "principal": self.principal.to_dict(),
            "principal_classification": self.principal.principal_class,
            "provider": self.principal.provider_kind,
            "exposure": self.exposure.to_dict(),
            "blast_radius": self.blast_radius.to_dict(),
            "recommendation": {
                "summary": self.exposure.recommendation,
                "tightened_trust_policy": self.exposure.recommended_policy,
            },
            "evidence": self.evidence,
        }


@dataclass
class RoleSummary:
    role_name: str
    role_arn: Optional[str]
    trust_statement_count: int
    blast_radius_tier: str
    inbound_principal_classes: List[str] = field(default_factory=list)
    highest_severity: str = Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "trust_statement_count": self.trust_statement_count,
            "blast_radius_tier": self.blast_radius_tier,
            "inbound_principal_classes": list(self.inbound_principal_classes),
            "highest_severity": self.highest_severity,
        }


@dataclass
class AnalysisResult:
    account_id: Optional[str]
    tool: str
    tool_version: str
    generated_at: str
    input_path: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    roles_analyzed: int = 0
    trust_statements_analyzed: int = 0
    principals_analyzed: int = 0
    role_summaries: List[RoleSummary] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in Severity.ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def highest_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=Severity.rank)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "trustedge.report/1",
            "tool": self.tool,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "input_path": self.input_path,
            "account_id": self.account_id,
            "summary": {
                "roles_analyzed": self.roles_analyzed,
                "trust_statements_analyzed": self.trust_statements_analyzed,
                "principals_analyzed": self.principals_analyzed,
                "findings_total": len(self.findings),
                "severity_counts": self.severity_counts(),
                "highest_severity": self.highest_severity(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "roles": [r.to_dict() for r in self.role_summaries],
            "input_issues": [i.to_dict() for i in self.issues],
            "limitations": list(self.limitations),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
