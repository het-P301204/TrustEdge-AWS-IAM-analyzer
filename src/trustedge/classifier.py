"""Principal classification.

The distinction this module exists to protect is the one the whole project
rests on: **a role's trusted principal is not the same thing as the permissions
the role holds.** ``Principal`` says who may become this identity;
``Action``/``Resource`` in the attached policies say what that identity can
then do. Conflating them is how "IAM scanners" end up reporting a read-only
role trusted by the whole internet as low risk and a locked-down admin role as
critical.

Everything here is derived from the ``Principal`` element alone.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    IamExport,
    ParseIssue,
    PrincipalClass,
    ProviderKind,
    Role,
    TrustPrincipal,
    TrustStatement,
)
from .policy import (
    ACCOUNT_ID_RE,
    account_id_from_principal,
    as_list,
    has_wildcard,
    is_pure_wildcard,
    normalize_issuer,
    oidc_provider_url_from_arn,
    parse_arn,
    principal_is_account_root,
    saml_provider_name_from_arn,
)
from .providers.oidc import classify_issuer, issuer_profile

#: The four principal block keys IAM defines.
PRINCIPAL_KEYS = ("AWS", "Service", "Federated", "CanonicalUser")

#: OIDC providers AWS builds in, so no IAM OIDC provider ARN is used.
BUILTIN_FEDERATED_ISSUERS = {
    "cognito-identity.amazonaws.com": ProviderKind.COGNITO,
    "accounts.google.com": ProviderKind.GOOGLE,
    "graph.facebook.com": ProviderKind.SHARED_OIDC,
    "www.amazon.com": ProviderKind.SHARED_OIDC,
}

ROLES_ANYWHERE_SERVICE = "rolesanywhere.amazonaws.com"


def classify_statement_principals(
    statement: TrustStatement,
    export: IamExport,
    role: Role,
    issues: Optional[List[ParseIssue]] = None,
) -> List[TrustPrincipal]:
    """Read and classify every principal in a trust statement's Principal block."""
    issues = issues if issues is not None else []
    raw_block = statement.raw.get("Principal")
    location = "role %s statement %d" % (role.role_name, statement.index)

    if raw_block is None:
        if not statement.has_not_principal:
            issues.append(
                ParseIssue(
                    "warning",
                    "principal_missing",
                    "%s has no Principal element. A role trust policy statement "
                    "without a Principal cannot authorise an assume-role call."
                    % location,
                    location,
                )
            )
        return []

    if isinstance(raw_block, str):
        if is_pure_wildcard(raw_block):
            return [_wildcard_principal("Principal", raw_block)]
        issues.append(
            ParseIssue(
                "warning",
                "principal_string_not_wildcard",
                "%s has a string Principal %r. IAM only accepts the bare string "
                'form "*"; anything else must use a {\"AWS\": ...} object.'
                % (location, raw_block),
                location,
            )
        )
        return [_unknown_principal("Principal", raw_block, "non-wildcard string form")]

    if not isinstance(raw_block, dict):
        issues.append(
            ParseIssue(
                "warning",
                "principal_malformed",
                "%s has a Principal that is a %s; expected an object or the "
                'string "*".' % (location, type(raw_block).__name__),
                location,
            )
        )
        return []

    out: List[TrustPrincipal] = []
    for raw_key, raw_value in raw_block.items():
        key = _canonical_principal_key(raw_key)
        if key is None:
            issues.append(
                ParseIssue(
                    "warning",
                    "principal_key_unknown",
                    "%s has an unrecognised Principal key %r. IAM defines AWS, "
                    "Service, Federated and CanonicalUser." % (location, raw_key),
                    location,
                )
            )
            continue
        if key != raw_key:
            issues.append(
                ParseIssue(
                    "warning",
                    "principal_key_case",
                    "%s spells the Principal key %r; IAM expects %r."
                    % (location, raw_key, key),
                    location,
                )
            )

        values = as_list(raw_value)
        if not values:
            issues.append(
                ParseIssue(
                    "warning",
                    "principal_value_empty",
                    "%s has an empty %s principal list." % (location, key),
                    location,
                )
            )
            continue

        for value in values:
            if not isinstance(value, str):
                issues.append(
                    ParseIssue(
                        "warning",
                        "principal_value_malformed",
                        "%s has a %s principal that is a %s, not a string; "
                        "skipped." % (location, key, type(value).__name__),
                        location,
                    )
                )
                continue
            out.append(_classify_one(key, value.strip(), export, role))
    return out


def _canonical_principal_key(raw_key: Any) -> Optional[str]:
    if not isinstance(raw_key, str):
        return None
    for candidate in PRINCIPAL_KEYS:
        if raw_key.lower() == candidate.lower():
            return candidate
    return None


def _classify_one(
    key: str, value: str, export: IamExport, role: Role
) -> TrustPrincipal:
    if key == "AWS":
        return _classify_aws(value, export, role)
    if key == "Service":
        return _classify_service(value)
    if key == "Federated":
        return _classify_federated(value, export)
    if key == "CanonicalUser":
        return TrustPrincipal(
            block_key=key,
            raw=value,
            principal_class=PrincipalClass.CANONICAL_USER,
            provider_kind=ProviderKind.AWS_ACCOUNT,
            label="S3 canonical user id",
        )
    return _unknown_principal(key, value, "unhandled principal key")


# --------------------------------------------------------------------------
# AWS principals
# --------------------------------------------------------------------------


def _classify_aws(value: str, export: IamExport, role: Role) -> TrustPrincipal:
    if is_pure_wildcard(value):
        return _wildcard_principal("AWS", value)

    account_id = account_id_from_principal(value)
    own_account = role.account_id or export.account_id

    if account_id is None:
        principal = TrustPrincipal(
            block_key="AWS",
            raw=value,
            principal_class=PrincipalClass.UNKNOWN,
            provider_kind=ProviderKind.UNKNOWN,
            label="unparsable AWS principal",
        )
        if has_wildcard(value):
            principal.notes.append(
                "The principal contains a wildcard in part of the ARN. IAM does "
                "not support partial wildcards in a Principal element, so this "
                "statement most likely matches nothing (fail-closed) rather "
                "than matching broadly."
            )
        else:
            principal.notes.append(
                "TrustEdge could not extract a 12-digit account id from this "
                "principal, so it cannot tell whether it is same-account or "
                "cross-account."
            )
        return principal

    is_root = principal_is_account_root(value)
    same_account = bool(own_account) and account_id == own_account

    principal = TrustPrincipal(
        block_key="AWS",
        raw=value,
        account_id=account_id,
        provider_kind=ProviderKind.AWS_ACCOUNT,
        principal_class=(
            PrincipalClass.SAME_ACCOUNT if same_account else PrincipalClass.CROSS_ACCOUNT
        ),
    )

    if not own_account:
        principal.principal_class = PrincipalClass.UNKNOWN
        principal.notes.append(
            "The export does not identify the account under analysis, so "
            "TrustEdge cannot decide whether account %s is external."
            % account_id
        )
        principal.label = "AWS account %s (relationship unknown)" % account_id
        return principal

    arn = parse_arn(value)
    resource = arn["resource"] if arn else ""
    if is_root:
        principal.label = "all principals in AWS account %s" % account_id
    elif resource.startswith("role/"):
        principal.label = "IAM role %s in account %s" % (
            resource[len("role/") :],
            account_id,
        )
    elif resource.startswith("user/"):
        principal.label = "IAM user %s in account %s" % (
            resource[len("user/") :],
            account_id,
        )
    elif resource.startswith("assumed-role/"):
        principal.label = "assumed-role session %s in account %s" % (
            resource[len("assumed-role/") :],
            account_id,
        )
        principal.notes.append(
            "This is an assumed-role session ARN. IAM matches it against the "
            "session's ARN, so the role session name must match exactly."
        )
    elif resource.startswith("federated-user/"):
        principal.label = "federated user %s in account %s" % (
            resource[len("federated-user/") :],
            account_id,
        )
    else:
        principal.label = "AWS principal in account %s" % account_id

    vendor = export.vendor_accounts.get(account_id)
    if vendor and not same_account:
        principal.label += " - operator-declared vendor: %s" % vendor.vendor

    return principal


# --------------------------------------------------------------------------
# Service principals
# --------------------------------------------------------------------------


def _classify_service(value: str) -> TrustPrincipal:
    lowered = value.lower()
    if is_pure_wildcard(value):
        principal = _wildcard_principal("Service", value)
        principal.notes.append(
            "A wildcard Service principal trusts every AWS service principal."
        )
        return principal

    if lowered == ROLES_ANYWHERE_SERVICE:
        return TrustPrincipal(
            block_key="Service",
            raw=value,
            principal_class=PrincipalClass.ROLES_ANYWHERE,
            provider_kind=ProviderKind.ROLES_ANYWHERE,
            provider_id=lowered,
            label="IAM Roles Anywhere (X.509 workload certificates)",
        )

    principal = TrustPrincipal(
        block_key="Service",
        raw=value,
        principal_class=PrincipalClass.AWS_SERVICE,
        provider_kind=ProviderKind.AWS_SERVICE,
        provider_id=lowered,
        label="AWS service principal %s" % value,
    )
    if lowered == "pods.eks.amazonaws.com":
        principal.provider_kind = ProviderKind.EKS_POD_IDENTITY
        principal.label = "EKS Pod Identity"
    return principal


# --------------------------------------------------------------------------
# Federated principals
# --------------------------------------------------------------------------


def _classify_federated(value: str, export: IamExport) -> TrustPrincipal:
    if is_pure_wildcard(value):
        principal = _wildcard_principal("Federated", value)
        principal.notes.append(
            "A wildcard Federated principal is not a documented IAM form; treat "
            "this statement as suspect and verify it in the console."
        )
        return principal

    saml_name = saml_provider_name_from_arn(value)
    if saml_name:
        return TrustPrincipal(
            block_key="Federated",
            raw=value,
            principal_class=PrincipalClass.SAML,
            provider_kind=ProviderKind.SAML,
            provider_id=saml_name,
            account_id=_account_of(value),
            label="SAML identity provider %s" % saml_name,
        )

    oidc_url = oidc_provider_url_from_arn(value)
    if oidc_url:
        issuer = normalize_issuer(oidc_url)
        kind = classify_issuer(issuer)
        principal = TrustPrincipal(
            block_key="Federated",
            raw=value,
            principal_class=PrincipalClass.OIDC,
            provider_kind=kind,
            provider_id=issuer,
            account_id=_account_of(value),
            label=_oidc_label(issuer, kind),
        )
        if kind == ProviderKind.PRIVATE_OIDC:
            principal.notes.append(
                "This issuer is not in AWS's shared-OIDC-provider list, so "
                "TrustEdge treats its URL as unique to one organisation. If it "
                "is actually a multi-tenant SaaS issuer, exposure is higher "
                "than graded."
            )
        return principal

    builtin = BUILTIN_FEDERATED_ISSUERS.get(value.lower())
    if builtin:
        issuer = normalize_issuer(value)
        return TrustPrincipal(
            block_key="Federated",
            raw=value,
            principal_class=PrincipalClass.OIDC,
            provider_kind=classify_issuer(issuer),
            provider_id=issuer,
            label=_oidc_label(issuer, builtin),
        )

    # An issuer URL written without the IAM provider ARN wrapper. Not valid IAM
    # for a customer-managed provider, but it appears in hand-written policies.
    if "." in value and not value.startswith("arn:"):
        issuer = normalize_issuer(value)
        principal = TrustPrincipal(
            block_key="Federated",
            raw=value,
            principal_class=PrincipalClass.OIDC,
            provider_kind=classify_issuer(issuer),
            provider_id=issuer,
            label=_oidc_label(issuer, classify_issuer(issuer)),
        )
        principal.notes.append(
            "A customer-managed OIDC provider must be referenced by its IAM "
            "provider ARN (arn:aws:iam::<account>:oidc-provider/%s), not by the "
            "bare issuer URL. Verify this statement is the shape you intended."
            % issuer
        )
        return principal

    return _unknown_principal(
        "Federated", value, "not a SAML provider ARN, OIDC provider ARN or known issuer"
    )


def _account_of(value: str) -> Optional[str]:
    arn = parse_arn(value)
    if arn and ACCOUNT_ID_RE.match(arn.get("account", "")):
        return arn["account"]
    return None


def _oidc_label(issuer: str, kind: str) -> str:
    profile = issuer_profile(issuer)
    if profile:
        return "%s OIDC (shared issuer %s)" % (profile["name"], issuer)
    if kind == ProviderKind.EKS_IRSA:
        return "EKS IRSA cluster issuer %s" % issuer
    return "OIDC issuer %s" % issuer


# --------------------------------------------------------------------------
# Fallbacks
# --------------------------------------------------------------------------


def _wildcard_principal(block_key: str, raw: str) -> TrustPrincipal:
    return TrustPrincipal(
        block_key=block_key,
        raw=raw,
        principal_class=PrincipalClass.WILDCARD,
        provider_kind=ProviderKind.ANY_AWS_PRINCIPAL,
        label="wildcard principal (any AWS principal)",
    )


def _unknown_principal(block_key: str, raw: str, reason: str) -> TrustPrincipal:
    principal = TrustPrincipal(
        block_key=block_key,
        raw=raw,
        principal_class=PrincipalClass.UNKNOWN,
        provider_kind=ProviderKind.UNKNOWN,
        label="unclassified principal",
    )
    principal.notes.append("Unclassified: %s." % reason)
    return principal


def summarise_classes(principals: List[TrustPrincipal]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for principal in principals:
        counts[principal.principal_class] = counts.get(principal.principal_class, 0) + 1
    return counts
