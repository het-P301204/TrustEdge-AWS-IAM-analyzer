"""Offline conversion of ``aws iam get-account-authorization-details`` output.

This is a pure JSON-to-JSON transform on a file you already have. TrustEdge
makes no AWS API calls anywhere, including here - the point of the converter is
that the one command a reader is likely to already have run produces something
TrustEdge can read.

Collect the input yourself with a read-only call::

    aws iam get-account-authorization-details --filter Role > auth-details.json

Then either analyse it directly (TrustEdge auto-detects the shape) or convert
it to the native export first::

    trustedge convert --input auth-details.json --output export.json

``get-account-authorization-details`` does **not** include IAM OIDC or SAML
identity providers, the organisation id, or any notion of which external
accounts belong to which vendor. Those have to be supplied separately with
``--add``; without them TrustEdge grades federated principals with less
context and says so in the report.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import ParseIssue
from .policy import ACCOUNT_ID_RE, as_list, parse_arn

#: Keys a supplementary ``--add`` file may contribute.
SUPPLEMENTARY_KEYS = (
    "account_id",
    "organization_id",
    "trusted_account_ids",
    "oidc_providers",
    "saml_providers",
    "vendor_accounts",
)


def from_authorization_details(
    document: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[ParseIssue]]:
    """Convert authorization-details JSON into the native TrustEdge export."""
    issues: List[ParseIssue] = []
    roles: List[Dict[str, Any]] = []
    managed_policies: List[Dict[str, Any]] = []

    raw_roles = document.get("RoleDetailList")
    if raw_roles is None:
        issues.append(
            ParseIssue(
                "error",
                "no_role_detail_list",
                "The authorization-details document has no RoleDetailList. Run "
                "the command with --filter Role (or without a filter) so roles "
                "are included.",
                "$.RoleDetailList",
            )
        )
        raw_roles = []
    elif not isinstance(raw_roles, list):
        issues.append(
            ParseIssue(
                "error",
                "role_detail_list_malformed",
                "RoleDetailList is a %s, not a list." % type(raw_roles).__name__,
                "$.RoleDetailList",
            )
        )
        raw_roles = []

    for index, raw in enumerate(raw_roles):
        if not isinstance(raw, dict):
            issues.append(
                ParseIssue(
                    "warning",
                    "role_detail_malformed",
                    "RoleDetailList[%d] is a %s, not an object; skipped."
                    % (index, type(raw).__name__),
                    "$.RoleDetailList[%d]" % index,
                )
            )
            continue
        roles.append(_convert_role(raw))

    for index, raw in enumerate(as_list(document.get("Policies"))):
        if not isinstance(raw, dict):
            issues.append(
                ParseIssue(
                    "warning",
                    "policy_malformed",
                    "Policies[%d] is a %s, not an object; skipped."
                    % (index, type(raw).__name__),
                    "$.Policies[%d]" % index,
                )
            )
            continue
        converted = _convert_policy(raw, index, issues)
        if converted is not None:
            managed_policies.append(converted)

    export: Dict[str, Any] = {
        "trustedge_export_version": "1",
        "source": "aws iam get-account-authorization-details",
        "roles": roles,
        "managed_policies": managed_policies,
    }
    account_id = _infer_account_id(roles)
    if account_id:
        export["account_id"] = account_id
    else:
        issues.append(
            ParseIssue(
                "warning",
                "account_id_not_inferable",
                "Could not infer the account id from role ARNs. Supply it with "
                "--add so cross-account principals can be distinguished from "
                "same-account ones.",
                "$",
            )
        )

    issues.append(
        ParseIssue(
            "warning",
            "authorization_details_lacks_providers",
            "get-account-authorization-details does not return IAM OIDC or SAML "
            "identity providers, the organisation id, or vendor ownership of "
            "external accounts. Federated principals are graded without that "
            "context. Supply it with 'trustedge convert --add'.",
            "$",
        )
    )
    return export, issues


def _convert_role(raw: Dict[str, Any]) -> Dict[str, Any]:
    role: Dict[str, Any] = {
        "role_name": raw.get("RoleName"),
        "arn": raw.get("Arn"),
        "path": raw.get("Path", "/"),
        "create_date": _stringify(raw.get("CreateDate")),
        "assume_role_policy_document": raw.get("AssumeRolePolicyDocument"),
        "description": raw.get("Description"),
    }

    inline: List[Dict[str, Any]] = []
    for entry in as_list(raw.get("RolePolicyList")):
        if isinstance(entry, dict):
            inline.append(
                {
                    "policy_name": entry.get("PolicyName"),
                    "policy_document": entry.get("PolicyDocument"),
                }
            )
    if inline:
        role["inline_policies"] = inline

    attached: List[Dict[str, Any]] = []
    for entry in as_list(raw.get("AttachedManagedPolicies")):
        if isinstance(entry, dict):
            attached.append(
                {
                    "policy_name": entry.get("PolicyName"),
                    "policy_arn": entry.get("PolicyArn"),
                }
            )
    if attached:
        role["attached_managed_policies"] = attached

    boundary = raw.get("PermissionsBoundary")
    if isinstance(boundary, dict) and boundary.get("PermissionsBoundaryArn"):
        role["permissions_boundary_arn"] = boundary["PermissionsBoundaryArn"]

    tags: Dict[str, str] = {}
    for entry in as_list(raw.get("Tags")):
        if isinstance(entry, dict) and isinstance(entry.get("Key"), str):
            tags[entry["Key"]] = _stringify(entry.get("Value")) or ""
    if tags:
        role["tags"] = tags

    return role


def _convert_policy(
    raw: Dict[str, Any], index: int, issues: List[ParseIssue]
) -> Optional[Dict[str, Any]]:
    """Pick a managed policy's default version document."""
    arn = raw.get("Arn")
    if not isinstance(arn, str) or not arn:
        issues.append(
            ParseIssue(
                "warning",
                "policy_arn_missing",
                "Policies[%d] has no Arn, so no role can reference it; skipped."
                % index,
                "$.Policies[%d]" % index,
            )
        )
        return None

    default_version = raw.get("DefaultVersionId")
    versions = [v for v in as_list(raw.get("PolicyVersionList")) if isinstance(v, dict)]
    chosen: Optional[Dict[str, Any]] = None
    for version in versions:
        if version.get("IsDefaultVersion") is True:
            chosen = version
            break
    if chosen is None and default_version:
        for version in versions:
            if version.get("VersionId") == default_version:
                chosen = version
                break
    if chosen is None and versions:
        chosen = versions[0]
        issues.append(
            ParseIssue(
                "warning",
                "policy_default_version_unclear",
                "Managed policy %s does not mark a default version; using "
                "version %s. Its permissions may differ from the version "
                "actually in force."
                % (arn, chosen.get("VersionId", "<unknown>")),
                "$.Policies[%d]" % index,
            )
        )
    if chosen is None:
        issues.append(
            ParseIssue(
                "warning",
                "policy_no_versions",
                "Managed policy %s has no PolicyVersionList, so its document is "
                "unavailable and roles attaching it will report a lower-bound "
                "blast radius." % arn,
                "$.Policies[%d]" % index,
            )
        )
        return None

    return {
        "policy_arn": arn,
        "policy_name": raw.get("PolicyName"),
        "default_version_id": chosen.get("VersionId", default_version),
        "policy_document": chosen.get("Document"),
    }


def merge_supplementary(
    export: Dict[str, Any], supplement: Any
) -> Tuple[Dict[str, Any], List[ParseIssue]]:
    """Fold an operator-supplied context file into a converted export."""
    issues: List[ParseIssue] = []
    if not isinstance(supplement, dict):
        issues.append(
            ParseIssue(
                "error",
                "supplement_malformed",
                "The --add file must contain a JSON object with keys from: %s."
                % ", ".join(SUPPLEMENTARY_KEYS),
                "$",
            )
        )
        return export, issues

    for key, value in supplement.items():
        if key not in SUPPLEMENTARY_KEYS:
            issues.append(
                ParseIssue(
                    "warning",
                    "supplement_key_ignored",
                    "Ignoring unsupported --add key %r. Supported keys: %s."
                    % (key, ", ".join(SUPPLEMENTARY_KEYS)),
                    "$",
                )
            )
            continue
        export[key] = value
    return export, issues


def _infer_account_id(roles: List[Dict[str, Any]]) -> Optional[str]:
    candidates = set()
    for role in roles:
        arn = parse_arn(role.get("arn") or "")
        if arn and ACCOUNT_ID_RE.match(arn.get("account", "")):
            candidates.add(arn["account"])
    if len(candidates) == 1:
        return candidates.pop()
    return None


def _stringify(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)
