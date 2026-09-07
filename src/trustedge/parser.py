"""Input validation and normalisation for TrustEdge exports.

Design rule for this module: **never raise on bad data inside the export.** A
single malformed trust statement in a 400-role account must not stop the other
399 roles from being analysed. Anything unreadable becomes a
:class:`~trustedge.models.ParseIssue` and analysis continues.

The only hard failure is an input that is not a JSON object at all, which is
raised as :class:`ExportFormatError` because there is nothing to analyse.

Two input shapes are accepted:

* the native TrustEdge export documented in ``docs/product.md``;
* the raw output of ``aws iam get-account-authorization-details``, which is
  auto-detected and converted in-memory (see :mod:`trustedge.convert`).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    IamExport,
    OidcProviderRecord,
    ParseIssue,
    PolicyRef,
    Role,
    SamlProviderRecord,
    TrustStatement,
    VendorRecord,
)
from .policy import (
    ACCOUNT_ID_RE,
    as_list,
    as_str_list,
    coerce_policy_document,
    normalize_issuer,
    parse_arn,
    policy_statements,
)


class ExportFormatError(ValueError):
    """The input cannot be interpreted as an IAM export at all."""


def _get(obj: Dict[str, Any], *names: str) -> Any:
    """Fetch the first present key, accepting snake_case or AWS PascalCase."""
    for name in names:
        if name in obj:
            return obj[name]
    return None


def load_json_file(path: str) -> Any:
    """Read and parse a JSON file, with errors a human can act on."""
    if not os.path.exists(path):
        raise ExportFormatError("input file does not exist: %s" % path)
    if os.path.isdir(path):
        raise ExportFormatError("input path is a directory, not a file: %s" % path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ExportFormatError("could not read %s: %s" % (path, exc)) from exc
    if not text.strip():
        raise ExportFormatError("input file is empty: %s" % path)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ExportFormatError(
            "input file is not valid JSON (%s): %s" % (path, exc)
        ) from exc


def looks_like_authorization_details(obj: Any) -> bool:
    """Detect ``aws iam get-account-authorization-details`` output."""
    if not isinstance(obj, dict):
        return False
    return any(
        key in obj
        for key in ("RoleDetailList", "UserDetailList", "GroupDetailList")
    )


def parse_export(obj: Any, source: Optional[str] = None) -> Tuple[IamExport, List[ParseIssue]]:
    """Normalise a loaded JSON document into an :class:`IamExport`."""
    issues: List[ParseIssue] = []

    if obj is None:
        raise ExportFormatError("input document is null")
    if isinstance(obj, list):
        raise ExportFormatError(
            "input document is a JSON array; expected an object with a 'roles' key"
        )
    if not isinstance(obj, dict):
        raise ExportFormatError(
            "input document is a %s; expected a JSON object" % type(obj).__name__
        )

    if looks_like_authorization_details(obj):
        from .convert import from_authorization_details

        obj, convert_issues = from_authorization_details(obj)
        issues.extend(convert_issues)

    export = IamExport(
        account_id=_clean_account_id(_get(obj, "account_id", "AccountId"), issues),
        generated_at=_as_optional_str(_get(obj, "generated_at", "GeneratedAt")),
        source=source,
        organization_id=_as_optional_str(_get(obj, "organization_id", "OrganizationId")),
        trusted_account_ids=[
            a
            for a in as_str_list(_get(obj, "trusted_account_ids", "TrustedAccountIds"))
            if ACCOUNT_ID_RE.match(a.strip())
        ],
    )

    export.managed_policies = _parse_managed_policies(obj, issues)
    export.oidc_providers = _parse_oidc_providers(obj, issues)
    export.saml_providers = _parse_saml_providers(obj, issues)
    export.vendor_accounts = _parse_vendor_accounts(obj, issues)

    raw_roles = _get(obj, "roles", "Roles")
    if raw_roles is None:
        issues.append(
            ParseIssue(
                "error",
                "no_roles_key",
                "Export has no 'roles' key; there is nothing to analyse.",
                "$",
            )
        )
        return export, issues
    if not isinstance(raw_roles, list):
        issues.append(
            ParseIssue(
                "error",
                "roles_not_a_list",
                "'roles' is a %s, not a list; no roles analysed."
                % type(raw_roles).__name__,
                "$.roles",
            )
        )
        return export, issues

    seen_names: Dict[str, int] = {}
    for index, raw_role in enumerate(raw_roles):
        location = "$.roles[%d]" % index
        if not isinstance(raw_role, dict):
            issues.append(
                ParseIssue(
                    "error",
                    "role_not_an_object",
                    "Role entry is a %s, not an object; skipped."
                    % type(raw_role).__name__,
                    location,
                )
            )
            continue
        role = _parse_role(raw_role, index, export, issues, location)
        if role is None:
            continue
        count = seen_names.get(role.role_name, 0)
        if count:
            issues.append(
                ParseIssue(
                    "warning",
                    "duplicate_role_name",
                    "Role name %r appears more than once in the export."
                    % role.role_name,
                    location,
                )
            )
        seen_names[role.role_name] = count + 1
        export.roles.append(role)

    if export.account_id is None:
        inferred = _infer_account_id(export.roles)
        if inferred:
            export.account_id = inferred
            issues.append(
                ParseIssue(
                    "warning",
                    "account_id_inferred",
                    "No account_id in the export; inferred %s from role ARNs. "
                    "Same-account vs cross-account classification depends on this."
                    % inferred,
                    "$",
                )
            )
        else:
            issues.append(
                ParseIssue(
                    "error",
                    "account_id_missing",
                    "No account_id in the export and none inferable from role ARNs. "
                    "Principals in other accounts cannot be distinguished from "
                    "same-account principals, so every AWS principal is reported "
                    "as NOT_DETERMINED.",
                    "$",
                )
            )

    return export, issues


# --------------------------------------------------------------------------
# Role parsing
# --------------------------------------------------------------------------


def _parse_role(
    raw: Dict[str, Any],
    index: int,
    export: IamExport,
    issues: List[ParseIssue],
    location: str,
) -> Optional[Role]:
    name = _as_optional_str(_get(raw, "role_name", "RoleName"))
    arn = _as_optional_str(_get(raw, "arn", "Arn", "role_arn", "RoleArn"))
    if not name and arn:
        arn_parts = parse_arn(arn)
        if arn_parts and "/" in arn_parts["resource"]:
            name = arn_parts["resource"].split("/")[-1]
    if not name:
        issues.append(
            ParseIssue(
                "error",
                "role_name_missing",
                "Role entry has neither role_name nor a parsable arn; skipped.",
                location,
            )
        )
        return None

    account_id = None
    if arn:
        arn_parts = parse_arn(arn)
        if arn_parts and ACCOUNT_ID_RE.match(arn_parts.get("account", "")):
            account_id = arn_parts["account"]

    role = Role(
        role_name=name,
        arn=arn,
        path=_as_optional_str(_get(raw, "path", "Path")) or "/",
        account_id=account_id or export.account_id,
        description=_as_optional_str(_get(raw, "description", "Description")),
        create_date=_as_optional_str(_get(raw, "create_date", "CreateDate")),
        tags=_parse_tags(_get(raw, "tags", "Tags")),
        permissions_boundary_arn=_parse_permissions_boundary(
            _get(raw, "permissions_boundary", "PermissionsBoundary", "permissions_boundary_arn")
        ),
    )

    raw_trust = _get(
        raw,
        "assume_role_policy_document",
        "AssumeRolePolicyDocument",
        "trust_policy",
        "TrustPolicy",
    )
    role.trust_policy_raw = raw_trust
    document, error = coerce_policy_document(raw_trust)
    if document is None:
        role.trust_policy_unusable = True
        issues.append(
            ParseIssue(
                "error",
                "trust_policy_unreadable",
                "Role %r: %s. No inbound trust analysis is possible for this role."
                % (name, error),
                location + ".assume_role_policy_document",
            )
        )
    else:
        role.trust_statements = _parse_trust_statements(
            document, name, issues, location + ".assume_role_policy_document"
        )
        if not role.trust_statements:
            role.trust_policy_unusable = True

    role.policies = _parse_role_policies(raw, name, export, issues, location)
    return role


def _parse_trust_statements(
    document: Dict[str, Any],
    role_name: str,
    issues: List[ParseIssue],
    location: str,
) -> List[TrustStatement]:
    statements, problems = policy_statements(document)
    for problem in problems:
        issues.append(
            ParseIssue(
                "error" if not statements else "warning",
                "trust_statement_problem",
                "Role %r trust policy: %s" % (role_name, problem),
                location,
            )
        )

    version = document.get("Version")
    if version is not None and version != "2012-10-17":
        issues.append(
            ParseIssue(
                "warning",
                "unexpected_policy_version",
                "Role %r trust policy declares Version %r. TrustEdge grades it "
                "with 2012-10-17 semantics." % (role_name, version),
                location,
            )
        )

    out: List[TrustStatement] = []
    for index, raw_statement in enumerate(statements):
        statement_location = "%s.Statement[%d]" % (location, index)
        effect = raw_statement.get("Effect")
        if not isinstance(effect, str) or effect.capitalize() not in ("Allow", "Deny"):
            issues.append(
                ParseIssue(
                    "warning",
                    "statement_effect_invalid",
                    "Role %r statement %d has Effect %r; treated as Allow, which "
                    "is the conservative reading for exposure analysis."
                    % (role_name, index, effect),
                    statement_location,
                )
            )
            effect = "Allow"
        else:
            effect = effect.capitalize()

        actions = [a for a in as_str_list(raw_statement.get("Action")) if a]
        if not actions and "NotAction" in raw_statement:
            issues.append(
                ParseIssue(
                    "warning",
                    "not_action_unsupported",
                    "Role %r statement %d uses NotAction. TrustEdge does not "
                    "expand NotAction and treats the statement as granting an "
                    "assume-role action." % (role_name, index),
                    statement_location,
                )
            )
            actions = ["sts:AssumeRole"]
        if not actions:
            issues.append(
                ParseIssue(
                    "warning",
                    "statement_action_missing",
                    "Role %r statement %d has no Action element; it cannot "
                    "authorise anything and is reported as informational."
                    % (role_name, index),
                    statement_location,
                )
            )

        has_not_principal = "NotPrincipal" in raw_statement
        if has_not_principal:
            issues.append(
                ParseIssue(
                    "warning",
                    "not_principal_unsupported",
                    "Role %r statement %d uses NotPrincipal. TrustEdge does not "
                    "grade NotPrincipal because the allowed set is the complement "
                    "of the listed principals; review this statement by hand."
                    % (role_name, index),
                    statement_location,
                )
            )

        raw_condition = raw_statement.get("Condition")
        if raw_condition is not None and not isinstance(raw_condition, dict):
            issues.append(
                ParseIssue(
                    "warning",
                    "condition_not_an_object",
                    "Role %r statement %d has a Condition that is a %s, not an "
                    "object; treated as no condition (the conservative reading)."
                    % (role_name, index, type(raw_condition).__name__),
                    statement_location,
                )
            )
            raw_condition = {}

        out.append(
            TrustStatement(
                index=index,
                effect=effect,
                sid=_as_optional_str(raw_statement.get("Sid")),
                actions=actions,
                condition=raw_condition if isinstance(raw_condition, dict) else {},
                has_not_principal=has_not_principal,
                raw=raw_statement,
            )
        )
    return out


def _parse_role_policies(
    raw: Dict[str, Any],
    role_name: str,
    export: IamExport,
    issues: List[ParseIssue],
    location: str,
) -> List[PolicyRef]:
    out: List[PolicyRef] = []

    # -- inline policies: list of {name, document} or a {name: document} map --
    inline = _get(
        raw, "inline_policies", "InlinePolicies", "RolePolicyList", "role_policy_list"
    )
    inline_items: List[Tuple[Optional[str], Any]] = []
    if isinstance(inline, dict):
        inline_items = list(inline.items())
    elif isinstance(inline, list):
        for entry in inline:
            if isinstance(entry, dict):
                inline_items.append(
                    (
                        _as_optional_str(
                            _get(entry, "policy_name", "PolicyName", "name")
                        ),
                        _get(entry, "policy_document", "PolicyDocument", "document"),
                    )
                )
            else:
                issues.append(
                    ParseIssue(
                        "warning",
                        "inline_policy_malformed",
                        "Role %r has an inline policy entry that is a %s, not an "
                        "object; skipped." % (role_name, type(entry).__name__),
                        location + ".inline_policies",
                    )
                )
    elif inline is not None:
        issues.append(
            ParseIssue(
                "warning",
                "inline_policies_malformed",
                "Role %r inline_policies is a %s; expected a list or object."
                % (role_name, type(inline).__name__),
                location + ".inline_policies",
            )
        )

    for policy_index, (policy_name, raw_document) in enumerate(inline_items):
        name = policy_name or "inline-%d" % policy_index
        document, error = coerce_policy_document(raw_document)
        ref = PolicyRef(name=name, source="inline", document=document)
        if document is None:
            ref.unresolved = True
            issues.append(
                ParseIssue(
                    "warning",
                    "inline_policy_unreadable",
                    "Role %r inline policy %r: %s. Its permissions are not "
                    "counted towards blast radius." % (role_name, name, error),
                    location + ".inline_policies",
                )
            )
        out.append(ref)

    # -- attached managed policies -----------------------------------------
    attached = _get(
        raw,
        "attached_managed_policies",
        "AttachedManagedPolicies",
        "attached_policies",
        "AttachedPolicies",
    )
    for entry in as_list(attached):
        arn: Optional[str] = None
        name: Optional[str] = None
        inline_doc: Any = None
        if isinstance(entry, str):
            arn = entry
        elif isinstance(entry, dict):
            arn = _as_optional_str(_get(entry, "policy_arn", "PolicyArn", "arn"))
            name = _as_optional_str(_get(entry, "policy_name", "PolicyName", "name"))
            inline_doc = _get(entry, "policy_document", "PolicyDocument")
        else:
            issues.append(
                ParseIssue(
                    "warning",
                    "attached_policy_malformed",
                    "Role %r has an attached-policy entry that is a %s; skipped."
                    % (role_name, type(entry).__name__),
                    location + ".attached_managed_policies",
                )
            )
            continue

        if not name and arn:
            arn_parts = parse_arn(arn)
            if arn_parts and "/" in arn_parts["resource"]:
                name = arn_parts["resource"].split("/")[-1]
        name = name or arn or "attached-policy"

        document: Optional[Dict[str, Any]] = None
        if inline_doc is not None:
            document, error = coerce_policy_document(inline_doc)
            if document is None:
                issues.append(
                    ParseIssue(
                        "warning",
                        "attached_policy_document_unreadable",
                        "Role %r attached policy %r: %s"
                        % (role_name, name, error),
                        location + ".attached_managed_policies",
                    )
                )
        if document is None and arn and arn in export.managed_policies:
            document = export.managed_policies[arn]

        ref = PolicyRef(
            name=name, source="attached_managed", arn=arn, document=document
        )
        if document is None:
            ref.unresolved = True
            issues.append(
                ParseIssue(
                    "warning",
                    "managed_policy_document_missing",
                    "Role %r attaches managed policy %r but the export contains "
                    "no document for it. Blast radius for this role is a lower "
                    "bound." % (role_name, name),
                    location + ".attached_managed_policies",
                )
            )
        out.append(ref)

    return out


# --------------------------------------------------------------------------
# Top-level collections
# --------------------------------------------------------------------------


def _parse_managed_policies(
    obj: Dict[str, Any], issues: List[ParseIssue]
) -> Dict[str, Dict[str, Any]]:
    """Build an ``arn -> document`` map from the export's policy library."""
    out: Dict[str, Dict[str, Any]] = {}
    raw = _get(obj, "managed_policies", "ManagedPolicies", "policies", "Policies")
    if raw is None:
        return out

    entries: List[Tuple[Optional[str], Any]] = []
    if isinstance(raw, dict):
        entries = list(raw.items())
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                entries.append(
                    (
                        _as_optional_str(_get(entry, "policy_arn", "PolicyArn", "arn")),
                        entry,
                    )
                )
            else:
                issues.append(
                    ParseIssue(
                        "warning",
                        "managed_policy_malformed",
                        "managed_policies contains a %s, not an object; skipped."
                        % type(entry).__name__,
                        "$.managed_policies",
                    )
                )
    else:
        issues.append(
            ParseIssue(
                "warning",
                "managed_policies_malformed",
                "managed_policies is a %s; expected a list or object."
                % type(raw).__name__,
                "$.managed_policies",
            )
        )
        return out

    for arn, value in entries:
        raw_document: Any = value
        if isinstance(value, dict) and (
            "policy_document" in value
            or "PolicyDocument" in value
            or "document" in value
        ):
            raw_document = _get(value, "policy_document", "PolicyDocument", "document")
        if not arn and isinstance(value, dict):
            arn = _as_optional_str(_get(value, "policy_arn", "PolicyArn", "arn"))
        document, error = coerce_policy_document(raw_document)
        if document is None:
            issues.append(
                ParseIssue(
                    "warning",
                    "managed_policy_document_unreadable",
                    "managed policy %s: %s" % (arn or "<no arn>", error),
                    "$.managed_policies",
                )
            )
            continue
        if not arn:
            issues.append(
                ParseIssue(
                    "warning",
                    "managed_policy_arn_missing",
                    "A managed policy document has no policy_arn, so roles cannot "
                    "reference it; skipped.",
                    "$.managed_policies",
                )
            )
            continue
        out[arn] = document
    return out


def _parse_oidc_providers(
    obj: Dict[str, Any], issues: List[ParseIssue]
) -> List[OidcProviderRecord]:
    out: List[OidcProviderRecord] = []
    raw = _get(obj, "oidc_providers", "OidcProviders", "OpenIDConnectProviders")
    for entry in as_list(raw):
        if isinstance(entry, str):
            out.append(OidcProviderRecord(arn=None, url=normalize_issuer(entry)))
            continue
        if not isinstance(entry, dict):
            issues.append(
                ParseIssue(
                    "warning",
                    "oidc_provider_malformed",
                    "oidc_providers contains a %s; skipped." % type(entry).__name__,
                    "$.oidc_providers",
                )
            )
            continue
        arn = _as_optional_str(_get(entry, "arn", "Arn"))
        url = _as_optional_str(_get(entry, "url", "Url", "URL"))
        if not url and arn:
            from .policy import oidc_provider_url_from_arn

            url = oidc_provider_url_from_arn(arn)
        if not url:
            issues.append(
                ParseIssue(
                    "warning",
                    "oidc_provider_url_missing",
                    "An oidc_providers entry has no url and no parsable arn; skipped.",
                    "$.oidc_providers",
                )
            )
            continue
        out.append(
            OidcProviderRecord(
                arn=arn,
                url=normalize_issuer(url),
                client_id_list=as_str_list(
                    _get(entry, "client_id_list", "ClientIDList", "client_ids")
                ),
                thumbprint_list=as_str_list(
                    _get(entry, "thumbprint_list", "ThumbprintList")
                ),
            )
        )
    return out


def _parse_saml_providers(
    obj: Dict[str, Any], issues: List[ParseIssue]
) -> List[SamlProviderRecord]:
    out: List[SamlProviderRecord] = []
    raw = _get(obj, "saml_providers", "SamlProviders", "SAMLProviders")
    for entry in as_list(raw):
        if isinstance(entry, str):
            out.append(SamlProviderRecord(arn=None, name=entry))
            continue
        if not isinstance(entry, dict):
            issues.append(
                ParseIssue(
                    "warning",
                    "saml_provider_malformed",
                    "saml_providers contains a %s; skipped." % type(entry).__name__,
                    "$.saml_providers",
                )
            )
            continue
        arn = _as_optional_str(_get(entry, "arn", "Arn"))
        name = _as_optional_str(_get(entry, "name", "Name"))
        if not name and arn:
            from .policy import saml_provider_name_from_arn

            name = saml_provider_name_from_arn(arn)
        out.append(SamlProviderRecord(arn=arn, name=name or "<unnamed>"))
    return out


def _parse_vendor_accounts(
    obj: Dict[str, Any], issues: List[ParseIssue]
) -> Dict[str, VendorRecord]:
    """Read the operator-supplied known-vendor mapping.

    This is an *assertion by the operator*, not something TrustEdge verifies.
    Every finding that uses it says so.
    """
    out: Dict[str, VendorRecord] = {}
    raw = _get(obj, "vendor_accounts", "VendorAccounts", "known_vendors")
    if raw is None:
        return out

    items: List[Tuple[Optional[str], Any]] = []
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                items.append(
                    (_as_optional_str(_get(entry, "account_id", "AccountId")), entry)
                )
    else:
        issues.append(
            ParseIssue(
                "warning",
                "vendor_accounts_malformed",
                "vendor_accounts is a %s; expected a list or object."
                % type(raw).__name__,
                "$.vendor_accounts",
            )
        )
        return out

    for account_id, value in items:
        if not account_id or not ACCOUNT_ID_RE.match(str(account_id).strip()):
            issues.append(
                ParseIssue(
                    "warning",
                    "vendor_account_id_invalid",
                    "vendor_accounts key %r is not a 12-digit AWS account id; skipped."
                    % account_id,
                    "$.vendor_accounts",
                )
            )
            continue
        account_id = str(account_id).strip()
        if isinstance(value, str):
            out[account_id] = VendorRecord(account_id=account_id, vendor=value)
            continue
        if not isinstance(value, dict):
            continue
        requires = _get(value, "requires_external_id", "RequiresExternalId")
        out[account_id] = VendorRecord(
            account_id=account_id,
            vendor=_as_optional_str(_get(value, "vendor", "Vendor", "name", "Name"))
            or "unnamed vendor",
            notes=_as_optional_str(_get(value, "notes", "Notes")) or "",
            requires_external_id=bool(requires) if requires is not None else None,
        )
    return out


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _as_optional_str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _clean_account_id(value: Any, issues: List[ParseIssue]) -> Optional[str]:
    text = _as_optional_str(value)
    if text is None:
        return None
    if not ACCOUNT_ID_RE.match(text):
        issues.append(
            ParseIssue(
                "warning",
                "account_id_malformed",
                "account_id %r is not a 12-digit AWS account id; ignored." % text,
                "$.account_id",
            )
        )
        return None
    return text


def _parse_tags(raw: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(key, str):
                out[key] = value if isinstance(value, str) else str(value)
    else:
        for entry in as_list(raw):
            if isinstance(entry, dict):
                key = entry.get("Key", entry.get("key"))
                value = entry.get("Value", entry.get("value"))
                if isinstance(key, str):
                    out[key] = value if isinstance(value, str) else str(value)
    return out


def _parse_permissions_boundary(raw: Any) -> Optional[str]:
    if isinstance(raw, str):
        return raw.strip() or None
    if isinstance(raw, dict):
        return _as_optional_str(
            _get(raw, "PermissionsBoundaryArn", "permissions_boundary_arn", "arn", "Arn")
        )
    return None


def _infer_account_id(roles: List[Role]) -> Optional[str]:
    """Pick the account id shared by the role ARNs, if they agree."""
    candidates = {r.account_id for r in roles if r.account_id}
    if len(candidates) == 1:
        return candidates.pop()
    return None
