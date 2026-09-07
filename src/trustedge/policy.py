"""Low-level IAM policy primitives: glob matching, ARN parsing, coercion.

Kept separate from :mod:`trustedge.parser` so it can be unit-tested in
isolation - these are the functions everything else's correctness rests on.

Wildcard semantics implemented here follow the AWS documentation for string
condition operators: ``StringLike`` values "can include multi-character match
wildcards (*) and single-character match wildcards (?) anywhere in the string",
and ``StringEquals`` performs "exact matching, case sensitive" with no wildcard
interpretation at all.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

#: A 12-digit AWS account id.
ACCOUNT_ID_RE = re.compile(r"^\d{12}$")

_GLOB_CACHE: Dict[str, "re.Pattern[str]"] = {}


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Compile an IAM-style glob (``*`` and ``?`` only) to an anchored regex.

    Deliberately does not use :mod:`fnmatch`: fnmatch also gives meaning to
    ``[...]`` character classes, which IAM does not, so a literal ``[`` in a
    policy value would be silently mis-parsed.
    """
    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    out = ["^"]
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    out.append("$")
    compiled = re.compile("".join(out), re.DOTALL)
    _GLOB_CACHE[pattern] = compiled
    return compiled


def glob_match(pattern: str, value: str, case_sensitive: bool = True) -> bool:
    """Match ``value`` against an IAM glob ``pattern``."""
    if not isinstance(pattern, str) or not isinstance(value, str):
        return False
    if not case_sensitive:
        pattern = pattern.lower()
        value = value.lower()
    return glob_to_regex(pattern).match(value) is not None


def action_matches(pattern: str, action: str) -> bool:
    """Whether an IAM Action pattern covers a concrete action.

    IAM action matching is case-insensitive, and ``*`` alone covers everything.
    """
    if not isinstance(pattern, str) or not isinstance(action, str):
        return False
    return glob_match(pattern.strip(), action.strip(), case_sensitive=False)


def is_pure_wildcard(value: Any) -> bool:
    """True when a policy value carries no information at all (``*``, ``?``, ``**``).

    This mirrors the check AWS itself applies to
    ``token.actions.githubusercontent.com:sub`` when a GitHub OIDC role trust
    policy is written: the value must not be "solely a wildcard character
    (* and ?) or null".
    """
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if stripped == "":
        return True
    return set(stripped) <= {"*", "?"}


def has_wildcard(value: Any) -> bool:
    return isinstance(value, str) and ("*" in value or "?" in value)


def literal_prefix(pattern: str) -> str:
    """The leading portion of a glob before the first wildcard.

    Used to measure how much of a subject claim is actually pinned:
    ``repo:acme/*`` pins ``repo:acme/`` and nothing else.
    """
    if not isinstance(pattern, str):
        return ""
    for index, char in enumerate(pattern):
        if char in "*?":
            return pattern[:index]
    return pattern


def as_list(value: Any) -> List[Any]:
    """Normalise the IAM "string or list of strings" idiom.

    ``None`` becomes an empty list so callers never branch on it.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def as_str_list(value: Any) -> List[str]:
    """Like :func:`as_list` but keeps only string members, stringifying scalars.

    IAM condition values are documented as strings even for numeric and boolean
    operators, but real exports contain genuine JSON numbers and booleans, so
    coerce rather than drop.
    """
    out: List[str] = []
    for item in as_list(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, bool):
            out.append("true" if item else "false")
        elif isinstance(item, (int, float)):
            out.append(str(item))
    return out


def coerce_policy_document(value: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Turn whatever the export holds into a policy-document dict.

    ``get-account-authorization-details`` returns policy documents as decoded
    JSON, but ``get-role`` and CloudFormation templates return them as
    URL-encoded JSON strings, and hand-written exports use plain JSON strings.
    All three are accepted.

    Returns ``(document, error_message)``; exactly one is non-None.
    """
    if value is None:
        return None, "policy document is absent"
    if isinstance(value, dict):
        return value, None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, "policy document is an empty string"
        # Try raw JSON first, then percent-decoded JSON.
        for candidate in (text, urllib.parse.unquote(text)):
            try:
                parsed = json.loads(candidate)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, dict):
                return parsed, None
            return None, "policy document JSON is not an object"
        return None, "policy document string is not valid JSON"
    return None, "policy document has unsupported type %s" % type(value).__name__


def policy_statements(document: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract the Statement list from a policy document.

    Accepts a single statement object or a list, per the IAM grammar. Non-object
    members are dropped and reported rather than raising.

    Returns ``(statements, problems)``.
    """
    problems: List[str] = []
    if not isinstance(document, dict):
        return [], ["policy document is not a JSON object"]
    raw = document.get("Statement")
    if raw is None:
        return [], ["policy document has no Statement element"]
    statements: List[Dict[str, Any]] = []
    for index, item in enumerate(as_list(raw)):
        if isinstance(item, dict):
            statements.append(item)
        else:
            problems.append(
                "statement %d is a %s, not an object; skipped"
                % (index, type(item).__name__)
            )
    if not statements and not problems:
        problems.append("policy document Statement list is empty")
    return statements, problems


# --------------------------------------------------------------------------
# ARN handling
# --------------------------------------------------------------------------


ARN_FIELDS = ("partition", "service", "region", "account", "resource")


def parse_arn(value: str) -> Optional[Dict[str, str]]:
    """Split an ARN into its components, or return None if it is not an ARN.

    An ARN has the form ``arn:partition:service:region:account:resource`` where
    ``resource`` may itself contain colons and slashes.
    """
    if not isinstance(value, str) or not value.startswith("arn:"):
        return None
    parts = value.split(":", 5)
    if len(parts) < 6:
        return None
    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account": parts[4],
        "resource": parts[5],
    }


def account_id_from_principal(value: str) -> Optional[str]:
    """Extract the account id from an ``AWS`` principal value.

    Handles the bare account id form, the account root ARN, IAM user/role ARNs
    and assumed-role session ARNs. Returns None for wildcards and for anything
    whose account segment is not a literal 12-digit id.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if ACCOUNT_ID_RE.match(stripped):
        return stripped
    arn = parse_arn(stripped)
    if arn and ACCOUNT_ID_RE.match(arn.get("account", "")):
        return arn["account"]
    return None


def is_role_or_user_arn(value: str) -> bool:
    arn = parse_arn(value)
    if not arn:
        return False
    if arn["service"] not in ("iam", "sts"):
        return False
    resource = arn["resource"]
    return resource.startswith(("role/", "user/", "assumed-role/", "federated-user/"))


def principal_is_account_root(value: str) -> bool:
    """True for ``123456789012`` and ``arn:aws:iam::123456789012:root``."""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if ACCOUNT_ID_RE.match(stripped):
        return True
    arn = parse_arn(stripped)
    return bool(arn and arn["service"] == "iam" and arn["resource"] == "root")


def oidc_provider_url_from_arn(value: str) -> Optional[str]:
    """``arn:aws:iam::111:oidc-provider/token.actions...`` -> the issuer host/path."""
    arn = parse_arn(value)
    if not arn or arn["service"] != "iam":
        return None
    resource = arn["resource"]
    prefix = "oidc-provider/"
    if resource.startswith(prefix):
        return resource[len(prefix):]
    return None


def saml_provider_name_from_arn(value: str) -> Optional[str]:
    arn = parse_arn(value)
    if not arn or arn["service"] != "iam":
        return None
    resource = arn["resource"]
    prefix = "saml-provider/"
    if resource.startswith(prefix):
        return resource[len(prefix):]
    return None


def normalize_issuer(url: str) -> str:
    """Strip scheme and trailing slash so ``https://gitlab.com/`` == ``gitlab.com``."""
    if not isinstance(url, str):
        return ""
    out = url.strip()
    for scheme in ("https://", "http://"):
        if out.lower().startswith(scheme):
            out = out[len(scheme):]
            break
    return out.rstrip("/")
