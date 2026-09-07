"""Condition-block modelling and condition-strength primitives.

This module encodes the parts of IAM condition semantics that decide whether a
condition actually guards anything. The two behaviours that matter most for
inbound trust analysis, both quoted from the AWS documentation:

1. Default operators fail *closed* on a missing key:

       "If the key that you specify in a policy condition is not present in the
       request context, the values do not match and the condition is false."

2. ``...IfExists`` operators fail *open* on a missing key:

       "If the condition key is present in the context of the request, process
       the key as specified in the policy. If the key is not present, evaluate
       the condition element as true."

   ``ForAllValues`` has the same hazard: "The ForAllValues qualifier returns
   true if there are no context keys in the request or if the context key value
   resolves to a null dataset".

So ``StringEqualsIfExists`` on a claim an identity provider does not always
issue is not a guard at all - and that is a finding TrustEdge can make with
high confidence from a static export.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from .models import WeakCondition
from .policy import as_str_list, has_wildcard, is_pure_wildcard, literal_prefix

SET_OPERATORS = ("ForAllValues", "ForAnyValue")

#: Operators whose values are interpreted as globs. Everything else treats
#: ``*`` and ``?`` as literal characters.
WILDCARD_OPERATORS = {
    "stringlike",
    "stringnotlike",
    "arnlike",
    "arnnotlike",
    "arnequals",
    "arnnotequals",
}

#: Operators that exclude rather than include. A negated operator never pins
#: *who* may enter; it only carves identities out of an already-open set.
NEGATED_MARKERS = ("NotEquals", "NotLike", "NotIpAddress")


@dataclass
class ConditionEntry:
    """One ``operator -> key -> value(s)`` triple from a Condition block."""

    raw_operator: str
    operator: str
    set_operator: Optional[str]
    if_exists: bool
    negated: bool
    key: str
    values: List[str]
    #: True when the value list in the export was not a string or list of
    #: strings (e.g. a nested object) and had to be dropped.
    malformed_values: bool = False

    @property
    def key_lower(self) -> str:
        return self.key.lower()

    @property
    def operator_lower(self) -> str:
        return self.operator.lower()

    @property
    def supports_wildcards(self) -> bool:
        return self.operator_lower in WILDCARD_OPERATORS

    @property
    def is_null_check(self) -> bool:
        return self.operator_lower == "null"

    def requires_key_present(self) -> bool:
        """``Null: {key: "false"}`` asserts the key exists and is non-null."""
        if not self.is_null_check:
            return False
        return any(v.strip().lower() == "false" for v in self.values)

    def requires_key_absent(self) -> bool:
        if not self.is_null_check:
            return False
        return any(v.strip().lower() == "true" for v in self.values)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operator": self.raw_operator,
            "key": self.key,
            "values": list(self.values),
        }


def split_operator(raw: str) -> Dict[str, Any]:
    """Decompose ``ForAllValues:StringLikeIfExists`` into its parts."""
    set_operator: Optional[str] = None
    operator = raw
    if ":" in raw:
        head, _, tail = raw.partition(":")
        for candidate in SET_OPERATORS:
            if head.strip().lower() == candidate.lower():
                set_operator = candidate
                operator = tail.strip()
                break
    if_exists = False
    if operator.lower().endswith("ifexists") and operator.lower() != "ifexists":
        if_exists = True
        operator = operator[: -len("IfExists")]
    negated = any(marker.lower() in operator.lower() for marker in NEGATED_MARKERS)
    return {
        "set_operator": set_operator,
        "operator": operator,
        "if_exists": if_exists,
        "negated": negated,
    }


class ConditionSet:
    """A parsed, queryable view over a trust statement's Condition block.

    Key lookups are case-insensitive because IAM condition key names are
    case-insensitive, while the original casing is preserved for evidence.
    """

    def __init__(self, entries: Sequence[ConditionEntry], problems: Sequence[str] = ()):
        self.entries: List[ConditionEntry] = list(entries)
        self.problems: List[str] = list(problems)

    # -- construction ------------------------------------------------------

    @classmethod
    def from_raw(cls, raw: Any) -> "ConditionSet":
        entries: List[ConditionEntry] = []
        problems: List[str] = []
        if raw is None:
            return cls(entries, problems)
        if not isinstance(raw, dict):
            problems.append(
                "Condition element is a %s, not an object; treated as absent"
                % type(raw).__name__
            )
            return cls(entries, problems)
        for raw_operator, block in raw.items():
            if not isinstance(raw_operator, str):
                problems.append("condition operator key is not a string; skipped")
                continue
            if not isinstance(block, dict):
                problems.append(
                    "condition operator %r does not map to an object; skipped"
                    % raw_operator
                )
                continue
            parts = split_operator(raw_operator)
            for key, value in block.items():
                if not isinstance(key, str):
                    problems.append(
                        "condition key under %r is not a string; skipped" % raw_operator
                    )
                    continue
                values = as_str_list(value)
                malformed = bool(value is not None and not values)
                if malformed:
                    problems.append(
                        "condition %s/%s has a value TrustEdge cannot read (%s)"
                        % (raw_operator, key, type(value).__name__)
                    )
                entries.append(
                    ConditionEntry(
                        raw_operator=raw_operator,
                        operator=parts["operator"],
                        set_operator=parts["set_operator"],
                        if_exists=parts["if_exists"],
                        negated=parts["negated"],
                        key=key,
                        values=values,
                        malformed_values=malformed,
                    )
                )
        return cls(entries, problems)

    # -- queries -----------------------------------------------------------

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    @property
    def keys(self) -> Set[str]:
        return {e.key_lower for e in self.entries}

    def for_key(self, key: str) -> List[ConditionEntry]:
        target = key.lower()
        return [e for e in self.entries if e.key_lower == target]

    def for_key_suffix(self, suffix: str) -> List[ConditionEntry]:
        """Match by claim suffix, e.g. ``:sub`` across any issuer prefix."""
        target = suffix.lower()
        return [e for e in self.entries if e.key_lower.endswith(target)]

    def has_key(self, key: str) -> bool:
        return bool(self.for_key(key))

    def key_is_asserted_present(self, key: str) -> bool:
        """Whether a ``Null: {key: "false"}`` check pins the key as present."""
        return any(e.requires_key_present() for e in self.for_key(key))

    def positive_entries(self, key: str) -> List[ConditionEntry]:
        """Non-negated, non-Null entries for a key - the ones that pin values."""
        return [
            e
            for e in self.for_key(key)
            if not e.negated and not e.is_null_check and not e.malformed_values
        ]

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Dict[str, Any]] = {}
        for entry in self.entries:
            out.setdefault(entry.raw_operator, {})[entry.key] = (
                entry.values[0] if len(entry.values) == 1 else list(entry.values)
            )
        return out


# --------------------------------------------------------------------------
# Condition-strength analysis
# --------------------------------------------------------------------------


@dataclass
class KeyGuard:
    """The result of asking "does this Condition block really pin ``key``?"."""

    key: str
    #: Entries that pin a value and are actually evaluated.
    effective: List[ConditionEntry] = field(default_factory=list)
    #: Entries present but neutralised (IfExists / ForAllValues without a Null
    #: guard, or a negated operator).
    neutralised: List[ConditionEntry] = field(default_factory=list)
    weaknesses: List[WeakCondition] = field(default_factory=list)
    #: Values that would be compared as literals despite containing ``*``.
    literal_wildcards: List[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.effective or self.neutralised)

    @property
    def guards(self) -> bool:
        """True when at least one entry genuinely constrains the key's value."""
        return bool(self.effective)

    @property
    def patterns(self) -> List[str]:
        out: List[str] = []
        for entry in self.effective:
            out.extend(entry.values)
        return out

    @property
    def all_values_wildcard(self) -> bool:
        """True when every pinned value carries no information (``*``)."""
        values = self.patterns
        if not values:
            return False
        return all(is_pure_wildcard(v) for v in values)


def analyze_key(
    conditions: ConditionSet,
    key: str,
    claim_always_present: bool = False,
) -> KeyGuard:
    """Work out whether ``key`` is genuinely constrained by ``conditions``.

    ``claim_always_present`` should be True when the identity provider is
    documented to always issue the claim (``sub`` in an OIDC ID token, for
    example). In that case an ``IfExists`` operator is a hygiene problem rather
    than a hole, and TrustEdge says so instead of crying wolf.
    """
    guard = KeyGuard(key=key)
    entries = conditions.for_key(key)
    if not entries:
        return guard

    asserted_present = conditions.key_is_asserted_present(key)

    for entry in entries:
        if entry.is_null_check:
            if entry.requires_key_absent():
                guard.weaknesses.append(
                    WeakCondition(
                        code="null_requires_absent",
                        key=entry.key,
                        operator=entry.raw_operator,
                        detail=(
                            "Null:%s=true requires the key to be ABSENT, which is "
                            "the opposite of a value restriction." % entry.key
                        ),
                    )
                )
            continue

        if entry.malformed_values:
            guard.neutralised.append(entry)
            guard.weaknesses.append(
                WeakCondition(
                    code="unreadable_condition_value",
                    key=entry.key,
                    operator=entry.raw_operator,
                    detail="Condition value could not be read as a string or list of strings.",
                )
            )
            continue

        if entry.negated:
            guard.neutralised.append(entry)
            guard.weaknesses.append(
                WeakCondition(
                    code="negated_operator_only",
                    key=entry.key,
                    operator=entry.raw_operator,
                    detail=(
                        "%s excludes specific values instead of pinning an allowed "
                        "set, and evaluates to true when the key is absent."
                        % entry.raw_operator
                    ),
                )
            )
            continue

        neutralised = False

        if entry.if_exists and not asserted_present and not claim_always_present:
            guard.weaknesses.append(
                WeakCondition(
                    code="if_exists_vacuous",
                    key=entry.key,
                    operator=entry.raw_operator,
                    detail=(
                        "%s evaluates to TRUE when %s is absent from the request "
                        "context, so a caller who does not present the claim is "
                        "not restricted by this condition. Add "
                        '"Null": {"%s": "false"} or drop the IfExists suffix.'
                        % (entry.raw_operator, entry.key, entry.key)
                    ),
                    vacuous=True,
                )
            )
            neutralised = True
        elif entry.if_exists:
            guard.weaknesses.append(
                WeakCondition(
                    code="if_exists_redundant",
                    key=entry.key,
                    operator=entry.raw_operator,
                    detail=(
                        "%s is used, but the claim is always issued (or a Null "
                        "check pins it present), so the condition still applies. "
                        "Prefer the plain operator so the intent is unambiguous."
                        % entry.raw_operator
                    ),
                )
            )

        if entry.set_operator == "ForAllValues" and not asserted_present:
            guard.weaknesses.append(
                WeakCondition(
                    code="forallvalues_vacuous",
                    key=entry.key,
                    operator=entry.raw_operator,
                    detail=(
                        "ForAllValues returns true when the context key is absent "
                        'or resolves to an empty set. Pair it with "Null": '
                        '{"%s": "false"}.' % entry.key
                    ),
                    vacuous=True,
                )
            )
            neutralised = True

        # A wildcard in a non-wildcard operator is compared as a literal
        # character, so the condition can never match. That is a broken policy
        # (fail-closed), not exposure - and worth telling the operator about.
        if not entry.supports_wildcards:
            for value in entry.values:
                if has_wildcard(value):
                    guard.literal_wildcards.append(value)
                    guard.weaknesses.append(
                        WeakCondition(
                            code="literal_wildcard_in_exact_operator",
                            key=entry.key,
                            operator=entry.raw_operator,
                            detail=(
                                "%s performs exact matching and does not interpret "
                                "'*' or '?'. The value %r will be compared "
                                "literally, so this statement can never match. "
                                "Use StringLike if a pattern was intended."
                                % (entry.raw_operator, value)
                            ),
                        )
                    )

        if neutralised:
            guard.neutralised.append(entry)
        else:
            guard.effective.append(entry)

    if guard.effective and guard.all_values_wildcard:
        guard.weaknesses.append(
            WeakCondition(
                code="wildcard_only_value",
                key=key,
                operator=guard.effective[0].raw_operator,
                detail=(
                    "The only value supplied for %s is a bare wildcard, so the "
                    "condition matches every possible value." % key
                ),
                vacuous=True,
            )
        )

    return guard


def pinned_segments(pattern: str, separator: str) -> int:
    """How many leading separator-delimited segments a glob fully pins.

    ``repo:acme/app:ref:refs/heads/main`` with separator ``:`` pins 4 segments;
    ``repo:acme/*`` pins 1. Used to grade how narrow an OIDC subject claim is.
    """
    if not isinstance(pattern, str) or not pattern:
        return 0
    prefix = literal_prefix(pattern)
    if prefix == pattern:
        return len([s for s in pattern.split(separator) if s != ""])
    # A trailing partial segment does not count as pinned.
    return len([s for s in prefix.split(separator)[:-1] if s != ""])


def describe_operator_set(entries: Sequence[ConditionEntry]) -> str:
    return ", ".join(sorted({e.raw_operator for e in entries}))
