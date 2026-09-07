"""Tests for condition-strength primitives.

These pin the two IAM behaviours the analyser's credibility depends on:
a normal operator fails closed when the key is absent, and ``...IfExists`` /
``ForAllValues`` fail open.
"""

from __future__ import annotations

import pytest

from trustedge.conditions import ConditionSet, analyze_key, pinned_segments, split_operator


class TestSplitOperator:
    def test_plain_operator(self):
        parts = split_operator("StringEquals")
        assert parts == {
            "set_operator": None,
            "operator": "StringEquals",
            "if_exists": False,
            "negated": False,
        }

    def test_if_exists_suffix(self):
        parts = split_operator("StringLikeIfExists")
        assert parts["operator"] == "StringLike"
        assert parts["if_exists"] is True

    def test_set_operator_prefix(self):
        parts = split_operator("ForAllValues:StringLike")
        assert parts["set_operator"] == "ForAllValues"
        assert parts["operator"] == "StringLike"

    def test_set_operator_and_if_exists_together(self):
        parts = split_operator("ForAnyValue:StringEqualsIfExists")
        assert parts["set_operator"] == "ForAnyValue"
        assert parts["operator"] == "StringEquals"
        assert parts["if_exists"] is True

    @pytest.mark.parametrize(
        "operator",
        ["StringNotEquals", "StringNotLike", "ArnNotEquals", "NotIpAddress"],
    )
    def test_negated_operators_are_detected(self, operator):
        assert split_operator(operator)["negated"] is True

    def test_null_is_not_treated_as_negated(self):
        assert split_operator("Null")["negated"] is False


class TestConditionSetParsing:
    def test_absent_condition_is_empty_not_an_error(self):
        conditions = ConditionSet.from_raw(None)
        assert len(conditions) == 0
        assert conditions.problems == []
        assert not conditions

    def test_non_object_condition_is_reported(self):
        conditions = ConditionSet.from_raw("sts:ExternalId=x")
        assert len(conditions) == 0
        assert conditions.problems

    def test_operator_not_mapping_to_object_is_reported(self):
        conditions = ConditionSet.from_raw({"StringEquals": "not an object"})
        assert len(conditions) == 0
        assert conditions.problems

    def test_unreadable_value_is_flagged_but_kept(self):
        conditions = ConditionSet.from_raw(
            {"StringEquals": {"k": {"nested": "object"}}}
        )
        assert len(conditions) == 1
        assert conditions.entries[0].malformed_values is True
        assert conditions.problems

    def test_key_lookup_is_case_insensitive(self):
        conditions = ConditionSet.from_raw({"StringEquals": {"STS:ExternalId": "x"}})
        assert conditions.has_key("sts:externalid")
        assert conditions.for_key("sts:ExternalId")[0].key == "STS:ExternalId"

    def test_multiple_operators_and_keys(self):
        conditions = ConditionSet.from_raw(
            {
                "StringEquals": {"a": "1", "b": "2"},
                "StringLike": {"c": ["3", "4"]},
            }
        )
        assert len(conditions) == 3
        assert conditions.keys == {"a", "b", "c"}
        assert conditions.for_key("c")[0].values == ["3", "4"]

    def test_round_trip_to_dict(self):
        raw = {"StringEquals": {"a": "1"}, "StringLike": {"b": ["2", "3"]}}
        conditions = ConditionSet.from_raw(raw)
        assert conditions.to_dict() == raw


class TestAnalyzeKey:
    def test_absent_key_does_not_guard(self):
        guard = analyze_key(ConditionSet.from_raw({}), "sts:ExternalId")
        assert guard.present is False
        assert guard.guards is False
        assert guard.weaknesses == []

    def test_plain_string_equals_guards(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringEquals": {"sts:ExternalId": "abc"}}),
            "sts:ExternalId",
        )
        assert guard.guards is True
        assert guard.patterns == ["abc"]
        assert guard.weaknesses == []

    def test_if_exists_on_an_optional_claim_is_vacuous(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {"StringEqualsIfExists": {"provider:environment": "prod"}}
            ),
            "provider:environment",
        )
        assert guard.present is True
        assert guard.guards is False, "IfExists on an absent key evaluates to true"
        assert "if_exists_vacuous" in [w.code for w in guard.weaknesses]
        assert any(w.vacuous for w in guard.weaknesses)

    def test_if_exists_is_only_untidy_when_the_claim_is_always_present(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringEqualsIfExists": {"provider:sub": "x"}}),
            "provider:sub",
            claim_always_present=True,
        )
        assert guard.guards is True
        codes = [w.code for w in guard.weaknesses]
        assert "if_exists_redundant" in codes
        assert "if_exists_vacuous" not in codes

    def test_null_false_check_rescues_if_exists(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {
                    "StringEqualsIfExists": {"provider:environment": "prod"},
                    "Null": {"provider:environment": "false"},
                }
            ),
            "provider:environment",
        )
        assert guard.guards is True
        assert "if_exists_vacuous" not in [w.code for w in guard.weaknesses]

    def test_forallvalues_without_a_null_check_is_vacuous(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {"ForAllValues:StringEquals": {"aws:TagKeys": "team"}}
            ),
            "aws:TagKeys",
        )
        assert guard.guards is False
        assert "forallvalues_vacuous" in [w.code for w in guard.weaknesses]

    def test_forallvalues_with_a_null_check_guards(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {
                    "ForAllValues:StringEquals": {"aws:TagKeys": "team"},
                    "Null": {"aws:TagKeys": "false"},
                }
            ),
            "aws:TagKeys",
        )
        assert guard.guards is True

    def test_foranyvalue_is_not_treated_as_vacuous(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {"ForAnyValue:StringEquals": {"aws:TagKeys": "team"}}
            ),
            "aws:TagKeys",
        )
        assert guard.guards is True

    def test_negated_operator_alone_does_not_guard(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringNotEquals": {"provider:sub": "bad"}}),
            "provider:sub",
        )
        assert guard.present is True
        assert guard.guards is False
        assert "negated_operator_only" in [w.code for w in guard.weaknesses]

    def test_bare_wildcard_value_is_flagged_as_vacuous(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringLike": {"provider:sub": "*"}}),
            "provider:sub",
        )
        assert guard.all_values_wildcard is True
        assert "wildcard_only_value" in [w.code for w in guard.weaknesses]

    def test_wildcard_under_exact_operator_is_a_literal(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringEquals": {"provider:sub": "repo:acme/*"}}),
            "provider:sub",
        )
        assert guard.literal_wildcards == ["repo:acme/*"]
        assert "literal_wildcard_in_exact_operator" in [
            w.code for w in guard.weaknesses
        ]
        # It still "guards" - it is just a guard nothing can satisfy.
        assert guard.guards is True

    def test_wildcard_under_stringlike_is_not_flagged_as_literal(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringLike": {"provider:sub": "repo:acme/*"}}),
            "provider:sub",
        )
        assert guard.literal_wildcards == []

    def test_arn_equals_supports_wildcards(self):
        guard = analyze_key(
            ConditionSet.from_raw(
                {"ArnEquals": {"aws:SourceArn": "arn:aws:s3:::bucket/*"}}
            ),
            "aws:SourceArn",
        )
        assert guard.literal_wildcards == []

    def test_null_true_is_flagged_as_the_opposite_of_a_restriction(self):
        guard = analyze_key(
            ConditionSet.from_raw({"Null": {"sts:ExternalId": "true"}}),
            "sts:ExternalId",
        )
        assert "null_requires_absent" in [w.code for w in guard.weaknesses]

    def test_unreadable_value_does_not_guard(self):
        guard = analyze_key(
            ConditionSet.from_raw({"StringEquals": {"k": {"nested": 1}}}), "k"
        )
        assert guard.guards is False
        assert "unreadable_condition_value" in [w.code for w in guard.weaknesses]


class TestPinnedSegments:
    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("system:serviceaccount:payments:api", 4),
            ("system:serviceaccount:payments:*", 3),
            ("system:serviceaccount:*:*", 2),
            ("system:*", 1),
            ("*", 0),
            ("", 0),
        ],
    )
    def test_counts_only_fully_pinned_segments(self, pattern, expected):
        assert pinned_segments(pattern, ":") == expected
