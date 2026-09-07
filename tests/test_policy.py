"""Tests for the IAM policy primitives everything else rests on."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from trustedge.policy import (
    account_id_from_principal,
    action_matches,
    as_list,
    as_str_list,
    coerce_policy_document,
    glob_match,
    has_wildcard,
    is_pure_wildcard,
    literal_prefix,
    normalize_issuer,
    oidc_provider_url_from_arn,
    parse_arn,
    policy_statements,
    principal_is_account_root,
    saml_provider_name_from_arn,
)


class TestGlobMatch:
    @pytest.mark.parametrize(
        "pattern,value",
        [
            ("*", "anything"),
            ("s3:*", "s3:GetObject"),
            ("iam:Get*", "iam:GetRole"),
            ("repo:acme/*", "repo:acme/app:ref:refs/heads/main"),
            ("a?c", "abc"),
            ("", ""),
        ],
    )
    def test_matches(self, pattern, value):
        assert glob_match(pattern, value)

    @pytest.mark.parametrize(
        "pattern,value",
        [
            ("s3:*", "sqs:SendMessage"),
            ("iam:Get*", "iam:PutRolePolicy"),
            ("a?c", "abbc"),
            ("exact", "exacts"),
            ("repo:acme/app", "repo:acme/app:ref:refs/heads/main"),
        ],
    )
    def test_does_not_match(self, pattern, value):
        assert not glob_match(pattern, value)

    def test_square_brackets_are_literal_not_a_character_class(self):
        # fnmatch would treat [ab] as a character class. IAM does not, so a
        # literal bracket in a policy value must be matched literally.
        assert glob_match("prefix[ab]", "prefix[ab]")
        assert not glob_match("prefix[ab]", "prefixa")

    def test_case_sensitivity_is_selectable(self):
        assert not glob_match("s3:GetObject", "s3:getobject")
        assert glob_match("s3:GetObject", "s3:getobject", case_sensitive=False)

    def test_non_strings_do_not_raise(self):
        assert not glob_match(None, "x")
        assert not glob_match("x", None)


class TestActionMatches:
    def test_action_matching_is_case_insensitive(self):
        assert action_matches("IAM:passrole", "iam:PassRole")
        assert action_matches("iam:*", "IAM:PassRole")

    def test_wildcard_covers_everything(self):
        assert action_matches("*", "iam:PassRole")

    def test_different_service_does_not_match(self):
        assert not action_matches("iam:*", "sts:AssumeRole")

    def test_whitespace_is_tolerated(self):
        assert action_matches("  iam:PassRole  ", "iam:PassRole")


class TestWildcardHelpers:
    @pytest.mark.parametrize("value", ["*", "?", "**", "  *  ", "", None])
    def test_pure_wildcards(self, value):
        assert is_pure_wildcard(value)

    @pytest.mark.parametrize("value", ["repo:acme/*", "a", "*a*"])
    def test_not_pure_wildcards(self, value):
        assert not is_pure_wildcard(value)

    def test_has_wildcard(self):
        assert has_wildcard("repo:acme/*")
        assert has_wildcard("a?b")
        assert not has_wildcard("plain")
        assert not has_wildcard(None)

    def test_literal_prefix(self):
        assert literal_prefix("repo:acme/*") == "repo:acme/"
        assert literal_prefix("no-wildcard") == "no-wildcard"
        assert literal_prefix("*leading") == ""


class TestAsList:
    def test_string_becomes_single_item_list(self):
        assert as_list("a") == ["a"]

    def test_none_becomes_empty_list(self):
        assert as_list(None) == []

    def test_list_passes_through(self):
        assert as_list(["a", "b"]) == ["a", "b"]

    def test_as_str_list_coerces_scalars_but_drops_objects(self):
        assert as_str_list(["a", 1, True, {"k": "v"}, None]) == ["a", "1", "true"]

    def test_as_str_list_of_nested_object_is_empty(self):
        assert as_str_list({"nested": "object"}) == []


class TestCoercePolicyDocument:
    def test_dict_passes_through(self):
        document, error = coerce_policy_document({"Version": "2012-10-17"})
        assert error is None
        assert document == {"Version": "2012-10-17"}

    def test_json_string(self):
        document, error = coerce_policy_document('{"Version": "2012-10-17"}')
        assert error is None
        assert document["Version"] == "2012-10-17"

    def test_url_encoded_json_string(self):
        original = {"Version": "2012-10-17", "Statement": []}
        encoded = urllib.parse.quote(json.dumps(original))
        document, error = coerce_policy_document(encoded)
        assert error is None
        assert document == original

    @pytest.mark.parametrize(
        "value", [None, "", "   ", "{not json", 42, ["a"], '"just a string"', "[]"]
    )
    def test_bad_inputs_return_an_error_not_an_exception(self, value):
        document, error = coerce_policy_document(value)
        assert document is None
        assert error


class TestPolicyStatements:
    def test_single_statement_object_is_accepted(self):
        statements, problems = policy_statements(
            {"Statement": {"Effect": "Allow", "Action": "*"}}
        )
        assert len(statements) == 1
        assert problems == []

    def test_list_of_statements(self):
        statements, problems = policy_statements({"Statement": [{"a": 1}, {"b": 2}]})
        assert len(statements) == 2
        assert problems == []

    def test_non_object_members_are_reported_not_raised(self):
        statements, problems = policy_statements(
            {"Statement": [{"good": True}, "bad", 42]}
        )
        assert len(statements) == 1
        assert len(problems) == 2

    def test_missing_statement_is_reported(self):
        statements, problems = policy_statements({"Version": "2012-10-17"})
        assert statements == []
        assert problems

    def test_empty_statement_list_is_reported(self):
        statements, problems = policy_statements({"Statement": []})
        assert statements == []
        assert problems

    def test_non_dict_document_is_reported(self):
        statements, problems = policy_statements("not a document")
        assert statements == []
        assert problems


class TestArnParsing:
    def test_parse_arn_splits_six_components(self):
        arn = parse_arn("arn:aws:iam::111122223333:role/path/to/MyRole")
        assert arn == {
            "partition": "aws",
            "service": "iam",
            "region": "",
            "account": "111122223333",
            "resource": "role/path/to/MyRole",
        }

    @pytest.mark.parametrize("value", ["not-an-arn", "arn:aws:iam", "", None])
    def test_non_arns_return_none(self, value):
        assert parse_arn(value) is None

    @pytest.mark.parametrize(
        "value",
        [
            "111122223333",
            "arn:aws:iam::111122223333:root",
            "arn:aws:iam::111122223333:role/Thing",
            "arn:aws:sts::111122223333:assumed-role/Thing/session",
        ],
    )
    def test_account_id_extraction(self, value):
        assert account_id_from_principal(value) == "111122223333"

    @pytest.mark.parametrize("value", ["*", "arn:aws:iam::*:role/Thing", "nonsense"])
    def test_account_id_absent(self, value):
        assert account_id_from_principal(value) is None

    def test_account_root_detection(self):
        assert principal_is_account_root("111122223333")
        assert principal_is_account_root("arn:aws:iam::111122223333:root")
        assert not principal_is_account_root("arn:aws:iam::111122223333:role/Thing")
        assert not principal_is_account_root("*")

    def test_oidc_provider_url_extraction(self):
        assert (
            oidc_provider_url_from_arn(
                "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
            )
            == "token.actions.githubusercontent.com"
        )
        assert oidc_provider_url_from_arn("arn:aws:iam::111122223333:root") is None

    def test_oidc_provider_url_keeps_path_segments(self):
        arn = (
            "arn:aws:iam::111122223333:oidc-provider/"
            "oidc.eks.us-east-1.amazonaws.com/id/ABC123"
        )
        assert (
            oidc_provider_url_from_arn(arn)
            == "oidc.eks.us-east-1.amazonaws.com/id/ABC123"
        )

    def test_saml_provider_name_extraction(self):
        assert (
            saml_provider_name_from_arn(
                "arn:aws:iam::111122223333:saml-provider/CorpDirectory"
            )
            == "CorpDirectory"
        )
        assert saml_provider_name_from_arn("arn:aws:iam::111122223333:root") is None


class TestNormalizeIssuer:
    @pytest.mark.parametrize(
        "value",
        ["https://gitlab.com", "http://gitlab.com/", "gitlab.com", "gitlab.com/"],
    )
    def test_scheme_and_trailing_slash_are_stripped(self, value):
        assert normalize_issuer(value) == "gitlab.com"

    def test_non_string_is_empty(self):
        assert normalize_issuer(None) == ""
