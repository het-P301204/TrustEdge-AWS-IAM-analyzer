"""Input validation tests.

The contract being tested: a malformed *part* of an export produces an issue
and everything else still gets analysed. Only an input that is not an IAM
export at all is allowed to raise.
"""

from __future__ import annotations

import json
import os

import pytest

from trustedge.parser import (
    ExportFormatError,
    load_json_file,
    looks_like_authorization_details,
    parse_export,
)


def codes(issues):
    return [i.code for i in issues]


class TestHardFailures:
    @pytest.mark.parametrize("document", [None, [], "a string", 42, True])
    def test_non_object_documents_raise(self, document):
        with pytest.raises(ExportFormatError):
            parse_export(document)

    def test_missing_roles_key_is_an_error_not_an_exception(self):
        export, issues = parse_export({"account_id": "111122223333"})
        assert export.roles == []
        assert "no_roles_key" in codes(issues)

    def test_roles_not_a_list_is_an_error(self):
        export, issues = parse_export({"roles": {"not": "a list"}})
        assert export.roles == []
        assert "roles_not_a_list" in codes(issues)


class TestFileLoading:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ExportFormatError):
            load_json_file(str(tmp_path / "nope.json"))

    def test_directory_instead_of_file(self, tmp_path):
        with pytest.raises(ExportFormatError):
            load_json_file(str(tmp_path))

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("", encoding="utf-8")
        with pytest.raises(ExportFormatError):
            load_json_file(str(path))

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ExportFormatError) as excinfo:
            load_json_file(str(path))
        assert "not valid JSON" in str(excinfo.value)

    def test_valid_json_loads(self, tmp_path):
        path = tmp_path / "ok.json"
        path.write_text('{"roles": []}', encoding="utf-8")
        assert load_json_file(str(path)) == {"roles": []}


class TestRoleParsing:
    def test_role_name_inferred_from_arn(self):
        export, _ = parse_export(
            {
                "account_id": "111122223333",
                "roles": [
                    {
                        "arn": "arn:aws:iam::111122223333:role/inferred-name",
                        "assume_role_policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    }
                ],
            }
        )
        assert export.roles[0].role_name == "inferred-name"

    def test_role_with_neither_name_nor_arn_is_skipped_with_an_error(self):
        export, issues = parse_export({"account_id": "111122223333", "roles": [{}]})
        assert export.roles == []
        assert "role_name_missing" in codes(issues)

    def test_non_object_role_is_skipped_with_an_error(self):
        export, issues = parse_export(
            {"account_id": "111122223333", "roles": ["a string"]}
        )
        assert export.roles == []
        assert "role_not_an_object" in codes(issues)

    def test_pascal_case_keys_are_accepted(self):
        export, _ = parse_export(
            {
                "AccountId": "111122223333",
                "Roles": [
                    {
                        "RoleName": "pascal",
                        "Arn": "arn:aws:iam::111122223333:role/pascal",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    }
                ],
            }
        )
        assert export.account_id == "111122223333"
        assert export.roles[0].role_name == "pascal"

    def test_account_id_inferred_from_role_arns(self):
        export, issues = parse_export(
            {
                "roles": [
                    {
                        "role_name": "r",
                        "arn": "arn:aws:iam::111122223333:role/r",
                        "assume_role_policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    }
                ]
            }
        )
        assert export.account_id == "111122223333"
        assert "account_id_inferred" in codes(issues)

    def test_account_id_absent_and_uninferable_is_an_error(self):
        export, issues = parse_export({"roles": [{"role_name": "r"}]})
        assert export.account_id is None
        assert "account_id_missing" in codes(issues)

    def test_malformed_account_id_is_ignored_with_a_warning(self):
        export, issues = parse_export({"account_id": "nope", "roles": []})
        assert export.account_id is None
        assert "account_id_malformed" in codes(issues)

    def test_duplicate_role_names_are_reported(self):
        role = {
            "role_name": "dup",
            "arn": "arn:aws:iam::111122223333:role/dup",
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        }
        export, issues = parse_export(
            {"account_id": "111122223333", "roles": [role, dict(role)]}
        )
        assert len(export.roles) == 2
        assert "duplicate_role_name" in codes(issues)


class TestTrustPolicyParsing:
    def _one_role(self, trust_policy):
        return {
            "account_id": "111122223333",
            "roles": [
                {
                    "role_name": "r",
                    "arn": "arn:aws:iam::111122223333:role/r",
                    "assume_role_policy_document": trust_policy,
                }
            ],
        }

    def test_missing_trust_policy_is_an_error_and_marks_the_role_unusable(self):
        export, issues = parse_export(
            {
                "account_id": "111122223333",
                "roles": [{"role_name": "r", "arn": "arn:aws:iam::111122223333:role/r"}],
            }
        )
        assert export.roles[0].trust_policy_unusable is True
        assert "trust_policy_unreadable" in codes(issues)

    def test_url_encoded_trust_policy_is_decoded(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        import urllib.parse

        encoded = urllib.parse.quote(json.dumps(document))
        export, issues = parse_export(self._one_role(encoded))
        assert len(export.roles[0].trust_statements) == 1
        assert "trust_policy_unreadable" not in codes(issues)

    def test_single_statement_object(self):
        export, _ = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    },
                }
            )
        )
        assert len(export.roles[0].trust_statements) == 1

    def test_one_bad_statement_does_not_lose_the_good_ones(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        "a string",
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        },
                    ],
                }
            )
        )
        assert len(export.roles[0].trust_statements) == 1
        assert "trust_statement_problem" in codes(issues)

    def test_invalid_effect_is_read_conservatively_as_allow(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Permit",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
        )
        assert export.roles[0].trust_statements[0].effect == "Allow"
        assert "statement_effect_invalid" in codes(issues)

    def test_deny_effect_is_preserved(self):
        export, _ = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
        )
        assert export.roles[0].trust_statements[0].effect == "Deny"

    def test_non_object_condition_is_dropped_with_a_warning(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                            "Condition": "sts:ExternalId=x",
                        }
                    ],
                }
            )
        )
        assert export.roles[0].trust_statements[0].condition == {}
        assert "condition_not_an_object" in codes(issues)

    def test_not_principal_is_recorded_and_warned_about(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
        )
        assert export.roles[0].trust_statements[0].has_not_principal is True
        assert "not_principal_unsupported" in codes(issues)

    def test_not_action_is_warned_about(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "NotAction": "sts:TagSession",
                        }
                    ],
                }
            )
        )
        assert "not_action_unsupported" in codes(issues)

    def test_unexpected_policy_version_is_warned_about(self):
        export, issues = parse_export(
            self._one_role(
                {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
        )
        assert "unexpected_policy_version" in codes(issues)


class TestPermissionPolicyParsing:
    def _role_with(self, **kwargs):
        role = {
            "role_name": "r",
            "arn": "arn:aws:iam::111122223333:role/r",
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        }
        role.update(kwargs)
        return {"account_id": "111122223333", "roles": [role]}

    def test_inline_policies_as_a_list(self):
        export, _ = parse_export(
            self._role_with(
                inline_policies=[
                    {
                        "policy_name": "p",
                        "policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ],
                        },
                    }
                ]
            )
        )
        policies = export.roles[0].policies
        assert len(policies) == 1
        assert policies[0].source == "inline"
        assert policies[0].document is not None

    def test_inline_policies_as_a_map(self):
        export, _ = parse_export(
            self._role_with(
                inline_policies={
                    "p": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    }
                }
            )
        )
        assert export.roles[0].policies[0].name == "p"

    def test_unreadable_inline_policy_is_marked_unresolved(self):
        export, issues = parse_export(
            self._role_with(inline_policies={"p": 12345})
        )
        assert export.roles[0].policies[0].unresolved is True
        assert "inline_policy_unreadable" in codes(issues)

    def test_attached_policy_document_resolved_from_the_library(self):
        document = {
            "account_id": "111122223333",
            "managed_policies": [
                {
                    "policy_arn": "arn:aws:iam::111122223333:policy/P",
                    "policy_name": "P",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    },
                }
            ],
            "roles": [
                {
                    "role_name": "r",
                    "arn": "arn:aws:iam::111122223333:role/r",
                    "assume_role_policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "attached_managed_policies": [
                        {"policy_arn": "arn:aws:iam::111122223333:policy/P"}
                    ],
                }
            ],
        }
        export, issues = parse_export(document)
        policy = export.roles[0].policies[0]
        assert policy.unresolved is False
        assert policy.document is not None
        assert "managed_policy_document_missing" not in codes(issues)

    def test_attached_policy_without_a_document_is_unresolved(self):
        export, issues = parse_export(
            self._role_with(
                attached_managed_policies=[
                    {"policy_arn": "arn:aws:iam::111122223333:policy/Absent"}
                ]
            )
        )
        assert export.roles[0].policies[0].unresolved is True
        assert "managed_policy_document_missing" in codes(issues)

    def test_attached_policy_as_a_bare_arn_string(self):
        export, _ = parse_export(
            self._role_with(
                attached_managed_policies=["arn:aws:iam::111122223333:policy/Bare"]
            )
        )
        assert export.roles[0].policies[0].name == "Bare"

    def test_permissions_boundary_object_and_string_forms(self):
        export, _ = parse_export(
            self._role_with(
                permissions_boundary={
                    "PermissionsBoundaryArn": "arn:aws:iam::111122223333:policy/B"
                }
            )
        )
        assert (
            export.roles[0].permissions_boundary_arn
            == "arn:aws:iam::111122223333:policy/B"
        )


class TestProviderAndVendorParsing:
    def test_oidc_provider_url_from_arn_when_url_absent(self):
        export, _ = parse_export(
            {
                "account_id": "111122223333",
                "roles": [],
                "oidc_providers": [
                    {
                        "arn": "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
                    }
                ],
            }
        )
        assert export.oidc_providers[0].url == "gitlab.com"

    def test_oidc_provider_url_is_normalised(self):
        export, _ = parse_export(
            {
                "account_id": "111122223333",
                "roles": [],
                "oidc_providers": [{"url": "https://gitlab.com/"}],
            }
        )
        assert export.oidc_providers[0].url == "gitlab.com"

    def test_malformed_oidc_provider_entry_is_reported(self):
        export, issues = parse_export(
            {"account_id": "111122223333", "roles": [], "oidc_providers": [42]}
        )
        assert export.oidc_providers == []
        assert "oidc_provider_malformed" in codes(issues)

    def test_vendor_map_accepts_shorthand_and_rejects_bad_keys(self):
        export, issues = parse_export(
            {
                "account_id": "111122223333",
                "roles": [],
                "vendor_accounts": {
                    "444455556666": "Example Corp",
                    "not-an-id": {"vendor": "Nope"},
                },
            }
        )
        assert export.vendor_accounts["444455556666"].vendor == "Example Corp"
        assert "not-an-id" not in export.vendor_accounts
        assert "vendor_account_id_invalid" in codes(issues)

    def test_managed_policy_without_an_arn_is_reported(self):
        export, issues = parse_export(
            {
                "account_id": "111122223333",
                "roles": [],
                "managed_policies": [
                    {
                        "policy_name": "NoArn",
                        "policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ],
                        },
                    }
                ],
            }
        )
        assert export.managed_policies == {}
        assert "managed_policy_arn_missing" in codes(issues)


class TestAuthorizationDetailsDetection:
    def test_detects_role_detail_list(self):
        assert looks_like_authorization_details({"RoleDetailList": []})

    def test_does_not_detect_a_native_export(self):
        assert not looks_like_authorization_details({"roles": []})

    def test_non_dict_is_not_detected(self):
        assert not looks_like_authorization_details([1, 2, 3])

    def test_authorization_details_is_converted_transparently(
        self, authorization_details_path
    ):
        document = load_json_file(authorization_details_path)
        export, issues = parse_export(document)
        names = [r.role_name for r in export.roles]
        assert "gh-deploy-from-authdetails" in names
        assert export.account_id == "111122223333"
        assert "authorization_details_lacks_providers" in codes(issues)


class TestMalformedFixture:
    def test_every_readable_role_survives(self, malformed_path):
        export, issues = parse_export(load_json_file(malformed_path))
        names = [r.role_name for r in export.roles]
        # The url-encoded and mixed-statement roles must both come through.
        assert "url-encoded-trust-policy" in names
        assert "mixed-good-and-bad-statements" in names
        # And the unparsable ones must be reported rather than silently dropped.
        assert "role_name_missing" in codes(issues)
        assert "role_not_an_object" in codes(issues)
        assert "trust_policy_unreadable" in codes(issues)

    def test_mixed_statement_role_keeps_the_good_statement(self, malformed_path):
        export, _ = parse_export(load_json_file(malformed_path))
        role = next(
            r for r in export.roles if r.role_name == "mixed-good-and-bad-statements"
        )
        sids = [s.sid for s in role.trust_statements]
        assert "GoodStatement" in sids

    def test_fixture_file_exists_and_is_json(self, malformed_path):
        assert os.path.exists(malformed_path)
        with open(malformed_path, "r", encoding="utf-8") as handle:
            json.load(handle)
