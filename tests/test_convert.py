"""Conversion tests for get-account-authorization-details input."""

from __future__ import annotations

from trustedge.convert import (
    SUPPLEMENTARY_KEYS,
    from_authorization_details,
    merge_supplementary,
)
from trustedge.parser import load_json_file, parse_export


def codes(issues):
    return [i.code for i in issues]


class TestConversion:
    def test_roles_are_converted(self, authorization_details_path):
        document = load_json_file(authorization_details_path)
        export, _ = from_authorization_details(document)
        names = [r["role_name"] for r in export["roles"]]
        assert "gh-deploy-from-authdetails" in names
        assert "lambda-from-authdetails" in names

    def test_trust_policy_is_carried_over(self, authorization_details_path):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        role = next(
            r for r in export["roles"] if r["role_name"] == "gh-deploy-from-authdetails"
        )
        assert role["assume_role_policy_document"]["Statement"][0]["Effect"] == "Allow"

    def test_inline_and_attached_policies_are_mapped(
        self, authorization_details_path
    ):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        role = next(
            r for r in export["roles"] if r["role_name"] == "gh-deploy-from-authdetails"
        )
        assert role["inline_policies"][0]["policy_name"] == "inline-pass-role"
        assert (
            role["attached_managed_policies"][0]["policy_arn"]
            == "arn:aws:iam::111122223333:policy/SyntheticAdmin"
        )

    def test_the_default_policy_version_is_chosen(self, authorization_details_path):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        policy = export["managed_policies"][0]
        assert policy["default_version_id"] == "v2"
        # v2 is the admin version; picking v1 would understate blast radius.
        assert policy["policy_document"]["Statement"][0]["Action"] == "*"

    def test_permissions_boundary_is_carried_over(self, authorization_details_path):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        role = next(
            r for r in export["roles"] if r["role_name"] == "lambda-from-authdetails"
        )
        assert role["permissions_boundary_arn"].endswith("DeveloperBoundary")

    def test_tags_are_carried_over(self, authorization_details_path):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        role = next(
            r for r in export["roles"] if r["role_name"] == "gh-deploy-from-authdetails"
        )
        assert role["tags"]["owner"] == "platform"

    def test_account_id_is_inferred_from_role_arns(self, authorization_details_path):
        export, _ = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        assert export["account_id"] == "111122223333"

    def test_the_missing_provider_context_is_always_disclosed(
        self, authorization_details_path
    ):
        _, issues = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        assert "authorization_details_lacks_providers" in codes(issues)

    def test_the_result_is_analysable(self, authorization_details_path):
        export, issues = from_authorization_details(
            load_json_file(authorization_details_path)
        )
        parsed, more = parse_export(export)
        assert len(parsed.roles) == 2
        assert parsed.account_id == "111122223333"


class TestConversionRobustness:
    def test_no_role_detail_list_is_an_error(self):
        export, issues = from_authorization_details({"UserDetailList": []})
        assert export["roles"] == []
        assert "no_role_detail_list" in codes(issues)

    def test_role_detail_list_of_the_wrong_type(self):
        export, issues = from_authorization_details({"RoleDetailList": {}})
        assert export["roles"] == []
        assert "role_detail_list_malformed" in codes(issues)

    def test_non_object_role_entries_are_skipped(self):
        export, issues = from_authorization_details(
            {"RoleDetailList": ["nope", {"RoleName": "ok", "Arn": "arn:aws:iam::111122223333:role/ok"}]}
        )
        assert len(export["roles"]) == 1
        assert "role_detail_malformed" in codes(issues)

    def test_policy_without_an_arn_is_skipped(self):
        export, issues = from_authorization_details(
            {
                "RoleDetailList": [],
                "Policies": [{"PolicyName": "NoArn", "PolicyVersionList": []}],
            }
        )
        assert export["managed_policies"] == []
        assert "policy_arn_missing" in codes(issues)

    def test_policy_without_versions_is_skipped_with_an_explanation(self):
        export, issues = from_authorization_details(
            {
                "RoleDetailList": [],
                "Policies": [
                    {
                        "PolicyName": "NoVersions",
                        "Arn": "arn:aws:iam::111122223333:policy/NoVersions",
                        "PolicyVersionList": [],
                    }
                ],
            }
        )
        assert export["managed_policies"] == []
        assert "policy_no_versions" in codes(issues)

    def test_policy_with_no_marked_default_falls_back_and_warns(self):
        export, issues = from_authorization_details(
            {
                "RoleDetailList": [],
                "Policies": [
                    {
                        "PolicyName": "Unclear",
                        "Arn": "arn:aws:iam::111122223333:policy/Unclear",
                        "PolicyVersionList": [
                            {
                                "VersionId": "v9",
                                "Document": {
                                    "Version": "2012-10-17",
                                    "Statement": [],
                                },
                            }
                        ],
                    }
                ],
            }
        )
        assert export["managed_policies"][0]["default_version_id"] == "v9"
        assert "policy_default_version_unclear" in codes(issues)

    def test_default_version_id_without_is_default_flag_is_honoured(self):
        export, _ = from_authorization_details(
            {
                "RoleDetailList": [],
                "Policies": [
                    {
                        "PolicyName": "ByIdOnly",
                        "Arn": "arn:aws:iam::111122223333:policy/ByIdOnly",
                        "DefaultVersionId": "v2",
                        "PolicyVersionList": [
                            {"VersionId": "v1", "Document": {"Statement": []}},
                            {
                                "VersionId": "v2",
                                "Document": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "*",
                                            "Resource": "*",
                                        }
                                    ]
                                },
                            },
                        ],
                    }
                ],
            }
        )
        policy = export["managed_policies"][0]
        assert policy["default_version_id"] == "v2"
        assert policy["policy_document"]["Statement"][0]["Action"] == "*"

    def test_uninferable_account_id_is_reported(self):
        export, issues = from_authorization_details(
            {
                "RoleDetailList": [
                    {"RoleName": "a", "Arn": "arn:aws:iam::111122223333:role/a"},
                    {"RoleName": "b", "Arn": "arn:aws:iam::999988887777:role/b"},
                ]
            }
        )
        assert "account_id" not in export
        assert "account_id_not_inferable" in codes(issues)


class TestSupplementaryMerge:
    def test_supported_keys_are_merged(self):
        export = {"roles": []}
        merged, issues = merge_supplementary(
            export, {"organization_id": "o-x", "trusted_account_ids": ["1"]}
        )
        assert merged["organization_id"] == "o-x"
        assert merged["trusted_account_ids"] == ["1"]
        assert issues == []

    def test_unsupported_keys_are_ignored_with_a_warning(self):
        merged, issues = merge_supplementary({"roles": []}, {"nonsense": 1})
        assert "nonsense" not in merged
        assert "supplement_key_ignored" in codes(issues)

    def test_non_object_supplement_is_an_error(self):
        merged, issues = merge_supplementary({"roles": []}, ["a", "list"])
        assert merged == {"roles": []}
        assert "supplement_malformed" in codes(issues)

    def test_the_supported_key_list_covers_what_aws_cannot_give_us(self):
        for key in (
            "oidc_providers",
            "saml_providers",
            "vendor_accounts",
            "organization_id",
            "trusted_account_ids",
        ):
            assert key in SUPPLEMENTARY_KEYS

    def test_a_supplemented_export_grades_with_more_context(
        self, authorization_details_path
    ):
        from trustedge import analyzer

        raw = load_json_file(authorization_details_path)
        export, _ = from_authorization_details(raw)
        without, _ = parse_export(dict(export))
        result_without = analyzer.analyze(without)

        supplemented, _ = merge_supplementary(
            dict(export),
            {
                "oidc_providers": [
                    {
                        "arn": "arn:aws:iam::111122223333:oidc-provider/"
                        "token.actions.githubusercontent.com",
                        "url": "token.actions.githubusercontent.com",
                    }
                ]
            },
        )
        with_context, _ = parse_export(supplemented)
        result_with = analyzer.analyze(with_context)

        assert len(with_context.oidc_providers) == 1
        assert len(without.oidc_providers) == 0
        # Both still produce findings; the supplement adds context, it does not
        # change the trust policy semantics.
        assert result_without.findings
        assert result_with.findings
