"""Blast radius resolution tests.

Two things matter most here: that the documented escalation primitives are
actually detected, and that resource scope is honoured - ``iam:PassRole`` on
one named role must not rank alongside ``iam:PassRole`` on ``*``.
"""

from __future__ import annotations

import pytest

from conftest import ACCOUNT, capability_codes, only_finding, cross_account_statement
from trustedge.blast_radius import (
    COMPUTE_CREATE_CODES,
    ESCALATION_PROBES,
    resolve,
)
from trustedge.models import BlastRadiusTier, Role
from trustedge.parser import parse_export

STATEMENT = cross_account_statement()


def inline(actions, resource="*", effect="Allow", condition=None, name="p"):
    statement = {"Effect": effect, "Action": actions, "Resource": resource}
    if condition is not None:
        statement["Condition"] = condition
    return [
        {
            "policy_name": name,
            "policy_document": {"Version": "2012-10-17", "Statement": [statement]},
        }
    ]


def radius_for(inline_policies, **kwargs):
    finding = only_finding([STATEMENT], inline_policies=inline_policies, **kwargs)
    return finding.blast_radius


class TestAdminDetection:
    def test_star_on_star_is_admin(self):
        radius = radius_for(inline("*"))
        assert radius.tier == BlastRadiusTier.ADMIN
        assert radius.admin_equivalent is True

    def test_star_on_a_specific_resource_is_not_admin(self):
        radius = radius_for(inline("*", resource="arn:aws:s3:::bucket/*"))
        assert radius.tier != BlastRadiusTier.ADMIN

    def test_iam_wildcard_is_admin_equivalent(self):
        radius = radius_for(inline("iam:*"))
        assert radius.admin_equivalent is True
        assert "admin_via_iam_control" in capability_codes(
            only_finding([STATEMENT], inline_policies=inline("iam:*"))
        )

    def test_not_action_excluding_iam_is_not_admin_equivalent(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert radius.admin_equivalent is False

    def test_not_action_excluding_something_harmless_is_admin_equivalent(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotAction": "s3:DeleteBucket",
                            "Resource": "*",
                        }
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert radius.admin_equivalent is True


class TestEscalationPrimitives:
    @pytest.mark.parametrize(
        "action,code",
        [
            ("iam:PassRole", "iam_pass_role"),
            ("iam:CreatePolicyVersion", "iam_create_policy_version"),
            ("iam:SetDefaultPolicyVersion", "iam_set_default_policy_version"),
            ("iam:AttachRolePolicy", "iam_attach_role_policy"),
            ("iam:PutRolePolicy", "iam_put_role_policy"),
            ("iam:UpdateAssumeRolePolicy", "iam_update_assume_role_policy"),
            ("iam:CreateAccessKey", "iam_create_access_key"),
            ("iam:CreateLoginProfile", "iam_create_login_profile"),
            ("iam:AddUserToGroup", "iam_add_user_to_group"),
            ("sts:AssumeRole", "sts_assume_role"),
            ("sts:GetFederationToken", "sts_get_federation_token"),
            ("kms:PutKeyPolicy", "kms_put_key_policy"),
            ("s3:PutBucketPolicy", "s3_put_bucket_policy"),
            ("lambda:UpdateFunctionCode", "lambda_update_function_code"),
            ("ssm:SendCommand", "ssm_send_command"),
        ],
    )
    def test_each_documented_primitive_is_detected(self, action, code):
        finding = only_finding([STATEMENT], inline_policies=inline(action))
        assert code in capability_codes(finding)

    def test_a_service_wildcard_also_matches_the_primitive(self):
        finding = only_finding([STATEMENT], inline_policies=inline("iam:Pass*"))
        assert "iam_pass_role" in capability_codes(finding)

    def test_passrole_alone_is_moderate(self):
        radius = radius_for(inline("iam:PassRole"))
        assert radius.tier == BlastRadiusTier.MODERATE

    def test_passrole_plus_compute_creation_is_high(self):
        radius = radius_for(inline(["iam:PassRole", "lambda:CreateFunction"]))
        assert radius.tier == BlastRadiusTier.HIGH
        codes = [c.code for c in radius.capabilities]
        assert "passrole_plus_compute" in codes

    @pytest.mark.parametrize(
        "compute_action",
        [
            "lambda:CreateFunction",
            "ec2:RunInstances",
            "cloudformation:CreateStack",
            "codebuild:CreateProject",
            "ecs:RegisterTaskDefinition",
            "glue:CreateDevEndpoint",
            "sagemaker:CreateNotebookInstance",
            "datapipeline:CreatePipeline",
            "ssm:SendCommand",
        ],
    )
    def test_every_compute_creator_combines_with_passrole(self, compute_action):
        radius = radius_for(inline(["iam:PassRole", compute_action]))
        assert "passrole_plus_compute" in [c.code for c in radius.capabilities]

    def test_compute_create_codes_match_the_probe_table(self):
        probe_codes = {p.code for p in ESCALATION_PROBES}
        assert COMPUTE_CREATE_CODES <= probe_codes

    def test_create_role_plus_attach_is_flagged_as_a_combination(self):
        radius = radius_for(inline(["iam:CreateRole", "iam:AttachRolePolicy"]))
        assert "create_role_plus_policy" in [c.code for c in radius.capabilities]

    def test_sts_assume_role_chain_is_recorded(self):
        radius = radius_for(
            inline("sts:AssumeRole", resource="arn:aws:iam::*:role/*")
        )
        codes = [c.code for c in radius.capabilities]
        assert "sts_assume_role" in codes
        assert "role chain" in " ".join(c.detail for c in radius.capabilities)


class TestResourceScoping:
    def test_high_weight_primitive_on_a_named_resource_is_downgraded(self):
        broad = radius_for(inline("iam:AttachRolePolicy", resource="*"))
        narrow = radius_for(
            inline(
                "iam:AttachRolePolicy",
                resource="arn:aws:iam::%s:role/AppRole" % ACCOUNT,
            )
        )
        assert broad.tier == BlastRadiusTier.HIGH
        assert narrow.tier == BlastRadiusTier.MODERATE

    def test_resource_scoping_is_explained(self):
        narrow = radius_for(
            inline(
                "iam:AttachRolePolicy",
                resource="arn:aws:iam::%s:role/AppRole" % ACCOUNT,
            )
        )
        assert "Resource-scoped rather than account-wide" in " ".join(
            narrow.reasoning
        )

    def test_missing_resource_element_is_read_as_broad(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "iam:AttachRolePolicy"}
                    ],
                },
            }
        ]
        assert radius_for(policies).tier == BlastRadiusTier.HIGH

    def test_not_resource_is_read_as_broad(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:AttachRolePolicy",
                            "NotResource": "arn:aws:iam::111122223333:role/Protected",
                        }
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert radius.tier == BlastRadiusTier.HIGH
        # ...and the approximation must be disclosed rather than assumed.
        assert any("NotResource" in item for item in radius.limitations)


class TestDataPlane:
    @pytest.mark.parametrize(
        "action,code",
        [
            ("secretsmanager:GetSecretValue", "secrets_read"),
            ("kms:Decrypt", "kms_decrypt"),
            ("s3:GetObject", "s3_read"),
            ("s3:PutObject", "s3_write"),
            ("dynamodb:Scan", "dynamodb_read"),
            ("rds-data:ExecuteStatement", "rds_data_execute"),
            ("ec2:ModifySnapshotAttribute", "ec2_snapshot_share"),
            ("ses:SendEmail", "ses_send"),
        ],
    )
    def test_data_plane_capabilities_are_detected(self, action, code):
        finding = only_finding([STATEMENT], inline_policies=inline(action))
        assert code in capability_codes(finding)

    def test_broad_secret_read_is_high(self):
        assert (
            radius_for(inline("secretsmanager:GetSecretValue")).tier
            == BlastRadiusTier.HIGH
        )

    def test_scoped_secret_read_is_moderate(self):
        radius = radius_for(
            inline(
                "secretsmanager:GetSecretValue",
                resource="arn:aws:secretsmanager:us-east-1:111122223333:secret:app/*",
            )
        )
        assert radius.tier == BlastRadiusTier.MODERATE

    def test_service_wildcard_is_recorded_separately(self):
        radius = radius_for(inline("s3:*"))
        codes = [c.code for c in radius.capabilities]
        assert "service_wildcard_s3" in codes
        assert radius.tier == BlastRadiusTier.HIGH

    def test_read_only_permissions_are_low(self):
        radius = radius_for(inline(["ec2:DescribeInstances", "iam:ListRoles"]))
        assert radius.tier == BlastRadiusTier.LOW


class TestDenyHandling:
    def test_unconditional_broad_deny_suppresses_a_capability(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Deny",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "*",
                        },
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert "iam_attach_role_policy" not in [c.code for c in radius.capabilities]
        assert radius.deny_statements_seen == 1

    def test_conditional_deny_is_recorded_but_not_applied(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Deny",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "*",
                            "Condition": {
                                "StringNotEquals": {"aws:RequestedRegion": "us-east-1"}
                            },
                        },
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert "iam_attach_role_policy" in [c.code for c in radius.capabilities]
        assert any("not evaluated" in item for item in radius.limitations)

    def test_resource_scoped_deny_is_not_applied(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Deny",
                            "Action": "iam:AttachRolePolicy",
                            "Resource": "arn:aws:iam::111122223333:role/Protected",
                        },
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert "iam_attach_role_policy" in [c.code for c in radius.capabilities]

    def test_broad_star_deny_suppresses_everything_it_covers(self):
        policies = [
            {
                "policy_name": "p",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    ],
                },
            }
        ]
        radius = radius_for(policies)
        assert radius.admin_equivalent is False


class TestUnknownAndEmpty:
    def test_no_policies_is_low_not_unknown(self):
        radius = radius_for([])
        assert radius.tier == BlastRadiusTier.LOW
        assert "no permissions" in " ".join(radius.reasoning)

    def test_unresolved_attached_policy_is_unknown_not_low(self):
        finding = only_finding(
            [STATEMENT],
            attached=[{"policy_arn": "arn:aws:iam::111122223333:policy/Absent"}],
        )
        assert finding.blast_radius.tier == BlastRadiusTier.UNKNOWN
        assert finding.blast_radius.unresolved_policies

    def test_partially_unresolved_is_reported_as_a_lower_bound(self):
        finding = only_finding(
            [STATEMENT],
            inline_policies=inline("s3:GetObject"),
            attached=[{"policy_arn": "arn:aws:iam::111122223333:policy/Absent"}],
        )
        assert "lower bound" in " ".join(finding.blast_radius.reasoning)

    def test_unreadable_policy_document_does_not_crash_resolution(self):
        export, _ = parse_export(
            {
                "account_id": ACCOUNT,
                "roles": [
                    {
                        "role_name": "r",
                        "arn": "arn:aws:iam::%s:role/r" % ACCOUNT,
                        "assume_role_policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [STATEMENT],
                        },
                        "inline_policies": {"bad": 12345},
                    }
                ],
            }
        )
        radius = resolve(export.roles[0], export)
        assert radius.tier == BlastRadiusTier.UNKNOWN

    def test_policy_document_without_statements_is_reported(self):
        policies = [
            {
                "policy_name": "empty",
                "policy_document": {"Version": "2012-10-17", "Statement": []},
            }
        ]
        radius = radius_for(policies)
        assert any("its permissions are not counted" in item for item in radius.limitations)


class TestStandardLimitations:
    def test_boundaries_and_scps_are_always_disclaimed(self):
        radius = radius_for(inline("*"))
        joined = " ".join(radius.limitations)
        assert "permissions boundaries" in joined
        assert "service control policies" in joined
        assert "Resource-based policies in other accounts" in joined

    def test_a_permissions_boundary_is_called_out(self):
        export, _ = parse_export(
            {
                "account_id": ACCOUNT,
                "roles": [
                    {
                        "role_name": "r",
                        "arn": "arn:aws:iam::%s:role/r" % ACCOUNT,
                        "assume_role_policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [STATEMENT],
                        },
                        "permissions_boundary_arn": "arn:aws:iam::%s:policy/B"
                        % ACCOUNT,
                        "inline_policies": inline("*"),
                    }
                ],
            }
        )
        radius = resolve(export.roles[0], export)
        assert radius.has_permissions_boundary is True
        assert any("permissions boundary (" in item for item in radius.limitations)

    def test_resolve_accepts_a_role_with_no_export(self):
        # The signature must stay usable standalone for library consumers.
        radius = resolve(Role(role_name="bare"))
        assert radius.tier == BlastRadiusTier.LOW
