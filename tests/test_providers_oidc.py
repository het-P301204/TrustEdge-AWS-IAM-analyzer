"""OIDC / CI federation rubric tests.

The central claim being tested: the *same* missing condition is graded
differently depending on whether the issuer is shared across AWS customers or
unique to one organisation. That is the difference between a useful tool and a
noise generator, so it gets its own test class at the bottom.
"""

from __future__ import annotations

import pytest

from conftest import (
    EKS_ISSUER,
    EKS_PROVIDER_ARN,
    GITHUB_ISSUER,
    GITHUB_PROVIDER_ARN,
    SECRETS_INLINE,
    analyze_statements,
    github_statement,
    github_sub_condition,
    only_finding,
    weakness_codes,
)
from trustedge.models import ExposureGrade
from trustedge.providers.oidc import (
    Scope,
    classify_issuer,
    issuer_profile,
    parse_github_sub,
)
from trustedge.models import ProviderKind


def github_finding(condition, **kwargs):
    return only_finding([github_statement(condition)], **kwargs)


# --------------------------------------------------------------------------
# Subject parsing
# --------------------------------------------------------------------------


class TestParseGithubSub:
    @pytest.mark.parametrize(
        "pattern,tenant,project,workload",
        [
            ("repo:acme/app:ref:refs/heads/main", True, True, True),
            ("repo:acme/app:environment:production", True, True, True),
            ("repo:acme/app:ref:refs/tags/v1.0.0", True, True, True),
            ("repo:acme/app:*", True, True, False),
            ("repo:acme/app", True, True, False),
            ("repo:acme/app:ref:refs/heads/*", True, True, False),
            ("repo:acme/*", True, False, False),
            ("repo:acme-*/app:*", False, False, False),
            ("repo:*", False, False, False),
            ("*", False, False, False),
            ("", False, False, False),
        ],
    )
    def test_scope_dimensions(self, pattern, tenant, project, workload):
        scope = parse_github_sub(pattern)
        assert (scope.tenant, scope.project, scope.workload) == (
            tenant,
            project,
            workload,
        )

    def test_pull_request_subject_pins_the_repo_but_not_a_workload(self):
        scope = parse_github_sub("repo:acme/app:pull_request")
        assert scope.project is True
        assert scope.workload is False

    def test_org_and_repo_values_are_captured(self):
        scope = parse_github_sub("repo:acme/app:ref:refs/heads/main")
        assert scope.tenant_value == "acme"
        assert scope.project_value == "app"
        assert scope.workload_value == "ref:refs/heads/main"

    def test_custom_subject_template_is_not_guessed_at(self):
        scope = parse_github_sub("custom:acme:deploy")
        assert "custom subject template" in " ".join(scope.sources)

    def test_fully_literal_custom_template_still_counts_as_pinned(self):
        scope = parse_github_sub("custom:acme:deploy")
        assert scope.level == 3

    def test_wildcarded_custom_template_pins_nothing(self):
        scope = parse_github_sub("custom:acme:*")
        assert scope.level == 0


class TestScopeMerge:
    def test_merge_is_a_union_because_conditions_are_anded(self):
        left = Scope()
        left.tenant = True
        right = Scope()
        right.project = True
        left.merge(right)
        assert left.tenant and left.project
        assert left.level == 2


# --------------------------------------------------------------------------
# GitHub Actions grading
# --------------------------------------------------------------------------


class TestGithubGrading:
    def test_repo_and_branch_pinned_is_strong(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/payments-api:ref:refs/heads/main")
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_environment_pinned_is_strong(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/payments-api:environment:production")
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_repo_pinned_without_a_ref_is_moderate(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/infra:*", operator="StringLike")
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "any ref in that repository" in " ".join(finding.exposure.reasoning)

    def test_org_wildcard_is_weak(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/*", operator="StringLike")
        )
        assert finding.exposure.grade == ExposureGrade.WEAK
        assert "any repository in the organisation" in " ".join(
            finding.exposure.reasoning
        )

    def test_no_sub_condition_at_all_is_open(self):
        finding = github_finding(
            {"StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"}}
        )
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "any GitHub organisation" in finding.exposure.who_can_assume

    def test_no_conditions_at_all_is_open(self):
        finding = only_finding([github_statement(None)])
        assert finding.exposure.grade == ExposureGrade.OPEN

    def test_bare_wildcard_sub_is_open(self):
        finding = github_finding(
            github_sub_condition("*", operator="StringLike")
        )
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "wildcard_only_value" in weakness_codes(finding)

    def test_wildcard_inside_the_org_segment_is_open(self):
        finding = github_finding(
            github_sub_condition("repo:acme-*/deploy-tools:*", operator="StringLike")
        )
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "github_sub_org_not_pinned" in weakness_codes(finding)

    def test_missing_sub_produces_a_machine_readable_weakness(self):
        # An OPEN finding with an empty weak_conditions list would be useless
        # to anything consuming the JSON report programmatically.
        finding = github_finding(
            {"StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"}}
        )
        assert "github_tenancy_not_pinned" in weakness_codes(finding)
        assert any(w.vacuous for w in finding.exposure.weak_conditions)

    def test_org_wildcard_does_not_also_report_the_missing_sub_weakness(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/*", operator="StringLike")
        )
        codes = weakness_codes(finding)
        assert "github_tenancy_not_pinned" not in codes

    def test_wildcarded_org_segment_reports_the_sub_specific_weakness(self):
        finding = github_finding(
            github_sub_condition("repo:acme-*/app:*", operator="StringLike")
        )
        codes = weakness_codes(finding)
        assert "github_sub_org_not_pinned" in codes
        assert "github_tenancy_not_pinned" not in codes

    def test_open_grade_cites_the_grandfathering_of_identity_provider_controls(self):
        finding = github_finding(
            {"StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"}}
        )
        joined = " ".join(finding.exposure.reasoning)
        assert "already exist" in joined

    def test_weakest_value_governs_when_several_subjects_are_allowed(self):
        # Values under one operator are OR-ed, so the loosest one decides.
        finding = github_finding(
            github_sub_condition(
                [
                    "repo:acme-corp/app:ref:refs/heads/main",
                    "repo:acme-corp/*",
                ],
                operator="StringLike",
            )
        )
        assert finding.exposure.grade == ExposureGrade.WEAK

    def test_immutable_id_claims_pin_the_scope_without_a_sub_condition(self):
        # AWS's own "use immutable identifiers" example has no sub condition.
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":aud": "sts.amazonaws.com",
                    GITHUB_ISSUER + ":repository_owner_id": "123456",
                    GITHUB_ISSUER + ":repository_id": "1296269",
                    GITHUB_ISSUER + ":ref": "refs/heads/main",
                }
            }
        )
        assert finding.exposure.grade == ExposureGrade.STRONG
        assert "github_mutable_identifiers_only" not in weakness_codes(finding)

    def test_repository_name_claim_pins_the_repository(self):
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":aud": "sts.amazonaws.com",
                    GITHUB_ISSUER + ":repository": "acme-corp/app",
                }
            }
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_repository_wildcard_claim_pins_only_the_org(self):
        finding = github_finding(
            {
                "StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"},
                "StringLike": {GITHUB_ISSUER + ":repository": "acme-corp/*"},
            }
        )
        assert finding.exposure.grade == ExposureGrade.WEAK

    def test_name_only_pinning_is_flagged_as_mutable(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/app:ref:refs/heads/main")
        )
        assert "github_mutable_identifiers_only" in weakness_codes(finding)

    def test_missing_audience_condition_is_noted(self):
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":sub": "repo:acme-corp/app:ref:refs/heads/main"
                }
            }
        )
        assert "oidc_aud_not_pinned" in weakness_codes(finding)
        # It is hygiene, not a hole: the grade must not drop for it.
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_if_exists_on_environment_is_reported_as_vacuous(self):
        finding = github_finding(
            {
                "StringLike": {GITHUB_ISSUER + ":sub": "repo:acme-corp/app:*"},
                "StringEqualsIfExists": {
                    GITHUB_ISSUER + ":environment": "production"
                },
            }
        )
        assert "if_exists_vacuous" in weakness_codes(finding)
        # The vacuous environment condition must not earn a workload pin.
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_if_exists_on_sub_is_only_untidy(self):
        finding = github_finding(
            {
                "StringEqualsIfExists": {
                    GITHUB_ISSUER + ":sub": "repo:acme-corp/app:ref:refs/heads/main"
                }
            }
        )
        codes = weakness_codes(finding)
        assert "if_exists_redundant" in codes
        assert "if_exists_vacuous" not in codes
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_string_equals_with_a_wildcard_is_reported_as_fail_closed(self):
        finding = github_finding(github_sub_condition("repo:acme-corp/*"))
        assert finding.exposure.fail_closed_notes
        assert "literal_wildcard_in_exact_operator" in weakness_codes(finding)

    def test_undocumented_claim_is_flagged_with_a_qualifier(self):
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":aud": "sts.amazonaws.com",
                    GITHUB_ISSUER + ":not_a_real_claim": "x",
                    GITHUB_ISSUER + ":sub": "repo:acme-corp/app:ref:refs/heads/main",
                }
            }
        )
        assert "undocumented_condition_key" in weakness_codes(finding)
        assert any(
            "cannot confirm" in limitation
            for limitation in finding.exposure.limitations
        )

    def test_documented_claims_are_not_flagged_as_undocumented(self):
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":aud": "sts.amazonaws.com",
                    GITHUB_ISSUER + ":job_workflow_ref": (
                        "acme-corp/reusable/.github/workflows/deploy.yml@refs/heads/main"
                    ),
                }
            }
        )
        assert "undocumented_condition_key" not in weakness_codes(finding)

    def test_job_workflow_ref_pins_repository_and_workload(self):
        finding = github_finding(
            {
                "StringEquals": {
                    GITHUB_ISSUER + ":aud": "sts.amazonaws.com",
                    GITHUB_ISSUER + ":job_workflow_ref": (
                        "acme-corp/reusable/.github/workflows/deploy.yml@refs/heads/main"
                    ),
                }
            }
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_recommended_policy_is_offered_only_when_org_and_repo_are_known(self):
        pinned_repo = github_finding(
            github_sub_condition("repo:acme-corp/app:*", operator="StringLike")
        )
        assert pinned_repo.exposure.recommended_policy is not None
        sub = pinned_repo.exposure.recommended_policy["Statement"][0]["Condition"][
            "StringEquals"
        ][GITHUB_ISSUER + ":sub"]
        assert sub.startswith("repo:acme-corp/app:")

    def test_no_policy_is_invented_when_the_org_is_unknown(self):
        open_finding = github_finding(
            {"StringEquals": {GITHUB_ISSUER + ":aud": "sts.amazonaws.com"}}
        )
        assert open_finding.exposure.recommended_policy is None
        assert "does not emit" in open_finding.exposure.recommendation

    def test_rubric_is_recorded_so_the_grade_is_auditable(self):
        finding = github_finding(
            github_sub_condition("repo:acme-corp/app:ref:refs/heads/main")
        )
        assert finding.exposure.rubric == "oidc.github_actions"
        assert finding.exposure.references


# --------------------------------------------------------------------------
# EKS IRSA
# --------------------------------------------------------------------------


def irsa_statement(condition):
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": EKS_PROVIDER_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


class TestIrsaGrading:
    def test_namespace_and_service_account_pinned_is_strong(self):
        finding = only_finding(
            [
                irsa_statement(
                    {
                        "StringEquals": {
                            EKS_ISSUER + ":aud": "sts.amazonaws.com",
                            EKS_ISSUER
                            + ":sub": "system:serviceaccount:payments:payments-api",
                        }
                    }
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_namespace_only_is_not_strong(self):
        finding = only_finding(
            [
                irsa_statement(
                    {
                        "StringLike": {
                            EKS_ISSUER + ":sub": "system:serviceaccount:payments:*"
                        }
                    }
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "any service account in that namespace" in " ".join(
            finding.exposure.reasoning
        )

    def test_cluster_wide_wildcard_is_still_only_moderate(self):
        finding = only_finding(
            [
                irsa_statement(
                    {"StringLike": {EKS_ISSUER + ":sub": "system:serviceaccount:*:*"}}
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "irsa_subject_not_pinned" in weakness_codes(finding)

    def test_missing_subject_is_flagged_but_not_open(self):
        finding = only_finding([irsa_statement(None)])
        assert finding.exposure.grade == ExposureGrade.MODERATE
        assert "irsa_subject_missing" in weakness_codes(finding)

    def test_missing_audience_is_noted(self):
        finding = only_finding(
            [
                irsa_statement(
                    {
                        "StringEquals": {
                            EKS_ISSUER
                            + ":sub": "system:serviceaccount:payments:payments-api"
                        }
                    }
                )
            ]
        )
        assert "irsa_audience_missing" in weakness_codes(finding)

    def test_limitations_mention_cluster_rbac(self):
        finding = only_finding([irsa_statement(None)])
        assert any("RBAC" in item for item in finding.exposure.limitations)


# --------------------------------------------------------------------------
# Registry and issuer classification
# --------------------------------------------------------------------------


class TestIssuerClassification:
    @pytest.mark.parametrize(
        "issuer,kind",
        [
            ("token.actions.githubusercontent.com", ProviderKind.GITHUB_ACTIONS),
            ("gitlab.com", ProviderKind.GITLAB),
            ("https://gitlab.com/", ProviderKind.GITLAB),
            ("app.terraform.io", ProviderKind.TERRAFORM_CLOUD),
            ("cognito-identity.amazonaws.com", ProviderKind.COGNITO),
            ("scalr.io", ProviderKind.SHARED_OIDC),
            ("idp.internal.example.com", ProviderKind.PRIVATE_OIDC),
            (EKS_ISSUER, ProviderKind.EKS_IRSA),
        ],
    )
    def test_classification(self, issuer, kind):
        assert classify_issuer(issuer) == kind

    def test_registry_records_the_documented_tenancy_claim(self):
        assert issuer_profile("app.terraform.io")["tenancy_claim"] == "sub"
        assert issuer_profile("oidc.vercel.com")["tenancy_claim"] == "aud"
        assert issuer_profile("cognito-identity.amazonaws.com")["tenancy_claim"] == "aud"

    def test_registry_records_where_a_decision_came_from(self):
        assert (
            issuer_profile("token.actions.githubusercontent.com")["source"]
            == "aws_identity_provider_controls"
        )
        assert issuer_profile("oidc.circleci.com")["source"] == "shared_by_inspection"

    def test_unknown_issuer_has_no_profile(self):
        assert issuer_profile("idp.internal.example.com") is None


class TestSharedIssuerRubric:
    def _statement(self, issuer, condition):
        statement = {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::111122223333:oidc-provider/" + issuer
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
        }
        if condition is not None:
            statement["Condition"] = condition
        return statement

    def test_missing_tenancy_claim_on_a_shared_issuer_is_open(self):
        finding = only_finding([self._statement("app.terraform.io", None)])
        assert finding.exposure.grade == ExposureGrade.OPEN
        assert "shared_issuer_tenancy_claim_missing" in weakness_codes(finding)

    def test_fully_pinned_subject_on_a_shared_issuer_is_strong(self):
        finding = only_finding(
            [
                self._statement(
                    "app.terraform.io",
                    {
                        "StringEquals": {
                            "app.terraform.io:sub": (
                                "organization:acme:project:platform:workspace:prod:run_phase:apply"
                            )
                        }
                    },
                )
            ]
        )
        assert finding.exposure.grade == ExposureGrade.STRONG

    def test_cognito_requires_an_audience_condition(self):
        finding = only_finding([self._statement("cognito-identity.amazonaws.com", None)])
        assert finding.exposure.grade == ExposureGrade.OPEN

    def test_shared_issuer_grade_carries_a_heuristic_caveat(self):
        finding = only_finding(
            [
                self._statement(
                    "scalr.io", {"StringEquals": {"scalr.io:sub": "acme:workspace"}}
                )
            ]
        )
        assert any(
            "no bespoke grammar" in item for item in finding.exposure.limitations
        )


class TestPrivateVersusSharedIssuer:
    """The rubric's central distinction, tested directly.

    The same trust policy shape - a federated OIDC principal with no subject
    condition - must grade OPEN on a shared issuer and no worse than MODERATE
    on a private one, because on a shared issuer every other customer of that
    SaaS can mint a token from the same URL.
    """

    def _no_condition_statement(self, issuer):
        return {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::111122223333:oidc-provider/" + issuer
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
        }

    def test_shared_issuer_without_a_subject_condition_is_open(self):
        finding = only_finding(
            [self._no_condition_statement("token.actions.githubusercontent.com")],
            inline_policies=SECRETS_INLINE,
        )
        assert finding.exposure.grade == ExposureGrade.OPEN

    def test_private_issuer_without_a_subject_condition_is_not_open(self):
        finding = only_finding(
            [self._no_condition_statement("idp.internal.example.com")],
            inline_policies=SECRETS_INLINE,
        )
        assert finding.exposure.grade == ExposureGrade.MODERATE

    def test_the_private_issuer_finding_says_why_it_might_be_wrong(self):
        finding = only_finding(
            [self._no_condition_statement("idp.internal.example.com")]
        )
        assert any(
            "multi-tenant SaaS issuer" in item
            for item in finding.exposure.limitations
        )

    def test_the_shared_issuer_ranks_higher_for_the_same_permissions(self):
        shared = only_finding(
            [self._no_condition_statement("token.actions.githubusercontent.com")],
            inline_policies=SECRETS_INLINE,
        )
        private = only_finding(
            [self._no_condition_statement("idp.internal.example.com")],
            inline_policies=SECRETS_INLINE,
        )
        assert shared.risk_score > private.risk_score

    def test_issuer_not_in_the_export_provider_list_is_noted(self):
        result = analyze_statements(
            [self._no_condition_statement("idp.internal.example.com")],
            oidc_providers=[
                {
                    "arn": GITHUB_PROVIDER_ARN,
                    "url": "token.actions.githubusercontent.com",
                }
            ],
        )
        finding = result.findings[0]
        assert "not in the export's oidc_providers list" in " ".join(
            finding.exposure.reasoning
        )
