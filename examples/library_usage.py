#!/usr/bin/env python3
"""Using TrustEdge as a library rather than a CLI.

Run it:

    PYTHONPATH=../src python library_usage.py
    # or, once installed:
    python library_usage.py

Everything below is offline: no credentials, no network, no AWS SDK.
"""

from __future__ import annotations

import json
import os
import sys

from trustedge import analyzer, report
from trustedge.models import BlastRadiusTier, ExposureGrade, Severity
from trustedge.parser import ExportFormatError, parse_export

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "fixtures", "sample-account.json")


def example_1_analyse_a_file() -> None:
    """The common case: one file in, one ranked result out."""
    print("=" * 72)
    print("1. Analyse an export file")
    print("=" * 72)

    result = analyzer.analyze_file(FIXTURE)

    print("account:            %s" % result.account_id)
    print("roles analysed:     %d" % result.roles_analyzed)
    print("trust statements:   %d" % result.trust_statements_analyzed)
    print("findings:           %d" % len(result.findings))
    print("severity counts:    %s" % result.severity_counts())
    print()

    for finding in result.findings[:5]:
        print("  [%-8s] %3d  %s" % (finding.severity, finding.risk_score, finding.role_name))
        print("             who: %s" % finding.exposure.who_can_assume)
        print("             why: %s" % finding.score_explanation)
        print()


def example_2_build_an_export_in_memory() -> None:
    """No file needed - grade a trust policy you have as a dict.

    Useful in a policy-review bot, a pre-commit hook over Terraform output, or
    a test that asserts your own trust policies stay narrow.
    """
    print("=" * 72)
    print("2. Grade a trust policy held in memory")
    print("=" * 72)

    document = {
        "account_id": "111122223333",
        "roles": [
            {
                "role_name": "candidate-role",
                "arn": "arn:aws:iam::111122223333:role/candidate-role",
                "assume_role_policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": (
                                    "arn:aws:iam::111122223333:oidc-provider/"
                                    "token.actions.githubusercontent.com"
                                )
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                                },
                                "StringLike": {
                                    "token.actions.githubusercontent.com:sub": "repo:acme-corp/*"
                                },
                            },
                        }
                    ],
                },
                "inline_policies": [
                    {
                        "policy_name": "read-secrets",
                        "policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "secretsmanager:GetSecretValue",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    export, issues = parse_export(document, source="in-memory")
    result = analyzer.analyze(export, issues=issues)
    finding = result.findings[0]

    print("exposure grade:  %s" % finding.exposure.grade)
    print("blast radius:    %s" % finding.blast_radius.tier)
    print("severity:        %s (risk %d)" % (finding.severity, finding.risk_score))
    print("rubric:          %s" % finding.exposure.rubric)
    print()
    print("reasoning:")
    for reason in finding.exposure.reasoning:
        print("  - %s" % reason)
    print()
    print("weak conditions:")
    for weak in finding.exposure.weak_conditions:
        print("  - %s%s" % (weak.code, " (neutralises the guard)" if weak.vacuous else ""))
    print()
    print("recommendation:  %s" % finding.exposure.recommendation)
    print()


def example_3_gate_on_a_policy_of_your_own() -> None:
    """Assert a property of your trust policies, in a test.

    This is the shape to use in your own test suite: an assertion about the
    exposure grade rather than about a severity number, so it keeps working
    when weights change.
    """
    print("=" * 72)
    print("3. Assert a property, for use in your own tests")
    print("=" * 72)

    def grade_of(condition):
        document = {
            "account_id": "111122223333",
            "roles": [
                {
                    "role_name": "r",
                    "arn": "arn:aws:iam::111122223333:role/r",
                    "assume_role_policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Federated": (
                                        "arn:aws:iam::111122223333:oidc-provider/"
                                        "token.actions.githubusercontent.com"
                                    )
                                },
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Condition": condition,
                            }
                        ],
                    },
                }
            ],
        }
        export, issues = parse_export(document)
        return analyzer.analyze(export, issues=issues).findings[0].exposure.grade

    issuer = "token.actions.githubusercontent.com"

    pinned = grade_of(
        {
            "StringEquals": {
                issuer + ":aud": "sts.amazonaws.com",
                issuer + ":sub": "repo:acme-corp/app:ref:refs/heads/main",
            }
        }
    )
    org_wide = grade_of(
        {
            "StringEquals": {issuer + ":aud": "sts.amazonaws.com"},
            "StringLike": {issuer + ":sub": "repo:acme-corp/*"},
        }
    )
    vacuous = grade_of(
        {
            "StringEquals": {issuer + ":aud": "sts.amazonaws.com"},
            "StringLike": {issuer + ":sub": "repo:acme-corp/app:*"},
            "StringEqualsIfExists": {issuer + ":environment": "production"},
        }
    )

    print("branch-pinned subject      -> %s" % pinned)
    print("org-wildcard subject       -> %s" % org_wide)
    print("repo + IfExists on env     -> %s" % vacuous)
    print()

    assert pinned == ExposureGrade.STRONG
    assert org_wide == ExposureGrade.WEAK
    # The IfExists environment condition earns nothing: it evaluates to true
    # when the workflow simply does not declare an environment.
    assert vacuous == ExposureGrade.MODERATE
    print("all assertions held")
    print()


def example_4_filter_and_render() -> None:
    """Pull out the findings you care about and render them yourself."""
    print("=" * 72)
    print("4. Filter, then render")
    print("=" * 72)

    result = analyzer.analyze_file(FIXTURE)

    high = [f for f in result.findings if Severity.at_least(f.severity, Severity.HIGH)]
    print("findings at HIGH or above: %d" % len(high))

    open_doors = [
        f for f in result.findings if f.exposure.grade == ExposureGrade.OPEN
    ]
    print("doors graded OPEN:         %d" % len(open_doors))

    admin_roles = [
        r for r in result.role_summaries if r.blast_radius_tier == BlastRadiusTier.ADMIN
    ]
    print("administrator-equivalent roles: %s"
          % ", ".join(r.role_name for r in admin_roles))
    print()

    # The renderers take an AnalysisResult, so you can post-process first.
    result.findings = high
    markdown = report.render_markdown(result)
    print("rendered markdown for the HIGH+ subset: %d characters" % len(markdown))
    payload = json.loads(report.render_json(result))
    print("JSON summary after filtering: %s" % payload["summary"]["severity_counts"])
    print()


def example_5_handle_bad_input() -> None:
    """The error contract: issues for bad parts, an exception only for a bad whole."""
    print("=" * 72)
    print("5. Error handling")
    print("=" * 72)

    # A malformed *part* produces issues, not an exception.
    export, issues = parse_export(
        {
            "account_id": "111122223333",
            "roles": [
                "this should be an object",
                {
                    "role_name": "survivor",
                    "arn": "arn:aws:iam::111122223333:role/survivor",
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
                },
            ],
        }
    )
    print("roles parsed:  %d" % len(export.roles))
    print("issues raised: %s" % [i.code for i in issues])

    # An input that is not an IAM export at all is the only hard failure.
    try:
        parse_export(["not", "an", "export"])
    except ExportFormatError as exc:
        print("hard failure:  %s" % exc)
    print()


def main() -> int:
    if not os.path.exists(FIXTURE):
        print("fixture not found: %s" % FIXTURE, file=sys.stderr)
        print("run this from the examples/ directory of the repository", file=sys.stderr)
        return 2
    example_1_analyse_a_file()
    example_2_build_an_export_in_memory()
    example_3_gate_on_a_policy_of_your_own()
    example_4_filter_and_render()
    example_5_handle_bad_input()
    return 0


if __name__ == "__main__":
    sys.exit(main())
