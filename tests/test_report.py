"""Report rendering tests.

A report is part of the product, not decoration: if the evidence or the
limitations are missing from it, the finding is not actionable. These tests
assert that the things a reviewer needs in order to disagree with TrustEdge are
present in the output.
"""

from __future__ import annotations

import json
import re

import pytest

from trustedge import report
from trustedge.models import Severity


@pytest.fixture(scope="module")
def markdown(sample_result):
    return report.render_markdown(sample_result)


@pytest.fixture(scope="module")
def html(sample_result):
    return report.render_html(sample_result)


@pytest.fixture(scope="module")
def payload(sample_result):
    return json.loads(report.render_json(sample_result))


class TestJson:
    def test_is_valid_json_with_a_schema_marker(self, payload):
        assert payload["schema"] == "trustedge.report/1"

    def test_summary_counts_match_the_findings(self, payload):
        assert payload["summary"]["findings_total"] == len(payload["findings"])
        counted = sum(payload["summary"]["severity_counts"].values())
        assert counted == len(payload["findings"])

    def test_every_field_the_brief_requires_is_present(self, payload):
        finding = payload["findings"][0]
        for key in (
            "finding_id",
            "role_name",
            "statement_index",
            "principal",
            "principal_classification",
            "provider",
            "exposure",
            "blast_radius",
            "severity",
            "risk_score",
            "score_explanation",
            "evidence",
            "recommendation",
        ):
            assert key in finding, key
        assert "grade" in finding["exposure"]
        assert "weak_conditions" in finding["exposure"]
        assert "confidence" in finding["exposure"]
        assert "limitations" in finding["exposure"]
        assert "tier" in finding["blast_radius"]
        assert "trust_statement" in finding["evidence"]

    def test_report_level_limitations_are_present(self, payload):
        assert payload["limitations"]

    def test_input_issues_are_carried_through(self, payload):
        assert isinstance(payload["input_issues"], list)

    def test_role_inventory_is_present(self, payload):
        assert payload["roles"]
        assert "blast_radius_tier" in payload["roles"][0]

    def test_round_trips_through_json(self, sample_result):
        text = report.render_json(sample_result)
        assert json.loads(text) == json.loads(text)


class TestMarkdown:
    def test_has_the_required_sections(self, markdown):
        for heading in (
            "# TrustEdge inbound trust boundary report",
            "## Executive summary",
            "## Findings",
            "## Role inventory",
            "## Limitations",
        ):
            assert heading in markdown, heading

    def test_executive_summary_reports_the_counts(self, markdown, sample_result):
        assert "| Roles analysed | %d |" % sample_result.roles_analyzed in markdown
        assert (
            "| Trust statements analysed | %d |"
            % sample_result.trust_statements_analyzed
            in markdown
        )

    def test_highest_risk_findings_table_is_present(self, markdown):
        assert "### Highest-risk findings" in markdown
        assert "| Rank | Risk | Severity | Role | Who can get in |" in markdown

    def test_each_finding_has_the_reviewer_facing_sections(self, markdown):
        for heading in (
            "**Who can assume it**",
            "**Why TrustEdge graded it this way**",
            "**Trust policy evidence**",
            "**Blast radius**",
            "**Score**",
            "**Recommended fix**",
        ):
            assert heading in markdown, heading

    def test_weak_conditions_are_tabulated(self, markdown):
        assert "**Weak or ineffective conditions**" in markdown
        assert "Neutralises the guard" in markdown

    def test_evidence_is_embedded_as_json(self, markdown):
        assert "```json" in markdown
        assert '"Effect": "Allow"' in markdown

    def test_a_tightened_policy_is_offered_where_one_is_safe(self, markdown):
        assert "Tightened trust policy" in markdown
        assert "placeholders in" in markdown

    def test_limitations_appear_per_finding_and_globally(self, markdown):
        assert "**What this finding does not establish**" in markdown
        assert "before treating an empty findings list as an all-clear" in markdown

    def test_references_are_linked(self, markdown):
        assert "docs.aws.amazon.com" in markdown

    def test_input_issues_section_appears_when_there_are_issues(self, sample_result):
        text = report.render_markdown(sample_result)
        if sample_result.issues:
            assert "## Input issues" in text

    def test_pipes_in_values_do_not_break_tables(self):
        assert report._md_cell("a|b") == "a\\|b"
        assert report._md_cell("line1\nline2") == "line1 line2"
        assert report._md_cell(None) == "-"

    def test_max_findings_truncates_and_says_so(self, sample_result):
        text = report.render_markdown(sample_result, max_findings=3)
        assert "Showing the 3 highest-ranked" in text
        # Finding headings look like "### 1. [SEVERITY] ..."
        headings = re.findall(r"^### \d+\. \[", text, flags=re.MULTILINE)
        assert len(headings) == 3

    def test_output_ends_with_a_newline(self, markdown):
        assert markdown.endswith("\n")


class TestHtml:
    def test_is_a_self_contained_document(self, html):
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "<style>" in html
        # No external resources: the report must open from a file:// URL with
        # no network and no build step. Documentation links are anchors the
        # reader chooses to click, not resources the page loads.
        assert "<script src=" not in html
        assert "<link " not in html
        assert "<img" not in html
        assert "@import" not in html

    def test_severity_filter_controls_are_present(self, html):
        assert "data-sev='ALL'" in html
        assert "trustedgeWireFilters" in html
        for severity in Severity.ORDER:
            assert "data-sev='%s'" % severity in html

    def test_findings_are_rendered_as_collapsible_details(self, html, sample_result):
        assert html.count("<details class='finding'") == len(sample_result.findings)

    def test_evidence_is_escaped_not_interpolated(self, html):
        assert "<script>alert" not in html

    def test_fragment_omits_the_document_wrapper(self, sample_result):
        fragment = report.render_html_fragment(sample_result)
        assert not fragment.startswith("<!DOCTYPE")
        assert "<header>" in fragment
        assert "</html>" not in fragment

    def test_html_escaping_of_hostile_content(self):
        from trustedge import analyzer
        from trustedge.parser import parse_export

        export, issues = parse_export(
            {
                "account_id": "111122223333",
                "roles": [
                    {
                        "role_name": "<script>alert(1)</script>",
                        "arn": "arn:aws:iam::111122223333:role/x",
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
        result = analyzer.analyze(export, issues=issues)
        rendered = report.render_html(result)
        assert "<script>alert(1)</script>" not in rendered
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered


class TestRenderDispatch:
    @pytest.mark.parametrize("fmt", ["json", "markdown", "md", "html"])
    def test_known_formats(self, sample_result, fmt):
        assert report.render(sample_result, fmt)

    def test_format_is_case_insensitive(self, sample_result):
        assert report.render(sample_result, "JSON")

    def test_unknown_format_raises_with_the_valid_options(self, sample_result):
        with pytest.raises(ValueError) as excinfo:
            report.render(sample_result, "pdf")
        assert "markdown" in str(excinfo.value)

    def test_max_findings_is_passed_to_markdown_only(self, sample_result):
        text = report.render(sample_result, "markdown", max_findings=1)
        assert "Showing the 1 highest-ranked" in text
        # JSON must always be complete.
        payload = json.loads(report.render(sample_result, "json", max_findings=1))
        assert payload["summary"]["findings_total"] == len(sample_result.findings)


@pytest.fixture(scope="module")
def empty_result():
    from trustedge import analyzer
    from trustedge.parser import parse_export

    export, issues = parse_export({"account_id": "111122223333", "roles": []})
    return analyzer.analyze(export, issues=issues)


class TestEmptyResultRendering:

    def test_markdown_says_nothing_was_found_without_implying_all_clear(
        self, empty_result
    ):
        text = report.render_markdown(empty_result)
        assert "No findings were produced." in text
        assert "not a clean bill of health" in text

    def test_html_renders(self, empty_result):
        assert report.render_html(empty_result).startswith("<!DOCTYPE html>")

    def test_json_renders(self, empty_result):
        payload = json.loads(report.render_json(empty_result))
        assert payload["findings"] == []
        assert payload["summary"]["highest_severity"] is None
