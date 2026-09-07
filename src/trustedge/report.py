"""Report rendering: JSON, Markdown and self-contained HTML.

The Markdown report is the primary human artifact. It is written so that a
reviewer who has never used TrustEdge can check every claim it makes: each
finding carries the verbatim trust statement it is about, the arithmetic behind
its score, and the documentation links behind its rubric.
"""

from __future__ import annotations

import html
import json
from typing import Dict, Iterable, List, Optional, Sequence

from .models import (
    AnalysisResult,
    BlastRadiusTier,
    ExposureGrade,
    Finding,
    Severity,
)

#: Used for the left border and badge of each finding in the HTML report.
#: Chosen to stay legible on a light background and to remain distinguishable
#: without relying on hue alone.
SEVERITY_COLOUR = {
    Severity.CRITICAL: "#8b1a1a",
    Severity.HIGH: "#b3541e",
    Severity.MEDIUM: "#8a6d1a",
    Severity.LOW: "#3d6b52",
    Severity.INFO: "#4a5568",
}


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def render_json(result: AnalysisResult, indent: int = 2) -> str:
    return result.to_json(indent=indent)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def render_markdown(result: AnalysisResult, max_findings: Optional[int] = None) -> str:
    lines: List[str] = []
    add = lines.append

    add("# TrustEdge inbound trust boundary report")
    add("")
    add(
        "> Who outside this account can become an identity inside it, how strong "
        "is the condition guarding that door, and what do they get once through?"
    )
    add("")
    add("| | |")
    add("|---|---|")
    add("| Account | `%s` |" % (result.account_id or "not stated in export"))
    add("| Input | `%s` |" % (result.input_path or "in-memory export"))
    add("| Generated | %s |" % result.generated_at)
    add("| Tool | %s %s |" % (result.tool, result.tool_version))
    add("")

    _markdown_summary(result, add)
    _markdown_findings(result, add, max_findings)
    _markdown_roles(result, add)
    _markdown_issues(result, add)
    _markdown_limitations(result, add)

    return "\n".join(lines) + "\n"


def _markdown_summary(result: AnalysisResult, add) -> None:
    counts = result.severity_counts()
    add("## Executive summary")
    add("")
    add("| Metric | Value |")
    add("|---|---|")
    add("| Roles analysed | %d |" % result.roles_analyzed)
    add("| Trust statements analysed | %d |" % result.trust_statements_analyzed)
    add("| Trust principals graded | %d |" % result.principals_analyzed)
    add("| Findings reported | %d |" % len(result.findings))
    add("| Highest severity | %s |" % (result.highest_severity() or "none"))
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity in Severity.ORDER:
        add("| %s | %d |" % (severity, counts.get(severity, 0)))
    add("")

    exposure = _distribution(f.exposure.grade for f in result.findings)
    if exposure:
        add("### Exposure distribution")
        add("")
        add("How strongly each graded door is guarded.")
        add("")
        add("| Exposure grade | Doors |")
        add("|---|---|")
        for grade in (
            ExposureGrade.OPEN,
            ExposureGrade.WEAK,
            ExposureGrade.MODERATE,
            ExposureGrade.STRONG,
            ExposureGrade.INTERNAL,
            ExposureGrade.NOT_DETERMINED,
            ExposureGrade.NOT_APPLICABLE,
        ):
            if grade in exposure:
                add("| %s | %d |" % (grade, exposure[grade]))
        add("")

    radius = _distribution(r.blast_radius_tier for r in result.role_summaries)
    if radius:
        add("### Blast radius distribution (per role)")
        add("")
        add("| Blast radius | Roles |")
        add("|---|---|")
        for tier in (
            BlastRadiusTier.ADMIN,
            BlastRadiusTier.HIGH,
            BlastRadiusTier.MODERATE,
            BlastRadiusTier.LOW,
            BlastRadiusTier.UNKNOWN,
        ):
            if tier in radius:
                add("| %s | %d |" % (tier, radius[tier]))
        add("")

    top = [f for f in result.findings if Severity.at_least(f.severity, Severity.HIGH)]
    add("### Highest-risk findings")
    add("")
    if not top:
        add(
            "No finding reached HIGH. That is a statement about what TrustEdge "
            "checks, not a clean bill of health - read the limitations section."
        )
        add("")
    else:
        add("| Rank | Risk | Severity | Role | Who can get in |")
        add("|---:|---:|---|---|---|")
        for index, finding in enumerate(top[:10], start=1):
            add(
                "| %d | %d | %s | `%s` | %s |"
                % (
                    index,
                    finding.risk_score,
                    finding.severity,
                    finding.role_name,
                    _md_cell(finding.exposure.who_can_assume),
                )
            )
        add("")


def _markdown_findings(
    result: AnalysisResult, add, max_findings: Optional[int]
) -> None:
    add("## Findings")
    add("")
    if not result.findings:
        add("No findings were produced.")
        add("")
        return

    findings = result.findings
    if max_findings is not None and len(findings) > max_findings:
        add(
            "_Showing the %d highest-ranked of %d findings. The JSON report "
            "contains all of them._" % (max_findings, len(findings))
        )
        add("")
        findings = findings[:max_findings]

    for index, finding in enumerate(findings, start=1):
        _markdown_finding(finding, index, add)


def _markdown_finding(finding: Finding, index: int, add) -> None:
    add(
        "### %d. [%s] %s"
        % (index, finding.severity, finding.title)
    )
    add("")
    add("`%s`" % finding.finding_id)
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add("| Role | `%s` |" % finding.role_name)
    if finding.role_arn:
        add("| Role ARN | `%s` |" % finding.role_arn)
    add(
        "| Trust statement | index %d%s |"
        % (
            finding.statement_index,
            (", Sid `%s`" % finding.statement_sid) if finding.statement_sid else "",
        )
    )
    add("| Principal | `%s` |" % _md_cell(finding.principal.raw))
    add("| Principal class | %s |" % finding.principal.principal_class)
    add("| Provider | %s |" % finding.principal.provider_kind)
    add("| Exposure grade | **%s** |" % finding.exposure.grade)
    add("| Blast radius | **%s** |" % finding.blast_radius.tier)
    add("| Risk score | **%d** |" % finding.risk_score)
    add("| Confidence | %s |" % finding.exposure.confidence)
    add("| Rubric | `%s` |" % finding.exposure.rubric)
    add("")

    add("**Who can assume it**")
    add("")
    add("%s." % finding.exposure.who_can_assume.rstrip("."))
    add("")

    add("**Why TrustEdge graded it this way**")
    add("")
    for reason in finding.exposure.reasoning:
        add("- %s" % reason)
    if not finding.exposure.reasoning:
        add("- No additional reasoning recorded.")
    add("")

    if finding.exposure.weak_conditions:
        add("**Weak or ineffective conditions**")
        add("")
        add("| Code | Condition key | Operator | Neutralises the guard | Detail |")
        add("|---|---|---|:-:|---|")
        for weak in finding.exposure.weak_conditions:
            add(
                "| `%s` | %s | %s | %s | %s |"
                % (
                    weak.code,
                    ("`%s`" % _md_cell(weak.key)) if weak.key else "-",
                    ("`%s`" % weak.operator) if weak.operator else "-",
                    "yes" if weak.vacuous else "no",
                    _md_cell(weak.detail),
                )
            )
        add("")

    if finding.exposure.fail_closed_notes:
        add("**Fail-closed defects (broken, not permissive)**")
        add("")
        for note in finding.exposure.fail_closed_notes:
            add("- %s" % note)
        add("")

    add("**Trust policy evidence**")
    add("")
    add("```json")
    add(json.dumps(finding.evidence.get("trust_statement", {}), indent=2))
    add("```")
    add("")

    add("**Blast radius**")
    add("")
    for reason in finding.blast_radius.reasoning:
        add("- %s" % reason)
    if finding.blast_radius.capabilities:
        add("")
        add("| Category | Capability | Action matched | Resources | Source policy |")
        add("|---|---|---|---|---|")
        for capability in finding.blast_radius.capabilities:
            add(
                "| %s | `%s` | `%s` | `%s` | %s |"
                % (
                    capability.category,
                    capability.code,
                    _md_cell(capability.action_pattern),
                    _md_cell(", ".join(capability.resource_patterns) or "-"),
                    _md_cell(capability.source_policy),
                )
            )
    add("")

    add("**Score**")
    add("")
    add("%s." % finding.score_explanation.rstrip("."))
    add("")

    add("**Recommended fix**")
    add("")
    add(finding.exposure.recommendation or "No specific recommendation recorded.")
    add("")
    if finding.exposure.recommended_policy:
        add("Tightened trust policy (review before applying - placeholders in "
            "angle brackets must be filled in with values TrustEdge cannot know):")
        add("")
        add("```json")
        add(json.dumps(finding.exposure.recommended_policy, indent=2))
        add("```")
        add("")

    limitations = list(finding.exposure.limitations) + list(
        finding.blast_radius.limitations
    )
    if limitations:
        add("**What this finding does not establish**")
        add("")
        for limitation in _dedupe(limitations):
            add("- %s" % limitation)
        add("")

    if finding.exposure.references:
        add("**References**")
        add("")
        for reference in _dedupe(finding.exposure.references):
            add("- <%s>" % reference)
        add("")

    add("---")
    add("")


def _markdown_roles(result: AnalysisResult, add) -> None:
    add("## Role inventory")
    add("")
    if not result.role_summaries:
        add("No roles were parsed from the export.")
        add("")
        return
    add("| Role | Trust statements | Principal classes | Blast radius | Worst finding |")
    add("|---|---:|---|---|---|")
    for summary in sorted(
        result.role_summaries, key=lambda s: (Severity.rank(s.highest_severity), s.role_name)
    ):
        add(
            "| `%s` | %d | %s | %s | %s |"
            % (
                summary.role_name,
                summary.trust_statement_count,
                ", ".join(summary.inbound_principal_classes) or "-",
                summary.blast_radius_tier,
                summary.highest_severity,
            )
        )
    add("")


def _markdown_issues(result: AnalysisResult, add) -> None:
    if not result.issues:
        return
    errors = [i for i in result.issues if i.level == "error"]
    warnings = [i for i in result.issues if i.level != "error"]
    add("## Input issues")
    add("")
    add(
        "TrustEdge never aborts on a malformed statement; it records the problem "
        "and analyses everything else. Each line below is a place where the "
        "export could not be fully read, so coverage there is incomplete."
    )
    add("")
    add("| Level | Code | Location | Message |")
    add("|---|---|---|---|")
    for issue in errors + warnings:
        add(
            "| %s | `%s` | `%s` | %s |"
            % (
                issue.level,
                issue.code,
                _md_cell(issue.location or "-"),
                _md_cell(issue.message),
            )
        )
    add("")


def _markdown_limitations(result: AnalysisResult, add) -> None:
    add("## Limitations")
    add("")
    add(
        "What TrustEdge cannot determine from an offline export. Read this "
        "before treating an empty findings list as an all-clear."
    )
    add("")
    for limitation in _dedupe(result.limitations):
        add("- %s" % limitation)
    add("")


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------


def render_html(result: AnalysisResult) -> str:
    """A single self-contained HTML file - no network, no build step."""
    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>TrustEdge report - %s</title>"
            % html.escape(result.account_id or "export"),
            "<style>%s</style>" % HTML_CSS,
            "</head><body>",
            render_html_fragment(result),
            "<script>%s</script>" % HTML_FILTER_JS,
            "<script>trustedgeWireFilters();</script>",
            "</body></html>",
        ]
    )


def render_html_fragment(result: AnalysisResult) -> str:
    """The report body only, for embedding in the ``trustedge serve`` page."""
    counts = result.severity_counts()
    parts: List[str] = []
    add = parts.append

    add("<header>")
    add("<h1>TrustEdge</h1>")
    add(
        "<p class='tagline'>Who outside this account can become an identity "
        "inside it, how strong is the guard on that door, and what do they get "
        "once through?</p>"
    )
    add(
        "<p class='meta'>Account <code>%s</code> &middot; %s &middot; %s %s</p>"
        % (
            html.escape(result.account_id or "not stated"),
            html.escape(result.generated_at),
            html.escape(result.tool),
            html.escape(result.tool_version),
        )
    )
    add("</header>")

    add("<section class='cards'>")
    for label, value in (
        ("Roles", result.roles_analyzed),
        ("Trust statements", result.trust_statements_analyzed),
        ("Principals graded", result.principals_analyzed),
        ("Findings", len(result.findings)),
    ):
        add("<div class='card'><span class='n'>%d</span><span class='l'>%s</span></div>" % (value, html.escape(label)))
    add("</section>")

    add("<section class='cards'>")
    for severity in Severity.ORDER:
        add(
            "<div class='card sev' style='border-color:%s'>"
            "<span class='n' style='color:%s'>%d</span>"
            "<span class='l'>%s</span></div>"
            % (
                SEVERITY_COLOUR[severity],
                SEVERITY_COLOUR[severity],
                counts.get(severity, 0),
                severity,
            )
        )
    add("</section>")

    add("<section><h2>Findings</h2>")
    add("<div class='filters'>Filter: ")
    add("<button data-sev='ALL' class='active'>All</button>")
    for severity in Severity.ORDER:
        add("<button data-sev='%s'>%s</button>" % (severity, severity))
    add("</div>")

    if not result.findings:
        add("<p>No findings were produced.</p>")
    for finding in result.findings:
        add(_html_finding(finding))
    add("</section>")

    add("<section><h2>Role inventory</h2>")
    add(
        "<table><thead><tr><th>Role</th><th>Trust statements</th>"
        "<th>Principal classes</th><th>Blast radius</th><th>Worst finding</th>"
        "</tr></thead><tbody>"
    )
    for summary in sorted(
        result.role_summaries,
        key=lambda s: (Severity.rank(s.highest_severity), s.role_name),
    ):
        add(
            "<tr><td><code>%s</code></td><td>%d</td><td>%s</td><td>%s</td>"
            "<td>%s</td></tr>"
            % (
                html.escape(summary.role_name),
                summary.trust_statement_count,
                html.escape(", ".join(summary.inbound_principal_classes) or "-"),
                html.escape(summary.blast_radius_tier),
                html.escape(summary.highest_severity),
            )
        )
    add("</tbody></table></section>")

    if result.issues:
        add("<section><h2>Input issues</h2><ul class='issues'>")
        for issue in result.issues:
            add(
                "<li><span class='badge %s'>%s</span> <code>%s</code> %s</li>"
                % (
                    html.escape(issue.level),
                    html.escape(issue.level),
                    html.escape(issue.code),
                    html.escape(issue.message),
                )
            )
        add("</ul></section>")

    add("<section><h2>Limitations</h2><ul>")
    for limitation in _dedupe(result.limitations):
        add("<li>%s</li>" % html.escape(limitation))
    add("</ul></section>")

    return "\n".join(parts)


def _html_finding(finding: Finding) -> str:
    colour = SEVERITY_COLOUR.get(finding.severity, "#4a5568")
    out: List[str] = []
    add = out.append
    add(
        "<details class='finding' data-sev='%s' style='border-left-color:%s'>"
        % (html.escape(finding.severity), colour)
    )
    add(
        "<summary><span class='badge' style='background:%s'>%s</span>"
        "<span class='risk'>%d</span> %s</summary>"
        % (
            colour,
            html.escape(finding.severity),
            finding.risk_score,
            html.escape(finding.title),
        )
    )
    add("<div class='body'>")
    add("<p class='fid'><code>%s</code></p>" % html.escape(finding.finding_id))

    add("<h4>Who can assume it</h4>")
    add("<p>%s</p>" % html.escape(finding.exposure.who_can_assume))

    add("<h4>Why TrustEdge graded it this way</h4><ul>")
    for reason in finding.exposure.reasoning or ["No reasoning recorded."]:
        add("<li>%s</li>" % html.escape(reason))
    add("</ul>")

    if finding.exposure.weak_conditions:
        add("<h4>Weak or ineffective conditions</h4><ul>")
        for weak in finding.exposure.weak_conditions:
            add(
                "<li><code>%s</code>%s %s%s</li>"
                % (
                    html.escape(weak.code),
                    (" on <code>%s</code>" % html.escape(weak.key)) if weak.key else "",
                    html.escape(weak.detail),
                    " <strong>(neutralises the guard)</strong>" if weak.vacuous else "",
                )
            )
        add("</ul>")

    if finding.exposure.fail_closed_notes:
        add("<h4>Fail-closed defects</h4><ul>")
        for note in finding.exposure.fail_closed_notes:
            add("<li>%s</li>" % html.escape(note))
        add("</ul>")

    add("<h4>Trust policy evidence</h4>")
    add(
        "<pre>%s</pre>"
        % html.escape(json.dumps(finding.evidence.get("trust_statement", {}), indent=2))
    )

    add("<h4>Blast radius: %s</h4><ul>" % html.escape(finding.blast_radius.tier))
    for reason in finding.blast_radius.reasoning:
        add("<li>%s</li>" % html.escape(reason))
    add("</ul>")
    if finding.blast_radius.capabilities:
        add(
            "<table><thead><tr><th>Category</th><th>Capability</th>"
            "<th>Action</th><th>Resources</th><th>Policy</th></tr></thead><tbody>"
        )
        for capability in finding.blast_radius.capabilities:
            add(
                "<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td>"
                "<td><code>%s</code></td><td>%s</td></tr>"
                % (
                    html.escape(capability.category),
                    html.escape(capability.code),
                    html.escape(capability.action_pattern),
                    html.escape(", ".join(capability.resource_patterns) or "-"),
                    html.escape(capability.source_policy),
                )
            )
        add("</tbody></table>")

    add("<h4>Score</h4><p>%s</p>" % html.escape(finding.score_explanation))

    add("<h4>Recommended fix</h4>")
    add(
        "<p>%s</p>"
        % html.escape(finding.exposure.recommendation or "None recorded.")
    )
    if finding.exposure.recommended_policy:
        add(
            "<pre>%s</pre>"
            % html.escape(json.dumps(finding.exposure.recommended_policy, indent=2))
        )

    limitations = _dedupe(
        list(finding.exposure.limitations) + list(finding.blast_radius.limitations)
    )
    if limitations:
        add("<h4>What this finding does not establish</h4><ul>")
        for limitation in limitations:
            add("<li>%s</li>" % html.escape(limitation))
        add("</ul>")

    if finding.exposure.references:
        add("<h4>References</h4><ul>")
        for reference in _dedupe(finding.exposure.references):
            add(
                '<li><a href="%s" rel="noreferrer noopener">%s</a></li>'
                % (html.escape(reference), html.escape(reference))
            )
        add("</ul>")

    add("</div></details>")
    return "\n".join(out)


#: Exposed so ``trustedge serve`` can reuse exactly the same styling as the
#: standalone HTML report instead of maintaining a second stylesheet.
HTML_CSS = """
:root { --fg:#1a202c; --muted:#4a5568; --line:#e2e8f0; --bg:#fbfcfe; }
* { box-sizing:border-box; }
body { margin:0; padding:0 1.25rem 4rem; font:15px/1.6 -apple-system,BlinkMacSystemFont,
  "Segoe UI",Roboto,Helvetica,Arial,sans-serif; color:var(--fg); background:var(--bg);
  max-width:1080px; margin-inline:auto; }
header { padding:2rem 0 1rem; border-bottom:1px solid var(--line); }
h1 { margin:0; font-size:1.6rem; letter-spacing:-.02em; }
.tagline { margin:.5rem 0 0; color:var(--muted); max-width:60ch; }
.meta { color:var(--muted); font-size:.85rem; }
h2 { margin-top:2.5rem; font-size:1.2rem; border-bottom:1px solid var(--line);
  padding-bottom:.4rem; }
h4 { margin:1.2rem 0 .3rem; font-size:.9rem; text-transform:uppercase;
  letter-spacing:.04em; color:var(--muted); }
.cards { display:flex; gap:.75rem; flex-wrap:wrap; margin:1.25rem 0; }
.card { flex:1 1 130px; border:1px solid var(--line); border-radius:8px;
  padding:.75rem .9rem; background:#fff; display:flex; flex-direction:column; }
.card.sev { border-left-width:4px; }
.card .n { font-size:1.5rem; font-weight:600; }
.card .l { font-size:.75rem; text-transform:uppercase; letter-spacing:.05em;
  color:var(--muted); }
.filters { margin:.5rem 0 1rem; font-size:.85rem; color:var(--muted); }
.filters button { font:inherit; border:1px solid var(--line); background:#fff;
  border-radius:999px; padding:.2rem .7rem; margin-right:.3rem; cursor:pointer; }
.filters button.active { background:var(--fg); color:#fff; border-color:var(--fg); }
details.finding { border:1px solid var(--line); border-left-width:4px;
  border-radius:6px; margin:.6rem 0; background:#fff; }
details.finding summary { cursor:pointer; padding:.7rem .9rem; font-weight:500;
  display:flex; align-items:center; gap:.6rem; }
details.finding .body { padding:0 .9rem 1rem; border-top:1px solid var(--line); }
.badge { font-size:.68rem; font-weight:700; letter-spacing:.06em; color:#fff;
  padding:.15rem .45rem; border-radius:4px; text-transform:uppercase; }
.badge.error { background:#8b1a1a; } .badge.warning { background:#8a6d1a; }
.risk { font-variant-numeric:tabular-nums; font-weight:700; min-width:2.2ch;
  text-align:right; color:var(--muted); }
.fid { color:var(--muted); font-size:.8rem; margin:.6rem 0 0; }
pre { background:#f4f6fa; border:1px solid var(--line); border-radius:6px;
  padding:.7rem .8rem; overflow-x:auto; font-size:.8rem; }
code { background:#f4f6fa; padding:.05rem .3rem; border-radius:3px; font-size:.85em; }
pre code { background:none; padding:0; }
table { border-collapse:collapse; width:100%; font-size:.85rem; margin:.5rem 0; }
th,td { border:1px solid var(--line); padding:.35rem .5rem; text-align:left;
  vertical-align:top; }
th { background:#f4f6fa; font-weight:600; }
ul { margin:.3rem 0 .3rem 1.1rem; padding:0; }
li { margin:.2rem 0; }
ul.issues { list-style:none; margin-left:0; }
a { color:#1a4f8b; }
"""

#: Severity filtering. Defined as a named function rather than an IIFE because
#: ``trustedge serve`` injects the report body with innerHTML, and script tags
#: inserted that way never execute - the page calls this function itself.
HTML_FILTER_JS = """
function trustedgeWireFilters() {
  var buttons = document.querySelectorAll('.filters button');
  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener('click', function () {
      var wanted = button.getAttribute('data-sev');
      Array.prototype.forEach.call(buttons, function (other) {
        if (other === button) { other.classList.add('active'); }
        else { other.classList.remove('active'); }
      });
      var findings = document.querySelectorAll('details.finding');
      Array.prototype.forEach.call(findings, function (finding) {
        var show = wanted === 'ALL' ||
                   finding.getAttribute('data-sev') === wanted;
        finding.style.display = show ? '' : 'none';
      });
    });
  });
}
"""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _distribution(values: Iterable[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _dedupe(values: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _md_cell(value: Optional[str]) -> str:
    """Make a string safe to drop into a Markdown table cell."""
    if value is None:
        return "-"
    return (
        str(value)
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}


def render(result: AnalysisResult, fmt: str, **kwargs) -> str:
    renderer = RENDERERS.get(fmt.lower())
    if renderer is None:
        raise ValueError(
            "unknown output format %r; choose one of %s"
            % (fmt, ", ".join(sorted(set(RENDERERS))))
        )
    if renderer is render_markdown:
        return render_markdown(result, max_findings=kwargs.get("max_findings"))
    return renderer(result)
