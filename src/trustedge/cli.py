"""Command line interface.

Exit codes are chosen so the tool composes in CI:

===  ==========================================================
  0  Ran successfully; no finding reached the ``--fail-on`` bar.
  1  Ran successfully; at least one finding reached ``--fail-on``.
  2  The input or the invocation was wrong (bad path, bad JSON,
     not an IAM export, unknown format).
  3  An unexpected internal error. This is a bug - please report it.
===  ==========================================================

Note the split between 1 and 2: a pipeline that treats "found something" and
"could not run" identically will eventually go green because the export path
was mistyped.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from . import report as report_module
from .analyzer import TOOL_NAME, analyze_file
from .models import Severity
from .parser import ExportFormatError, load_json_file, parse_export
from .version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT_ERROR = 2
EXIT_INTERNAL_ERROR = 3

FORMATS = ("json", "markdown", "md", "html")
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info", "none")

_EXTENSION_FORMATS = {
    ".json": "json",
    ".md": "markdown",
    ".markdown": "markdown",
    ".html": "html",
    ".htm": "html",
}

EPILOG = """\
examples:
  # Human-readable report to stdout
  trustedge analyze --input fixtures/sample-account.json

  # Machine-readable report to a file
  trustedge analyze --input fixtures/sample-account.json \\
      --output reports/sample-report.json --format json

  # Markdown report, and fail the build on anything HIGH or worse
  trustedge analyze --input fixtures/sample-account.json \\
      --output reports/sample-report.md --format markdown --fail-on high

  # Check an export parses before trusting a report built from it
  trustedge validate --input fixtures/sample-account.json

  # Turn a read-only AWS CLI dump into a TrustEdge export
  aws iam get-account-authorization-details --filter Role > auth.json
  trustedge convert --input auth.json --output export.json

  # Local read-only viewer on http://127.0.0.1:8765
  trustedge serve

TrustEdge makes no AWS API calls and needs no credentials.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustedge",
        description=(
            "%s - AWS inbound trust boundary analyzer. Grades who outside an "
            "account can become an identity inside it, and ranks each door by "
            "exposure x blast radius." % TOOL_NAME
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # -- analyze ----------------------------------------------------------
    analyze_parser = subparsers.add_parser(
        "analyze",
        aliases=["analyse"],
        help="analyse an IAM export and produce a ranked report",
        description="Analyse an IAM export and produce a ranked report.",
    )
    analyze_parser.add_argument(
        "-i",
        "--input",
        required=True,
        metavar="PATH",
        help="path to the IAM export JSON (native TrustEdge export or raw "
        "get-account-authorization-details output)",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report here instead of stdout; parent directories "
        "are created",
    )
    analyze_parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        help="output format (default: inferred from --output extension, "
        "otherwise markdown)",
    )
    analyze_parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="none",
        help="exit 1 if any finding reaches this severity (default: none)",
    )
    analyze_parser.add_argument(
        "--include-internal",
        action="store_true",
        help="also report same-account and compute-attachment trust, which "
        "is graded INTERNAL and omitted by default",
    )
    analyze_parser.add_argument(
        "--max-findings",
        type=int,
        metavar="N",
        help="limit the Markdown report to the N highest-ranked findings "
        "(the JSON report always contains all of them)",
    )
    analyze_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress the progress summary on stderr",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # -- validate ---------------------------------------------------------
    validate_parser = subparsers.add_parser(
        "validate",
        help="check that an export parses, and list everything unreadable in it",
        description=(
            "Parse an export and report every field TrustEdge could not read. "
            "Use this before trusting a report: an export that silently lost "
            "half its roles produces a clean-looking report."
        ),
    )
    validate_parser.add_argument("-i", "--input", required=True, metavar="PATH")
    validate_parser.add_argument(
        "-f", "--format", choices=("text", "json"), default="text"
    )
    validate_parser.set_defaults(func=cmd_validate)

    # -- convert ----------------------------------------------------------
    convert_parser = subparsers.add_parser(
        "convert",
        help="convert get-account-authorization-details output to a TrustEdge export",
        description=(
            "Convert the output of 'aws iam get-account-authorization-details' "
            "into the native TrustEdge export. This is a pure JSON transform on "
            "a file you already have; no AWS calls are made."
        ),
    )
    convert_parser.add_argument("-i", "--input", required=True, metavar="PATH")
    convert_parser.add_argument("-o", "--output", metavar="PATH")
    convert_parser.add_argument(
        "--add",
        metavar="PATH",
        action="append",
        default=[],
        help="merge a JSON file of context the AWS output does not contain "
        "(account_id, organization_id, trusted_account_ids, oidc_providers, "
        "saml_providers, vendor_accounts). May be given more than once.",
    )
    convert_parser.set_defaults(func=cmd_convert)

    # -- serve ------------------------------------------------------------
    serve_parser = subparsers.add_parser(
        "serve",
        help="run the local read-only report viewer",
        description=(
            "Run a small local viewer that analyses an export you drop into the "
            "page. Binds to loopback; nothing is written to disk and nothing "
            "leaves the machine."
        ),
    )
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("-q", "--quiet", action="store_true")
    serve_parser.set_defaults(func=cmd_serve)

    return parser


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    fmt = args.format or _infer_format(args.output) or "markdown"
    if args.max_findings is not None and args.max_findings < 1:
        _fail("--max-findings must be 1 or greater")
        return EXIT_INPUT_ERROR

    result = analyze_file(args.input, include_internal=args.include_internal)
    text = report_module.render(result, fmt, max_findings=args.max_findings)

    if args.output:
        _write(args.output, text)
        if not args.quiet:
            _emit_summary(result, args.output)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

    errors = [i for i in result.issues if i.level == "error"]
    if errors and not args.quiet:
        sys.stderr.write(
            "note: %d part(s) of the export could not be read; coverage is "
            "incomplete. Run 'trustedge validate' for details.\n" % len(errors)
        )

    if args.fail_on != "none":
        threshold = args.fail_on.upper()
        triggered = [
            f for f in result.findings if Severity.at_least(f.severity, threshold)
        ]
        if triggered:
            if not args.quiet:
                sys.stderr.write(
                    "failing: %d finding(s) at %s or above (worst: %s, risk %d, "
                    "role %s)\n"
                    % (
                        len(triggered),
                        threshold,
                        triggered[0].severity,
                        triggered[0].risk_score,
                        triggered[0].role_name,
                    )
                )
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    document = load_json_file(args.input)
    export, issues = parse_export(document, source=args.input)
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level != "error"]

    if args.format == "json":
        sys.stdout.write(
            json.dumps(
                {
                    "input": args.input,
                    "account_id": export.account_id,
                    "roles_parsed": len(export.roles),
                    "trust_statements_parsed": sum(
                        len(r.trust_statements) for r in export.roles
                    ),
                    "managed_policy_documents": len(export.managed_policies),
                    "oidc_providers": len(export.oidc_providers),
                    "saml_providers": len(export.saml_providers),
                    "vendor_accounts": len(export.vendor_accounts),
                    "errors": [i.to_dict() for i in errors],
                    "warnings": [i.to_dict() for i in warnings],
                },
                indent=2,
            )
            + "\n"
        )
        return EXIT_INPUT_ERROR if errors else EXIT_OK

    out = sys.stdout
    out.write("input:                     %s\n" % args.input)
    out.write("account id:                %s\n" % (export.account_id or "<not stated>"))
    out.write("roles parsed:              %d\n" % len(export.roles))
    out.write(
        "trust statements parsed:   %d\n"
        % sum(len(r.trust_statements) for r in export.roles)
    )
    out.write("managed policy documents:  %d\n" % len(export.managed_policies))
    out.write("OIDC providers:            %d\n" % len(export.oidc_providers))
    out.write("SAML providers:            %d\n" % len(export.saml_providers))
    out.write("vendor account entries:    %d\n" % len(export.vendor_accounts))
    unusable = [r.role_name for r in export.roles if r.trust_policy_unusable]
    if unusable:
        out.write(
            "roles with an unusable trust policy: %s\n" % ", ".join(unusable)
        )
    out.write("\n")
    if not issues:
        out.write("No problems found. Every field TrustEdge reads was readable.\n")
        return EXIT_OK
    for label, group in (("ERROR", errors), ("WARNING", warnings)):
        for issue in group:
            out.write(
                "%-7s %-38s %s\n"
                % (label, issue.code, issue.message)
            )
            if issue.location:
                out.write("%-7s %-38s at %s\n" % ("", "", issue.location))
    out.write(
        "\n%d error(s), %d warning(s). Errors mean data was dropped, so the "
        "analysis does not cover it.\n" % (len(errors), len(warnings))
    )
    return EXIT_INPUT_ERROR if errors else EXIT_OK


def cmd_convert(args: argparse.Namespace) -> int:
    from .convert import (
        from_authorization_details,
        merge_supplementary,
    )
    from .parser import looks_like_authorization_details

    document = load_json_file(args.input)
    if not looks_like_authorization_details(document):
        _fail(
            "%s does not look like 'aws iam get-account-authorization-details' "
            "output (no RoleDetailList / UserDetailList / GroupDetailList). If "
            "it is already a TrustEdge export, pass it straight to "
            "'trustedge analyze'." % args.input
        )
        return EXIT_INPUT_ERROR

    export, issues = from_authorization_details(document)
    for path in args.add:
        supplement = load_json_file(path)
        export, more = merge_supplementary(export, supplement)
        issues.extend(more)

    text = json.dumps(export, indent=2) + "\n"
    if args.output:
        _write(args.output, text)
        sys.stderr.write(
            "converted %d role(s) and %d managed policy document(s) into %s\n"
            % (
                len(export.get("roles", [])),
                len(export.get("managed_policies", [])),
                args.output,
            )
        )
    else:
        sys.stdout.write(text)

    for issue in issues:
        sys.stderr.write("%s: %s\n" % (issue.level, issue.message))
    return EXIT_INPUT_ERROR if any(i.level == "error" for i in issues) else EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .web import serve

    return serve(host=args.host, port=args.port, quiet=args.quiet)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _infer_format(output: Optional[str]) -> Optional[str]:
    if not output:
        return None
    _, extension = os.path.splitext(output)
    return _EXTENSION_FORMATS.get(extension.lower())


def _write(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _emit_summary(result, output_path: str) -> None:
    counts = result.severity_counts()
    sys.stderr.write(
        "%s %s: %d role(s), %d trust statement(s), %d finding(s) "
        "(%d critical, %d high, %d medium, %d low, %d info) -> %s\n"
        % (
            result.tool,
            result.tool_version,
            result.roles_analyzed,
            result.trust_statements_analyzed,
            len(result.findings),
            counts.get(Severity.CRITICAL, 0),
            counts.get(Severity.HIGH, 0),
            counts.get(Severity.MEDIUM, 0),
            counts.get(Severity.LOW, 0),
            counts.get(Severity.INFO, 0),
            output_path,
        )
    )


def _fail(message: str) -> None:
    sys.stderr.write("trustedge: error: %s\n" % message)


def _close_stdout_quietly() -> None:  # pragma: no cover
    try:
        sys.stdout.close()
    except Exception:
        pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_INPUT_ERROR

    try:
        return args.func(args)
    except ExportFormatError as exc:
        _fail(str(exc))
        return EXIT_INPUT_ERROR
    except ValueError as exc:
        _fail(str(exc))
        return EXIT_INPUT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head et al
        _close_stdout_quietly()
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("\ninterrupted\n")
        return EXIT_INPUT_ERROR
    except OSError as exc:
        _fail("file system error: %s" % exc)
        return EXIT_INPUT_ERROR
    except Exception as exc:  # pragma: no cover - defensive
        _fail(
            "unexpected internal error (%s: %s). This is a bug in TrustEdge; "
            "please report it with a synthetic export that reproduces it."
            % (type(exc).__name__, exc)
        )
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = [
    "main",
    "build_parser",
    "EXIT_OK",
    "EXIT_FINDINGS",
    "EXIT_INPUT_ERROR",
    "EXIT_INTERNAL_ERROR",
]
