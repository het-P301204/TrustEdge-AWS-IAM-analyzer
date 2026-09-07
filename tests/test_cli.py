"""CLI tests, including the exit codes CI depends on.

The distinction being defended: exit 1 means "found something", exit 2 means
"could not run". A pipeline that conflates them goes green the day someone
mistypes the export path.
"""

from __future__ import annotations

import json
import os

import pytest

from trustedge import cli


def run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class TestHelpAndVersion:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--version"])
        assert excinfo.value.code == 0
        assert "trustedge" in capsys.readouterr().out

    def test_help_flag(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "inbound trust boundary" in out
        assert "analyze" in out

    def test_no_command_prints_help_and_fails(self, capsys):
        code, out, _ = run([], capsys)
        assert code == cli.EXIT_INPUT_ERROR
        assert "usage:" in out

    def test_examples_are_in_the_epilog(self):
        assert "trustedge analyze --input" in cli.EPILOG
        assert "no AWS API calls" in cli.EPILOG

    def test_subcommand_help(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["analyze", "--help"])
        out = capsys.readouterr().out
        assert "--fail-on" in out
        assert "--include-internal" in out


class TestAnalyze:
    def test_markdown_to_stdout_by_default(self, sample_account_path, capsys):
        code, out, _ = run(["analyze", "--input", sample_account_path], capsys)
        assert code == cli.EXIT_OK
        assert out.startswith("# TrustEdge inbound trust boundary report")

    def test_analyse_spelling_is_accepted(self, sample_account_path, capsys):
        code, out, _ = run(["analyse", "--input", sample_account_path], capsys)
        assert code == cli.EXIT_OK
        assert "TrustEdge" in out

    def test_json_format_to_stdout(self, sample_account_path, capsys):
        code, out, _ = run(
            ["analyze", "--input", sample_account_path, "--format", "json"], capsys
        )
        assert code == cli.EXIT_OK
        payload = json.loads(out)
        assert payload["schema"] == "trustedge.report/1"

    def test_output_file_is_written_and_parents_created(
        self, sample_account_path, tmp_path, capsys
    ):
        target = tmp_path / "nested" / "dir" / "report.json"
        code, _, err = run(
            [
                "analyze",
                "--input",
                sample_account_path,
                "--output",
                str(target),
                "--format",
                "json",
            ],
            capsys,
        )
        assert code == cli.EXIT_OK
        assert target.exists()
        json.loads(target.read_text(encoding="utf-8"))
        assert "finding(s)" in err

    def test_format_is_inferred_from_the_output_extension(
        self, sample_account_path, tmp_path, capsys
    ):
        for name, marker in (
            ("report.json", '"schema"'),
            ("report.md", "# TrustEdge"),
            ("report.html", "<!DOCTYPE html>"),
        ):
            target = tmp_path / name
            code, _, _ = run(
                ["analyze", "--input", sample_account_path, "--output", str(target)],
                capsys,
            )
            assert code == cli.EXIT_OK
            assert marker in target.read_text(encoding="utf-8"), name

    def test_quiet_suppresses_the_stderr_summary(
        self, sample_account_path, tmp_path, capsys
    ):
        target = tmp_path / "report.md"
        code, _, err = run(
            [
                "analyze",
                "--input",
                sample_account_path,
                "--output",
                str(target),
                "--quiet",
            ],
            capsys,
        )
        assert code == cli.EXIT_OK
        assert err == ""

    def test_include_internal_changes_the_finding_count(
        self, sample_account_path, capsys
    ):
        _, default_out, _ = run(
            ["analyze", "--input", sample_account_path, "--format", "json"], capsys
        )
        _, internal_out, _ = run(
            [
                "analyze",
                "--input",
                sample_account_path,
                "--format",
                "json",
                "--include-internal",
            ],
            capsys,
        )
        default = json.loads(default_out)["summary"]["findings_total"]
        internal = json.loads(internal_out)["summary"]["findings_total"]
        assert internal > default

    def test_max_findings_limits_the_markdown_report(
        self, sample_account_path, capsys
    ):
        code, out, _ = run(
            ["analyze", "--input", sample_account_path, "--max-findings", "2"], capsys
        )
        assert code == cli.EXIT_OK
        assert "Showing the 2 highest-ranked" in out

    def test_max_findings_must_be_positive(self, sample_account_path, capsys):
        code, _, err = run(
            ["analyze", "--input", sample_account_path, "--max-findings", "0"], capsys
        )
        assert code == cli.EXIT_INPUT_ERROR
        assert "1 or greater" in err

    def test_the_authorization_details_shape_is_accepted_directly(
        self, authorization_details_path, capsys
    ):
        code, out, _ = run(
            ["analyze", "--input", authorization_details_path, "--format", "json"],
            capsys,
        )
        assert code == cli.EXIT_OK
        payload = json.loads(out)
        assert payload["summary"]["roles_analyzed"] >= 1


class TestExitCodes:
    def test_clean_run_is_zero_without_fail_on(self, sample_account_path, capsys):
        code, _, _ = run(["analyze", "--input", sample_account_path], capsys)
        assert code == cli.EXIT_OK

    def test_fail_on_critical_returns_one(self, sample_account_path, capsys):
        code, _, err = run(
            [
                "analyze",
                "--input",
                sample_account_path,
                "--fail-on",
                "critical",
                "--format",
                "json",
            ],
            capsys,
        )
        assert code == cli.EXIT_FINDINGS
        assert "at CRITICAL or above" in err

    def test_fail_on_high_also_triggers_on_critical(
        self, sample_account_path, capsys
    ):
        code, _, _ = run(
            ["analyze", "--input", sample_account_path, "--fail-on", "high"], capsys
        )
        assert code == cli.EXIT_FINDINGS

    def test_fail_on_a_threshold_nothing_reaches_returns_zero(
        self, minimal_path, capsys
    ):
        code, _, _ = run(
            ["analyze", "--input", minimal_path, "--fail-on", "critical"], capsys
        )
        assert code == cli.EXIT_OK

    def test_missing_input_file_is_an_input_error_not_a_finding(
        self, tmp_path, capsys
    ):
        code, _, err = run(
            ["analyze", "--input", str(tmp_path / "nope.json")], capsys
        )
        assert code == cli.EXIT_INPUT_ERROR
        assert "does not exist" in err

    def test_invalid_json_is_an_input_error(self, tmp_path, capsys):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        code, _, err = run(["analyze", "--input", str(path)], capsys)
        assert code == cli.EXIT_INPUT_ERROR
        assert "not valid JSON" in err

    def test_a_json_array_input_is_an_input_error(self, tmp_path, capsys):
        path = tmp_path / "array.json"
        path.write_text("[]", encoding="utf-8")
        code, _, err = run(["analyze", "--input", str(path)], capsys)
        assert code == cli.EXIT_INPUT_ERROR
        assert "expected an object" in err

    def test_unknown_format_is_rejected_by_argparse(self, sample_account_path):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(
                ["analyze", "--input", sample_account_path, "--format", "pdf"]
            )
        assert excinfo.value.code == 2

    def test_incomplete_export_is_reported_on_stderr(self, malformed_path, capsys):
        code, _, err = run(
            ["analyze", "--input", malformed_path, "--format", "json"], capsys
        )
        assert code == cli.EXIT_OK
        assert "coverage is" in err


class TestValidate:
    def test_clean_export_reports_no_problems(self, minimal_path, capsys):
        code, out, _ = run(["validate", "--input", minimal_path], capsys)
        assert code == cli.EXIT_OK
        assert "No problems found" in out
        assert "roles parsed:" in out
        assert "account id:" in out

    def test_malformed_export_lists_the_problems_and_exits_two(
        self, malformed_path, capsys
    ):
        code, out, _ = run(["validate", "--input", malformed_path], capsys)
        assert code == cli.EXIT_INPUT_ERROR
        assert "ERROR" in out
        assert "trust_policy_unreadable" in out
        assert "error(s)" in out

    def test_json_output(self, malformed_path, capsys):
        code, out, _ = run(
            ["validate", "--input", malformed_path, "--format", "json"], capsys
        )
        assert code == cli.EXIT_INPUT_ERROR
        payload = json.loads(out)
        assert payload["roles_parsed"] >= 8
        assert payload["errors"]

    def test_roles_with_unusable_trust_policies_are_named(
        self, malformed_path, capsys
    ):
        _, out, _ = run(["validate", "--input", malformed_path], capsys)
        assert "no-trust-policy" in out

    def test_sample_account_validates_cleanly(self, sample_account_path, capsys):
        code, out, _ = run(["validate", "--input", sample_account_path], capsys)
        assert code == cli.EXIT_OK, out


class TestConvertCommand:
    def test_converts_to_stdout(self, authorization_details_path, capsys):
        code, out, err = run(
            ["convert", "--input", authorization_details_path], capsys
        )
        assert code == cli.EXIT_OK
        export = json.loads(out)
        assert export["roles"]
        assert export["account_id"] == "111122223333"
        assert "lacks IAM OIDC" in err or "does not return IAM OIDC" in err

    def test_converts_to_a_file(self, authorization_details_path, tmp_path, capsys):
        target = tmp_path / "export.json"
        code, _, _ = run(
            [
                "convert",
                "--input",
                authorization_details_path,
                "--output",
                str(target),
            ],
            capsys,
        )
        assert code == cli.EXIT_OK
        assert json.loads(target.read_text(encoding="utf-8"))["roles"]

    def test_add_merges_supplementary_context(
        self, authorization_details_path, tmp_path, capsys
    ):
        supplement = tmp_path / "context.json"
        supplement.write_text(
            json.dumps(
                {
                    "organization_id": "o-test",
                    "vendor_accounts": {"444455556666": "Test Vendor"},
                    "not_a_supported_key": True,
                }
            ),
            encoding="utf-8",
        )
        code, out, err = run(
            [
                "convert",
                "--input",
                authorization_details_path,
                "--add",
                str(supplement),
            ],
            capsys,
        )
        assert code == cli.EXIT_OK
        export = json.loads(out)
        assert export["organization_id"] == "o-test"
        assert "not_a_supported_key" not in export
        assert "supported keys" in err.lower() or "Supported keys" in err

    def test_converting_a_native_export_is_rejected_with_advice(
        self, sample_account_path, capsys
    ):
        code, _, err = run(["convert", "--input", sample_account_path], capsys)
        assert code == cli.EXIT_INPUT_ERROR
        assert "trustedge analyze" in err

    def test_the_converted_export_is_analysable(
        self, authorization_details_path, tmp_path, capsys
    ):
        target = tmp_path / "export.json"
        run(
            [
                "convert",
                "--input",
                authorization_details_path,
                "--output",
                str(target),
            ],
            capsys,
        )
        code, out, _ = run(
            ["analyze", "--input", str(target), "--format", "json"], capsys
        )
        assert code == cli.EXIT_OK
        assert json.loads(out)["summary"]["roles_analyzed"] >= 1


class TestServeArgumentParsing:
    def test_serve_defaults_to_loopback(self):
        parser = cli.build_parser()
        args = parser.parse_args(["serve"])
        assert args.host == "127.0.0.1"
        assert args.port == 8765

    def test_serve_accepts_host_and_port(self):
        parser = cli.build_parser()
        args = parser.parse_args(["serve", "--host", "0.0.0.0", "--port", "9000"])
        assert args.host == "0.0.0.0"
        assert args.port == 9000


class TestFileWriting:
    def test_writes_utf8_with_unix_newlines(self, sample_account_path, tmp_path, capsys):
        target = tmp_path / "report.md"
        run(
            ["analyze", "--input", sample_account_path, "--output", str(target)],
            capsys,
        )
        raw = target.read_bytes()
        assert b"\r\n" not in raw
        raw.decode("utf-8")

    def test_existing_file_is_overwritten(self, minimal_path, tmp_path, capsys):
        target = tmp_path / "report.md"
        target.write_text("stale content", encoding="utf-8")
        run(["analyze", "--input", minimal_path, "--output", str(target)], capsys)
        assert "stale content" not in target.read_text(encoding="utf-8")

    def test_output_directory_is_created(self, minimal_path, tmp_path, capsys):
        target = tmp_path / "a" / "b" / "c.md"
        run(["analyze", "--input", minimal_path, "--output", str(target)], capsys)
        assert os.path.isfile(str(target))
