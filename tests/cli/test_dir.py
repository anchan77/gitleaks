"""
Tests for the dir command.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from gitleaks.cli.common import cli


def test_dir_command_help():
    """Test dir command help output."""
    runner = CliRunner()
    result = runner.invoke(cli, ["dir", "--help"])
    assert result.exit_code == 0
    assert "Scan directories or files for secrets" in result.output
    assert "--follow-symlinks" in result.output


def test_dir_command_default_path():
    """Test dir command with default path (current directory)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "dir"])
    assert result.exit_code == 0
    assert "configuration loaded successfully" in result.output


def test_dir_command_with_path():
    """Test dir command with specific path."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(cli, ["--no-banner", "dir", tmpdir])
        assert result.exit_code == 0
        assert "configuration loaded successfully" in result.output


def test_dir_command_nonexistent_path():
    """Test dir command with non-existent path."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "dir", "/nonexistent/path/xyz"])
    # Click returns exit code 2 for usage errors (invalid path)
    assert result.exit_code == 2
    # The error message should indicate the path doesn't exist
    assert "does not exist" in result.output.lower()


def test_dir_command_with_follow_symlinks():
    """Test dir command with --follow-symlinks flag."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(cli, ["--no-banner", "dir", "--follow-symlinks", tmpdir])
        assert result.exit_code == 0
        assert "configuration loaded successfully" in result.output


def test_dir_command_with_log_level():
    """Test dir command with different log levels."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(cli, ["--no-banner", "--log-level", "debug", "dir", tmpdir])
        assert result.exit_code == 0
        # Debug level should show additional logging


def test_dir_command_with_timeout():
    """Test dir command with timeout flag."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(cli, ["--no-banner", "--timeout", "5", "dir", tmpdir])
        assert result.exit_code == 0
        assert "configuration loaded successfully" in result.output


def test_dir_command_with_testdata():
    """
    End-to-end integration test that scans testdata/repos/nogit/ and verifies JSON output.

    This test verifies:
    - Exit code is 1 (default exit code when leaks are found)
    - JSON report contains exactly 2 findings
    - Both findings are for the aws-access-token rule
    - Files are testdata/repos/nogit/api.go and testdata/repos/nogit/main.go
    - Secret value is AKIALALEMEL33243OLIA
    - Line numbers and other metadata are correct
    """
    runner = CliRunner()

    # Determine the path to testdata/repos/nogit relative to this test file
    test_file_dir = Path(__file__).parent
    repo_root = test_file_dir.parent.parent
    testdata_path = repo_root / "testdata" / "repos" / "nogit"

    if not testdata_path.exists():
        pytest.skip("Testdata directory not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "report.json")

        # Run gitleaks dir command with JSON report
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "--report-path", report_path,
                "--report-format", "json",
                "dir",
                str(testdata_path)
            ]
        )

        # Verify exit code is 1 (leaks found with default exit code)
        assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}"

        # Verify report file was created
        assert os.path.exists(report_path), "Report file should be created"

        # Load and parse the JSON report
        with open(report_path, "r") as f:
            findings = json.load(f)

        # Verify exactly 2 findings
        assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}"

        # Verify both findings are for aws-access-token rule
        for finding in findings:
            assert finding["RuleID"] == "aws-access-token", \
                f"Expected rule 'aws-access-token', got '{finding['RuleID']}'"

        # Verify the files
        files = sorted([finding["File"] for finding in findings])
        assert any("api.go" in f for f in files), "Should find api.go"
        assert any("main.go" in f for f in files), "Should find main.go"

        # Verify the secret value
        for finding in findings:
            assert finding["Secret"] == "AKIALALEMEL33243OLIA", \
                f"Expected secret 'AKIALALEMEL33243OLIA', got '{finding['Secret']}'"
            assert finding["Match"] == "AKIALALEMEL33243OLIA", \
                f"Expected match 'AKIALALEMEL33243OLIA', got '{finding['Match']}'"

        # Verify line numbers (both secrets are on line 21)
        for finding in findings:
            assert finding["StartLine"] == 21, \
                f"Expected line 21, got {finding['StartLine']}"
            assert finding["EndLine"] == 21, \
                f"Expected line 21, got {finding['EndLine']}"

        # Verify start/end columns
        for finding in findings:
            assert finding["StartColumn"] == 16, \
                f"Expected start column 16, got {finding['StartColumn']}"
            assert finding["EndColumn"] == 35, \
                f"Expected end column 35, got {finding['EndColumn']}"

        # Verify fingerprints are unique and correctly formatted
        fingerprints = [finding["Fingerprint"] for finding in findings]
        assert len(set(fingerprints)) == 2, "Fingerprints should be unique"
        for fp in fingerprints:
            assert "aws-access-token:21" in fp, \
                f"Fingerprint should contain rule and line: {fp}"

        # Verify description is present
        for finding in findings:
            assert "AWS" in finding["Description"], \
                "Description should mention AWS"
            assert len(finding["Description"]) > 0, \
                "Description should not be empty"

        # Verify entropy is calculated
        for finding in findings:
            assert finding["Entropy"] > 0, \
                f"Entropy should be positive, got {finding['Entropy']}"

        # Verify commit/author fields are empty (not a git repo)
        for finding in findings:
            assert finding["Commit"] == "", "Commit should be empty for dir scan"
            assert finding["Author"] == "", "Author should be empty for dir scan"
            assert finding["Email"] == "", "Email should be empty for dir scan"
            assert finding["Date"] == "", "Date should be empty for dir scan"
            assert finding["Message"] == "", "Message should be empty for dir scan"
