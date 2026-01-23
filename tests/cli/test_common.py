"""
Tests for CLI common utilities and root command group.
"""

import pytest
from click.testing import CliRunner

from gitleaks.cli.common import bytes_convert, cli, format_duration


def test_bytes_convert():
    """Test byte conversion to human-readable format."""
    assert bytes_convert(0) == "0"
    assert bytes_convert(500) == "500 bytes"
    assert bytes_convert(1500) == "1.5 KB"
    assert bytes_convert(1500000) == "1.5 MB"
    assert bytes_convert(1500000000) == "1.5 GB"
    assert bytes_convert(1000) == "1 KB"
    assert bytes_convert(1000000) == "1 MB"


def test_format_duration():
    """Test duration formatting."""
    assert "µs" in format_duration(0.0001)
    assert "ms" in format_duration(0.001)
    assert "ms" in format_duration(0.5)
    assert "s" in format_duration(1.5)
    assert "m" in format_duration(90)
    assert "h" in format_duration(3700)


def test_cli_help():
    """Test CLI help output."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Gitleaks scans code" in result.output
    assert "--config" in result.output
    assert "--report-path" in result.output
    assert "--log-level" in result.output


def test_cli_version():
    """Test CLI version output."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "gitleaks" in result.output
    assert "version" in result.output


def test_cli_no_banner():
    """Test CLI with --no-banner flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "--help"])
    assert result.exit_code == 0
    # Just verify the command runs successfully
    assert "Gitleaks scans code" in result.output


def test_cli_with_banner():
    """Test CLI with banner (default)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    # Just verify the command runs successfully
    # Note: Banner is written to stderr, which CliRunner doesn't capture by default
    assert "Gitleaks scans code" in result.output
