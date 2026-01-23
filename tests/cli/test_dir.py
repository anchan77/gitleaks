"""
Tests for the dir command.
"""

import os
import tempfile

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
