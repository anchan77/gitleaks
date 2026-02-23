#!/usr/bin/env python3
"""
BE Testing - CLI Contract Validation Tests

Generated pytest script to validate the CLI spec against the running application.
Each command is tested as a parameterized test case using pytest.

This script supports two modes:
1. SRC Validation: Tests commands and captures outputs (no expected_stdout/stderr)
2. DST Contract Validation: Tests commands and validates outputs match expected

Generated at: 2026-02-23T22:13:30.466085+00:00
Project: gitleaks-to-python
Milestone: 1
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

# =============================================================================
# Test Configuration (embedded from spec validation)
# =============================================================================

# Parse JSON at runtime to handle null -> None, true -> True, false -> False
TEST_CASES = json.loads(r'''[
    {
        "name": "test_root_help_output",
        "category": "HELP_OUTPUT",
        "description": "Verify root --help shows usage information with all subcommands listed",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "Gitleaks scans code, past or present, for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_short_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify root -h shows usage information",
        "command": "gitleaks",
        "args": [
            "-h"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "Gitleaks scans code, past or present, for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_lists_git_command",
        "category": "HELP_OUTPUT",
        "description": "Verify root help lists the 'git' subcommand",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "git",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_lists_dir_command",
        "category": "HELP_OUTPUT",
        "description": "Verify root help lists the 'dir' subcommand",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "dir",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_lists_stdin_command",
        "category": "HELP_OUTPUT",
        "description": "Verify root help lists the 'stdin' subcommand",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "stdin",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_lists_version_command",
        "category": "HELP_OUTPUT",
        "description": "Verify root help lists the 'version' subcommand",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "version",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_does_not_list_protect_command",
        "category": "HELP_OUTPUT",
        "description": "Verify root help does NOT list the deprecated/hidden 'protect' subcommand",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout_excludes": "protect",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_shows_config_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify root help shows --config/-c persistent flag",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--config",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_shows_verbose_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify root help shows --verbose/-v persistent flag",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--verbose",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_shows_report_path_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify root help shows --report-path/-r persistent flag",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--report-path",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_help_shows_exit_code_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify root help shows --exit-code persistent flag",
        "command": "gitleaks",
        "args": [
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--exit-code",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_output",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' shows git subcommand usage",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan git repositories for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_shows_platform_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' shows --platform flag",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--platform",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_shows_staged_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' shows --staged flag",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--staged",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_shows_pre_commit_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' shows --pre-commit flag",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--pre-commit",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_shows_log_opts_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' shows --log-opts flag",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--log-opts",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_help_shows_inherited_config_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'git --help' also shows inherited --config persistent flag",
        "command": "gitleaks",
        "args": [
            "git",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--config",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_help_output",
        "category": "HELP_OUTPUT",
        "description": "Verify 'dir --help' shows dir subcommand usage",
        "command": "gitleaks",
        "args": [
            "dir",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_help_shows_follow_symlinks_flag",
        "category": "HELP_OUTPUT",
        "description": "Verify 'dir --help' shows --follow-symlinks flag",
        "command": "gitleaks",
        "args": [
            "dir",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "--follow-symlinks",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_stdin_help_output",
        "category": "HELP_OUTPUT",
        "description": "Verify 'stdin --help' shows stdin subcommand usage",
        "command": "gitleaks",
        "args": [
            "stdin",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "detect secrets from stdin",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_version_help_output",
        "category": "HELP_OUTPUT",
        "description": "Verify 'version --help' shows version subcommand usage",
        "command": "gitleaks",
        "args": [
            "version",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "display gitleaks version",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_version_subcommand",
        "category": "VERSION_OUTPUT",
        "description": "Verify 'version' subcommand prints the version string",
        "command": "gitleaks",
        "args": [
            "version"
        ],
        "expected_exit_code": 0,
        "expected_stdout": ".",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_root_version_flag",
        "category": "VERSION_OUTPUT",
        "description": "Verify root --version flag prints version",
        "command": "gitleaks",
        "args": [
            "--version"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "gitleaks version",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_unknown_flag_exit_code",
        "category": "INVALID_OPTIONS",
        "description": "Unknown flag should exit with code 126",
        "command": "gitleaks",
        "args": [
            "--unknown-flag"
        ],
        "expected_exit_code": 126,
        "expected_stdout": null,
        "expected_stderr": "unknown flag",
        "timeout_seconds": 10
    },
    {
        "name": "test_unknown_subcommand",
        "category": "INVALID_ARGS",
        "description": "Unknown subcommand should produce an error",
        "command": "gitleaks",
        "args": [
            "nonexistent"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "unknown command",
        "timeout_seconds": 10
    },
    {
        "name": "test_git_too_many_args",
        "category": "INVALID_ARGS",
        "description": "git subcommand with more than 1 positional arg should fail",
        "command": "gitleaks",
        "args": [
            "git",
            "path1",
            "path2"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "accepts at most 1 arg",
        "timeout_seconds": 10
    },
    {
        "name": "test_git_unknown_flag",
        "category": "INVALID_OPTIONS",
        "description": "Unknown flag on git subcommand should exit with 126",
        "command": "gitleaks",
        "args": [
            "git",
            "--nonexistent-flag"
        ],
        "expected_exit_code": 126,
        "expected_stdout": null,
        "expected_stderr": "unknown flag",
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_unknown_flag",
        "category": "INVALID_OPTIONS",
        "description": "Unknown flag on dir subcommand should exit with 126",
        "command": "gitleaks",
        "args": [
            "dir",
            "--nonexistent-flag"
        ],
        "expected_exit_code": 126,
        "expected_stdout": null,
        "expected_stderr": "unknown flag",
        "timeout_seconds": 10
    },
    {
        "name": "test_stdin_unknown_flag",
        "category": "INVALID_OPTIONS",
        "description": "Unknown flag on stdin subcommand should exit with 126",
        "command": "gitleaks",
        "args": [
            "stdin",
            "--nonexistent-flag"
        ],
        "expected_exit_code": 126,
        "expected_stdout": null,
        "expected_stderr": "unknown flag",
        "timeout_seconds": 10
    },
    {
        "name": "test_invalid_config_path",
        "category": "INVALID_OPTIONS",
        "description": "Invalid config file path should produce a fatal error",
        "command": "gitleaks",
        "args": [
            "dir",
            "--config",
            "/nonexistent/path/to/config.toml",
            "."
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "unable to load gitleaks config",
        "timeout_seconds": 10
    },
    {
        "name": "test_invalid_log_level",
        "category": "INVALID_OPTIONS",
        "description": "Invalid log level should produce a warning (not a fatal error)",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "invalid_level"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_exit_code_flag_type_validation",
        "category": "INVALID_OPTIONS",
        "description": "Non-integer value for --exit-code should fail",
        "command": "gitleaks",
        "args": [
            "dir",
            "--exit-code",
            "abc"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "invalid argument",
        "timeout_seconds": 10
    },
    {
        "name": "test_max_target_megabytes_type_validation",
        "category": "INVALID_OPTIONS",
        "description": "Non-integer value for --max-target-megabytes should fail",
        "command": "gitleaks",
        "args": [
            "dir",
            "--max-target-megabytes",
            "abc"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "invalid argument",
        "timeout_seconds": 10
    },
    {
        "name": "test_max_decode_depth_type_validation",
        "category": "INVALID_OPTIONS",
        "description": "Non-integer value for --max-decode-depth should fail",
        "command": "gitleaks",
        "args": [
            "dir",
            "--max-decode-depth",
            "abc"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "invalid argument",
        "timeout_seconds": 10
    },
    {
        "name": "test_timeout_type_validation",
        "category": "INVALID_OPTIONS",
        "description": "Non-integer value for --timeout should fail",
        "command": "gitleaks",
        "args": [
            "dir",
            "--timeout",
            "abc"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "invalid argument",
        "timeout_seconds": 10
    },
    {
        "name": "test_redact_type_validation",
        "category": "INVALID_OPTIONS",
        "description": "Non-integer value for --redact should fail",
        "command": "gitleaks",
        "args": [
            "dir",
            "--redact=abc"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "invalid argument",
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_alias_directory",
        "category": "HAPPY_PATH",
        "description": "Verify 'directory' works as an alias for 'dir'",
        "command": "gitleaks",
        "args": [
            "directory",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_alias_file",
        "category": "HAPPY_PATH",
        "description": "Verify 'file' works as an alias for 'dir'",
        "command": "gitleaks",
        "args": [
            "file",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_no_banner_flag",
        "category": "HAPPY_PATH",
        "description": "Verify --no-banner suppresses the banner output",
        "command": "gitleaks",
        "args": [
            "version",
            "--no-banner"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr_excludes": "gitleaks",
        "timeout_seconds": 10
    },
    {
        "name": "test_banner_displayed_by_default",
        "category": "HAPPY_PATH",
        "description": "Verify banner is displayed by default when running a scan command",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_config_flag_short_form",
        "category": "HAPPY_PATH",
        "description": "Verify -c short flag is accepted for config",
        "command": "gitleaks",
        "args": [
            "dir",
            "-c",
            "/nonexistent/config.toml",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_verbose_flag_short_form",
        "category": "HAPPY_PATH",
        "description": "Verify -v short flag is accepted for verbose",
        "command": "gitleaks",
        "args": [
            "version",
            "-v"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_trace",
        "category": "HAPPY_PATH",
        "description": "Verify --log-level trace is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "trace"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_debug",
        "category": "HAPPY_PATH",
        "description": "Verify --log-level debug is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "debug"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_warn",
        "category": "HAPPY_PATH",
        "description": "Verify --log-level warn is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "warn"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_error",
        "category": "HAPPY_PATH",
        "description": "Verify --log-level error is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "error"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_fatal",
        "category": "HAPPY_PATH",
        "description": "Verify --log-level fatal is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--log-level",
            "fatal"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_log_level_short_flag",
        "category": "HAPPY_PATH",
        "description": "Verify -l short flag is accepted for log-level",
        "command": "gitleaks",
        "args": [
            "version",
            "-l",
            "debug"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_exit_code_custom_value",
        "category": "HAPPY_PATH",
        "description": "Verify --exit-code accepts a custom integer value",
        "command": "gitleaks",
        "args": [
            "dir",
            "--exit-code",
            "42",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_report_format_json_flag",
        "category": "HAPPY_PATH",
        "description": "Verify --report-format json is accepted on help",
        "command": "gitleaks",
        "args": [
            "dir",
            "--report-format",
            "json",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_report_format_short_flag",
        "category": "HAPPY_PATH",
        "description": "Verify -f short flag is accepted for report-format",
        "command": "gitleaks",
        "args": [
            "dir",
            "-f",
            "csv",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_report_path_short_flag",
        "category": "HAPPY_PATH",
        "description": "Verify -r short flag is accepted for report-path",
        "command": "gitleaks",
        "args": [
            "dir",
            "-r",
            "/tmp/report.json",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_baseline_path_short_flag",
        "category": "HAPPY_PATH",
        "description": "Verify -b short flag is accepted for baseline-path",
        "command": "gitleaks",
        "args": [
            "dir",
            "-b",
            "/tmp/baseline.json",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_gitleaks_ignore_path_short_flag",
        "category": "HAPPY_PATH",
        "description": "Verify -i short flag is accepted for gitleaks-ignore-path",
        "command": "gitleaks",
        "args": [
            "dir",
            "-i",
            "/tmp/ignore",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_redact_no_value",
        "category": "HAPPY_PATH",
        "description": "Verify --redact without value defaults to 100%",
        "command": "gitleaks",
        "args": [
            "dir",
            "--redact",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_redact_with_value",
        "category": "HAPPY_PATH",
        "description": "Verify --redact=50 is accepted",
        "command": "gitleaks",
        "args": [
            "dir",
            "--redact=50",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_max_decode_depth_custom",
        "category": "HAPPY_PATH",
        "description": "Verify --max-decode-depth accepts custom integer",
        "command": "gitleaks",
        "args": [
            "dir",
            "--max-decode-depth",
            "10",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_max_archive_depth_custom",
        "category": "HAPPY_PATH",
        "description": "Verify --max-archive-depth accepts custom integer",
        "command": "gitleaks",
        "args": [
            "dir",
            "--max-archive-depth",
            "3",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_timeout_custom",
        "category": "HAPPY_PATH",
        "description": "Verify --timeout accepts custom integer (seconds)",
        "command": "gitleaks",
        "args": [
            "dir",
            "--timeout",
            "60",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_max_target_megabytes_custom",
        "category": "HAPPY_PATH",
        "description": "Verify --max-target-megabytes accepts custom integer",
        "command": "gitleaks",
        "args": [
            "dir",
            "--max-target-megabytes",
            "50",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_enable_rule_single",
        "category": "HAPPY_PATH",
        "description": "Verify --enable-rule accepts a single rule ID",
        "command": "gitleaks",
        "args": [
            "dir",
            "--enable-rule",
            "generic-api-key",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_enable_rule_multiple",
        "category": "HAPPY_PATH",
        "description": "Verify --enable-rule accepts multiple rule IDs (comma-separated or repeated)",
        "command": "gitleaks",
        "args": [
            "dir",
            "--enable-rule",
            "generic-api-key",
            "--enable-rule",
            "aws-access-key",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_no_color_flag",
        "category": "HAPPY_PATH",
        "description": "Verify --no-color flag is accepted",
        "command": "gitleaks",
        "args": [
            "version",
            "--no-color"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_ignore_gitleaks_allow_flag",
        "category": "HAPPY_PATH",
        "description": "Verify --ignore-gitleaks-allow flag is accepted",
        "command": "gitleaks",
        "args": [
            "dir",
            "--ignore-gitleaks-allow",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_config_env_var_gitleaks_config",
        "category": "HAPPY_PATH",
        "description": "Verify GITLEAKS_CONFIG env var is used when --config is not set",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--help"
        ],
        "env": {
            "GITLEAKS_CONFIG": "/tmp/test_config.toml"
        },
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_config_env_var_gitleaks_config_toml",
        "category": "HAPPY_PATH",
        "description": "Verify GITLEAKS_CONFIG_TOML env var is accepted (inline TOML content)",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--help"
        ],
        "env": {
            "GITLEAKS_CONFIG_TOML": "title = \"test\""
        },
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_dir_scan_empty_directory",
        "category": "HAPPY_PATH",
        "description": "Verify dir command can scan an empty directory with no findings",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "/tmp/gitleaks_test_empty"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_empty"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_empty"
            ]
        }
    },
    {
        "name": "test_dir_scan_file_with_secret",
        "category": "HAPPY_PATH",
        "description": "Verify dir command detects a secret in a file and exits with default exit code 1",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "/tmp/gitleaks_test_secret"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_secret",
                "echo 'aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"' > /tmp/gitleaks_test_secret/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_secret"
            ]
        }
    },
    {
        "name": "test_dir_scan_custom_exit_code",
        "category": "HAPPY_PATH",
        "description": "Verify dir command uses custom exit code when leaks are found",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--exit-code",
            "42",
            "/tmp/gitleaks_test_exitcode"
        ],
        "expected_exit_code": 42,
        "expected_stdout": null,
        "expected_stderr": "leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_exitcode",
                "echo 'aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"' > /tmp/gitleaks_test_exitcode/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_exitcode"
            ]
        }
    },
    {
        "name": "test_dir_scan_exit_code_zero_for_clean",
        "category": "HAPPY_PATH",
        "description": "Verify dir command exits 0 when no leaks are found even with custom exit code",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--exit-code",
            "42",
            "/tmp/gitleaks_test_clean"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_clean",
                "echo 'hello world' > /tmp/gitleaks_test_clean/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_clean"
            ]
        }
    },
    {
        "name": "test_dir_scan_with_json_report",
        "category": "FILE_INPUT",
        "description": "Verify dir command generates a JSON report when --report-path is set",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/tmp/gitleaks_test_report.json",
            "--report-format",
            "json",
            "/tmp/gitleaks_test_report_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_report_dir",
                "echo 'hello world' > /tmp/gitleaks_test_report_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_report_dir",
                "/tmp/gitleaks_test_report.json"
            ]
        }
    },
    {
        "name": "test_dir_scan_with_csv_report",
        "category": "FILE_INPUT",
        "description": "Verify dir command generates a CSV report when --report-format csv is set",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/tmp/gitleaks_test_report.csv",
            "--report-format",
            "csv",
            "/tmp/gitleaks_test_csv_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_csv_dir",
                "echo 'hello world' > /tmp/gitleaks_test_csv_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_csv_dir",
                "/tmp/gitleaks_test_report.csv"
            ]
        }
    },
    {
        "name": "test_dir_scan_report_format_inferred_from_extension",
        "category": "FILE_INPUT",
        "description": "Verify report format is inferred from file extension when --report-format is not set",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/tmp/gitleaks_inferred.json",
            "/tmp/gitleaks_test_infer_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_infer_dir",
                "echo 'hello world' > /tmp/gitleaks_test_infer_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_infer_dir",
                "/tmp/gitleaks_inferred.json"
            ]
        }
    },
    {
        "name": "test_dir_scan_report_to_stdout",
        "category": "HAPPY_PATH",
        "description": "Verify --report-path - sends report to stdout",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "-",
            "--report-format",
            "json",
            "/tmp/gitleaks_test_stdout_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "[",
        "expected_stderr": null,
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_stdout_dir",
                "echo 'hello world' > /tmp/gitleaks_test_stdout_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_stdout_dir"
            ]
        }
    },
    {
        "name": "test_stdin_scan_no_leaks",
        "category": "PIPE_INPUT",
        "description": "Verify stdin command with clean input exits 0",
        "command": "gitleaks",
        "args": [
            "stdin",
            "--no-banner"
        ],
        "stdin": "hello world this is clean content",
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30
    },
    {
        "name": "test_stdin_scan_with_secret",
        "category": "PIPE_INPUT",
        "description": "Verify stdin command detects a secret and exits with code 1",
        "command": "gitleaks",
        "args": [
            "stdin",
            "--no-banner"
        ],
        "stdin": "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"",
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "leaks found",
        "timeout_seconds": 30
    },
    {
        "name": "test_stdin_scan_empty_input",
        "category": "PIPE_INPUT",
        "description": "Verify stdin command with empty input exits 0",
        "command": "gitleaks",
        "args": [
            "stdin",
            "--no-banner"
        ],
        "stdin": "",
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30
    },
    {
        "name": "test_dir_scan_with_custom_config",
        "category": "FILE_INPUT",
        "description": "Verify dir command accepts a custom config file via --config",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--config",
            "/tmp/gitleaks_test_custom_config.toml",
            "/tmp/gitleaks_test_custom_cfg_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_custom_cfg_dir",
                "echo 'hello world' > /tmp/gitleaks_test_custom_cfg_dir/test.txt",
                "printf 'title = \"custom config\"\\n[[rules]]\\nid = \"test-rule\"\\nregex = \"NEVER_MATCH_THIS_12345\"\\nkeywords = [\"nevermatch\"]\\n' > /tmp/gitleaks_test_custom_config.toml"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_custom_cfg_dir",
                "/tmp/gitleaks_test_custom_config.toml"
            ]
        }
    },
    {
        "name": "test_dir_scan_with_config_env_var",
        "category": "FILE_INPUT",
        "description": "Verify dir command uses GITLEAKS_CONFIG env var for config path",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "/tmp/gitleaks_test_env_cfg_dir"
        ],
        "env": {
            "GITLEAKS_CONFIG": "/tmp/gitleaks_test_env_config.toml"
        },
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_env_cfg_dir",
                "echo 'hello world' > /tmp/gitleaks_test_env_cfg_dir/test.txt",
                "printf 'title = \"env config\"\\n[[rules]]\\nid = \"test-rule\"\\nregex = \"NEVER_MATCH_THIS_12345\"\\nkeywords = [\"nevermatch\"]\\n' > /tmp/gitleaks_test_env_config.toml"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_env_cfg_dir",
                "/tmp/gitleaks_test_env_config.toml"
            ]
        }
    },
    {
        "name": "test_dir_scan_with_inline_config_env_var",
        "category": "FILE_INPUT",
        "description": "Verify dir command uses GITLEAKS_CONFIG_TOML env var for inline config",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "/tmp/gitleaks_test_inline_cfg_dir"
        ],
        "env": {
            "GITLEAKS_CONFIG_TOML": "title = \"inline\"\n[[rules]]\nid = \"test-rule\"\nregex = \"NEVER_MATCH_THIS_12345\"\nkeywords = [\"nevermatch\"]"
        },
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_inline_cfg_dir",
                "echo 'hello world' > /tmp/gitleaks_test_inline_cfg_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_inline_cfg_dir"
            ]
        }
    },
    {
        "name": "test_dir_scan_config_cli_takes_precedence_over_env",
        "category": "HAPPY_PATH",
        "description": "Verify --config flag takes precedence over GITLEAKS_CONFIG env var",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--config",
            "/tmp/gitleaks_test_prec_config.toml",
            "/tmp/gitleaks_test_prec_dir"
        ],
        "env": {
            "GITLEAKS_CONFIG": "/tmp/gitleaks_test_prec_env_config.toml"
        },
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_prec_dir",
                "echo 'hello' > /tmp/gitleaks_test_prec_dir/test.txt",
                "echo 'title = \"cli config\"' > /tmp/gitleaks_test_prec_config.toml"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_prec_dir",
                "/tmp/gitleaks_test_prec_config.toml"
            ]
        }
    },
    {
        "name": "test_dir_scan_nonexistent_path",
        "category": "INVALID_ARGS",
        "description": "Verify dir command with non-existent path fails",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "/nonexistent/path/that/does/not/exist"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_scan_not_a_repo",
        "category": "INVALID_ARGS",
        "description": "Verify git command on non-git directory fails",
        "command": "gitleaks",
        "args": [
            "git",
            "--no-banner",
            "/tmp/gitleaks_test_not_repo"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_not_repo",
                "echo 'hello' > /tmp/gitleaks_test_not_repo/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_not_repo"
            ]
        }
    },
    {
        "name": "test_dir_scan_verbose_output",
        "category": "HAPPY_PATH",
        "description": "Verify dir command with --verbose flag shows verbose output",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--verbose",
            "/tmp/gitleaks_test_verbose_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_verbose_dir",
                "echo 'hello world' > /tmp/gitleaks_test_verbose_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_verbose_dir"
            ]
        }
    },
    {
        "name": "test_dir_scan_with_redact",
        "category": "HAPPY_PATH",
        "description": "Verify dir command with --redact flag redacts secrets in output",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--verbose",
            "--redact",
            "/tmp/gitleaks_test_redact_dir"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_redact_dir",
                "echo 'aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"' > /tmp/gitleaks_test_redact_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_redact_dir"
            ]
        }
    },
    {
        "name": "test_boundary_empty_string_config_flag",
        "category": "BOUNDARY",
        "description": "Verify --config with empty string is handled gracefully",
        "command": "gitleaks",
        "args": [
            "version",
            "--config",
            ""
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_boundary_exit_code_zero",
        "category": "BOUNDARY",
        "description": "Verify --exit-code 0 means always exit 0 even with leaks",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--exit-code",
            "0",
            "/tmp/gitleaks_test_exit0_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": null,
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_exit0_dir",
                "echo 'aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"' > /tmp/gitleaks_test_exit0_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_exit0_dir"
            ]
        }
    },
    {
        "name": "test_boundary_max_target_megabytes_zero",
        "category": "BOUNDARY",
        "description": "Verify --max-target-megabytes 0 means no limit",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--max-target-megabytes",
            "0",
            "/tmp/gitleaks_test_mtm0_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_mtm0_dir",
                "echo 'hello world' > /tmp/gitleaks_test_mtm0_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_mtm0_dir"
            ]
        }
    },
    {
        "name": "test_boundary_timeout_zero",
        "category": "BOUNDARY",
        "description": "Verify --timeout 0 means no timeout",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--timeout",
            "0",
            "/tmp/gitleaks_test_timeout0_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_timeout0_dir",
                "echo 'hello world' > /tmp/gitleaks_test_timeout0_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_timeout0_dir"
            ]
        }
    },
    {
        "name": "test_boundary_max_decode_depth_zero",
        "category": "BOUNDARY",
        "description": "Verify --max-decode-depth 0 disables recursive decoding",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--max-decode-depth",
            "0",
            "/tmp/gitleaks_test_mdd0_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_mdd0_dir",
                "echo 'hello world' > /tmp/gitleaks_test_mdd0_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_mdd0_dir"
            ]
        }
    },
    {
        "name": "test_boundary_max_archive_depth_zero",
        "category": "BOUNDARY",
        "description": "Verify --max-archive-depth 0 (default) means no archive traversal",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--max-archive-depth",
            "0",
            "/tmp/gitleaks_test_mad0_dir"
        ],
        "expected_exit_code": 0,
        "expected_stdout": null,
        "expected_stderr": "no leaks found",
        "timeout_seconds": 30,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_mad0_dir",
                "echo 'hello world' > /tmp/gitleaks_test_mad0_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_mad0_dir"
            ]
        }
    },
    {
        "name": "test_invalid_report_format",
        "category": "INVALID_OPTIONS",
        "description": "Verify an invalid report format produces a fatal error",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/tmp/gitleaks_invalid_report.txt",
            "--report-format",
            "invalid_format",
            "/tmp/gitleaks_test_inv_fmt_dir"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "unknown report format",
        "timeout_seconds": 10,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_inv_fmt_dir",
                "echo 'hello' > /tmp/gitleaks_test_inv_fmt_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_inv_fmt_dir",
                "/tmp/gitleaks_invalid_report.txt"
            ]
        }
    },
    {
        "name": "test_report_template_without_template_format",
        "category": "INVALID_OPTIONS",
        "description": "Verify --report-template without --report-format=template produces an error",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/tmp/gitleaks_tmpl_err.json",
            "--report-format",
            "json",
            "--report-template",
            "/tmp/template.txt",
            "/tmp/gitleaks_test_tmpl_err_dir"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "Report format must be 'template'",
        "timeout_seconds": 10,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_tmpl_err_dir",
                "echo 'hello' > /tmp/gitleaks_test_tmpl_err_dir/test.txt",
                "echo '{{.}}' > /tmp/template.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_tmpl_err_dir",
                "/tmp/gitleaks_tmpl_err.json",
                "/tmp/template.txt"
            ]
        }
    },
    {
        "name": "test_report_path_unwritable",
        "category": "INVALID_OPTIONS",
        "description": "Verify unwritable --report-path produces an error",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--report-path",
            "/nonexistent_dir/report.json",
            "--report-format",
            "json",
            "/tmp/gitleaks_test_unwr_dir"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "Report path is not writable",
        "timeout_seconds": 10,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_unwr_dir",
                "echo 'hello' > /tmp/gitleaks_test_unwr_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_unwr_dir"
            ]
        }
    },
    {
        "name": "test_diagnostics_flag_http",
        "category": "HAPPY_PATH",
        "description": "Verify --diagnostics http is accepted as a valid option",
        "command": "gitleaks",
        "args": [
            "dir",
            "--diagnostics",
            "http",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_diagnostics_dir_with_http_mode_error",
        "category": "INVALID_OPTIONS",
        "description": "Verify --diagnostics-dir with http mode produces an error",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--diagnostics",
            "http",
            "--diagnostics-dir",
            "/tmp/diag",
            "/tmp/gitleaks_test_diag_dir"
        ],
        "expected_exit_code": 1,
        "expected_stdout": null,
        "expected_stderr": "should not be set in http mode",
        "timeout_seconds": 10,
        "setup": {
            "commands": [
                "mkdir -p /tmp/gitleaks_test_diag_dir",
                "echo 'hello' > /tmp/gitleaks_test_diag_dir/test.txt"
            ]
        },
        "cleanup": {
            "delete_files": [
                "/tmp/gitleaks_test_diag_dir"
            ]
        }
    },
    {
        "name": "test_git_scan_with_platform_github",
        "category": "HAPPY_PATH",
        "description": "Verify git subcommand accepts --platform github",
        "command": "gitleaks",
        "args": [
            "git",
            "--platform",
            "github",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan git repositories for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_git_scan_with_platform_gitlab",
        "category": "HAPPY_PATH",
        "description": "Verify git subcommand accepts --platform gitlab",
        "command": "gitleaks",
        "args": [
            "git",
            "--platform",
            "gitlab",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan git repositories for secrets",
        "expected_stderr": null,
        "timeout_seconds": 10
    },
    {
        "name": "test_multiple_persistent_flags_combined",
        "category": "HAPPY_PATH",
        "description": "Verify multiple persistent flags can be used together",
        "command": "gitleaks",
        "args": [
            "dir",
            "--no-banner",
            "--verbose",
            "--no-color",
            "--log-level",
            "debug",
            "--max-target-megabytes",
            "10",
            "--max-decode-depth",
            "3",
            "--help"
        ],
        "expected_exit_code": 0,
        "expected_stdout": "scan directories or files",
        "expected_stderr": null,
        "timeout_seconds": 10
    }
]''')

# CLI binary/entry point
CLI_COMMAND = "gitleaks"

# Working directory for CLI execution
WORKING_DIR = "."

# Default command timeout in seconds
DEFAULT_TIMEOUT = 30

# Response validation mode: when True, validates output against expected
VALIDATE_OUTPUT = any(
    tc.get("actual_stdout") is not None or tc.get("actual_stderr") is not None
    for tc in TEST_CASES
)

# =============================================================================
# Output Validation Utilities
# =============================================================================



def normalize_output(output: str) -> str:
    """Normalize output for comparison (strip whitespace, normalize newlines)."""
    if output is None:
        return ""
    return output.strip().replace("\r\n", "\n")


def matches_pattern(actual: str, pattern: str | None) -> bool:
    """
    Check if actual output matches the expected pattern.

    Pattern matching rules:
    - If pattern is None, always matches (no validation)
    - If pattern starts with 'regex:', use regex matching
    - Otherwise, check if pattern is contained in actual output (case-insensitive)
    """
    if pattern is None:
        return True

    actual_normalized = normalize_output(actual)

    if pattern.startswith("regex:"):
        regex_pattern = pattern[6:]  # Remove 'regex:' prefix
        return bool(re.search(regex_pattern, actual_normalized, re.IGNORECASE | re.MULTILINE))

    # Default: substring match (case-insensitive)
    return pattern.lower() in actual_normalized.lower()


def validate_cli_output(
    actual_stdout: str,
    actual_stderr: str,
    expected_stdout: str | None,
    expected_stderr: str | None,
) -> tuple[bool, list[str]]:
    """
    Validate CLI output against expected patterns.

    Args:
        actual_stdout: Actual stdout from command
        actual_stderr: Actual stderr from command
        expected_stdout: Expected stdout pattern (or None)
        expected_stderr: Expected stderr pattern (or None)

    Returns:
        tuple: (is_valid, list of violations)
    """
    violations: list[str] = []

    if expected_stdout is not None and not matches_pattern(actual_stdout, expected_stdout):
        violations.append(
            f"stdout mismatch: expected pattern '{expected_stdout}' not found in output"
        )

    if expected_stderr is not None and not matches_pattern(actual_stderr, expected_stderr):
        violations.append(
            f"stderr mismatch: expected pattern '{expected_stderr}' not found in output"
        )

    return len(violations) == 0, violations


def format_output_diff(violations: list[str]) -> str:
    """Format output differences for error message."""
    if not violations:
        return "No differences"

    output = []
    for i, diff in enumerate(violations):
        output.append(f"  - {diff}")

    return "\n".join(output)


# =============================================================================
# Test Results Collection
# =============================================================================

test_results: list[dict[str, Any]] = []


def record_result(
    name: str,
    command: str,
    args: list[str],
    expected_exit_code: int,
    actual_exit_code: int,
    passed: bool,
    duration_ms: float,
    category: str | None = None,
    description: str | None = None,
    error: str | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    output_match: bool | None = None,
    output_diff: list[str] | None = None,
) -> None:
    """Record a test result for final output."""
    result: dict[str, Any] = {
        "name": name,
        "command": command,
        "args": args,
        "expected_exit_code": expected_exit_code,
        "actual_exit_code": actual_exit_code,
        "passed": passed,
        "duration_ms": duration_ms,
        "category": category,
        "description": description,
    }
    if error:
        result["error"] = error

    # Track output validation results (for DST contract testing)
    if output_match is not None:
        result["output_match"] = output_match
    if output_diff:
        result["output_diff"] = output_diff

    # Capture outputs for validation
    if stdout:
        if passed:
            result["actual_stdout"] = stdout  # Capture more for passed tests
        else:
            result["stdout"] = stdout

    if stderr:
        if passed:
            result["actual_stderr"] = stderr
        else:
            result["stderr"] = stderr

    test_results.append(result)


# =============================================================================
# Setup and Cleanup Helpers
# =============================================================================


def run_setup(setup_config: dict[str, Any], work_dir: Path) -> bool:
    """Run setup actions before a test."""
    if not setup_config:
        return True

    try:
        # Create file
        if "create_file" in setup_config:
            file_config = setup_config["create_file"]
            file_path = work_dir / file_config["path"]
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(file_config.get("content", ""))
            print(f"Setup: Created file {file_path}")

        # Create directory
        if "create_dir" in setup_config:
            dir_path = work_dir / setup_config["create_dir"]
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"Setup: Created directory {dir_path}")

        # Run command
        if "run_command" in setup_config:
            cmd = setup_config["run_command"]
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
            )
            if result.returncode != 0:
                print(f"Setup command failed: {result.stderr}")
                return False

        return True

    except Exception as e:
        print(f"Setup error: {e}")
        return False


def run_cleanup(cleanup_config: dict[str, Any], work_dir: Path) -> None:
    """Run cleanup actions after a test (best effort)."""
    if not cleanup_config:
        return

    try:
        # Delete files
        if "delete_files" in cleanup_config:
            for file_path in cleanup_config["delete_files"]:
                full_path = work_dir / file_path
                if full_path.exists():
                    full_path.unlink()
                    print(f"Cleanup: Deleted file {full_path}")

        # Delete directories
        if "delete_dirs" in cleanup_config:
            for dir_path in cleanup_config["delete_dirs"]:
                full_path = work_dir / dir_path
                if full_path.exists():
                    shutil.rmtree(full_path)
                    print(f"Cleanup: Deleted directory {full_path}")

        # Run command
        if "run_command" in cleanup_config:
            cmd = cleanup_config["run_command"]
            subprocess.run(
                cmd,
                shell=True,
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
            )

    except Exception as e:
        print(f"Cleanup warning: {e}")


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def cli_work_dir() -> Path:
    """Get the CLI working directory."""
    return Path(WORKING_DIR)


@pytest.fixture(scope="session", autouse=True)
def verify_cli_exists() -> None:
    """Verify the CLI command exists before running tests."""
    print(f"\nVerifying CLI command exists: {CLI_COMMAND}...")

    # Check if it's a direct path
    if os.path.isfile(CLI_COMMAND):
        print(f"CLI found at: {CLI_COMMAND}")
        return

    # Check if it's in PATH
    result = shutil.which(CLI_COMMAND)
    if result:
        print(f"CLI found in PATH: {result}")
        return

    # Try common locations
    work_dir = Path(WORKING_DIR)
    common_paths = [
        work_dir / CLI_COMMAND,
        work_dir / "dist" / CLI_COMMAND,
        work_dir / "target" / "release" / CLI_COMMAND,
        work_dir / "bin" / CLI_COMMAND,
    ]

    for path in common_paths:
        if path.exists():
            print(f"CLI found at: {path}")
            return

    pytest.fail(f"CLI command '{CLI_COMMAND}' not found. Please ensure the app is built.")


# =============================================================================
# Test Cases
# =============================================================================


def get_test_ids() -> list[str]:
    """Generate test IDs for parametrization."""
    return [tc.get("name", f"test_{i}") for i, tc in enumerate(TEST_CASES)]


@pytest.mark.parametrize("test_case", TEST_CASES, ids=get_test_ids())
def test_cli_command(test_case: dict[str, Any], cli_work_dir: Path) -> None:
    """Test a single CLI command based on test case configuration."""
    # Extract test case info
    name = test_case.get("name", "unnamed")
    command = test_case.get("command", CLI_COMMAND)
    args = test_case.get("args", [])
    stdin_input = test_case.get("stdin")
    env_vars = test_case.get("env", {})
    expected_exit_code = test_case.get("expected_exit_code", 0)
    expected_stdout = test_case.get("expected_stdout")
    expected_stderr = test_case.get("expected_stderr")
    category = test_case.get("category")
    description = test_case.get("description")
    setup_config = test_case.get("setup")
    cleanup_config = test_case.get("cleanup")
    timeout = test_case.get("timeout_seconds", DEFAULT_TIMEOUT)

    # Expected outputs for DST contract validation (from SRC validation)
    actual_stdout_expected = test_case.get("actual_stdout")
    actual_stderr_expected = test_case.get("actual_stderr")

    try:
        # Run setup if configured
        if setup_config:
            if not run_setup(setup_config, cli_work_dir):
                record_result(
                    name=name,
                    command=command,
                    args=args,
                    expected_exit_code=expected_exit_code,
                    actual_exit_code=-1,
                    passed=False,
                    duration_ms=0,
                    category=category,
                    description=description,
                    error="Setup failed",
                )
                pytest.fail(f"Setup failed for test '{name}'")

        # Build full command
        full_cmd = [command] + args

        # Prepare environment
        env = os.environ.copy()
        env.update(env_vars)

        # Execute command
        start_time = time.time()
        try:
            result = subprocess.run(
                full_cmd,
                input=stdin_input,
                cwd=str(cli_work_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration_ms = (time.time() - start_time) * 1000
            actual_exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr

            # Check exit code first
            exit_code_passed = actual_exit_code == expected_exit_code
            error_msg = None if exit_code_passed else (
                f"Expected exit code {expected_exit_code}, got {actual_exit_code}"
            )

            # Check output patterns
            output_match: bool | None = None
            output_diff: list[str] | None = None

            # For DST validation, compare against captured SRC output
            if actual_stdout_expected is not None or actual_stderr_expected is not None:
                output_match, output_diff = validate_cli_output(
                    stdout,
                    stderr,
                    actual_stdout_expected,
                    actual_stderr_expected,
                )
                if not output_match:
                    error_msg = f"Output contract violation:\n{format_output_diff(output_diff)}"
            # For SRC validation or basic validation, check expected patterns
            elif expected_stdout is not None or expected_stderr is not None:
                output_match, output_diff = validate_cli_output(
                    stdout,
                    stderr,
                    expected_stdout,
                    expected_stderr,
                )
                if not output_match:
                    error_msg = f"Output pattern mismatch:\n{format_output_diff(output_diff)}"

            # Overall pass
            passed = exit_code_passed and (output_match is None or output_match)

            record_result(
                name=name,
                command=command,
                args=args,
                expected_exit_code=expected_exit_code,
                actual_exit_code=actual_exit_code,
                passed=passed,
                duration_ms=duration_ms,
                category=category,
                description=description,
                error=error_msg,
                stdout=stdout,
                stderr=stderr,
                output_match=output_match,
                output_diff=output_diff,
            )

            # pytest assertions
            if not exit_code_passed:
                pytest.fail(
                    f"Test '{name}': Expected exit code {expected_exit_code}, got {actual_exit_code}.\n"
                    f"stdout: {stdout if stdout else 'empty'}\n"
                    f"stderr: {stderr if stderr else 'empty'}"
                )

            if output_match is False:
                pytest.fail(
                    f"Test '{name}': Output validation failed.\n"
                    f"Violations:\n{format_output_diff(output_diff or [])}"
                )

        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start_time) * 1000
            record_result(
                name=name,
                command=command,
                args=args,
                expected_exit_code=expected_exit_code,
                actual_exit_code=-1,
                passed=False,
                duration_ms=duration_ms,
                category=category,
                description=description,
                error=f"Command timed out after {timeout}s",
                stdout=e.stdout if hasattr(e, 'stdout') else None,
                stderr=e.stderr if hasattr(e, 'stderr') else None,
            )
            pytest.fail(f"Test '{name}': Command timed out after {timeout}s")

    except Exception as e:
        record_result(
            name=name,
            command=command,
            args=args,
            expected_exit_code=expected_exit_code,
            actual_exit_code=-1,
            passed=False,
            duration_ms=0,
            category=category,
            description=description,
            error=f"Test error: {type(e).__name__}: {e}",
        )
        raise

    finally:
        # Always run cleanup
        if cleanup_config:
            run_cleanup(cleanup_config, cli_work_dir)


# =============================================================================
# Test Results Output
# =============================================================================


@pytest.fixture(scope="session", autouse=True)
def output_test_results(request: pytest.FixtureRequest) -> Any:
    """Output test results in JSON format after all tests complete."""
    yield  # Wait for all tests to complete

    # Calculate final results
    passed_count = sum(1 for r in test_results if r["passed"])
    failed_count = len([r for r in test_results if not r["passed"]])
    total_count = len(test_results)
    all_passed = failed_count == 0 and total_count > 0

    failures = [r for r in test_results if not r["passed"]]

    # Count output validation results (for DST contract testing)
    output_validated_count = sum(1 for r in test_results if r.get("output_match") is not None)
    output_match_count = sum(1 for r in test_results if r.get("output_match") is True)

    output = {
        "all_passed": all_passed,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "total_count": total_count,
        "results": test_results,
        "failures": failures,
    }

    # Add contract validation summary if any tests had expected outputs
    if output_validated_count > 0:
        output["contract_validation"] = {
            "tests_with_expected_output": output_validated_count,
            "output_matches": output_match_count,
            "output_mismatches": output_validated_count - output_match_count,
        }

    print("\n" + "=" * 60)
    print(f"Results: {passed_count}/{total_count} passed")
    if output_validated_count > 0:
        print(f"Contract validation: {output_match_count}/{output_validated_count} outputs matched")
    print("=" * 60)
    print(json.dumps(output))
    sys.stdout.flush()
