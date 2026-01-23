"""
Common CLI utilities and root command group for gitleaks.

This module provides the Click command group, persistent flags, and shared
utilities used across all CLI commands.
"""

import asyncio
import os
import sys
import time
from datetime import datetime
from typing import IO, List, Optional

import click

from gitleaks import __version__
from gitleaks.config.loader import load_config
from gitleaks.logging import (
    configure_logging,
    debug,
    error,
    fatal,
    info,
    warn,
)
from gitleaks.reporting import (
    CsvReporter,
    Finding,
    JsonReporter,
    JunitReporter,
    Reporter,
    SarifReporter,
    TemplateReporter,
)

# Banner displayed at startup (unless --no-banner is used)
BANNER = """
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

"""

# Config description for help text
CONFIG_DESCRIPTION = """config file path
order of precedence:
1. --config/-c
2. env var GITLEAKS_CONFIG
3. env var GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.gitleaks.toml
If none of the four options are used, then gitleaks will use the default config"""

# Byte conversion constants
BYTE = 1.0
KILOBYTE = BYTE * 1000
MEGABYTE = KILOBYTE * 1000
GIGABYTE = MEGABYTE * 1000


# Context object to pass data between commands
class GitleaksContext:
    """Context object to store CLI state and configuration."""

    def __init__(self):
        self.config_path: Optional[str] = None
        self.exit_code: int = 1
        self.report_path: Optional[str] = None
        self.report_format: Optional[str] = None
        self.report_template: Optional[str] = None
        self.baseline_path: Optional[str] = None
        self.log_level: str = "info"
        self.verbose: bool = False
        self.no_color: bool = False
        self.max_target_megabytes: int = 0
        self.ignore_gitleaks_allow: bool = False
        self.redact: int = 0
        self.no_banner: bool = False
        self.enable_rule: list[str] = []
        self.gitleaks_ignore_path: str = "."
        self.max_decode_depth: int = 5
        self.max_archive_depth: int = 0
        self.timeout: int = 0
        self.start_time: float = 0


pass_context = click.make_pass_decorator(GitleaksContext, ensure=True)


def bytes_convert(bytes_val: int) -> str:
    """
    Convert byte count to human-readable format.

    Args:
        bytes_val: Number of bytes

    Returns:
        Human-readable string representation (e.g., "1.5 MB")
    """
    if bytes_val == 0:
        return "0"

    value = float(bytes_val)
    unit = "bytes"

    if bytes_val >= GIGABYTE:
        unit = "GB"
        value = value / GIGABYTE
    elif bytes_val >= MEGABYTE:
        unit = "MB"
        value = value / MEGABYTE
    elif bytes_val >= KILOBYTE:
        unit = "KB"
        value = value / KILOBYTE

    # Format with 2 decimal places and strip trailing ".00"
    string_value = f"{value:.2f}".rstrip("0").rstrip(".")

    return f"{string_value} {unit}"


def format_duration(duration: float) -> str:
    """
    Format duration in seconds to human-readable format.

    Args:
        duration: Duration in seconds

    Returns:
        Human-readable duration string
    """
    if duration < 0.001:
        return f"{duration * 1000000:.0f}µs"
    elif duration < 0.1:
        return f"{duration * 1000:.1f}ms"
    elif duration < 1:
        return f"{duration * 1000:.0f}ms"
    elif duration < 60:
        return f"{duration:.2f}s"
    elif duration < 3600:
        minutes = int(duration / 60)
        seconds = duration % 60
        return f"{minutes}m{seconds:.0f}s"
    else:
        hours = int(duration / 3600)
        minutes = int((duration % 3600) / 60)
        return f"{hours}h{minutes}m"


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, message="gitleaks version %(version)s")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=False),
    help=CONFIG_DESCRIPTION,
)
@click.option(
    "--exit-code",
    type=int,
    default=1,
    help="exit code when leaks have been encountered",
)
@click.option(
    "--report-path",
    "-r",
    type=str,
    help='report file (use "-" for stdout)',
)
@click.option(
    "--report-format",
    "-f",
    type=click.Choice(["json", "csv", "junit", "sarif", "template"], case_sensitive=False),
    help="output format (json, csv, junit, sarif, template)",
)
@click.option(
    "--report-template",
    type=str,
    help="template file or built-in template name (basic, leet, myspace, w98, wxp) used to generate the report (implies --report-format=template)",
)
@click.option(
    "--baseline-path",
    "-b",
    type=click.Path(exists=True),
    help="path to baseline with issues that can be ignored",
)
@click.option(
    "--log-level",
    "-l",
    type=click.Choice(["trace", "debug", "info", "warn", "error", "fatal"], case_sensitive=False),
    default="info",
    help="log level (trace, debug, info, warn, error, fatal)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="show verbose output from scan",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="turn off color for verbose output",
)
@click.option(
    "--max-target-megabytes",
    type=int,
    default=0,
    help="files larger than this will be skipped",
)
@click.option(
    "--ignore-gitleaks-allow",
    is_flag=True,
    help="ignore gitleaks:allow comments",
)
@click.option(
    "--redact",
    type=int,
    default=0,
    flag_value=100,
    help="redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%%)",
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="suppress banner",
)
@click.option(
    "--enable-rule",
    multiple=True,
    help="only enable specific rules by id",
)
@click.option(
    "--gitleaks-ignore-path",
    "-i",
    type=str,
    default=".",
    help="path to .gitleaksignore file or folder containing one",
)
@click.option(
    "--max-decode-depth",
    type=int,
    default=5,
    help="allow recursive decoding up to this depth",
)
@click.option(
    "--max-archive-depth",
    type=int,
    default=0,
    help='allow scanning into nested archives up to this depth (default "0", no archive traversal is done)',
)
@click.option(
    "--timeout",
    type=int,
    default=0,
    help='set a timeout for gitleaks commands in seconds (default "0", no timeout is set)',
)
@pass_context
def cli(
    ctx: GitleaksContext,
    config: Optional[str],
    exit_code: int,
    report_path: Optional[str],
    report_format: Optional[str],
    report_template: Optional[str],
    baseline_path: Optional[str],
    log_level: str,
    verbose: bool,
    no_color: bool,
    max_target_megabytes: int,
    ignore_gitleaks_allow: bool,
    redact: int,
    no_banner: bool,
    enable_rule: tuple[str, ...],
    gitleaks_ignore_path: str,
    max_decode_depth: int,
    max_archive_depth: int,
    timeout: int,
) -> None:
    """Gitleaks scans code, past or present, for secrets."""
    # Store all options in context for use by subcommands
    ctx.config_path = config
    ctx.exit_code = exit_code
    ctx.report_path = report_path
    ctx.report_format = report_format
    ctx.report_template = report_template
    ctx.baseline_path = baseline_path
    ctx.log_level = log_level
    ctx.verbose = verbose
    ctx.no_color = no_color
    ctx.max_target_megabytes = max_target_megabytes
    ctx.ignore_gitleaks_allow = ignore_gitleaks_allow
    ctx.redact = redact
    ctx.no_banner = no_banner
    ctx.enable_rule = list(enable_rule)
    ctx.gitleaks_ignore_path = gitleaks_ignore_path
    ctx.max_decode_depth = max_decode_depth
    ctx.max_archive_depth = max_archive_depth
    ctx.timeout = timeout
    ctx.start_time = time.time()

    # Configure logging
    configure_logging(log_level, no_color)

    # Display banner unless suppressed
    if not no_banner:
        sys.stderr.write(BANNER)
        sys.stderr.flush()


def init_config(ctx: GitleaksContext, source: str) -> None:
    """
    Initialize and load configuration based on CLI flags and environment.

    Args:
        ctx: Gitleaks context object
        source: Source path being scanned

    Returns:
        Loaded configuration object
    """
    # Configuration loading order:
    # 1. --config/-c flag
    # 2. GITLEAKS_CONFIG environment variable
    # 3. GITLEAKS_CONFIG_TOML environment variable (inline content)
    # 4. .gitleaks.toml in source directory
    # 5. Default config

    config_path = None

    if ctx.config_path:
        config_path = ctx.config_path
        debug().debug(f"using gitleaks config {config_path} from `--config`")
    elif os.getenv("GITLEAKS_CONFIG"):
        config_path = os.getenv("GITLEAKS_CONFIG")
        debug().debug(f"using gitleaks config from GITLEAKS_CONFIG env var: {config_path}")
    elif os.getenv("GITLEAKS_CONFIG_TOML"):
        # This will be handled by the loader
        debug().debug("using gitleaks config from GITLEAKS_CONFIG_TOML env var content")
    else:
        # Try to find .gitleaks.toml in source directory
        if os.path.isfile(source):
            debug().debug(
                f"unable to load gitleaks config from {os.path.join(os.path.dirname(source), '.gitleaks.toml')} "
                f"since --source={source} is a file, using default config"
            )
        elif os.path.isdir(source):
            potential_config = os.path.join(source, ".gitleaks.toml")
            if os.path.exists(potential_config):
                config_path = potential_config
                debug().debug(
                    f"using existing gitleaks config {config_path} from `(--source)/.gitleaks.toml`"
                )
            else:
                debug().debug(
                    f"no gitleaks config found in path {potential_config}, using default gitleaks config"
                )

    # Load the configuration
    try:
        config = load_config(config_path)
        return config
    except Exception as e:
        fatal().critical(f"unable to load gitleaks config: {e}")
        sys.exit(1)


def file_exists(file_path: str) -> bool:
    """
    Check if a file exists (not a directory).

    Args:
        file_path: Path to check

    Returns:
        True if the path exists and is a file, False otherwise
    """
    try:
        return os.path.isfile(file_path)
    except Exception:
        return False


def get_reporter(
    ctx: GitleaksContext, ordered_rules: Optional[List] = None
) -> Reporter:
    """
    Get the appropriate reporter based on CLI flags and configuration.

    Args:
        ctx: Gitleaks context containing report format and template settings
        ordered_rules: Optional list of Rule objects for SARIF reporter

    Returns:
        Reporter instance configured according to user preferences

    Raises:
        SystemExit: If reporter configuration is invalid
    """
    report_format = ctx.report_format
    report_template = ctx.report_template
    report_path = ctx.report_path

    # If template is specified, override format to template
    if report_template:
        report_format = "template"

    # Infer format from file extension if not explicitly set
    if not report_format and report_path and report_path != "-":
        report_path_lower = report_path.lower()
        if report_path_lower.endswith(".csv"):
            report_format = "csv"
        elif report_path_lower.endswith(".sarif") or report_path_lower.endswith(
            ".sarif.json"
        ):
            report_format = "sarif"
        elif report_path_lower.endswith(".xml"):
            report_format = "junit"
        elif report_path_lower.endswith(".json"):
            report_format = "json"

    # Default to JSON if still not set
    if not report_format:
        report_format = "json"

    # Create the appropriate reporter
    if report_format == "json":
        return JsonReporter()
    elif report_format == "csv":
        return CsvReporter()
    elif report_format == "sarif":
        return SarifReporter(ordered_rules=ordered_rules)
    elif report_format == "junit":
        return JunitReporter()
    elif report_format == "template":
        return TemplateReporter(template_path=report_template)
    else:
        fatal().critical(f"unknown report format: {report_format}")
        sys.exit(1)


def write_report(
    ctx: GitleaksContext, findings: List[Finding], ordered_rules: Optional[List] = None
) -> None:
    """
    Write findings to the configured report output.

    Args:
        ctx: Gitleaks context containing report configuration
        findings: List of findings to report
        ordered_rules: Optional list of Rule objects for SARIF reporter

    Raises:
        SystemExit: If writing the report fails
    """
    reporter = get_reporter(ctx, ordered_rules)
    report_path = ctx.report_path

    try:
        if not report_path or report_path == "-":
            # Write to stdout
            reporter.write(sys.stdout, findings)
        else:
            # Write to file
            with open(report_path, "w") as f:
                reporter.write(f, findings)
                info().info(f"report written to {report_path}")
    except Exception as e:
        fatal().critical(f"failed to write report: {e}")
        sys.exit(1)
