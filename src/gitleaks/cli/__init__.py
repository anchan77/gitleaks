"""
CLI module for gitleaks.

This module provides the Click-based command-line interface.
"""

from __future__ import annotations

import sys

import click

from gitleaks import __version__
from gitleaks.logging import configure_logging


@click.group(invoke_without_command=True)
@click.option(
    "--version", "-v", is_flag=True, help="Show the version and exit."
)
@click.option(
    "--log-level",
    type=click.Choice(["trace", "debug", "info", "warn", "error", "fatal"], case_sensitive=False),
    default="info",
    help="Set the log level.",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output.",
)
@click.pass_context
def main(ctx: click.Context, version: bool, log_level: str, no_color: bool) -> None:
    """
    Gitleaks - Detect secrets and sensitive information in git repositories.

    A tool for detecting and preventing hardcoded secrets like passwords,
    API keys, and tokens in git repos.
    """
    # Configure logging based on CLI options
    configure_logging(level=log_level, json_output=not no_color)

    if version:
        click.echo(f"gitleaks {__version__}")
        sys.exit(0)

    # Ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)

    # If no command is given, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


__all__ = ["main"]
