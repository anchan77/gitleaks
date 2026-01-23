"""
Version command for gitleaks.

This module provides the 'version' subcommand that displays the gitleaks version.
"""

import click

from gitleaks import __version__
from gitleaks.cli.common import cli


@cli.command(name="version")
def version_command() -> None:
    """Display gitleaks version."""
    click.echo(f"gitleaks version {__version__}")
