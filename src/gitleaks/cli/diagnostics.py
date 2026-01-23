"""
Diagnostics command for gitleaks.

This module provides the 'diagnostics' subcommand that displays diagnostic
information about the environment, configuration, and loaded rules.
"""

import os
import platform
import sys
from pathlib import Path
from typing import Optional

import click

from gitleaks import __version__
from gitleaks.cli.common import GitleaksContext, pass_context
from gitleaks.cli.common import cli
from gitleaks.config.loader import load_config
from gitleaks.logging import debug, error, info


@cli.command(name="diagnostics")
@click.option(
    "--source",
    type=click.Path(exists=True),
    default=".",
    help="Path to scan (for finding config file)",
)
@pass_context
def diagnostics_command(ctx: GitleaksContext, source: str) -> None:
    """
    Display diagnostic information.

    Shows version, runtime information, configuration details, and rule statistics.
    """
    # Display version information
    click.echo(f"gitleaks version {__version__}")
    click.echo()

    # Display runtime information
    click.echo("Runtime Information:")
    click.echo(f"  Python version: {sys.version.split()[0]}")
    click.echo(f"  Platform: {platform.system()} {platform.release()}")
    click.echo(f"  Architecture: {platform.machine()}")
    click.echo()

    # Try to find and load configuration
    config_path = _find_config_path(ctx, source)

    if config_path:
        click.echo(f"Configuration:")
        click.echo(f"  Config path: {config_path}")

        # Try to load the config and display statistics
        try:
            config = load_config(config_path)

            # Count rules
            rule_count = len(config.rules) if config.rules else 0
            click.echo(f"  Rules loaded: {rule_count}")

            # Count keywords across all rules
            keyword_count = 0
            if config.rules:
                for rule in config.rules:
                    if rule.keywords:
                        keyword_count += len(rule.keywords)
            click.echo(f"  Keywords: {keyword_count}")

            # Display allowlist information
            if config.allowlist:
                allowlist_info = []
                if config.allowlist.paths:
                    allowlist_info.append(f"{len(config.allowlist.paths)} paths")
                if config.allowlist.commits:
                    allowlist_info.append(f"{len(config.allowlist.commits)} commits")
                if config.allowlist.regexes:
                    allowlist_info.append(f"{len(config.allowlist.regexes)} regexes")
                if config.allowlist.stop_words:
                    allowlist_info.append(f"{len(config.allowlist.stop_words)} stop words")

                if allowlist_info:
                    click.echo(f"  Allowlist entries: {', '.join(allowlist_info)}")

            # Display other config settings
            click.echo()
            click.echo("Configuration Settings:")
            if hasattr(config, 'extend') and config.extend:
                click.echo(f"  Extends: {config.extend.path if hasattr(config.extend, 'path') else config.extend}")
            if hasattr(config, 'title') and config.title:
                click.echo(f"  Title: {config.title}")

        except Exception as e:
            error().error(f"Failed to load configuration: {e}")
            click.echo(f"  Error loading config: {e}")
    else:
        click.echo("Configuration:")
        click.echo("  No configuration file found (will use defaults)")

    click.echo()

    # Display environment information
    click.echo("Environment:")
    gitleaks_config = os.getenv("GITLEAKS_CONFIG")
    if gitleaks_config:
        click.echo(f"  GITLEAKS_CONFIG: {gitleaks_config}")

    gitleaks_config_toml = os.getenv("GITLEAKS_CONFIG_TOML")
    if gitleaks_config_toml:
        click.echo(f"  GITLEAKS_CONFIG_TOML: <set>")

    if not gitleaks_config and not gitleaks_config_toml:
        click.echo("  No GITLEAKS_* environment variables set")


def _find_config_path(ctx: GitleaksContext, source: str) -> Optional[str]:
    """
    Find the configuration file path using the same logic as init_config.

    Args:
        ctx: Gitleaks context object
        source: Source path being scanned

    Returns:
        Path to config file if found, None otherwise
    """
    config_path = None

    if ctx.config_path:
        config_path = ctx.config_path
        debug().debug(f"using gitleaks config {config_path} from `--config`")
    elif os.getenv("GITLEAKS_CONFIG"):
        config_path = os.getenv("GITLEAKS_CONFIG")
        debug().debug(f"using gitleaks config from GITLEAKS_CONFIG env var: {config_path}")
    elif os.getenv("GITLEAKS_CONFIG_TOML"):
        # Config is provided inline via environment variable
        return "<GITLEAKS_CONFIG_TOML environment variable>"
    else:
        # Try to find .gitleaks.toml in source directory
        if os.path.isfile(source):
            source_dir = os.path.dirname(source)
        elif os.path.isdir(source):
            source_dir = source
        else:
            source_dir = "."

        potential_config = os.path.join(source_dir, ".gitleaks.toml")
        if os.path.exists(potential_config):
            config_path = potential_config
            debug().debug(
                f"using existing gitleaks config {config_path} from `(--source)/.gitleaks.toml`"
            )

    return config_path
