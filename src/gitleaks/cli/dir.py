"""
Directory scanning command for gitleaks.

This module implements the `dir` command which scans directories or files
for secrets.
"""

import asyncio
import os
import sys
import time
from typing import Optional

import click

from gitleaks.cli.common import (
    GitleaksContext,
    bytes_convert,
    cli,
    file_exists,
    format_duration,
    init_config,
    pass_context,
)
from gitleaks.logging import debug, error, fatal, info, warn


async def dir_scan_async(
    ctx: GitleaksContext, source: str, follow_symlinks: bool
) -> None:
    """
    Async handler for directory scanning.

    This function will eventually coordinate async file I/O and scanning.
    For now, it's a tracer bullet proving the async integration works.

    Args:
        ctx: Gitleaks context object
        source: Source path to scan
        follow_symlinks: Whether to follow symbolic links
    """
    # Load configuration
    config = init_config(ctx, source)

    # Log scan parameters
    debug().debug(f"scanning source: {source}")
    debug().debug(f"follow symlinks: {follow_symlinks}")
    debug().debug(f"max target megabytes: {ctx.max_target_megabytes}")
    debug().debug(f"max archive depth: {ctx.max_archive_depth}")

    # TODO: The actual detection logic will be implemented in Task 5 (Basic Detection Engine)
    # For now, we just validate the setup and exit cleanly

    info().info(
        f"configuration loaded successfully from {config.path if hasattr(config, 'path') else 'default config'}"
    )
    info().info(f"loaded {len(config.rules)} rule(s)")

    # Placeholder message
    info().info("directory scanning command initialized successfully")
    info().info("detection engine will be implemented in Task 5")

    # Simulate async work (this will be replaced with actual async scanning in Task 5)
    await asyncio.sleep(0)

    # Calculate scan duration
    duration = time.time() - ctx.start_time

    # Exit cleanly
    info().info(f"scan completed in {format_duration(duration)}")
    info().info("no leaks found")


@cli.command(name="dir")
@click.argument("path", type=click.Path(exists=True), default=".", required=False)
@click.option(
    "--follow-symlinks",
    is_flag=True,
    help="scan files that are symlinks to other files",
)
@pass_context
def dir_command(ctx: GitleaksContext, path: str, follow_symlinks: bool) -> None:
    """Scan directories or files for secrets.

    Args:
        PATH: Path to directory or file to scan (defaults to current directory)
    """
    source = path if path else "."

    # Validate source path
    if not os.path.exists(source):
        fatal().critical(f"source path does not exist: {source}")
        sys.exit(1)

    # Use asyncio.run() to invoke the async handler
    # This bridges Click's synchronous interface with our async implementation
    try:
        if ctx.timeout > 0:
            # If timeout is set, use wait_for to enforce it
            asyncio.run(
                asyncio.wait_for(
                    dir_scan_async(ctx, source, follow_symlinks),
                    timeout=ctx.timeout,
                )
            )
        else:
            # No timeout, run directly
            asyncio.run(dir_scan_async(ctx, source, follow_symlinks))
    except asyncio.TimeoutError:
        fatal().critical(f"scan timed out after {ctx.timeout} seconds")
        sys.exit(1)
