"""
Directory scanning command for gitleaks.

This module implements the `dir` command which scans directories or files
for secrets.
"""

import asyncio
import os
import sys
import time
from typing import List, Optional

import click

from gitleaks.cli.common import (
    GitleaksContext,
    bytes_convert,
    cli,
    file_exists,
    format_duration,
    get_reporter,
    init_config,
    pass_context,
    setup_detector,
    write_report,
)
from gitleaks.detector.engine import Detector
from gitleaks.logging import debug, error, fatal, info, warn
from gitleaks.reporting.finding import Finding
from gitleaks.sources.dir_source import Files


async def dir_scan_async(
    ctx: GitleaksContext, source: str, follow_symlinks: bool
) -> None:
    """
    Async handler for directory scanning.

    This function coordinates the end-to-end detection pipeline:
    - Load configuration
    - Instantiate detector
    - Create directory source
    - Run detection
    - Report findings
    - Exit with appropriate code

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

    info().info(
        f"configuration loaded successfully from {config.path if hasattr(config, 'path') else 'default config'}"
    )
    info().info(f"loaded {len(config.rules)} rule(s)")

    # Instantiate detector with configuration
    detector = Detector(config)

    # Configure detector flags from context
    detector.verbose = ctx.verbose
    detector.redact = ctx.redact
    detector.max_target_megabytes = ctx.max_target_megabytes
    detector.follow_symlinks = follow_symlinks
    detector.no_color = ctx.no_color
    detector.ignore_gitleaks_allow = ctx.ignore_gitleaks_allow
    detector.max_archive_depth = ctx.max_archive_depth

    # Set up baseline and gitleaksignore
    setup_detector(ctx, detector, source)

    # Set concurrency semaphore (use default of 40 for now)
    # This controls how many fragments are processed concurrently

    # Create directory source
    max_file_size = 0
    if ctx.max_target_megabytes > 0:
        max_file_size = ctx.max_target_megabytes * 1_000_000  # Convert MB to bytes

    files_source = Files(
        path=source,
        config=config,
        follow_symlinks=follow_symlinks,
        max_file_size=max_file_size,
        max_archive_depth=ctx.max_archive_depth,
        max_concurrency=10,  # Reasonable default for file I/O concurrency
    )

    # Run detection
    debug().debug("starting detection")
    start_time = time.time()

    try:
        findings: List[Finding] = await detector.detect_source(files_source)
        scan_error = None
    except Exception as e:
        error().error(f"scan error: {e}")
        findings = []
        scan_error = e

    # Calculate scan duration
    duration = time.time() - start_time

    # Display summary
    total_bytes = detector._total_bytes
    bytes_msg = f"scanned ~{total_bytes} bytes ({bytes_convert(total_bytes)})"

    if scan_error is None:
        info().info(f"{bytes_msg} in {format_duration(duration)}")
        if len(findings) > 0:
            warn().warn(f"leaks found: {len(findings)}")
        else:
            info().info("no leaks found")
    else:
        warn().warn(bytes_msg)
        warn().warn(f"partial scan completed in {format_duration(duration)}")
        if len(findings) > 0:
            warn().warn(f"{len(findings)} leaks found in partial scan")
        else:
            warn().warn("no leaks found in partial scan")

    # Write report if requested
    if ctx.report_path:
        reporter = get_reporter(ctx, config)
        if reporter:
            write_report(ctx.report_path, reporter, findings)

    # Exit with appropriate code
    if scan_error:
        sys.exit(1)

    if len(findings) > 0:
        sys.exit(ctx.exit_code)

    # No findings, clean exit
    sys.exit(0)


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
