"""
Directory source provider for filesystem scanning.

This module implements the Files source provider that walks filesystem
directories and yields fragments for scanning. It handles file filtering,
symlink resolution, size limits, and concurrent processing.
"""

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable

from ..config.models import Config
from ..logging import get_logger
from .common import should_skip_path, normalize_path
from .fragment import Fragment
from .file import File


# Type alias for the callback function used to yield fragments
FragmentsFunc = Callable[[Fragment, Optional[Exception]], Optional[Exception]]


@dataclass
class ScanTarget:
    """
    Represents a file to be scanned.

    Attributes:
        path: Resolved real path to the file
        symlink: Path to symlink if file was discovered via symlink
    """

    path: str
    symlink: str = ""


class Files:
    """
    Source provider for scanning filesystem directories.

    This class walks a directory tree and yields fragments from each file
    for scanning. It implements the Source protocol and provides:
    - Recursive directory traversal
    - File filtering (size, empty, allowlists)
    - Symlink handling
    - Concurrent file processing with semaphore limits
    - Permission error handling
    """

    def __init__(
        self,
        path: str,
        config: Optional[Config] = None,
        follow_symlinks: bool = False,
        max_file_size: int = 0,
        max_archive_depth: int = 0,
        max_concurrency: int = 10,
    ):
        """
        Initialize a Files source.

        Args:
            path: Root directory path to scan
            config: Gitleaks configuration for allowlist filtering
            follow_symlinks: Whether to follow symlinks to files
            max_file_size: Maximum file size in bytes (0 = no limit)
            max_archive_depth: Maximum depth for nested archives (Task 8)
            max_concurrency: Maximum concurrent file operations
        """
        self.path = path
        self.config = config
        self.follow_symlinks = follow_symlinks
        self.max_file_size = max_file_size
        self.max_archive_depth = max_archive_depth
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def fragments(self, yield_func: FragmentsFunc) -> None:
        """
        Iterate through directory and yield content fragments.

        This method walks the directory tree, discovers files, and yields
        fragments from each file concurrently. It respects:
        - Allowlist filtering (paths)
        - File size limits
        - Empty file filtering
        - Symlink handling based on follow_symlinks flag

        Args:
            yield_func: Callback function to process each fragment.
                       Should return an exception to stop iteration, or None to continue.

        Raises:
            Exception: If an error occurs during scanning or if yield_func returns an exception.
        """
        logger = get_logger()

        # Track tasks for concurrent file processing
        tasks = []

        # Walk the directory tree
        for root, dirs, files in os.walk(self.path, topdown=True, followlinks=False):
            # Normalize the root path
            root_normalized = normalize_path(root)

            # Check if this directory should be skipped
            if should_skip_path(self.config, root_normalized):
                logger.debug("skipping directory: global allowlist", path=root_normalized)
                # Clear dirs to prevent descending into this directory
                dirs.clear()
                continue

            # Check each file in this directory
            for filename in files:
                file_path = os.path.join(root, filename)
                file_path_normalized = normalize_path(file_path)

                try:
                    # Create scan target
                    scan_target = await self._create_scan_target(file_path)

                    if scan_target is None:
                        # File was filtered out
                        continue

                    # Schedule file processing
                    task = asyncio.create_task(
                        self._process_file(scan_target, yield_func)
                    )
                    tasks.append(task)

                except Exception as e:
                    logger.warning(
                        "error checking file, skipping",
                        path=file_path_normalized,
                        error=str(e)
                    )
                    continue

        # Wait for all file processing tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _create_scan_target(self, path: str) -> Optional[ScanTarget]:
        """
        Create a scan target for a file path, applying filters.

        This method checks if the file should be scanned based on:
        - File existence and permissions
        - Empty file check
        - Size limits
        - Allowlist filtering
        - Symlink handling

        Args:
            path: File path to check

        Returns:
            ScanTarget if file should be scanned, None if filtered out
        """
        logger = get_logger()
        path_normalized = normalize_path(path)

        try:
            # Check if path is a symlink
            if os.path.islink(path):
                if not self.follow_symlinks:
                    logger.debug("skipping symlink: follow symlinks disabled", path=path_normalized)
                    return None

                # Resolve the symlink
                try:
                    real_path = os.path.realpath(path)
                except Exception as e:
                    logger.error("skipping symlink: could not evaluate", path=path_normalized, error=str(e))
                    return None

                # Check if symlink target is a directory
                if os.path.isdir(real_path):
                    logger.debug("skipping symlink: target is directory", path=path_normalized, target=real_path)
                    return None

                # Create scan target with symlink info
                return ScanTarget(path=real_path, symlink=path)

            # Get file info
            stat_info = os.stat(path)

            # Check if it's a regular file
            if not os.path.isfile(path):
                logger.debug("skipping: not a regular file", path=path_normalized)
                return None

            # Check for empty files
            if stat_info.st_size == 0:
                logger.debug("skipping empty file", path=path_normalized)
                return None

            # Check file size limit
            if self.max_file_size > 0 and stat_info.st_size > self.max_file_size:
                size_mb = stat_info.st_size / 1_000_000
                max_mb = self.max_file_size / 1_000_000
                logger.warning(
                    "skipping file: too large",
                    path=path_normalized,
                    size_mb=f"{size_mb:.2f}",
                    max_size_mb=f"{max_mb:.2f}"
                )
                return None

            # Check allowlist filtering
            if should_skip_path(self.config, path_normalized):
                logger.debug("skipping file: global allowlist", path=path_normalized)
                return None

            # File passes all checks
            return ScanTarget(path=path)

        except PermissionError:
            logger.warning("skipping file: permission denied", path=path_normalized)
            return None
        except Exception as e:
            logger.warning("skipping file: error", path=path_normalized, error=str(e))
            return None

    async def _process_file(self, scan_target: ScanTarget, yield_func: FragmentsFunc) -> None:
        """
        Process a single file and yield its fragments.

        This method is called concurrently for each file. It:
        - Acquires a semaphore slot to limit concurrency
        - Opens the file
        - Creates a File source
        - Yields fragments through the File source

        Args:
            scan_target: File to process
            yield_func: Callback to yield fragments
        """
        logger = get_logger()

        async with self._semaphore:
            path_normalized = normalize_path(scan_target.path)
            logger.debug("scanning path", path=path_normalized)

            try:
                # Open the file
                with open(scan_target.path, 'rb') as f:
                    # Create a File source
                    file_source = File(
                        content=f,
                        path=scan_target.path,
                        symlink=scan_target.symlink,
                        config=self.config,
                        max_archive_depth=self.max_archive_depth,
                    )

                    # Yield fragments from the file
                    await file_source.fragments(yield_func)

            except PermissionError:
                logger.warning("skipping file: permission denied", path=path_normalized)
            except Exception as e:
                logger.error("error processing file", path=path_normalized, error=str(e))
