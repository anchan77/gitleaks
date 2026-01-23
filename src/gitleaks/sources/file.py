"""
Single file source provider.

This module provides functionality to read a single file and yield fragments
for scanning. It handles chunking large files, MIME type detection to skip
binary files, and provides the foundation for archive handling (Task 8).
"""

import io
import os
from pathlib import Path
from typing import Optional, Callable

import magic

from ..config.models import Config
from .common import normalize_path, get_windows_path, read_until_safe_boundary, MAX_PEEK_SIZE
from .fragment import Fragment


# Type alias for the callback function used to yield fragments
FragmentsFunc = Callable[[Fragment, Optional[Exception]], Optional[Exception]]


# Default buffer size for reading files (100kb)
DEFAULT_BUFFER_SIZE = 100_000

# Separator used in paths to indicate nesting within archives
INNER_PATH_SEPARATOR = "!"


class File:
    """
    Source for yielding fragments from a single file.

    This class handles reading a file and yielding its content as fragments
    for the detection engine. It supports chunking large files, MIME type
    detection, and tracks metadata like line numbers and symlinks.

    Archive handling (recursively scanning archives) is deferred to Task 8.
    """

    def __init__(
        self,
        content: io.BufferedReader,
        path: str,
        symlink: str = "",
        config: Optional[Config] = None,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        outer_paths: Optional[list[str]] = None,
        max_archive_depth: int = 0,
        archive_depth: int = 0,
    ):
        """
        Initialize a File source.

        Args:
            content: Buffered reader for the file content
            path: Resolved real path to the file
            symlink: Path to symlink if file was discovered via symlink
            config: Gitleaks configuration for allowlist filtering
            buffer_size: Size of buffer for reading chunks
            outer_paths: List of container paths (for archives, Task 8)
            max_archive_depth: Maximum depth for nested archives (Task 8)
            archive_depth: Current nesting depth in archives (Task 8)
        """
        self.content = content
        self.path = normalize_path(path)
        self.symlink = normalize_path(symlink) if symlink else ""
        self.config = config
        self.buffer_size = buffer_size
        self.outer_paths = outer_paths or []
        self.max_archive_depth = max_archive_depth
        self.archive_depth = archive_depth

    def full_path(self) -> str:
        """
        Get the full path including any outer archive paths.

        Returns:
            Full path with archive containers separated by INNER_PATH_SEPARATOR
        """
        if self.outer_paths:
            return INNER_PATH_SEPARATOR.join(self.outer_paths + [self.path])
        return self.path

    async def fragments(self, yield_func: FragmentsFunc) -> None:
        """
        Yield fragments from this file.

        This method reads the file in chunks and yields each chunk as a fragment.
        It handles:
        - MIME type detection to skip binary files
        - Chunking at safe boundaries (avoiding splitting secrets)
        - Line number tracking
        - Symlink metadata preservation

        Archive handling is deferred to Task 8.

        Args:
            yield_func: Callback to process each fragment

        Raises:
            Exception: If yield_func returns an error or reading fails
        """
        # Task 8: Archive detection and handling will go here
        # For now, treat everything as a regular file

        await self._file_fragments(yield_func)

    async def _file_fragments(self, yield_func: FragmentsFunc) -> None:
        """
        Read file content and yield as fragments.

        Args:
            yield_func: Callback to process each fragment
        """
        total_lines = 0
        first_chunk = True

        try:
            while True:
                # Read a chunk
                chunk_data = self.content.read(self.buffer_size)

                if not chunk_data:
                    # EOF reached
                    break

                # On first chunk, check MIME type to skip binary files
                if first_chunk:
                    first_chunk = False

                    try:
                        # Use python-magic to detect MIME type
                        mime = magic.from_buffer(chunk_data, mime=True)

                        # Skip binary files (application/* MIME types)
                        # Exception: application/json, application/xml are text-like
                        if mime.startswith('application/'):
                            if mime not in ('application/json', 'application/xml',
                                           'application/javascript', 'application/x-sh'):
                                # This is a binary file, skip it
                                from ..logging import get_logger
                                logger = get_logger()
                                logger.debug(
                                    "skipping binary file",
                                    path=self.full_path(),
                                    mime_type=mime
                                )
                                return
                    except Exception as e:
                        # If MIME detection fails, log and continue
                        from ..logging import get_logger
                        logger = get_logger()
                        logger.warning(
                            "could not determine file type, continuing anyway",
                            path=self.full_path(),
                            error=str(e)
                        )

                # Try to extend chunk to a safe boundary (two consecutive newlines)
                # This avoids splitting secrets across chunk boundaries
                extended_chunk = read_until_safe_boundary(
                    self.content,
                    chunk_data,
                    MAX_PEEK_SIZE
                )

                # Decode chunk to string
                try:
                    content_str = extended_chunk.decode('utf-8', errors='replace')
                except Exception:
                    # If decoding fails, skip this file
                    from ..logging import get_logger
                    logger = get_logger()
                    logger.warning(
                        "could not decode file as UTF-8",
                        path=self.full_path()
                    )
                    return

                # Create fragment
                fragment = Fragment(
                    raw=content_str,
                    raw_bytes=extended_chunk,
                    file_path=self.full_path(),
                    symlink_file=self.symlink,
                    start_line=total_lines + 1,
                )

                # Set Windows-specific path if on Windows
                if os.name == 'nt':
                    fragment.windows_file_path = get_windows_path(self.full_path())

                # Count newlines in this chunk for line tracking
                total_lines += content_str.count('\n')

                # Yield the fragment
                err = yield_func(fragment, None)
                if err:
                    raise err

        except Exception as e:
            # If it's already an error from yield_func, re-raise
            if isinstance(e, Exception):
                raise
            # Otherwise, wrap in a generic error
            fragment = Fragment(file_path=self.full_path())
            err = yield_func(fragment, Exception(f"could not read file: {e}"))
            if err:
                raise err
