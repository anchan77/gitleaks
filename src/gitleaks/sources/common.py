"""
Common utilities for source providers.

This module provides shared functionality used by all source providers,
including path filtering, archive detection, and content reading helpers.
"""

import io
import os
import platform
from pathlib import Path
from typing import Optional

from ..config.models import Config


# Maximum number of bytes to read ahead when looking for safe boundaries
MAX_PEEK_SIZE = 25_000  # 25kb

# Set of whitespace characters for boundary detection
WHITESPACE_CHARS = {ord(' '), ord('\t'), ord('\n'), ord('\r')}

# Platform detection
IS_WINDOWS = platform.system() == "Windows"


def is_archive(path: str) -> bool:
    """
    Check if a file path is likely an archive or compressed file.

    This performs a lightweight check based on file extensions.
    More thorough checks can be done by the archive source provider.

    Args:
        path: File path to check

    Returns:
        True if the path appears to be an archive file

    Note:
        This is a basic implementation. The Go version uses the archives library
        for more sophisticated detection. For now, we use extension-based detection.
    """
    if not path:
        return False

    # Common archive extensions
    archive_extensions = {
        '.zip', '.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.txz',
        '.7z', '.rar', '.tar.gz', '.tar.bz2', '.tar.xz', '.tar.zst'
    }

    path_lower = path.lower()
    return any(path_lower.endswith(ext) for ext in archive_extensions)


def should_skip_path(cfg: Optional[Config], path: str) -> bool:
    """
    Check if a path should be skipped based on allowlist configuration.

    This function checks the path against all allowlists in the configuration
    to determine if it should be excluded from scanning.

    Args:
        cfg: Configuration containing allowlists
        path: Path to check (should use forward slashes as separator)

    Returns:
        True if the path should be skipped (is in an allowlist)

    Note:
        On Windows, also checks the backslash version of the path for
        backwards compatibility (will be removed in v9).
    """
    if cfg is None:
        return False

    # Check each allowlist
    for allowlist in cfg.allowlists:
        if allowlist.path_allowed(path):
            return True

        # Windows compatibility hack (TODO: remove in v9)
        # This handles the case where config has backslash paths on Windows
        if IS_WINDOWS and '/' in path:
            windows_path = path.replace('/', '\\')
            if allowlist.path_allowed(windows_path):
                return True

    return False


def read_until_safe_boundary(
    reader: io.BufferedReader,
    initial_bytes: bytes,
    max_peek_size: int = MAX_PEEK_SIZE
) -> bytes:
    """
    Read from a reader until reaching a safe boundary (two consecutive newlines).

    This function extends an initial buffer by reading more data until it finds
    a safe splitting point (two consecutive newlines), up to a maximum size.
    This helps avoid splitting content in the middle of a logical unit (like a
    secret or token that spans multiple lines).

    Args:
        reader: Buffered reader to read additional data from
        initial_bytes: Initial bytes already read
        max_peek_size: Maximum number of additional bytes to read beyond initial_bytes

    Returns:
        Extended buffer ending at a safe boundary (or max size if no boundary found)

    Note:
        This is used when chunking large files to avoid breaking secrets across chunks.
        Reference: https://github.com/gitleaks/gitleaks/issues/1651
    """
    if not initial_bytes:
        return initial_bytes

    # Start with the initial buffer
    buffer = bytearray(initial_bytes)

    # Check if buffer already ends in consecutive newlines
    consecutive_newlines = 0
    for i in range(len(buffer) - 1, -1, -1):
        byte = buffer[i]
        if byte == ord('\n'):
            consecutive_newlines += 1
            if consecutive_newlines >= 2:
                # Already at a safe boundary
                return bytes(buffer)
        elif byte in WHITESPACE_CHARS:
            # Other whitespace doesn't reset the count
            continue
        else:
            # Non-whitespace found, stop counting
            break

    # Read additional bytes until we find a safe boundary or hit the limit
    consecutive_newlines = 0
    bytes_read = 0

    try:
        while bytes_read < max_peek_size:
            # Read one byte at a time
            byte_data = reader.read(1)
            if not byte_data:
                # EOF reached
                break

            buffer.extend(byte_data)
            bytes_read += 1

            byte = byte_data[0]
            if byte == ord('\n'):
                consecutive_newlines += 1
                if consecutive_newlines >= 2:
                    # Found safe boundary
                    break
            elif byte in WHITESPACE_CHARS:
                # Other whitespace doesn't reset the count
                continue
            else:
                # Non-whitespace found, reset count
                consecutive_newlines = 0

    except Exception:
        # If reading fails, return what we have
        pass

    return bytes(buffer)


def normalize_path(path: str) -> str:
    """
    Normalize a file path to use forward slashes.

    Args:
        path: Path to normalize

    Returns:
        Path with forward slashes as separators
    """
    return path.replace('\\', '/')


def get_windows_path(normalized_path: str) -> str:
    """
    Convert a normalized path to Windows format if on Windows.

    Args:
        normalized_path: Path with forward slashes

    Returns:
        Path with backslashes if on Windows, otherwise unchanged
    """
    if IS_WINDOWS:
        return normalized_path.replace('/', '\\')
    return normalized_path
