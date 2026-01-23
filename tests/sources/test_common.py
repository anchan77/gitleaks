"""
Tests for sources.common module.

Tests the common utilities used by source providers, including
path filtering, archive detection, and safe boundary reading.
"""

import io
import pytest

from gitleaks.sources.common import (
    is_archive,
    should_skip_path,
    read_until_safe_boundary,
    normalize_path,
    get_windows_path,
    MAX_PEEK_SIZE,
)
from gitleaks.config.models import Config, Allowlist


class TestIsArchive:
    """Tests for archive file detection."""

    def test_zip_file(self):
        """Test that .zip files are detected as archives."""
        assert is_archive("test.zip") is True
        assert is_archive("path/to/archive.ZIP") is True

    def test_tar_files(self):
        """Test that tar files are detected as archives."""
        assert is_archive("test.tar") is True
        assert is_archive("test.tar.gz") is True
        assert is_archive("test.tar.bz2") is True
        assert is_archive("test.tar.xz") is True
        assert is_archive("test.tgz") is True

    def test_compressed_files(self):
        """Test that compressed files are detected."""
        assert is_archive("test.gz") is True
        assert is_archive("test.bz2") is True
        assert is_archive("test.xz") is True
        assert is_archive("test.7z") is True
        assert is_archive("test.rar") is True

    def test_non_archive_files(self):
        """Test that non-archive files are not detected as archives."""
        assert is_archive("test.txt") is False
        assert is_archive("test.py") is False
        assert is_archive("test.go") is False
        assert is_archive("README.md") is False

    def test_empty_path(self):
        """Test that empty path returns False."""
        assert is_archive("") is False


class TestShouldSkipPath:
    """Tests for path filtering based on allowlists."""

    def test_no_config(self):
        """Test that no paths are skipped when config is None."""
        assert should_skip_path(None, "/any/path") is False

    def test_empty_allowlist(self):
        """Test that no paths are skipped with empty allowlist."""
        config = Config(allowlists=[])
        assert should_skip_path(config, "/any/path") is False

    def test_path_in_allowlist(self):
        """Test that paths matching allowlist patterns are skipped."""
        allowlist = Allowlist(paths=[r".*\.txt$", r"^/vendor/"])
        config = Config(allowlists=[allowlist])

        assert should_skip_path(config, "file.txt") is True
        assert should_skip_path(config, "path/to/file.txt") is True
        assert should_skip_path(config, "/vendor/lib/file.go") is True

    def test_path_not_in_allowlist(self):
        """Test that paths not matching allowlist patterns are not skipped."""
        allowlist = Allowlist(paths=[r".*\.txt$"])
        config = Config(allowlists=[allowlist])

        assert should_skip_path(config, "file.py") is False
        assert should_skip_path(config, "path/to/file.go") is False

    def test_multiple_allowlists(self):
        """Test that paths are checked against all allowlists."""
        allowlist1 = Allowlist(paths=[r".*\.txt$"])
        allowlist2 = Allowlist(paths=[r".*\.log$"])
        config = Config(allowlists=[allowlist1, allowlist2])

        assert should_skip_path(config, "file.txt") is True
        assert should_skip_path(config, "file.log") is True
        assert should_skip_path(config, "file.py") is False


class TestReadUntilSafeBoundary:
    """Tests for safe boundary reading."""

    def test_safe_original_split_lf(self):
        """Test that splitting at consecutive LF is safe and exits early."""
        content = b"abc\n\ndefghijklmnop\n\nqrstuvwxyz"
        initial = content[:5]  # "abc\n\n"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 20)
        assert result == b"abc\n\n"

    def test_safe_original_split_crlf(self):
        """Test that splitting at consecutive CRLF is safe and exits early."""
        content = b"a\r\n\r\nbcdefghijklmnop\n"
        initial = content[:5]  # "a\r\n\r\n"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 20)
        assert result == b"a\r\n\r\n"

    def test_safe_split_lf(self):
        """Test finding a safe split point with LF."""
        content = b"abcdefg\nhijklmnop\n\nqrstuvwxyz"
        initial = content[:5]  # "abcde"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 20)
        assert result == b"abcdefg\nhijklmnop\n\n"

    def test_safe_split_crlf(self):
        """Test finding a safe split point with CRLF."""
        content = b"abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz"
        initial = content[:5]  # "abcde"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 25)
        assert result == b"abcdefg\r\nhijklmnop\r\n\r\n"

    def test_safe_split_blank_line(self):
        """Test that blank lines with whitespace are treated as safe boundaries."""
        content = b"abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"
        initial = content[:5]  # "abcde"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 25)
        assert result == b"abcdefg\nhijklmnop\n\t  \t\n"

    def test_no_safe_split(self):
        """Test that function returns max size when no safe boundary found."""
        content = b"abcdefg\nhijklmnopqrstuvwxyz"
        initial = content[:5]  # "abcde"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 20)
        # Should read up to 20 additional bytes + initial 5 = 25 total
        assert len(result) == 25
        assert result == b"abcdefg\nhijklmnopqrstuvwx"

    def test_empty_initial_buffer(self):
        """Test that empty initial buffer returns immediately."""
        reader = io.BufferedReader(io.BytesIO(b"some content"))
        result = read_until_safe_boundary(reader, b"", 20)
        assert result == b""

    def test_eof_reached(self):
        """Test handling when EOF is reached before safe boundary."""
        content = b"abcdefg\nhijklmnop"
        initial = content[:5]  # "abcde"
        reader = io.BufferedReader(io.BytesIO(content[5:]))

        result = read_until_safe_boundary(reader, initial, 50)
        # Should return all available content
        assert result == content


class TestPathNormalization:
    """Tests for path normalization utilities."""

    def test_normalize_path_with_backslashes(self):
        """Test that backslashes are converted to forward slashes."""
        assert normalize_path(r"C:\Users\test\file.txt") == "C:/Users/test/file.txt"
        assert normalize_path(r"path\to\file") == "path/to/file"

    def test_normalize_path_with_forward_slashes(self):
        """Test that forward slashes are preserved."""
        assert normalize_path("path/to/file") == "path/to/file"
        assert normalize_path("/usr/local/bin") == "/usr/local/bin"

    def test_normalize_empty_path(self):
        """Test normalizing empty path."""
        assert normalize_path("") == ""
