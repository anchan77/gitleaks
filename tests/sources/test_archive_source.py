"""
Tests for archive source provider.

This module tests archive detection, extraction, and recursive scanning
for various archive formats including zip, tar, 7z, and compressed files.
"""

import io
import os
import pytest
from pathlib import Path

from gitleaks.sources.archive_source import (
    detect_archive_type,
    detect_archive_type_from_bytes,
    scan_archive,
)
from gitleaks.sources.fragment import Fragment
from gitleaks.config.models import Config


# Path to test archives
TEST_DATA_PATH = Path(__file__).parent.parent.parent / "testdata"
ARCHIVES_PATH = TEST_DATA_PATH / "archives"


@pytest.fixture
def simple_config():
    """Create a simple config for testing."""
    return None  # No allowlists for basic tests


class FragmentCollector:
    """Helper class to collect fragments during testing."""

    def __init__(self):
        self.fragments = []
        self.errors = []

    def __call__(self, fragment: Fragment, error: Exception | None) -> Exception | None:
        if error:
            self.errors.append(error)
        else:
            self.fragments.append(fragment)
        return None


class TestArchiveTypeDetection:
    """Test archive type detection from file paths and content."""

    def test_detect_zip_by_extension(self):
        """Test ZIP detection by file extension."""
        assert detect_archive_type("test.zip") == "zip"
        assert detect_archive_type("test.ZIP") == "zip"
        assert detect_archive_type("/path/to/file.zip") == "zip"

    def test_detect_tar_by_extension(self):
        """Test TAR detection by file extension."""
        assert detect_archive_type("test.tar") == "tar"
        assert detect_archive_type("test.tar.gz") == "tar.gz"
        assert detect_archive_type("test.tgz") == "tar.gz"
        assert detect_archive_type("test.tar.bz2") == "tar.bz2"
        assert detect_archive_type("test.tbz2") == "tar.bz2"
        assert detect_archive_type("test.tar.xz") == "tar.xz"
        assert detect_archive_type("test.txz") == "tar.xz"
        assert detect_archive_type("test.tar.zst") == "tar.zst"

    def test_detect_compressed_by_extension(self):
        """Test compressed file detection by extension."""
        assert detect_archive_type("test.gz") == "gzip"
        assert detect_archive_type("test.bz2") == "bzip2"
        assert detect_archive_type("test.xz") == "xz"
        assert detect_archive_type("test.zst") == "zstd"

    def test_detect_7z_by_extension(self):
        """Test 7z detection by file extension."""
        assert detect_archive_type("test.7z") == "7z"

    def test_detect_rar_by_extension(self):
        """Test RAR detection by file extension."""
        assert detect_archive_type("test.rar") == "rar"

    def test_detect_non_archive(self):
        """Test non-archive files return None."""
        assert detect_archive_type("test.txt") is None
        assert detect_archive_type("test.py") is None
        assert detect_archive_type("test") is None

    def test_detect_zip_by_magic_bytes(self):
        """Test ZIP detection by magic bytes."""
        # ZIP magic: PK\x03\x04
        data = b'PK\x03\x04' + b'\x00' * 508
        assert detect_archive_type_from_bytes(data) == "zip"

    def test_detect_gzip_by_magic_bytes(self):
        """Test GZIP detection by magic bytes."""
        # GZIP magic: \x1f\x8b
        data = b'\x1f\x8b' + b'\x00' * 510
        assert detect_archive_type_from_bytes(data) == "gzip"

    def test_detect_bzip2_by_magic_bytes(self):
        """Test BZIP2 detection by magic bytes."""
        # BZIP2 magic: BZ
        data = b'BZ' + b'\x00' * 510
        assert detect_archive_type_from_bytes(data) == "bzip2"

    def test_detect_tar_by_magic_bytes(self):
        """Test TAR detection by magic bytes at offset 257."""
        # TAR magic at offset 257: ustar\x00
        data = b'\x00' * 257 + b'ustar\x00' + b'\x00' * 250
        assert detect_archive_type_from_bytes(data) == "tar"

    def test_detect_non_archive_by_bytes(self):
        """Test non-archive content returns None."""
        data = b'This is just plain text' + b'\x00' * 489
        assert detect_archive_type_from_bytes(data) is None


@pytest.mark.skipif(not ARCHIVES_PATH.exists(), reason="Test data not available")
class TestArchiveScanning:
    """Test actual archive scanning with test data."""

    @pytest.mark.asyncio
    async def test_scan_zip_archive(self, simple_config):
        """Test scanning a ZIP archive."""
        zip_path = ARCHIVES_PATH / "files.zip"
        if not zip_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(zip_path, 'rb') as f:
            await scan_archive(
                f,
                str(zip_path),
                "zip",
                simple_config,
                [],
                1,  # max_archive_depth
                0,  # current depth
                collector
            )

        # Should have found at least one fragment
        assert len(collector.fragments) > 0

        # Check that fragments have proper paths with archive separator
        assert any("!" in frag.file_path for frag in collector.fragments)

    @pytest.mark.asyncio
    async def test_scan_tar_archive(self, simple_config):
        """Test scanning a TAR archive."""
        tar_path = ARCHIVES_PATH / "files.tar"
        if not tar_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(tar_path, 'rb') as f:
            await scan_archive(
                f,
                str(tar_path),
                "tar",
                simple_config,
                [],
                1,
                0,
                collector
            )

        # Should have found at least one fragment
        assert len(collector.fragments) > 0

        # Check that fragments have proper paths
        assert any("!" in frag.file_path for frag in collector.fragments)

    @pytest.mark.asyncio
    async def test_scan_tar_gz_archive(self, simple_config):
        """Test scanning a TAR.GZ archive."""
        tgz_path = ARCHIVES_PATH / "nested.tar.gz"
        if not tgz_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(tgz_path, 'rb') as f:
            await scan_archive(
                f,
                str(tgz_path),
                "tar.gz",
                simple_config,
                [],
                2,  # Need depth 2 for nested archives
                0,
                collector
            )

        # Should have found fragments
        assert len(collector.fragments) > 0

    @pytest.mark.asyncio
    async def test_scan_7z_archive(self, simple_config):
        """Test scanning a 7z archive."""
        sevenzip_path = ARCHIVES_PATH / "files.7z"
        if not sevenzip_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(sevenzip_path, 'rb') as f:
            await scan_archive(
                f,
                str(sevenzip_path),
                "7z",
                simple_config,
                [],
                1,
                0,
                collector
            )

        # Should have found at least one fragment
        assert len(collector.fragments) > 0

    @pytest.mark.asyncio
    async def test_scan_gzip_file(self, simple_config):
        """Test scanning a single GZIP compressed file."""
        gz_path = ARCHIVES_PATH / "files" / "main.go.gz"
        if not gz_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(gz_path, 'rb') as f:
            await scan_archive(
                f,
                str(gz_path),
                "gzip",
                simple_config,
                [],
                1,
                0,
                collector
            )

        # Should have found fragments from the decompressed file
        assert len(collector.fragments) > 0

    @pytest.mark.asyncio
    async def test_max_depth_enforcement(self, simple_config):
        """Test that max archive depth is enforced."""
        tgz_path = ARCHIVES_PATH / "nested.tar.gz"
        if not tgz_path.exists():
            pytest.skip("Test data not available")

        # Scan with depth 0 - should not enter the archive
        collector_depth0 = FragmentCollector()
        with open(tgz_path, 'rb') as f:
            await scan_archive(
                f,
                str(tgz_path),
                "tar.gz",
                simple_config,
                [],
                0,  # max_archive_depth = 0
                0,
                collector_depth0
            )

        # With depth 0, should not scan (depth check happens before scanning)
        assert len(collector_depth0.fragments) == 0

        # Scan with depth 1 - should enter first level
        collector_depth1 = FragmentCollector()
        with open(tgz_path, 'rb') as f:
            await scan_archive(
                f,
                str(tgz_path),
                "tar.gz",
                simple_config,
                [],
                1,  # max_archive_depth = 1
                0,
                collector_depth1
            )

        # Should have some fragments from first level
        fragments_depth1 = len(collector_depth1.fragments)

        # Scan with depth 2 - should enter nested archives
        collector_depth2 = FragmentCollector()
        with open(tgz_path, 'rb') as f:
            await scan_archive(
                f,
                str(tgz_path),
                "tar.gz",
                simple_config,
                [],
                2,  # max_archive_depth = 2
                0,
                collector_depth2
            )

        # Should have more or equal fragments with depth 2
        fragments_depth2 = len(collector_depth2.fragments)
        assert fragments_depth2 >= fragments_depth1

    @pytest.mark.asyncio
    async def test_virtual_paths_in_archives(self, simple_config):
        """Test that virtual paths use the ! separator correctly."""
        zip_path = ARCHIVES_PATH / "files.zip"
        if not zip_path.exists():
            pytest.skip("Test data not available")

        collector = FragmentCollector()

        with open(zip_path, 'rb') as f:
            await scan_archive(
                f,
                str(zip_path),
                "zip",
                simple_config,
                [],
                1,
                0,
                collector
            )

        # All fragments should have paths with the archive name
        for fragment in collector.fragments:
            assert "!" in fragment.file_path
            # Path should be like: /path/to/files.zip!inner/file.txt
            parts = fragment.file_path.split("!")
            assert len(parts) >= 2
            assert "files.zip" in parts[0]


@pytest.mark.asyncio
async def test_archive_with_allowlist():
    """Test that allowlists are applied to archive contents."""
    from gitleaks.config.models import Allowlist, Config

    # Create a config with an allowlist that blocks .go files
    allowlist = Allowlist(paths=[r"\.go$"])
    config = Config(allowlists=[allowlist])

    zip_path = ARCHIVES_PATH / "files.zip"
    if not zip_path.exists():
        pytest.skip("Test data not available")

    collector = FragmentCollector()

    with open(zip_path, 'rb') as f:
        await scan_archive(
            f,
            str(zip_path),
            "zip",
            config,
            [],
            1,
            0,
            collector
        )

    # Check that no .go files were scanned
    for fragment in collector.fragments:
        assert not fragment.file_path.endswith(".go")


@pytest.mark.asyncio
async def test_corrupted_archive_handling(simple_config):
    """Test handling of corrupted archive files."""
    # Create a fake corrupted ZIP
    corrupted_data = b'PK\x03\x04' + b'\xff' * 100  # ZIP magic but invalid content

    collector = FragmentCollector()

    # Should handle gracefully without crashing
    await scan_archive(
        io.BytesIO(corrupted_data),
        "corrupted.zip",
        "zip",
        simple_config,
        [],
        1,
        0,
        collector
    )

    # May or may not have fragments, but should not crash
    # Errors should be logged but not raised
