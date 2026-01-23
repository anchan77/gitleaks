"""
Tests for directory source provider.
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Optional

import pytest

from gitleaks.sources import Files, Fragment
from gitleaks.config.models import Config, Allowlist


class TestFiles:
    """Tests for the Files source provider."""

    @pytest.mark.asyncio
    async def test_empty_directory(self):
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = Files(path=tmpdir)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)
            assert len(fragments_found) == 0

    @pytest.mark.asyncio
    async def test_single_file(self):
        """Test scanning a directory with a single file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_content = "hello world\nthis is a test\n"
            test_file.write_text(test_content)

            files = Files(path=tmpdir)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            assert len(fragments_found) == 1
            assert fragments_found[0].raw == test_content
            assert "test.txt" in fragments_found[0].file_path
            assert fragments_found[0].start_line == 1

    @pytest.mark.asyncio
    async def test_empty_file_skipped(self):
        """Test that empty files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "empty.txt"
            test_file.touch()

            files = Files(path=tmpdir)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)
            assert len(fragments_found) == 0

    @pytest.mark.asyncio
    async def test_max_file_size(self):
        """Test that files exceeding max size are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a small file
            small_file = Path(tmpdir) / "small.txt"
            small_file.write_text("small")

            # Create a large file
            large_file = Path(tmpdir) / "large.txt"
            large_file.write_text("x" * 1000)

            # Set max file size to 500 bytes
            files = Files(path=tmpdir, max_file_size=500)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Only small file should be scanned
            assert len(fragments_found) == 1
            assert "small.txt" in fragments_found[0].file_path

    @pytest.mark.asyncio
    async def test_allowlist_path_filtering(self):
        """Test that allowlisted paths are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files
            included_file = Path(tmpdir) / "included.txt"
            included_file.write_text("include me")

            excluded_file = Path(tmpdir) / "excluded.txt"
            excluded_file.write_text("exclude me")

            # Create allowlist that excludes "excluded.txt"
            allowlist = Allowlist(paths=[r".*excluded\.txt$"])
            config = Config(allowlists=[allowlist])

            files = Files(path=tmpdir, config=config)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Only included file should be scanned
            assert len(fragments_found) == 1
            assert "included.txt" in fragments_found[0].file_path

    @pytest.mark.asyncio
    async def test_subdirectories(self):
        """Test that subdirectories are traversed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()

            file1 = Path(tmpdir) / "file1.txt"
            file1.write_text("file1")

            file2 = subdir / "file2.txt"
            file2.write_text("file2")

            files = Files(path=tmpdir)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Both files should be scanned
            assert len(fragments_found) == 2
            paths = [f.file_path for f in fragments_found]
            assert any("file1.txt" in p for p in paths)
            assert any("file2.txt" in p for p in paths)

    @pytest.mark.asyncio
    async def test_symlink_to_file_followed(self):
        """Test that symlinks to files are followed when enabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a real file
            real_file = Path(tmpdir) / "real.txt"
            real_file.write_text("real content")

            # Create a symlink
            link_file = Path(tmpdir) / "link.txt"
            try:
                link_file.symlink_to(real_file)
            except (OSError, NotImplementedError):
                # Symlinks may not be supported on this platform
                pytest.skip("Symlinks not supported on this platform")

            files = Files(path=tmpdir, follow_symlinks=True)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Should scan both real file and symlink
            assert len(fragments_found) == 2

    @pytest.mark.asyncio
    async def test_symlink_to_file_not_followed(self):
        """Test that symlinks to files are not followed when disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a real file
            real_file = Path(tmpdir) / "real.txt"
            real_file.write_text("real content")

            # Create a symlink
            link_file = Path(tmpdir) / "link.txt"
            try:
                link_file.symlink_to(real_file)
            except (OSError, NotImplementedError):
                # Symlinks may not be supported on this platform
                pytest.skip("Symlinks not supported on this platform")

            files = Files(path=tmpdir, follow_symlinks=False)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Should only scan real file, not symlink
            assert len(fragments_found) == 1
            assert "real.txt" in fragments_found[0].file_path

    @pytest.mark.asyncio
    async def test_chunking_large_file(self):
        """Test that large files are chunked properly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file larger than the buffer size
            large_file = Path(tmpdir) / "large.txt"
            # Write 200kb of content (default buffer is 100kb)
            content = "x" * 200_000
            large_file.write_text(content)

            files = Files(path=tmpdir)
            fragments_found = []

            def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                fragments_found.append(frag)
                return None

            await files.fragments(collect_fragment)

            # Should have at least 2 fragments
            assert len(fragments_found) >= 2

            # Concatenating all fragments should give the original content
            reconstructed = "".join(f.raw for f in fragments_found)
            assert reconstructed == content
