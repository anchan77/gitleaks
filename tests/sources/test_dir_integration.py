"""
Integration tests for directory source provider using actual testdata.
"""

from pathlib import Path
from typing import Optional

import pytest

from gitleaks.sources import Files, Fragment


class TestDirectoryIntegration:
    """Integration tests using actual testdata from the source repository."""

    @pytest.mark.asyncio
    async def test_scan_nogit_directory(self):
        """Test scanning the nogit test directory."""
        # Use the testdata from the destination repository
        # Path is relative to the repository root
        test_file_dir = Path(__file__).parent
        repo_root = test_file_dir.parent.parent
        testdata_path = repo_root / "testdata" / "repos" / "nogit"

        if not testdata_path.exists():
            pytest.skip("Testdata directory not available")

        files = Files(path=str(testdata_path))
        fragments_found = []

        def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
            if err:
                return err
            fragments_found.append(frag)
            return None

        await files.fragments(collect_fragment)

        # Verify we found some fragments
        assert len(fragments_found) > 0

        # Verify we scanned the expected files
        file_paths = [f.file_path for f in fragments_found]
        assert any("main.go" in p for p in file_paths), "Should scan main.go"
        assert any("api.go" in p for p in file_paths), "Should scan api.go"

        # Verify content was read
        all_content = "".join(f.raw for f in fragments_found)
        assert "AKIALALEMEL33243OLIA" in all_content, "Should contain the AWS token from main.go"

    @pytest.mark.asyncio
    async def test_scan_with_gitleaksignore(self):
        """Test that .gitleaksignore files are present but handled by config."""
        # Use the testdata from the destination repository
        test_file_dir = Path(__file__).parent
        repo_root = test_file_dir.parent.parent
        testdata_path = repo_root / "testdata" / "repos" / "nogit"

        if not testdata_path.exists():
            pytest.skip("Testdata directory not available")

        files = Files(path=str(testdata_path))
        fragments_found = []

        def collect_fragment(frag: Fragment, err: Optional[Exception]) -> Optional[Exception]:
            if err:
                return err
            fragments_found.append(frag)
            return None

        await files.fragments(collect_fragment)

        # .gitleaksignore should be scanned (filtering is done at detection time, not source time)
        file_paths = [f.file_path for f in fragments_found]
        # The file itself might be scanned as it's a regular file
        # Filtering based on .gitleaksignore content is done by the detector, not source
        assert len(file_paths) >= 3, "Should scan multiple files"
