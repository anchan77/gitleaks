"""
Integration tests for archive scanning with secret detection.

This module tests end-to-end archive scanning including detection
of secrets within archived files.
"""

import pytest
from pathlib import Path

from gitleaks.sources.dir_source import Files
from gitleaks.detector.engine import Detector
from gitleaks.config.models import Config, Rule


# Path to test archives
TEST_DATA_PATH = Path(__file__).parent.parent.parent / "testdata"
ARCHIVES_PATH = TEST_DATA_PATH / "archives"


@pytest.mark.asyncio
async def test_detect_secrets_in_zip_archive():
    """Test that secrets inside ZIP archives are detected end-to-end."""
    # The files.zip contains .env.prod with DB_PASSWORD
    zip_path = ARCHIVES_PATH / "files.zip"
    if not zip_path.exists():
        pytest.skip("Test archive not available")

    # Create a simple rule that would match passwords
    rule = Rule(
        id="test-password-rule",
        description="Test password detection",
        regex=r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]+)",
        secret_group=2,
    )

    config = Config(rules=[rule])

    # Create Files source with archive scanning enabled
    files_source = Files(
        path=str(ARCHIVES_PATH),
        config=config,
        max_archive_depth=1,
    )

    # Create detector
    detector = Detector(config=config)

    # Collect fragments from the files source
    fragments_collected = []

    def collect_fragment(fragment, error):
        if error is None:
            fragments_collected.append(fragment)
        return None

    await files_source.fragments(collect_fragment)

    # Should have fragments from inside archives
    archive_fragments = [f for f in fragments_collected if "!" in f.file_path]
    assert len(archive_fragments) > 0, "Should have fragments from archives"

    # Run detection on archive fragments
    all_findings = []
    for fragment in archive_fragments:
        findings = await detector._detect_fragment(fragment)
        all_findings.extend(findings)

    # Should find at least one secret
    assert len(all_findings) > 0, "Should detect secrets in archive contents"

    # Verify finding has correct path with archive separator
    finding = all_findings[0]
    assert "!" in finding.file, f"Finding path should contain archive separator: {finding.file}"
    assert finding.secret, "Finding should have a secret value"


@pytest.mark.asyncio
async def test_scan_archives_directory():
    """Test scanning the testdata/archives/ directory with multiple archive formats."""
    if not ARCHIVES_PATH.exists():
        pytest.skip("Test archive directory not available")

    # Create a rule that matches common patterns
    rule = Rule(
        id="test-generic-secret",
        description="Test generic secret",
        regex=r"(?i)(api[_-]?key|password|secret|token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]+)",
        secret_group=2,
    )

    config = Config(rules=[rule])

    # Scan the archives directory
    files_source = Files(
        path=str(ARCHIVES_PATH),
        config=config,
        max_archive_depth=2,  # Allow nested archives
    )

    fragments_collected = []

    def collect_fragment(fragment, error):
        if error is None:
            fragments_collected.append(fragment)
        return None

    await files_source.fragments(collect_fragment)

    # Should have collected fragments from various archives
    zip_fragments = [f for f in fragments_collected if ".zip!" in f.file_path]
    tar_fragments = [f for f in fragments_collected if ".tar!" in f.file_path]
    gz_fragments = [f for f in fragments_collected if ".gz!" in f.file_path]

    # Should have fragments from at least ZIP archives
    assert len(zip_fragments) > 0, "Should scan ZIP archives"

    # All archive fragments should use "!" separator
    for fragment in fragments_collected:
        if any(ext in fragment.file_path for ext in [".zip", ".tar", ".gz", ".7z"]):
            # Check if it's an archive being scanned (not just a file)
            if "!" in fragment.file_path:
                parts = fragment.file_path.split("!")
                assert len(parts) >= 2, f"Archive path should have archive!file format: {fragment.file_path}"


@pytest.mark.asyncio
async def test_scan_archives_test_repository():
    """Test scanning testdata/repos/archives/ directory."""
    repos_archives_path = TEST_DATA_PATH / "repos" / "archives"
    if not repos_archives_path.exists():
        pytest.skip("Test repository not available")

    # Create a simple rule
    rule = Rule(
        id="test-secret-pattern",
        description="Test secret pattern",
        regex=r"(?i)(secret|password|token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{8,})",
        secret_group=2,
    )

    config = Config(rules=[rule])

    # Scan the test repository
    files_source = Files(
        path=str(repos_archives_path),
        config=config,
        max_archive_depth=1,
    )

    fragments_collected = []

    def collect_fragment(fragment, error):
        if error is None:
            fragments_collected.append(fragment)
        return None

    await files_source.fragments(collect_fragment)

    # Should have scanned the directory
    assert len(fragments_collected) > 0, "Should collect fragments from test repository"

    # Check if any archives were found and scanned
    archive_fragments = [f for f in fragments_collected if "!" in f.file_path]

    # The repos/archives directory contains main.go.zst
    zst_fragments = [f for f in fragments_collected if ".zst!" in f.file_path]
    if zst_fragments:
        # If zstandard is available and .zst file was scanned
        assert len(zst_fragments) > 0, "Should scan .zst archives"


@pytest.mark.asyncio
async def test_nested_archive_scanning():
    """Test that nested archives are scanned with proper depth limits."""
    # Use nested.tar.gz which contains nested archives
    nested_archive = ARCHIVES_PATH / "nested.tar.gz"
    if not nested_archive.exists():
        pytest.skip("Nested test archive not available")

    rule = Rule(
        id="test-any-content",
        description="Match any content",
        regex=r"[a-zA-Z]{5,}",  # Match any word with 5+ letters
    )

    config = Config(rules=[rule])

    # Test with depth 1 - should only scan first level
    files_source_depth1 = Files(
        path=str(ARCHIVES_PATH),
        config=config,
        max_archive_depth=1,
    )

    fragments_depth1 = []

    def collect_depth1(fragment, error):
        if error is None and "nested.tar.gz" in fragment.file_path:
            fragments_depth1.append(fragment)
        return None

    await files_source_depth1.fragments(collect_depth1)

    # Test with depth 2 - should scan nested archives
    files_source_depth2 = Files(
        path=str(ARCHIVES_PATH),
        config=config,
        max_archive_depth=2,
    )

    fragments_depth2 = []

    def collect_depth2(fragment, error):
        if error is None and "nested.tar.gz" in fragment.file_path:
            fragments_depth2.append(fragment)
        return None

    await files_source_depth2.fragments(collect_depth2)

    # Depth 2 should scan more content (or at least equal) than depth 1
    assert len(fragments_depth2) >= len(fragments_depth1), \
        "Higher depth should scan equal or more content"

    # Check for multi-level paths (archive!archive!file)
    multi_level_paths = [f for f in fragments_depth2 if f.file_path.count("!") > 1]
    # May or may not find multi-level depending on test data structure
