"""Tests for package version."""

import gitleaks


def test_version_exists():
    """Test that __version__ attribute exists."""
    assert hasattr(gitleaks, "__version__")


def test_version_is_string():
    """Test that __version__ is a string."""
    assert isinstance(gitleaks.__version__, str)


def test_version_format():
    """Test that version follows semantic versioning format."""
    version = gitleaks.__version__
    parts = version.split(".")
    # Should have at least major.minor.patch
    assert len(parts) >= 3
    # Major version should be numeric
    assert parts[0].isdigit()
