"""
Integration tests for baseline and gitleaksignore support in the detector.

These tests verify that the detector correctly filters findings using baseline
and gitleaksignore files.
"""

import json
import tempfile
from pathlib import Path

import pytest

from gitleaks.config.loader import load_config
from gitleaks.detector.engine import Detector
from gitleaks.reporting.finding import Finding


class TestDetectorBaseline:
    """Tests for detector baseline integration."""

    def test_add_baseline_valid(self, tmp_path):
        """Test adding a valid baseline to detector."""
        config = load_config(None)
        detector = Detector(config)

        # Create a baseline file
        baseline_data = [
            {
                "RuleID": "test-rule",
                "Description": "Test",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 0,
                "EndColumn": 10,
                "Match": "secret",
                "Secret": "secret",
                "File": "test.txt",
                "Commit": "abc123",
                "Entropy": 3.0,
                "Author": "Test",
                "Email": "test@test.com",
                "Date": "2025-01-01",
                "Message": "test",
                "Tags": [],
                "Fingerprint": "abc123:test.txt:test-rule:1",
            }
        ]

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        # Add baseline
        detector.add_baseline(str(baseline_file), str(tmp_path))

        assert len(detector.baseline) == 1
        assert detector.baseline[0].rule_id == "test-rule"

    def test_add_baseline_nonexistent(self, tmp_path):
        """Test adding a nonexistent baseline file."""
        config = load_config(None)
        detector = Detector(config)

        with pytest.raises(FileNotFoundError):
            detector.add_baseline("nonexistent.json", str(tmp_path))

    def test_baseline_filtering(self, tmp_path):
        """Test that baseline findings are suppressed."""
        config = load_config(None)
        detector = Detector(config)

        # Create a baseline with one finding
        baseline_data = [
            {
                "RuleID": "test-rule",
                "Description": "Test",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 0,
                "EndColumn": 10,
                "Match": "secret123",
                "Secret": "secret123",
                "File": "test.txt",
                "Commit": "abc123",
                "Entropy": 3.0,
                "Author": "Test",
                "Email": "test@test.com",
                "Date": "2025-01-01",
                "Message": "test",
                "Tags": [],
                "Fingerprint": "abc123:test.txt:test-rule:1",
            }
        ]

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        detector.add_baseline(str(baseline_file), str(tmp_path))

        # Create a finding that matches baseline
        baseline_finding = Finding(
            rule_id="test-rule",
            description="Test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="secret123",
            secret="secret123",
            file="test.txt",
            commit="abc123",
            entropy=3.0,
            author="Test",
            email="test@test.com",
            date="2025-01-01",
            message="test",
        )
        baseline_finding.fingerprint = "abc123:test.txt:test-rule:1"

        # Create a new finding
        new_finding = Finding(
            rule_id="test-rule",
            description="Test",
            start_line=2,  # Different line
            end_line=2,
            start_column=0,
            end_column=10,
            match="secret456",
            secret="secret456",
            file="test.txt",
            commit="abc123",
            entropy=3.0,
            author="Test",
            email="test@test.com",
            date="2025-01-01",
            message="test",
        )
        new_finding.fingerprint = "abc123:test.txt:test-rule:2"

        # Test suppression
        from gitleaks.config.models import Rule
        dummy_rule = Rule(id="test-rule", description="Test", regex="test")

        # Baseline finding should be suppressed
        assert detector._should_suppress_finding(baseline_finding, dummy_rule) is True

        # New finding should not be suppressed
        assert detector._should_suppress_finding(new_finding, dummy_rule) is False


class TestDetectorGitleaksIgnore:
    """Tests for detector gitleaksignore integration."""

    def test_add_gitleaksignore_valid(self, tmp_path):
        """Test adding a valid .gitleaksignore file."""
        config = load_config(None)
        detector = Detector(config)

        # Create a .gitleaksignore file
        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("# Comment\n")
            f.write("file1.txt:rule-id:10\n")
            f.write("abc123:file2.txt:rule-id:20\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        assert len(detector.gitleaks_ignore) == 2
        assert "file1.txt:rule-id:10" in detector.gitleaks_ignore
        assert "abc123:file2.txt:rule-id:20" in detector.gitleaks_ignore

    def test_add_gitleaksignore_nonexistent(self):
        """Test adding a nonexistent .gitleaksignore file."""
        config = load_config(None)
        detector = Detector(config)

        with pytest.raises(FileNotFoundError):
            detector.add_gitleaks_ignore("nonexistent.gitleaksignore")

    def test_gitleaksignore_empty_lines(self, tmp_path):
        """Test that empty lines are ignored."""
        config = load_config(None)
        detector = Detector(config)

        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("\n")
            f.write("file1.txt:rule-id:10\n")
            f.write("\n")
            f.write("file2.txt:rule-id:20\n")
            f.write("\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        assert len(detector.gitleaks_ignore) == 2

    def test_gitleaksignore_comments(self, tmp_path):
        """Test that comments are ignored."""
        config = load_config(None)
        detector = Detector(config)

        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("# This is a comment\n")
            f.write("file1.txt:rule-id:10\n")
            f.write("# Another comment\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        assert len(detector.gitleaks_ignore) == 1

    def test_gitleaksignore_windows_paths(self, tmp_path):
        """Test that Windows paths are normalized."""
        config = load_config(None)
        detector = Detector(config)

        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("path\\to\\file.txt:rule-id:10\n")
            f.write("abc123:path\\to\\file2.txt:rule-id:20\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        # Paths should be normalized to use forward slashes
        assert "path/to/file.txt:rule-id:10" in detector.gitleaks_ignore
        assert "abc123:path/to/file2.txt:rule-id:20" in detector.gitleaks_ignore

    def test_gitleaksignore_filtering_global(self, tmp_path):
        """Test that global fingerprints suppress findings."""
        config = load_config(None)
        detector = Detector(config)

        # Create .gitleaksignore with global fingerprint
        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("test.txt:test-rule:10\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        # Create finding with matching fingerprint
        finding = Finding(
            rule_id="test-rule",
            description="Test",
            start_line=10,
            end_line=10,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
        )
        finding.fingerprint = "test.txt:test-rule:10"

        from gitleaks.config.models import Rule
        dummy_rule = Rule(id="test-rule", description="Test", regex="test")

        # Finding should be suppressed
        assert detector._should_suppress_finding(finding, dummy_rule) is True

    def test_gitleaksignore_filtering_commit(self, tmp_path):
        """Test that commit fingerprints suppress findings."""
        config = load_config(None)
        detector = Detector(config)

        # Create .gitleaksignore with commit fingerprint
        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("abc123:test.txt:test-rule:10\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        # Create finding with matching fingerprint
        finding = Finding(
            rule_id="test-rule",
            description="Test",
            start_line=10,
            end_line=10,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="abc123",
        )
        finding.fingerprint = "abc123:test.txt:test-rule:10"

        from gitleaks.config.models import Rule
        dummy_rule = Rule(id="test-rule", description="Test", regex="test")

        # Finding should be suppressed
        assert detector._should_suppress_finding(finding, dummy_rule) is True

    def test_gitleaksignore_no_match(self, tmp_path):
        """Test that non-matching findings are not suppressed."""
        config = load_config(None)
        detector = Detector(config)

        # Create .gitleaksignore
        ignore_file = tmp_path / ".gitleaksignore"
        with open(ignore_file, "w") as f:
            f.write("other.txt:test-rule:10\n")

        detector.add_gitleaks_ignore(str(ignore_file))

        # Create finding that doesn't match
        finding = Finding(
            rule_id="test-rule",
            description="Test",
            start_line=20,  # Different line
            end_line=20,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
        )
        finding.fingerprint = "test.txt:test-rule:20"

        from gitleaks.config.models import Rule
        dummy_rule = Rule(id="test-rule", description="Test", regex="test")

        # Finding should not be suppressed
        assert detector._should_suppress_finding(finding, dummy_rule) is False
