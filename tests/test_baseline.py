"""
Tests for baseline support in gitleaks.

This module tests baseline loading, finding comparison, and baseline filtering.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from gitleaks.detector.baseline import load_baseline, is_new_finding
from gitleaks.reporting.finding import Finding


class TestLoadBaseline:
    """Tests for baseline loading from JSON files."""

    def test_load_valid_baseline(self, tmp_path):
        """Test loading a valid baseline JSON file."""
        # Create a baseline file
        baseline_data = [
            {
                "RuleID": "test-rule",
                "Description": "Test rule",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 0,
                "EndColumn": 10,
                "Match": "test secret",
                "Secret": "test secret",
                "File": "test.txt",
                "Commit": "abc123",
                "Entropy": 3.5,
                "Author": "Test Author",
                "Email": "test@example.com",
                "Date": "2025-01-01T00:00:00Z",
                "Message": "Test commit",
                "Tags": ["tag1"],
                "Fingerprint": "abc123:test.txt:test-rule:1",
            }
        ]

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        # Load baseline
        findings = load_baseline(str(baseline_file))

        assert len(findings) == 1
        assert findings[0].rule_id == "test-rule"
        assert findings[0].file == "test.txt"
        assert findings[0].commit == "abc123"

    def test_load_nonexistent_file(self):
        """Test loading a baseline file that doesn't exist."""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_baseline("nonexistent.json")
        assert "could not open" in str(exc_info.value)

    def test_load_invalid_json(self, tmp_path):
        """Test loading a file with invalid JSON."""
        baseline_file = tmp_path / "invalid.json"
        with open(baseline_file, "w") as f:
            f.write("not valid json{")

        with pytest.raises(ValueError) as exc_info:
            load_baseline(str(baseline_file))
        assert "not supported" in str(exc_info.value)

    def test_load_csv_format(self, tmp_path):
        """Test loading a CSV file (should fail)."""
        baseline_file = tmp_path / "baseline.csv"
        with open(baseline_file, "w") as f:
            f.write("RuleID,File,Line\n")
            f.write("test-rule,test.txt,1\n")

        with pytest.raises(ValueError) as exc_info:
            load_baseline(str(baseline_file))
        assert "not supported" in str(exc_info.value)


class TestIsNewFinding:
    """Tests for finding comparison against baseline."""

    def test_new_finding_commit_differs(self):
        """Test that finding is new when commit differs."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit2",  # Different commit
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
            )
        ]

        assert is_new_finding(finding, 0, baseline) is True

    def test_not_new_finding_exact_match(self):
        """Test that finding is not new when it matches baseline exactly."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
            )
        ]

        assert is_new_finding(finding, 0, baseline) is False

    def test_not_new_finding_tags_ignored(self):
        """Test that tags are ignored when comparing findings."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
            tags=["tag1", "tag2"],
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
                tags=["tag3"],  # Different tags
            )
        ]

        # Tags are ignored, so this should not be new
        assert is_new_finding(finding, 0, baseline) is False

    def test_redacted_finding_match(self):
        """Test that redacted findings match when other fields match."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="REDACTED",
            secret="REDACTED",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
            entropy=3.5,
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="actual secret",
                secret="actual secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
                entropy=3.5,
            )
        ]

        # With redact > 0, match and secret are not compared
        assert is_new_finding(finding, 100, baseline) is False

        # Without redact, they don't match
        assert is_new_finding(finding, 0, baseline) is True

    def test_new_finding_different_line(self):
        """Test that finding is new when line number differs."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=2,  # Different line
            end_line=2,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
            )
        ]

        assert is_new_finding(finding, 0, baseline) is True

    def test_empty_baseline(self):
        """Test that all findings are new when baseline is empty."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
        )

        assert is_new_finding(finding, 0, []) is True

    def test_multiple_baseline_findings(self):
        """Test comparing against multiple baseline findings."""
        finding = Finding(
            rule_id="test-rule",
            description="test",
            start_line=2,
            end_line=2,
            start_column=0,
            end_column=10,
            match="secret",
            secret="secret",
            file="test.txt",
            commit="commit1",
            author="author",
            email="email@test.com",
            date="2025-01-01",
            message="msg",
        )

        baseline = [
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=1,
                end_line=1,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
            ),
            Finding(
                rule_id="test-rule",
                description="test",
                start_line=2,
                end_line=2,
                start_column=0,
                end_column=10,
                match="secret",
                secret="secret",
                file="test.txt",
                commit="commit1",
                author="author",
                email="email@test.com",
                date="2025-01-01",
                message="msg",
            ),
        ]

        # Should match the second baseline finding
        assert is_new_finding(finding, 0, baseline) is False
