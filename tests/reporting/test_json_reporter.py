"""
Tests for the JSON reporter.

Ports tests from report/json_test.go
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
from gitleaks.reporting.finding import Finding
from gitleaks.reporting.json_reporter import JsonReporter


# Test data matching the Go test
SIMPLE_FINDING = Finding(
    description="",
    rule_id="test-rule",
    match="line containing secret",
    secret="a secret",
    start_line=1,
    end_line=2,
    start_column=1,
    end_column=2,
    message="opps",
    file="auth.py",
    symlink_file="",
    commit="0000000000000000",
    author="John Doe",
    email="johndoe@gmail.com",
    date="10-19-2003",
    tags=[],
)


class TestWriteJSON:
    """Test JSON reporter output."""

    def test_simple(self, tmp_path):
        """Test writing a simple finding to JSON."""
        reporter = JsonReporter()
        output_file = tmp_path / "simple.json"

        # Write the findings
        with open(output_file, "w") as f:
            reporter.write(f, [SIMPLE_FINDING])

        # Read the output
        with open(output_file, "r") as f:
            output = f.read()

        # Load expected output
        expected_path = Path(__file__).parent.parent.parent / "testdata" / "expected" / "report" / "json_simple.json"
        with open(expected_path, "r") as f:
            expected = f.read()

        # Normalize line endings for comparison
        output_normalized = output.replace("\r\n", "\n")
        expected_normalized = expected.replace("\r\n", "\n")

        assert output_normalized == expected_normalized

        # Also verify it's valid JSON
        parsed = json.loads(output)
        assert len(parsed) == 1
        assert parsed[0]["RuleID"] == "test-rule"
        assert parsed[0]["Secret"] == "a secret"

    def test_empty(self, tmp_path):
        """Test writing an empty list of findings."""
        reporter = JsonReporter()
        output_file = tmp_path / "empty.json"

        # Write empty findings
        with open(output_file, "w") as f:
            reporter.write(f, [])

        # Read the output
        with open(output_file, "r") as f:
            output = f.read()

        # Load expected output
        expected_path = Path(__file__).parent.parent.parent / "testdata" / "expected" / "report" / "empty.json"
        with open(expected_path, "r") as f:
            expected = f.read()

        # Normalize line endings
        output_normalized = output.replace("\r\n", "\n")
        expected_normalized = expected.replace("\r\n", "\n")

        assert output_normalized == expected_normalized

        # Verify it's valid JSON
        parsed = json.loads(output)
        assert parsed == []

    def test_json_fields(self):
        """Test that JSON output includes correct fields."""
        reporter = JsonReporter()
        finding = Finding(
            rule_id="test",
            description="Test desc",
            start_line=10,
            end_line=11,
            start_column=5,
            end_column=15,
            match="matched text",
            secret="secret123",
            file="test.txt",
            symlink_file="",
            commit="abc123",
            link="https://example.com",
            entropy=3.5,
            author="Author",
            email="author@example.com",
            date="2023-01-01",
            message="commit msg",
            tags=["tag1", "tag2"],
            fingerprint="abc",
            line="This line should not appear in JSON",
        )

        # Write to a string buffer
        import io
        buffer = io.StringIO()
        reporter.write(buffer, [finding])
        output = buffer.getvalue()

        # Parse and verify
        parsed = json.loads(output)
        assert len(parsed) == 1
        finding_dict = parsed[0]

        # Check included fields
        assert finding_dict["RuleID"] == "test"
        assert finding_dict["Description"] == "Test desc"
        assert finding_dict["StartLine"] == 10
        assert finding_dict["EndLine"] == 11
        assert finding_dict["StartColumn"] == 5
        assert finding_dict["EndColumn"] == 15
        assert finding_dict["Match"] == "matched text"
        assert finding_dict["Secret"] == "secret123"
        assert finding_dict["File"] == "test.txt"
        assert finding_dict["SymlinkFile"] == ""
        assert finding_dict["Commit"] == "abc123"
        assert finding_dict["Link"] == "https://example.com"
        assert finding_dict["Entropy"] == 3.5
        assert finding_dict["Author"] == "Author"
        assert finding_dict["Email"] == "author@example.com"
        assert finding_dict["Date"] == "2023-01-01"
        assert finding_dict["Message"] == "commit msg"
        assert finding_dict["Tags"] == ["tag1", "tag2"]
        assert finding_dict["Fingerprint"] == "abc"

        # Check that 'line' field is NOT in JSON (marked as json:"-" in Go)
        assert "Line" not in finding_dict
        assert "line" not in finding_dict

    def test_json_omits_empty_link(self):
        """Test that empty Link field is omitted (omitempty in Go)."""
        reporter = JsonReporter()
        finding = Finding(
            rule_id="test",
            file="test.txt",
            link="",  # Empty link should be omitted
        )

        import io
        buffer = io.StringIO()
        reporter.write(buffer, [finding])
        output = buffer.getvalue()

        parsed = json.loads(output)
        finding_dict = parsed[0]

        # Link should not be in the output
        assert "Link" not in finding_dict
