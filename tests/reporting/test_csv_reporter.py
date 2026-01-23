"""Tests for CSV reporter."""

import io

import pytest

from gitleaks.reporting import Finding
from gitleaks.reporting.csv_reporter import CsvReporter


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        rule_id="test-rule",
        description="Test Rule",
        file="test.py",
        secret="my-secret",
        match="password=my-secret",
        start_line=10,
        end_line=10,
        start_column=5,
        end_column=20,
        commit="abc123def456",
        author="Test Author",
        email="test@example.com",
        message="Test commit message",
        date="2024-01-01",
        tags=["test", "secret"],
        fingerprint="fingerprint123",
    )


def test_csv_reporter_empty_findings():
    """Test CSV reporter with no findings."""
    reporter = CsvReporter()
    output = io.StringIO()

    reporter.write(output, [])

    # Empty findings should produce no output
    assert output.getvalue() == ""


def test_csv_reporter_single_finding(sample_finding):
    """Test CSV reporter with a single finding."""
    reporter = CsvReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()
    lines = result.strip().split("\n")

    # Should have header + 1 data row
    assert len(lines) == 2

    # Check header
    assert "RuleID" in lines[0]
    assert "File" in lines[0]
    assert "Secret" in lines[0]

    # Check data
    assert "test-rule" in lines[1]
    assert "test.py" in lines[1]
    assert "my-secret" in lines[1]
    assert "test secret" in lines[1]  # Tags joined with space


def test_csv_reporter_multiple_findings(sample_finding):
    """Test CSV reporter with multiple findings."""
    finding2 = Finding(
        rule_id="another-rule",
        description="Another Rule",
        file="another.py",
        secret="another-secret",
        match="key=another-secret",
        start_line=20,
        end_line=20,
        start_column=1,
        end_column=15,
        tags=["prod"],
    )

    reporter = CsvReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding, finding2])

    result = output.getvalue()
    lines = result.strip().split("\n")

    # Should have header + 2 data rows
    assert len(lines) == 3

    # Check both findings are present
    assert "test-rule" in result
    assert "another-rule" in result


def test_csv_reporter_with_link():
    """Test CSV reporter with finding that has a link."""
    finding_with_link = Finding(
        rule_id="test-rule",
        description="Test Rule",
        file="test.py",
        secret="secret",
        match="secret",
        start_line=1,
        end_line=1,
        start_column=1,
        end_column=10,
        link="https://github.com/repo/commit/abc123",
    )

    reporter = CsvReporter()
    output = io.StringIO()

    reporter.write(output, [finding_with_link])

    result = output.getvalue()
    lines = result.strip().split("\n")

    # Check header includes Link column
    assert "Link" in lines[0]

    # Check link is in data
    assert "https://github.com/repo/commit/abc123" in lines[1]
