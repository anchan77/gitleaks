"""Tests for CSV reporter."""

import io
import csv

from gitleaks.reporting.csv_reporter import CsvReporter
from gitleaks.reporting.finding import Finding


class TestCsvReporter:
    """Test CSV reporter functionality."""

    def test_empty_findings(self):
        """Test CSV reporter with no findings."""
        reporter = CsvReporter()
        output = io.StringIO()

        reporter.write(output, [])

        output.seek(0)
        content = output.read()
        assert content == ""

    def test_single_finding(self):
        """Test CSV reporter with a single finding."""
        reporter = CsvReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="aws-access-key",
            commit="abc123",
            file="config.yml",
            secret="AKIAIOSFODNN7EXAMPLE",
            match="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            start_line=10,
            end_line=10,
            start_column=1,
            end_column=45,
            author="John Doe",
            message="Add AWS credentials",
            date="2024-01-15",
            email="john@example.com",
            fingerprint="abc123:config.yml:aws-access-key:10",
            tags=["key", "AWS"],
        )

        reporter.write(output, [finding])

        output.seek(0)
        reader = csv.DictReader(output)
        rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["RuleID"] == "aws-access-key"
        assert rows[0]["Commit"] == "abc123"
        assert rows[0]["File"] == "config.yml"
        assert rows[0]["Secret"] == "AKIAIOSFODNN7EXAMPLE"
        assert rows[0]["StartLine"] == "10"
        assert rows[0]["Tags"] == "key AWS"

    def test_multiple_findings(self):
        """Test CSV reporter with multiple findings."""
        reporter = CsvReporter()
        output = io.StringIO()

        findings = [
            Finding(
                rule_id="aws-access-key",
                file="config.yml",
                secret="AKIAIOSFODNN7EXAMPLE",
                match="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
                start_line=10,
            ),
            Finding(
                rule_id="generic-api-key",
                file="app.py",
                secret="sk_test_123456",
                match="API_KEY = 'sk_test_123456'",
                start_line=5,
            ),
        ]

        reporter.write(output, findings)

        output.seek(0)
        reader = csv.DictReader(output)
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["RuleID"] == "aws-access-key"
        assert rows[1]["RuleID"] == "generic-api-key"

    def test_finding_with_symlink(self):
        """Test CSV reporter with symlink file."""
        reporter = CsvReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="/real/path/file.txt",
            symlink_file="/symlink/path/file.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        reader = csv.DictReader(output)
        rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["File"] == "/real/path/file.txt"
        assert rows[0]["SymlinkFile"] == "/symlink/path/file.txt"
