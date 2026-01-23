"""Tests for SARIF reporter."""

import io
import json

from gitleaks.reporting.sarif_reporter import SarifReporter
from gitleaks.reporting.finding import Finding


class TestSarifReporter:
    """Test SARIF reporter functionality."""

    def test_empty_findings(self):
        """Test SARIF reporter with no findings."""
        reporter = SarifReporter()
        output = io.StringIO()

        reporter.write(output, [])

        output.seek(0)
        content = json.load(output)

        assert content["version"] == "2.1.0"
        assert "$schema" in content
        assert len(content["runs"]) == 1
        assert len(content["runs"][0]["results"]) == 0

    def test_single_finding(self):
        """Test SARIF reporter with a single finding."""
        reporter = SarifReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="aws-access-key",
            description="AWS Access Key",
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
            tags=["key", "AWS"],
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = json.load(output)

        assert content["version"] == "2.1.0"
        assert len(content["runs"]) == 1
        run = content["runs"][0]

        # Check tool info
        assert run["tool"]["driver"]["name"] == "gitleaks"
        assert "semanticVersion" in run["tool"]["driver"]

        # Check results
        assert len(run["results"]) == 1
        result = run["results"][0]
        assert result["ruleId"] == "aws-access-key"
        assert "aws-access-key" in result["message"]["text"]
        assert result["partialFingerprints"]["commitSha"] == "abc123"
        assert result["partialFingerprints"]["author"] == "John Doe"
        assert result["properties"]["tags"] == ["key", "AWS"]

        # Check location
        assert len(result["locations"]) == 1
        location = result["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "config.yml"
        region = location["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["startColumn"] == 1

    def test_multiple_findings(self):
        """Test SARIF reporter with multiple findings."""
        reporter = SarifReporter()
        output = io.StringIO()

        findings = [
            Finding(
                rule_id="aws-access-key",
                description="AWS Access Key",
                file="config.yml",
                secret="AKIAIOSFODNN7EXAMPLE",
                match="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
                start_line=10,
                end_line=10,
                start_column=1,
                end_column=45,
            ),
            Finding(
                rule_id="generic-api-key",
                description="Generic API Key",
                file="app.py",
                secret="sk_test_123456",
                match="API_KEY = 'sk_test_123456'",
                start_line=5,
                end_line=5,
                start_column=1,
                end_column=30,
            ),
        ]

        reporter.write(output, findings)

        output.seek(0)
        content = json.load(output)

        assert len(content["runs"][0]["results"]) == 2

    def test_finding_with_symlink(self):
        """Test SARIF reporter prefers symlink file over real file."""
        reporter = SarifReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            description="Test Rule",
            file="/real/path/file.txt",
            symlink_file="/symlink/path/file.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
            end_line=1,
            start_column=1,
            end_column=20,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = json.load(output)

        result = content["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        # Should prefer symlink file
        assert uri == "/symlink/path/file.txt"

    def test_finding_without_commit(self):
        """Test SARIF reporter with finding that has no commit."""
        reporter = SarifReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            description="Test Rule",
            file="file.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
            end_line=1,
            start_column=1,
            end_column=20,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = json.load(output)

        result = content["runs"][0]["results"][0]
        # Message should not include commit
        assert "commit" not in result["message"]["text"].lower() or "at commit" not in result[
            "message"
        ]["text"]
