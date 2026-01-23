"""Tests for JUnit reporter."""

import io
import xml.etree.ElementTree as ET

from gitleaks.reporting.junit_reporter import JunitReporter
from gitleaks.reporting.finding import Finding


class TestJunitReporter:
    """Test JUnit reporter functionality."""

    def test_empty_findings(self):
        """Test JUnit reporter with no findings."""
        reporter = JunitReporter()
        output = io.StringIO()

        reporter.write(output, [])

        output.seek(0)
        content = output.read()

        # Parse XML
        root = ET.fromstring(content)
        assert root.tag == "testsuites"

        # Should have one testsuite with 0 tests
        testsuites = root.findall("testsuite")
        assert len(testsuites) == 1
        assert testsuites[0].get("tests") == "0"
        assert testsuites[0].get("failures") == "0"

    def test_single_finding(self):
        """Test JUnit reporter with a single finding."""
        reporter = JunitReporter()
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
            fingerprint="abc123:config.yml:aws-access-key:10",
            tags=["key", "AWS"],
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        # Parse XML
        root = ET.fromstring(content)
        testsuites = root.findall("testsuite")
        assert len(testsuites) == 1
        assert testsuites[0].get("tests") == "1"
        assert testsuites[0].get("failures") == "1"
        assert testsuites[0].get("name") == "gitleaks"

        # Check test case
        testcases = testsuites[0].findall("testcase")
        assert len(testcases) == 1
        testcase = testcases[0]
        assert testcase.get("classname") == "AWS Access Key"
        assert testcase.get("file") == "config.yml"
        assert "aws-access-key" in testcase.get("name")
        assert "line 10" in testcase.get("name")
        assert "commit abc123" in testcase.get("name")

        # Check failure
        failures = testcase.findall("failure")
        assert len(failures) == 1
        failure = failures[0]
        assert failure.get("type") == "AWS Access Key"
        assert "aws-access-key" in failure.get("message")

    def test_multiple_findings(self):
        """Test JUnit reporter with multiple findings."""
        reporter = JunitReporter()
        output = io.StringIO()

        findings = [
            Finding(
                rule_id="aws-access-key",
                description="AWS Access Key",
                file="config.yml",
                secret="AKIAIOSFODNN7EXAMPLE",
                match="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
                start_line=10,
            ),
            Finding(
                rule_id="generic-api-key",
                description="Generic API Key",
                file="app.py",
                secret="sk_test_123456",
                match="API_KEY = 'sk_test_123456'",
                start_line=5,
            ),
        ]

        reporter.write(output, findings)

        output.seek(0)
        content = output.read()

        # Parse XML
        root = ET.fromstring(content)
        testsuites = root.findall("testsuite")
        assert testsuites[0].get("tests") == "2"
        assert testsuites[0].get("failures") == "2"

        testcases = testsuites[0].findall("testcase")
        assert len(testcases) == 2

    def test_finding_without_commit(self):
        """Test JUnit reporter with finding that has no commit."""
        reporter = JunitReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            description="Test Rule",
            file="file.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        # Parse XML
        root = ET.fromstring(content)
        testcases = root.findall(".//testcase")
        assert len(testcases) == 1
        # Message should not include commit
        assert "commit" not in testcases[0].get("name")

    def test_xml_escaping(self):
        """Test that special XML characters are properly escaped."""
        reporter = JunitReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            description="Test & Rule with <special> chars",
            file="file.txt",
            secret="secret123",
            match='password="secret123"',
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        # Parse XML - if escaping is wrong, this will fail
        root = ET.fromstring(content)
        testcases = root.findall(".//testcase")
        assert len(testcases) == 1
        assert "&" in testcases[0].get("classname")
        # Check that special chars are escaped in attribute value
        assert "&lt;special&gt;" in content
        assert "&amp;" in content
