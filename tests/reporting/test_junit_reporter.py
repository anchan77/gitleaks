"""Tests for JUnit XML reporter."""

import io
import xml.etree.ElementTree as ET

import pytest

from gitleaks.reporting import Finding
from gitleaks.reporting.junit_reporter import JunitReporter


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
    )


def test_junit_reporter_basic_structure(sample_finding):
    """Test JUnit reporter produces valid XML structure."""
    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    # Check root element
    assert root.tag == "testsuites"

    # Check testsuite
    testsuite = root.find("testsuite")
    assert testsuite is not None
    assert testsuite.get("name") == "gitleaks"
    assert testsuite.get("tests") == "1"
    assert testsuite.get("failures") == "1"


def test_junit_reporter_empty_findings():
    """Test JUnit reporter with no findings."""
    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    testsuite = root.find("testsuite")
    assert testsuite.get("tests") == "0"
    assert testsuite.get("failures") == "0"


def test_junit_reporter_testcase_details(sample_finding):
    """Test JUnit reporter includes testcase details."""
    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    testcase = root.find(".//testcase")
    assert testcase is not None
    assert testcase.get("classname") == "Test Rule"
    assert testcase.get("file") == "test.py"
    assert "test-rule" in testcase.get("name")
    assert "line 10" in testcase.get("name")


def test_junit_reporter_failure_element(sample_finding):
    """Test JUnit reporter includes failure element with details."""
    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    failure = root.find(".//failure")
    assert failure is not None
    assert failure.get("type") == "Test Rule"
    assert "test-rule" in failure.get("message")

    # Check failure contains JSON data
    failure_text = failure.text
    assert "RuleID" in failure_text
    assert "test-rule" in failure_text
    assert "test.py" in failure_text


def test_junit_reporter_multiple_findings(sample_finding):
    """Test JUnit reporter with multiple findings."""
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
    )

    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding, finding2])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    testsuite = root.find("testsuite")
    assert testsuite.get("tests") == "2"
    assert testsuite.get("failures") == "2"

    testcases = root.findall(".//testcase")
    assert len(testcases) == 2


def test_junit_reporter_message_without_commit():
    """Test JUnit reporter message format when commit is not present."""
    finding = Finding(
        rule_id="test-rule",
        description="Test Rule",
        file="test.py",
        secret="secret",
        match="secret",
        start_line=5,
        end_line=5,
        start_column=1,
        end_column=10,
    )

    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [finding])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    testcase = root.find(".//testcase")
    name = testcase.get("name")
    assert "test-rule has detected a secret in file test.py, line 5." == name
    assert "commit" not in name


def test_junit_reporter_message_with_commit(sample_finding):
    """Test JUnit reporter message format when commit is present."""
    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    tree = ET.parse(output)
    root = tree.getroot()

    testcase = root.find(".//testcase")
    name = testcase.get("name")
    assert (
        "test-rule has detected a secret in file test.py, line 10, at commit abc123def456."
        == name
    )


def test_junit_reporter_xml_escaping():
    """Test JUnit reporter properly escapes XML special characters."""
    finding = Finding(
        rule_id="test-rule",
        description='Test <Rule> & "Description"',
        file="test.py",
        secret="secret",
        match="secret",
        start_line=1,
        end_line=1,
        start_column=1,
        end_column=10,
    )

    reporter = JunitReporter()
    output = io.StringIO()

    reporter.write(output, [finding])

    output.seek(0)
    # Should be valid XML
    tree = ET.parse(output)
    root = tree.getroot()

    testcase = root.find(".//testcase")
    classname = testcase.get("classname")
    # XML parser should decode the escaped characters
    assert "<" in classname or "&lt;" in ET.tostring(testcase, encoding="unicode")
