"""Tests for SARIF reporter."""

import io
import json

import pytest

from gitleaks.config.models import Rule
from gitleaks.reporting import Finding
from gitleaks.reporting.sarif_reporter import SarifReporter


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


@pytest.fixture
def sample_rules():
    """Create sample rules for testing."""
    return [
        Rule(id="rule-1", description="Rule 1", regex="secret1", keywords=["secret"]),
        Rule(id="rule-2", description="Rule 2", regex="secret2", keywords=["key"]),
    ]


def test_sarif_reporter_basic_structure(sample_finding):
    """Test SARIF reporter produces valid SARIF 2.1.0 structure."""
    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    sarif = json.load(output)

    # Check SARIF schema
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_reporter_tool_metadata(sample_finding):
    """Test SARIF reporter includes correct tool metadata."""
    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    sarif = json.load(output)

    tool = sarif["runs"][0]["tool"]
    driver = tool["driver"]

    assert driver["name"] == "gitleaks"
    assert "semanticVersion" in driver
    assert driver["informationUri"] == "https://github.com/gitleaks/gitleaks"
    assert isinstance(driver["rules"], list)


def test_sarif_reporter_empty_findings():
    """Test SARIF reporter with no findings."""
    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [])

    output.seek(0)
    sarif = json.load(output)

    # Should still have valid structure
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []


def test_sarif_reporter_finding_details(sample_finding):
    """Test SARIF reporter includes all finding details."""
    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    sarif = json.load(output)

    result = sarif["runs"][0]["results"][0]

    # Check basic fields
    assert result["ruleId"] == "test-rule"
    assert "message" in result
    assert "test.py" in result["message"]["text"]

    # Check locations
    assert len(result["locations"]) == 1
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "test.py"
    assert location["region"]["startLine"] == 10
    assert location["region"]["endLine"] == 10
    assert location["region"]["snippet"]["text"] == "my-secret"

    # Check partial fingerprints (commit metadata)
    fingerprints = result["partialFingerprints"]
    assert fingerprints["commitSha"] == "abc123def456"
    assert fingerprints["author"] == "Test Author"
    assert fingerprints["email"] == "test@example.com"

    # Check properties (tags)
    assert result["properties"]["tags"] == ["test", "secret"]


def test_sarif_reporter_with_ordered_rules(sample_finding, sample_rules):
    """Test SARIF reporter with ordered rules."""
    reporter = SarifReporter(ordered_rules=sample_rules)
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    sarif = json.load(output)

    # Check rules are included
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    assert rules[0]["id"] == "rule-1"
    assert rules[0]["shortDescription"]["text"] == "Rule 1"
    assert rules[1]["id"] == "rule-2"
    assert rules[1]["shortDescription"]["text"] == "Rule 2"


def test_sarif_reporter_symlink_file():
    """Test SARIF reporter uses symlink file when present."""
    finding = Finding(
        rule_id="test-rule",
        description="Test Rule",
        file="/actual/path.py",
        symlink_file="/link/to/path.py",
        secret="secret",
        match="secret",
        start_line=1,
        end_line=1,
        start_column=1,
        end_column=10,
    )

    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [finding])

    output.seek(0)
    sarif = json.load(output)

    # Should use symlink file as URI
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "/link/to/path.py"


def test_sarif_reporter_message_without_commit():
    """Test SARIF reporter message format when commit is not present."""
    finding = Finding(
        rule_id="test-rule",
        description="Test Rule",
        file="test.py",
        secret="secret",
        match="secret",
        start_line=1,
        end_line=1,
        start_column=1,
        end_column=10,
    )

    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [finding])

    output.seek(0)
    sarif = json.load(output)

    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "test-rule has detected secret for file test.py." == message
    assert "commit" not in message


def test_sarif_reporter_message_with_commit(sample_finding):
    """Test SARIF reporter message format when commit is present."""
    reporter = SarifReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    output.seek(0)
    sarif = json.load(output)

    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert (
        "test-rule has detected secret for file test.py at commit abc123def456."
        == message
    )
