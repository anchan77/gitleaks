"""Tests for Jinja2 template reporter."""

import io
from pathlib import Path

import pytest

from gitleaks.reporting import Finding
from gitleaks.reporting.template_reporter import TemplateReporter


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


def test_template_reporter_default_template(sample_finding):
    """Test template reporter with default (basic) template."""
    reporter = TemplateReporter()
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    # Should produce HTML output
    assert "<!DOCTYPE html>" in result or "<html" in result
    assert "test-rule" in result
    assert "test.py" in result


def test_template_reporter_builtin_basic(sample_finding):
    """Test template reporter with built-in 'basic' template."""
    reporter = TemplateReporter(template_path="basic")
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "<!DOCTYPE html>" in result
    assert "Gitleaks Security Findings" in result
    assert "test-rule" in result


def test_template_reporter_builtin_leet(sample_finding):
    """Test template reporter with built-in 'leet' template."""
    reporter = TemplateReporter(template_path="leet")
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "<!DOCTYPE html>" in result
    assert "test-rule" in result


def test_template_reporter_builtin_myspace(sample_finding):
    """Test template reporter with built-in 'myspace' template."""
    reporter = TemplateReporter(template_path="myspace")
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "<!DOCTYPE html>" in result
    assert "test-rule" in result


def test_template_reporter_builtin_w98(sample_finding):
    """Test template reporter with built-in 'w98' template."""
    reporter = TemplateReporter(template_path="w98")
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "<!DOCTYPE html>" in result
    assert "test-rule" in result


def test_template_reporter_builtin_wxp(sample_finding):
    """Test template reporter with built-in 'wxp' template."""
    reporter = TemplateReporter(template_path="wxp")
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "<!DOCTYPE html>" in result
    assert "test-rule" in result


def test_template_reporter_custom_template(sample_finding, tmp_path):
    """Test template reporter with custom template file."""
    # Create a custom template
    template_file = tmp_path / "custom.html"
    template_file.write_text(
        """
<html>
<body>
<h1>Custom Template</h1>
{% for finding in findings %}
<div>Rule: {{ finding.rule_id }}</div>
<div>File: {{ finding.file }}</div>
{% endfor %}
</body>
</html>
"""
    )

    reporter = TemplateReporter(template_path=str(template_file))
    output = io.StringIO()

    reporter.write(output, [sample_finding])

    result = output.getvalue()

    assert "Custom Template" in result
    assert "test-rule" in result
    assert "test.py" in result


def test_template_reporter_invalid_builtin():
    """Test template reporter with invalid built-in template name."""
    with pytest.raises(FileNotFoundError):
        TemplateReporter(template_path="nonexistent")


def test_template_reporter_invalid_file_path():
    """Test template reporter with invalid file path."""
    with pytest.raises(FileNotFoundError):
        TemplateReporter(template_path="/nonexistent/path/template.html")


def test_template_reporter_empty_findings():
    """Test template reporter with no findings."""
    reporter = TemplateReporter(template_path="basic")
    output = io.StringIO()

    reporter.write(output, [])

    result = output.getvalue()

    # Should still produce valid HTML with no findings
    assert "<!DOCTYPE html>" in result
    assert "Gitleaks Security Findings" in result


def test_template_reporter_multiple_findings(sample_finding):
    """Test template reporter with multiple findings."""
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

    reporter = TemplateReporter(template_path="basic")
    output = io.StringIO()

    reporter.write(output, [sample_finding, finding2])

    result = output.getvalue()

    # Both findings should be present
    assert "test-rule" in result
    assert "another-rule" in result
    assert "test.py" in result
    assert "another.py" in result


def test_template_reporter_context_variables(sample_finding):
    """Test that template has access to all expected context variables."""
    # Create a simple template that uses context variables
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
        f.write(
            """
Length: {{ len(findings) }}
Now: {{ now.year }}
Finding: {{ findings[0].rule_id if findings else 'none' }}
"""
        )
        f.flush()

        reporter = TemplateReporter(template_path=f.name)
        output = io.StringIO()

        reporter.write(output, [sample_finding])

        result = output.getvalue()

        assert "Length: 1" in result
        assert "Now:" in result
        assert "Finding: test-rule" in result

        # Clean up
        Path(f.name).unlink()


def test_template_reporter_no_template_loaded_error():
    """Test that writing without a template raises an error."""
    reporter = TemplateReporter.__new__(TemplateReporter)
    reporter.template = None

    with pytest.raises(RuntimeError, match="No template loaded"):
        reporter.write(io.StringIO(), [])
