"""Tests for template reporter."""

import io
import tempfile
from pathlib import Path

import pytest

from gitleaks.reporting.template_reporter import TemplateReporter
from gitleaks.reporting.finding import Finding


class TestTemplateReporter:
    """Test template reporter functionality."""

    def test_builtin_template(self):
        """Test template reporter with built-in template."""
        reporter = TemplateReporter()
        output = io.StringIO()

        finding = Finding(
            rule_id="aws-access-key",
            description="AWS Access Key",
            file="config.yml",
            secret="AKIAIOSFODNN7EXAMPLE",
            match="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            start_line=10,
            tags=["key", "AWS"],
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        # Should be HTML
        assert "<!DOCTYPE html>" in content
        assert "aws-access-key" in content
        assert "config.yml" in content

    def test_custom_template(self):
        """Test template reporter with custom template."""
        # Create a temporary template file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write("<html>Total: {{ findings|length }}</html>")
            template_path = f.name

        try:
            reporter = TemplateReporter(template_path=template_path)
            output = io.StringIO()

            findings = [
                Finding(
                    rule_id="rule1",
                    file="file1.txt",
                    secret="secret1",
                    match="match1",
                    start_line=1,
                ),
                Finding(
                    rule_id="rule2",
                    file="file2.txt",
                    secret="secret2",
                    match="match2",
                    start_line=2,
                ),
            ]

            reporter.write(output, findings)

            output.seek(0)
            content = output.read()

            assert "<html>Total: 2</html>" in content
        finally:
            Path(template_path).unlink()

    def test_empty_template_path_raises_error(self):
        """Test that empty template path raises ValueError."""
        with pytest.raises(ValueError, match="template path cannot be empty"):
            TemplateReporter(template_path="")

    def test_nonexistent_template_raises_error(self):
        """Test that nonexistent template file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            TemplateReporter(template_path="/nonexistent/template.html")

    def test_template_with_finding_fields(self):
        """Test that template can access all finding fields."""
        # Create a template that uses various fields
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(
                """
                {% for finding in findings %}
                Rule: {{ finding.rule_id }}
                File: {{ finding.file }}
                Line: {{ finding.start_line }}
                Secret: {{ finding.secret }}
                {% endfor %}
                """
            )
            template_path = f.name

        try:
            reporter = TemplateReporter(template_path=template_path)
            output = io.StringIO()

            finding = Finding(
                rule_id="test-rule",
                file="test.txt",
                secret="secret123",
                match="password=secret123",
                start_line=42,
            )

            reporter.write(output, [finding])

            output.seek(0)
            content = output.read()

            assert "Rule: test-rule" in content
            assert "File: test.txt" in content
            assert "Line: 42" in content
            assert "Secret: secret123" in content
        finally:
            Path(template_path).unlink()

    def test_template_with_empty_findings(self):
        """Test template with no findings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write("<html>Count: {{ findings|length }}</html>")
            template_path = f.name

        try:
            reporter = TemplateReporter(template_path=template_path)
            output = io.StringIO()

            reporter.write(output, [])

            output.seek(0)
            content = output.read()

            assert "<html>Count: 0</html>" in content
        finally:
            Path(template_path).unlink()

    def test_template_with_tags(self):
        """Test template can access tags."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(
                """
                {% for finding in findings %}
                Tags: {% for tag in finding.tags %}{{ tag }} {% endfor %}
                {% endfor %}
                """
            )
            template_path = f.name

        try:
            reporter = TemplateReporter(template_path=template_path)
            output = io.StringIO()

            finding = Finding(
                rule_id="test-rule",
                file="test.txt",
                secret="secret123",
                match="password=secret123",
                start_line=1,
                tags=["key", "AWS", "secret"],
            )

            reporter.write(output, [finding])

            output.seek(0)
            content = output.read()

            assert "Tags: key AWS secret" in content
        finally:
            Path(template_path).unlink()

    def test_builtin_template_by_name(self):
        """Test loading built-in template by name."""
        reporter = TemplateReporter(template_path="basic")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "<!DOCTYPE html>" in content
        assert "test-rule" in content

    def test_builtin_leet_template(self):
        """Test loading built-in leet template."""
        reporter = TemplateReporter(template_path="leet")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "G1TL3@K5" in content or "LEET" in content.upper()

    def test_builtin_myspace_template(self):
        """Test loading built-in myspace template."""
        reporter = TemplateReporter(template_path="myspace")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "<!DOCTYPE html>" in content

    def test_builtin_w98_template(self):
        """Test loading built-in w98 template."""
        reporter = TemplateReporter(template_path="w98")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "<!DOCTYPE html>" in content
        assert "Windows" in content or "window" in content.lower()

    def test_builtin_wxp_template(self):
        """Test loading built-in wxp template."""
        reporter = TemplateReporter(template_path="wxp")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "<!DOCTYPE html>" in content

    def test_builtin_template_with_html_extension(self):
        """Test loading built-in template with .html extension."""
        reporter = TemplateReporter(template_path="leet.html")
        output = io.StringIO()

        finding = Finding(
            rule_id="test-rule",
            file="test.txt",
            secret="secret123",
            match="password=secret123",
            start_line=1,
        )

        reporter.write(output, [finding])

        output.seek(0)
        content = output.read()

        assert "<!DOCTYPE html>" in content
