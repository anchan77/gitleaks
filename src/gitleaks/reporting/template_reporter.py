"""
Template reporter for gitleaks findings.

Supports custom Jinja2 templates for flexible output formatting.
"""

import os
from pathlib import Path
from typing import IO, List, Optional
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, Template, TemplateError

from gitleaks.reporting.finding import Finding


class TemplateReporter:
    """
    Template reporter that renders findings using Jinja2 templates.

    Supports both custom user templates and built-in templates.
    Templates receive findings as a list and have access to various
    helper functions for formatting.
    """

    # Built-in template names (without .html extension)
    BUILTIN_TEMPLATES = {"basic", "leet", "myspace", "w98", "wxp"}

    def __init__(self, template_path: Optional[str] = None) -> None:
        """
        Initialize the template reporter.

        Args:
            template_path: Path to a custom Jinja2 template file, or name of a built-in
                          template (basic, leet, myspace, w98, wxp). If not provided,
                          the built-in "basic" template will be used.

        Raises:
            ValueError: If template_path is empty string
            FileNotFoundError: If the template file doesn't exist
            TemplateError: If the template cannot be parsed
        """
        if template_path is not None and template_path == "":
            raise ValueError("template path cannot be empty")

        self.template: Template

        if template_path:
            # Check if it's a built-in template name
            if template_path in self.BUILTIN_TEMPLATES:
                self.template = self._load_builtin_template(f"{template_path}.html")
            else:
                # Try to load as a file path
                # First check if it's an absolute or relative path that exists
                path = Path(template_path)
                if path.exists():
                    self.template = self._load_template_from_file(template_path)
                else:
                    # Maybe it's a built-in template with .html extension
                    template_name = template_path.replace(".html", "")
                    if template_name in self.BUILTIN_TEMPLATES:
                        self.template = self._load_builtin_template(f"{template_name}.html")
                    else:
                        # File doesn't exist
                        raise FileNotFoundError(f"template file not found: {template_path}")
        else:
            # Use built-in basic template
            self.template = self._load_builtin_template("basic.html")

    def _load_template_from_file(self, template_path: str) -> Template:
        """
        Load a template from a file path.

        Args:
            template_path: Path to the template file

        Returns:
            Compiled Jinja2 template

        Raises:
            FileNotFoundError: If the template file doesn't exist
            TemplateError: If the template cannot be parsed
        """
        path = Path(template_path)
        if not path.exists():
            raise FileNotFoundError(f"template file not found: {template_path}")

        # Create Jinja2 environment with the template's directory as loader path
        env = Environment(
            loader=FileSystemLoader(str(path.parent)),
            autoescape=True,  # Auto-escape HTML for security
        )

        # Add custom filters and functions
        env.globals["now"] = datetime.utcnow

        try:
            return env.get_template(path.name)
        except TemplateError as e:
            raise TemplateError(f"error parsing template: {e}") from e

    def _load_builtin_template(self, template_name: str) -> Template:
        """
        Load a built-in template from the templates directory.

        Args:
            template_name: Name of the built-in template

        Returns:
            Compiled Jinja2 template

        Raises:
            FileNotFoundError: If the built-in template doesn't exist
            TemplateError: If the template cannot be parsed
        """
        # Get the templates directory relative to this file
        templates_dir = Path(__file__).parent / "templates"

        if not templates_dir.exists():
            raise FileNotFoundError(f"built-in templates directory not found: {templates_dir}")

        template_path = templates_dir / template_name
        if not template_path.exists():
            raise FileNotFoundError(f"built-in template not found: {template_name}")

        # Create Jinja2 environment
        env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=True,  # Auto-escape HTML for security
        )

        # Add custom filters and functions
        env.globals["now"] = datetime.utcnow

        try:
            return env.get_template(template_name)
        except TemplateError as e:
            raise TemplateError(f"error parsing built-in template: {e}") from e

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the given output stream using the template.

        Args:
            writer: An IO object supporting write operations (file, stdout, etc.)
            findings: List of Finding objects to write

        Raises:
            IOError: If writing to the output fails
            TemplateError: If template rendering fails
        """
        try:
            # Render template with findings
            # Convert Finding dataclasses to dicts for easier template access
            findings_data = [self._finding_to_dict(f) for f in findings]
            output = self.template.render(findings=findings_data)

            # Write rendered output
            writer.write(output)
        except TemplateError as e:
            raise TemplateError(f"error rendering template: {e}") from e

    def _finding_to_dict(self, finding: Finding) -> dict:
        """
        Convert a Finding to a dictionary for template rendering.

        Args:
            finding: The Finding object to convert

        Returns:
            Dictionary representation of the finding
        """
        return {
            "rule_id": finding.rule_id,
            "description": finding.description,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "start_column": finding.start_column,
            "end_column": finding.end_column,
            "line": finding.line,
            "match": finding.match,
            "secret": finding.secret,
            "file": finding.file,
            "symlink_file": finding.symlink_file,
            "commit": finding.commit,
            "link": finding.link,
            "entropy": finding.entropy,
            "author": finding.author,
            "email": finding.email,
            "date": finding.date,
            "message": finding.message,
            "tags": finding.tags,
            "fingerprint": finding.fingerprint,
        }
