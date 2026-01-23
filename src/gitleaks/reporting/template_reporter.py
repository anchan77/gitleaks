"""Jinja2 template reporter for gitleaks findings."""

import importlib.resources
from datetime import datetime
from pathlib import Path
from typing import IO, List, Optional

from jinja2 import Environment, FileSystemLoader, Template

from gitleaks.reporting import Finding


class TemplateReporter:
    """Jinja2 template format reporter."""

    # Built-in template names
    BUILTIN_TEMPLATES = {"basic", "leet", "myspace", "w98", "wxp"}

    def __init__(self, template_path: Optional[str] = None):
        """Initialize template reporter.

        Args:
            template_path: Path to template file or built-in template name
        """
        self.template: Optional[Template] = None

        if template_path:
            # Check if it's a built-in template name
            if template_path in self.BUILTIN_TEMPLATES:
                self.template = self._load_builtin_template(f"{template_path}.html")
            else:
                # Try as file path
                path = Path(template_path)
                if path.exists():
                    self.template = self._load_template_from_file(template_path)
                else:
                    raise FileNotFoundError(
                        f"Template file not found: {template_path}. "
                        f"Use a built-in template ({', '.join(sorted(self.BUILTIN_TEMPLATES))}) "
                        "or provide a valid file path."
                    )
        else:
            # Default to basic template
            self.template = self._load_builtin_template("basic.html")

    def _load_builtin_template(self, template_name: str) -> Template:
        """Load a built-in template from the templates directory.

        Args:
            template_name: Name of the built-in template file

        Returns:
            Jinja2 Template object
        """
        try:
            # Try to load from package resources
            template_dir = Path(__file__).parent / "templates"
            if template_dir.exists():
                env = Environment(loader=FileSystemLoader(str(template_dir)))
                return env.get_template(template_name)
            else:
                raise FileNotFoundError(f"Built-in templates directory not found")
        except Exception as e:
            raise RuntimeError(f"Failed to load built-in template {template_name}: {e}")

    def _load_template_from_file(self, template_path: str) -> Template:
        """Load a template from a file path.

        Args:
            template_path: Path to template file

        Returns:
            Jinja2 Template object
        """
        path = Path(template_path)
        env = Environment(loader=FileSystemLoader(str(path.parent)))
        return env.get_template(path.name)

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """Write findings using Jinja2 template.

        Args:
            writer: Output stream to write to
            findings: List of findings to report
        """
        if not self.template:
            raise RuntimeError("No template loaded")

        # Render template with findings and current datetime
        output = self.template.render(findings=findings, len=len, now=datetime.now())
        writer.write(output)
