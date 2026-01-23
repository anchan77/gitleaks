"""
Command-line interface components for gitleaks.

This package contains Click command definitions and CLI utilities.
"""

from gitleaks.cli.common import cli
from gitleaks.cli.diagnostics import diagnostics_command
from gitleaks.cli.dir import dir_command
from gitleaks.cli.version import version_command

__all__ = ["cli", "diagnostics_command", "dir_command", "version_command"]
