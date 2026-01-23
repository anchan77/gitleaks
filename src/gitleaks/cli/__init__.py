"""
Command-line interface components for gitleaks.

This package contains Click command definitions and CLI utilities.
"""

from gitleaks.cli.common import cli
from gitleaks.cli.dir import dir_command

__all__ = ["cli", "dir_command"]
