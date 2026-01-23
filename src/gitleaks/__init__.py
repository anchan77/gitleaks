"""
Gitleaks - SAST tool for detecting hardcoded secrets in git repositories.

This is the Python implementation of gitleaks, providing secret scanning
capabilities for git repositories, directories, and stdin input.
"""

import os

# Version can be overridden at build time via GITLEAKS_VERSION environment variable
# This mimics Go's ldflags approach for setting version at build time
__version__ = os.getenv("GITLEAKS_VERSION", "0.1.0")
__all__ = ["__version__"]
