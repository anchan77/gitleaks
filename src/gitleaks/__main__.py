"""
Main entry point for the gitleaks command-line tool.

This module enables execution via `python -m gitleaks` and serves as the
entry point for the console script defined in pyproject.toml.
"""

import sys
from gitleaks import __version__


def main() -> int:
    """
    Main entry point for gitleaks CLI.

    Currently prints a placeholder message. Full CLI implementation will be
    added in subsequent tasks.

    Returns:
        Exit code (0 for success)
    """
    print(f"gitleaks version {__version__}")
    print()
    print("Gitleaks - Detect hardcoded secrets like passwords, API keys, and tokens in git repos")
    print()
    print("This is the Python implementation of gitleaks.")
    print()
    print("Usage: gitleaks [command] [flags]")
    print()
    print("Available Commands:")
    print("  detect      Detect secrets in code")
    print("  protect     Protect secrets in code")
    print("  dir         Scan a directory")
    print("  git         Scan git history")
    print("  version     Print version information")
    print()
    print("Flags:")
    print("  -h, --help     Help for gitleaks")
    print("  -v, --verbose  Verbose output")
    print()
    print("Full CLI implementation coming soon...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
