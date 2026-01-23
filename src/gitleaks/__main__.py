"""
Main entry point for the gitleaks command-line interface.

This module serves as the entry point for both `python -m gitleaks` and
the `gitleaks` console script installed by Poetry.
"""

import signal
import sys

from gitleaks import __version__
from gitleaks.logging import fatal, get_logger

logger = get_logger(__name__)


def handle_interrupt(signum: int, frame: object) -> None:
    """Handle interrupt signals (Ctrl+C) gracefully."""
    fatal().msg("Interrupt signal received. Exiting...")
    sys.exit(130)  # Standard exit code for SIGINT


def main() -> None:
    """
    Main entry point for gitleaks CLI.

    Currently displays a placeholder message. The full CLI implementation
    will be added in subsequent tasks.
    """
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, handle_interrupt)

    # Placeholder implementation - the actual CLI will be implemented
    # in future tasks using Click framework
    print(f"gitleaks version {__version__}")
    print()
    print("Usage: gitleaks [command] [options]")
    print()
    print("Commands:")
    print("  detect    Detect secrets in a git repository or directory")
    print("  protect   Protect secrets by scanning commits before they are pushed")
    print("  version   Print version information")
    print()
    print("This is a placeholder. Full CLI implementation coming in subsequent tasks.")
    print()
    print("Run 'gitleaks --help' for more information (once implemented).")


if __name__ == "__main__":
    main()
