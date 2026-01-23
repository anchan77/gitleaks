"""
Main entry point for the gitleaks command-line interface.

This module serves as the entry point for both `python -m gitleaks` and
the `gitleaks` console script installed by Poetry.
"""

import signal
import sys

from gitleaks.cli import cli
from gitleaks.logging import fatal


def handle_interrupt(signum: int, frame: object) -> None:
    """Handle interrupt signals (Ctrl+C) gracefully."""
    fatal().critical("Interrupt signal received. Exiting...")
    sys.exit(130)  # Standard exit code for SIGINT


def main() -> None:
    """
    Main entry point for gitleaks CLI.

    This function sets up signal handlers and invokes the Click CLI.
    """
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, handle_interrupt)

    # Run the Click CLI
    try:
        cli()
    except SystemExit as e:
        # Handle unknown flag errors with exit code 126
        if hasattr(e, "code") and isinstance(e.code, int):
            sys.exit(e.code)
        raise
    except Exception as e:
        fatal().critical(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
