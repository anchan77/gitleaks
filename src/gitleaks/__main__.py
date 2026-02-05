"""
Entry point for running gitleaks as a module: python -m gitleaks

This enables the package to be executed directly with:
    python -m gitleaks [COMMAND] [OPTIONS]
"""

from gitleaks.cli import main

if __name__ == "__main__":
    main()
