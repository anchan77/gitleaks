"""
Reporting and output formatting for gitleaks.

This package contains reporter implementations for various formats:
- JSON
- CSV (future)
- SARIF (future)
- JUnit (future)
- Custom templates (future)

The Reporter protocol defines the interface that all reporters must implement.
"""

from typing import Protocol, List, IO
from gitleaks.reporting.finding import Finding, RequiredFinding
from gitleaks.reporting.constants import (
    CWE,
    CWE_DESCRIPTION,
    STDOUT_REPORT_PATH,
    VERSION,
    DRIVER,
)


class Reporter(Protocol):
    """
    Reporter protocol defines the interface for all output formatters.

    Reporters take a list of findings and write them to an output stream
    in a specific format (JSON, CSV, SARIF, etc.).
    """

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the given output stream.

        Args:
            writer: An IO object supporting write operations (file, stdout, etc.)
            findings: List of Finding objects to write

        Raises:
            IOError: If writing to the output fails
        """
        ...


__all__ = [
    "Reporter",
    "Finding",
    "RequiredFinding",
    "CWE",
    "CWE_DESCRIPTION",
    "STDOUT_REPORT_PATH",
    "VERSION",
    "DRIVER",
]
