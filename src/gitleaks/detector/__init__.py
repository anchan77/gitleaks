"""
Secret detection engine for gitleaks.

This package contains the core detection engine, regex matching,
allowlist filtering, and finding accumulation logic.
"""

from gitleaks.detector.engine import Detector
from gitleaks.detector.location import Location, location, find_newline_indices, extract_line
from gitleaks.detector.utils import shannon_entropy, filter_findings, create_scm_link, print_finding

__all__ = [
    "Detector",
    "Location",
    "location",
    "find_newline_indices",
    "extract_line",
    "shannon_entropy",
    "filter_findings",
    "create_scm_link",
    "print_finding",
]
