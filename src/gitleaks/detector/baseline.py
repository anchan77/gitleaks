"""
Baseline support for gitleaks.

This module implements baseline loading and finding comparison to allow
suppressing findings that are present in a baseline report.
"""

import json
from pathlib import Path
from typing import List, Optional

from gitleaks.reporting.finding import Finding
from gitleaks.logging import get_logger

logger = get_logger(__name__)


def load_baseline(baseline_path: str) -> List[Finding]:
    """
    Load baseline findings from a JSON file.

    Args:
        baseline_path: Path to baseline JSON file

    Returns:
        List of Finding objects from baseline

    Raises:
        FileNotFoundError: If baseline file doesn't exist
        json.JSONDecodeError: If baseline file is not valid JSON
        ValueError: If baseline format is not supported
    """
    path = Path(baseline_path)

    if not path.exists():
        raise FileNotFoundError(f"could not open {baseline_path}")

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"the format of the file {baseline_path} is not supported") from e

    # Validate that data is a list
    if not isinstance(data, list):
        raise ValueError(f"the format of the file {baseline_path} is not supported")

    # Convert JSON objects to Finding objects
    baseline_findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        # Create Finding from dict (use same fields as JSON serialization)
        # Map JSON field names to Finding constructor parameters
        finding = Finding(
            rule_id=item.get("RuleID", ""),
            description=item.get("Description", ""),
            start_line=item.get("StartLine", 0),
            end_line=item.get("EndLine", 0),
            start_column=item.get("StartColumn", 0),
            end_column=item.get("EndColumn", 0),
            match=item.get("Match", ""),
            secret=item.get("Secret", ""),
            file=item.get("File", ""),
            symlink_file=item.get("SymlinkFile", ""),
            commit=item.get("Commit", ""),
            entropy=item.get("Entropy", 0.0),
            author=item.get("Author", ""),
            email=item.get("Email", ""),
            date=item.get("Date", ""),
            message=item.get("Message", ""),
            tags=item.get("Tags", []),
            fingerprint=item.get("Fingerprint", ""),
        )
        baseline_findings.append(finding)

    return baseline_findings


def is_new_finding(finding: Finding, redact: int, baseline: List[Finding]) -> bool:
    """
    Check if a finding is new (not present in baseline).

    This function compares a finding against a baseline list to determine
    if it's a new finding. When redaction is enabled, secret and match
    fields are not compared.

    Args:
        finding: Finding to check
        redact: Redaction percentage (0-100). If > 0, secrets are not compared
        baseline: List of baseline findings

    Returns:
        True if finding is new (not in baseline), False if it matches baseline
    """
    # Check each baseline finding for a match
    for b in baseline:
        # Compare all relevant fields
        # Note: Tags are intentionally not compared as updated tags don't make
        # a finding "new". Fingerprint is also not compared in case the format changes.
        if (finding.rule_id == b.rule_id and
            finding.description == b.description and
            finding.start_line == b.start_line and
            finding.end_line == b.end_line and
            finding.start_column == b.start_column and
            finding.end_column == b.end_column and
            # When redacting, skip comparing match/secret
            (redact > 0 or (finding.match == b.match and finding.secret == b.secret)) and
            finding.file == b.file and
            finding.commit == b.commit and
            finding.author == b.author and
            finding.email == b.email and
            finding.date == b.date and
            finding.message == b.message and
            finding.entropy == b.entropy):
            # Found a match in baseline
            return False

    # No match found, this is a new finding
    return True
