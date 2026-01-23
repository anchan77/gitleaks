"""
Finding data model for gitleaks secret detection.

The Finding class represents a detected secret with all relevant metadata
for reporting and tracking.
"""

import math
from dataclasses import dataclass, field
from typing import Optional, List

from gitleaks.sources.fragment import Fragment


@dataclass
class RequiredFinding:
    """
    A subset of Finding fields for composite rule checking.

    Used for multi-part rules that require multiple secrets to be present.
    Contains only the fields needed for reporting auxiliary findings.
    """

    rule_id: str = ""
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    line: str = ""  # Not serialized to JSON
    match: str = ""
    secret: str = ""


@dataclass
class Finding:
    """
    Finding contains comprehensive information about a detected secret.

    This dataclass holds all the data needed to report a finding, including
    the matched secret, location information, git metadata, and entropy metrics.

    Attributes:
        rule_id: ID of the rule that matched
        description: Human-readable description of the rule
        start_line: Starting line number of the finding (1-indexed)
        end_line: Ending line number of the finding (1-indexed)
        start_column: Starting column number (1-indexed)
        end_column: Ending column number (1-indexed)
        line: The full line containing the secret (not serialized to JSON)
        match: The matched text containing the secret
        secret: The extracted secret value
        file: File path where the secret was found
        symlink_file: Original symlink path if applicable
        commit: Git commit SHA if from a git source
        link: URL to the finding in the remote repository
        entropy: Shannon entropy of the secret value
        author: Git commit author name
        email: Git commit author email
        date: Git commit date
        message: Git commit message
        tags: List of tags associated with the rule
        fingerprint: Unique identifier for deduplication
        fragment: The source fragment containing this finding
        required_findings: List of auxiliary findings for composite rules
    """

    # Rule information
    rule_id: str = ""
    description: str = ""

    # Location information
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0

    # Content information (line not serialized to JSON)
    line: str = ""
    match: str = ""
    secret: str = ""

    # File information
    file: str = ""
    symlink_file: str = ""

    # Git information
    commit: str = ""
    link: str = ""
    author: str = ""
    email: str = ""
    date: str = ""
    message: str = ""

    # Metadata
    entropy: float = 0.0
    tags: List[str] = field(default_factory=list)
    fingerprint: str = ""

    # Source fragment (not serialized to JSON in Go implementation)
    fragment: Optional[Fragment] = None

    # Composite rule support (private in Go, not serialized)
    required_findings: List[RequiredFinding] = field(default_factory=list, repr=False)

    def add_required_findings(self, findings: List[RequiredFinding]) -> None:
        """
        Add auxiliary findings for composite rules.

        Args:
            findings: List of RequiredFinding objects to add
        """
        self.required_findings.extend(findings)

    def redact(self, percent: int) -> None:
        """
        Redact the secret from this finding.

        Replaces the secret in the line, match, and secret fields with a
        partially or fully redacted version based on the percentage.

        Args:
            percent: Percentage of the secret to redact (0-100).
                    100 replaces the entire secret with "REDACTED".
        """
        if percent >= 100:
            secret = "REDACTED"
        else:
            secret = mask_secret(self.secret, percent)

        # Replace the secret in all relevant fields
        self.line = self.line.replace(self.secret, secret)
        self.match = self.match.replace(self.secret, secret)
        self.secret = secret


def mask_secret(secret: str, percent: int) -> str:
    """
    Mask a secret by showing only a portion of it.

    The function masks the specified percentage of the secret, leaving
    the rest visible followed by "...".

    Args:
        secret: The secret to mask
        percent: Percentage to mask (0-100). Higher values mask more.

    Returns:
        The masked secret string

    Examples:
        >>> mask_secret("secret", 75)
        'se...'
        >>> mask_secret("secret", 90)
        's...'
        >>> mask_secret("secret", 10)
        'secre...'
    """
    if percent > 100:
        percent = 100

    secret_len = len(secret)
    if secret_len <= 0:
        return secret

    # Calculate how many characters to keep visible
    # percent represents how much to hide, so (100 - percent) is visible
    visible_percent = 100 - percent
    visible_length = round(secret_len * visible_percent / 100.0)

    # Use banker's rounding (round to even) to match Go's math.RoundToEven
    # Python's round() uses banker's rounding by default in Python 3
    visible_length = int(round(secret_len * visible_percent / 100.0))

    return secret[:visible_length] + "..."
