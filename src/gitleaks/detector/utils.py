"""
Utility functions for the detection engine.

This module provides helper functions for entropy calculation, finding filtering,
SCM link generation, and terminal output.
"""

import math
from typing import List, Optional
from urllib.parse import quote

from gitleaks.reporting.finding import Finding
from gitleaks.logging import get_logger

logger = get_logger(__name__)


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Shannon entropy measures the randomness/unpredictability of data.
    Higher entropy indicates more random data. The formula is:
    H = -Σ(p(x) * log2(p(x))) where p(x) is the probability of character x.

    Args:
        data: The string to calculate entropy for

    Returns:
        The Shannon entropy as a float (bits needed to encode the data)

    Examples:
        >>> shannon_entropy("aaaa")
        0.0
        >>> shannon_entropy("abcd1234")  # More random
        3.0  # (approximately)
    """
    if not data:
        return 0.0

    # Count character frequencies
    char_counts: dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    inv_length = 1.0 / len(data)

    for count in char_counts.values():
        freq = count * inv_length
        entropy -= freq * math.log2(freq)

    return entropy


def filter_findings(findings: List[Finding], redact: int = 0) -> List[Finding]:
    """
    Deduplicate and redact findings.

    This function implements the "generic rule deduplication" logic:
    If a "generic" rule matches the same line/commit as a more specific rule,
    and the specific rule's secret contains the generic rule's secret,
    then skip the generic finding.

    Args:
        findings: List of findings to filter
        redact: Redaction percentage (0-100). 0 means no redaction,
               100 means full redaction.

    Returns:
        Filtered list of findings
    """
    ret_findings: List[Finding] = []

    for finding in findings:
        include = True

        # Check for generic rule deduplication
        if "generic" in finding.rule_id.lower():
            for other_finding in findings:
                # Check if another finding supersedes this generic one
                if (finding.start_line == other_finding.start_line and
                    finding.commit == other_finding.commit and
                    finding.rule_id != other_finding.rule_id and
                    finding.secret in other_finding.secret and
                    "generic" not in other_finding.rule_id.lower()):

                    # Log the deduplication
                    generic_match = finding.match.replace(finding.secret, "REDACTED")
                    better_match = other_finding.match.replace(other_finding.secret, "REDACTED")
                    logger.debug(
                        f"skipping {finding.rule_id} finding ({generic_match}), "
                        f"{other_finding.rule_id} rule takes precedence ({better_match})"
                    )
                    include = False
                    break

        # Apply redaction if requested
        if redact > 0:
            finding.redact(redact)

        if include:
            ret_findings.append(finding)

    return ret_findings


def create_scm_link(remote_info: Optional[dict], finding: Finding) -> str:
    """
    Create a deep link to the finding in the SCM platform.

    Supports GitHub, GitLab, Azure DevOps, Gitea, and Bitbucket.

    Args:
        remote_info: Dictionary with 'platform' and 'url' keys, or None
        finding: The finding to create a link for

    Returns:
        The SCM link URL, or empty string if not applicable
    """
    if not remote_info or not finding.commit:
        return ""

    platform = remote_info.get("platform", "")
    base_url = remote_info.get("url", "")

    if not platform or not base_url or platform in ["unknown", "none"]:
        return ""

    # Clean the file path - handle inner archive paths
    file_path = finding.file
    has_inner_path = False

    # Check for inner path separator (e.g., "archive.zip::inner/file.txt")
    if "::" in file_path:
        file_path, _ = file_path.split("::", 1)
        has_inner_path = True

    # URL encode spaces and special characters
    file_path = quote(file_path, safe="/")

    # Platform-specific link generation
    if platform.lower() == "github":
        link = f"{base_url}/blob/{finding.commit}/{file_path}"
        if has_inner_path:
            return link

        # Add ?plain=1 for notebooks and markdown
        ext = file_path.lower().split(".")[-1] if "." in file_path else ""
        if ext in ["ipynb", "md"]:
            link += "?plain=1"

        # Add line numbers
        if finding.start_line != 0:
            link += f"#L{finding.start_line}"
        if finding.end_line != finding.start_line:
            link += f"-L{finding.end_line}"

        return link

    elif platform.lower() == "gitlab":
        link = f"{base_url}/blob/{finding.commit}/{file_path}"
        if has_inner_path:
            return link

        if finding.start_line != 0:
            link += f"#L{finding.start_line}"
        if finding.end_line != finding.start_line:
            link += f"-{finding.end_line}"

        return link

    elif platform.lower() == "azuredevops":
        link = f"{base_url}/commit/{finding.commit}?path=/{file_path}"
        if has_inner_path:
            return link

        if finding.start_line != 0:
            link += f"&line={finding.start_line}"
        if finding.end_line != finding.start_line:
            link += f"&lineEnd={finding.end_line}"

        # Azure DevOps requires these parameters for line highlighting
        link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
        return link

    elif platform.lower() == "gitea":
        link = f"{base_url}/src/commit/{finding.commit}/{file_path}"
        if has_inner_path:
            return link

        ext = file_path.lower().split(".")[-1] if "." in file_path else ""
        if ext in ["ipynb", "md"]:
            link += "?display=source"

        if finding.start_line != 0:
            link += f"#L{finding.start_line}"
        if finding.end_line != finding.start_line:
            link += f"-L{finding.end_line}"

        return link

    elif platform.lower() == "bitbucket":
        link = f"{base_url}/src/{finding.commit}/{file_path}"
        if has_inner_path:
            return link

        if finding.start_line != 0:
            link += f"#lines-{finding.start_line}"
        if finding.end_line != finding.start_line:
            link += f":{finding.end_line}"

        return link

    # Unknown platform
    return ""


def print_finding(finding: Finding, no_color: bool = False) -> None:
    """
    Print a finding to stdout with formatting.

    Args:
        finding: The finding to print
        no_color: If True, disable color output
    """
    # Trim whitespace
    line = finding.line.strip()
    secret = finding.secret.strip()
    match = finding.match.strip()

    is_file_match = match.startswith("file detected:")

    # Print finding and secret
    if is_file_match or no_color:
        print(f"{'Finding:':<12} {match}")
        print(f"{'Secret:':<12} {secret}")
    else:
        # For non-file matches, print with context
        match_in_line_idx = line.find(match)
        if match_in_line_idx != -1:
            # Truncate start if too long
            start = line[0:match_in_line_idx]
            if match_in_line_idx > 20:
                start_idx = match_in_line_idx - 20
                start = "..." + line[start_idx:match_in_line_idx]

            # Build the line with match highlighted
            line_end_idx = match_in_line_idx + len(match)
            if line_end_idx < len(line):
                line_end = line[line_end_idx:]
                if len(line_end) > 20:
                    line_end = line_end[0:20] + "..."
            else:
                line_end = ""

            # Truncate secret if too long
            display_secret = secret
            if len(secret) > 100:
                display_secret = secret[0:100] + "..."

            finding_str = f"{start}[{match}]{line_end}"
            print(f"{'Finding:':<12} {finding_str}")
            print(f"{'Secret:':<12} {display_secret}")
        else:
            print(f"{'Finding:':<12} {match}")
            print(f"{'Secret:':<12} {secret}")

    # Print metadata
    print(f"{'RuleID:':<12} {finding.rule_id}")
    print(f"{'Entropy:':<12} {finding.entropy:.6f}")

    if not finding.file:
        # No file info, print required findings if any
        if finding.required_findings:
            print("\nRequired Findings:")
            for rf in finding.required_findings:
                print(f"  - {rf.rule_id}: {rf.match}")
        print()
        return

    if finding.tags:
        print(f"{'Tags:':<12} {', '.join(finding.tags)}")

    print(f"{'File:':<12} {finding.file}")
    print(f"{'Line:':<12} {finding.start_line}")

    if not finding.commit:
        print(f"{'Fingerprint:':<12} {finding.fingerprint}")
        if finding.required_findings:
            print("\nRequired Findings:")
            for rf in finding.required_findings:
                print(f"  - {rf.rule_id}: {rf.match}")
        print()
        return

    # Print git metadata
    print(f"{'Commit:':<12} {finding.commit}")
    print(f"{'Author:':<12} {finding.author}")
    print(f"{'Email:':<12} {finding.email}")
    print(f"{'Date:':<12} {finding.date}")
    print(f"{'Fingerprint:':<12} {finding.fingerprint}")

    if finding.link:
        print(f"{'Link:':<12} {finding.link}")

    if finding.required_findings:
        print("\nRequired Findings:")
        for rf in finding.required_findings:
            print(f"  - {rf.rule_id}: {rf.match}")

    print()
