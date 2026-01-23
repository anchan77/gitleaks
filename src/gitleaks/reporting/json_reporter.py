"""
JSON reporter for gitleaks findings.

Serializes findings to JSON format for machine-readable output.
"""

import json
from typing import List, IO
from dataclasses import asdict

from gitleaks.reporting.finding import Finding


class JsonReporter:
    """
    Reporter that outputs findings in JSON format.

    The JSON output includes all finding fields except those explicitly
    excluded (line, fragment, required_findings).
    """

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the output stream in JSON format.

        The output is formatted with single-space indentation to match
        the Go implementation's output format.

        Args:
            writer: An IO object supporting write operations
            findings: List of Finding objects to serialize

        Raises:
            IOError: If writing to the output fails
            TypeError: If findings cannot be serialized to JSON
        """
        # Convert findings to dictionaries, excluding certain fields
        findings_data = []
        for finding in findings:
            finding_dict = self._finding_to_dict(finding)
            findings_data.append(finding_dict)

        # Encode with single-space indentation to match Go's encoder.SetIndent("", " ")
        json_output = json.dumps(findings_data, indent=" ", ensure_ascii=False)

        # Write to the output stream
        writer.write(json_output)
        writer.write("\n")

    def _finding_to_dict(self, finding: Finding) -> dict:
        """
        Convert a Finding to a dictionary suitable for JSON serialization.

        Excludes fields that should not appear in JSON output:
        - line (marked with json:"-" in Go)
        - fragment (marked with omitempty and typically None)
        - required_findings (private field)

        The field names are converted to match Go's JSON output:
        - Python snake_case -> Go PascalCase

        Args:
            finding: The Finding object to convert

        Returns:
            Dictionary with JSON-serializable data
        """
        # Convert entropy to int if it's a whole number to match Go's output
        # Go's float32 outputs as integer when it has no fractional part
        entropy = int(finding.entropy) if finding.entropy == int(finding.entropy) else finding.entropy

        return {
            "RuleID": finding.rule_id,
            "Description": finding.description,
            "StartLine": finding.start_line,
            "EndLine": finding.end_line,
            "StartColumn": finding.start_column,
            "EndColumn": finding.end_column,
            "Match": finding.match,
            "Secret": finding.secret,
            "File": finding.file,
            "SymlinkFile": finding.symlink_file,
            "Commit": finding.commit,
            "Entropy": entropy,
            "Author": finding.author,
            "Email": finding.email,
            "Date": finding.date,
            "Message": finding.message,
            "Tags": finding.tags,
            "Fingerprint": finding.fingerprint,
            # Omit "Link" if empty (matches Go's omitempty)
            **({"Link": finding.link} if finding.link else {}),
        }
