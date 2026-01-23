"""
CSV reporter for gitleaks findings.

Exports findings to CSV format with all relevant fields.
"""

import csv
from typing import IO, List

from gitleaks.reporting.finding import Finding


class CsvReporter:
    """
    CSV reporter that writes findings to a CSV file.

    The CSV output includes all relevant finding fields such as RuleID, Commit,
    File, Secret, Match, line/column positions, git metadata, and tags.
    """

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the given output stream in CSV format.

        Args:
            writer: An IO object supporting write operations (file, stdout, etc.)
            findings: List of Finding objects to write

        Raises:
            IOError: If writing to the output fails
        """
        if not findings:
            return

        csv_writer = csv.writer(writer)

        # Define column headers
        columns = [
            "RuleID",
            "Commit",
            "File",
            "SymlinkFile",
            "Secret",
            "Match",
            "StartLine",
            "EndLine",
            "StartColumn",
            "EndColumn",
            "Author",
            "Message",
            "Date",
            "Email",
            "Fingerprint",
            "Tags",
        ]

        # Check if Link field is present in any finding
        # This mimics the Go implementation's "omitempty" attempt
        if findings[0].link:
            columns.append("Link")

        # Write header row
        csv_writer.writerow(columns)

        # Write data rows
        for f in findings:
            row = [
                f.rule_id,
                f.commit,
                f.file,
                f.symlink_file,
                f.secret,
                f.match,
                str(f.start_line),
                str(f.end_line),
                str(f.start_column),
                str(f.end_column),
                f.author,
                f.message,
                f.date,
                f.email,
                f.fingerprint,
                " ".join(f.tags),  # Join tags with space separator
            ]

            # Add link if present
            if findings[0].link:
                row.append(f.link)

            csv_writer.writerow(row)
