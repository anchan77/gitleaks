"""CSV reporter for gitleaks findings."""

import csv
from typing import IO, List

from gitleaks.reporting import Finding


class CsvReporter:
    """CSV format reporter."""

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """Write findings to CSV format.

        Args:
            writer: Output stream to write to
            findings: List of findings to report
        """
        if not findings:
            return

        csv_writer = csv.writer(writer)

        # Column headers
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

        # Add Link column if any finding has a link
        if findings[0].link:
            columns.append("Link")

        csv_writer.writerow(columns)

        # Write findings
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
                " ".join(f.tags),  # Join tags with space
            ]

            if findings[0].link:
                row.append(f.link)

            csv_writer.writerow(row)
