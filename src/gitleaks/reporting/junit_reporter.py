"""
JUnit XML reporter for gitleaks findings.

Exports findings to JUnit XML format for integration with CI/CD systems.
"""

import json
from typing import IO, List
from xml.sax.saxutils import escape

from gitleaks.reporting.finding import Finding


class JunitReporter:
    """
    JUnit reporter that writes findings to JUnit XML format.

    Each finding is represented as a test case with a failure. This format
    is widely supported by CI/CD systems for displaying test results.
    """

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the given output stream in JUnit XML format.

        Args:
            writer: An IO object supporting write operations (file, stdout, etc.)
            findings: List of Finding objects to write

        Raises:
            IOError: If writing to the output fails
        """
        # Write XML header
        writer.write('<?xml version="1.0" encoding="UTF-8"?>\n')

        # Write testsuites opening tag
        writer.write("<testsuites>\n")

        # Write testsuite
        self._write_test_suite(writer, findings)

        # Write testsuites closing tag
        writer.write("</testsuites>\n")

    def _write_test_suite(self, writer: IO, findings: List[Finding]) -> None:
        """Write a test suite containing all findings as test cases."""
        num_findings = len(findings)

        writer.write(
            f'\t<testsuite failures="{num_findings}" '
            f'name="gitleaks" '
            f'tests="{num_findings}" '
            f'time="">\n'
        )

        # Write each finding as a test case
        for f in findings:
            self._write_test_case(writer, f)

        writer.write("\t</testsuite>\n")

    def _write_test_case(self, writer: IO, f: Finding) -> None:
        """Write a single finding as a test case with failure."""
        classname = escape(f.description)
        file_attr = escape(f.file)
        name = escape(self._get_message(f))

        writer.write(
            f'\t\t<testcase classname="{classname}" '
            f'file="{file_attr}" '
            f'name="{name}" '
            f'time="">\n'
        )

        # Write failure element
        self._write_failure(writer, f)

        writer.write("\t\t</testcase>\n")

    def _write_failure(self, writer: IO, f: Finding) -> None:
        """Write failure element with finding data."""
        message = escape(self._get_message(f))
        failure_type = escape(f.description)
        data = self._get_data(f)

        writer.write(f'\t\t\t<failure message="{message}" type="{failure_type}">\n')
        writer.write(escape(data))
        writer.write("\n\t\t\t</failure>\n")

    def _get_message(self, f: Finding) -> str:
        """Generate message for a finding."""
        if not f.commit:
            return (
                f"{f.rule_id} has detected a secret in file {f.file}, "
                f"line {f.start_line}."
            )
        return (
            f"{f.rule_id} has detected a secret in file {f.file}, "
            f"line {f.start_line}, at commit {f.commit}."
        )

    def _get_data(self, f: Finding) -> str:
        """Get JSON representation of finding."""
        # Convert finding to dict for JSON serialization
        # Exclude non-serializable fields (fragment, line)
        finding_dict = {
            "RuleID": f.rule_id,
            "Description": f.description,
            "StartLine": f.start_line,
            "EndLine": f.end_line,
            "StartColumn": f.start_column,
            "EndColumn": f.end_column,
            "Match": f.match,
            "Secret": f.secret,
            "File": f.file,
            "SymlinkFile": f.symlink_file,
            "Commit": f.commit,
            "Link": f.link,
            "Entropy": f.entropy,
            "Author": f.author,
            "Email": f.email,
            "Date": f.date,
            "Message": f.message,
            "Tags": f.tags,
            "Fingerprint": f.fingerprint,
        }

        return json.dumps(finding_dict, indent="\t")
