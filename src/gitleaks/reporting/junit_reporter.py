"""JUnit XML reporter for gitleaks findings."""

import json
from typing import IO, List
from xml.sax.saxutils import escape, quoteattr

from gitleaks.reporting import Finding


class JunitReporter:
    """JUnit XML format reporter."""

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """Write findings to JUnit XML format.

        Args:
            writer: Output stream to write to
            findings: List of findings to report
        """
        writer.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        writer.write("<testsuites>\n")
        self._write_test_suite(writer, findings)
        writer.write("</testsuites>\n")

    def _write_test_suite(self, writer: IO, findings: List[Finding]) -> None:
        """Write a test suite containing all findings as test cases."""
        num_findings = len(findings)
        writer.write(
            f'\t<testsuite failures="{num_findings}" name="gitleaks" '
            f'tests="{num_findings}" time="">\n'
        )

        for f in findings:
            self._write_test_case(writer, f)

        writer.write("\t</testsuite>\n")

    def _write_test_case(self, writer: IO, f: Finding) -> None:
        """Write a single test case (finding)."""
        classname = quoteattr(f.description)
        name = quoteattr(self._get_message(f))
        file = quoteattr(f.file)

        writer.write(
            f'\t\t<testcase classname={classname} file={file} '
            f'name={name} time="">\n'
        )

        # Write failure element
        failure_type = quoteattr(f.description)
        failure_message = quoteattr(self._get_message(f))
        failure_data = escape(self._get_data(f))

        writer.write(
            f'\t\t\t<failure message={failure_message} type={failure_type}>'
        )
        writer.write(failure_data)
        writer.write("</failure>\n")

        writer.write("\t\t</testcase>\n")

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
        """Generate failure data (JSON representation of finding)."""
        try:
            # Convert finding to dict for JSON serialization
            finding_dict = {
                "RuleID": f.rule_id,
                "Description": f.description,
                "File": f.file,
                "SymlinkFile": f.symlink_file,
                "Secret": f.secret,
                "Match": f.match,
                "StartLine": f.start_line,
                "EndLine": f.end_line,
                "StartColumn": f.start_column,
                "EndColumn": f.end_column,
                "Author": f.author,
                "Message": f.message,
                "Date": f.date,
                "Email": f.email,
                "Commit": f.commit,
                "Fingerprint": f.fingerprint,
                "Tags": f.tags,
            }
            if f.link:
                finding_dict["Link"] = f.link

            return json.dumps(finding_dict, indent="\t")
        except Exception:
            return ""
