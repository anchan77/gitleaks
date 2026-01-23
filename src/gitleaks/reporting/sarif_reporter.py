"""
SARIF reporter for gitleaks findings.

Implements SARIF 2.1.0 schema for static analysis results.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from dataclasses import dataclass, field
from typing import IO, List, Optional, Dict, Any

from gitleaks.reporting.finding import Finding
from gitleaks.reporting.constants import VERSION, DRIVER


@dataclass
class ShortDescription:
    """SARIF short description."""

    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text}


@dataclass
class Rule:
    """SARIF rule definition."""

    id: str
    short_description: ShortDescription

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "shortDescription": self.short_description.to_dict()}


@dataclass
class Driver:
    """SARIF tool driver information."""

    name: str
    semantic_version: str
    information_uri: str
    rules: List[Rule]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "semanticVersion": self.semantic_version,
            "informationUri": self.information_uri,
            "rules": [rule.to_dict() for rule in self.rules],
        }


@dataclass
class Tool:
    """SARIF tool information."""

    driver: Driver

    def to_dict(self) -> Dict[str, Any]:
        return {"driver": self.driver.to_dict()}


@dataclass
class Message:
    """SARIF message."""

    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text}


@dataclass
class ArtifactLocation:
    """SARIF artifact location (file path)."""

    uri: str

    def to_dict(self) -> Dict[str, Any]:
        return {"uri": self.uri}


@dataclass
class Snippet:
    """SARIF code snippet."""

    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text}


@dataclass
class Region:
    """SARIF region (location within a file)."""

    start_line: int
    start_column: int
    end_line: int
    end_column: int
    snippet: Snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "startLine": self.start_line,
            "startColumn": self.start_column,
            "endLine": self.end_line,
            "endColumn": self.end_column,
            "snippet": self.snippet.to_dict(),
        }


@dataclass
class PhysicalLocation:
    """SARIF physical location."""

    artifact_location: ArtifactLocation
    region: Region

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifactLocation": self.artifact_location.to_dict(),
            "region": self.region.to_dict(),
        }


@dataclass
class Location:
    """SARIF location."""

    physical_location: PhysicalLocation

    def to_dict(self) -> Dict[str, Any]:
        return {"physicalLocation": self.physical_location.to_dict()}


@dataclass
class PartialFingerprints:
    """
    SARIF partial fingerprints.

    Used to store git metadata until revision data can be added elsewhere.
    """

    commit_sha: str
    email: str
    author: str
    date: str
    commit_message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitSha": self.commit_sha,
            "email": self.email,
            "author": self.author,
            "date": self.date,
            "commitMessage": self.commit_message,
        }


@dataclass
class Properties:
    """SARIF properties (tags)."""

    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"tags": self.tags}


@dataclass
class Result:
    """SARIF result (finding)."""

    message: Message
    rule_id: str
    locations: List[Location]
    partial_fingerprints: PartialFingerprints
    properties: Properties

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message.to_dict(),
            "ruleId": self.rule_id,
            "locations": [loc.to_dict() for loc in self.locations],
            "partialFingerprints": self.partial_fingerprints.to_dict(),
            "properties": self.properties.to_dict(),
        }


@dataclass
class Run:
    """SARIF run."""

    tool: Tool
    results: List[Result]

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool.to_dict(), "results": [r.to_dict() for r in self.results]}


@dataclass
class Sarif:
    """SARIF document root."""

    schema: str
    version: str
    runs: List[Run]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [run.to_dict() for run in self.runs],
        }


class SarifReporter:
    """
    SARIF reporter that writes findings to SARIF 2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) is a standard format
    for static analysis tool output that enables interoperability and integration
    with various development tools.
    """

    def __init__(self, ordered_rules: Optional[List[Any]] = None) -> None:
        """
        Initialize the SARIF reporter.

        Args:
            ordered_rules: Optional list of config.Rule objects in the order they
                          should appear in the SARIF output. This ensures consistent
                          rule indices across runs.
        """
        self.ordered_rules = ordered_rules or []

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """
        Write findings to the given output stream in SARIF 2.1.0 format.

        Args:
            writer: An IO object supporting write operations (file, stdout, etc.)
            findings: List of Finding objects to write

        Raises:
            IOError: If writing to the output fails
        """
        sarif = Sarif(
            schema="https://json.schemastore.org/sarif-2.1.0.json",
            version="2.1.0",
            runs=self._get_runs(findings),
        )

        # Write JSON with indentation
        json.dump(sarif.to_dict(), writer, indent=1)

    def _get_runs(self, findings: List[Finding]) -> List[Run]:
        """Create SARIF runs from findings."""
        return [Run(tool=self._get_tool(), results=self._get_results(findings))]

    def _get_tool(self) -> Tool:
        """Create SARIF tool information."""
        rules = self._get_rules()

        # Ensure that empty rules are represented as [] instead of null/None
        if not rules:
            rules = []

        driver = Driver(
            name=DRIVER,
            semantic_version=VERSION,
            information_uri="https://github.com/gitleaks/gitleaks",
            rules=rules,
        )

        return Tool(driver=driver)

    def _get_rules(self) -> List[Rule]:
        """Create SARIF rules from ordered_rules."""
        rules = []
        for rule in self.ordered_rules:
            rules.append(
                Rule(
                    id=rule.rule_id,
                    short_description=ShortDescription(text=rule.description),
                )
            )
        return rules

    def _get_results(self, findings: List[Finding]) -> List[Result]:
        """Convert findings to SARIF results."""
        results = []
        for f in findings:
            message_text = self._message_text(f)
            locations = self._get_location(f)
            partial_fingerprints = PartialFingerprints(
                commit_sha=f.commit,
                email=f.email,
                author=f.author,
                date=f.date,
                commit_message=f.message,
            )
            properties = Properties(tags=f.tags)

            result = Result(
                message=Message(text=message_text),
                rule_id=f.rule_id,
                locations=locations,
                partial_fingerprints=partial_fingerprints,
                properties=properties,
            )
            results.append(result)
        return results

    def _message_text(self, f: Finding) -> str:
        """Generate message text for a finding."""
        if not f.commit:
            return f"{f.rule_id} has detected secret for file {f.file}."
        return f"{f.rule_id} has detected secret for file {f.file} at commit {f.commit}."

    def _get_location(self, f: Finding) -> List[Location]:
        """Create SARIF location from finding."""
        # Use symlink file if present, otherwise use regular file
        uri = f.symlink_file if f.symlink_file else f.file

        region = Region(
            start_line=f.start_line,
            start_column=f.start_column,
            end_line=f.end_line,
            end_column=f.end_column,
            snippet=Snippet(text=f.secret),
        )

        physical_location = PhysicalLocation(
            artifact_location=ArtifactLocation(uri=uri), region=region
        )

        return [Location(physical_location=physical_location)]
