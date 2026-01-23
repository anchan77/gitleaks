"""SARIF 2.1.0 reporter for gitleaks findings."""

import json
from dataclasses import asdict, dataclass, field
from typing import IO, Any, Dict, List, Optional

from gitleaks.reporting import Finding
from gitleaks.reporting.constants import DRIVER, VERSION


@dataclass
class ShortDescription:
    """SARIF short description."""

    text: str


@dataclass
class Rule:
    """SARIF rule definition."""

    id: str
    short_description: ShortDescription = field(metadata={"json": "shortDescription"})

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {"id": self.id, "shortDescription": {"text": self.short_description.text}}


@dataclass
class Driver:
    """SARIF driver (tool) definition."""

    name: str
    semantic_version: str = field(metadata={"json": "semanticVersion"})
    information_uri: str = field(metadata={"json": "informationUri"})
    rules: List[Rule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "name": self.name,
            "semanticVersion": self.semantic_version,
            "informationUri": self.information_uri,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class Tool:
    """SARIF tool definition."""

    driver: Driver

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict."""
        return {"driver": self.driver.to_dict()}


@dataclass
class Message:
    """SARIF message."""

    text: str


@dataclass
class ArtifactLocation:
    """SARIF artifact location."""

    uri: str


@dataclass
class Snippet:
    """SARIF code snippet."""

    text: str


@dataclass
class Region:
    """SARIF region (location within file)."""

    start_line: int = field(metadata={"json": "startLine"})
    end_line: int = field(metadata={"json": "endLine"})
    start_column: int = field(metadata={"json": "startColumn"})
    end_column: int = field(metadata={"json": "endColumn"})
    snippet: Snippet = field(default_factory=lambda: Snippet(""))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "startLine": self.start_line,
            "endLine": self.end_line,
            "startColumn": self.start_column,
            "endColumn": self.end_column,
            "snippet": {"text": self.snippet.text},
        }


@dataclass
class PhysicalLocation:
    """SARIF physical location."""

    artifact_location: ArtifactLocation = field(
        metadata={"json": "artifactLocation"}
    )
    region: Region = field(default_factory=lambda: Region(0, 0, 0, 0))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "artifactLocation": {"uri": self.artifact_location.uri},
            "region": self.region.to_dict(),
        }


@dataclass
class Location:
    """SARIF location."""

    physical_location: PhysicalLocation = field(
        metadata={"json": "physicalLocation"}
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {"physicalLocation": self.physical_location.to_dict()}


@dataclass
class PartialFingerprints:
    """SARIF partial fingerprints for commit metadata."""

    commit_sha: str = field(metadata={"json": "commitSha"})
    email: str = ""
    author: str = ""
    date: str = ""
    commit_message: str = field(default="", metadata={"json": "commitMessage"})

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "commitSha": self.commit_sha,
            "email": self.email,
            "author": self.author,
            "date": self.date,
            "commitMessage": self.commit_message,
        }


@dataclass
class Properties:
    """SARIF properties (for tags)."""

    tags: List[str] = field(default_factory=list)


@dataclass
class Result:
    """SARIF result (finding)."""

    message: Message
    rule_id: str = field(metadata={"json": "ruleId"})
    locations: List[Location] = field(default_factory=list)
    partial_fingerprints: PartialFingerprints = field(
        default_factory=lambda: PartialFingerprints(""), metadata={"json": "partialFingerprints"}
    )
    properties: Properties = field(default_factory=lambda: Properties())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "message": {"text": self.message.text},
            "ruleId": self.rule_id,
            "locations": [loc.to_dict() for loc in self.locations],
            "partialFingerprints": self.partial_fingerprints.to_dict(),
            "properties": {"tags": self.properties.tags},
        }


@dataclass
class Run:
    """SARIF run."""

    tool: Tool
    results: List[Result] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict."""
        return {
            "tool": self.tool.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class Sarif:
    """SARIF root object."""

    schema: str = field(metadata={"json": "$schema"})
    version: str
    runs: List[Run] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with proper JSON field names."""
        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [run.to_dict() for run in self.runs],
        }


class SarifReporter:
    """SARIF 2.1.0 format reporter."""

    def __init__(self, ordered_rules: Optional[List[Any]] = None):
        """Initialize SARIF reporter.

        Args:
            ordered_rules: Optional list of Rule objects from config for consistent rule indices
        """
        self.ordered_rules = ordered_rules or []

    def write(self, writer: IO, findings: List[Finding]) -> None:
        """Write findings to SARIF 2.1.0 format.

        Args:
            writer: Output stream to write to
            findings: List of findings to report
        """
        sarif = Sarif(
            schema="https://json.schemastore.org/sarif-2.1.0.json",
            version="2.1.0",
            runs=self._get_runs(findings),
        )

        json.dump(sarif.to_dict(), writer, indent=" ")

    def _get_runs(self, findings: List[Finding]) -> List[Run]:
        """Create SARIF runs."""
        return [Run(tool=self._get_tool(), results=self._get_results(findings))]

    def _get_tool(self) -> Tool:
        """Create SARIF tool definition."""
        rules = self._get_rules()

        # Ensure empty rules is represented as [] not null
        if not rules:
            rules = []

        return Tool(
            driver=Driver(
                name=DRIVER,
                semantic_version=VERSION,
                information_uri="https://github.com/gitleaks/gitleaks",
                rules=rules,
            )
        )

    def _get_rules(self) -> List[Rule]:
        """Create SARIF rules from ordered_rules.

        NOTE: Uses rule.id (not rule.rule_id) to match config.Rule model.
        """
        rules = []
        for rule in self.ordered_rules:
            rules.append(
                Rule(
                    id=rule.id,  # CRITICAL: Use rule.id, not rule.rule_id
                    short_description=ShortDescription(text=rule.description),
                )
            )
        return rules

    def _get_results(self, findings: List[Finding]) -> List[Result]:
        """Convert findings to SARIF results."""
        results = []
        for f in findings:
            result = Result(
                message=Message(text=self._message_text(f)),
                rule_id=f.rule_id,
                locations=self._get_locations(f),
                partial_fingerprints=PartialFingerprints(
                    commit_sha=f.commit,
                    email=f.email,
                    author=f.author,
                    date=f.date,
                    commit_message=f.message,
                ),
                properties=Properties(tags=f.tags),
            )
            results.append(result)
        return results

    def _message_text(self, f: Finding) -> str:
        """Generate message text for a finding."""
        if not f.commit:
            return f"{f.rule_id} has detected secret for file {f.file}."
        return f"{f.rule_id} has detected secret for file {f.file} at commit {f.commit}."

    def _get_locations(self, f: Finding) -> List[Location]:
        """Create SARIF locations for a finding."""
        # Use symlink file if present, otherwise use regular file
        uri = f.symlink_file if f.symlink_file else f.file

        return [
            Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(uri=uri),
                    region=Region(
                        start_line=f.start_line,
                        end_line=f.end_line,
                        start_column=f.start_column,
                        end_column=f.end_column,
                        snippet=Snippet(text=f.secret),
                    ),
                )
            )
        ]
