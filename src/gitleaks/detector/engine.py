"""
Core detection engine for gitleaks.

This module implements the Detector class which orchestrates secret scanning:
- Keyword prefiltering with Aho-Corasick trie
- Regex pattern matching against fragments
- Allowlist filtering
- Finding generation and deduplication
- Concurrent fragment processing
"""

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import List, Optional, Set, Dict
import regex
import ahocorasick

from gitleaks.config.models import Config, Rule, Allowlist, AllowlistMatchCondition
from gitleaks.sources.fragment import Fragment
from gitleaks.reporting.finding import Finding
from gitleaks.detector.location import location, find_newline_indices, extract_line
from gitleaks.detector.utils import shannon_entropy, filter_findings, create_scm_link, print_finding
from gitleaks.detector.baseline import load_baseline, is_new_finding
from gitleaks.logging import get_logger

logger = get_logger(__name__)

# Constants
GITLEAKS_ALLOW_SIGNATURE = "gitleaks:allow"


class Detector:
    """
    Main detector for scanning content fragments and finding secrets.

    The Detector manages the scanning pipeline: keyword prefiltering, pattern
    matching, allowlist filtering, and finding generation.
    """

    def __init__(self, config: Config):
        """
        Initialize the detector with a configuration.

        Args:
            config: Configuration containing rules and allowlists
        """
        self.config = config
        self.redact = 0  # Redaction percentage (0-100)
        self.verbose = False
        self.max_target_megabytes = 1024  # Default 1GB
        self.follow_symlinks = False
        self.no_color = False
        self.ignore_gitleaks_allow = False
        self.max_archive_depth = 3  # Default max depth for nested archives

        # Thread-safe storage for findings
        self._findings: List[Finding] = []
        self._findings_lock = asyncio.Lock()

        # Commit tracking (for logging)
        self._commits: Set[str] = set()
        self._commits_lock = asyncio.Lock()

        # Build keyword prefilter using Aho-Corasick trie
        self._prefilter = ahocorasick.Automaton()
        self._build_prefilter()

        # Concurrency control
        self._semaphore = asyncio.Semaphore(40)  # Default concurrency limit

        # Statistics
        self._total_bytes = 0

        # Baseline and gitleaksignore support
        self.baseline: List[Finding] = []
        self.baseline_path: str = ""
        self.gitleaks_ignore: Dict[str, bool] = {}

    def _build_prefilter(self) -> None:
        """Build Aho-Corasick trie from all keywords in rules."""
        # Collect all unique keywords from rules (already lowercased in Rule model)
        self._has_keywords = False
        for rule in self.config.rules:
            for keyword in rule.keywords:
                keyword_lower = keyword.lower()
                self._prefilter.add_word(keyword_lower, keyword_lower)
                self._has_keywords = True

        # Finalize the automaton only if keywords were added
        if self._has_keywords:
            self._prefilter.make_automaton()

    async def detect_source(
        self,
        source: "Source",
        on_finding: Optional[Callable[[Finding], None]] = None
    ) -> List[Finding]:
        """
        Detect secrets from a source.

        Args:
            source: Source to scan (implements fragments() method)
            on_finding: Optional callback invoked for each finding

        Returns:
            List of all findings

        Raises:
            Any exception raised by the source
        """
        # Reset findings for new scan
        async with self._findings_lock:
            self._findings = []

        # Define callback to process fragments
        def process_callback(fragment: Fragment, error: Optional[Exception]) -> Optional[Exception]:
            if error:
                return error

            # Create task for async processing
            task = asyncio.create_task(self._process_fragment(fragment, on_finding))
            # Store task so we can await it later
            if not hasattr(self, '_pending_tasks'):
                self._pending_tasks = []
            self._pending_tasks.append(task)

            return None

        # Initialize task list
        self._pending_tasks = []

        # Call fragments with callback
        await source.fragments(process_callback)

        # Wait for all processing tasks to complete
        if self._pending_tasks:
            await asyncio.gather(*self._pending_tasks)
            self._pending_tasks = []

        # Return all findings
        async with self._findings_lock:
            findings = list(self._findings)

        # Apply filtering and redaction
        findings = filter_findings(findings, self.redact)

        return findings

    async def _process_fragment(
        self,
        fragment: Fragment,
        on_finding: Optional[Callable[[Finding], None]] = None
    ) -> None:
        """
        Process a single fragment through the detection pipeline.

        Args:
            fragment: Fragment to scan
            on_finding: Optional callback for each finding
        """
        async with self._semaphore:
            # Track commit if present
            if fragment.commit_sha:
                async with self._commits_lock:
                    self._commits.add(fragment.commit_sha)

            # Detect findings in fragment
            findings = await self._detect_fragment(fragment)

            # Store and optionally callback
            async with self._findings_lock:
                for finding in findings:
                    self._findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                    if self.verbose:
                        # Apply redaction before printing if needed
                        if self.redact > 0:
                            # Create a copy to avoid modifying the stored finding
                            import copy
                            redacted_finding = copy.deepcopy(finding)
                            redacted_finding.redact(self.redact)
                            print_finding(redacted_finding, self.no_color)
                        else:
                            print_finding(finding, self.no_color)

    async def _detect_fragment(self, fragment: Fragment) -> List[Finding]:
        """
        Detect secrets in a single fragment.

        Args:
            fragment: Fragment to scan

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        # Update byte count
        if fragment.raw:
            self._total_bytes += len(fragment.raw)

        # Check if fragment should be skipped
        if not fragment.raw and not fragment.file_path:
            logger.debug("skipping empty fragment")
            return findings

        # Check global allowlists for commit/path
        if self._check_commit_or_path_allowed(fragment):
            logger.debug(f"skipping file: global allowlist matches {fragment.file_path}")
            return findings

        # Check size limit (0 means no limit)
        if fragment.raw and self.max_target_megabytes > 0:
            size_mb = len(fragment.raw) / (1024 * 1024)
            if size_mb > self.max_target_megabytes:
                logger.debug(
                    f"skipping file {fragment.file_path}: "
                    f"size {size_mb:.2f}MB exceeds limit {self.max_target_megabytes}MB"
                )
                return findings

        # Build keyword map using prefilter
        keywords = self._extract_keywords(fragment.raw)

        # Run detection for each rule
        for rule in self.config.rules:
            # Skip if rule has keywords but none match
            if rule.keywords and not any(k.lower() in keywords for k in rule.keywords):
                continue

            # Detect with this rule
            rule_findings = await self._detect_rule(fragment, rule)
            findings.extend(rule_findings)

        return findings

    def _extract_keywords(self, content: str) -> Set[str]:
        """
        Extract keywords from content using Aho-Corasick prefilter.

        Args:
            content: Content to search

        Returns:
            Set of matched keywords (lowercased)
        """
        keywords = set()
        if not content or not self._has_keywords:
            return keywords

        content_lower = content.lower()
        for _, keyword in self._prefilter.iter(content_lower):
            keywords.add(keyword)

        return keywords

    async def _detect_rule(self, fragment: Fragment, rule: Rule) -> List[Finding]:
        """
        Detect secrets using a specific rule.

        Args:
            fragment: Fragment to scan
            rule: Rule to apply

        Returns:
            List of findings for this rule
        """
        findings: List[Finding] = []

        # Check rule-specific allowlists for commit/path
        if self._check_rule_allowlist_commit_path(fragment, rule):
            logger.debug(
                f"skipping rule {rule.id} for {fragment.file_path}: "
                f"rule allowlist matches"
            )
            return findings

        # Handle path-only rules
        if rule._path_compiled and not rule._regex_compiled:
            if rule._path_compiled.search(fragment.file_path):
                finding = self._create_path_finding(fragment, rule)
                if not self._should_suppress_finding(finding, rule):
                    findings.append(finding)
            return findings

        # Check if path pattern is required and matches
        if rule._path_compiled:
            if not rule._path_compiled.search(fragment.file_path):
                return findings

        # If no regex, nothing more to do
        if not rule._regex_compiled:
            return findings

        # Find all regex matches
        content = fragment.raw
        newline_indices = find_newline_indices(content)

        for match in rule._regex_compiled.finditer(content):
            # Calculate location
            match_index = (match.start(), match.end())
            loc = location(newline_indices, content, match_index)

            # Extract the line containing the match
            line = extract_line(content, loc.start_line_index, loc.end_line_index)

            # Check for gitleaks:allow comment (unless disabled)
            if not self.ignore_gitleaks_allow:
                if GITLEAKS_ALLOW_SIGNATURE in line:
                    logger.debug(f"skipping match on line {loc.start_line + 1}: gitleaks:allow")
                    continue

            # Extract secret from capture groups
            secret = self._extract_secret(match, rule)

            # Skip if secret is empty
            if not secret:
                continue

            # Calculate entropy (but don't filter by it in this milestone)
            entropy = shannon_entropy(secret)

            # Create finding
            finding = Finding(
                rule_id=rule.id,
                description=rule.description,
                start_line=loc.start_line + 1 + fragment.start_line,  # Convert to 1-indexed
                end_line=loc.end_line + 1 + fragment.start_line,
                start_column=loc.start_column,
                end_column=loc.end_column,
                line=line,
                match=match.group(0),
                secret=secret,
                file=fragment.file_path,
                symlink_file=fragment.symlink_file,
                entropy=entropy,
                tags=list(rule.tags) if rule.tags else [],
            )

            # Add commit information if available
            if fragment.commit_info:
                finding.commit = fragment.commit_info.sha
                finding.author = fragment.commit_info.author_name
                finding.email = fragment.commit_info.author_email
                finding.date = fragment.commit_info.date
                finding.message = fragment.commit_info.message

                # Generate SCM link
                if fragment.commit_info.remote:
                    remote_dict = {
                        "platform": fragment.commit_info.remote.platform,
                        "url": fragment.commit_info.remote.url
                    }
                    finding.link = create_scm_link(remote_dict, finding)

            # Generate fingerprint
            finding.fingerprint = self._generate_fingerprint(finding)

            # Check if finding should be suppressed
            if self._should_suppress_finding(finding, rule):
                continue

            findings.append(finding)

        return findings

    def _extract_secret(self, match: regex.Match, rule: Rule) -> str:
        """
        Extract the secret from regex match groups.

        Args:
            match: Regex match object
            rule: Rule being applied

        Returns:
            Extracted secret string
        """
        groups = match.groups()

        # If no capture groups, use the full match
        if not groups:
            return match.group(0)

        # If secretGroup is specified and valid, use that group
        if rule.secret_group > 0:
            if rule.secret_group <= len(groups):
                return groups[rule.secret_group - 1] or ""
            else:
                logger.warn(
                    f"rule {rule.id} secretGroup {rule.secret_group} "
                    f"exceeds group count {len(groups)}"
                )
                return ""

        # Otherwise, return first non-empty group
        for group in groups:
            if group:
                return group

        # If all groups are empty, return the full match
        return match.group(0)

    def _create_path_finding(self, fragment: Fragment, rule: Rule) -> Finding:
        """
        Create a finding for a path-only match.

        Args:
            fragment: Fragment being scanned
            rule: Rule that matched

        Returns:
            Finding object
        """
        finding = Finding(
            rule_id=rule.id,
            description=rule.description,
            match=f"file detected: {fragment.file_path}",
            secret=fragment.file_path,
            file=fragment.file_path,
            symlink_file=fragment.symlink_file,
            start_line=0,
            end_line=0,
            start_column=0,
            end_column=0,
            tags=list(rule.tags) if rule.tags else [],
        )

        # Add commit information if available
        if fragment.commit_info:
            finding.commit = fragment.commit_info.sha
            finding.author = fragment.commit_info.author_name
            finding.email = fragment.commit_info.author_email
            finding.date = fragment.commit_info.date
            finding.message = fragment.commit_info.message

        # Generate fingerprint
        finding.fingerprint = self._generate_fingerprint(finding)

        return finding

    def _generate_fingerprint(self, finding: Finding) -> str:
        """
        Generate a unique fingerprint for deduplication.

        Args:
            finding: Finding to generate fingerprint for

        Returns:
            Fingerprint string
        """
        if finding.commit:
            return f"{finding.commit}:{finding.file}:{finding.rule_id}:{finding.start_line}"
        else:
            return f"{finding.file}:{finding.rule_id}:{finding.start_line}"

    def _check_commit_or_path_allowed(self, fragment: Fragment) -> bool:
        """
        Check if fragment is allowed by global commit/path allowlists.

        This is a fast-path check before running rules. Only applies to:
        - Allowlists with OR condition (any criterion can match)
        - Allowlists with only commit/path checks (no regex/stopwords)

        For AND conditions with multiple criteria types, the full check
        must be deferred until all criteria can be evaluated.

        Args:
            fragment: Fragment to check

        Returns:
            True if fragment should be skipped
        """
        if not self.config.allowlists:
            return False

        for allowlist in self.config.allowlists:
            # For AND condition, skip fast-path if there are regex/stopword checks
            # because we can't determine if ALL conditions match without the content
            if allowlist._match_condition == AllowlistMatchCondition.AND:
                if allowlist.regexes or allowlist.stop_words:
                    continue

            # For OR condition with only regex/stopwords, skip (no commit/path to check)
            if not allowlist.commits and not allowlist.paths:
                continue

            # Check allowlist (commit and/or path only)
            if self._allowlist_matches(
                allowlist,
                commit=fragment.commit_sha if fragment.commit_info else "",
                path=fragment.file_path,
                content="",
                check_regex=False,
                check_stopwords=False
            ):
                return True

        return False

    def _check_rule_allowlist_commit_path(self, fragment: Fragment, rule: Rule) -> bool:
        """
        Check if fragment is allowed by rule-specific commit/path allowlists.

        Args:
            fragment: Fragment to check
            rule: Rule being applied

        Returns:
            True if fragment should be skipped for this rule
        """
        if not rule.allowlists:
            return False

        for allowlist in rule.allowlists:
            # For AND condition, skip fast-path if there are regex/stopword checks
            if allowlist._match_condition == AllowlistMatchCondition.AND:
                if allowlist.regexes or allowlist.stop_words:
                    continue

            # For OR condition with only regex/stopwords, skip (no commit/path to check)
            if not allowlist.commits and not allowlist.paths:
                continue

            # Check allowlist (commit and/or path only)
            if self._allowlist_matches(
                allowlist,
                commit=fragment.commit_sha if fragment.commit_info else "",
                path=fragment.file_path,
                content="",
                check_regex=False,
                check_stopwords=False
            ):
                return True

        return False

    def _is_finding_allowed(self, finding: Finding, rule: Rule) -> bool:
        """
        Check if finding is allowed (should be suppressed).

        Args:
            finding: Finding to check
            rule: Rule that generated the finding

        Returns:
            True if finding should be suppressed
        """
        # Check global allowlists
        for allowlist in self.config.allowlists:
            if self._allowlist_matches_finding(allowlist, finding):
                return True

        # Check rule-specific allowlists
        for allowlist in rule.allowlists:
            if self._allowlist_matches_finding(allowlist, finding):
                return True

        return False

    def _should_suppress_finding(self, finding: Finding, rule: Rule) -> bool:
        """
        Check if finding should be suppressed (allowlist, gitleaksignore, or baseline).

        Args:
            finding: Finding to check
            rule: Rule that generated the finding

        Returns:
            True if finding should be suppressed
        """
        # Check allowlists first
        if self._is_finding_allowed(finding, rule):
            logger.debug(f"skipping finding: allowlist matches")
            return True

        # Check gitleaksignore
        # Generate both global and commit fingerprints for checking
        global_fingerprint = f"{finding.file}:{finding.rule_id}:{finding.start_line}"

        if global_fingerprint in self.gitleaks_ignore:
            logger.debug(f"skipping finding: global fingerprint in gitleaksignore: {global_fingerprint}")
            return True

        if finding.commit and finding.fingerprint in self.gitleaks_ignore:
            logger.debug(f"skipping finding: commit fingerprint in gitleaksignore: {finding.fingerprint}")
            return True

        # Check baseline
        if self.baseline and not is_new_finding(finding, self.redact, self.baseline):
            logger.debug(f"skipping finding: present in baseline: {finding.fingerprint}")
            return True

        return False

    def _allowlist_matches_finding(self, allowlist: Allowlist, finding: Finding) -> bool:
        """
        Check if allowlist matches a finding.

        Args:
            allowlist: Allowlist to check
            finding: Finding to check

        Returns:
            True if allowlist matches
        """
        # Determine content to check based on regex_target
        if allowlist.regex_target == "match":
            content = finding.match
        elif allowlist.regex_target == "line":
            content = finding.line
        else:  # Default: "secret" or ""
            content = finding.secret

        return self._allowlist_matches(
            allowlist,
            commit=finding.commit,
            path=finding.file,
            content=content,
            check_regex=True,
            check_stopwords=True
        )

    def _allowlist_matches(
        self,
        allowlist: Allowlist,
        commit: str,
        path: str,
        content: str,
        check_regex: bool = True,
        check_stopwords: bool = True
    ) -> bool:
        """
        Check if allowlist criteria match.

        Args:
            allowlist: Allowlist to check
            commit: Commit SHA (may be empty)
            path: File path
            content: Content to check (secret/match/line)
            check_regex: Whether to check regex patterns
            check_stopwords: Whether to check stopwords

        Returns:
            True if allowlist matches
        """
        # Track which checks passed
        checks = []

        # Check commits
        if allowlist.commits:
            commit_match, _ = allowlist.commit_allowed(commit)
            checks.append(commit_match)

        # Check paths
        if allowlist.paths:
            path_match = allowlist.path_allowed(path)
            checks.append(path_match)

        # Check regexes
        if check_regex and allowlist.regexes:
            regex_match = allowlist.regex_allowed(content)
            checks.append(regex_match)

        # Check stopwords
        if check_stopwords and allowlist.stop_words:
            stopword_match, _ = allowlist.contains_stop_word(content)
            checks.append(stopword_match)

        # If no checks were performed, don't match
        if not checks:
            return False

        # Apply condition (AND or OR)
        if allowlist._match_condition == AllowlistMatchCondition.AND:
            return all(checks)
        else:  # OR
            return any(checks)

    def add_finding(self, finding: Finding) -> None:
        """
        Manually add a finding to the detector.

        This is a synchronous method for adding findings outside of
        the normal detection pipeline.

        Args:
            finding: Finding to add
        """
        self._findings.append(finding)

    def get_findings(self) -> List[Finding]:
        """
        Get all accumulated findings.

        Returns:
            List of findings
        """
        return list(self._findings)

    def add_baseline(self, baseline_path: str, source: str) -> None:
        """
        Load and configure baseline for suppressing known findings.

        Args:
            baseline_path: Path to baseline JSON file
            source: Source path being scanned (used to compute relative baseline path)

        Raises:
            FileNotFoundError: If baseline file doesn't exist
            ValueError: If baseline format is invalid
        """
        if not baseline_path:
            return

        # Convert paths to absolute
        absolute_source = Path(source).resolve()
        absolute_baseline = Path(baseline_path).resolve()

        # Compute relative path from source to baseline
        try:
            if absolute_source.is_file():
                # If source is a file, use its parent directory
                relative_baseline = absolute_baseline.relative_to(absolute_source.parent)
            else:
                relative_baseline = absolute_baseline.relative_to(absolute_source)
            baseline_path_str = str(relative_baseline)
        except ValueError:
            # If relative path can't be computed, use absolute path
            baseline_path_str = str(absolute_baseline)

        # Load baseline findings
        self.baseline = load_baseline(str(absolute_baseline))
        self.baseline_path = baseline_path_str

        logger.info(f"loaded baseline from {baseline_path_str} with {len(self.baseline)} findings")

    def add_gitleaks_ignore(self, gitleaks_ignore_path: str) -> None:
        """
        Load fingerprints from a .gitleaksignore file.

        The .gitleaksignore file format supports:
        - Global fingerprints: file:rule-id:start-line
        - Commit fingerprints: commit:file:rule-id:start-line
        - Comments starting with #
        - Empty lines (ignored)

        Args:
            gitleaks_ignore_path: Path to .gitleaksignore file

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file can't be read
        """
        path = Path(gitleaks_ignore_path)

        if not path.exists():
            raise FileNotFoundError(f"gitleaksignore file not found: {gitleaks_ignore_path}")

        logger.debug(f"found .gitleaksignore file at {gitleaks_ignore_path}")

        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Normalize path separators (Windows compatibility)
                # Split fingerprint into parts
                parts = line.split(':')

                if len(parts) == 3:
                    # Global fingerprint: file:rule-id:start-line
                    parts[0] = parts[0].replace('\\', '/')
                    fingerprint = ':'.join(parts)
                elif len(parts) == 4:
                    # Commit fingerprint: commit:file:rule-id:start-line
                    parts[1] = parts[1].replace('\\', '/')
                    fingerprint = ':'.join(parts)
                else:
                    logger.warn(f"invalid .gitleaksignore entry: {line}")
                    continue

                # Store fingerprint in ignore set
                self.gitleaks_ignore[fingerprint] = True

        logger.info(f"loaded {len(self.gitleaks_ignore)} fingerprints from {gitleaks_ignore_path}")
