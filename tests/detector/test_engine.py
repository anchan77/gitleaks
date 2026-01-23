"""Tests for the detection engine."""

import pytest
import asyncio
from gitleaks.detector.engine import Detector
from gitleaks.config.models import Config, Rule, Allowlist
from gitleaks.sources.fragment import Fragment, CommitInfo, RemoteInfo
from gitleaks.reporting.finding import Finding


class TestDetectorInit:
    """Tests for Detector initialization."""

    def test_init_with_empty_config(self):
        """Test initialization with empty config."""
        config = Config(rules=[])
        detector = Detector(config)
        assert detector.config == config
        assert detector.redact == 0
        assert detector.verbose == False
        assert detector.max_target_megabytes == 1024

    def test_init_with_rules(self):
        """Test initialization with rules builds prefilter."""
        rules = [
            Rule(id="test-rule", regex=r"secret", keywords=["api", "key"])
        ]
        config = Config(rules=rules)
        detector = Detector(config)
        assert detector.config == config


class TestKeywordPrefiltering:
    """Tests for keyword prefiltering."""

    def test_extract_keywords_empty(self):
        """Test keyword extraction from empty content."""
        config = Config(rules=[])
        detector = Detector(config)
        keywords = detector._extract_keywords("")
        assert keywords == set()

    def test_extract_keywords_with_matches(self):
        """Test keyword extraction with matches."""
        rules = [
            Rule(id="test", regex=r"secret", keywords=["api", "password"])
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        content = "This is an API key: secret123"
        keywords = detector._extract_keywords(content)
        assert "api" in keywords
        assert "password" not in keywords

    def test_keyword_case_insensitive(self):
        """Test that keyword matching is case-insensitive."""
        rules = [
            Rule(id="test", regex=r"secret", keywords=["api"])
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        content = "This is an API key"
        keywords = detector._extract_keywords(content)
        assert "api" in keywords


class TestPatternMatching:
    """Tests for pattern matching."""

    @pytest.mark.asyncio
    async def test_simple_regex_match(self):
        """Test simple regex matching."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="This is a secret123 value", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        assert findings[0].rule_id == "test-secret"
        assert findings[0].secret == "secret123"
        assert findings[0].match == "secret123"

    @pytest.mark.asyncio
    async def test_secret_group_extraction(self):
        """Test extraction of secret from capture group."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"api_key=([a-z0-9]+)",
                secret_group=1,
                description="API key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="api_key=abc123def", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        assert findings[0].secret == "abc123def"
        assert findings[0].match == "api_key=abc123def"

    @pytest.mark.asyncio
    async def test_multiple_matches(self):
        """Test multiple matches in same fragment."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(
            raw="secret123 and another secret456",
            file_path="test.txt"
        )
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 2
        assert findings[0].secret == "secret123"
        assert findings[1].secret == "secret456"

    @pytest.mark.asyncio
    async def test_multiline_match(self):
        """Test matching across multiple lines."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(
            raw="line 1\nline 2 with secret123\nline 3",
            file_path="test.txt"
        )
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        assert findings[0].start_line == 2  # 1-indexed
        assert findings[0].secret == "secret123"


class TestAllowlistFiltering:
    """Tests for allowlist filtering."""

    @pytest.mark.asyncio
    async def test_path_allowlist(self):
        """Test path-based allowlist filtering."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(paths=[r".*test\.txt$"])
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered by global allowlist
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_regex_allowlist(self):
        """Test regex-based allowlist filtering."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"secret[0-9]+",
                description="Test secret",
                allowlists=[
                    Allowlist(regexes=[r"secret123"])  # Rule-specific allowlist
                ]
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered by rule allowlist
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_stopword_allowlist(self):
        """Test stopword-based allowlist filtering."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"(secret[0-9]+)",  # Capture group to extract secret
                description="Test secret",
                allowlists=[
                    Allowlist(stop_words=["secret", "123"])
                ]
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="This is an example secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because "secret" is in the secret value
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_and_condition_all_criteria_match(self):
        """Test AND condition with all criteria matching - should filter."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                paths=[r".*test\.txt$"],
                regexes=[r"secret123"],
                condition="and"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because both path AND regex match
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_and_condition_partial_criteria_match(self):
        """Test AND condition with only some criteria matching - should NOT filter."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                paths=[r".*test\.txt$"],
                regexes=[r"secret999"],  # This won't match secret123
                condition="and"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should NOT be filtered because regex doesn't match (AND requires ALL)
        assert len(findings) == 1
        assert findings[0].secret == "secret123"

    @pytest.mark.asyncio
    async def test_or_condition_any_criteria_match(self):
        """Test OR condition with any criteria matching - should filter."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                paths=[r".*test\.txt$"],
                regexes=[r"secret999"],  # This won't match, but path will
                condition="or"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because path matches (OR requires ANY)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_or_condition_no_criteria_match(self):
        """Test OR condition with no criteria matching - should NOT filter."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                paths=[r".*other\.txt$"],
                regexes=[r"secret999"],
                condition="or"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should NOT be filtered because neither path nor regex match
        assert len(findings) == 1
        assert findings[0].secret == "secret123"

    @pytest.mark.asyncio
    async def test_and_condition_with_commit_path_regex(self):
        """Test AND condition with commit, path, and regex criteria."""
        from gitleaks.sources.fragment import CommitInfo

        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                commits=["abc123def"],  # Exact commit SHA
                paths=[r".*test\.txt$"],
                regexes=[r"secret123"],
                condition="and"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        commit_info = CommitInfo(
            sha="abc123def",
            author_name="Test",
            author_email="test@example.com",
            date="2024-01-01",
            message="Test commit",
            remote=None
        )
        fragment = Fragment(
            raw="secret123",
            file_path="test.txt",
            commit_info=commit_info
        )
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because commit AND path AND regex all match
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_and_condition_commit_path_only_no_regex_fast_path(self):
        """Test AND condition with only commit+path (no regex/stopwords) uses fast-path."""
        from gitleaks.sources.fragment import CommitInfo

        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        allowlists = [
            Allowlist(
                commits=["abc123def"],  # Exact commit SHA
                paths=[r".*test\.txt$"],
                condition="and"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        commit_info = CommitInfo(
            sha="abc123def",
            author_name="Test",
            author_email="test@example.com",
            date="2024-01-01",
            message="Test commit",
            remote=None
        )
        fragment = Fragment(
            raw="secret123",
            file_path="test.txt",
            commit_info=commit_info
        )
        findings = await detector._detect_fragment(fragment)

        # Should be filtered by fast-path because commit AND path match
        # and there are no regex/stopword criteria
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_and_condition_with_stopwords(self):
        """Test AND condition with path and stopwords."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"(secret[0-9]+)",
                description="Test secret"
            )
        ]
        allowlists = [
            Allowlist(
                paths=[r".*test\.txt$"],
                stop_words=["secret", "123"],
                condition="and"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because path matches AND stopwords are present
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_or_condition_with_mixed_criteria(self):
        """Test OR condition where only one of multiple criteria matches."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"(secret[0-9]+)",
                description="Test secret"
            )
        ]
        allowlists = [
            Allowlist(
                paths=[r".*other\.txt$"],  # Won't match
                stop_words=["secret"],      # Will match
                regexes=[r"secret999"],     # Won't match
                condition="or"
            )
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered because stopwords match (OR requires ANY)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_rule_specific_allowlist_and_condition(self):
        """Test rule-specific AND allowlist with path and regex."""
        rules = [
            Rule(
                id="test-secret",
                regex=r"secret[0-9]+",
                description="Test secret",
                allowlists=[
                    Allowlist(
                        paths=[r".*test\.txt$"],
                        regexes=[r"secret123"],
                        condition="and"
                    )
                ]
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="test.txt")
        findings = await detector._detect_fragment(fragment)

        # Should be filtered by rule-specific allowlist
        assert len(findings) == 0


class TestGitleaksAllowComment:
    """Tests for gitleaks:allow inline comment."""

    @pytest.mark.asyncio
    async def test_gitleaks_allow_comment(self):
        """Test that gitleaks:allow comment suppresses finding."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(
            raw="secret123  # gitleaks:allow",
            file_path="test.txt"
        )
        findings = await detector._detect_fragment(fragment)

        # Should be suppressed by gitleaks:allow
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_gitleaks_allow_ignored(self):
        """Test that gitleaks:allow can be ignored."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)
        detector.ignore_gitleaks_allow = True

        fragment = Fragment(
            raw="secret123  # gitleaks:allow",
            file_path="test.txt"
        )
        findings = await detector._detect_fragment(fragment)

        # Should NOT be suppressed when ignore_gitleaks_allow is True
        assert len(findings) == 1


class TestFindingMetadata:
    """Tests for finding metadata generation."""

    @pytest.mark.asyncio
    async def test_finding_has_file_info(self):
        """Test that finding includes file information."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="secret123", file_path="src/test.py")
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        assert findings[0].file == "src/test.py"

    @pytest.mark.asyncio
    async def test_finding_has_commit_info(self):
        """Test that finding includes commit information."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        commit_info = CommitInfo(
            sha="abc123def456",
            author_name="John Doe",
            author_email="john@example.com",
            date="2024-01-01T12:00:00Z",
            message="Add feature",
            remote=RemoteInfo(platform="github", url="https://github.com/user/repo")
        )
        fragment = Fragment(
            raw="secret123",
            file_path="test.py",
            commit_info=commit_info
        )
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.commit == "abc123def456"
        assert finding.author == "John Doe"
        assert finding.email == "john@example.com"
        assert finding.date == "2024-01-01T12:00:00Z"
        assert "github.com" in finding.link

    @pytest.mark.asyncio
    async def test_fingerprint_generation(self):
        """Test fingerprint generation for deduplication."""
        rules = [
            Rule(id="test-secret", regex=r"secret[0-9]+", description="Test secret")
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Without commit
        fragment = Fragment(raw="secret123", file_path="test.py")
        findings = await detector._detect_fragment(fragment)
        assert findings[0].fingerprint == "test.py:test-secret:1"

        # With commit
        commit_info = CommitInfo(
            sha="abc123",
            author_name="Test",
            author_email="test@example.com",
            date="2024-01-01",
            message="Test",
            remote=None
        )
        fragment_with_commit = Fragment(
            raw="secret123",
            file_path="test.py",
            commit_info=commit_info
        )
        findings = await detector._detect_fragment(fragment_with_commit)
        assert findings[0].fingerprint == "abc123:test.py:test-secret:1"


class TestPathOnlyRules:
    """Tests for path-only rules (no regex, just path pattern)."""

    @pytest.mark.asyncio
    async def test_path_only_match(self):
        """Test rule that only matches on path."""
        rules = [
            Rule(
                id="sensitive-file",
                path=r".*\.pem$",
                description="PEM file detected"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        fragment = Fragment(raw="", file_path="certificate.pem")
        findings = await detector._detect_fragment(fragment)

        assert len(findings) == 1
        assert findings[0].rule_id == "sensitive-file"
        assert "file detected" in findings[0].match.lower()


class TestDetectSourceIntegration:
    """Integration tests for detect_source() with real Source implementations."""

    @pytest.mark.asyncio
    async def test_detect_source_with_file_source(self):
        """Test detect_source with File source."""
        import io
        from gitleaks.sources.file import File

        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Create a File source with a secret
        content = b"This file contains AKIAIRYLJVKMPEGZMPJS secret"
        reader = io.BytesIO(content)
        file_source = File(
            content=reader,
            path="test.txt",
            config=config
        )

        # Use detect_source
        findings = await detector.detect_source(file_source)

        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key"
        assert findings[0].secret == "AKIAIRYLJVKMPEGZMPJS"
        assert findings[0].file == "test.txt"

    @pytest.mark.asyncio
    async def test_detect_source_with_on_finding_callback(self):
        """Test detect_source with on_finding callback."""
        import io
        from gitleaks.sources.file import File

        rules = [
            Rule(
                id="test-secret",
                regex=r"secret[0-9]+",
                description="Test secret"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Track findings via callback
        callback_findings = []

        def on_finding(finding: Finding):
            callback_findings.append(finding)

        # Create a File source with multiple secrets
        content = b"secret123\nsecret456"
        reader = io.BytesIO(content)
        file_source = File(
            content=reader,
            path="secrets.txt",
            config=config
        )

        # Use detect_source with callback
        findings = await detector.detect_source(file_source, on_finding=on_finding)

        assert len(findings) == 2
        assert len(callback_findings) == 2
        assert findings[0].secret == "secret123"
        assert findings[1].secret == "secret456"

    @pytest.mark.asyncio
    async def test_detect_source_with_allowlist(self):
        """Test detect_source respects allowlists."""
        import io
        from gitleaks.sources.file import File

        rules = [
            Rule(
                id="test-secret",
                regex=r"secret[0-9]+",
                description="Test secret"
            )
        ]
        allowlists = [
            Allowlist(paths=[r".*allowed\.txt$"])
        ]
        config = Config(rules=rules, allowlists=allowlists)
        detector = Detector(config)

        # Create File source with allowed path
        content = b"secret123"
        reader = io.BytesIO(content)
        file_source = File(
            content=reader,
            path="allowed.txt",
            config=config
        )

        # Should be filtered by allowlist
        findings = await detector.detect_source(file_source)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_source_empty_source(self):
        """Test detect_source with empty source."""
        import io
        from gitleaks.sources.file import File

        rules = [
            Rule(
                id="test-secret",
                regex=r"secret[0-9]+",
                description="Test secret"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Create empty File source
        content = b""
        reader = io.BytesIO(content)
        file_source = File(
            content=reader,
            path="empty.txt",
            config=config
        )

        findings = await detector.detect_source(file_source)
        assert len(findings) == 0
