"""Tests for detector utility functions."""

import pytest
from gitleaks.detector.utils import shannon_entropy, filter_findings, create_scm_link
from gitleaks.reporting.finding import Finding


class TestShannonEntropy:
    """Tests for shannon_entropy function."""

    def test_empty_string(self):
        """Test entropy of empty string."""
        assert shannon_entropy("") == 0.0

    def test_uniform_string(self):
        """Test entropy of uniform string (all same character)."""
        entropy = shannon_entropy("aaaa")
        assert entropy == 0.0

    def test_two_characters(self):
        """Test entropy of string with two different characters."""
        entropy = shannon_entropy("aabb")
        # For "aabb": 2 a's and 2 b's out of 4 chars
        # p(a) = 0.5, p(b) = 0.5
        # H = -(0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0
        assert abs(entropy - 1.0) < 0.001

    def test_high_entropy(self):
        """Test entropy of random-looking string."""
        entropy = shannon_entropy("abcd1234")
        # Should have relatively high entropy
        assert entropy > 2.0

    def test_realistic_secret(self):
        """Test entropy of a realistic secret."""
        secret = "ghp_1234567890abcdefghijklmnopqrstuv"
        entropy = shannon_entropy(secret)
        # Typical high-entropy secret
        assert entropy > 3.5


class TestFilterFindings:
    """Tests for filter_findings function."""

    def test_no_findings(self):
        """Test filtering with no findings."""
        result = filter_findings([])
        assert result == []

    def test_non_generic_findings(self):
        """Test that non-generic findings are preserved."""
        findings = [
            Finding(rule_id="aws-access-key", secret="AKIAIOSFODNN7EXAMPLE", start_line=1),
            Finding(rule_id="github-pat", secret="ghp_1234567890", start_line=2),
        ]
        result = filter_findings(findings)
        assert len(result) == 2

    def test_generic_finding_without_specific(self):
        """Test that generic finding is kept if no specific rule matches."""
        findings = [
            Finding(rule_id="generic-api-key", secret="api_key_123", start_line=1, commit="abc123"),
        ]
        result = filter_findings(findings)
        assert len(result) == 1

    def test_generic_finding_with_specific_same_line(self):
        """Test that generic finding is filtered when specific rule matches same line."""
        findings = [
            Finding(
                rule_id="generic-api-key",
                secret="api_key",
                match="api_key_123456",
                start_line=1,
                commit="abc123"
            ),
            Finding(
                rule_id="aws-access-key",
                secret="api_key_123456",
                match="api_key_123456",
                start_line=1,
                commit="abc123"
            ),
        ]
        result = filter_findings(findings)
        # Generic should be filtered out
        assert len(result) == 1
        assert result[0].rule_id == "aws-access-key"

    def test_generic_finding_different_line(self):
        """Test that generic finding is kept if on different line."""
        findings = [
            Finding(
                rule_id="generic-api-key",
                secret="api_key",
                start_line=1,
                commit="abc123"
            ),
            Finding(
                rule_id="aws-access-key",
                secret="api_key_123456",
                start_line=2,  # Different line
                commit="abc123"
            ),
        ]
        result = filter_findings(findings)
        # Both should be kept
        assert len(result) == 2

    def test_redaction_zero(self):
        """Test that redaction of 0 doesn't change findings."""
        findings = [
            Finding(rule_id="test", secret="my_secret", match="key=my_secret", line="key=my_secret", start_line=1),
        ]
        result = filter_findings(findings, redact=0)
        assert result[0].secret == "my_secret"

    def test_redaction_full(self):
        """Test full redaction."""
        findings = [
            Finding(rule_id="test", secret="my_secret", match="key=my_secret", line="key=my_secret", start_line=1),
        ]
        result = filter_findings(findings, redact=100)
        assert result[0].secret == "REDACTED"


class TestCreateScmLink:
    """Tests for create_scm_link function."""

    def test_no_remote_info(self):
        """Test with no remote info."""
        finding = Finding(rule_id="test", file="test.py", commit="abc123", start_line=10)
        link = create_scm_link(None, finding)
        assert link == ""

    def test_no_commit(self):
        """Test with no commit."""
        finding = Finding(rule_id="test", file="test.py", start_line=10)
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert link == ""

    def test_unknown_platform(self):
        """Test with unknown platform."""
        finding = Finding(rule_id="test", file="test.py", commit="abc123", start_line=10)
        remote = {"platform": "unknown", "url": "https://example.com"}
        link = create_scm_link(remote, finding)
        assert link == ""

    def test_github_single_line(self):
        """Test GitHub link for single line."""
        finding = Finding(
            rule_id="test",
            file="src/test.py",
            commit="abc123def",
            start_line=10,
            end_line=10
        )
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert link == "https://github.com/user/repo/blob/abc123def/src/test.py#L10"

    def test_github_multiline(self):
        """Test GitHub link for multiple lines."""
        finding = Finding(
            rule_id="test",
            file="src/test.py",
            commit="abc123def",
            start_line=10,
            end_line=12
        )
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert link == "https://github.com/user/repo/blob/abc123def/src/test.py#L10-L12"

    def test_github_notebook(self):
        """Test GitHub link for notebook with ?plain=1."""
        finding = Finding(
            rule_id="test",
            file="notebook.ipynb",
            commit="abc123def",
            start_line=5,
            end_line=5
        )
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert "?plain=1" in link
        assert link == "https://github.com/user/repo/blob/abc123def/notebook.ipynb?plain=1#L5"

    def test_gitlab(self):
        """Test GitLab link."""
        finding = Finding(
            rule_id="test",
            file="src/test.py",
            commit="abc123def",
            start_line=10,
            end_line=12
        )
        remote = {"platform": "gitlab", "url": "https://gitlab.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert link == "https://gitlab.com/user/repo/blob/abc123def/src/test.py#L10-12"

    def test_bitbucket(self):
        """Test Bitbucket link."""
        finding = Finding(
            rule_id="test",
            file="src/test.py",
            commit="abc123def",
            start_line=10,
            end_line=12
        )
        remote = {"platform": "bitbucket", "url": "https://bitbucket.org/user/repo"}
        link = create_scm_link(remote, finding)
        assert link == "https://bitbucket.org/user/repo/src/abc123def/src/test.py#lines-10:12"

    def test_inner_archive_path(self):
        """Test link with inner archive path (no line numbers)."""
        finding = Finding(
            rule_id="test",
            file="archive.zip::inner/test.py",
            commit="abc123def",
            start_line=10,
            end_line=10
        )
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        # Should not include line numbers for inner paths
        assert link == "https://github.com/user/repo/blob/abc123def/archive.zip"

    def test_path_with_spaces(self):
        """Test path with spaces gets URL encoded."""
        finding = Finding(
            rule_id="test",
            file="my file.py",
            commit="abc123def",
            start_line=10,
            end_line=10
        )
        remote = {"platform": "github", "url": "https://github.com/user/repo"}
        link = create_scm_link(remote, finding)
        assert "my%20file.py" in link
