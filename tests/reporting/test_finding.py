"""
Tests for the Finding model and redaction functionality.

Ports tests from report/finding_test.go
"""

import pytest
from gitleaks.reporting.finding import Finding, RequiredFinding, mask_secret


class TestRedact:
    """Test the redact method of Finding."""

    def test_redact_100_percent(self):
        """Test that 100% redaction replaces secret with 'REDACTED'."""
        finding = Finding(
            match="line containing secret",
            secret="secret",
        )

        finding.redact(100)

        assert finding.secret == "REDACTED"
        assert finding.match == "line containing REDACTED"

    def test_redact_with_line(self):
        """Test that redaction also updates the line field."""
        finding = Finding(
            line="line containing secret",
            match="line containing secret",
            secret="secret",
        )

        finding.redact(100)

        assert finding.secret == "REDACTED"
        assert finding.match == "line containing REDACTED"
        assert finding.line == "line containing REDACTED"


class TestMask:
    """Test the mask_secret function with various percentages."""

    def test_normal_secret(self):
        """Test masking a normal-length secret at 75%."""
        finding = Finding(
            match="line containing secret",
            secret="secret",
        )

        finding.redact(75)

        assert finding.secret == "se..."
        assert finding.match == "line containing se..."

    def test_empty_secret(self):
        """Test masking an empty secret."""
        finding = Finding(
            match="line containing",
            secret="",
        )

        finding.redact(75)

        assert finding.secret == ""
        assert finding.match == "line containing"

    def test_short_secret(self):
        """Test masking a very short secret at 75%."""
        finding = Finding(
            match="line containing",
            secret="ss",
        )

        finding.redact(75)

        # With 2 character secret and 75% masking:
        # visible = 2 * (100-75) / 100 = 0.5, rounds to 0
        assert finding.secret == "..."
        assert finding.match == "line containing"


class TestMaskSecret:
    """Test the mask_secret function directly."""

    def test_normal_masking(self):
        """Test 75% masking of 'secret' (6 chars)."""
        result = mask_secret("secret", 75)
        # visible = 6 * 25 / 100 = 1.5, rounds to 2 (banker's rounding)
        assert result == "se..."

    def test_high_masking(self):
        """Test 90% masking of 'secret'."""
        result = mask_secret("secret", 90)
        # visible = 6 * 10 / 100 = 0.6, rounds to 1 (banker's rounding to even)
        assert result == "s..."

    def test_low_masking(self):
        """Test 10% masking of 'secret'."""
        result = mask_secret("secret", 10)
        # visible = 6 * 90 / 100 = 5.4, rounds to 5
        assert result == "secre..."

    def test_invalid_masking(self):
        """Test that percent > 100 is clamped to 100."""
        result = mask_secret("secret", 1000)
        # percent clamped to 100, so visible = 0
        assert result == "..."

    def test_empty_secret(self):
        """Test masking an empty string."""
        result = mask_secret("", 75)
        assert result == ""

    def test_single_char_secret(self):
        """Test masking a single character."""
        result = mask_secret("x", 75)
        # visible = 1 * 25 / 100 = 0.25, rounds to 0
        assert result == "..."


class TestAddRequiredFindings:
    """Test adding required findings to a Finding."""

    def test_add_required_findings(self):
        """Test that required findings can be added."""
        finding = Finding(rule_id="main-rule")
        required = [
            RequiredFinding(rule_id="req-1", secret="sec1"),
            RequiredFinding(rule_id="req-2", secret="sec2"),
        ]

        finding.add_required_findings(required)

        assert len(finding.required_findings) == 2
        assert finding.required_findings[0].rule_id == "req-1"
        assert finding.required_findings[1].rule_id == "req-2"

    def test_add_required_findings_multiple_times(self):
        """Test that multiple calls to add_required_findings accumulate."""
        finding = Finding(rule_id="main-rule")

        finding.add_required_findings([RequiredFinding(rule_id="req-1")])
        finding.add_required_findings([RequiredFinding(rule_id="req-2")])

        assert len(finding.required_findings) == 2
