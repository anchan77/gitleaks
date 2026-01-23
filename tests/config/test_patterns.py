"""
Tests for pattern generation utilities.
"""

import re

import pytest

from src.gitleaks.config.patterns import (
    alphanumeric,
    alphanumeric_extended,
    alphanumeric_extended_long,
    alphanumeric_extended_short,
    hex8_4_4_4_12,
    hex_pattern,
    numeric,
)


class TestNumeric:
    """Test numeric pattern generation."""

    def test_numeric_fixed_size(self):
        """Test numeric pattern with fixed size."""
        pattern = numeric("4")
        assert pattern == "[0-9]{4}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("1234")
        assert not regex.match("12a4")

    def test_numeric_range(self):
        """Test numeric pattern with size range."""
        pattern = numeric("4,8")
        assert pattern == "[0-9]{4,8}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("1234")
        assert regex.match("12345678")
        assert not regex.match("123")  # Too short


class TestHexPattern:
    """Test hexadecimal pattern generation."""

    def test_hex_fixed_size(self):
        """Test hex pattern with fixed size."""
        pattern = hex_pattern("8")
        assert pattern == "[a-f0-9]{8}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("abcd1234")
        assert regex.match("deadbeef")
        assert not regex.match("ABCD1234")  # Uppercase not included
        assert not regex.match("xyz12345")  # Invalid hex chars

    def test_hex_range(self):
        """Test hex pattern with size range."""
        pattern = hex_pattern("8,16")
        assert pattern == "[a-f0-9]{8,16}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("abcd1234")
        assert regex.match("0123456789abcdef")


class TestAlphanumeric:
    """Test alphanumeric pattern generation."""

    def test_alphanumeric_fixed_size(self):
        """Test alphanumeric pattern with fixed size."""
        pattern = alphanumeric("10")
        assert pattern == "[a-z0-9]{10}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("abc1234xyz")
        assert not regex.match("ABC1234XYZ")  # Uppercase not included
        assert not regex.match("abc_123xyz")  # Underscore not included

    def test_alphanumeric_range(self):
        """Test alphanumeric pattern with size range."""
        pattern = alphanumeric("10,20")
        assert pattern == "[a-z0-9]{10,20}"

        regex = re.compile(pattern)
        assert regex.match("abc1234xyz")
        assert regex.match("0123456789abcdefghij")


class TestAlphanumericExtendedShort:
    """Test alphanumeric extended short pattern generation."""

    def test_alphanumeric_extended_short(self):
        """Test alphanumeric extended short pattern."""
        pattern = alphanumeric_extended_short("10")
        assert pattern == "[a-z0-9_-]{10}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("abc_123-xy")
        assert regex.match("test-token")
        assert not regex.match("test=token")  # Equals not included


class TestAlphanumericExtended:
    """Test alphanumeric extended pattern generation."""

    def test_alphanumeric_extended(self):
        """Test alphanumeric extended pattern."""
        pattern = alphanumeric_extended("20")
        assert pattern == "[a-z0-9=_\\-]{20}"

        # Test it compiles
        regex = re.compile(pattern)
        # Need exactly 20 characters
        assert regex.match("abc_123-xy=test12345")  # 20 chars
        assert regex.match("token=value_test1234")  # 20 chars


class TestAlphanumericExtendedLong:
    """Test alphanumeric extended long pattern generation."""

    def test_alphanumeric_extended_long(self):
        """Test alphanumeric extended long pattern."""
        pattern = alphanumeric_extended_long("32")
        assert pattern == "[a-z0-9\\/=_\\+\\-]{32}"

        # Test it compiles
        regex = re.compile(pattern)
        # Need exactly 32 characters
        assert regex.match("abc123/xyz=test+value_token-id12")  # 32 chars
        # Should support base64-like characters
        assert regex.match("abcdefghijklmnop+qrstuvwxyz012/=")  # 32 chars


class TestHex8_4_4_4_12:
    """Test UUID pattern generation."""

    def test_hex8_4_4_4_12(self):
        """Test UUID format pattern."""
        pattern = hex8_4_4_4_12()
        assert pattern == "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

        # Test it compiles
        regex = re.compile(pattern)
        assert regex.match("12345678-1234-5678-1234-567890abcdef")
        assert regex.match("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert not regex.match("12345678-1234-5678-1234-567890ABCDEF")  # Uppercase
        assert not regex.match("12345678-1234-5678-1234")  # Too short
        assert not regex.match("12345678123456781234567890abcdef")  # No dashes


class TestPatternIntegration:
    """Test that patterns can be used in actual regex construction."""

    def test_compose_patterns(self):
        """Test that patterns can be composed into larger regexes."""
        # Example: AWS access key pattern
        # Format: AKIA + 16 alphanumeric characters
        pattern = f"AKIA{alphanumeric('16')}"
        assert pattern == "AKIA[a-z0-9]{16}"

        regex = re.compile(pattern)
        assert regex.match("AKIAabcdefghij123456")
        assert not regex.match("AKIAabcdefghij12345")  # Too short

    def test_uuid_in_context(self):
        """Test UUID pattern in a larger context."""
        # Example: Secret with UUID format
        pattern = f"secret_{hex8_4_4_4_12()}"

        regex = re.compile(pattern)
        assert regex.match("secret_12345678-1234-5678-1234-567890abcdef")
        assert not regex.match("secret_invalid-uuid-format")
