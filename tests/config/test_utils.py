"""Tests for configuration utilities."""

import regex

from gitleaks.config.utils import any_regex_match, join_regex_or, regex_matched


class TestRegexUtilities:
    """Tests for regex utility functions."""

    def test_regex_matched_with_match(self) -> None:
        """regex_matched should return True for matches."""
        pattern = regex.compile(r"\btest\b")
        assert regex_matched("this is a test", pattern)

    def test_regex_matched_without_match(self) -> None:
        """regex_matched should return False for non-matches."""
        pattern = regex.compile(r"\btest\b")
        assert not regex_matched("testing", pattern)

    def test_regex_matched_with_none_pattern(self) -> None:
        """regex_matched should return False for None pattern."""
        assert not regex_matched("test", None)

    def test_any_regex_match_with_match(self) -> None:
        """any_regex_match should return True if any pattern matches."""
        patterns = [
            regex.compile(r"foo"),
            regex.compile(r"bar"),
            regex.compile(r"baz"),
        ]
        assert any_regex_match("this has bar in it", patterns)

    def test_any_regex_match_without_match(self) -> None:
        """any_regex_match should return False if no patterns match."""
        patterns = [
            regex.compile(r"foo"),
            regex.compile(r"bar"),
        ]
        assert not any_regex_match("this has nothing", patterns)

    def test_any_regex_match_empty_list(self) -> None:
        """any_regex_match should return False for empty pattern list."""
        assert not any_regex_match("test", [])

    def test_join_regex_or_combines_patterns(self) -> None:
        """join_regex_or should create a combined OR pattern."""
        patterns = [
            regex.compile(r"foo"),
            regex.compile(r"bar"),
            regex.compile(r"baz"),
        ]
        combined = join_regex_or(patterns)

        assert combined.search("this has foo")
        assert combined.search("this has bar")
        assert combined.search("this has baz")
        assert not combined.search("no match")

    def test_join_regex_or_empty_list_raises(self) -> None:
        """join_regex_or should raise error for empty list."""
        import pytest

        with pytest.raises(ValueError, match="empty list"):
            join_regex_or([])
