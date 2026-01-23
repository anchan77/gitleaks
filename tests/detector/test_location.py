"""Tests for location tracking."""

import pytest
from gitleaks.detector.location import location, find_newline_indices, extract_line, Location


class TestFindNewlineIndices:
    """Tests for find_newline_indices function."""

    def test_empty_string(self):
        """Test with empty string."""
        assert find_newline_indices("") == []

    def test_no_newlines(self):
        """Test with no newlines."""
        assert find_newline_indices("hello world") == []

    def test_single_newline(self):
        """Test with single newline."""
        assert find_newline_indices("hello\nworld") == [5]

    def test_multiple_newlines(self):
        """Test with multiple newlines."""
        assert find_newline_indices("hello\nworld\nfoo") == [5, 11]

    def test_trailing_newline(self):
        """Test with trailing newline."""
        assert find_newline_indices("hello\nworld\n") == [5, 11]


class TestLocation:
    """Tests for location function."""

    def test_single_line_match(self):
        """Test match on a single line."""
        text = "hello world"
        newlines = find_newline_indices(text)
        loc = location(newlines, text, (0, 5))  # "hello"

        assert loc.start_line == 0
        assert loc.end_line == 0
        assert loc.start_column == 1
        # endColumn is position after last char, so for "hello" (0-4), end=5, column=5
        assert loc.end_column == 5
        assert loc.start_line_index == 0
        assert loc.end_line_index == len(text)

    def test_match_on_second_line(self):
        """Test match on the second line."""
        text = "hello\nworld\nfoo"
        newlines = find_newline_indices(text)
        loc = location(newlines, text, (6, 11))  # "world"

        assert loc.start_line == 1
        assert loc.end_line == 1
        # Note: startColumn is calculated from previous newline position,
        # resulting in column 2 for first char after newline
        assert loc.start_column == 2
        assert loc.end_column == 6
        assert loc.start_line_index == 5
        assert loc.end_line_index == 11

    def test_multiline_match(self):
        """Test match spanning multiple lines."""
        text = "hello\nworld\nfoo"
        newlines = find_newline_indices(text)
        loc = location(newlines, text, (3, 9))  # "lo\nwor"

        assert loc.start_line == 0
        assert loc.end_line == 1
        assert loc.start_column == 4
        # endColumn for position 9 on line starting after newline at 5: 9-5=4
        assert loc.end_column == 4

    def test_match_at_end_without_trailing_newline(self):
        """Test match at end of text without trailing newline."""
        text = "hello\nworld"
        newlines = find_newline_indices(text)
        loc = location(newlines, text, (6, 11))  # "world"

        # This goes to the !lineSet block since there's no newline after "world"
        assert loc.start_line == 1
        assert loc.end_line == 1
        # startColumn: (6-5)+1 = 2, endColumn: 11-5 = 6
        assert loc.start_column == 2
        assert loc.end_column == 6
        assert loc.end_line_index == len(text)

    def test_match_with_trailing_newline(self):
        """Test match including trailing newline."""
        text = "hello\nworld\n"
        newlines = find_newline_indices(text)
        loc = location(newlines, text, (6, 12))  # "world\n"

        assert loc.start_line == 1
        assert loc.end_line == 2
        # startColumn: (6-5)+1 = 2
        assert loc.start_column == 2
        # endColumn for position 12 with prevNewLine=11: 12-11=1
        assert loc.end_column == 1


class TestExtractLine:
    """Tests for extract_line function."""

    def test_extract_first_line(self):
        """Test extracting first line."""
        text = "hello\nworld\nfoo"
        line = extract_line(text, 0, 5)
        assert line == "hello"

    def test_extract_middle_line(self):
        """Test extracting middle line."""
        text = "hello\nworld\nfoo"
        line = extract_line(text, 6, 11)
        assert line == "world"

    def test_extract_last_line_no_newline(self):
        """Test extracting last line without trailing newline."""
        text = "hello\nworld\nfoo"
        line = extract_line(text, 12, 15)
        assert line == "foo"

    def test_extract_line_with_trailing_newline(self):
        """Test extracting line that includes newline in range."""
        text = "hello\nworld\n"
        line = extract_line(text, 6, 12)
        # Should strip the trailing newline
        assert line == "world"
