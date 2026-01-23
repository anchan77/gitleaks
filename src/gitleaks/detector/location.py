"""
Location tracking for finding positions within text.

This module provides functions to calculate line and column numbers
for regex matches within a text fragment.
"""

from dataclasses import dataclass
import re
from typing import List, Tuple


@dataclass
class Location:
    """
    Represents the location of a match within a text fragment.

    Attributes:
        start_line: 0-indexed line number where match starts
        end_line: 0-indexed line number where match ends
        start_column: 1-indexed column number where match starts
        end_column: 1-indexed column number where match ends
        start_line_index: Byte offset to start of start_line
        end_line_index: Byte offset to end of end_line
    """
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    start_line_index: int
    end_line_index: int


def location(newline_indices: List[int], raw: str, match_index: Tuple[int, int]) -> Location:
    """
    Calculate the location of a match within a text fragment.

    This function determines line and column numbers for a regex match,
    handling edge cases like text without newlines and matches on the last line.

    Note: This implementation matches the Go version's behavior where:
    - start_column is 1-indexed (first column is 1)
    - end_column is also 1-indexed but represents position AFTER last char

    Args:
        newline_indices: List of byte positions of all \\n characters in raw
        raw: The original text content
        match_index: Tuple of (start, end) byte positions of the match

    Returns:
        Location object with line/column information

    Examples:
        >>> text = "hello\\nworld\\nfoo"
        >>> newlines = [5, 11]  # Positions of \\n
        >>> location(newlines, text, (6, 11))  # "world"
        Location(start_line=1, end_line=1, start_column=1, end_column=5, ...)
    """
    start, end = match_index

    # Initialize location
    loc = Location(
        start_line=0,
        end_line=0,
        start_column=1,
        end_column=1,
        start_line_index=0,
        end_line_index=len(raw)
    )

    # Handle empty text or no newlines - create virtual newline at end
    if not newline_indices:
        newline_indices = [len(raw)]

    # Track the start position of the current line
    # For line 0, this is 0. For subsequent lines, it's the position
    # immediately after the previous newline character.
    # In Go, newlineIndices from FindAllStringIndex contains pairs [start, end]
    # where start is the newline position and end is start+1.
    # We simulate this by tracking after each newline.
    prev_newline = 0
    line_set = False

    for line_num, newline_byte_index in enumerate(newline_indices):
        # Check if we've found the start line
        # Condition: prevNewLine <= start < newlineByteIndex
        if prev_newline <= start and start < newline_byte_index:
            line_set = True
            loc.start_line = line_num
            loc.end_line = line_num
            loc.start_column = (start - prev_newline) + 1  # 1-indexed
            loc.start_line_index = prev_newline
            loc.end_line_index = newline_byte_index

        # Check if we've found the end line
        # Condition: prevNewLine < end <= newlineByteIndex
        if prev_newline < end and end <= newline_byte_index:
            loc.end_line = line_num
            # Go code: location.endColumn = (end - prevNewLine)
            # Note: NO +1 here! endColumn is the position of the end marker
            loc.end_column = end - prev_newline
            loc.end_line_index = newline_byte_index

        # Move prev_newline to the current newline position
        # In the Go code: prevNewLine = pair[0] where pair is from FindAllStringIndex
        # For a newline at position N, FindAllStringIndex returns [N, N+1]
        # So pair[0] = N (the newline position itself)
        prev_newline = newline_byte_index

    # Edge case: match is on the last line without a trailing newline
    # OR the end position is beyond the last newline
    if not line_set:
        loc.start_column = (start - prev_newline) + 1  # 1-indexed
        loc.end_column = end - prev_newline  # NO +1
        loc.start_line = len(newline_indices)
        loc.end_line = len(newline_indices)

        # Search for end of line
        i = 0
        while end + i < len(raw):
            if raw[end + i] in ('\n', '\r'):
                break
            i += 1
        loc.end_line_index = end + i
    elif end > prev_newline:
        # End position is beyond the last processed newline
        # This means it's on the line after the last newline
        loc.end_line = len(newline_indices)
        loc.end_column = end - prev_newline

    return loc


def find_newline_indices(text: str) -> List[int]:
    """
    Find all newline character positions in text.

    Args:
        text: Text to search for newlines

    Returns:
        List of byte positions where \\n characters occur

    Examples:
        >>> find_newline_indices("hello\\nworld\\n")
        [5, 11]
        >>> find_newline_indices("no newlines")
        []
    """
    return [match.start() for match in re.finditer(r'\n', text)]


def extract_line(raw: str, start_line_index: int, end_line_index: int) -> str:
    """
    Extract a line from text using byte indices.

    Args:
        raw: The original text
        start_line_index: Byte offset to start of line
        end_line_index: Byte offset to end of line (inclusive of newline if present)

    Returns:
        The extracted line, with trailing newline stripped
    """
    line = raw[start_line_index:end_line_index]
    # Strip trailing newline if present
    if line.endswith('\n'):
        line = line[:-1]
    return line
