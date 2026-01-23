"""
Utility functions for configuration handling.

This module provides helper functions for regex operations and other
config-related utilities.
"""

from typing import Optional, TYPE_CHECKING

import regex

if TYPE_CHECKING:
    RegexPattern = regex.Pattern[str]
else:
    RegexPattern = regex.Pattern


def any_regex_match(text: str, patterns: list[RegexPattern]) -> bool:
    """
    Check if text matches any of the given regex patterns.

    Args:
        text: The text to match against.
        patterns: List of compiled regex patterns.

    Returns:
        True if any pattern matches, False otherwise.
    """
    for pattern in patterns:
        if regex_matched(text, pattern):
            return True
    return False


def regex_matched(text: str, pattern: Optional[RegexPattern]) -> bool:
    """
    Check if text matches a regex pattern.

    Args:
        text: The text to match against.
        pattern: Compiled regex pattern (can be None).

    Returns:
        True if pattern matches, False otherwise.
    """
    if pattern is None:
        return False
    return pattern.search(text) is not None


def join_regex_or(patterns: list[RegexPattern]) -> RegexPattern:
    """
    Combine multiple regex patterns into a single pattern using OR.

    Args:
        patterns: List of compiled regex patterns.

    Returns:
        A new compiled pattern that matches any of the input patterns.
    """
    if not patterns:
        raise ValueError("Cannot join empty list of patterns")

    # Combine patterns with OR operator
    combined = "(?:" + "|".join(p.pattern for p in patterns) + ")"
    return regex.compile(combined)
