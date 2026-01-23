"""
Pattern generation utilities for building regex patterns.

These helper functions are used to construct common regex patterns used in
secret detection rules. They provide a consistent way to build patterns with
specific character classes and repetition counts.
"""


def numeric(size: str) -> str:
    """
    Generate a regex pattern matching numeric characters.

    Args:
        size: Repetition count (e.g., "4" or "4,8").

    Returns:
        Regex pattern string for numeric characters.

    Example:
        >>> numeric("4")
        '[0-9]{4}'
    """
    return f"[0-9]{{{size}}}"


def hex_pattern(size: str) -> str:
    """
    Generate a regex pattern matching hexadecimal characters (lowercase).

    Args:
        size: Repetition count (e.g., "8" or "8,16").

    Returns:
        Regex pattern string for hexadecimal characters.

    Example:
        >>> hex_pattern("8")
        '[a-f0-9]{8}'
    """
    return f"[a-f0-9]{{{size}}}"


def alphanumeric(size: str) -> str:
    """
    Generate a regex pattern matching lowercase alphanumeric characters.

    Args:
        size: Repetition count (e.g., "10" or "10,20").

    Returns:
        Regex pattern string for alphanumeric characters.

    Example:
        >>> alphanumeric("10")
        '[a-z0-9]{10}'
    """
    return f"[a-z0-9]{{{size}}}"


def alphanumeric_extended_short(size: str) -> str:
    """
    Generate a regex pattern for alphanumeric with underscore and hyphen.

    Args:
        size: Repetition count (e.g., "10" or "10,20").

    Returns:
        Regex pattern string for extended alphanumeric characters.

    Example:
        >>> alphanumeric_extended_short("10")
        '[a-z0-9_-]{10}'
    """
    return f"[a-z0-9_-]{{{size}}}"


def alphanumeric_extended(size: str) -> str:
    """
    Generate a regex pattern for alphanumeric with common separator characters.

    Includes: lowercase letters, digits, equals, underscore, hyphen.

    Args:
        size: Repetition count (e.g., "20" or "20,40").

    Returns:
        Regex pattern string for extended alphanumeric characters.

    Example:
        >>> alphanumeric_extended("20")
        '[a-z0-9=_\\-]{20}'
    """
    return f"[a-z0-9=_\\-]{{{size}}}"


def alphanumeric_extended_long(size: str) -> str:
    """
    Generate a regex pattern for alphanumeric with base64-like characters.

    Includes: lowercase letters, digits, forward slash, equals, plus, underscore, hyphen.

    Args:
        size: Repetition count (e.g., "32" or "32,64").

    Returns:
        Regex pattern string for extended alphanumeric characters.

    Example:
        >>> alphanumeric_extended_long("32")
        '[a-z0-9\\/=_\\+\\-]{32}'
    """
    return f"[a-z0-9\\/=_\\+\\-]{{{size}}}"


def hex8_4_4_4_12() -> str:
    """
    Generate a regex pattern matching UUID format (8-4-4-4-12 hex digits).

    Returns:
        Regex pattern string for UUID format.

    Example:
        >>> hex8_4_4_4_12()
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    """
    return "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
