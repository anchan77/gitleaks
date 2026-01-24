"""Tests for the logging module."""

import pytest
from gitleaks.logging import configure_logging, get_logger


def test_get_logger():
    """Test that get_logger returns a valid logger instance."""
    logger = get_logger("test")
    assert logger is not None


def test_configure_logging_with_json():
    """Test that logging can be configured with JSON output."""
    configure_logging(level="DEBUG", use_json=True)
    logger = get_logger("test")
    assert logger is not None


def test_configure_logging_with_console():
    """Test that logging can be configured with console output."""
    configure_logging(level="INFO", use_json=False, use_colors=False)
    logger = get_logger("test")
    assert logger is not None


def test_logger_levels():
    """Test that all log levels are available."""
    from gitleaks.logging import debug, error, fatal, info, trace, warn

    # Just verify the functions exist and are callable
    assert callable(trace())
    assert callable(debug())
    assert callable(info())
    assert callable(warn())
    assert callable(error())
    assert callable(fatal())
