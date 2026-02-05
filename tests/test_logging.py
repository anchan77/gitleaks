"""Tests for the logging module."""

import json
import logging
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from gitleaks.logging import (
    LOG_LEVELS,
    TRACE,
    configure_logging,
    debug,
    error,
    get_logger,
    info,
    trace,
    warn,
)


class TestLogLevels:
    """Test log level configuration."""

    def test_trace_level_exists(self) -> None:
        """Trace level should be defined below DEBUG."""
        assert TRACE < logging.DEBUG
        assert TRACE == 5

    def test_log_levels_mapping(self) -> None:
        """Log levels mapping should contain all expected levels."""
        assert "trace" in LOG_LEVELS
        assert "debug" in LOG_LEVELS
        assert "info" in LOG_LEVELS
        assert "warn" in LOG_LEVELS
        assert "warning" in LOG_LEVELS
        assert "error" in LOG_LEVELS
        assert "fatal" in LOG_LEVELS
        assert "critical" in LOG_LEVELS

    def test_log_levels_values(self) -> None:
        """Log level values should match Python's logging module."""
        assert LOG_LEVELS["debug"] == logging.DEBUG
        assert LOG_LEVELS["info"] == logging.INFO
        assert LOG_LEVELS["warn"] == logging.WARNING
        assert LOG_LEVELS["warning"] == logging.WARNING
        assert LOG_LEVELS["error"] == logging.ERROR
        assert LOG_LEVELS["fatal"] == logging.CRITICAL


class TestConfigureLogging:
    """Test logging configuration."""

    def test_configure_logging_default(self) -> None:
        """Default configuration should set INFO level with JSON output."""
        configure_logging()
        # Should not raise any exceptions
        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_configure_logging_debug_level(self) -> None:
        """Configuration with debug level should work."""
        configure_logging(level="debug")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_configure_logging_trace_level(self) -> None:
        """Configuration with trace level should work."""
        configure_logging(level="trace")
        root_logger = logging.getLogger()
        assert root_logger.level == TRACE


class TestGetLogger:
    """Test logger creation."""

    def test_get_logger_no_name(self) -> None:
        """Get logger without name should work."""
        configure_logging()
        log = get_logger()
        assert log is not None

    def test_get_logger_with_name(self) -> None:
        """Get logger with name should work."""
        configure_logging()
        log = get_logger("test_logger")
        assert log is not None

    def test_get_logger_with_initial_values(self) -> None:
        """Get logger with initial values should bind them."""
        configure_logging()
        log = get_logger("test_logger", component="test")
        assert log is not None


class TestConvenienceFunctions:
    """Test convenience logging functions."""

    def test_info_function(self) -> None:
        """Info function should not raise."""
        configure_logging(level="info")
        # Should not raise
        info("Test info message")

    def test_debug_function(self) -> None:
        """Debug function should not raise."""
        configure_logging(level="debug")
        # Should not raise
        debug("Test debug message")

    def test_warn_function(self) -> None:
        """Warn function should not raise."""
        configure_logging(level="info")
        # Should not raise
        warn("Test warning message")

    def test_error_function(self) -> None:
        """Error function should not raise."""
        configure_logging(level="info")
        # Should not raise
        error("Test error message")

    def test_trace_function(self) -> None:
        """Trace function should not raise."""
        configure_logging(level="debug")
        # Should not raise
        trace("Test trace message")

    def test_info_with_kwargs(self) -> None:
        """Info function should accept kwargs."""
        configure_logging(level="info")
        # Should not raise
        info("Test message", key="value", number=42)
