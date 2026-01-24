"""
Structured logging configuration using structlog.

This module provides a centralized logging setup that mirrors the behavior of
the Go implementation's zerolog configuration, with JSON output, ISO 8601 timestamps,
and multiple log levels.
"""

import logging
import sys
from typing import Any

import structlog
from structlog.typing import EventDict, WrappedLogger


def add_app_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Add application-specific context to log records.

    Args:
        logger: The wrapped logger instance
        method_name: The name of the method being called
        event_dict: The event dictionary to modify

    Returns:
        Modified event dictionary with additional context
    """
    event_dict["logger"] = logger.name
    return event_dict


def configure_logging(
    level: str = "INFO",
    use_json: bool = True,
    use_colors: bool = False,
) -> None:
    """
    Configure structlog for the application.

    Args:
        level: Log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
        use_json: Whether to use JSON output format
        use_colors: Whether to use colored output (for console)
    """
    # Map custom log levels to standard Python logging levels
    level_mapping = {
        "TRACE": logging.DEBUG,  # Python doesn't have TRACE, map to DEBUG
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "FATAL": logging.CRITICAL,
        "CRITICAL": logging.CRITICAL,
    }

    log_level = level_mapping.get(level.upper(), logging.INFO)

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )

    # Shared processors for both JSON and console output
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_app_context,
    ]

    if use_json:
        # JSON output for production/CI
        structlog.configure(
            processors=shared_processors
            + [
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        # Console output for development
        structlog.configure(
            processors=shared_processors
            + [
                structlog.dev.ConsoleRenderer(colors=use_colors),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )


# Initialize with default configuration
configure_logging()


def get_logger(name: str = "gitleaks") -> Any:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (defaults to 'gitleaks')

    Returns:
        A structlog logger instance
    """
    return structlog.get_logger(name)


# Module-level logger instance for convenience
logger = get_logger()


# Convenience functions that mirror the Go implementation
def trace() -> Any:
    """Get logger at TRACE level (mapped to DEBUG in Python)."""
    return logger.debug


def debug() -> Any:
    """Get logger at DEBUG level."""
    return logger.debug


def info() -> Any:
    """Get logger at INFO level."""
    return logger.info


def warn() -> Any:
    """Get logger at WARN level."""
    return logger.warning


def error() -> Any:
    """Get logger at ERROR level."""
    return logger.error


def fatal() -> Any:
    """Get logger at FATAL level (mapped to CRITICAL in Python)."""
    return logger.critical


__all__ = [
    "configure_logging",
    "get_logger",
    "logger",
    "trace",
    "debug",
    "info",
    "warn",
    "error",
    "fatal",
]
