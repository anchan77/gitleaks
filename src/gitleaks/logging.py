"""
Structured logging configuration for gitleaks.

This module configures structlog to provide JSON-formatted logging
with timestamps and contextual fields, mirroring the behavior of
zerolog from the Go implementation.
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def add_timestamp(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add ISO 8601 timestamp to log events."""
    event_dict["timestamp"] = structlog.processors.TimeStamper(fmt="iso")(
        logger, method_name, event_dict
    )["timestamp"]
    return event_dict


def configure_logging(log_level: str = "INFO", use_json: bool = True) -> None:
    """
    Configure the logging system.

    Args:
        log_level: Logging level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
        use_json: If True, output JSON format; otherwise use console format
    """
    # Map gitleaks log levels to Python logging levels
    level_map = {
        "TRACE": logging.DEBUG,  # Python doesn't have TRACE, use DEBUG
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "FATAL": logging.CRITICAL,
        "CRITICAL": logging.CRITICAL,
    }

    python_level = level_map.get(log_level.upper(), logging.INFO)

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=python_level,
        force=True,  # Allow reconfiguration
    )

    # Also set level on root logger to ensure it propagates
    logging.root.setLevel(python_level)

    # Define the processor chain
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
    ]

    if use_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,  # Allow reconfiguration
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (defaults to 'gitleaks')

    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name or "gitleaks")


# Initialize with default configuration
configure_logging()

# Export a default logger instance
logger = get_logger()


# Provide convenience functions matching the Go API
def trace() -> structlog.stdlib.BoundLogger:
    """Get logger for trace level (mapped to debug in Python)."""
    return logger


def debug() -> structlog.stdlib.BoundLogger:
    """Get logger for debug level."""
    return logger


def info() -> structlog.stdlib.BoundLogger:
    """Get logger for info level."""
    return logger


def warn() -> structlog.stdlib.BoundLogger:
    """Get logger for warning level."""
    return logger


def error() -> structlog.stdlib.BoundLogger:
    """Get logger for error level."""
    return logger


def fatal() -> structlog.stdlib.BoundLogger:
    """Get logger for fatal/critical level."""
    return logger


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
