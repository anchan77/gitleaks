"""
Structured logging configuration for gitleaks using structlog.

This module provides JSON-formatted logging with ISO 8601 timestamps,
mirroring the zerolog behavior from the Go implementation.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.typing import EventDict, WrappedLogger

# Custom log levels to match Go's zerolog
TRACE = 5  # Below DEBUG (10)
logging.addLevelName(TRACE, "TRACE")

# Log level mapping
LOG_LEVELS = {
    "trace": TRACE,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.CRITICAL,
    "critical": logging.CRITICAL,
}


def _add_log_level(
    _logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add the log level to the event dict."""
    level_name = method_name
    if level_name == "warn":
        level_name = "warning"
    event_dict["level"] = level_name.upper()
    return event_dict


def _rename_event_key(
    _logger: WrappedLogger, _method_name: str, event_dict: EventDict
) -> EventDict:
    """Rename 'event' to 'message' to match zerolog semantics."""
    if "event" in event_dict:
        event_dict["message"] = event_dict.pop("event")
    return event_dict


def _handle_trace_level(
    _logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Handle trace level indicator."""
    if event_dict.pop("_trace", False):
        event_dict["level"] = "TRACE"
    return event_dict


def configure_logging(
    level: str = "info",
    json_output: bool = True,
) -> None:
    """
    Configure structlog for the application.

    Args:
        level: Log level name (trace, debug, info, warn, error, fatal)
        json_output: If True, output JSON; otherwise use console format
    """
    log_level = LOG_LEVELS.get(level.lower(), logging.INFO)

    # Reset basic config if already configured
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    # Configure the standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
        force=True,
    )

    # Common processors
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        _add_log_level,
        _handle_trace_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        # JSON output for production
        processors: list[structlog.typing.Processor] = [
            *shared_processors,
            _rename_event_key,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console output for development
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,  # Allow reconfiguration
    )


def get_logger(name: str | None = None, **initial_values: Any) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.

    Args:
        name: Optional logger name
        **initial_values: Initial context values to bind to the logger

    Returns:
        A configured structlog BoundLogger instance
    """
    log = structlog.get_logger(name)
    if initial_values:
        log = log.bind(**initial_values)
    return log


def _get_logger() -> structlog.stdlib.BoundLogger:
    """Get the module-level logger (lazily)."""
    return structlog.get_logger("gitleaks")


# Convenience functions mirroring zerolog API
def trace(msg: str, **kwargs: Any) -> None:
    """Log a trace-level message."""
    # Use debug level but mark as trace for processor to handle
    _get_logger().debug(msg, _trace=True, **kwargs)


def debug(msg: str, **kwargs: Any) -> None:
    """Log a debug-level message."""
    _get_logger().debug(msg, **kwargs)


def info(msg: str, **kwargs: Any) -> None:
    """Log an info-level message."""
    _get_logger().info(msg, **kwargs)


def warn(msg: str, **kwargs: Any) -> None:
    """Log a warning-level message."""
    _get_logger().warning(msg, **kwargs)


def error(msg: str, **kwargs: Any) -> None:
    """Log an error-level message."""
    _get_logger().error(msg, **kwargs)


def fatal(msg: str, **kwargs: Any) -> None:
    """Log a fatal-level message and exit."""
    _get_logger().critical(msg, **kwargs)
    sys.exit(1)


# Module-level logger for direct access
# Usage: from gitleaks.logging import logger; logger.info("message")
logger: structlog.stdlib.BoundLogger


def __getattr__(name: str) -> Any:
    """Lazy attribute access for module-level logger."""
    if name == "logger":
        return _get_logger()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Initialize with default configuration
configure_logging()
