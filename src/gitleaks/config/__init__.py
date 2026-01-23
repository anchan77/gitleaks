"""
Configuration management for gitleaks.

This package contains Pydantic models for TOML configuration,
config loaders, and validation logic.
"""

from .loader import load_config, load_default_config
from .models import Allowlist, AllowlistMatchCondition, Config, Extend, Required, Rule
from .utils import any_regex_match, join_regex_or, regex_matched

__all__ = [
    # Main loader function
    "load_config",
    "load_default_config",
    # Models
    "Config",
    "Rule",
    "Allowlist",
    "AllowlistMatchCondition",
    "Extend",
    "Required",
    # Utilities
    "any_regex_match",
    "regex_matched",
    "join_regex_or",
]
