"""
Configuration validation utilities.

This module provides functions to validate rules by testing them against
known true positives and false positives.

Note: Full validation with detector engine requires the detector module to be implemented.
Basic pattern compilation validation is available now.
"""

from typing import Optional, TYPE_CHECKING

import structlog

from .models import Config, Rule

if TYPE_CHECKING:
    from ..sources.fragment import Fragment

logger = structlog.get_logger(__name__)


def validate_rule(
    rule: Rule,
    true_positives: list[str],
    false_positives: list[str],
    config: Optional[Config] = None,
) -> Rule:
    """
    Validate a rule against known true and false positives.

    Note: Full detector-based validation will be available once the detector engine
    is implemented. For now, this validates that the regex pattern compiles.

    Args:
        rule: The rule to validate.
        true_positives: List of strings that should be detected.
        false_positives: List of strings that should NOT be detected.
        config: Optional config for creating detector (uses minimal config if None).

    Returns:
        The validated rule.

    Raises:
        ValueError: If validation fails.
        NotImplementedError: If full detector validation is requested.
    """
    # For now, just ensure the patterns compiled during model validation
    if rule.regex and rule._regex_compiled is None:
        raise ValueError(
            f"Rule {rule.id}: Regex pattern did not compile during validation"
        )

    if rule.path and rule._path_compiled is None:
        raise ValueError(
            f"Rule {rule.id}: Path pattern did not compile during validation"
        )

    # TODO: Once detector engine is implemented, add full validation:
    # - Test true_positives are detected
    # - Test false_positives are not detected
    logger.debug("Rule basic validation passed", rule_id=rule.id)
    return rule


def validate_rule_with_paths(
    rule: Rule,
    true_positives: dict[str, str],
    false_positives: dict[str, str],
    config: Optional[Config] = None,
) -> Rule:
    """
    Validate a rule against known true and false positives with file paths.

    Note: Full detector-based validation will be available once the detector engine
    is implemented. For now, this validates that patterns compile.

    Args:
        rule: The rule to validate.
        true_positives: Dict mapping file paths to content that should be detected.
        false_positives: Dict mapping file paths to content that should NOT be detected.
        config: Optional config for creating detector (uses minimal config if None).

    Returns:
        The validated rule.

    Raises:
        ValueError: If validation fails.
        NotImplementedError: If full detector validation is requested.
    """
    # For now, just ensure the patterns compiled during model validation
    if rule.regex and rule._regex_compiled is None:
        raise ValueError(
            f"Rule {rule.id}: Regex pattern did not compile during validation"
        )

    if rule.path and rule._path_compiled is None:
        raise ValueError(
            f"Rule {rule.id}: Path pattern did not compile during validation"
        )

    # TODO: Once detector engine is implemented, add full validation:
    # - Test true_positives with paths are detected
    # - Test false_positives with paths are not detected
    logger.debug("Rule basic validation with paths passed", rule_id=rule.id)
    return rule


def validate_config(config: Config) -> bool:
    """
    Validate a complete configuration.

    This ensures that all rules have valid regex patterns and can be compiled.

    Args:
        config: The configuration to validate.

    Returns:
        True if the config is valid.

    Raises:
        ValueError: If the config is invalid.
    """
    for rule in config.rules_map.values():
        # Ensure regex compiled if present
        if rule.regex and rule._regex_compiled is None:
            raise ValueError(f"Rule {rule.id}: Regex pattern did not compile")

        # Ensure path pattern compiled if present
        if rule.path and rule._path_compiled is None:
            raise ValueError(f"Rule {rule.id}: Path pattern did not compile")

        # Validate that rule has at least one detection mechanism
        if not rule.regex and not rule.path:
            raise ValueError(
                f"Rule {rule.id}: Must have either regex or path pattern"
            )

    logger.info("Config validation passed", rule_count=len(config.rules_map))
    return True
