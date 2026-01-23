"""
Configuration file loading and extension logic.

This module handles locating, loading, and validating .gitleaks.toml configuration
files, including support for config extension and the default embedded config.
"""

import os
import sys
from pathlib import Path
from typing import Optional

# Python 3.11+ has tomllib in stdlib, 3.10 needs tomli package
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        raise ImportError(
            "tomli is required for Python 3.10. Install with: pip install tomli"
        )

import structlog

from .models import Allowlist, Config, Extend, Required, Rule

logger = structlog.get_logger(__name__)

# Maximum depth for config extension to prevent circular references
MAX_EXTEND_DEPTH = 2

# Default configuration content (will be populated by copying gitleaks.toml)
DEFAULT_CONFIG_TOML: Optional[str] = None


def load_default_config() -> str:
    """
    Load the default gitleaks configuration.

    Returns:
        The default config as a TOML string.

    Raises:
        FileNotFoundError: If the default config file cannot be found.
    """
    global DEFAULT_CONFIG_TOML

    if DEFAULT_CONFIG_TOML is not None:
        return DEFAULT_CONFIG_TOML

    # Try to load from package data
    config_dir = Path(__file__).parent
    default_config_path = config_dir / "gitleaks.toml"

    if not default_config_path.exists():
        raise FileNotFoundError(
            f"Default config not found at {default_config_path}. "
            "This should be bundled with the package."
        )

    with open(default_config_path, "r", encoding="utf-8") as f:
        DEFAULT_CONFIG_TOML = f.read()

    return DEFAULT_CONFIG_TOML


def load_config(
    config_path: Optional[str] = None,
    source_path: Optional[str] = None,
    config_content: Optional[str] = None,
) -> Config:
    """
    Load and parse a gitleaks configuration file.

    Configuration is resolved in the following order:
    1. config_content (TOML string from env var or inline)
    2. config_path (explicit path via --config flag)
    3. GITLEAKS_CONFIG env var
    4. GITLEAKS_CONFIG_TOML env var (content)
    5. .gitleaks.toml in source_path
    6. Default embedded config

    Args:
        config_path: Explicit path to config file.
        source_path: Path to source directory to scan (for finding .gitleaks.toml).
        config_content: Configuration content as TOML string.

    Returns:
        Parsed and validated Config object.

    Raises:
        ValueError: If config is invalid.
        FileNotFoundError: If specified config file doesn't exist.
    """
    toml_content: Optional[str] = None
    resolved_path: Optional[str] = None

    # 1. Check for inline content
    if config_content:
        toml_content = config_content
        logger.debug("Using inline config content")

    # 2. Check for explicit config path
    elif config_path:
        resolved_path = config_path
        logger.debug("Using config path", path=config_path)

    # 3. Check GITLEAKS_CONFIG env var
    elif "GITLEAKS_CONFIG" in os.environ:
        resolved_path = os.environ["GITLEAKS_CONFIG"]
        logger.debug("Using config from GITLEAKS_CONFIG env", path=resolved_path)

    # 4. Check GITLEAKS_CONFIG_TOML env var
    elif "GITLEAKS_CONFIG_TOML" in os.environ:
        toml_content = os.environ["GITLEAKS_CONFIG_TOML"]
        logger.debug("Using config content from GITLEAKS_CONFIG_TOML env")

    # 5. Look for .gitleaks.toml in source path
    elif source_path:
        candidate = Path(source_path) / ".gitleaks.toml"
        if candidate.exists():
            resolved_path = str(candidate)
            logger.debug("Found config in source path", path=resolved_path)

    # Load file if we have a path
    if resolved_path and not toml_content:
        path_obj = Path(resolved_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Config file not found: {resolved_path}")
        with open(path_obj, "r", encoding="utf-8") as f:
            toml_content = f.read()

    # 6. Fall back to default config if nothing else found
    if not toml_content:
        logger.debug("Using default config")
        toml_content = load_default_config()
        resolved_path = "<default>"

    # Parse TOML
    try:
        toml_data = tomllib.loads(toml_content)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Invalid TOML in config: {e}")

    # Translate to Config object with extension support
    config = _translate_config(toml_data, resolved_path or "<inline>", extend_depth=0)

    return config


def _translate_config(
    toml_data: dict, config_path: str, extend_depth: int = 0
) -> Config:
    """
    Translate raw TOML data into a Config object.

    This function handles parsing the TOML structure, validating rules,
    and processing config extension.

    Args:
        toml_data: Parsed TOML data.
        config_path: Path to config file (for error messages).
        extend_depth: Current extension depth (for preventing infinite loops).

    Returns:
        Validated Config object.

    Raises:
        ValueError: If config is invalid or extension depth exceeded.
    """
    if extend_depth >= MAX_EXTEND_DEPTH:
        raise ValueError(
            f"Config extension depth exceeded maximum of {MAX_EXTEND_DEPTH}. "
            "Check for circular config references."
        )

    # Parse basic fields
    title = toml_data.get("title", "")
    description = toml_data.get("description", "")
    min_version = toml_data.get("minVersion", "")

    # Parse extend configuration
    extend_data = toml_data.get("extend", {})
    extend = Extend(
        path=extend_data.get("path", ""),
        url=extend_data.get("url", ""),
        use_default=extend_data.get("useDefault", False),
        disabled_rules=extend_data.get("disabledRules", []),
    )

    # Validate extend configuration
    if extend.path and extend.use_default:
        raise ValueError(
            "Config error: cannot set both extend.path and extend.useDefault"
        )

    # Parse rules
    rules: list[Rule] = []
    rule_allowlists: dict[str, list[Allowlist]] = {}

    for rule_data in toml_data.get("rules", []):
        # Parse rule allowlists
        rule_allowlist_objs: list[Allowlist] = []

        # Handle deprecated single allowlist (check both case variations)
        rule_allowlist_key = None
        if "allowList" in rule_data:
            rule_allowlist_key = "allowList"
        elif "allowlist" in rule_data:
            rule_allowlist_key = "allowlist"

        if rule_allowlist_key:
            if "allowlists" in rule_data:
                raise ValueError(
                    f"Rule {rule_data.get('id', '<unknown>')}: "
                    "[rules.allowlist] is deprecated and cannot be used alongside [[rules.allowlists]]"
                )
            rule_allowlist_objs.append(_parse_allowlist(rule_data[rule_allowlist_key]))

        # Parse allowlists array
        for allowlist_data in rule_data.get("allowlists", []):
            rule_allowlist_objs.append(_parse_allowlist(allowlist_data))

        # Parse required rules
        required_rules: list[Required] = []
        for req_data in rule_data.get("required", []):
            required_rules.append(
                Required(
                    id=req_data.get("id", ""),
                    within_lines=req_data.get("withinLines"),
                    within_columns=req_data.get("withinColumns"),
                )
            )

        # Create rule object
        rule = Rule(
            id=rule_data.get("id", ""),
            description=rule_data.get("description", ""),
            regex=rule_data.get("regex", ""),
            path=rule_data.get("path", ""),
            secret_group=rule_data.get("secretGroup", 0),
            entropy=rule_data.get("entropy", 0.0),
            keywords=rule_data.get("keywords", []),
            tags=rule_data.get("tags", []),
            allowlists=rule_allowlist_objs,
            required=required_rules,
            skip_report=rule_data.get("skipReport", False),
        )

        rules.append(rule)

    # Parse global allowlists
    global_allowlists: list[Allowlist] = []

    # Handle deprecated single allowlist (check both case variations)
    allowlist_key = None
    if "allowList" in toml_data:
        allowlist_key = "allowList"
    elif "allowlist" in toml_data:
        allowlist_key = "allowlist"

    if allowlist_key:
        if "allowlists" in toml_data:
            raise ValueError(
                "[allowlist] is deprecated and cannot be used alongside [[allowlists]]"
            )
        global_allowlists.append(_parse_allowlist(toml_data[allowlist_key]))

    # Parse allowlists array
    for allowlist_data in toml_data.get("allowlists", []):
        allowlist = _parse_allowlist(allowlist_data)

        # Check if this is a targeted allowlist
        target_rules = allowlist_data.get("targetRules", [])
        if target_rules:
            # Store for later attachment to specific rules
            for rule_id in target_rules:
                if rule_id not in rule_allowlists:
                    rule_allowlists[rule_id] = []
                rule_allowlists[rule_id].append(allowlist)
        else:
            # Global allowlist
            global_allowlists.append(allowlist)

    # Create initial config
    config = Config(
        title=title,
        description=description,
        extend=extend,
        rules=rules,
        allowlists=global_allowlists,
        min_version=min_version,
        path=config_path,
    )

    # Validate minimum version
    _validate_min_version(config.min_version, config_path)

    # Handle config extension (at any depth)
    if extend.use_default:
        logger.debug("Extending config with default config")
        default_toml = load_default_config()
        default_data = tomllib.loads(default_toml)
        base_config = _translate_config(default_data, "<default>", extend_depth + 1)
        config = _extend_config(config, base_config)
    elif extend.path:
        logger.debug("Extending config", path=extend.path)
        # Resolve extend path relative to current config's directory
        if config_path and config_path not in ("<default>", "<inline>"):
            base_dir = Path(config_path).parent
            extend_path = base_dir / extend.path
        else:
            extend_path = Path(extend.path)

        if not extend_path.exists():
            raise FileNotFoundError(f"Extended config not found: {extend.path}")
        with open(extend_path, "r", encoding="utf-8") as f:
            extend_toml = f.read()
        extend_data = tomllib.loads(extend_toml)
        base_config = _translate_config(
            extend_data, str(extend_path), extend_depth + 1
        )
        config = _extend_config(config, base_config)

    # Attach targeted allowlists to rules (only at root level)
    if extend_depth == 0:
        for rule_id, allowlists in rule_allowlists.items():
            if rule_id not in config.rules_map:
                raise ValueError(
                    f"[[allowlists]] target rule ID '{rule_id}' does not exist"
                )
            rule = config.rules_map[rule_id]
            rule.allowlists.extend(allowlists)

        # Validate all required rule references exist
        for rule in config.rules_map.values():
            for req in rule.required:
                if req.id not in config.rules_map:
                    raise ValueError(
                        f"{rule.id}: [[rules.required]] rule ID '{req.id}' does not exist"
                    )

        # Final validation: ensure all rules have regex or path
        for rule in config.rules_map.values():
            if not rule.regex and not rule.path:
                raise ValueError(
                    f"{rule.id}: both |regex| and |path| are empty, this rule will have no effect"
                )

    return config


def _parse_allowlist(allowlist_data: dict) -> Allowlist:
    """
    Parse an allowlist from TOML data.

    Args:
        allowlist_data: Raw allowlist data from TOML.

    Returns:
        Validated Allowlist object.
    """
    # Handle case variations for camelCase fields
    stop_words = allowlist_data.get("stopWords") or allowlist_data.get("stopwords", [])
    regex_target = allowlist_data.get("regexTarget") or allowlist_data.get("regextarget", "")
    target_rules = allowlist_data.get("targetRules") or allowlist_data.get("targetrules", [])

    return Allowlist(
        description=allowlist_data.get("description", ""),
        condition=allowlist_data.get("condition", ""),
        commits=allowlist_data.get("commits", []),
        paths=allowlist_data.get("paths", []),
        regex_target=regex_target,
        regexes=allowlist_data.get("regexes", []),
        stop_words=stop_words,
        target_rules=target_rules,
    )


def _extend_config(current: Config, base: Config) -> Config:
    """
    Extend current config with rules and allowlists from base config.

    This merges rules from the base config into the current config,
    respecting disabled rules and allowing rule overrides.

    Args:
        current: The current config (child).
        base: The base config to extend from (parent).

    Returns:
        The merged config.
    """
    # Get config name for helpful log messages
    config_name = current.extend.path if current.extend.path else "default"

    # Build set of disabled rule IDs
    disabled_rule_ids = set(current.extend.disabled_rules)

    # Warn about disabled rules that don't exist
    for rule_id in disabled_rule_ids:
        if rule_id not in base.rules_map:
            logger.warning(
                "Disabled rule doesn't exist in extended config",
                rule_id=rule_id,
                config=config_name,
            )

    # Merge rules from base config
    for rule_id, base_rule in base.rules_map.items():
        # Skip disabled rules
        if rule_id in disabled_rule_ids:
            logger.debug(
                "Ignoring rule from extended config", rule_id=rule_id, config=config_name
            )
            continue

        if rule_id not in current.rules_map:
            # Rule doesn't exist in current config, add it
            current.rules_map[rule_id] = base_rule
            current.ordered_rules.append(rule_id)
            # Add keywords
            for keyword in base_rule.keywords:
                current.keywords.add(keyword.lower())
        else:
            # Rule exists, merge current changes into base
            current_rule = current.rules_map[rule_id]
            merged_rule = _merge_rules(current_rule, base_rule)
            current.rules_map[rule_id] = merged_rule
            # Update keywords
            for keyword in merged_rule.keywords:
                current.keywords.add(keyword.lower())

    # Append allowlists from base (no merging)
    current.allowlists.extend(base.allowlists)

    # Sort ordered rules to keep consistent ordering
    current.ordered_rules.sort()

    return current


def _merge_rules(current: Rule, base: Rule) -> Rule:
    """
    Merge a current rule with a base rule.

    Current rule fields take precedence over base rule fields.

    Args:
        current: The current rule (child).
        base: The base rule (parent).

    Returns:
        The merged rule.
    """
    # Start with a copy of the base rule
    merged = Rule(
        id=base.id,
        description=current.description if current.description else base.description,
        regex=current.regex if current.regex else base.regex,
        path=current.path if current.path else base.path,
        secret_group=current.secret_group if current.secret_group != 0 else base.secret_group,
        entropy=current.entropy if current.entropy != 0 else base.entropy,
        keywords=base.keywords + current.keywords,
        tags=base.tags + current.tags,
        allowlists=base.allowlists + current.allowlists,
        required=current.required,  # Required rules from current override
        skip_report=current.skip_report or base.skip_report,
    )

    return merged


def _validate_min_version(min_version: str, config_path: str) -> None:
    """
    Validate that the current gitleaks version meets the minimum required version.

    Note: For the Python implementation, we'll do a simple warning for now.
    Full semantic version checking can be added later.

    Args:
        min_version: Minimum required version string.
        config_path: Path to config (for logging).
    """
    if not min_version:
        logger.debug(
            "No minVersion specified in config",
            config_path=config_path,
        )
        return

    # For now, just log a debug message
    # TODO: Implement semantic version checking
    logger.debug(
        "Config specifies minimum version",
        min_version=min_version,
        config_path=config_path,
    )
