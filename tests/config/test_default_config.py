"""
Tests for default configuration loading and validation.
"""

import pytest

from src.gitleaks.config.loader import load_config, load_default_config
from src.gitleaks.config.validation import validate_config


class TestDefaultConfigLoading:
    """Test loading of the embedded default configuration."""

    def test_load_default_config_returns_string(self):
        """Test that load_default_config returns a non-empty string."""
        config_toml = load_default_config()
        assert isinstance(config_toml, str)
        assert len(config_toml) > 0
        assert "title = \"gitleaks config\"" in config_toml

    def test_load_default_config_caches(self):
        """Test that load_default_config caches the result."""
        config1 = load_default_config()
        config2 = load_default_config()
        # Should return the exact same string (from cache)
        assert config1 is config2

    def test_load_config_defaults_to_embedded(self):
        """Test that load_config falls back to embedded default when no config file exists."""
        # Load config with no path specified (should use default)
        config = load_config()

        assert config is not None
        assert config.title == "gitleaks config"
        assert len(config.rules) > 100  # Should have 200+ rules
        assert config.path == "<default>"


class TestDefaultConfigContent:
    """Test the content and validity of the default configuration."""

    def test_default_config_has_expected_rules(self):
        """Test that the default config has the expected number of rules."""
        config = load_config()

        # As of the source, there should be 222 rules
        assert len(config.rules) == 222
        assert len(config.rules_map) == 222

    def test_default_config_has_keywords(self):
        """Test that keywords are extracted from rules."""
        config = load_config()

        # Should have many keywords
        assert len(config.keywords) > 200
        # Keywords should be lowercase
        for keyword in config.keywords:
            assert keyword == keyword.lower()

    def test_default_config_has_global_allowlist(self):
        """Test that the default config has global allowlists."""
        config = load_config()

        # Should have at least one global allowlist
        assert len(config.allowlists) >= 1

        # Check that allowlist has paths defined
        allowlist = config.allowlists[0]
        assert len(allowlist.paths) > 0

    def test_default_config_min_version(self):
        """Test that the default config specifies a minimum version."""
        config = load_config()

        assert config.min_version != ""
        # Should start with 'v'
        assert config.min_version.startswith("v")


class TestDefaultConfigRules:
    """Test individual aspects of rules in the default configuration."""

    def test_all_rules_have_ids(self):
        """Test that all rules have non-empty IDs."""
        config = load_config()

        for rule_id, rule in config.rules_map.items():
            assert rule.id == rule_id
            assert rule.id != ""
            assert len(rule.id) > 0

    def test_all_rules_have_descriptions(self):
        """Test that all rules have descriptions."""
        config = load_config()

        for rule in config.rules_map.values():
            # Most rules should have descriptions
            # (Some might not, but the majority should)
            if rule.regex:  # If it has a regex, it should have a description
                assert rule.description != ""

    def test_all_rules_have_regex_or_path(self):
        """Test that all rules have either regex or path pattern."""
        config = load_config()

        for rule in config.rules_map.values():
            assert rule.regex or rule.path, f"Rule {rule.id} has neither regex nor path"

    def test_common_rules_exist(self):
        """Test that some well-known rules exist in the default config."""
        config = load_config()

        # Check for some common secret types
        expected_rules = [
            "aws-access-token",
            "github-pat",
            "slack-bot-token",
            "private-key",
        ]

        for rule_id in expected_rules:
            assert rule_id in config.rules_map, f"Expected rule '{rule_id}' not found"


class TestRegexCompilation:
    """Test that all regex patterns in the default config compile successfully."""

    def test_all_regex_patterns_compile(self):
        """Test that all regex patterns compile without errors."""
        config = load_config()

        failed_rules = []
        for rule_id, rule in config.rules_map.items():
            # Check regex compilation
            if rule.regex and rule._regex_compiled is None:
                failed_rules.append((rule_id, "regex not compiled"))

        assert len(failed_rules) == 0, f"Failed rules: {failed_rules}"

    def test_all_path_patterns_compile(self):
        """Test that all path patterns compile without errors."""
        config = load_config()

        failed_rules = []
        for rule_id, rule in config.rules_map.items():
            # Check path compilation
            if rule.path and rule._path_compiled is None:
                failed_rules.append((rule_id, "path not compiled"))

        assert len(failed_rules) == 0, f"Failed rules: {failed_rules}"

    def test_validate_config_passes(self):
        """Test that validate_config passes for the default configuration."""
        config = load_config()

        # Should not raise any exceptions
        result = validate_config(config)
        assert result is True


class TestConfigExtension:
    """Test that the default config can be extended."""

    def test_extend_default_config(self):
        """Test that a custom config can extend the default config."""
        # Create a minimal config that extends the default
        custom_config_toml = """
title = "custom config"

[extend]
useDefault = true

[[rules]]
id = "custom-rule"
description = "A custom rule"
regex = '''custom-pattern'''
"""

        # Load the custom config
        config = load_config(config_content=custom_config_toml)

        # Should have all default rules plus the custom rule in rules_map
        assert len(config.rules_map) > 222  # Default 222 + custom
        assert "custom-rule" in config.rules_map

        # The custom rule should be in rules list
        assert "custom-rule" in [r.id for r in config.rules]

    def test_disable_default_rule(self):
        """Test that rules from the default config can be disabled."""
        # Create a config that extends default but disables a rule
        custom_config_toml = """
title = "custom config"

[extend]
useDefault = true
disabledRules = ["aws-access-token"]
"""

        config = load_config(config_content=custom_config_toml)

        # aws-access-token should be disabled
        assert "aws-access-token" not in config.rules_map

        # Other rules should still be present
        assert "github-pat" in config.rules_map


class TestAllowlistPatterns:
    """Test allowlist patterns from the default config."""

    def test_global_allowlist_paths(self):
        """Test that global allowlist path patterns work."""
        config = load_config()

        allowlist = config.allowlists[0]

        # Test some paths that should be allowed
        assert allowlist.path_allowed("node_modules/package.json")
        assert allowlist.path_allowed("vendor/github.com/something")
        assert allowlist.path_allowed("test.png")
        assert allowlist.path_allowed(".gitleaks.toml")

    def test_global_allowlist_regexes(self):
        """Test that global allowlist regexes work."""
        config = load_config()

        allowlist = config.allowlists[0]

        # Test some patterns that should be allowed
        # (These are common placeholders/environment variables)
        if allowlist.regexes:
            # Test that the allowlist has regex patterns
            assert len(allowlist._regex_patterns) > 0
