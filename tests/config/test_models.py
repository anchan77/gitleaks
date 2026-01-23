"""Tests for configuration models."""

import pytest
import regex

from gitleaks.config.models import Allowlist, AllowlistMatchCondition, Config, Extend, Required, Rule


class TestAllowlist:
    """Tests for Allowlist model."""

    def test_empty_allowlist_raises_error(self) -> None:
        """Empty allowlist should raise validation error."""
        with pytest.raises(ValueError, match="must contain at least one check"):
            Allowlist()

    def test_allowlist_with_commits(self) -> None:
        """Allowlist with commits should validate."""
        allowlist = Allowlist(commits=["abc123", "def456"])
        assert len(allowlist.commits) == 2
        assert allowlist._match_condition == AllowlistMatchCondition.OR

    def test_allowlist_with_paths(self) -> None:
        """Allowlist with path patterns should compile regex."""
        allowlist = Allowlist(paths=[r"\.txt$", r"^test/"])
        assert len(allowlist._path_patterns) == 2
        assert allowlist._combined_path_pattern is not None

    def test_allowlist_with_regexes(self) -> None:
        """Allowlist with regex patterns should compile."""
        allowlist = Allowlist(regexes=[r"password", r"api[_-]?key"])
        assert len(allowlist._regex_patterns) == 2
        assert allowlist._combined_regex_pattern is not None

    def test_allowlist_with_stop_words(self) -> None:
        """Allowlist with stop words should normalize to lowercase."""
        allowlist = Allowlist(stop_words=["Example", "TEST"])
        assert "example" in allowlist.stop_words
        assert "test" in allowlist.stop_words

    def test_allowlist_condition_and(self) -> None:
        """Allowlist with AND condition should parse correctly."""
        allowlist = Allowlist(commits=["abc"], condition="AND")
        assert allowlist._match_condition == AllowlistMatchCondition.AND

    def test_allowlist_condition_or(self) -> None:
        """Allowlist with OR condition should parse correctly."""
        allowlist = Allowlist(commits=["abc"], condition="OR")
        assert allowlist._match_condition == AllowlistMatchCondition.OR

    def test_allowlist_invalid_condition(self) -> None:
        """Invalid condition should raise error."""
        with pytest.raises(ValueError, match="unknown allowlist condition"):
            Allowlist(commits=["abc"], condition="INVALID")

    def test_allowlist_invalid_regex_target(self) -> None:
        """Invalid regex target should raise error."""
        with pytest.raises(ValueError, match="unknown allowlist regexTarget"):
            Allowlist(commits=["abc"], regex_target="invalid")

    def test_commit_allowed(self) -> None:
        """Test commit_allowed method."""
        allowlist = Allowlist(commits=["abc123", "DEF456"])
        # Commits are case-insensitive
        assert allowlist.commit_allowed("abc123")[0]
        assert allowlist.commit_allowed("ABC123")[0]
        assert allowlist.commit_allowed("def456")[0]
        assert not allowlist.commit_allowed("xyz")[0]

    def test_path_allowed(self) -> None:
        """Test path_allowed method."""
        allowlist = Allowlist(paths=[r"\.txt$", r"^test/"])
        assert allowlist.path_allowed("file.txt")
        assert allowlist.path_allowed("test/file.py")
        assert not allowlist.path_allowed("file.py")

    def test_regex_allowed(self) -> None:
        """Test regex_allowed method."""
        allowlist = Allowlist(regexes=[r"password", r"test_"])
        assert allowlist.regex_allowed("my_password")
        assert allowlist.regex_allowed("test_value")
        assert not allowlist.regex_allowed("secret")

    def test_contains_stop_word(self) -> None:
        """Test contains_stop_word method."""
        allowlist = Allowlist(stop_words=["example", "test"])
        found, word = allowlist.contains_stop_word("This is an example")
        assert found
        assert word == "example"

        found, word = allowlist.contains_stop_word("This is EXAMPLE text")
        assert found

        found, _ = allowlist.contains_stop_word("no match here")
        assert not found


class TestRequired:
    """Tests for Required model."""

    def test_required_with_id(self) -> None:
        """Required with valid ID should validate."""
        required = Required(id="rule-id")
        assert required.id == "rule-id"

    def test_required_empty_id_raises_error(self) -> None:
        """Required with empty ID should raise error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            Required(id="")

    def test_required_with_within_lines(self) -> None:
        """Required with within_lines should validate."""
        required = Required(id="rule-id", within_lines=5)
        assert required.within_lines == 5


class TestRule:
    """Tests for Rule model."""

    def test_rule_with_id_and_regex(self) -> None:
        """Rule with valid ID and regex should validate."""
        rule = Rule(id="test-rule", regex=r"\bpassword\b")
        assert rule.id == "test-rule"
        assert rule._regex_compiled is not None

    def test_rule_empty_id_raises_error(self) -> None:
        """Rule with empty ID should raise error."""
        with pytest.raises(ValueError, match="id is missing or empty"):
            Rule(id="", regex=r"test")

    def test_rule_no_regex_no_path_allowed_for_override(self) -> None:
        """Rule with neither regex nor path is allowed (for config extension).

        Note: Validation happens at the config loader level after extension/merging.
        This allows rules to override base rules without duplicating all fields.
        """
        rule = Rule(id="test-rule")
        assert rule.id == "test-rule"
        assert not rule.regex
        assert not rule.path

    def test_rule_invalid_regex_raises_error(self) -> None:
        """Rule with invalid regex should raise error."""
        with pytest.raises(ValueError, match="invalid regex pattern"):
            Rule(id="test-rule", regex=r"(?P<unclosed")

    def test_rule_invalid_secret_group_raises_error(self) -> None:
        """Rule with invalid secret group should raise error."""
        with pytest.raises(ValueError, match="invalid regex secret group"):
            Rule(id="test-rule", regex=r"(\w+)", secret_group=5)

    def test_rule_with_path(self) -> None:
        """Rule with path pattern should compile."""
        rule = Rule(id="test-rule", path=r"\.py$")
        assert rule._path_compiled is not None

    def test_rule_with_keywords(self) -> None:
        """Rule with keywords should normalize to lowercase."""
        rule = Rule(id="test-rule", regex=r"test", keywords=["API", "Key"])
        assert "api" in rule.keywords
        assert "key" in rule.keywords

    def test_rule_with_allowlist_deprecated(self) -> None:
        """Rule with deprecated single allowlist should migrate to allowlists."""
        allowlist = Allowlist(commits=["abc123"])
        rule = Rule(id="test-rule", regex=r"test", allowlist=allowlist)
        assert len(rule.allowlists) == 1
        assert rule.allowlist is None

    def test_rule_with_both_allowlist_formats_raises_error(self) -> None:
        """Rule with both allowlist formats should raise error."""
        allowlist = Allowlist(commits=["abc123"])
        with pytest.raises(ValueError, match="deprecated"):
            Rule(
                id="test-rule",
                regex=r"test",
                allowlist=allowlist,
                allowlists=[allowlist],
            )

    def test_rule_entropy_threshold(self) -> None:
        """Rule with entropy threshold should store value."""
        rule = Rule(id="test-rule", regex=r"(\w+)", entropy=3.5)
        assert rule.entropy == 3.5

    def test_rule_secret_group(self) -> None:
        """Rule with secret group should validate and store."""
        rule = Rule(id="test-rule", regex=r"key=(\w+)", secret_group=1)
        assert rule.secret_group == 1

    def test_rule_get_regex_compiled(self) -> None:
        """Test get_regex_compiled method."""
        rule = Rule(id="test-rule", regex=r"\btest\b")
        compiled = rule.get_regex_compiled()
        assert compiled is not None
        assert compiled.search("this is a test")

    def test_rule_get_path_compiled(self) -> None:
        """Test get_path_compiled method."""
        rule = Rule(id="test-rule", regex=r"test", path=r"\.py$")
        compiled = rule.get_path_compiled()
        assert compiled is not None
        assert compiled.search("file.py")


class TestExtend:
    """Tests for Extend model."""

    def test_extend_with_path(self) -> None:
        """Extend with path should validate."""
        extend = Extend(path="/path/to/config.toml")
        assert extend.path == "/path/to/config.toml"

    def test_extend_with_use_default(self) -> None:
        """Extend with useDefault should validate."""
        extend = Extend(use_default=True)
        assert extend.use_default is True

    def test_extend_with_disabled_rules(self) -> None:
        """Extend with disabled rules should validate."""
        extend = Extend(use_default=True, disabled_rules=["rule1", "rule2"])
        assert len(extend.disabled_rules) == 2


class TestConfig:
    """Tests for Config model."""

    def test_config_empty(self) -> None:
        """Empty config should validate."""
        config = Config()
        assert config.title == ""
        assert len(config.rules) == 0

    def test_config_with_title(self) -> None:
        """Config with title should validate."""
        config = Config(title="Test Config")
        assert config.title == "Test Config"

    def test_config_with_rules(self) -> None:
        """Config with rules should build rules map."""
        rules = [
            Rule(id="rule1", regex=r"test1"),
            Rule(id="rule2", regex=r"test2"),
        ]
        config = Config(rules=rules)
        assert len(config.rules_map) == 2
        assert "rule1" in config.rules_map
        assert "rule2" in config.rules_map

    def test_config_extracts_keywords(self) -> None:
        """Config should extract keywords from rules."""
        rules = [
            Rule(id="rule1", regex=r"test", keywords=["api", "key"]),
            Rule(id="rule2", regex=r"test", keywords=["password"]),
        ]
        config = Config(rules=rules)
        assert "api" in config.keywords
        assert "key" in config.keywords
        assert "password" in config.keywords

    def test_config_with_deprecated_allowlist(self) -> None:
        """Config with deprecated single allowlist should migrate."""
        allowlist = Allowlist(commits=["abc123"])
        config = Config(allowlist=allowlist)
        assert len(config.allowlists) == 1
        assert config.allowlist is None

    def test_config_with_both_allowlist_formats_raises_error(self) -> None:
        """Config with both allowlist formats should raise error."""
        allowlist = Allowlist(commits=["abc123"])
        with pytest.raises(ValueError, match="deprecated"):
            Config(allowlist=allowlist, allowlists=[allowlist])

    def test_config_get_ordered_rules(self) -> None:
        """Test get_ordered_rules method."""
        rules = [
            Rule(id="rule2", regex=r"test2"),
            Rule(id="rule1", regex=r"test1"),
        ]
        config = Config(rules=rules)
        ordered = config.get_ordered_rules()
        assert len(ordered) == 2
        assert ordered[0].id == "rule2"
        assert ordered[1].id == "rule1"
