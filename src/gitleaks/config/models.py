"""
Pydantic models for gitleaks configuration schema.

This module defines the data models for parsing and validating .gitleaks.toml
configuration files, including rules, allowlists, and extension settings.
"""

from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

import regex
from pydantic import BaseModel, Field, field_validator, model_validator

if TYPE_CHECKING:
    RegexPattern = regex.Pattern[str]
else:
    RegexPattern = regex.Pattern


class AllowlistMatchCondition(str, Enum):
    """Match condition for allowlist criteria."""

    OR = "OR"
    AND = "AND"


class Required(BaseModel):
    """Configuration for required rules (composite rule dependencies)."""

    id: str = Field(..., alias="id")
    within_lines: Optional[int] = Field(None, alias="withinLines")
    within_columns: Optional[int] = Field(None, alias="withinColumns")

    model_config = {"populate_by_name": True}

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Ensure rule ID is not empty."""
        if not v or not v.strip():
            raise ValueError("required rule ID cannot be empty")
        return v


class Allowlist(BaseModel):
    """
    Allowlist configuration for ignoring specific matches.

    Allowlists can filter by commits, paths, regex patterns, or stop words.
    The match condition determines whether all criteria must match (AND) or
    any criterion is sufficient (OR).
    """

    description: str = ""
    condition: str = ""
    commits: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    regex_target: str = Field("", alias="regexTarget")
    regexes: list[str] = Field(default_factory=list)
    stop_words: list[str] = Field(default_factory=list, alias="stopWords")
    target_rules: list[str] = Field(default_factory=list, alias="targetRules")

    # Compiled patterns and processed data (set during validation)
    _match_condition: AllowlistMatchCondition = AllowlistMatchCondition.OR
    _commit_map: dict[str, Any] = {}
    _path_patterns: list[RegexPattern] = []
    _regex_patterns: list[RegexPattern] = []
    _combined_path_pattern: Optional[RegexPattern] = None
    _combined_regex_pattern: Optional[RegexPattern] = None
    _validated: bool = False

    model_config = {"populate_by_name": True, "arbitrary_types_allowed": True}

    @field_validator("regex_target")
    @classmethod
    def validate_regex_target(cls, v: str) -> str:
        """Validate regex target field."""
        if v and v not in ("", "secret", "match", "line"):
            raise ValueError(
                f"unknown allowlist regexTarget '{v}' (expected 'match', 'line', or 'secret')"
            )
        # Normalize "secret" to empty string
        return "" if v == "secret" else v

    @model_validator(mode="after")
    def validate_and_compile(self) -> "Allowlist":
        """Validate allowlist has at least one check and compile patterns."""
        if self._validated:
            return self

        # Validate that at least one check is present
        if (
            not self.commits
            and not self.paths
            and not self.regexes
            and not self.stop_words
        ):
            raise ValueError(
                "allowlist must contain at least one check for: commits, paths, regexes, or stopWords"
            )

        # Parse match condition
        condition_upper = self.condition.upper()
        if condition_upper in ("AND", "&&"):
            self._match_condition = AllowlistMatchCondition.AND
        elif condition_upper in ("", "OR", "||"):
            self._match_condition = AllowlistMatchCondition.OR
        else:
            raise ValueError(
                f"unknown allowlist condition '{self.condition}' (expected 'and' or 'or')"
            )

        # Process commits: deduplicate and create lookup map
        if self.commits:
            unique_commits = {commit.strip().lower() for commit in self.commits}
            self.commits = list(unique_commits)
            self._commit_map = {c: None for c in unique_commits}

        # Process stop words: deduplicate and lowercase
        if self.stop_words:
            unique_stopwords = {sw.lower() for sw in self.stop_words}
            self.stop_words = list(unique_stopwords)

        # Compile path patterns
        if self.paths:
            for path_pattern in self.paths:
                try:
                    # Translate RE2/Ruby-style \z to Python-style \Z
                    translated = path_pattern.replace(r"\z", r"\Z")
                    self._path_patterns.append(regex.compile(translated))
                except regex.error as e:
                    raise ValueError(f"invalid path regex '{path_pattern}': {e}")
            # Create combined pattern for efficiency
            if len(self._path_patterns) > 0:
                combined = "(?:" + "|".join(p.pattern for p in self._path_patterns) + ")"
                self._combined_path_pattern = regex.compile(combined)

        # Compile regex patterns
        if self.regexes:
            for regex_pattern in self.regexes:
                try:
                    # Translate RE2/Ruby-style \z to Python-style \Z
                    translated = regex_pattern.replace(r"\z", r"\Z")
                    self._regex_patterns.append(regex.compile(translated))
                except regex.error as e:
                    raise ValueError(f"invalid allowlist regex '{regex_pattern}': {e}")
            # Create combined pattern for efficiency
            if len(self._regex_patterns) > 0:
                combined = "(?:" + "|".join(p.pattern for p in self._regex_patterns) + ")"
                self._combined_regex_pattern = regex.compile(combined)

        self._validated = True
        return self

    def commit_allowed(self, commit: str) -> tuple[bool, str]:
        """Check if a commit is allowed."""
        if not commit:
            return False, ""
        commit_lower = commit.lower()
        if commit_lower in self._commit_map:
            return True, commit
        return False, ""

    def path_allowed(self, path: str) -> bool:
        """Check if a path is allowed."""
        if not path:
            return False
        if self._combined_path_pattern:
            return self._combined_path_pattern.search(path) is not None
        return False

    def regex_allowed(self, content: str) -> bool:
        """Check if content matches allowlist regexes."""
        if not content:
            return False
        if self._combined_regex_pattern:
            return self._combined_regex_pattern.search(content) is not None
        return False

    def contains_stop_word(self, content: str) -> tuple[bool, str]:
        """Check if content contains any stop words."""
        if not content:
            return False, ""
        content_lower = content.lower()
        for stopword in self.stop_words:
            if stopword in content_lower:
                return True, stopword
        return False, ""


class Rule(BaseModel):
    """
    Rule configuration for secret detection.

    Rules define patterns to detect secrets, along with optional entropy
    thresholds, path filters, and allowlists.
    """

    id: str = Field(..., alias="id")
    description: str = ""
    regex: str = ""
    path: str = ""
    secret_group: int = Field(0, alias="secretGroup")
    entropy: float = 0.0
    keywords: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    allowlists: list[Allowlist] = Field(default_factory=list)
    # Deprecated: single allowlist for backwards compatibility
    allowlist: Optional[Allowlist] = Field(None, alias="allowList")
    required: list[Required] = Field(default_factory=list)
    skip_report: bool = Field(False, alias="skipReport")

    # Compiled patterns (set during validation)
    _regex_compiled: Optional[RegexPattern] = None
    _path_compiled: Optional[RegexPattern] = None
    _validated: bool = False

    model_config = {"populate_by_name": True, "arbitrary_types_allowed": True}

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Ensure rule ID is not empty."""
        if not v or not v.strip():
            raise ValueError("rule id is missing or empty")
        return v

    @field_validator("keywords", mode="before")
    @classmethod
    def normalize_keywords(cls, v: Any) -> list[str]:
        """Normalize keywords to lowercase."""
        if v is None:
            return []
        return [k.lower() for k in v]

    @model_validator(mode="after")
    def validate_and_compile(self) -> "Rule":
        """Validate rule configuration and compile patterns."""
        if self._validated:
            return self

        # Handle backwards compatibility: merge single allowlist into allowlists
        if self.allowlist is not None:
            if self.allowlists:
                raise ValueError(
                    f"{self.id}: [rules.allowlist] is deprecated and cannot be used "
                    f"alongside [[rules.allowlists]]"
                )
            self.allowlists = [self.allowlist]
            self.allowlist = None

        # Note: We don't validate that regex/path exist here because rules
        # can be used to override base rules in extended configs.
        # The final validation will happen after config extension/merging.

        # Compile regex pattern
        if self.regex:
            try:
                # Translate RE2/Ruby-style \z (absolute end) to Python-style \Z
                # This is a common difference between RE2 and Python regex
                pattern = self.regex.replace(r"\z", r"\Z")
                self._regex_compiled = regex.compile(pattern)
            except regex.error as e:
                raise ValueError(f"{self.id}: invalid regex pattern: {e}")

            # Validate secret group
            if self._regex_compiled:
                num_groups = self._regex_compiled.groups
                if self.secret_group > num_groups:
                    raise ValueError(
                        f"{self.id}: invalid regex secret group {self.secret_group}, "
                        f"max regex secret group {num_groups}"
                    )

        # Compile path pattern
        if self.path:
            try:
                # Translate RE2/Ruby-style \z to Python-style \Z
                pattern = self.path.replace(r"\z", r"\Z")
                self._path_compiled = regex.compile(pattern)
            except regex.error as e:
                raise ValueError(f"{self.id}: invalid path pattern: {e}")

        # Validate allowlists
        for al in self.allowlists:
            if al is None:
                continue
            # Allowlist validation happens in its own model_validator

        # Validate required rules
        for req in self.required:
            if not req.id:
                raise ValueError(f"{self.id}: [[rules.required]] rule ID is empty")

        self._validated = True
        return self

    def get_regex_compiled(self) -> Optional[RegexPattern]:
        """Get compiled regex pattern."""
        return self._regex_compiled

    def get_path_compiled(self) -> Optional[RegexPattern]:
        """Get compiled path pattern."""
        return self._path_compiled


class Extend(BaseModel):
    """Configuration for extending other config files."""

    path: str = ""
    url: str = ""
    use_default: bool = Field(False, alias="useDefault")
    disabled_rules: list[str] = Field(default_factory=list, alias="disabledRules")

    model_config = {"populate_by_name": True}


class Config(BaseModel):
    """
    Main configuration model for gitleaks.

    This model represents a complete gitleaks configuration, including rules,
    allowlists, and extension settings.
    """

    title: str = ""
    description: str = ""
    extend: Extend = Field(default_factory=Extend)
    rules: list[Rule] = Field(default_factory=list)
    # Deprecated: single allowlist for backwards compatibility
    allowlist: Optional[Allowlist] = Field(None, alias="allowList")
    allowlists: list[Allowlist] = Field(default_factory=list)
    min_version: str = Field("", alias="minVersion")

    # Processed data (set after translation)
    path: str = ""
    rules_map: dict[str, Rule] = Field(default_factory=dict)
    keywords: set[str] = Field(default_factory=set)
    ordered_rules: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def process_rules_and_allowlists(self) -> "Config":
        """Process rules into map and extract keywords."""
        # Handle backwards compatibility: merge single allowlist into allowlists
        if self.allowlist is not None:
            if self.allowlists:
                raise ValueError(
                    "[allowlist] is deprecated and cannot be used alongside [[allowlists]]"
                )
            self.allowlists = [self.allowlist]
            self.allowlist = None

        # Build rules map and keyword set
        for rule in self.rules:
            self.rules_map[rule.id] = rule
            self.ordered_rules.append(rule.id)
            for keyword in rule.keywords:
                self.keywords.add(keyword.lower())

        return self

    def get_ordered_rules(self) -> list[Rule]:
        """Get rules in their original order."""
        result = []
        for rule_id in self.ordered_rules:
            if rule_id in self.rules_map:
                result.append(self.rules_map[rule_id])
        return result
