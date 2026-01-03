use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

use super::error::ConfigError;

/// AllowlistMatchCondition determines whether all criteria must match
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub enum AllowlistMatchCondition {
    #[serde(rename = "or", alias = "OR", alias = "||")]
    Or,
    #[serde(rename = "and", alias = "AND", alias = "&&")]
    And,
}

impl Default for AllowlistMatchCondition {
    fn default() -> Self {
        AllowlistMatchCondition::Or
    }
}

impl std::fmt::Display for AllowlistMatchCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowlistMatchCondition::Or => write!(f, "OR"),
            AllowlistMatchCondition::And => write!(f, "AND"),
        }
    }
}

/// RegexTarget determines what the allowlist regexes match against
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegexTarget {
    /// Match against the extracted secret value (default)
    Secret,
    /// Match against the full regex match
    Match,
    /// Match against the entire line
    Line,
}

impl Default for RegexTarget {
    fn default() -> Self {
        RegexTarget::Secret
    }
}

/// Raw allowlist structure as it appears in TOML
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ViperAllowlist {
    /// Short human readable description of the allowlist
    #[serde(default)]
    pub description: String,

    /// MatchCondition determines whether all criteria must match. Defaults to "OR".
    #[serde(default, rename = "condition")]
    pub match_condition: AllowlistMatchCondition,

    /// Commits is a slice of commit SHAs that are allowed to be ignored
    #[serde(default)]
    pub commits: Vec<String>,

    /// Paths is a slice of path regular expressions that are allowed to be ignored
    #[serde(default)]
    pub paths: Vec<String>,

    /// Can be `match`, `line`, or `secret` (default).
    ///
    /// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
    ///
    /// If `line` the _Regexes_ will be tested against the entire line.
    ///
    /// If `secret` the _Regexes_ will be tested against the found secret.
    #[serde(default)]
    pub regex_target: Option<String>,

    /// Regexes is slice of content regular expressions that are allowed to be ignored
    #[serde(default)]
    pub regexes: Vec<String>,

    /// StopWords is a slice of stop words that are allowed to be ignored.
    /// This targets the _secret_, not the content of the regex match like the
    /// Regexes slice.
    #[serde(default)]
    pub stopwords: Vec<String>,
}

/// Allowlist allows a rule to be ignored for specific
/// regexes, paths, and/or commits
#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Short human readable description of the allowlist
    pub description: String,

    /// MatchCondition determines whether all criteria must match. Defaults to "OR".
    pub match_condition: AllowlistMatchCondition,

    /// Commits is a slice of commit SHAs that are allowed to be ignored
    pub commits: Vec<String>,

    /// Paths is a slice of path regular expressions that are allowed to be ignored
    pub paths: Vec<String>,

    /// Can be `match`, `line`, or `secret` (default).
    pub regex_target: RegexTarget,

    /// Regexes is slice of content regular expressions that are allowed to be ignored
    pub regexes: Vec<String>,

    /// StopWords is a slice of stop words that are allowed to be ignored
    pub stopwords: Vec<String>,
}

/// CompiledAllowlist contains an allowlist with compiled regex patterns and stopword trie
#[derive(Debug, Clone)]
pub struct CompiledAllowlist {
    /// Short human readable description of the allowlist
    pub description: String,

    /// MatchCondition determines whether all criteria must match. Defaults to "OR".
    pub match_condition: AllowlistMatchCondition,

    /// Normalized commits (lowercased) in a HashSet for O(1) lookup
    pub commit_set: Option<HashSet<String>>,

    /// Combined path regex pattern (all path patterns joined with OR)
    pub path_pattern: Option<Regex>,

    /// Original path patterns (for reference)
    pub paths: Vec<String>,

    /// Can be `match`, `line`, or `secret` (default).
    pub regex_target: RegexTarget,

    /// Combined content regex pattern (all content patterns joined with OR)
    pub regex_pattern: Option<Regex>,

    /// Original regex patterns (for reference)
    pub regexes: Vec<String>,

    /// Aho-Corasick trie for efficient stopword matching
    pub stopword_trie: Option<AhoCorasick>,

    /// Original stopwords (for reference)
    pub stopwords: Vec<String>,
}

impl ViperAllowlist {
    /// Parse and validate a ViperAllowlist into an Allowlist
    pub fn parse(&self) -> Result<Allowlist, ConfigError> {
        // Validate that at least one criterion is specified
        if self.commits.is_empty()
            && self.paths.is_empty()
            && self.regexes.is_empty()
            && self.stopwords.is_empty()
        {
            return Err(ConfigError::EmptyAllowlist);
        }

        // Parse and validate regex target
        let regex_target = match self.regex_target.as_deref() {
            None | Some("") | Some("secret") => RegexTarget::Secret,
            Some("match") => RegexTarget::Match,
            Some("line") => RegexTarget::Line,
            Some(other) => return Err(ConfigError::UnknownRegexTarget(other.to_string())),
        };

        Ok(Allowlist {
            description: self.description.clone(),
            match_condition: self.match_condition,
            commits: self.commits.clone(),
            paths: self.paths.clone(),
            regex_target,
            regexes: self.regexes.clone(),
            stopwords: self.stopwords.clone(),
        })
    }
}

impl Allowlist {
    /// Compile the allowlist into a CompiledAllowlist with optimized data structures
    pub fn compile(&self) -> Result<CompiledAllowlist, ConfigError> {
        // Deduplicate and normalize commits (case-insensitive)
        let commit_set = if !self.commits.is_empty() {
            let mut set = HashSet::new();
            for commit in &self.commits {
                set.insert(commit.trim().to_lowercase());
            }
            Some(set)
        } else {
            None
        };

        // Compile path patterns
        let path_pattern = if !self.paths.is_empty() {
            Some(join_regex_or(&self.paths)?)
        } else {
            None
        };

        // Compile content regex patterns
        let regex_pattern = if !self.regexes.is_empty() {
            Some(join_regex_or(&self.regexes)?)
        } else {
            None
        };

        // Build stopword trie (case-insensitive)
        let (stopword_trie, deduplicated_stopwords) = if !self.stopwords.is_empty() {
            let mut unique_stopwords = HashSet::new();
            for stopword in &self.stopwords {
                unique_stopwords.insert(stopword.to_lowercase());
            }
            let stopwords_vec: Vec<String> = unique_stopwords.into_iter().collect();
            let trie = AhoCorasick::new(&stopwords_vec)
                .map_err(|e| ConfigError::InvalidRegex("stopwords".to_string(), e.to_string()))?;
            (Some(trie), stopwords_vec)
        } else {
            (None, Vec::new())
        };

        Ok(CompiledAllowlist {
            description: self.description.clone(),
            match_condition: self.match_condition,
            commit_set,
            path_pattern,
            paths: self.paths.clone(),
            regex_target: self.regex_target.clone(),
            regex_pattern,
            regexes: self.regexes.clone(),
            stopword_trie,
            stopwords: deduplicated_stopwords,
        })
    }
}

impl CompiledAllowlist {
    /// Check if a commit is allowed
    pub fn commit_allowed(&self, commit: &str) -> bool {
        if commit.is_empty() {
            return false;
        }

        if let Some(ref commit_set) = self.commit_set {
            commit_set.contains(&commit.to_lowercase())
        } else {
            false
        }
    }

    /// Check if a path is allowed
    pub fn path_allowed(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }

        if let Some(ref pattern) = self.path_pattern {
            pattern.is_match(path)
        } else {
            false
        }
    }

    /// Check if content matches allowlist regexes
    pub fn regex_allowed(&self, content: &str) -> bool {
        if content.is_empty() {
            return false;
        }

        if let Some(ref pattern) = self.regex_pattern {
            pattern.is_match(content)
        } else {
            false
        }
    }

    /// Check if the content contains a stopword
    pub fn contains_stopword(&self, content: &str) -> bool {
        if content.is_empty() {
            return false;
        }

        if let Some(ref trie) = self.stopword_trie {
            let content_lower = content.to_lowercase();
            trie.is_match(&content_lower)
        } else {
            false
        }
    }

    /// Evaluate whether a finding should be allowed based on all criteria
    /// Returns true if the finding should be suppressed (allowed)
    pub fn evaluate(
        &self,
        commit: Option<&str>,
        path: Option<&str>,
        secret: &str,
        match_text: &str,
        line: &str,
    ) -> bool {
        // Determine what content to test against based on regex_target
        let content_to_test = match self.regex_target {
            RegexTarget::Secret => secret,
            RegexTarget::Match => match_text,
            RegexTarget::Line => line,
        };

        // Collect which criteria have values
        let has_commits = self.commit_set.is_some();
        let has_paths = self.path_pattern.is_some();
        let has_regexes = self.regex_pattern.is_some();
        let has_stopwords = self.stopword_trie.is_some();

        // Evaluate each criterion
        let commit_match = if has_commits {
            commit.map(|c| self.commit_allowed(c)).unwrap_or(false)
        } else {
            false
        };

        let path_match = if has_paths {
            path.map(|p| self.path_allowed(p)).unwrap_or(false)
        } else {
            false
        };

        let regex_match = if has_regexes {
            self.regex_allowed(content_to_test)
        } else {
            false
        };

        let stopword_match = if has_stopwords {
            self.contains_stopword(secret)
        } else {
            false
        };

        // Apply match condition logic
        match self.match_condition {
            AllowlistMatchCondition::Or => {
                // Any criterion matches -> allow
                commit_match || path_match || regex_match || stopword_match
            }
            AllowlistMatchCondition::And => {
                // All non-empty criteria must match
                let mut all_match = true;

                if has_commits {
                    all_match = all_match && commit_match;
                }
                if has_paths {
                    all_match = all_match && path_match;
                }
                if has_regexes {
                    all_match = all_match && regex_match;
                }
                if has_stopwords {
                    all_match = all_match && stopword_match;
                }

                all_match
            }
        }
    }
}

/// Helper function to join multiple regex patterns with OR
fn join_regex_or(patterns: &[String]) -> Result<Regex, ConfigError> {
    let mut combined = String::from("(?:");
    for (i, pattern) in patterns.iter().enumerate() {
        combined.push_str(pattern);
        if i < patterns.len() - 1 {
            combined.push('|');
        }
    }
    combined.push(')');

    Regex::new(&combined).map_err(|e| ConfigError::InvalidRegex(combined, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_allowed() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: vec!["commitA".to_string()],
            paths: Vec::new(),
            regex_target: RegexTarget::Secret,
            regexes: Vec::new(),
            stopwords: Vec::new(),
        };

        let compiled = allowlist.compile().unwrap();

        // Should match (case-insensitive)
        assert!(compiled.commit_allowed("commitA"));
        assert!(compiled.commit_allowed("COMMITA"));
        assert!(compiled.commit_allowed("commita"));

        // Should not match
        assert!(!compiled.commit_allowed("commitB"));
        assert!(!compiled.commit_allowed(""));
    }

    #[test]
    fn test_path_allowed() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: Vec::new(),
            paths: vec!["path".to_string()],
            regex_target: RegexTarget::Secret,
            regexes: Vec::new(),
            stopwords: Vec::new(),
        };

        let compiled = allowlist.compile().unwrap();

        // Should match
        assert!(compiled.path_allowed("a path"));
        assert!(compiled.path_allowed("path/to/file"));

        // Should not match
        assert!(!compiled.path_allowed("a ???"));
        assert!(!compiled.path_allowed(""));
    }

    #[test]
    fn test_regex_allowed() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: Vec::new(),
            paths: Vec::new(),
            regex_target: RegexTarget::Secret,
            regexes: vec!["matchthis".to_string()],
            stopwords: Vec::new(),
        };

        let compiled = allowlist.compile().unwrap();

        // Should match
        assert!(compiled.regex_allowed("a secret: matchthis, done"));
        assert!(compiled.regex_allowed("matchthis"));

        // Should not match
        assert!(!compiled.regex_allowed("a secret"));
        assert!(!compiled.regex_allowed(""));
    }

    #[test]
    fn test_stopword_matching() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: Vec::new(),
            paths: Vec::new(),
            regex_target: RegexTarget::Secret,
            regexes: Vec::new(),
            stopwords: vec!["password".to_string(), "test".to_string()],
        };

        let compiled = allowlist.compile().unwrap();

        // Should match (case-insensitive)
        assert!(compiled.contains_stopword("mypassword123"));
        assert!(compiled.contains_stopword("PASSWORD"));
        assert!(compiled.contains_stopword("this is a test"));
        assert!(compiled.contains_stopword("TEST"));

        // Should not match
        assert!(!compiled.contains_stopword("secret"));
        assert!(!compiled.contains_stopword(""));
    }

    #[test]
    fn test_empty_allowlist_validation() {
        let viper = ViperAllowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: Vec::new(),
            paths: Vec::new(),
            regex_target: None,
            regexes: Vec::new(),
            stopwords: Vec::new(),
        };

        let result = viper.parse();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::EmptyAllowlist));
    }

    #[test]
    fn test_invalid_regex_target() {
        let viper = ViperAllowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: vec!["test".to_string()],
            paths: Vec::new(),
            regex_target: Some("invalid".to_string()),
            regexes: Vec::new(),
            stopwords: Vec::new(),
        };

        let result = viper.parse();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::UnknownRegexTarget(_)
        ));
    }

    #[test]
    fn test_match_condition_or() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: vec!["abc123".to_string()],
            paths: vec![r"\.go$".to_string()],
            regex_target: RegexTarget::Secret,
            regexes: vec!["test".to_string()],
            stopwords: vec!["password".to_string()],
        };

        let compiled = allowlist.compile().unwrap();

        // Should allow if any criterion matches
        assert!(compiled.evaluate(Some("abc123"), None, "secret", "match", "line"));
        assert!(compiled.evaluate(None, Some("file.go"), "secret", "match", "line"));
        assert!(compiled.evaluate(None, None, "test", "match", "line"));
        assert!(compiled.evaluate(None, None, "mypassword", "match", "line"));

        // Should not allow if no criteria match
        assert!(!compiled.evaluate(None, None, "secret", "match", "line"));
    }

    #[test]
    fn test_match_condition_and() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::And,
            commits: vec!["abc123".to_string()],
            paths: vec![r"\.go$".to_string()],
            regex_target: RegexTarget::Secret,
            regexes: Vec::new(),
            stopwords: Vec::new(),
        };

        let compiled = allowlist.compile().unwrap();

        // Should allow only if all criteria match
        assert!(compiled.evaluate(Some("abc123"), Some("file.go"), "secret", "match", "line"));

        // Should not allow if only some criteria match
        assert!(!compiled.evaluate(Some("abc123"), None, "secret", "match", "line"));
        assert!(!compiled.evaluate(None, Some("file.go"), "secret", "match", "line"));
        assert!(!compiled.evaluate(None, None, "secret", "match", "line"));
    }

    #[test]
    fn test_deduplication() {
        let allowlist = Allowlist {
            description: String::new(),
            match_condition: AllowlistMatchCondition::Or,
            commits: vec!["commitA".to_string(), "commitB".to_string(), "commitA".to_string()],
            paths: Vec::new(),
            regex_target: RegexTarget::Secret,
            regexes: Vec::new(),
            stopwords: vec![
                "stopwordA".to_string(),
                "stopwordB".to_string(),
                "stopwordA".to_string(),
            ],
        };

        let compiled = allowlist.compile().unwrap();

        // Commits should be deduplicated
        assert_eq!(compiled.commit_set.as_ref().unwrap().len(), 2);

        // Stopwords should be deduplicated
        assert_eq!(compiled.stopwords.len(), 2);
    }
}
