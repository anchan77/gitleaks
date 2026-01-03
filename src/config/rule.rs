use serde::Deserialize;

use super::allowlist::Allowlist;

/// Rule contains information that define details on how to detect secrets
#[derive(Debug, Clone)]
pub struct Rule {
    /// RuleID is a unique identifier for this rule
    pub rule_id: String,

    /// Description is the description of the rule
    pub description: String,

    /// Entropy is a float representing the minimum shannon
    /// entropy a regex group must have to be considered a secret
    pub entropy: f64,

    /// SecretGroup is an int used to extract secret from regex
    /// match and used as the group that will have its entropy
    /// checked if `entropy` is set
    pub secret_group: usize,

    /// Regex is a regular expression pattern used to detect secrets (stored as string for now)
    pub regex: Option<String>,

    /// Path is a regular expression pattern used to filter secrets by path (stored as string for now)
    pub path: Option<String>,

    /// Tags is an array of strings used for metadata and reporting purposes
    pub tags: Vec<String>,

    /// Keywords are used for pre-regex check filtering
    pub keywords: Vec<String>,

    /// Allowlists allows a rule to be ignored for specific commits, paths, regexes, and/or stopwords
    pub allowlists: Vec<Allowlist>,

    /// If a rule has RequiredRules, it makes the rule dependent on the RequiredRules
    pub required_rules: Vec<Required>,

    /// SkipReport indicates whether findings should be reported
    pub skip_report: bool,

    /// Internal flag to track whether validation has been called
    #[allow(dead_code)]
    pub(crate) validated: bool,
}

/// Required represents a composite rule dependency
#[derive(Debug, Clone, Deserialize)]
pub struct Required {
    /// The ID of the required rule
    #[serde(rename = "id")]
    pub rule_id: String,

    /// Within how many lines the required rule must match
    #[serde(rename = "withinLines")]
    pub within_lines: Option<i32>,

    /// Within how many columns the required rule must match
    #[serde(rename = "withinColumns")]
    pub within_columns: Option<i32>,
}

impl Rule {
    /// Validate guards against common misconfigurations
    pub fn validate(&mut self) -> Result<(), crate::config::error::ConfigError> {
        use crate::config::error::ConfigError;

        if self.validated {
            return Ok(());
        }

        // Ensure |id| is present
        if self.rule_id.trim().is_empty() {
            return Err(ConfigError::MissingRuleId(
                if !self.description.is_empty() {
                    Some(self.description.clone())
                } else {
                    None
                },
                self.regex.clone(),
                self.path.clone(),
            ));
        }

        // Ensure the rule actually matches something
        if self.regex.is_none() && self.path.is_none() {
            return Err(ConfigError::NoRegexOrPath(self.rule_id.clone()));
        }

        // Note: secretGroup validation is done during compilation in CompiledConfig::from_config()
        // since it requires the regex to be compiled first

        self.validated = true;
        Ok(())
    }
}
