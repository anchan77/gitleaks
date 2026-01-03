use crate::config::{CompiledAllowlist, Config, ConfigError};
use regex::Regex;
use std::collections::HashMap;

/// CompiledRule contains a rule with compiled regex patterns
#[derive(Debug, Clone)]
pub struct CompiledRule {
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

    /// Compiled regex pattern for matching secrets
    pub regex: Option<Regex>,

    /// Compiled regex pattern for filtering by path
    pub path: Option<Regex>,

    /// Tags is an array of strings used for metadata and reporting purposes
    pub tags: Vec<String>,

    /// Keywords are used for pre-regex check filtering
    pub keywords: Vec<String>,

    /// Allowlists allows a rule to be ignored for specific commits, paths, regexes, and/or stopwords
    pub allowlists: Vec<CompiledAllowlist>,

    /// If a rule has RequiredRules, it makes the rule dependent on the RequiredRules
    pub required_rules: Vec<crate::config::rule::Required>,

    /// SkipReport indicates whether findings should be reported
    pub skip_report: bool,
}

/// CompiledConfig is a configuration with all regex patterns compiled
/// and keyword indices built
#[derive(Debug)]
pub struct CompiledConfig {
    /// Title of the configuration
    pub title: String,

    /// Description of the configuration
    pub description: String,

    /// Map of rule IDs to compiled rules
    pub rules: HashMap<String, CompiledRule>,

    /// Ordered list of rule IDs (for consistent output)
    pub ordered_rules: Vec<String>,

    /// Keyword index for prefiltering
    pub keyword_index: Option<crate::config::keywords::KeywordIndex>,

    /// Global allowlists
    pub allowlists: Vec<CompiledAllowlist>,
}

impl CompiledConfig {
    /// Compile a raw Config into a CompiledConfig with all regex patterns compiled
    pub fn from_config(config: Config) -> Result<Self, ConfigError> {
        let mut compiled_rules = HashMap::new();
        let mut all_keywords = Vec::new();

        for (rule_id, rule) in config.rules {
            // Compile the regex pattern if present
            let compiled_regex = if let Some(regex_str) = &rule.regex {
                Some(Regex::new(regex_str).map_err(|e| {
                    ConfigError::InvalidRegex(regex_str.to_string(), e.to_string())
                })?)
            } else {
                None
            };

            // Compile the path pattern if present
            let compiled_path = if let Some(path_str) = &rule.path {
                Some(Regex::new(path_str).map_err(|e| {
                    ConfigError::InvalidRegex(path_str.to_string(), e.to_string())
                })?)
            } else {
                None
            };

            // Validate secret_group against compiled regex
            if let Some(ref regex) = compiled_regex {
                let num_captures = regex.captures_len() - 1; // captures_len includes the full match
                if rule.secret_group > num_captures {
                    return Err(ConfigError::InvalidSecretGroup(
                        rule.rule_id.clone(),
                        rule.secret_group,
                        num_captures,
                    ));
                }
            }

            // Collect keywords for the index
            for keyword in &rule.keywords {
                all_keywords.push((keyword.to_lowercase(), rule_id.clone()));
            }

            // Compile rule-specific allowlists
            let mut compiled_allowlists = Vec::new();
            for allowlist in &rule.allowlists {
                let compiled = allowlist.compile()?;
                compiled_allowlists.push(compiled);
            }

            let compiled_rule = CompiledRule {
                rule_id: rule.rule_id.clone(),
                description: rule.description,
                entropy: rule.entropy,
                secret_group: rule.secret_group,
                regex: compiled_regex,
                path: compiled_path,
                tags: rule.tags,
                keywords: rule.keywords,
                allowlists: compiled_allowlists,
                required_rules: rule.required_rules,
                skip_report: rule.skip_report,
            };

            compiled_rules.insert(rule_id, compiled_rule);
        }

        // Build the keyword index if there are any keywords
        let keyword_index = if !all_keywords.is_empty() {
            Some(crate::config::keywords::KeywordIndex::new(all_keywords)?)
        } else {
            None
        };

        // Compile global allowlists
        let mut compiled_global_allowlists = Vec::new();
        for allowlist in &config.allowlists {
            let compiled = allowlist.compile()?;
            compiled_global_allowlists.push(compiled);
        }

        Ok(CompiledConfig {
            title: config.title,
            description: config.description,
            rules: compiled_rules,
            ordered_rules: config.ordered_rules,
            keyword_index,
            allowlists: compiled_global_allowlists,
        })
    }

    /// Get a compiled rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&CompiledRule> {
        self.rules.get(rule_id)
    }

    /// Get all rules in order
    pub fn get_ordered_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.ordered_rules
            .iter()
            .filter_map(move |id| self.rules.get(id))
    }
}
