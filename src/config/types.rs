use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use super::allowlist::{Allowlist, AllowlistMatchCondition, ViperAllowlist};
use super::error::ConfigError;
use super::extend::Extend;
use super::rule::{Required, Rule};

/// ViperGlobalAllowlist represents a global allowlist that can target specific rules
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ViperGlobalAllowlist {
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
    #[serde(default)]
    pub regex_target: Option<String>,

    /// Regexes is slice of content regular expressions that are allowed to be ignored
    #[serde(default)]
    pub regexes: Vec<String>,

    /// StopWords is a slice of stop words that are allowed to be ignored.
    #[serde(default)]
    pub stopwords: Vec<String>,

    /// Target rules for this allowlist
    #[serde(default)]
    pub target_rules: Vec<String>,
}

impl ViperGlobalAllowlist {
    /// Convert to a ViperAllowlist for parsing
    fn to_viper_allowlist(&self) -> ViperAllowlist {
        ViperAllowlist {
            description: self.description.clone(),
            match_condition: self.match_condition,
            commits: self.commits.clone(),
            paths: self.paths.clone(),
            regex_target: self.regex_target.clone(),
            regexes: self.regexes.clone(),
            stopwords: self.stopwords.clone(),
        }
    }
}

/// ViperRule is the raw rule structure as it appears in TOML
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Placeholder fields will be used in Task 4
struct ViperRule {
    #[serde(default)]
    id: String,

    #[serde(default)]
    description: String,

    #[serde(default)]
    path: String,

    #[serde(default)]
    regex: String,

    #[serde(default, rename = "secretGroup")]
    secret_group: usize,

    #[serde(default)]
    entropy: f64,

    #[serde(default)]
    keywords: Vec<String>,

    #[serde(default)]
    tags: Vec<String>,

    // Deprecated: this is a shim for backwards-compatibility
    // TODO: Remove this in 9.x
    #[serde(default, rename = "allowlist")]
    allow_list: Option<ViperAllowlist>,

    #[serde(default)]
    allowlists: Vec<ViperAllowlist>,

    #[serde(default)]
    required: Vec<Required>,

    #[serde(default, rename = "skipReport")]
    skip_report: bool,
}

/// ViperConfig is the config struct used to parse the TOML config file.
/// This struct does not include compiled regular expressions.
/// It is used as an intermediary to convert to the Config struct.
#[derive(Debug, Deserialize)]
pub struct ViperConfig {
    #[serde(default)]
    pub title: String,

    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub extend: Extend,

    #[serde(default)]
    rules: Vec<ViperRule>,

    // Deprecated: this is a shim for backwards-compatibility
    // TODO: Remove this in 9.x
    #[serde(default, rename = "allowlist")]
    pub allow_list: Option<ViperGlobalAllowlist>,

    #[serde(default)]
    pub allowlists: Vec<ViperGlobalAllowlist>,

    #[serde(default, rename = "minVersion")]
    pub min_version: String,
}

/// Config is a configuration struct that contains rules and allowlists if present
#[derive(Debug, Clone)]
pub struct Config {
    pub title: String,
    pub extend: Extend,
    pub path: String,
    pub description: String,
    pub rules: HashMap<String, Rule>,
    pub keywords: HashSet<String>,
    /// Used to keep sarif results consistent
    pub ordered_rules: Vec<String>,
    pub allowlists: Vec<Allowlist>,
    pub min_version: String,
}

impl ViperConfig {
    /// Translate converts a ViperConfig to a Config with validation
    pub fn translate(&self) -> Result<Config, ConfigError> {
        let mut keywords = HashSet::new();
        let mut ordered_rules = Vec::new();
        let mut rules_map = HashMap::new();

        // Validate individual rules
        for vr in &self.rules {
            // Process keywords - convert to lowercase
            let mut rule_keywords = Vec::new();
            for k in &vr.keywords {
                let keyword = k.to_lowercase();
                keywords.insert(keyword.clone());
                rule_keywords.push(keyword);
            }

            // Parse rule-specific allowlists
            let mut rule_allowlists = Vec::new();

            // Check for deprecated allow_list field
            if let Some(ref old_allowlist) = vr.allow_list {
                if !vr.allowlists.is_empty() {
                    return Err(ConfigError::DeprecatedRuleAllowlistConflict(vr.id.clone()));
                }
                let allowlist = old_allowlist.parse()
                    .map_err(|e| ConfigError::RuleAllowlistError(vr.id.clone(), e.to_string()))?;
                rule_allowlists.push(allowlist);
            }

            // Parse new format allowlists
            for allowlist_viper in &vr.allowlists {
                let allowlist = allowlist_viper.parse()
                    .map_err(|e| ConfigError::RuleAllowlistError(vr.id.clone(), e.to_string()))?;
                rule_allowlists.push(allowlist);
            }

            // Create the rule
            let mut rule = Rule {
                rule_id: vr.id.clone(),
                description: vr.description.clone(),
                regex: if vr.regex.is_empty() {
                    None
                } else {
                    Some(vr.regex.clone())
                },
                path: if vr.path.is_empty() {
                    None
                } else {
                    Some(vr.path.clone())
                },
                secret_group: vr.secret_group,
                entropy: vr.entropy,
                keywords: rule_keywords,
                tags: vr.tags.clone(),
                allowlists: rule_allowlists,
                required_rules: Vec::new(),
                skip_report: vr.skip_report,
                validated: false,
            };

            // Process required rules
            for r in &vr.required {
                if r.rule_id.is_empty() {
                    return Err(ConfigError::EmptyRequiredRuleId(rule.rule_id.clone()));
                }
                rule.required_rules.push(r.clone());
            }

            ordered_rules.push(rule.rule_id.clone());
            rules_map.insert(rule.rule_id.clone(), rule);
        }

        // Validate that all required rules exist
        for rule in rules_map.values() {
            for rr in &rule.required_rules {
                if !rules_map.contains_key(&rr.rule_id) {
                    return Err(ConfigError::RequiredRuleNotFound(
                        rule.rule_id.clone(),
                        rr.rule_id.clone(),
                    ));
                }
            }
        }

        // Parse global allowlists
        let mut global_allowlists = Vec::new();
        let mut targeted_allowlists: HashMap<String, Vec<Allowlist>> = HashMap::new();

        // Check for deprecated allow_list field
        if let Some(ref old_allowlist) = self.allow_list {
            if !self.allowlists.is_empty() {
                return Err(ConfigError::DeprecatedAllowlistConflict);
            }
            // Process the old format global allowlist
            let viper_allowlist = old_allowlist.to_viper_allowlist();
            let allowlist = viper_allowlist.parse()
                .map_err(|e| ConfigError::GlobalAllowlistError(e.to_string()))?;

            if !old_allowlist.target_rules.is_empty() {
                for rule_id in &old_allowlist.target_rules {
                    targeted_allowlists.entry(rule_id.clone())
                        .or_insert_with(Vec::new)
                        .push(allowlist.clone());
                }
            } else {
                global_allowlists.push(allowlist);
            }
        }

        // Parse new format global allowlists
        for global_viper in &self.allowlists {
            let viper_allowlist = global_viper.to_viper_allowlist();
            let allowlist = viper_allowlist.parse()
                .map_err(|e| ConfigError::GlobalAllowlistError(e.to_string()))?;

            if !global_viper.target_rules.is_empty() {
                for rule_id in &global_viper.target_rules {
                    targeted_allowlists.entry(rule_id.clone())
                        .or_insert_with(Vec::new)
                        .push(allowlist.clone());
                }
            } else {
                global_allowlists.push(allowlist);
            }
        }

        // Assemble the config
        let mut config = Config {
            title: self.title.clone(),
            description: self.description.clone(),
            extend: self.extend.clone(),
            rules: rules_map,
            keywords,
            ordered_rules,
            allowlists: global_allowlists,
            min_version: self.min_version.clone(),
            path: String::new(), // Will be set during loading in Task 6
        };

        // Apply targeted allowlists to their target rules and validate target rule existence
        for (rule_id, allowlists) in targeted_allowlists {
            if let Some(rule) = config.rules.get_mut(&rule_id) {
                rule.allowlists.extend(allowlists);
            } else {
                return Err(ConfigError::TargetRuleNotFound(rule_id));
            }
        }

        // Validate all rules
        for rule in config.rules.values_mut() {
            rule.validate()?;
        }

        Ok(config)
    }
}

impl Config {
    /// Parse a TOML string into a Config
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let viper_config: ViperConfig = toml::from_str(toml_str)?;
        viper_config.translate()
    }
}
