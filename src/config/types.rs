use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use super::error::ConfigError;
use super::extend::Extend;
use super::rule::{Required, Rule};

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
    #[serde(default, rename = "allowList")]
    allow_list: Option<()>, // Placeholder for Task 4

    #[serde(default)]
    allowlists: Vec<()>, // Placeholder for Task 4

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
    #[serde(default, rename = "allowList")]
    pub allow_list: Option<()>, // Placeholder for Task 4

    #[serde(default)]
    pub allowlists: Vec<()>, // Placeholder for Task 4

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
    pub allowlists: Vec<()>, // Placeholder for Task 4
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
                allowlists: Vec::new(), // Will be populated in Task 4
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

        // Assemble the config
        let mut config = Config {
            title: self.title.clone(),
            description: self.description.clone(),
            extend: self.extend.clone(),
            rules: rules_map,
            keywords,
            ordered_rules,
            allowlists: Vec::new(), // Will be populated in Task 4
            min_version: self.min_version.clone(),
            path: String::new(), // Will be set during loading in Task 6
        };

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
