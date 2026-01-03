use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::cell::Cell;

use super::allowlist::{Allowlist, AllowlistMatchCondition, ViperAllowlist};
use super::error::ConfigError;
use super::extend::Extend;
use super::rule::{Required, Rule};

// Thread-local storage for extension depth tracking
thread_local! {
    static EXTEND_DEPTH: Cell<usize> = Cell::new(0);
}

const MAX_EXTEND_DEPTH: usize = 2;

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
        self.translate_with_path("")
    }

    /// Translate with a specific config path (for extension loading)
    pub fn translate_with_path(&self, config_path: &str) -> Result<Config, ConfigError> {
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
            path: config_path.to_string(),
        };

        // Handle extension logic
        let current_extend_depth = EXTEND_DEPTH.with(|d| d.get());
        if MAX_EXTEND_DEPTH != current_extend_depth {
            // Validate that both path and use_default are not set
            if !config.extend.path.is_empty() && config.extend.use_default {
                return Err(ConfigError::ExtendConflict);
            }

            // Handle extension
            if config.extend.use_default {
                config.extend_default()?;
            } else if !config.extend.path.is_empty() {
                config.extend_path()?;
            }
        }

        // Apply targeted allowlists to their target rules and validate target rule existence
        // This is done after extension and only at depth 0
        if current_extend_depth == 0 {
            for (rule_id, allowlists) in targeted_allowlists {
                if let Some(rule) = config.rules.get_mut(&rule_id) {
                    rule.allowlists.extend(allowlists);
                } else {
                    return Err(ConfigError::TargetRuleNotFound(rule_id));
                }
            }

            // Validate all rules after everything has been assembled
            for rule in config.rules.values_mut() {
                rule.validate()?;
            }
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

    /// Load a config from a file path
    pub fn from_file(file_path: &str) -> Result<Self, ConfigError> {
        let toml_str = std::fs::read_to_string(file_path)?;
        let viper_config: ViperConfig = toml::from_str(&toml_str)?;
        viper_config.translate_with_path(file_path)
    }

    /// Extend from the default embedded configuration
    fn extend_default(&mut self) -> Result<(), ConfigError> {
        // Increment extend depth
        EXTEND_DEPTH.with(|d| d.set(d.get() + 1));

        // Load and parse the default config
        let default_config_str = get_default_config();
        let default_viper: ViperConfig = toml::from_str(default_config_str)
            .map_err(|e| ConfigError::TomlError(e))?;

        let base_config = default_viper.translate_with_path("")
            .map_err(|e| {
                EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
                e
            })?;

        // Merge the base config into this config
        self.extend_from(base_config);

        // Decrement extend depth
        EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        Ok(())
    }

    /// Extend from a file path
    fn extend_path(&mut self) -> Result<(), ConfigError> {
        // Increment extend depth
        EXTEND_DEPTH.with(|d| d.set(d.get() + 1));

        // Use the extend path as-is (relative to working directory, not config file)
        // This matches Go's behavior where viper.SetConfigFile uses the path as-is
        let extend_path = &self.extend.path;

        // Read the file
        let config_content = std::fs::read_to_string(extend_path)
            .map_err(|e| {
                EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
                ConfigError::IoError(e)
            })?;

        // Parse the config
        let base_viper: ViperConfig = toml::from_str(&config_content)
            .map_err(|e| {
                EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
                ConfigError::TomlError(e)
            })?;

        // Pass the extend path as the config path for recursive extension
        let base_config = base_viper.translate_with_path(extend_path)
            .map_err(|e| {
                EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
                e
            })?;

        // Merge the base config into this config
        self.extend_from(base_config);

        // Decrement extend depth
        EXTEND_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        Ok(())
    }

    /// Merge a base config into this config
    fn extend_from(&mut self, base_config: Config) {
        // Convert disabled rules into a set for efficient lookup
        let disabled_rule_ids: HashSet<String> = self.extend.disabled_rules.iter().cloned().collect();

        // Iterate through base config rules
        for (rule_id, base_rule) in base_config.rules {
            // Skip disabled rules
            if disabled_rule_ids.contains(&rule_id) {
                continue;
            }

            // Check if the rule exists in the current config
            if let Some(current_rule) = self.rules.get(&rule_id) {
                // Rule exists, merge the current rule into the base rule
                let mut merged_rule = base_rule.clone();

                // Override fields if they are set in the current rule
                if !current_rule.description.is_empty() {
                    merged_rule.description = current_rule.description.clone();
                }
                if current_rule.entropy != 0.0 {
                    merged_rule.entropy = current_rule.entropy;
                }
                if current_rule.secret_group != 0 {
                    merged_rule.secret_group = current_rule.secret_group;
                }
                if current_rule.regex.is_some() {
                    merged_rule.regex = current_rule.regex.clone();
                }
                if current_rule.path.is_some() {
                    merged_rule.path = current_rule.path.clone();
                }

                // Append tags and keywords (not replace)
                merged_rule.tags.extend(current_rule.tags.clone());
                merged_rule.keywords.extend(current_rule.keywords.clone());
                merged_rule.allowlists.extend(current_rule.allowlists.clone());

                // Add merged keywords to global keywords set
                for keyword in &merged_rule.keywords {
                    self.keywords.insert(keyword.clone());
                }

                // Update the rule in the map
                self.rules.insert(rule_id, merged_rule);
            } else {
                // Rule doesn't exist in current config, add it
                // Add the rule's keywords to the global keywords set
                for keyword in &base_rule.keywords {
                    self.keywords.insert(keyword.clone());
                }
                self.rules.insert(rule_id.clone(), base_rule);
                self.ordered_rules.push(rule_id);
            }
        }

        // Append global allowlists from the base config
        self.allowlists.extend(base_config.allowlists);

        // Sort ordered rules to keep them consistent
        self.ordered_rules.sort();
    }

    /// Get rules in order
    pub fn get_ordered_rules(&self) -> Vec<&Rule> {
        self.ordered_rules
            .iter()
            .filter_map(|id| self.rules.get(id))
            .collect()
    }
}

/// Get the default embedded configuration
/// This is a stub for now - will be implemented in Task 6
fn get_default_config() -> &'static str {
    // For now, return an empty config
    // This will be replaced with the actual embedded gitleaks.toml in Task 6
    ""
}
