use serde::Deserialize;

/// Extend is a struct that allows users to define how they want their
/// configuration extended by other configuration files
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Extend {
    #[serde(default)]
    pub path: String,

    #[serde(default)]
    pub url: String,

    #[serde(default, rename = "useDefault")]
    pub use_default: bool,

    #[serde(default, rename = "disabledRules")]
    pub disabled_rules: Vec<String>,
}
