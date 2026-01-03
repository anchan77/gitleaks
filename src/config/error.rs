use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("rule |id| is missing or empty{}", format_context(.0, .1, .2))]
    MissingRuleId(Option<String>, Option<String>, Option<String>), // description, regex, path

    #[error("{0}: both |regex| and |path| are empty, this rule will have no effect")]
    NoRegexOrPath(String),

    #[error("{0}: invalid regex secret group {1}, max regex secret group {2}")]
    InvalidSecretGroup(String, usize, usize),

    #[error("{0}: [[rules.required]] rule ID is empty")]
    EmptyRequiredRuleId(String),

    #[error("{0}: [[rules.required]] rule ID '{1}' does not exist")]
    RequiredRuleNotFound(String, String),

    #[error("{0}: [[rules.allowlists]] {1}")]
    RuleAllowlistError(String, String),

    #[error("[[allowlists]] {0}")]
    GlobalAllowlistError(String),

    #[error("[[allowlists]] target rule ID '{0}' does not exist")]
    TargetRuleNotFound(String),

    #[error("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")]
    DeprecatedAllowlistConflict,

    #[error("{0}: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]")]
    DeprecatedRuleAllowlistConflict(String),

    #[error("unknown allowlist |condition| '{0}' (expected 'and', 'or')")]
    UnknownAllowlistCondition(String),

    #[error("unknown allowlist |regexTarget| '{0}' (expected 'match', 'line')")]
    UnknownRegexTarget(String),

    #[error("must contain at least one check for: commits, paths, regexes, or stopwords")]
    EmptyAllowlist,

    #[error("unable to load config due to extend.path and extend.useDefault being set")]
    ExtendConflict,

    #[error("invalid regex pattern '{0}': {1}")]
    InvalidRegex(String, String),

    #[error("TOML parsing error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

fn format_context(
    description: &Option<String>,
    regex: &Option<String>,
    path: &Option<String>,
) -> String {
    let mut parts = Vec::new();
    if let Some(desc) = description {
        parts.push(format!(", description: {}", desc));
    }
    if let Some(re) = regex {
        parts.push(format!(", regex: {}", re));
    }
    if let Some(p) = path {
        parts.push(format!(", path: {}", p));
    }
    parts.join("")
}
