use std::fs;
use std::path::{Path, PathBuf};
use log::{debug, error};

use super::{Config, ConfigError, ViperConfig};
use super::version::validate_min_version;

/// The default embedded gitleaks configuration
pub const DEFAULT_CONFIG: &str = include_str!("../../config/gitleaks.toml");

/// Configuration source information for debugging
#[derive(Debug)]
pub enum ConfigSource {
    /// Configuration from --config flag
    CliFlag(PathBuf),
    /// Configuration from GITLEAKS_CONFIG environment variable
    EnvPath(PathBuf),
    /// Configuration from GITLEAKS_CONFIG_TOML environment variable (inline TOML)
    EnvContent,
    /// Configuration from .gitleaks.toml in target directory
    LocalFile(PathBuf),
    /// Default embedded configuration
    DefaultEmbedded,
}

impl ConfigSource {
    pub fn description(&self) -> String {
        match self {
            ConfigSource::CliFlag(p) => format!("--config flag: {}", p.display()),
            ConfigSource::EnvPath(p) => format!("GITLEAKS_CONFIG env var: {}", p.display()),
            ConfigSource::EnvContent => "GITLEAKS_CONFIG_TOML env var content".to_string(),
            ConfigSource::LocalFile(p) => format!(".gitleaks.toml in target: {}", p.display()),
            ConfigSource::DefaultEmbedded => "default embedded configuration".to_string(),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            ConfigSource::CliFlag(p) | ConfigSource::EnvPath(p) | ConfigSource::LocalFile(p) => Some(p),
            _ => None,
        }
    }
}

/// Load configuration following the precedence order:
/// 1. --config/-c flag (highest priority)
/// 2. GITLEAKS_CONFIG environment variable
/// 3. GITLEAKS_CONFIG_TOML environment variable (with TOML content directly)
/// 4. .gitleaks.toml in the target directory
/// 5. Default embedded configuration (lowest priority)
pub fn load_config(
    config_flag: Option<&str>,
    target_path: Option<&str>,
) -> Result<(Config, ConfigSource), ConfigError> {
    // 1. Check --config flag
    if let Some(config_path) = config_flag {
        debug!("Loading config from --config flag: {}", config_path);
        let path = PathBuf::from(config_path);
        return load_config_from_file(&path)
            .map(|cfg| (cfg, ConfigSource::CliFlag(path)));
    }

    // 2. Check GITLEAKS_CONFIG environment variable
    if let Ok(env_path) = std::env::var("GITLEAKS_CONFIG") {
        debug!("Loading config from GITLEAKS_CONFIG env var: {}", env_path);
        let path = PathBuf::from(&env_path);
        return load_config_from_file(&path)
            .map(|cfg| (cfg, ConfigSource::EnvPath(path)));
    }

    // 3. Check GITLEAKS_CONFIG_TOML environment variable
    if let Ok(env_content) = std::env::var("GITLEAKS_CONFIG_TOML") {
        debug!("Loading config from GITLEAKS_CONFIG_TOML env var content");
        return load_config_from_string(&env_content, "GITLEAKS_CONFIG_TOML")
            .map(|cfg| (cfg, ConfigSource::EnvContent));
    }

    // 4. Check for .gitleaks.toml in target directory
    if let Some(target) = target_path {
        let target_path = Path::new(target);

        // Check if target is a directory
        if target_path.is_file() {
            debug!(
                "Target '{}' is a file, not a directory. Skipping .gitleaks.toml lookup, using default config.",
                target_path.display()
            );
        } else if target_path.is_dir() {
            let local_config = target_path.join(".gitleaks.toml");
            if local_config.exists() {
                debug!("Loading config from .gitleaks.toml in target: {}", local_config.display());
                return load_config_from_file(&local_config)
                    .map(|cfg| (cfg, ConfigSource::LocalFile(local_config)));
            } else {
                debug!("No .gitleaks.toml found at: {}", local_config.display());
            }
        }
    }

    // 5. Use default embedded configuration
    debug!("Using default embedded configuration");
    load_config_from_string(DEFAULT_CONFIG, "embedded default")
        .map(|cfg| (cfg, ConfigSource::DefaultEmbedded))
}

/// Load configuration from a file path
fn load_config_from_file(path: &Path) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)
        .map_err(|e| ConfigError::LoadError(format!("Failed to read config file '{}': {}", path.display(), e)))?;

    load_config_from_string(&content, path.to_str().unwrap_or("unknown"))
}

/// Load and parse configuration from a TOML string
fn load_config_from_string(toml_content: &str, source_name: &str) -> Result<Config, ConfigError> {
    // Parse TOML into ViperConfig
    let viper_config: ViperConfig = toml::from_str(toml_content)
        .map_err(|e| ConfigError::ParseError(format!("Failed to parse TOML from '{}': {}", source_name, e)))?;

    // Validate minVersion if present
    let min_ver = if viper_config.min_version.is_empty() {
        None
    } else {
        Some(viper_config.min_version.as_str())
    };
    if let Err(e) = validate_min_version(min_ver, source_name) {
        error!("Version validation failed: {}", e);
        return Err(ConfigError::ValidationError(e));
    }

    // Translate ViperConfig to Config
    let config = viper_config.translate()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_loads() {
        // The default config should always be parseable
        let result = load_config_from_string(DEFAULT_CONFIG, "test");
        assert!(result.is_ok(), "Default config should parse: {:?}", result.err());
    }

    #[test]
    fn test_load_config_with_no_sources() {
        // With no config sources, should use default
        let result = load_config(None, None);
        assert!(result.is_ok());

        let (_, source) = result.unwrap();
        assert!(matches!(source, ConfigSource::DefaultEmbedded));
    }

    #[test]
    fn test_config_source_description() {
        let source = ConfigSource::DefaultEmbedded;
        assert_eq!(source.description(), "default embedded configuration");

        let source = ConfigSource::CliFlag(PathBuf::from("/test/config.toml"));
        assert!(source.description().contains("--config"));
    }
}
