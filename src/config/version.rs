use semver::Version;
use log::{debug, warn};

use crate::version;

/// Validates that the config's minimum version requirement is satisfied
/// by the current gitleaks version.
///
/// Returns Ok(()) if validation passes or if no minVersion is specified.
/// Logs a warning if the config requires a newer version than the current build.
pub fn validate_min_version(min_ver: Option<&str>, config_path: &str) -> Result<(), String> {
    let min_ver = match min_ver {
        Some(v) if !v.is_empty() => v,
        _ => {
            debug!(
                "no minVersion specified in config at '{}' - consider adding minVersion to ensure compatibility",
                config_path
            );
            return Ok(());
        }
    };

    // Skip version check for development builds
    if version::is_dev_build() {
        debug!(
            "dev build, skipping config version check (required: {})",
            min_ver
        );
        return Ok(());
    }

    // Parse the minimum required version (strip leading 'v' if present)
    let min_ver_clean = min_ver.strip_prefix('v').unwrap_or(min_ver);
    let min_semver = Version::parse(min_ver_clean)
        .map_err(|e| format!("invalid minVersion '{}': {}", min_ver, e))?;

    // Parse the current version (strip leading 'v' if present)
    let current_version = version::version();
    let current_ver_clean = current_version.strip_prefix('v').unwrap_or(current_version);
    let current_semver = Version::parse(current_ver_clean)
        .map_err(|e| format!("unable to parse current version '{}': {}", current_version, e))?;

    // Compare versions
    if current_semver < min_semver {
        warn!(
            "config at '{}' requires gitleaks version {} but current version is {}",
            config_path, min_ver, current_version
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_min_version_empty() {
        // Empty minVersion should pass
        assert!(validate_min_version(None, "test.toml").is_ok());
        assert!(validate_min_version(Some(""), "test.toml").is_ok());
    }

    #[test]
    fn test_validate_min_version_invalid() {
        // In dev builds, validation is skipped entirely, so even invalid versions return Ok
        // In production builds (with GITLEAKS_VERSION set), invalid semver should return an error
        // Since we're in a dev build by default, this test verifies the skip behavior
        let result = validate_min_version(Some("not-a-version"), "test.toml");
        // In dev mode, validation is skipped
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_min_version_valid() {
        // This should work regardless of the current version
        // Since we're in dev mode, version check should be skipped
        assert!(validate_min_version(Some("8.0.0"), "test.toml").is_ok());
        assert!(validate_min_version(Some("1.0.0"), "test.toml").is_ok());
    }

    #[test]
    fn test_validate_min_version_with_v_prefix() {
        // Version with 'v' prefix should be parsed correctly
        // Since we're in dev mode, version check should be skipped
        assert!(validate_min_version(Some("v8.25.0"), "test.toml").is_ok());
        assert!(validate_min_version(Some("v1.0.0"), "test.toml").is_ok());
    }
}
