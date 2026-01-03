/// Version information for gitleaks
/// This is set by the build process in production builds

/// The default message used for development builds
pub const DEFAULT_VERSION_MSG: &str = "version is set by build process";

/// Get the version at compile time
/// In production builds, this would be set via environment variable GITLEAKS_VERSION
/// In development builds, it defaults to the default message
pub const VERSION: &str = {
    match option_env!("GITLEAKS_VERSION") {
        Some(v) => v,
        None => DEFAULT_VERSION_MSG,
    }
};

/// Get the current version string
pub fn version() -> &'static str {
    VERSION
}

/// Check if this is a development build
/// Development builds have VERSION == DEFAULT_VERSION_MSG
pub fn is_dev_build() -> bool {
    VERSION == DEFAULT_VERSION_MSG
}
