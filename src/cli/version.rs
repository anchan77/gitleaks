/// Version command implementation
///
/// Displays the gitleaks version information, similar to cmd/version.go in the Go version.

/// Get the version string
///
/// In the Go version, this is set via ldflags during the build process.
/// In Rust, we use the CARGO_PKG_VERSION environment variable which is
/// automatically set by Cargo during compilation.
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Run the version command
pub fn run() {
    println!("{}", get_version());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
        assert!(version.contains('.'));
    }
}
