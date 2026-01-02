/// Logging infrastructure for gitleaks
///
/// This module provides a wrapper around tracing for structured logging,
/// similar to the Go zerolog implementation in the original codebase.

use tracing::Level;
use tracing_subscriber::EnvFilter;

/// Initialize the logging system with the specified log level
pub fn init(log_level: &str) -> anyhow::Result<()> {
    let level = parse_log_level(log_level);

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level.as_str()))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    Ok(())
}

/// Parse a log level string into a tracing Level
fn parse_log_level(level_str: &str) -> Level {
    match level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "err" | "error" => Level::ERROR,
        _ => {
            eprintln!("Unknown log level: {}, defaulting to info", level_str);
            Level::INFO
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("trace"), Level::TRACE);
        assert_eq!(parse_log_level("debug"), Level::DEBUG);
        assert_eq!(parse_log_level("info"), Level::INFO);
        assert_eq!(parse_log_level("warn"), Level::WARN);
        assert_eq!(parse_log_level("error"), Level::ERROR);
        assert_eq!(parse_log_level("unknown"), Level::INFO);
    }
}
