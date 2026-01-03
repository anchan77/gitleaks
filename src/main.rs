use clap::{Parser, Subcommand};
use log::{debug, info};
use std::path::PathBuf;
use std::process;

use gitleaks::config::load_config;
use gitleaks::version;

const BANNER: &str = r#"
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

"#;

/// Gitleaks scans code, past or present, for secrets
#[derive(Parser, Debug)]
#[command(name = "gitleaks")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Config file path
    ///
    /// Order of precedence:
    /// 1. --config/-c
    /// 2. env var GITLEAKS_CONFIG
    /// 3. env var GITLEAKS_CONFIG_TOML with the file content
    /// 4. (target path)/.gitleaks.toml
    /// If none of the four options are used, then gitleaks will use the default config
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Suppress banner
    #[arg(long)]
    no_banner: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect secrets in a git repository or filesystem
    Detect {
        /// Path to scan (default: current directory)
        #[arg(short, long, default_value = ".")]
        source: PathBuf,
    },

    /// Protect pre-commit hook to prevent committing secrets
    Protect {
        /// Path to scan (default: current directory)
        #[arg(short, long, default_value = ".")]
        source: PathBuf,
    },

    /// Print version information
    Version,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level);

    // Display banner unless suppressed
    if !cli.no_banner {
        eprint!("{}", BANNER);
    }

    // Handle version command
    if matches!(cli.command, Some(Commands::Version)) {
        println!("gitleaks version {}", version::version());
        return;
    }

    // Load configuration
    let config_path = cli.config.as_ref().map(|p| p.to_str().unwrap());
    let target_path = match &cli.command {
        Some(Commands::Detect { source }) | Some(Commands::Protect { source }) => {
            Some(source.to_str().unwrap())
        }
        _ => Some("."),
    };

    let (config, source) = match load_config(config_path, target_path) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            process::exit(1);
        }
    };

    debug!("Loaded configuration from: {}", source.description());
    info!("Configuration loaded successfully with {} rules", config.rules.len());

    // Execute command
    match &cli.command {
        Some(Commands::Detect { source }) => {
            info!("Running detect on: {}", source.display());
            // TODO: Implement detection logic in future milestones
            println!("Detection functionality will be implemented in future milestones");
        }
        Some(Commands::Protect { source }) => {
            info!("Running protect on: {}", source.display());
            // TODO: Implement protect logic in future milestones
            println!("Protect functionality will be implemented in future milestones");
        }
        Some(Commands::Version) => {
            // Already handled above
        }
        None => {
            // No command specified, show help
            println!("No command specified. Use --help for usage information.");
        }
    }
}

/// Initialize the logging system based on the specified log level
fn init_logging(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => {
            eprintln!("Unknown log level '{}', defaulting to 'info'", log_level);
            log::LevelFilter::Info
        }
    };

    env_logger::Builder::from_default_env()
        .filter_level(level)
        .init();

    debug!("Logging initialized at level: {}", log_level);
}
