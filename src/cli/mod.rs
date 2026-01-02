/// CLI module for gitleaks
///
/// This module defines the command-line interface structure using clap,
/// similar to the cobra-based CLI in the Go version.

pub mod version;

use clap::{Parser, Subcommand};

const BANNER: &str = r#"
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

"#;

const CONFIG_DESCRIPTION: &str = r#"config file path
order of precedence:
1. --config/-c
2. env var GITLEAKS_CONFIG
3. env var GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.gitleaks.toml
If none of the four options are used, then gitleaks will use the default config"#;

#[derive(Parser, Debug)]
#[command(author, version, about = "Gitleaks scans code, past or present, for secrets", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Config file path
    #[arg(short = 'c', long = "config", help = CONFIG_DESCRIPTION, env = "GITLEAKS_CONFIG")]
    pub config: Option<String>,

    /// Exit code when leaks have been encountered
    #[arg(long = "exit-code", default_value = "1")]
    pub exit_code: i32,

    /// Report file (use "-" for stdout)
    #[arg(short = 'r', long = "report-path")]
    pub report_path: Option<String>,

    /// Output format (json, csv, junit, sarif, template)
    #[arg(short = 'f', long = "report-format")]
    pub report_format: Option<String>,

    /// Template file used to generate the report (implies --report-format=template)
    #[arg(long = "report-template")]
    pub report_template: Option<String>,

    /// Path to baseline with issues that can be ignored
    #[arg(short = 'b', long = "baseline-path")]
    pub baseline_path: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long = "log-level", default_value = "info")]
    pub log_level: String,

    /// Show verbose output from scan
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Turn off color for verbose output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Files larger than this will be skipped (in megabytes)
    #[arg(long = "max-target-megabytes", default_value = "0")]
    pub max_target_megabytes: usize,

    /// Ignore gitleaks:allow comments
    #[arg(long = "ignore-gitleaks-allow")]
    pub ignore_gitleaks_allow: bool,

    /// Redact secrets from logs and stdout. To redact only parts of the secret
    /// just apply a percent value from 0..100. For example --redact=20 (default 100%)
    #[arg(long = "redact")]
    pub redact: Option<u8>,

    /// Suppress banner
    #[arg(long = "no-banner")]
    pub no_banner: bool,

    /// Only enable specific rules by id
    #[arg(long = "enable-rule")]
    pub enable_rule: Vec<String>,

    /// Path to .gitleaksignore file or folder containing one
    #[arg(short = 'i', long = "gitleaks-ignore-path", default_value = ".")]
    pub gitleaks_ignore_path: String,

    /// Allow recursive decoding up to this depth
    #[arg(long = "max-decode-depth", default_value = "5")]
    pub max_decode_depth: usize,

    /// Allow scanning into nested archives up to this depth
    /// (default "0", no archive traversal is done)
    #[arg(long = "max-archive-depth", default_value = "0")]
    pub max_archive_depth: usize,

    /// Set a timeout for gitleaks commands in seconds
    /// (default "0", no timeout is set)
    #[arg(long = "timeout", default_value = "0")]
    pub timeout: u64,

    /// Enable diagnostics (http OR comma-separated list: cpu,mem,trace)
    /// cpu=CPU prof, mem=memory prof, trace=exec tracing, http=serve via net/http/pprof
    #[arg(long = "diagnostics")]
    pub diagnostics: Option<String>,

    /// Directory to store diagnostics output files when not using http mode
    /// (defaults to current directory)
    #[arg(long = "diagnostics-dir")]
    pub diagnostics_dir: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Display gitleaks version
    Version,
    // Future commands will be added here:
    // Detect
    // Protect
    // etc.
}

impl Cli {
    /// Display the banner if not suppressed
    pub fn show_banner(&self) {
        if !self.no_banner {
            eprint!("{}", BANNER);
        }
    }
}
