/// Main entry point for gitleaks
///
/// This is the binary crate entry point that sets up signal handling,
/// initializes logging, and executes the CLI commands.

use clap::Parser;
use gitleaks::cli::{Cli, Commands};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info};

fn main() {
    // Set up interrupt signal handling
    // This creates a flag that will be set to true when Ctrl+C is pressed
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        error!("Interrupt signal received. Exiting...");
        process::exit(1);
    })
    .expect("Error setting Ctrl-C handler");

    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize logging with the specified log level
    if let Err(e) = gitleaks::logging::init(&cli.log_level) {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    // Show banner if not suppressed
    cli.show_banner();

    // Execute the appropriate command
    match &cli.command {
        Some(Commands::Version) => {
            gitleaks::cli::version::run();
        }
        None => {
            // No subcommand provided, show help
            // In future tasks, this will be the default "detect" behavior
            info!("No command specified. Use --help for usage information.");
            info!("Note: Detection functionality will be implemented in future milestones.");
        }
    }
}
