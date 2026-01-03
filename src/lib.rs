pub mod config;
pub mod sources;
pub mod version;

// Re-export commonly used types
pub use config::{Config, ConfigError};
pub use sources::{CommitInfo, Fragment, Platform, RemoteInfo, Source, SourceError};
