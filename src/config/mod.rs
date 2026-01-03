pub mod error;
pub mod extend;
pub mod rule;
pub mod types;

// Re-export commonly used types
pub use error::ConfigError;
pub use extend::Extend;
pub use rule::{Required, Rule};
pub use types::{Config, ViperConfig};
