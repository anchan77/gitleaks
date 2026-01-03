pub mod allowlist;
pub mod compiled;
pub mod error;
pub mod extend;
pub mod keywords;
pub mod load;
pub mod rule;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use allowlist::{Allowlist, AllowlistMatchCondition, CompiledAllowlist, RegexTarget, ViperAllowlist};
pub use compiled::{CompiledConfig, CompiledRule};
pub use error::ConfigError;
pub use extend::Extend;
pub use keywords::KeywordIndex;
pub use load::{load_config, ConfigSource, DEFAULT_CONFIG};
pub use rule::{Required, Rule};
pub use types::{Config, ViperConfig};
pub use version::validate_min_version;
