use super::fragment::Fragment;
use thiserror::Error;

/// Errors that can occur during fragment generation
#[derive(Debug, Error)]
pub enum SourceError {
    /// IO error while reading source
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error specific to git operations
    #[error("Git error: {0}")]
    Git(String),

    /// Error during archive extraction
    #[error("Archive error: {0}")]
    Archive(String),

    /// Generic error with a message
    #[error("{0}")]
    Other(String),
}

/// A source that can yield fragments for scanning.
///
/// Sources represent different origins of content to scan: files, stdin, git repositories, etc.
/// The trait provides a unified interface for the detector to work with any source type.
///
/// # Design Choice: Iterator-based API
///
/// This trait uses an iterator-based approach rather than a callback pattern (like Go's FragmentsFunc).
/// This provides better Rust ergonomics and composability:
/// - Natural integration with Rust's iterator adapters (map, filter, etc.)
/// - Easy integration with parallel processing libraries like rayon
/// - Better error handling with Result in the iterator item type
/// - More idiomatic Rust code
///
/// # Example
///
/// ```ignore
/// fn scan_source(source: impl Source) -> Result<(), SourceError> {
///     for result in source.fragments() {
///         let fragment = result?;
///         // Process fragment...
///     }
///     Ok(())
/// }
/// ```
pub trait Source {
    /// Returns an iterator over fragments from this source.
    ///
    /// Each item is a `Result<Fragment, SourceError>` to handle errors during
    /// fragment generation without stopping iteration.
    ///
    /// The iterator is boxed to allow for different implementation types and
    /// to work with trait objects.
    fn fragments(&mut self) -> Box<dyn Iterator<Item = Result<Fragment, SourceError>> + '_>;
}
