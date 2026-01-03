//! Fragment and source abstractions for content scanning.
//!
//! This module provides the core abstractions for representing scannable content
//! and its sources. The main types are:
//!
//! - [`Fragment`]: A unit of scannable content with metadata (file path, line numbers, etc.)
//! - [`Source`]: A trait for types that can yield fragments (files, git repos, stdin, etc.)
//! - [`CommitInfo`]: Metadata about git commits
//! - [`RemoteInfo`]: Information about remote git repositories
//! - [`Platform`]: Enumeration of supported SCM platforms
//!
//! # Design
//!
//! The fragment system provides a unified representation of content regardless of its origin.
//! This allows the detector to work with fragments from any source type without needing to
//! understand the specifics of file reading, git operations, or archive extraction.
//!
//! The `Source` trait uses an iterator-based API for better Rust ergonomics and composability.
//! This allows natural integration with Rust's iterator adapters and parallel processing libraries.

mod fragment;
mod git_info;
mod platform;
mod source;

// Re-export public types
pub use fragment::Fragment;
pub use git_info::{CommitInfo, RemoteInfo};
pub use platform::Platform;
pub use source::{Source, SourceError};
