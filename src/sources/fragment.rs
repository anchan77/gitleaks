use super::git_info::CommitInfo;

/// A fragment of source content with associated metadata.
///
/// Fragments represent scannable units of content that can originate from
/// various sources (files, stdin, git diffs, archives). Each fragment includes
/// metadata about its origin to enable accurate reporting of findings.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The raw string content of the fragment
    pub raw: String,

    /// The path to the file this fragment came from.
    /// Path separators are normalized to '/' regardless of platform.
    pub file_path: String,

    /// If the file was accessed via a symlink, this contains the symlink path
    pub symlink_file: Option<String>,

    /// The line number where this fragment starts (1-indexed)
    pub start_line: usize,

    /// Git commit metadata, if this fragment came from a git source
    pub commit_info: Option<CommitInfo>,

    /// Indicates if this fragment is inherited from a previous finding
    /// (used for tracking baseline findings across scans)
    pub inherited_from_finding: bool,
}

impl Fragment {
    /// Creates a new Fragment with the given content and file path.
    ///
    /// All other fields are initialized to default values:
    /// - start_line: 1
    /// - symlink_file: None
    /// - commit_info: None
    /// - inherited_from_finding: false
    pub fn new(raw: String, file_path: String) -> Self {
        Self {
            raw,
            file_path,
            symlink_file: None,
            start_line: 1,
            commit_info: None,
            inherited_from_finding: false,
        }
    }

    /// Creates a new Fragment with a specified start line.
    pub fn with_start_line(raw: String, file_path: String, start_line: usize) -> Self {
        Self {
            raw,
            file_path,
            symlink_file: None,
            start_line,
            commit_info: None,
            inherited_from_finding: false,
        }
    }
}
