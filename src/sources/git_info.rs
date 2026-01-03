use super::platform::Platform;

/// Information about a remote git repository
#[derive(Debug, Clone)]
pub struct RemoteInfo {
    /// The SCM platform (GitHub, GitLab, etc.)
    pub platform: Platform,
    /// The URL of the remote repository
    pub url: String,
}

/// Metadata about a git commit
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// Author's email address
    pub author_email: String,
    /// Author's name
    pub author_name: String,
    /// Commit date (ISO 8601 format typically)
    pub date: String,
    /// Commit message
    pub message: String,
    /// Information about the remote repository, if available
    pub remote: Option<RemoteInfo>,
    /// Commit SHA hash
    pub sha: String,
}
