/// Represents different source code management (SCM) platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Unknown or unrecognized platform
    Unknown,
    /// Explicitly disabled platform detection
    None,
    /// GitHub
    GitHub,
    /// GitLab
    GitLab,
    /// Azure DevOps
    AzureDevOps,
    /// Gitea
    Gitea,
    /// Bitbucket
    Bitbucket,
}

impl Platform {
    /// Returns the string representation of the platform
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Unknown => "unknown",
            Platform::None => "none",
            Platform::GitHub => "github",
            Platform::GitLab => "gitlab",
            Platform::AzureDevOps => "azuredevops",
            Platform::Gitea => "gitea",
            Platform::Bitbucket => "bitbucket",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for Platform {
    fn default() -> Self {
        Platform::Unknown
    }
}
