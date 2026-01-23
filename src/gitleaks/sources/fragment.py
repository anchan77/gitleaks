"""
Fragment data model for representing content units to be scanned.

A Fragment represents a piece of content from a source (file, git diff, stdin, etc.)
along with metadata needed for accurate reporting of findings.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RemoteInfo:
    """
    Information about a git remote repository.

    Provides the data needed to reconstruct links from findings
    (e.g., links to specific commits or files in GitHub/GitLab).
    """

    platform: str  # e.g., "github", "gitlab", "bitbucket"
    url: str  # Remote URL


@dataclass
class CommitInfo:
    """
    Information about a git commit.

    Captures metadata about the commit containing a finding,
    used for detailed reporting.
    """

    author_email: str
    author_name: str
    date: str  # ISO 8601 format
    message: str
    remote: Optional[RemoteInfo]
    sha: str


@dataclass
class Fragment:
    """
    Represents a fragment of source content with metadata.

    A Fragment is the basic unit of content that the detection engine scans.
    It contains the raw content along with metadata about its origin (file path,
    commit, line numbers, etc.) needed for accurate reporting.

    Path normalization: All file paths MUST use forward slashes (/) as separators,
    regardless of the platform. This ensures consistent behavior across operating systems.
    """

    # Raw content as a string
    raw: str = ""

    # Raw content as bytes (optional, for binary content handling)
    raw_bytes: Optional[bytes] = None

    # File path with normalized forward slashes
    file_path: str = ""

    # Path to symlink if this fragment came from a symlink
    symlink_file: str = ""

    # Windows-specific path with original separator (for backwards compatibility)
    # TODO: This is for compatibility with gitleaks v8; remove in v9
    windows_file_path: str = ""

    # Commit SHA if this fragment is from a git commit
    # TODO: Deprecated in favor of commit_info.sha; remove in v9
    commit_sha: str = ""

    # Line number where this fragment starts (1-indexed)
    start_line: int = 0

    # Full commit information if applicable
    commit_info: Optional[CommitInfo] = None

    # Indicates if this fragment was inherited from a previous finding
    # (used for tracking findings across commits)
    inherited_from_finding: bool = False

    def __post_init__(self) -> None:
        """
        Post-initialization to normalize paths.

        Ensures that file_path always uses forward slashes, and
        windows_file_path preserves the original if needed.
        """
        # Normalize file_path to use forward slashes
        if self.file_path:
            # Convert backslashes to forward slashes
            self.file_path = self.file_path.replace("\\", "/")
