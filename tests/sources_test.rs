use gitleaks::{CommitInfo, Fragment, Platform, RemoteInfo, Source, SourceError};

#[test]
fn test_fragment_creation() {
    let fragment = Fragment::new("test content".to_string(), "test.txt".to_string());

    assert_eq!(fragment.raw, "test content");
    assert_eq!(fragment.file_path, "test.txt");
    assert_eq!(fragment.start_line, 1);
    assert!(fragment.symlink_file.is_none());
    assert!(fragment.commit_info.is_none());
    assert!(!fragment.inherited_from_finding);
}

#[test]
fn test_fragment_with_start_line() {
    let fragment = Fragment::with_start_line(
        "line 42 content".to_string(),
        "source.rs".to_string(),
        42,
    );

    assert_eq!(fragment.raw, "line 42 content");
    assert_eq!(fragment.file_path, "source.rs");
    assert_eq!(fragment.start_line, 42);
}

#[test]
fn test_fragment_with_commit_info() {
    let remote_info = RemoteInfo {
        platform: Platform::GitHub,
        url: "https://github.com/example/repo".to_string(),
    };

    let commit_info = CommitInfo {
        author_email: "test@example.com".to_string(),
        author_name: "Test Author".to_string(),
        date: "2024-01-01T00:00:00Z".to_string(),
        message: "Test commit".to_string(),
        remote: Some(remote_info),
        sha: "abc123".to_string(),
    };

    let mut fragment = Fragment::new("content".to_string(), "file.txt".to_string());
    fragment.commit_info = Some(commit_info);

    assert!(fragment.commit_info.is_some());
    let commit = fragment.commit_info.as_ref().unwrap();
    assert_eq!(commit.author_email, "test@example.com");
    assert_eq!(commit.sha, "abc123");

    let remote = commit.remote.as_ref().unwrap();
    assert_eq!(remote.platform, Platform::GitHub);
    assert_eq!(remote.url, "https://github.com/example/repo");
}

#[test]
fn test_platform_display() {
    assert_eq!(Platform::GitHub.to_string(), "github");
    assert_eq!(Platform::GitLab.to_string(), "gitlab");
    assert_eq!(Platform::AzureDevOps.to_string(), "azuredevops");
    assert_eq!(Platform::Gitea.to_string(), "gitea");
    assert_eq!(Platform::Bitbucket.to_string(), "bitbucket");
    assert_eq!(Platform::Unknown.to_string(), "unknown");
    assert_eq!(Platform::None.to_string(), "none");
}

#[test]
fn test_platform_default() {
    let platform: Platform = Default::default();
    assert_eq!(platform, Platform::Unknown);
}

/// Simple test source implementation
struct TestSource {
    fragments: Vec<Result<Fragment, SourceError>>,
}

impl Source for TestSource {
    fn fragments(&mut self) -> Box<dyn Iterator<Item = Result<Fragment, SourceError>> + '_> {
        Box::new(self.fragments.drain(..))
    }
}

#[test]
fn test_source_trait() {
    let mut source = TestSource {
        fragments: vec![
            Ok(Fragment::new("content 1".to_string(), "file1.txt".to_string())),
            Ok(Fragment::new("content 2".to_string(), "file2.txt".to_string())),
        ],
    };

    let collected: Vec<_> = source.fragments().collect();
    assert_eq!(collected.len(), 2);

    assert!(collected[0].is_ok());
    assert_eq!(collected[0].as_ref().unwrap().file_path, "file1.txt");

    assert!(collected[1].is_ok());
    assert_eq!(collected[1].as_ref().unwrap().file_path, "file2.txt");
}

#[test]
fn test_source_trait_with_errors() {
    let mut source = TestSource {
        fragments: vec![
            Ok(Fragment::new("content 1".to_string(), "file1.txt".to_string())),
            Err(SourceError::Other("test error".to_string())),
            Ok(Fragment::new("content 3".to_string(), "file3.txt".to_string())),
        ],
    };

    let collected: Vec<_> = source.fragments().collect();
    assert_eq!(collected.len(), 3);

    assert!(collected[0].is_ok());
    assert!(collected[1].is_err());
    assert!(collected[2].is_ok());

    match &collected[1] {
        Err(SourceError::Other(msg)) => assert_eq!(msg, "test error"),
        _ => panic!("Expected SourceError::Other"),
    }
}
