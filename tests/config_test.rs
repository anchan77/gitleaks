use gitleaks::config::Config;
use std::fs;

const CONFIG_PATH: &str = "testdata/config/";

#[test]
fn test_translate_generic() {
    let toml_str = fs::read_to_string(format!("{}generic.toml", CONFIG_PATH))
        .expect("Failed to read generic.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert_eq!(config.title, "gitleaks config");
    assert!(config.rules.contains_key("generic-api-key"));

    let rule = &config.rules["generic-api-key"];
    assert_eq!(rule.rule_id, "generic-api-key");
    assert_eq!(rule.description, "Generic API Key");
    assert!(rule.regex.is_some());
    assert_eq!(rule.entropy, 3.5);
    assert_eq!(rule.keywords.len(), 9);
    assert!(rule.keywords.contains(&"key".to_string()));
    assert!(rule.keywords.contains(&"api".to_string()));
    assert!(rule.keywords.contains(&"token".to_string()));
    assert_eq!(rule.tags.len(), 0);
}

#[test]
fn test_translate_rule_path_only() {
    let toml_str = fs::read_to_string(format!("{}valid/rule_path_only.toml", CONFIG_PATH))
        .expect("Failed to read rule_path_only.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert!(config.rules.contains_key("python-files-only"));

    let rule = &config.rules["python-files-only"];
    assert_eq!(rule.rule_id, "python-files-only");
    assert_eq!(rule.description, "Python Files");
    assert!(rule.path.is_some());
    assert_eq!(rule.path.as_ref().unwrap(), ".py");
    assert!(rule.regex.is_none());
    assert_eq!(rule.keywords.len(), 0);
    assert_eq!(rule.tags.len(), 0);
}

#[test]
fn test_translate_rule_regex_escaped_character_group() {
    let toml_str = fs::read_to_string(format!(
        "{}valid/rule_regex_escaped_character_group.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read rule_regex_escaped_character_group.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert!(config.rules.contains_key("pypi-upload-token"));

    let rule = &config.rules["pypi-upload-token"];
    assert_eq!(rule.rule_id, "pypi-upload-token");
    assert_eq!(rule.description, "PyPI upload token");
    assert!(rule.regex.is_some());
    assert_eq!(
        rule.regex.as_ref().unwrap(),
        r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}"
    );
    assert_eq!(rule.keywords.len(), 0);
    assert_eq!(rule.tags.len(), 2);
    assert!(rule.tags.contains(&"key".to_string()));
    assert!(rule.tags.contains(&"pypi".to_string()));
}

#[test]
fn test_translate_rule_entropy_group() {
    let toml_str = fs::read_to_string(format!("{}valid/rule_entropy_group.toml", CONFIG_PATH))
        .expect("Failed to read rule_entropy_group.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert!(config.rules.contains_key("discord-api-key"));

    let rule = &config.rules["discord-api-key"];
    assert_eq!(rule.rule_id, "discord-api-key");
    assert_eq!(rule.description, "Discord API key");
    assert!(rule.regex.is_some());
    assert_eq!(rule.entropy, 3.5);
    assert_eq!(rule.secret_group, 3);
    assert_eq!(rule.keywords.len(), 0);
    assert_eq!(rule.tags.len(), 0);
}

#[test]
fn test_translate_rule_missing_id() {
    let toml_str = fs::read_to_string(format!("{}invalid/rule_missing_id.toml", CONFIG_PATH))
        .expect("Failed to read rule_missing_id.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("rule |id| is missing or empty"),
        "Expected missing ID error, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("description: Discord API key"),
        "Expected description in error, got: {}",
        err_msg
    );
}

#[test]
fn test_translate_rule_no_regex_or_path() {
    let toml_str =
        fs::read_to_string(format!("{}invalid/rule_no_regex_or_path.toml", CONFIG_PATH))
            .expect("Failed to read rule_no_regex_or_path.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("discord-api-key: both |regex| and |path| are empty"),
        "Expected no regex or path error, got: {}",
        err_msg
    );
}

// Note: The bad_entropy_group test is deferred to Task 3 since we're not compiling regexes yet
// and can't validate the secret_group against the actual number of capture groups.
// For now, we'll just verify the config parses successfully:
#[test]
fn test_translate_rule_bad_entropy_group_deferred() {
    let toml_str =
        fs::read_to_string(format!("{}invalid/rule_bad_entropy_group.toml", CONFIG_PATH))
            .expect("Failed to read rule_bad_entropy_group.toml");

    // This should parse successfully for now; validation of secret_group
    // against actual regex groups will be added in Task 3
    let config = Config::from_toml(&toml_str);

    // For now, we expect this to succeed since we're not yet compiling regexes
    // In Task 3, this test should be updated to expect an error
    assert!(
        config.is_ok(),
        "Config parsing failed (expected for now without regex compilation): {:?}",
        config.err()
    );
}
