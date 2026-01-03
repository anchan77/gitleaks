use gitleaks::config::{CompiledConfig, Config};
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

// Task 3: Test for bad secret_group validation during compilation
#[test]
fn test_compile_rule_bad_entropy_group() {
    let toml_str =
        fs::read_to_string(format!("{}invalid/rule_bad_entropy_group.toml", CONFIG_PATH))
            .expect("Failed to read rule_bad_entropy_group.toml");

    // Config parsing should succeed
    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    // But compilation should fail because secret_group (5) exceeds the number of capture groups (3)
    let result = CompiledConfig::from_config(config);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("invalid regex secret group 5"),
        "Expected invalid secret group error, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("max regex secret group 3"),
        "Expected max secret group 3, got: {}",
        err_msg
    );
}

// Task 3: Test successful regex compilation with escaped character groups
#[test]
fn test_compile_rule_regex_escaped_character_group() {
    let toml_str = fs::read_to_string(format!(
        "{}valid/rule_regex_escaped_character_group.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read rule_regex_escaped_character_group.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert!(compiled.rules.contains_key("pypi-upload-token"));
    let rule = &compiled.rules["pypi-upload-token"];
    assert!(rule.regex.is_some());

    // Test that the compiled regex works
    let test_str = format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(50));
    assert!(rule.regex.as_ref().unwrap().is_match(&test_str));
}

// Task 3: Test compilation with valid secret_group
#[test]
fn test_compile_rule_entropy_group() {
    let toml_str = fs::read_to_string(format!("{}valid/rule_entropy_group.toml", CONFIG_PATH))
        .expect("Failed to read rule_entropy_group.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert!(compiled.rules.contains_key("discord-api-key"));
    let rule = &compiled.rules["discord-api-key"];
    assert!(rule.regex.is_some());
    assert_eq!(rule.secret_group, 3);

    // Test that the compiled regex works
    // The regex pattern is: (?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]
    // It expects: discord...=..."secret"... where secret is 64 chars of [a-h0-9]
    let secret = "a".repeat(64); // 64 characters from [a-h0-9]
    let test_str = format!(r#"discord_token="{}""#, secret);
    assert!(rule.regex.as_ref().unwrap().is_match(&test_str));
}

// Task 3: Test compilation of path-only rule
#[test]
fn test_compile_rule_path_only() {
    let toml_str = fs::read_to_string(format!("{}valid/rule_path_only.toml", CONFIG_PATH))
        .expect("Failed to read rule_path_only.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert!(compiled.rules.contains_key("python-files-only"));
    let rule = &compiled.rules["python-files-only"];
    assert!(rule.path.is_some());
    assert!(rule.regex.is_none());

    // Test that the compiled path pattern works
    assert!(rule.path.as_ref().unwrap().is_match("test.py"));
    assert!(rule.path.as_ref().unwrap().is_match("src/main.py"));
}

// Task 3: Test invalid regex pattern
#[test]
fn test_compile_invalid_regex() {
    let toml_str = r#"
        [[rules]]
        id = "test-invalid-regex"
        description = "Test invalid regex"
        regex = "[invalid(regex"
    "#;

    let config = Config::from_toml(toml_str).expect("Failed to parse config");
    let result = CompiledConfig::from_config(config);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("invalid regex pattern"),
        "Expected invalid regex pattern error, got: {}",
        err_msg
    );
}

// Task 3: Test keyword index building
#[test]
fn test_compile_keyword_index() {
    let toml_str = fs::read_to_string(format!("{}generic.toml", CONFIG_PATH))
        .expect("Failed to read generic.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    // Should have a keyword index since the generic rule has keywords
    assert!(compiled.keyword_index.is_some());

    let keyword_index = compiled.keyword_index.as_ref().unwrap();

    // Test that keywords are found
    assert!(keyword_index.has_any_keyword("This has an API key"));
    assert!(keyword_index.has_any_keyword("secret token here"));
    assert!(!keyword_index.has_any_keyword("nothing interesting"));

    // Test finding matching rules
    let rules = keyword_index.find_matching_rules("This has an API key");
    assert!(!rules.is_empty());
    assert!(rules.contains(&"generic-api-key".to_string()));
}

// Task 3: Test ordered rules are preserved
#[test]
fn test_compile_ordered_rules() {
    let toml_str = r#"
        title = "test config"
        [[rules]]
        id = "rule-one"
        description = "First rule"
        regex = "test1"

        [[rules]]
        id = "rule-two"
        description = "Second rule"
        regex = "test2"

        [[rules]]
        id = "rule-three"
        description = "Third rule"
        regex = "test3"
    "#;

    let config = Config::from_toml(toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    // Verify the order is preserved
    assert_eq!(compiled.ordered_rules, vec!["rule-one", "rule-two", "rule-three"]);

    // Verify all rules are in the map
    assert_eq!(compiled.rules.len(), 3);
    assert!(compiled.rules.contains_key("rule-one"));
    assert!(compiled.rules.contains_key("rule-two"));
    assert!(compiled.rules.contains_key("rule-three"));
}

// Task 4: Allowlist tests

#[test]
fn test_allowlist_global_old_compat() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_global_old_compat.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_global_old_compat.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert_eq!(config.allowlists.len(), 1);
    assert_eq!(config.allowlists[0].stopwords.len(), 1);
    assert!(config
        .allowlists[0]
        .stopwords
        .contains(&"0989c462-69c9-49fa-b7d2-30dc5c576a97".to_string()));
}

#[test]
fn test_allowlist_global_regex() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_global_regex.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_global_regex.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert_eq!(config.allowlists.len(), 1);
    assert_eq!(config.allowlists[0].regexes.len(), 1);
    assert_eq!(config.allowlists[0].regexes[0], "AKIALALEM.L33243OLIA");
}

#[test]
fn test_allowlist_rule_regex() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_rule_regex.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_rule_regex.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert_eq!(config.title, "simple config with allowlist for aws");
    assert!(config.rules.contains_key("aws-access-key"));

    let rule = &config.rules["aws-access-key"];
    assert_eq!(rule.allowlists.len(), 1);
    assert_eq!(rule.allowlists[0].regexes.len(), 1);
    assert_eq!(rule.allowlists[0].regexes[0], "AKIALALEMEL33243OLIA");
}

#[test]
fn test_allowlist_rule_commit() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_rule_commit.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_rule_commit.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert!(config.rules.contains_key("aws-access-key"));

    let rule = &config.rules["aws-access-key"];
    assert_eq!(rule.allowlists.len(), 1);
    assert_eq!(rule.allowlists[0].commits.len(), 1);
    assert_eq!(rule.allowlists[0].commits[0], "allowthiscommit");
}

#[test]
fn test_allowlist_rule_path() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_rule_path.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_rule_path.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    assert!(config.rules.contains_key("aws-access-key"));

    let rule = &config.rules["aws-access-key"];
    assert_eq!(rule.allowlists.len(), 1);
    assert_eq!(rule.allowlists[0].paths.len(), 1);
    assert_eq!(rule.allowlists[0].paths[0], ".go");
}

#[test]
fn test_allowlist_global_empty() {
    let toml_str =
        fs::read_to_string(format!("{}invalid/allowlist_global_empty.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_global_empty.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("must contain at least one check"),
        "Expected empty allowlist error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_rule_empty() {
    let toml_str =
        fs::read_to_string(format!("{}invalid/allowlist_rule_empty.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_rule_empty.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("must contain at least one check"),
        "Expected empty allowlist error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_global_regextarget() {
    let toml_str = fs::read_to_string(format!(
        "{}invalid/allowlist_global_regextarget.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read allowlist_global_regextarget.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("unknown allowlist |regexTarget|"),
        "Expected unknown regexTarget error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_rule_regextarget() {
    let toml_str = fs::read_to_string(format!(
        "{}invalid/allowlist_rule_regextarget.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read allowlist_rule_regextarget.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("unknown allowlist |regexTarget|"),
        "Expected unknown regexTarget error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_global_old_and_new() {
    let toml_str = fs::read_to_string(format!(
        "{}invalid/allowlist_global_old_and_new.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read allowlist_global_old_and_new.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("[allowlist] is deprecated"),
        "Expected deprecated allowlist conflict error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_rule_old_and_new() {
    let toml_str = fs::read_to_string(format!(
        "{}invalid/allowlist_rule_old_and_new.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read allowlist_rule_old_and_new.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("[rules.allowlist] is deprecated"),
        "Expected deprecated rule allowlist conflict error, got: {}",
        err_msg
    );
}

#[test]
fn test_allowlist_global_target_rule_id() {
    let toml_str = fs::read_to_string(format!(
        "{}invalid/allowlist_global_target_rule_id.toml",
        CONFIG_PATH
    ))
    .expect("Failed to read allowlist_global_target_rule_id.toml");

    let result = Config::from_toml(&toml_str);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("target rule ID") && err_msg.contains("does not exist"),
        "Expected target rule not found error, got: {}",
        err_msg
    );
}

// Test allowlist compilation
#[test]
fn test_compile_allowlist_rule() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_rule_regex.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_rule_regex.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert!(compiled.rules.contains_key("aws-access-key"));

    let rule = &compiled.rules["aws-access-key"];
    assert_eq!(rule.allowlists.len(), 1);

    let allowlist = &rule.allowlists[0];
    assert!(allowlist.regex_pattern.is_some());

    // Test that the compiled regex works
    assert!(allowlist.regex_allowed("AKIALALEMEL33243OLIA"));
    assert!(!allowlist.regex_allowed("AKIALALEMEL33243OLIB"));
}

#[test]
fn test_compile_allowlist_global() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_global_regex.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_global_regex.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert_eq!(compiled.allowlists.len(), 1);

    let allowlist = &compiled.allowlists[0];
    assert!(allowlist.regex_pattern.is_some());

    // Test that the compiled regex works
    assert!(allowlist.regex_allowed("AKIALALEM.L33243OLIA"));
    assert!(!allowlist.regex_allowed("AKIALALEM.L33243OLIB"));
}

#[test]
fn test_compile_allowlist_stopwords() {
    let toml_str =
        fs::read_to_string(format!("{}valid/allowlist_global_old_compat.toml", CONFIG_PATH))
            .expect("Failed to read allowlist_global_old_compat.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");
    let compiled = CompiledConfig::from_config(config).expect("Failed to compile config");

    assert_eq!(compiled.allowlists.len(), 1);

    let allowlist = &compiled.allowlists[0];
    assert!(allowlist.stopword_trie.is_some());

    // Test that the stopword matching works (case-insensitive)
    assert!(allowlist.contains_stopword("0989c462-69c9-49fa-b7d2-30dc5c576a97"));
    assert!(allowlist.contains_stopword("0989C462-69C9-49FA-B7D2-30DC5C576A97"));
    assert!(allowlist.contains_stopword("prefix_0989c462-69c9-49fa-b7d2-30dc5c576a97_suffix"));
    assert!(!allowlist.contains_stopword("different-uuid"));
}


#[test]
fn test_allowlist_global_target_rules() {
    let toml_str = fs::read_to_string(format!("{}valid/allowlist_global_target_rules.toml", CONFIG_PATH))
        .expect("Failed to read allowlist_global_target_rules.toml");

    let config = Config::from_toml(&toml_str).expect("Failed to parse config");

    // Should have 3 rules
    assert_eq!(config.rules.len(), 3);
    
    // Should have 1 global allowlist (the one without targetRules)
    assert_eq!(config.allowlists.len(), 1);
    assert_eq!(config.allowlists[0].regexes.len(), 1);
    assert_eq!(config.allowlists[0].regexes[0], ".*fake.*");
    
    // github-app-token should have 1 allowlist (from targetRules)
    let github_app_token = &config.rules["github-app-token"];
    assert_eq!(github_app_token.allowlists.len(), 1);
    assert_eq!(github_app_token.allowlists[0].paths.len(), 1);
    assert_eq!(github_app_token.allowlists[0].paths[0], r"(?:^|/)@octokit/auth-token/README\.md$");
    
    // github-oauth should have 0 allowlists
    let github_oauth = &config.rules["github-oauth"];
    assert_eq!(github_oauth.allowlists.len(), 0);
    
    // github-pat should have 1 allowlist (from targetRules)
    let github_pat = &config.rules["github-pat"];
    assert_eq!(github_pat.allowlists.len(), 1);
    assert_eq!(github_pat.allowlists[0].paths.len(), 1);
    assert_eq!(github_pat.allowlists[0].paths[0], r"(?:^|/)@octokit/auth-token/README\.md$");
}
