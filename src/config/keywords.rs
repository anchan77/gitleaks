use crate::config::ConfigError;
use aho_corasick::AhoCorasick;
use std::collections::HashMap;

/// KeywordIndex is a prefilter index that uses Aho-Corasick to quickly
/// determine which rules might match content based on keyword presence
#[derive(Debug)]
pub struct KeywordIndex {
    /// The Aho-Corasick automaton for finding keywords
    automaton: AhoCorasick,

    /// Map from pattern index to the list of rule IDs that have that keyword
    pattern_to_rules: Vec<Vec<String>>,
}

impl KeywordIndex {
    /// Create a new keyword index from a list of (keyword, rule_id) pairs
    pub fn new(keywords: Vec<(String, String)>) -> Result<Self, ConfigError> {
        if keywords.is_empty() {
            // This shouldn't happen, but handle it gracefully
            return Err(ConfigError::InvalidRegex(
                "keywords".to_string(),
                "no keywords provided".to_string(),
            ));
        }

        // Group keywords by their text, collecting all rule IDs for each keyword
        let mut keyword_map: HashMap<String, Vec<String>> = HashMap::new();
        for (keyword, rule_id) in keywords {
            keyword_map
                .entry(keyword)
                .or_insert_with(Vec::new)
                .push(rule_id);
        }

        // Build the pattern list and pattern-to-rules mapping
        let mut patterns = Vec::new();
        let mut pattern_to_rules = Vec::new();

        for (keyword, rule_ids) in keyword_map {
            patterns.push(keyword);
            pattern_to_rules.push(rule_ids);
        }

        // Build the Aho-Corasick automaton (case-insensitive)
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| {
                ConfigError::InvalidRegex("keywords".to_string(), e.to_string())
            })?;

        Ok(KeywordIndex {
            automaton,
            pattern_to_rules,
        })
    }

    /// Find all rule IDs that might match the given content based on keyword presence
    /// Returns a set of rule IDs that have at least one keyword present in the content
    pub fn find_matching_rules(&self, content: &str) -> Vec<String> {
        let mut matching_rules = std::collections::HashSet::new();

        // Find all keyword matches in the content
        for mat in self.automaton.find_iter(content) {
            let pattern_idx = mat.pattern().as_usize();
            if let Some(rule_ids) = self.pattern_to_rules.get(pattern_idx) {
                for rule_id in rule_ids {
                    matching_rules.insert(rule_id.clone());
                }
            }
        }

        matching_rules.into_iter().collect()
    }

    /// Check if any keywords are present in the content
    pub fn has_any_keyword(&self, content: &str) -> bool {
        self.automaton.is_match(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_index_basic() {
        let keywords = vec![
            ("secret".to_string(), "rule1".to_string()),
            ("password".to_string(), "rule2".to_string()),
            ("api".to_string(), "rule3".to_string()),
        ];

        let index = KeywordIndex::new(keywords).unwrap();

        // Test finding rules
        let content = "This contains a SECRET key";
        let rules = index.find_matching_rules(content);
        assert_eq!(rules.len(), 1);
        assert!(rules.contains(&"rule1".to_string()));

        // Test case insensitivity
        let content = "PASSWORD=123";
        let rules = index.find_matching_rules(content);
        assert_eq!(rules.len(), 1);
        assert!(rules.contains(&"rule2".to_string()));
    }

    #[test]
    fn test_keyword_index_multiple_matches() {
        let keywords = vec![
            ("secret".to_string(), "rule1".to_string()),
            ("password".to_string(), "rule2".to_string()),
        ];

        let index = KeywordIndex::new(keywords).unwrap();

        let content = "secret password";
        let rules = index.find_matching_rules(content);
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&"rule1".to_string()));
        assert!(rules.contains(&"rule2".to_string()));
    }

    #[test]
    fn test_keyword_index_no_match() {
        let keywords = vec![
            ("secret".to_string(), "rule1".to_string()),
        ];

        let index = KeywordIndex::new(keywords).unwrap();

        let content = "nothing interesting here";
        let rules = index.find_matching_rules(content);
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_keyword_index_same_keyword_multiple_rules() {
        let keywords = vec![
            ("api".to_string(), "rule1".to_string()),
            ("api".to_string(), "rule2".to_string()),
            ("api".to_string(), "rule3".to_string()),
        ];

        let index = KeywordIndex::new(keywords).unwrap();

        let content = "api_key = abc123";
        let rules = index.find_matching_rules(content);
        assert_eq!(rules.len(), 3);
        assert!(rules.contains(&"rule1".to_string()));
        assert!(rules.contains(&"rule2".to_string()));
        assert!(rules.contains(&"rule3".to_string()));
    }

    #[test]
    fn test_has_any_keyword() {
        let keywords = vec![
            ("secret".to_string(), "rule1".to_string()),
        ];

        let index = KeywordIndex::new(keywords).unwrap();

        assert!(index.has_any_keyword("This has a secret"));
        assert!(index.has_any_keyword("SECRET"));
        assert!(!index.has_any_keyword("nothing here"));
    }
}
