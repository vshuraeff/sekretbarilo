// rule definitions and loading

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;

/// a detection rule definition (before compilation)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Rule {
    pub id: String,
    pub description: String,
    #[serde(rename = "regex")]
    pub regex_pattern: String,
    pub secret_group: usize,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    #[serde(default)]
    pub allowlist: RuleAllowlist,
}

/// per-rule allowlist configuration
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleAllowlist {
    /// regex patterns to match against the captured secret value;
    /// if any matches, the finding is skipped
    #[serde(default)]
    pub regexes: Vec<String>,
    /// file path patterns to skip for this rule
    #[serde(default)]
    pub paths: Vec<String>,
}

/// top-level structure for the rules TOML file
#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// a compiled rule ready for scanning
pub struct CompiledRule {
    pub id: String,
    pub regex: Regex,
    pub secret_group: usize,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    /// true if the rule uses context-dependent matching (case-insensitive
    /// assignment patterns). set automatically from the regex pattern.
    pub context_dependent: bool,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("secret_group", &self.secret_group)
            .field("keywords", &self.keywords)
            .field("entropy_threshold", &self.entropy_threshold)
            .finish()
    }
}

/// the compiled scanner with aho-corasick automaton and compiled rules
pub struct CompiledScanner {
    /// aho-corasick automaton built from all rule keywords
    pub automaton: AhoCorasick,
    /// mapping from automaton pattern index to rule indices
    pub keyword_to_rules: Vec<Vec<usize>>,
    /// all compiled rules
    pub rules: Vec<CompiledRule>,
}

/// the embedded default rules TOML
const DEFAULT_RULES_TOML: &str = include_str!("../config/rules.toml");

/// load default rules from the embedded TOML file
pub fn load_default_rules() -> Result<Vec<Rule>, String> {
    let config: RulesConfig = toml::from_str(DEFAULT_RULES_TOML)
        .map_err(|e| format!("failed to parse embedded rules.toml: {}", e))?;
    Ok(config.rules)
}

/// load user rules from a TOML string
#[allow(dead_code)]
pub fn load_rules_from_str(toml_content: &str) -> Result<Vec<Rule>, String> {
    let config: RulesConfig =
        toml::from_str(toml_content).map_err(|e| format!("failed to parse rules TOML: {}", e))?;
    Ok(config.rules)
}

/// merge user rules with default rules.
/// user rules with the same id override defaults; new ids are appended.
pub fn merge_rules(defaults: Vec<Rule>, user_rules: Vec<Rule>) -> Vec<Rule> {
    let mut merged = defaults;
    for user_rule in user_rules {
        if let Some(pos) = merged.iter().position(|r| r.id == user_rule.id) {
            merged[pos] = user_rule;
        } else {
            merged.push(user_rule);
        }
    }
    merged
}

/// build a compiled scanner from rule definitions
pub fn compile_rules(rules: &[Rule]) -> Result<CompiledScanner, String> {
    let mut compiled_rules = Vec::with_capacity(rules.len());
    for rule in rules {
        let regex = RegexBuilder::new(&rule.regex_pattern)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| format!("failed to compile regex for rule '{}': {}", rule.id, e))?;
        // tier 2/3 rules use (?i) case-insensitive flag with assignment patterns.
        // tier 1 rules with entropy match distinctive token prefixes directly.
        let context_dependent = rule.regex_pattern.starts_with("(?i)");
        compiled_rules.push(CompiledRule {
            id: rule.id.clone(),
            regex,
            secret_group: rule.secret_group,
            keywords: rule.keywords.clone(),
            entropy_threshold: rule.entropy_threshold,
            context_dependent,
        });
    }

    // collect all keywords and map them back to rule indices
    let mut all_keywords: Vec<String> = Vec::new();
    let mut keyword_to_rules: Vec<Vec<usize>> = Vec::new();

    for (rule_idx, rule) in compiled_rules.iter().enumerate() {
        for keyword in &rule.keywords {
            let kw_lower = keyword.to_lowercase();
            // check if this keyword already exists
            if let Some(existing_idx) = all_keywords.iter().position(|k| k == &kw_lower) {
                keyword_to_rules[existing_idx].push(rule_idx);
            } else {
                all_keywords.push(kw_lower);
                keyword_to_rules.push(vec![rule_idx]);
            }
        }
    }

    let automaton = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&all_keywords)
        .map_err(|e| format!("failed to build aho-corasick automaton: {}", e))?;

    Ok(CompiledScanner {
        automaton,
        keyword_to_rules,
        rules: compiled_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, pattern: &str, keywords: Vec<&str>) -> Rule {
        Rule {
            id: id.into(),
            description: id.into(),
            regex_pattern: pattern.into(),
            secret_group: 0,
            keywords: keywords.into_iter().map(String::from).collect(),
            entropy_threshold: None,
            allowlist: RuleAllowlist::default(),
        }
    }

    #[test]
    fn compile_rules_basic() {
        let rules = vec![make_rule("test-rule", r"secret_[a-z]+", vec!["secret_"])];
        let scanner = compile_rules(&rules).unwrap();
        assert_eq!(scanner.rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0]);
    }

    #[test]
    fn compile_rules_shared_keyword() {
        let rules = vec![
            make_rule("rule-a", r"AKIA[A-Z0-9]{16}", vec!["akia"]),
            make_rule("rule-b", r"AKIA[A-Z0-9]{16}", vec!["akia"]),
        ];
        let scanner = compile_rules(&rules).unwrap();
        // shared keyword should map to both rules
        assert_eq!(scanner.keyword_to_rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0, 1]);
    }

    #[test]
    fn compile_rules_invalid_regex() {
        let rules = vec![make_rule("bad", r"[invalid", vec!["test"])];
        assert!(compile_rules(&rules).is_err());
    }

    #[test]
    fn load_default_rules_succeeds() {
        let rules = load_default_rules().unwrap();
        assert!(!rules.is_empty());
        // verify a few well-known rules exist
        assert!(rules.iter().any(|r| r.id == "aws-access-key-id"));
        assert!(rules.iter().any(|r| r.id == "github-personal-access-token"));
        assert!(rules.iter().any(|r| r.id == "generic-api-key"));
    }

    #[test]
    fn load_default_rules_all_compile() {
        let rules = load_default_rules().unwrap();
        let result = compile_rules(&rules);
        assert!(
            result.is_ok(),
            "failed to compile default rules: {:?}",
            result.err()
        );
    }

    #[test]
    fn load_rules_from_str_basic() {
        let toml = r#"
[[rules]]
id = "custom-token"
description = "Custom token"
regex = "(CUSTOM_[A-Z]{10})"
secret_group = 1
keywords = ["custom_"]
"#;
        let rules = load_rules_from_str(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "custom-token");
        assert_eq!(rules[0].secret_group, 1);
    }

    #[test]
    fn load_rules_from_str_with_entropy() {
        let toml = r#"
[[rules]]
id = "secret-with-entropy"
description = "Secret needing entropy"
regex = "(?i)secret\\s*=\\s*['\"]([^'\"]+)['\"]"
secret_group = 1
keywords = ["secret"]
entropy_threshold = 3.5
"#;
        let rules = load_rules_from_str(toml).unwrap();
        assert_eq!(rules[0].entropy_threshold, Some(3.5));
    }

    #[test]
    fn load_rules_from_str_with_allowlist() {
        let toml = r#"
[[rules]]
id = "aws-key"
description = "AWS key"
regex = "(AKIA[A-Z0-9]{16})"
secret_group = 1
keywords = ["akia"]

[rules.allowlist]
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = ["test/.*"]
"#;
        let rules = load_rules_from_str(toml).unwrap();
        assert_eq!(rules[0].allowlist.regexes.len(), 1);
        assert_eq!(rules[0].allowlist.paths.len(), 1);
    }

    #[test]
    fn load_rules_from_str_invalid() {
        let toml = "this is not valid toml [[[";
        assert!(load_rules_from_str(toml).is_err());
    }

    #[test]
    fn merge_rules_user_overrides_default() {
        let defaults = vec![
            make_rule("rule-a", r"pattern_a", vec!["a"]),
            make_rule("rule-b", r"pattern_b", vec!["b"]),
        ];
        let user = vec![make_rule("rule-a", r"new_pattern_a", vec!["a_new"])];
        let merged = merge_rules(defaults, user);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].regex_pattern, "new_pattern_a");
        assert_eq!(merged[0].keywords, vec!["a_new"]);
        assert_eq!(merged[1].id, "rule-b");
    }

    #[test]
    fn merge_rules_user_adds_new() {
        let defaults = vec![make_rule("rule-a", r"pattern_a", vec!["a"])];
        let user = vec![make_rule("rule-c", r"pattern_c", vec!["c"])];
        let merged = merge_rules(defaults, user);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "rule-a");
        assert_eq!(merged[1].id, "rule-c");
    }

    #[test]
    fn merge_rules_empty_user() {
        let defaults = vec![make_rule("rule-a", r"pattern_a", vec!["a"])];
        let merged = merge_rules(defaults.clone(), vec![]);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn default_rules_have_keywords() {
        let rules = load_default_rules().unwrap();
        for rule in &rules {
            assert!(
                !rule.keywords.is_empty(),
                "rule '{}' has no keywords",
                rule.id
            );
        }
    }

    #[test]
    fn default_rules_have_unique_ids() {
        let rules = load_default_rules().unwrap();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "duplicate rule IDs found");
    }
}
