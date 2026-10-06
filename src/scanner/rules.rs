// rule definitions and loading

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;

/// a detection rule definition (before compilation)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Rule {
    pub id: String,
    pub description: String,
    #[serde(rename = "regex")]
    pub regex_pattern: String,
    pub secret_group: usize,
    #[serde(default)]
    pub secret_groups: Vec<usize>,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    pub payload_group: Option<usize>,
    pub min_payload_entropy: Option<f64>,
    #[serde(default)]
    pub reject_hex_payload: bool,
    #[serde(default)]
    pub allowlist: RuleAllowlist,
    /// rule class: what evidence the rule keys on. omitted on a user rule, it
    /// inherits the embedded rule of the same id, or `contextual` for a new id.
    #[serde(default)]
    pub class: Option<RuleClass>,
}

/// the evidence a rule keys on; classes are switched on and off as groups
/// through `[settings.rule_classes]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleClass {
    /// a recognizable credential format, marker or provider-specific structure
    Signature,
    /// a credential-naming key, auth header or credential-bearing url
    Contextual,
    /// value shape and entropy alone, without a signature or named context
    Heuristic,
}

impl RuleClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleClass::Signature => "signature",
            RuleClass::Contextual => "contextual",
            RuleClass::Heuristic => "heuristic",
        }
    }

    /// built-in on/off state when no config layer sets the class.
    pub fn enabled_by_default(self) -> bool {
        !matches!(self, RuleClass::Heuristic)
    }
}

impl std::fmt::Display for RuleClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Rule {
    /// the resolved class; a rule without one counts as `contextual`.
    pub fn resolved_class(&self) -> RuleClass {
        self.class.unwrap_or(RuleClass::Contextual)
    }
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
#[derive(Debug, Clone)]
pub struct CaptureIndices {
    pub entropy_key: Option<usize>,
    pub password_key: Option<usize>,
    pub context_unquoted: Option<usize>,
    pub entropy_unquoted: Option<usize>,
    pub entropy_value_groups: [Option<usize>; 10],
    pub entropy_rescan_groups: [Option<usize>; 4],
    pub kind_groups: [Option<usize>; 6],
}

impl CaptureIndices {
    fn new(regex: &Regex) -> Self {
        let names: HashMap<_, _> = regex
            .capture_names()
            .enumerate()
            .filter_map(|(index, name)| name.map(|name| (name.to_owned(), index)))
            .collect();
        let index = |name: &str| names.get(name).copied();
        Self {
            entropy_key: index("entropy_key"),
            password_key: index("password_key"),
            context_unquoted: index("context_unquoted"),
            entropy_unquoted: index("entropy_unquoted"),
            entropy_value_groups: [
                "entropy_default",
                "entropy_reference",
                "entropy_bare_double",
                "entropy_bare_single",
                "entropy_url",
                "entropy_double",
                "entropy_single",
                "entropy_bracket",
                "entropy_unquoted",
                "entropy_bare",
            ]
            .map(index),
            entropy_rescan_groups: [
                "entropy_double",
                "entropy_single",
                "entropy_bare_double",
                "entropy_bare_single",
            ]
            .map(index),
            kind_groups: [
                "entropy_default",
                "entropy_unquoted",
                "entropy_bare",
                "entropy_double",
                "entropy_single",
                "entropy_bracket",
            ]
            .map(index),
        }
    }
}

pub struct CompiledRule {
    pub id: String,
    pub regex: Regex,
    pub secret_group: usize,
    pub secret_groups: Vec<usize>,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    pub payload_group: Option<usize>,
    pub min_payload_entropy: Option<f64>,
    pub reject_hex_payload: bool,
    pub capture_indices: CaptureIndices,
    /// true if the rule uses context-dependent matching (case-insensitive
    /// assignment patterns). set automatically from the regex pattern.
    pub context_dependent: bool,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("secret_group", &self.secret_group)
            .field("secret_groups", &self.secret_groups)
            .field("keywords", &self.keywords)
            .field("entropy_threshold", &self.entropy_threshold)
            .field("payload_group", &self.payload_group)
            .field("min_payload_entropy", &self.min_payload_entropy)
            .field("reject_hex_payload", &self.reject_hex_payload)
            .field("capture_indices", &self.capture_indices)
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
    for mut user_rule in user_rules {
        if let Some(pos) = merged.iter().position(|r| r.id == user_rule.id) {
            if user_rule.class.is_none() {
                user_rule.class = merged[pos].class;
            }
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
        let safe_id = crate::audit::history::sanitize_display(&rule.id);
        let regex = RegexBuilder::new(&rule.regex_pattern)
            .size_limit(1 << 20)
            .build()
            .map_err(|_| {
                // the regex error text quotes the pattern; name the rule only
                format!("invalid regex in rule '{safe_id}'")
            })?;
        if (rule.min_payload_entropy.is_some() || rule.reject_hex_payload)
            && rule.payload_group.is_none()
        {
            return Err(format!(
                "rule '{safe_id}' has a payload guard without payload_group"
            ));
        }
        if let Some(group) = rule.payload_group
            && (group == 0 || group >= regex.captures_len())
        {
            return Err(format!("rule '{safe_id}' has invalid payload_group"));
        }
        if rule
            .min_payload_entropy
            .is_some_and(|floor| !floor.is_finite() || !(0.0..=8.0).contains(&floor))
        {
            return Err(format!("rule '{safe_id}' has invalid min_payload_entropy"));
        }
        // tier 2/3 rules use (?i) case-insensitive flag with assignment patterns.
        // tier 1 rules with entropy match distinctive token prefixes directly.
        let context_dependent = rule.regex_pattern.starts_with("(?i)");
        let capture_indices = CaptureIndices::new(&regex);
        compiled_rules.push(CompiledRule {
            id: rule.id.clone(),
            regex,
            secret_group: rule.secret_group,
            secret_groups: rule.secret_groups.clone(),
            keywords: rule.keywords.clone(),
            entropy_threshold: rule.entropy_threshold,
            payload_group: rule.payload_group,
            min_payload_entropy: rule.min_payload_entropy,
            reject_hex_payload: rule.reject_hex_payload,
            capture_indices,
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
            secret_groups: Vec::new(),
            keywords: keywords.into_iter().map(String::from).collect(),
            entropy_threshold: None,
            payload_group: None,
            min_payload_entropy: None,
            reject_hex_payload: false,
            allowlist: RuleAllowlist::default(),
            class: None,
        }
    }

    #[test]
    fn every_default_rule_declares_a_class() {
        let rules = load_default_rules().unwrap();
        let missing: Vec<&str> = rules
            .iter()
            .filter(|r| r.class.is_none())
            .map(|r| r.id.as_str())
            .collect();
        assert!(missing.is_empty(), "rules without class: {missing:?}");
        let heuristic: Vec<&str> = rules
            .iter()
            .filter(|r| r.class == Some(RuleClass::Heuristic))
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(heuristic, vec!["generic-high-entropy-value"]);
    }

    #[test]
    fn merge_rules_user_override_inherits_class() {
        let mut default = make_rule("x", "x", vec!["x"]);
        default.class = Some(RuleClass::Heuristic);
        let merged = merge_rules(vec![default], vec![make_rule("x", "y", vec!["y"])]);
        assert_eq!(merged[0].class, Some(RuleClass::Heuristic));
        assert_eq!(merged[0].regex_pattern, "y");
    }

    #[test]
    fn new_user_rule_without_class_is_contextual() {
        let merged = merge_rules(Vec::new(), vec![make_rule("n", "n", vec!["n"])]);
        assert_eq!(merged[0].resolved_class(), RuleClass::Contextual);
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
    fn capture_indices_include_named_and_nonparticipating_alternatives() {
        let rule = make_rule(
            "captures",
            r#"(?P<entropy_key>key)=(?:(?P<entropy_double>"[^"]+")|(?P<entropy_single>'[^']+'))"#,
            vec!["key"],
        );
        let scanner = compile_rules(&[rule]).unwrap();
        let compiled = &scanner.rules[0];
        let indices = &compiled.capture_indices;
        assert_eq!(indices.entropy_key, Some(1));
        assert_eq!(indices.entropy_value_groups[5], Some(2));
        assert_eq!(indices.entropy_value_groups[6], Some(3));
        assert_eq!(indices.password_key, None);
        let captures = compiled.regex.captures(b"key='value'").unwrap();
        assert!(
            captures
                .get(indices.entropy_value_groups[5].unwrap())
                .is_none()
        );
        assert_eq!(
            captures
                .get(indices.entropy_value_groups[6].unwrap())
                .unwrap()
                .as_bytes(),
            b"'value'"
        );
    }

    #[test]
    fn payload_guards_require_a_valid_capture() {
        let mut rule = make_rule("payload", r"(sk-([a-z]+))", vec!["sk-"]);
        rule.min_payload_entropy = Some(3.0);
        assert!(compile_rules(&[rule.clone()]).is_err());
        for group in [0, 3] {
            rule.payload_group = Some(group);
            assert!(compile_rules(&[rule.clone()]).is_err());
        }
        rule.payload_group = Some(2);
        for floor in [f64::NAN, f64::INFINITY, -0.1, 8.1] {
            rule.min_payload_entropy = Some(floor);
            assert!(compile_rules(&[rule.clone()]).is_err());
        }
        rule.min_payload_entropy = Some(3.0);
        assert!(compile_rules(&[rule.clone()]).is_ok());

        let mut hex_only = make_rule("payload", r"(EAA([a-z]+))", vec!["eaa"]);
        hex_only.reject_hex_payload = true;
        assert!(compile_rules(&[hex_only.clone()]).is_err());
        hex_only.payload_group = Some(2);
        assert!(compile_rules(&[hex_only]).is_ok());
    }

    #[test]
    fn invalid_same_id_override_fails_compilation() {
        let defaults = load_default_rules().unwrap();
        let mut override_rule = make_rule("openai-api-key", r"(sk-proj-[a-z]+)", vec!["sk-proj-"]);
        override_rule.min_payload_entropy = Some(3.0);
        let merged = merge_rules(defaults.clone(), vec![override_rule.clone()]);
        assert!(compile_rules(&merged).is_err());
        override_rule.payload_group = Some(2);
        let merged = merge_rules(defaults, vec![override_rule]);
        assert!(compile_rules(&merged).is_err());
    }

    #[test]
    fn default_payload_guards_point_to_nested_payloads() {
        let scanner = compile_rules(&load_default_rules().unwrap()).unwrap();
        for (id, entropy, hex_veto) in [
            ("openai-api-key", Some(3.0), false),
            ("facebook-access-token", None, true),
        ] {
            let rule = scanner.rules.iter().find(|rule| rule.id == id).unwrap();
            assert_eq!(rule.secret_group, 1);
            assert_eq!(rule.payload_group, Some(2));
            assert_eq!(rule.min_payload_entropy, entropy);
            assert_eq!(rule.reject_hex_payload, hex_veto);
        }
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
    fn only_generic_entropy_default_rule_is_keywordless() {
        let rules = load_default_rules().unwrap();
        let keywordless: Vec<_> = rules
            .iter()
            .filter(|rule| rule.keywords.is_empty())
            .map(|rule| rule.id.as_str())
            .collect();
        assert_eq!(keywordless, ["generic-high-entropy-value"]);
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
