// rule definitions and loading

use aho_corasick::AhoCorasick;
use regex::bytes::Regex;

/// a detection rule definition (before compilation)
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub regex_pattern: String,
    pub secret_group: usize,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
}

/// a compiled rule ready for scanning
pub struct CompiledRule {
    pub id: String,
    pub description: String,
    pub regex: Regex,
    pub secret_group: usize,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("description", &self.description)
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

/// build a compiled scanner from rule definitions
pub fn compile_rules(rules: &[Rule]) -> Result<CompiledScanner, String> {
    let mut compiled_rules = Vec::with_capacity(rules.len());
    for rule in rules {
        let regex = Regex::new(&rule.regex_pattern)
            .map_err(|e| format!("failed to compile regex for rule '{}': {}", rule.id, e))?;
        compiled_rules.push(CompiledRule {
            id: rule.id.clone(),
            description: rule.description.clone(),
            regex,
            secret_group: rule.secret_group,
            keywords: rule.keywords.clone(),
            entropy_threshold: rule.entropy_threshold,
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

    #[test]
    fn compile_rules_basic() {
        let rules = vec![Rule {
            id: "test-rule".into(),
            description: "test".into(),
            regex_pattern: r"secret_[a-z]+".into(),
            secret_group: 0,
            keywords: vec!["secret_".into()],
            entropy_threshold: None,
        }];
        let scanner = compile_rules(&rules).unwrap();
        assert_eq!(scanner.rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0]);
    }

    #[test]
    fn compile_rules_shared_keyword() {
        let rules = vec![
            Rule {
                id: "rule-a".into(),
                description: "a".into(),
                regex_pattern: r"AKIA[A-Z0-9]{16}".into(),
                secret_group: 0,
                keywords: vec!["akia".into()],
                entropy_threshold: None,
            },
            Rule {
                id: "rule-b".into(),
                description: "b".into(),
                regex_pattern: r"AKIA[A-Z0-9]{16}".into(),
                secret_group: 0,
                keywords: vec!["akia".into()],
                entropy_threshold: None,
            },
        ];
        let scanner = compile_rules(&rules).unwrap();
        // shared keyword should map to both rules
        assert_eq!(scanner.keyword_to_rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0, 1]);
    }

    #[test]
    fn compile_rules_invalid_regex() {
        let rules = vec![Rule {
            id: "bad".into(),
            description: "bad regex".into(),
            regex_pattern: r"[invalid".into(),
            secret_group: 0,
            keywords: vec!["test".into()],
            entropy_threshold: None,
        }];
        assert!(compile_rules(&rules).is_err());
    }
}
