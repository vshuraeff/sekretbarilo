// core scanning engine (aho-corasick + regex)

use crate::diff::parser::DiffFile;
use crate::scanner::entropy;
use crate::scanner::hash_detect;
use crate::scanner::rules::CompiledScanner;

/// a detected secret finding
#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub matched_value: Vec<u8>,
}

/// scan parsed diff files for secrets using the compiled scanner.
/// this is the main entry point for the scanning engine.
///
/// pipeline per line:
///   1. aho-corasick keyword pre-filter (single pass)
///   2. regex matching (only for rules whose keywords matched)
///   3. extract secret via capture group
///   4. hash detection (skip if it's a hash)
///   5. entropy evaluation (if rule has threshold)
pub fn scan(files: &[DiffFile], scanner: &CompiledScanner) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file in files {
        // skip deleted and binary files
        if file.is_deleted || file.is_binary {
            continue;
        }

        for added_line in &file.added_lines {
            scan_line(
                &file.path,
                added_line.line_number,
                &added_line.content,
                scanner,
                &mut findings,
            );
        }
    }

    findings
}

/// scan a single line against all rules using the aho-corasick pre-filter
fn scan_line(
    file_path: &str,
    line_number: usize,
    line: &[u8],
    scanner: &CompiledScanner,
    findings: &mut Vec<Finding>,
) {
    // step 1: aho-corasick keyword pre-filter
    // find which rules have keywords present in this line
    let mut candidate_rules = Vec::new();
    for mat in scanner.automaton.find_iter(line) {
        let pattern_idx = mat.pattern().as_usize();
        if let Some(rule_indices) = scanner.keyword_to_rules.get(pattern_idx) {
            for &rule_idx in rule_indices {
                if !candidate_rules.contains(&rule_idx) {
                    candidate_rules.push(rule_idx);
                }
            }
        }
    }

    if candidate_rules.is_empty() {
        return;
    }

    // step 2: regex matching only for candidate rules
    for &rule_idx in &candidate_rules {
        let rule = &scanner.rules[rule_idx];

        if let Some(captures) = rule.regex.captures(line) {
            // step 3: extract secret value via capture group
            let secret = if rule.secret_group > 0 {
                captures
                    .get(rule.secret_group)
                    .map(|m| m.as_bytes())
                    .unwrap_or_else(|| captures.get(0).map(|m| m.as_bytes()).unwrap_or(b""))
            } else {
                captures.get(0).map(|m| m.as_bytes()).unwrap_or(b"")
            };

            if secret.is_empty() {
                continue;
            }

            // step 4: hash detection - skip hashes
            if hash_detect::is_hash_in_context(secret, line) {
                continue;
            }

            // step 5: entropy evaluation (if rule requires it)
            if let Some(threshold) = rule.entropy_threshold {
                if !entropy::passes_entropy_check(secret, threshold) {
                    continue;
                }
            }

            findings.push(Finding {
                file: file_path.to_string(),
                line: line_number,
                rule_id: rule.id.clone(),
                matched_value: secret.to_vec(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parser::{AddedLine, DiffFile};
    use crate::scanner::rules::{compile_rules, Rule};

    fn make_scanner(rules: Vec<Rule>) -> CompiledScanner {
        compile_rules(&rules).unwrap()
    }

    fn make_file(path: &str, lines: Vec<(usize, &[u8])>) -> DiffFile {
        DiffFile {
            path: path.to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: lines
                .into_iter()
                .map(|(num, content)| AddedLine {
                    line_number: num,
                    content: content.to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn scan_empty_files() {
        let scanner = make_scanner(vec![Rule {
            id: "test".into(),
            description: "test".into(),
            regex_pattern: r"secret_[a-z]+".into(),
            secret_group: 0,
            keywords: vec!["secret_".into()],
            entropy_threshold: None,
        }]);
        let files: Vec<DiffFile> = vec![];
        let findings = scan(&files, &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_detects_keyword_match() {
        let scanner = make_scanner(vec![Rule {
            id: "aws-access-key".into(),
            description: "AWS access key".into(),
            regex_pattern: r"(AKIA[A-Z0-9]{16})".into(),
            secret_group: 1,
            keywords: vec!["akia".into()],
            entropy_threshold: None,
        }]);
        let file = make_file(
            "config.rs",
            vec![(42, b"let key = \"AKIAIOSFODNN7EXAMPLE\"")],
        );
        let findings = scan(&[file], &scanner);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].file, "config.rs");
        assert_eq!(findings[0].line, 42);
        assert_eq!(findings[0].matched_value, b"AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn scan_skips_no_keyword_match() {
        let scanner = make_scanner(vec![Rule {
            id: "aws-access-key".into(),
            description: "AWS access key".into(),
            regex_pattern: r"AKIA[A-Z0-9]{16}".into(),
            secret_group: 0,
            keywords: vec!["akia".into()],
            entropy_threshold: None,
        }]);
        // line has no "akia" keyword
        let file = make_file("config.rs", vec![(1, b"let x = 42;")]);
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_deleted_files() {
        let scanner = make_scanner(vec![Rule {
            id: "test".into(),
            description: "test".into(),
            regex_pattern: r"AKIA[A-Z0-9]{16}".into(),
            secret_group: 0,
            keywords: vec!["akia".into()],
            entropy_threshold: None,
        }]);
        let mut file = make_file(
            "old.rs",
            vec![(1, b"AKIAIOSFODNN7EXAMPLE")],
        );
        file.is_deleted = true;
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_binary_files() {
        let scanner = make_scanner(vec![Rule {
            id: "test".into(),
            description: "test".into(),
            regex_pattern: r"AKIA[A-Z0-9]{16}".into(),
            secret_group: 0,
            keywords: vec!["akia".into()],
            entropy_threshold: None,
        }]);
        let mut file = make_file(
            "image.png",
            vec![(1, b"AKIAIOSFODNN7EXAMPLE")],
        );
        file.is_binary = true;
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    fn generic_secret_rule(threshold: Option<f64>) -> Rule {
        Rule {
            id: "generic-secret".into(),
            description: "generic secret".into(),
            // use ['"] pattern without backslash escaping in raw strings
            regex_pattern: r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#.into(),
            secret_group: 1,
            keywords: vec!["secret".into()],
            entropy_threshold: threshold,
        }
    }

    #[test]
    fn scan_entropy_filter_blocks_low_entropy() {
        let scanner = make_scanner(vec![generic_secret_rule(Some(3.5))]);
        // low entropy secret (repeated chars)
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aaaaaaaaaaaaaaaaaaaaaaaa\"")],
        );
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_entropy_filter_allows_high_entropy() {
        let scanner = make_scanner(vec![generic_secret_rule(Some(3.0))]);
        // high entropy secret
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"")],
        );
        let findings = scan(&[file], &scanner);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_skips_sha256_hash() {
        let scanner = make_scanner(vec![generic_secret_rule(None)]);
        // the captured value is exactly 64 hex chars (SHA-256)
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            )],
        );
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_git_commit_hash_in_context() {
        let scanner = make_scanner(vec![generic_secret_rule(None)]);
        // 40-char hex (SHA-1) in a line with "commit" context
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
            )],
        );
        let findings = scan(&[file], &scanner);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_multiple_files_multiple_rules() {
        let scanner = make_scanner(vec![
            Rule {
                id: "aws-key".into(),
                description: "AWS key".into(),
                regex_pattern: r"(AKIA[A-Z0-9]{16})".into(),
                secret_group: 1,
                keywords: vec!["akia".into()],
                entropy_threshold: None,
            },
            Rule {
                id: "github-token".into(),
                description: "GitHub token".into(),
                regex_pattern: r"(ghp_[0-9a-zA-Z]{36})".into(),
                secret_group: 1,
                keywords: vec!["ghp_".into()],
                entropy_threshold: None,
            },
        ]);
        let file1 = make_file(
            "aws.rs",
            vec![(10, b"key = \"AKIAIOSFODNN7EXAMPLE\"")],
        );
        // ghp_ + 36 alphanumeric chars
        let file2 = make_file(
            "github.rs",
            vec![(20, b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"")],
        );
        let findings = scan(&[file1, file2], &scanner);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "aws-key");
        assert_eq!(findings[0].file, "aws.rs");
        assert_eq!(findings[1].rule_id, "github-token");
        assert_eq!(findings[1].file, "github.rs");
    }

    #[test]
    fn scan_capture_group_zero_uses_full_match() {
        let scanner = make_scanner(vec![Rule {
            id: "prefix-token".into(),
            description: "test".into(),
            regex_pattern: r"ghp_[0-9a-zA-Z]{36}".into(),
            secret_group: 0,
            keywords: vec!["ghp_".into()],
            entropy_threshold: None,
        }]);
        // ghp_ + 36 alphanumeric chars
        let file = make_file(
            "test.rs",
            vec![(1, b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")],
        );
        let findings = scan(&[file], &scanner);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].matched_value,
            b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        );
    }
}
