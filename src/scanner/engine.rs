// core scanning engine (aho-corasick + regex)

use rayon::prelude::*;

use crate::config::allowlist::CompiledAllowlist;
use crate::diff::parser::DiffFile;
use crate::scanner::entropy;
use crate::scanner::hash_detect;
use crate::scanner::password;
use crate::scanner::rules::CompiledScanner;

/// minimum number of files to trigger parallel processing with rayon
const PARALLEL_FILE_THRESHOLD: usize = 4;

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
///   1. global path allowlist (skip binary, vendor, generated files)
///   2. aho-corasick keyword pre-filter (single pass)
///   3. regex matching (only for rules whose keywords matched)
///   4. extract secret via capture group
///   5. per-rule allowlist check (value regex + path match)
///   6. variable reference detection (skip $VAR, ${VAR}, etc.)
///   7. stopword filter (skip if secret contains stopword)
///   8. hash detection (skip if it's a hash)
///   9. entropy evaluation (with doc file bonus if applicable)
///
/// for diffs with many files, processing is parallelized with rayon.
pub fn scan(
    files: &[DiffFile],
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<Finding> {
    // filter to scannable files first (early exit for binary, deleted, allowlisted)
    let scannable: Vec<&DiffFile> = files
        .iter()
        .filter(|f| !f.is_deleted && !f.is_binary && !f.added_lines.is_empty())
        .filter(|f| !allowlist.is_path_skipped(&f.path))
        .collect();

    if scannable.is_empty() {
        return Vec::new();
    }

    // use parallel processing for large diffs
    if scannable.len() >= PARALLEL_FILE_THRESHOLD {
        let mut findings: Vec<Finding> = scannable
            .par_iter()
            .flat_map(|file| scan_file(file, scanner, allowlist))
            .collect();
        findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        findings
    } else {
        let mut findings = Vec::new();
        for file in &scannable {
            findings.extend(scan_file(file, scanner, allowlist));
        }
        findings
    }
}

/// scan a single file's added lines for secrets.
/// returns findings for this file only.
fn scan_file(
    file: &DiffFile,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<Finding> {
    let is_doc = allowlist.is_documentation_file(&file.path);
    let num_rules = scanner.rules.len();

    // reusable bitset for candidate rules (avoids per-line vec allocation)
    let mut candidate_bits = vec![false; num_rules];
    let mut findings = Vec::new();

    for added_line in &file.added_lines {
        let ctx = ScanLineContext {
            file_path: &file.path,
            line_number: added_line.line_number,
            line: &added_line.content,
            scanner,
            allowlist,
            is_doc_file: is_doc,
        };
        scan_line(&ctx, &mut candidate_bits, &mut findings);
    }

    findings
}

/// check if a rule targets password-type secrets
fn is_password_rule(rule_id: &str) -> bool {
    rule_id == "generic-password-assignment" || rule_id == "password-in-url"
}

/// check if a rule extracts credentials from connection strings/URLs.
/// these rules need full stopword filtering but use standard entropy checks,
/// not the password strength heuristic.
fn is_credential_rule(rule_id: &str) -> bool {
    rule_id.starts_with("database-connection-string-")
        || rule_id == "redis-connection-string"
}

/// context for scanning a single line
struct ScanLineContext<'a> {
    file_path: &'a str,
    line_number: usize,
    line: &'a [u8],
    scanner: &'a CompiledScanner,
    allowlist: &'a CompiledAllowlist,
    is_doc_file: bool,
}

/// scan a single line against all rules using the aho-corasick pre-filter.
/// uses a reusable bitset to avoid allocations per line.
fn scan_line(
    ctx: &ScanLineContext<'_>,
    candidate_bits: &mut [bool],
    findings: &mut Vec<Finding>,
) {
    // clear bitset
    for bit in candidate_bits.iter_mut() {
        *bit = false;
    }

    // step 2: aho-corasick keyword pre-filter
    // find which rules have keywords present in this line
    let mut has_candidates = false;
    for mat in ctx.scanner.automaton.find_iter(ctx.line) {
        let pattern_idx = mat.pattern().as_usize();
        if let Some(rule_indices) = ctx.scanner.keyword_to_rules.get(pattern_idx) {
            for &rule_idx in rule_indices {
                if !candidate_bits[rule_idx] {
                    candidate_bits[rule_idx] = true;
                    has_candidates = true;
                }
            }
        }
    }

    if !has_candidates {
        return;
    }

    // step 3: regex matching only for candidate rules
    for (rule_idx, &is_candidate) in candidate_bits.iter().enumerate() {
        if !is_candidate || rule_idx >= ctx.scanner.rules.len() {
            continue;
        }

        let rule = &ctx.scanner.rules[rule_idx];

        // evaluate all matches for this rule on the line, not just the first.
        // if the first match is filtered (allowlist/stopword/var-ref), a later
        // match on the same line could still be a real secret.
        for captures in rule.regex.captures_iter(ctx.line) {
            // step 4: extract secret value via capture group
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

            // step 5: per-rule allowlist check
            if ctx.allowlist.is_rule_allowlisted(&rule.id, secret, ctx.file_path) {
                continue;
            }

            // step 6: variable reference detection
            if ctx.allowlist.is_variable_reference(secret) {
                continue;
            }

            // step 7: stopword filter.
            // tier 1 rules (no entropy threshold) only check for placeholder
            // patterns (e.g. XXXX...) to avoid false positives on format
            // examples, but skip word-based stopwords since tokens like
            // sk_test_ inherently contain "test".
            // tier 2+ rules, password rules, and credential rules get the
            // full stopword check.
            if rule.entropy_threshold.is_some()
                || is_password_rule(&rule.id)
                || is_credential_rule(&rule.id)
            {
                if ctx.allowlist.contains_stopword(secret) {
                    continue;
                }
            } else if ctx.allowlist.is_placeholder_pattern(secret) {
                continue;
            }

            // step 8: hash detection - skip hashes
            if hash_detect::is_hash_in_context(secret, ctx.line) {
                continue;
            }

            // step 8.5: password strength heuristic for password rules.
            // weak/placeholder passwords are allowed through; only strong
            // passwords are flagged as real secrets.
            if is_password_rule(&rule.id) && !password::is_strong_password(secret) {
                continue;
            }

            // step 9: entropy evaluation (if rule requires it).
            // password rules skip entropy check -- the password strength
            // heuristic (step 8.5) already validates these. the entropy
            // min-length threshold would otherwise reject strong passwords
            // shorter than MIN_ENTROPY_LENGTH (e.g. 12-char passwords).
            if !is_password_rule(&rule.id) {
                if let Some(mut threshold) = rule.entropy_threshold {
                    // apply global override as a floor (never lower a rule's threshold)
                    if let Some(override_val) = ctx.allowlist.entropy_threshold_override {
                        threshold = threshold.max(override_val);
                    }
                    // apply doc file bonus (raise threshold = less likely to flag)
                    if ctx.is_doc_file {
                        threshold += ctx.allowlist.doc_entropy_bonus();
                    }
                    if !entropy::passes_entropy_check(secret, threshold) {
                        continue;
                    }
                }
            }

            findings.push(Finding {
                file: ctx.file_path.to_string(),
                line: ctx.line_number,
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
    use crate::scanner::rules::{compile_rules, Rule, RuleAllowlist};

    fn make_rule(id: &str, pattern: &str, group: usize, keywords: Vec<&str>, threshold: Option<f64>) -> Rule {
        Rule {
            id: id.into(),
            description: id.into(),
            regex_pattern: pattern.into(),
            secret_group: group,
            keywords: keywords.into_iter().map(String::from).collect(),
            entropy_threshold: threshold,
            allowlist: RuleAllowlist::default(),
        }
    }

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

    fn default_al() -> CompiledAllowlist {
        CompiledAllowlist::default_allowlist().unwrap()
    }

    #[test]
    fn scan_empty_files() {
        let scanner = make_scanner(vec![
            make_rule("test", r"secret_[a-z]+", 0, vec!["secret_"], None),
        ]);
        let al = default_al();
        let files: Vec<DiffFile> = vec![];
        let findings = scan(&files, &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_detects_keyword_match() {
        let scanner = make_scanner(vec![
            make_rule("aws-access-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "config.rs",
            vec![(42, b"let key = \"AKIAIOSFODNN7ABCDEFGH\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].file, "config.rs");
        assert_eq!(findings[0].line, 42);
    }

    #[test]
    fn scan_skips_no_keyword_match() {
        let scanner = make_scanner(vec![
            make_rule("aws-access-key", r"AKIA[A-Z0-9]{16}", 0, vec!["akia"], None),
        ]);
        let al = default_al();
        // line has no "akia" keyword
        let file = make_file("config.rs", vec![(1, b"let x = 42;")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_deleted_files() {
        let scanner = make_scanner(vec![
            make_rule("test", r"AKIA[A-Z0-9]{16}", 0, vec!["akia"], None),
        ]);
        let al = default_al();
        let mut file = make_file(
            "old.rs",
            vec![(1, b"AKIAIOSFODNN7ABCDEFGH")],
        );
        file.is_deleted = true;
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_binary_files() {
        let scanner = make_scanner(vec![
            make_rule("test", r"AKIA[A-Z0-9]{16}", 0, vec!["akia"], None),
        ]);
        let al = default_al();
        let mut file = make_file(
            "image.png",
            vec![(1, b"AKIAIOSFODNN7ABCDEFGH")],
        );
        file.is_binary = true;
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_entropy_filter_blocks_low_entropy() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], Some(3.5)),
        ]);
        let al = default_al();
        // low entropy secret (repeated chars)
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aaaaaaaaaaaaaaaaaaaaaaaa\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_entropy_filter_allows_high_entropy() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], Some(3.0)),
        ]);
        let al = default_al();
        // high entropy secret
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_skips_sha256_hash_with_context() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], None),
        ]);
        let al = default_al();
        // the captured value is exactly 64 hex chars (SHA-256) in a line with checksum context
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_detects_hex_secret_at_hash_length() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], None),
        ]);
        let al = default_al();
        // 64 hex chars but no hash context - should be detected as a secret
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1, "hex secret without hash context should be detected");
    }

    #[test]
    fn scan_skips_git_commit_hash_in_context() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], None),
        ]);
        let al = default_al();
        // 40-char hex (SHA-1) in a line with "commit" context
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_multiple_files_multiple_rules() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
            make_rule("github-token", r"(ghp_[0-9a-zA-Z]{36})", 1, vec!["ghp_"], None),
        ]);
        let al = default_al();
        let file1 = make_file(
            "aws.rs",
            vec![(10, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")],
        );
        let file2 = make_file(
            "github.rs",
            vec![(20, b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"")],
        );
        let findings = scan(&[file1, file2], &scanner, &al);
        assert_eq!(findings.len(), 2);
        // with parallel processing, order may vary, so check both exist
        assert!(findings.iter().any(|f| f.rule_id == "aws-key" && f.file == "aws.rs"));
        assert!(findings.iter().any(|f| f.rule_id == "github-token" && f.file == "github.rs"));
    }

    #[test]
    fn scan_capture_group_zero_uses_full_match() {
        let scanner = make_scanner(vec![
            make_rule("prefix-token", r"ghp_[0-9a-zA-Z]{36}", 0, vec!["ghp_"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "test.rs",
            vec![(1, b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].matched_value,
            b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        );
    }

    #[test]
    fn scan_with_default_rules_detects_aws_key() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let file = make_file(
            "config.py",
            vec![(5, b"AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.iter().any(|f| f.rule_id == "aws-access-key-id"),
            "expected aws-access-key-id finding, got: {:?}", findings
        );
    }

    #[test]
    fn scan_with_default_rules_detects_github_token() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let file = make_file(
            "config.py",
            vec![(5, b"TOKEN = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.iter().any(|f| f.rule_id == "github-personal-access-token"),
            "expected github-personal-access-token finding, got: {:?}", findings
        );
    }

    #[test]
    fn scan_with_default_rules_detects_pem_key() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let file = make_file(
            "key.pem",
            vec![(1, b"-----BEGIN RSA PRIVATE KEY-----")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.iter().any(|f| f.rule_id == "pem-private-key"),
            "expected pem-private-key finding, got: {:?}", findings
        );
    }

    // -- allowlist integration tests --

    #[test]
    fn scan_skips_allowlisted_paths() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        let al = default_al();
        // file in a vendor directory
        let file = make_file(
            "node_modules/some-lib/config.js",
            vec![(1, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip vendor directory files");
    }

    #[test]
    fn scan_skips_binary_extension_paths() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "screenshot.png",
            vec![(1, b"AKIAIOSFODNN7ABCDEFGH")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip binary file extensions");
    }

    #[test]
    fn scan_skips_generated_files() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "package-lock.json",
            vec![(1, b"AKIAIOSFODNN7ABCDEFGH")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip generated files");
    }

    #[test]
    fn scan_skips_stopword_secrets() {
        // stopword filtering only applies to rules with entropy thresholds (tier 2+)
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], Some(3.5)),
        ]);
        let al = default_al();
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"example_token_for_testing\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip secrets containing stopwords");
    }

    #[test]
    fn scan_skips_variable_references() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"${DB_PASSWORD}\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip variable references");
    }

    #[test]
    fn scan_skips_process_env_references() {
        let scanner = make_scanner(vec![
            make_rule("generic-secret", r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#, 1, vec!["secret"], None),
        ]);
        let al = default_al();
        let file = make_file(
            "config.js",
            vec![(1, b"secret = \"process.env.SECRET_KEY\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip process.env references");
    }

    #[test]
    fn scan_with_per_rule_allowlist() {
        let rules = vec![Rule {
            id: "aws-key".to_string(),
            description: "AWS key".to_string(),
            regex_pattern: r"(AKIA[A-Z0-9]{16})".to_string(),
            secret_group: 1,
            keywords: vec!["akia".to_string()],
            entropy_threshold: None,
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
        }];
        let scanner = compile_rules(&rules).unwrap();
        let al = crate::config::build_allowlist(
            &crate::config::ProjectConfig::default(),
            &rules,
        ).unwrap();

        // the example key should be skipped
        let file1 = make_file(
            "config.py",
            vec![(5, b"key = \"AKIAIOSFODNN7EXAMPLE\"")],
        );
        let findings1 = scan(&[file1], &scanner, &al);
        assert!(findings1.is_empty(), "example AWS key should be allowlisted");

        // a real key should be detected
        let file2 = make_file(
            "config.py",
            vec![(5, b"key = \"AKIAIOSFODNN7ABCDEFG\"")],
        );
        let findings2 = scan(&[file2], &scanner, &al);
        assert_eq!(findings2.len(), 1, "real AWS key should be detected");
    }

    #[test]
    fn scan_doc_files_get_entropy_bonus() {
        let scanner = make_scanner(vec![
            make_rule(
                "generic-secret",
                r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
                1,
                vec!["secret"],
                Some(3.0),
            ),
        ]);
        let al = default_al();

        // a value with moderate entropy that would trigger in source code
        let line = b"secret = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"";

        // in a source file, it should be detected
        let src_file = make_file("src/config.rs", vec![(1, line)]);
        let findings_src = scan(&[src_file], &scanner, &al);
        assert!(!findings_src.is_empty(), "should detect in source files");

        // in a doc file (README.md), the raised threshold allows it through.
        // with 1.0 bonus, threshold becomes 4.0 instead of 3.0, so the
        // same string that triggers in source should not trigger in docs.
        let doc_file = make_file("README.md", vec![(1, line)]);
        let findings_doc = scan(&[doc_file], &scanner, &al);
        assert!(
            findings_doc.len() <= findings_src.len(),
            "doc files should not flag more than source files"
        );
    }

    #[test]
    fn scan_detects_second_match_when_first_filtered() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        // set up an allowlist that skips the example key but not a real one
        let rules = vec![crate::scanner::rules::Rule {
            id: "aws-key".to_string(),
            description: "AWS key".to_string(),
            regex_pattern: r"(AKIA[A-Z0-9]{16})".to_string(),
            secret_group: 1,
            keywords: vec!["akia".to_string()],
            entropy_threshold: None,
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
        }];
        let al = crate::config::build_allowlist(
            &crate::config::ProjectConfig::default(),
            &rules,
        ).unwrap();

        // line has two AWS keys: first is the allowlisted example, second is real
        let file = make_file(
            "config.py",
            vec![(5, b"keys = [\"AKIAIOSFODNN7EXAMPLE\", \"AKIAIOSFODNN7ABCDEFG\"]")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1, "should detect the second (real) key even though first is allowlisted");
        assert_eq!(findings[0].matched_value, b"AKIAIOSFODNN7ABCDEFG");
    }

    #[test]
    fn scan_skips_files_with_no_added_lines() {
        let scanner = make_scanner(vec![
            make_rule("test", r"secret_[a-z]+", 0, vec!["secret_"], None),
        ]);
        let al = default_al();
        let file = DiffFile {
            path: "empty.rs".to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: vec![],
        };
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_parallel_with_many_files() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
        ]);
        let al = default_al();
        // create enough files to trigger parallel processing
        let files: Vec<DiffFile> = (0..10)
            .map(|i| make_file(
                &format!("file{}.rs", i),
                vec![(1, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")],
            ))
            .collect();
        let findings = scan(&files, &scanner, &al);
        assert_eq!(findings.len(), 10);
    }
}
