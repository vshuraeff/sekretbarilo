// false positive test suite (phase 8.5)
//
// verifies that common non-secret patterns are NOT flagged by the scanner.
// each test category exercises the full pipeline (parse_diff -> scan) with
// realistic code snippets that should pass through without findings.

use sekretbarilo::config;
use sekretbarilo::diff::parser::{parse_diff, AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{scan, Finding};
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

// -- helpers --

fn default_scanner_and_allowlist() -> (
    sekretbarilo::scanner::rules::CompiledScanner,
    sekretbarilo::config::allowlist::CompiledAllowlist,
) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();
    (scanner, al)
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

fn scan_line(path: &str, line: &[u8]) -> Vec<Finding> {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(path, vec![(1, line)]);
    scan(&[file], &scanner, &al)
}

fn assert_no_findings(path: &str, line: &[u8]) {
    let findings = scan_line(path, line);
    assert!(
        findings.is_empty(),
        "expected no findings for line {:?} in {}, got: {:?}",
        String::from_utf8_lossy(line),
        path,
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, String::from_utf8_lossy(&f.matched_value)))
            .collect::<Vec<_>>()
    );
}

fn scan_lines(path: &str, lines: &[&[u8]]) -> Vec<Finding> {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        path,
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| (i + 1, *l))
            .collect(),
    );
    scan(&[file], &scanner, &al)
}

/// build a realistic unified diff for a single new file with the given path and lines.
fn make_new_file_diff(path: &str, lines: &[&str]) -> Vec<u8> {
    let mut diff = format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{count} @@\n",
        path = path,
        count = lines.len(),
    );
    for line in lines {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    diff.into_bytes()
}

/// run the full pipeline: parse diff -> scan -> return findings
fn scan_diff(raw_diff: &[u8]) -> Vec<Finding> {
    let files = parse_diff(raw_diff);
    let (scanner, al) = default_scanner_and_allowlist();
    scan(&files, &scanner, &al)
}

// ============================================================================
// category 1: UUIDs in non-password context
// ============================================================================

#[test]
fn fp_uuid_v4_as_config_id() {
    assert_no_findings(
        "src/config.rs",
        b"let session_id = \"550e8400-e29b-41d4-a716-446655440000\";",
    );
}

#[test]
fn fp_uuid_in_database_migration() {
    assert_no_findings(
        "migrations/001_init.sql",
        b"INSERT INTO users (id) VALUES ('6ba7b810-9dad-11d1-80b4-00c04fd430c8');",
    );
}

#[test]
fn fp_uuid_as_trace_id() {
    assert_no_findings(
        "src/tracing.rs",
        b"trace_id: \"123e4567-e89b-12d3-a456-426614174000\"",
    );
}

#[test]
fn fp_uuid_in_json_fixture() {
    assert_no_findings(
        "test/fixtures/data.json",
        b"\"correlation_id\": \"f47ac10b-58cc-4372-a567-0e02b2c3d479\"",
    );
}

#[test]
fn fp_multiple_uuids_in_yaml() {
    let lines: &[&[u8]] = &[
        b"resource_id: \"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11\"",
        b"parent_id: \"b1ffcd00-ad1c-5ef9-cc7e-7cca0e491b22\"",
        b"tenant_id: \"c2aade11-be2d-6fa0-dd8f-8ddb1f502c33\"",
    ];
    let findings = scan_lines("config/settings.yaml", lines);
    assert!(
        findings.is_empty(),
        "UUIDs in YAML config should not trigger findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// category 2: CSS color codes (#ffffff)
// ============================================================================

#[test]
fn fp_css_hex_color_6_digit() {
    assert_no_findings("src/styles.css", b"color: #ff5733;");
}

#[test]
fn fp_css_hex_color_3_digit() {
    assert_no_findings("src/styles.css", b"background: #abc;");
}

#[test]
fn fp_css_hex_color_in_js() {
    assert_no_findings(
        "src/theme.js",
        b"const primaryColor = \"#1a2b3c\";",
    );
}

#[test]
fn fp_css_multiple_colors() {
    let lines: &[&[u8]] = &[
        b"  --primary: #336699;",
        b"  --secondary: #ff6600;",
        b"  --background: #ffffff;",
        b"  --text: #333333;",
        b"  --danger: #dc3545;",
    ];
    let findings = scan_lines("src/variables.css", lines);
    assert!(
        findings.is_empty(),
        "CSS colors should not trigger findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn fp_css_rgba_values() {
    assert_no_findings(
        "src/styles.css",
        b"background: rgba(255, 128, 0, 0.5);",
    );
}

#[test]
fn fp_css_hex_color_8_digit_alpha() {
    assert_no_findings("src/styles.css", b"color: #ff573380;");
}

// ============================================================================
// category 3: base64-encoded non-secret data
// ============================================================================

#[test]
fn fp_base64_image_data_uri() {
    assert_no_findings(
        "src/icons.ts",
        b"const icon = \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA\";",
    );
}

#[test]
fn fp_base64_in_test_fixture() {
    assert_no_findings(
        "tests/fixtures/data.rs",
        b"let encoded = \"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U=\";",
    );
}

#[test]
fn fp_base64_utf8_content() {
    // base64 of "The quick brown fox jumps over the lazy dog"
    assert_no_findings(
        "src/encoding.rs",
        b"let data = \"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==\";",
    );
}

#[test]
fn fp_base64_in_html_template() {
    assert_no_findings(
        "templates/email.html",
        b"<img src=\"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7\" />",
    );
}

// ============================================================================
// category 4: long variable names matching patterns
// ============================================================================

#[test]
fn fp_long_variable_name_with_secret_keyword() {
    assert_no_findings(
        "src/config.rs",
        b"let secret_manager_client_timeout_milliseconds = 5000;",
    );
}

#[test]
fn fp_long_variable_name_with_password_keyword() {
    assert_no_findings(
        "src/auth.rs",
        b"let password_validation_minimum_length = 12;",
    );
}

#[test]
fn fp_long_variable_name_with_api_key_keyword() {
    assert_no_findings(
        "src/client.rs",
        b"let api_key_rotation_interval_seconds = 3600;",
    );
}

#[test]
fn fp_function_name_with_secret_keyword() {
    assert_no_findings(
        "src/vault.rs",
        b"fn get_secret_from_vault(path: &str) -> Result<String, Error> {",
    );
}

#[test]
fn fp_function_name_with_password_keyword() {
    assert_no_findings(
        "src/auth.rs",
        b"fn validate_password_complexity(password: &str) -> bool {",
    );
}

#[test]
fn fp_struct_field_with_api_key_keyword() {
    assert_no_findings(
        "src/models.rs",
        b"    api_key_created_at: DateTime<Utc>,",
    );
}

#[test]
fn fp_constant_name_with_token_keyword() {
    assert_no_findings(
        "src/constants.rs",
        b"const BEARER_TOKEN_HEADER_NAME: &str = \"Authorization\";",
    );
}

#[test]
fn fp_enum_variant_with_secret_keyword() {
    assert_no_findings(
        "src/errors.rs",
        b"    SecretNotFoundInVault,",
    );
}

// ============================================================================
// category 5: regex patterns in source code that look like secrets
// ============================================================================

#[test]
fn fp_regex_pattern_for_aws_key_validation() {
    assert_no_findings(
        "src/validator.rs",
        b"let re = Regex::new(r\"AKIA[A-Z0-9]{16}\").unwrap();",
    );
}

#[test]
fn fp_regex_pattern_for_jwt_validation() {
    assert_no_findings(
        "src/auth.rs",
        b"let jwt_regex = r\"eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\";",
    );
}

#[test]
fn fp_regex_pattern_for_github_token() {
    assert_no_findings(
        "src/scanner.rs",
        b"let pattern = r\"ghp_[0-9a-zA-Z]{36,}\";",
    );
}

#[test]
fn fp_regex_in_test_assertion() {
    assert_no_findings(
        "tests/rules_test.rs",
        b"assert!(re.is_match(\"sk_live_aaaa1111bbbb2222cccc\"));",
    );
}

#[test]
fn fp_regex_pattern_in_comment() {
    assert_no_findings(
        "src/rules.rs",
        b"// matches patterns like: ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    );
}

#[test]
fn fp_regex_pattern_for_password_field() {
    assert_no_findings(
        "src/parser.rs",
        b"let password_regex = Regex::new(r\"password\\s*[=:]\\s*(.+)\").unwrap();",
    );
}

// ============================================================================
// category 6: hash values (MD5, SHA1, SHA256) in various contexts
// ============================================================================

#[test]
fn fp_sha256_checksum_in_dockerfile() {
    assert_no_findings(
        "Dockerfile",
        b"RUN echo \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  myfile.tar.gz\" | sha256sum -c",
    );
}

#[test]
fn fp_sha256_in_lockfile_like_content() {
    assert_no_findings(
        "src/verify.rs",
        b"let expected_hash = \"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e\";",
    );
}

#[test]
fn fp_sha1_in_integrity_check() {
    assert_no_findings(
        "src/integrity.rs",
        b"let sha1_digest = \"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\";",
    );
}

#[test]
fn fp_md5_checksum() {
    assert_no_findings(
        "src/checksum.rs",
        b"let md5_hash = \"d41d8cd98f00b204e9800998ecf8427e\";",
    );
}

#[test]
fn fp_sha256_in_subresource_integrity() {
    assert_no_findings(
        "templates/index.html",
        b"integrity=\"sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

#[test]
fn fp_multiple_hashes_in_checksums_file() {
    let lines: &[&[u8]] = &[
        b"d41d8cd98f00b204e9800998ecf8427e  empty.txt",
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  also-empty.txt",
        b"da39a3ee5e6b4b0d3255bfef95601890afd80709  nothing.bin",
    ];
    let findings = scan_lines("CHECKSUMS.txt", lines);
    assert!(
        findings.is_empty(),
        "hash values in checksum files should not trigger, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn fp_sha256_content_hash_in_rust() {
    assert_no_findings(
        "src/cache.rs",
        b"const EMPTY_SHA256: &str = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";",
    );
}

// ============================================================================
// category 7: commit SHAs in merge commits
// ============================================================================

#[test]
fn fp_commit_sha_in_changelog() {
    assert_no_findings(
        "CHANGELOG.md",
        b"- Fixed bug in parser (commit da39a3ee5e6b4b0d3255bfef95601890afd80709)",
    );
}

#[test]
fn fp_abbreviated_commit_sha_in_comment() {
    assert_no_findings(
        "src/main.rs",
        b"// see commit abc1234 for details on this change",
    );
}

#[test]
fn fp_merge_commit_reference() {
    assert_no_findings(
        "CHANGELOG.md",
        b"Merge commit 'da39a3ee5e6b4b0d3255bfef95601890afd80709' into main",
    );
}

#[test]
fn fp_cherry_pick_commit_reference() {
    assert_no_findings(
        "scripts/release.sh",
        b"git cherry-pick da39a3ee5e6b4b0d3255bfef95601890afd80709",
    );
}

#[test]
fn fp_revert_commit_reference() {
    assert_no_findings(
        "CHANGELOG.md",
        b"Revert commit a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    );
}

#[test]
fn fp_git_log_output_in_script() {
    let lines: &[&[u8]] = &[
        b"# commit log from last release",
        b"# da39a3ee5e6b4b0d3255bfef95601890afd80709 feat: add login",
        b"# 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 fix: typo in docs",
    ];
    let findings = scan_lines("scripts/changelog.sh", lines);
    assert!(
        findings.is_empty(),
        "commit SHAs in script comments should not trigger, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn fp_sha_in_github_compare_url() {
    assert_no_findings(
        "CHANGELOG.md",
        b"Full diff: https://github.com/user/repo/compare/abc1234...def5678",
    );
}

// ============================================================================
// category 8: mixed false positive scenarios (full pipeline integration)
// ============================================================================

#[test]
fn fp_full_pipeline_mixed_safe_content() {
    let diff = make_new_file_diff(
        "src/app.rs",
        &[
            "// configuration for the application",
            "let session_id = \"550e8400-e29b-41d4-a716-446655440000\";",
            "let color = \"#ff5733\";",
            "let hash = \"d41d8cd98f00b204e9800998ecf8427e\";",
            "let max_password_length = 128;",
        ],
    );
    let findings = scan_diff(&diff);
    assert!(
        findings.is_empty(),
        "mixed safe content should produce no findings, got: {:?}",
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, String::from_utf8_lossy(&f.matched_value)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fp_full_pipeline_documentation_with_examples() {
    let diff = make_new_file_diff(
        "docs/api-guide.md",
        &[
            "# API Authentication",
            "",
            "To authenticate, pass your API key in the header:",
            "",
            "```",
            "Authorization: Bearer YOUR_API_TOKEN_HERE",
            "```",
            "",
            "Example with curl:",
            "```bash",
            "curl -H \"Authorization: Bearer <your-token>\" https://api.example.com",
            "```",
        ],
    );
    let findings = scan_diff(&diff);
    assert!(
        findings.is_empty(),
        "documentation examples with placeholders should not trigger, got: {:?}",
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, String::from_utf8_lossy(&f.matched_value)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fp_full_pipeline_test_file_with_assertions() {
    let diff = make_new_file_diff(
        "tests/auth_test.rs",
        &[
            "fn test_password_validation() {",
            "    assert!(validate_password(\"test_placeholder_value\"));",
            "    assert!(!validate_password(\"short\"));",
            "    let api_key_format = Regex::new(r\"[A-Za-z0-9]{32}\").unwrap();",
            "    assert!(api_key_format.is_match(\"abcdef12345678901234567890abcdef\"));",
            "}",
        ],
    );
    let findings = scan_diff(&diff);
    assert!(
        findings.is_empty(),
        "test files with validation logic should not trigger, got: {:?}",
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, String::from_utf8_lossy(&f.matched_value)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fp_full_pipeline_ci_config_with_env_refs() {
    let diff = make_new_file_diff(
        "ci/deploy.yaml",
        &[
            "env:",
            "  DATABASE_URL: ${{ secrets.DATABASE_URL }}",
            "  API_KEY: ${{ secrets.API_KEY }}",
            "  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_KEY }}",
        ],
    );
    let findings = scan_diff(&diff);
    assert!(
        findings.is_empty(),
        "CI config with secret references should not trigger, got: {:?}",
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, String::from_utf8_lossy(&f.matched_value)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fp_numeric_only_assignments() {
    // numeric values assigned to password/secret fields should not trigger
    assert_no_findings(
        "src/config.rs",
        b"let password_max_attempts = 5;",
    );
    assert_no_findings(
        "src/config.rs",
        b"let secret_rotation_days = 90;",
    );
}

#[test]
fn fp_boolean_and_null_assignments() {
    assert_no_findings(
        "src/config.rs",
        b"let password_required = true;",
    );
    assert_no_findings(
        "src/config.rs",
        b"let secret_enabled = false;",
    );
}

#[test]
fn fp_type_annotations_with_keywords() {
    assert_no_findings(
        "src/types.rs",
        b"fn hash_password(password: &str) -> HashedPassword {",
    );
    assert_no_findings(
        "src/types.rs",
        b"struct SecretStore { secrets: HashMap<String, EncryptedSecret> }",
    );
}

#[test]
fn fp_import_statements_with_keywords() {
    assert_no_findings(
        "src/main.rs",
        b"use crate::config::secret_manager;",
    );
    assert_no_findings(
        "src/main.rs",
        b"from cryptography.hazmat.primitives import hashes as password_hasher",
    );
}

#[test]
fn fp_log_messages_with_keywords() {
    assert_no_findings(
        "src/auth.rs",
        b"log::info!(\"password reset email sent to user {}\", user_id);",
    );
    assert_no_findings(
        "src/auth.rs",
        b"tracing::debug!(\"api_key validation passed for client\");",
    );
}

#[test]
fn fp_error_messages_with_keywords() {
    assert_no_findings(
        "src/errors.rs",
        b"\"invalid password: must contain at least 8 characters\"",
    );
    assert_no_findings(
        "src/errors.rs",
        b"\"api_key not found in request headers\"",
    );
}
