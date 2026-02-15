// integration tests with realistic diffs (phase 8.3)
//
// each test constructs a realistic unified diff string, parses it through the
// full pipeline (parse_diff -> check_env_files / scan), and asserts on the
// combined output. this exercises the diff parser, scanner engine, allowlist,
// stopword, hash detection, and entropy filtering together.

use sekretbarilo::config;
use sekretbarilo::diff::check_env_files;
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

/// build a realistic unified diff for a single new file with the given path and lines.
/// each line is added at sequential line numbers starting from 1.
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

/// build a realistic unified diff for modifying an existing file.
/// added_lines is a list of (line_number, content) pairs grouped into a single hunk.
fn make_modified_file_diff(path: &str, start_line: usize, added_lines: &[&str]) -> Vec<u8> {
    let mut diff = format!(
        "diff --git a/{path} b/{path}\nindex 1234567..abcdefg 100644\n--- a/{path}\n+++ b/{path}\n@@ -0,0 +{start},{count} @@\n",
        path = path,
        start = start_line,
        count = added_lines.len(),
    );
    for line in added_lines {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    diff.into_bytes()
}

/// run the full pipeline: parse diff -> scan -> return findings
fn scan_diff(raw_diff: &[u8]) -> (Vec<DiffFile>, Vec<Finding>) {
    let files = parse_diff(raw_diff);
    let (scanner, al) = default_scanner_and_allowlist();
    let findings = scan(&files, &scanner, &al);
    (files, findings)
}

// ============================================================================
// test 1: .env file should be blocked
// ============================================================================

#[test]
fn integration_env_file_blocked() {
    let diff = make_new_file_diff(
        ".env",
        &[
            "DB_HOST=localhost",
            "DB_PASSWORD=supersecret123",
            "API_KEY=sk-1234567890",
        ],
    );
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert_eq!(env_check.blocked_files.len(), 1);
    assert_eq!(env_check.blocked_files[0], ".env");
}

#[test]
fn integration_env_local_blocked() {
    let diff = make_new_file_diff(".env.local", &["SECRET=mysecret"]);
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert_eq!(env_check.blocked_files.len(), 1);
    assert_eq!(env_check.blocked_files[0], ".env.local");
}

#[test]
fn integration_env_production_blocked() {
    let diff = make_new_file_diff(
        ".env.production",
        &["DATABASE_URL=postgres://prod:pass@db:5432/app"],
    );
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert_eq!(env_check.blocked_files.len(), 1);
}

// ============================================================================
// test 2: .env.example should be allowed
// ============================================================================

#[test]
fn integration_env_example_allowed() {
    let diff = make_new_file_diff(
        ".env.example",
        &[
            "DB_HOST=localhost",
            "DB_PASSWORD=changeme",
            "API_KEY=your_api_key_here",
        ],
    );
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert!(
        env_check.blocked_files.is_empty(),
        ".env.example should not be blocked"
    );
}

#[test]
fn integration_env_sample_allowed() {
    let diff = make_new_file_diff(".env.sample", &["SECRET=changeme"]);
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert!(env_check.blocked_files.is_empty());
}

#[test]
fn integration_env_template_allowed() {
    let diff = make_new_file_diff(".env.template", &["TOKEN=replace_me"]);
    let files = parse_diff(&diff);
    let env_check = check_env_files(&files);

    assert!(env_check.blocked_files.is_empty());
}

// ============================================================================
// test 3: AWS key in source code should be blocked
// ============================================================================

#[test]
fn integration_aws_key_in_source_blocked() {
    let diff = make_modified_file_diff(
        "src/config.py",
        15,
        &["AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7ABCDEFG\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "aws-access-key-id"),
        "AWS access key in source code should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_aws_key_in_deploy_script_blocked() {
    let diff = make_new_file_diff(
        "deploy.sh",
        &[
            "#!/bin/bash",
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7XYZWTUV",
            "export AWS_SECRET_ACCESS_KEY='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'",
            "aws s3 sync . s3://mybucket",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "aws-access-key-id"),
        "AWS key in deploy script should be detected"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "aws-secret-access-key"),
        "AWS secret key in deploy script should be detected"
    );
}

// ============================================================================
// test 4: AWS example key (AKIAIOSFODNN7EXAMPLE) should be allowed
// ============================================================================

#[test]
fn integration_aws_example_key_allowed() {
    let diff = make_modified_file_diff(
        "src/config.py",
        10,
        &[
            "# use the example key for testing",
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        !findings.iter().any(|f| f.rule_id == "aws-access-key-id"),
        "AWS example key (AKIAIOSFODNN7EXAMPLE) should be allowlisted, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// test 5: strong password in config should be blocked
// ============================================================================

#[test]
fn integration_strong_password_blocked() {
    let diff = make_modified_file_diff(
        "config/database.yml",
        5,
        &["production:", "  password: \"Kj8mP2xQ9vL4nR5tB7wY\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "generic-password-assignment"),
        "strong password should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_password_in_url_blocked() {
    let diff = make_modified_file_diff(
        "src/db.rs",
        20,
        &["let url = \"postgres://admin:Kj8mP2xQ9vL4nR5tB7wY@db.prod-host.com:5432/mydb\";"],
    );
    let (_, findings) = scan_diff(&diff);

    // should trigger either database-connection-string-postgres or password-in-url
    assert!(
        !findings.is_empty(),
        "password in database URL should be detected"
    );
}

// ============================================================================
// test 6: password=changeme should be allowed (stopword)
// ============================================================================

#[test]
fn integration_password_changeme_allowed() {
    let diff = make_modified_file_diff(
        "config/settings.py",
        8,
        &["password = \"changeme_please_update_this\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "password=changeme should be skipped by stopword filter, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_password_placeholder_allowed() {
    let diff = make_modified_file_diff(
        "config/app.toml",
        3,
        &["password = \"placeholder_value_replace_me\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "placeholder password should be skipped by stopword filter"
    );
}

// ============================================================================
// test 7: SHA-256 hash in code should be allowed
// ============================================================================

#[test]
fn integration_sha256_hash_allowed() {
    let diff = make_modified_file_diff("src/verify.rs", 30, &[
        "let expected_hash = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";",
    ]);
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "SHA-256 hash should not be flagged as a secret, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_sha1_hash_allowed() {
    let diff = make_modified_file_diff(
        "src/checksum.py",
        10,
        &["sha1 = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(findings.is_empty(), "SHA-1 hash should not be flagged");
}

#[test]
fn integration_md5_hash_allowed() {
    let diff = make_modified_file_diff(
        "checksums.txt",
        1,
        &["md5 checksum = \"d41d8cd98f00b204e9800998ecf8427e\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(findings.is_empty(), "MD5 hash should not be flagged");
}

// ============================================================================
// test 8: git commit hash should be allowed
// ============================================================================

#[test]
fn integration_git_commit_hash_allowed() {
    let diff = make_modified_file_diff(
        "CHANGELOG.md",
        5,
        &[
            "## v1.2.0",
            "",
            "- fix: resolve login issue (commit da39a3ee5e6b4b0d3255bfef95601890afd80709)",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "git commit hash in changelog should not be flagged, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// test 9: private key (PEM) should be blocked
// ============================================================================

#[test]
fn integration_pem_private_key_blocked() {
    let diff = make_new_file_diff(
        "certs/server.key",
        &[
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA2a2rwplBQLSgHBFNPOL+NX/qJY0GN9fUbdC8W76EYVTaIR1O",
            "jYQWJLCp7GnfP6hnRj7g9v3KwM4cMpZ/8zNzEXample1234567890abcdefghijkl",
            "-----END RSA PRIVATE KEY-----",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "pem-private-key"),
        "PEM private key should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_pem_ec_private_key_blocked() {
    let diff = make_new_file_diff(
        "keys/ec.pem",
        &[
            "-----BEGIN EC PRIVATE KEY-----",
            "MHQCAQEEIBkg0P+hafLzMFnG+Gmc1F0ixQxaK1EJLeJhJxMqw2OfoAcGBSuBBAAi",
            "-----END EC PRIVATE KEY-----",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "pem-private-key"),
        "EC private key should be detected"
    );
}

// ============================================================================
// test 10: password in README as example should be allowed
// ============================================================================

#[test]
fn integration_password_in_readme_example_allowed() {
    // documentation files get an entropy bonus that raises the threshold,
    // plus "example" is a stopword. passwords in docs should not block.
    let diff = make_modified_file_diff(
        "README.md",
        50,
        &[
            "## Configuration",
            "",
            "Set your database password in the config file:",
            "",
            "```yaml",
            "password: \"your_example_password_here\"",
            "```",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "password example in README should not be flagged, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_api_key_in_docs_with_sample_allowed() {
    let diff = make_modified_file_diff(
        "docs/setup.md",
        10,
        &["Set your API key:", "api_key = \"sample_api_key_for_docs\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "sample API key in docs should be skipped by stopword filter"
    );
}

// ============================================================================
// test 11: variable reference $DB_PASSWORD should be allowed
// ============================================================================

#[test]
fn integration_variable_reference_dollar_brace_allowed() {
    let diff = make_modified_file_diff(
        "docker-compose.yml",
        12,
        &["    environment:", "      - password=\"${DB_PASSWORD}\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "${{DB_PASSWORD}} should be skipped as variable reference, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_variable_reference_process_env_allowed() {
    let diff = make_modified_file_diff(
        "src/config.js",
        5,
        &["const secret = process.env.SECRET_KEY;"],
    );
    let (_, findings) = scan_diff(&diff);

    // the value "process.env.SECRET_KEY" is bare code (no quotes), so
    // password/secret regex rules won't capture it. no findings expected.
    assert!(
        findings.is_empty(),
        "bare process.env reference should not be flagged, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_variable_reference_in_quotes_allowed() {
    let diff = make_modified_file_diff("config.py", 10, &["secret = \"${SECRET_KEY}\""]);
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "quoted ${{SECRET_KEY}} should be skipped as variable reference, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// test 12: base64 bearer token should be blocked
// ============================================================================

#[test]
fn integration_bearer_token_blocked() {
    let diff = make_modified_file_diff(
        "src/api_client.py",
        25,
        &[
            "headers = {",
            "    \"Authorization\": \"Bearer aB3dEf7hIj1kLmN0pQrStUvW\"",
            "}",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "http-bearer-token"),
        "bearer token should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_basic_auth_blocked() {
    let diff = make_modified_file_diff(
        "src/http_client.rs",
        18,
        &["let auth = \"Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NQ==\";"],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "http-basic-auth"),
        "HTTP basic auth should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// test 13: binary file in diff should be skipped
// ============================================================================

#[test]
fn integration_binary_file_skipped() {
    // construct a diff that includes a binary file alongside a source file
    let diff = b"\
diff --git a/assets/logo.png b/assets/logo.png
new file mode 100644
Binary files /dev/null and b/assets/logo.png differ
diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -0,0 +1 @@
+fn main() { println!(\"hello\"); }
";
    let (files, findings) = scan_diff(diff);

    // binary file should be parsed as binary
    assert!(files[0].is_binary, "logo.png should be detected as binary");
    assert!(
        files[0].added_lines.is_empty(),
        "binary file should have no added lines"
    );

    // no findings from the binary file or the clean source file
    assert!(
        findings.is_empty(),
        "clean source + binary file should produce no findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_binary_extension_path_skipped() {
    // even if a file with a binary extension has "added lines" (unusual but possible),
    // the path allowlist should skip it
    let (scanner, al) = default_scanner_and_allowlist();
    let file = DiffFile {
        path: "assets/icon.png".to_string(),
        is_new: true,
        is_deleted: false,
        is_renamed: false,
        is_binary: false, // not marked binary, but path has .png extension
        added_lines: vec![AddedLine {
            line_number: 1,
            content: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
        }],
    };
    let findings = scan(&[file], &scanner, &al);

    assert!(
        findings.is_empty(),
        ".png path should be skipped by path allowlist regardless of is_binary flag"
    );
}

// ============================================================================
// additional integration: multi-file realistic diff
// ============================================================================

#[test]
fn integration_multi_file_realistic_diff() {
    // a realistic multi-file commit with a mix of findings and safe content
    let diff = b"\
diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1,2 @@
+DB_HOST=localhost
+DB_PASSWORD=supersecret
diff --git a/src/config.py b/src/config.py
--- a/src/config.py
+++ b/src/config.py
@@ -0,0 +10,2 @@
+AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"
+password = \"changeme\"
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -0,0 +50,1 @@
+api_key = \"example_key_for_readme\"
diff --git a/assets/logo.png b/assets/logo.png
Binary files /dev/null and b/assets/logo.png differ
";
    let files = parse_diff(diff);
    let (scanner, al) = default_scanner_and_allowlist();
    let findings = scan(&files, &scanner, &al);
    let env_check = check_env_files(&files);

    // .env should be blocked
    assert_eq!(env_check.blocked_files.len(), 1);
    assert_eq!(env_check.blocked_files[0], ".env");

    // AWS key in src/config.py should be detected
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "aws-access-key-id" && f.file == "src/config.py"),
        "AWS key in config.py should be detected"
    );

    // password=changeme in src/config.py should be skipped (stopword)
    assert!(
        !findings
            .iter()
            .any(|f| f.file == "src/config.py" && f.rule_id == "generic-password-assignment"),
        "password=changeme should be skipped"
    );

    // README.md example key should be skipped (stopword "example")
    assert!(
        !findings.iter().any(|f| f.file == "README.md"),
        "example key in README should be skipped"
    );

    // binary file should produce no findings
    assert!(
        !findings.iter().any(|f| f.file == "assets/logo.png"),
        "binary file should produce no findings"
    );
}

#[test]
fn integration_env_deleted_not_blocked() {
    // deleting a .env file should NOT block the commit
    let diff = b"\
diff --git a/.env b/.env
deleted file mode 100644
--- a/.env
+++ /dev/null
@@ -1,3 +0,0 @@
-DB_HOST=localhost
-DB_PASSWORD=secret
-API_KEY=sk-12345
";
    let files = parse_diff(diff);
    let env_check = check_env_files(&files);

    assert!(files[0].is_deleted);
    assert!(
        env_check.blocked_files.is_empty(),
        "deleting .env should not block the commit"
    );
}

// ============================================================================
// integration: line number preservation through full pipeline
// ============================================================================

#[test]
fn integration_line_numbers_preserved() {
    let diff = b"\
diff --git a/src/config.rs b/src/config.rs
--- a/src/config.rs
+++ b/src/config.rs
@@ -0,0 +42 @@
+let key = \"AKIAIOSFODNN7ABCDEFG\";
";
    let (_, findings) = scan_diff(diff);

    assert!(!findings.is_empty(), "should detect AWS key");
    assert_eq!(
        findings[0].line, 42,
        "line number should be preserved from diff hunk header"
    );
    assert_eq!(findings[0].file, "src/config.rs");
}

// ============================================================================
// integration: multiple secrets in a single file
// ============================================================================

#[test]
fn integration_multiple_secrets_single_file() {
    let diff = make_new_file_diff(
        "leaked_config.py",
        &[
            "# production credentials (DO NOT COMMIT)",
            "AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"",
            "GITHUB_TOKEN = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"",
            "-----BEGIN RSA PRIVATE KEY-----",
            "STRIPE_KEY = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        ],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.len() >= 3,
        "expected at least 3 different secrets detected, got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| format!("{}:{}", f.rule_id, f.line))
            .collect::<Vec<_>>()
    );

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"aws-access-key-id"));
    assert!(rule_ids.contains(&"github-personal-access-token"));
    assert!(rule_ids.contains(&"pem-private-key"));
}

// ============================================================================
// integration: jwt token should be blocked
// ============================================================================

#[test]
fn integration_jwt_token_blocked() {
    let diff = make_modified_file_diff("src/auth.js", 10, &[
        "const token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\";",
    ]);
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.iter().any(|f| f.rule_id == "jwt-token"),
        "JWT token should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// integration: database connection strings
// ============================================================================

#[test]
fn integration_postgres_connection_string_blocked() {
    let diff = make_modified_file_diff(
        "src/db.py",
        5,
        &["db_url = \"postgres://admin:Xk9#mQ2!vR7$nP4w@db.prod-host.com:5432/mydb\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "database-connection-string-postgres"),
        "postgres connection string should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn integration_mongodb_connection_string_blocked() {
    let diff = make_modified_file_diff(
        "src/db.js",
        8,
        &["const uri = \"mongodb://admin:Xk9#mQ2!vR7$nP4w@mongo.prod-host.com:27017/app\";"],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "database-connection-string-mongodb"),
        "mongodb connection string should be detected"
    );
}

// ============================================================================
// integration: generated / vendor files skipped
// ============================================================================

#[test]
fn integration_vendor_directory_skipped() {
    let diff = make_new_file_diff(
        "node_modules/some-pkg/config.js",
        &["module.exports = { key: \"AKIAIOSFODNN7ABCDEFG\" };"],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "files in node_modules should be skipped by path allowlist"
    );
}

#[test]
fn integration_lockfile_skipped() {
    let diff = make_new_file_diff(
        "package-lock.json",
        &["\"resolved\": \"https://registry.npmjs.org/secret/-/secret-1.0.0.tgz\""],
    );
    let (_, findings) = scan_diff(&diff);

    assert!(
        findings.is_empty(),
        "package-lock.json should be skipped by path allowlist"
    );
}

// ============================================================================
// integration: clean commit with no secrets
// ============================================================================

#[test]
fn integration_clean_commit_no_findings() {
    let diff = b"\
diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -0,0 +1,5 @@
+fn main() {
+    let config = load_config();
+    let port = 8080;
+    println!(\"server starting on port {}\", port);
+}
diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -0,0 +5,1 @@
+serde = \"1.0\"
";
    let (files, findings) = scan_diff(diff);
    let env_check = check_env_files(&files);

    assert!(env_check.blocked_files.is_empty());
    assert!(
        findings.is_empty(),
        "clean commit should have no findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}
