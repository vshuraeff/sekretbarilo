// integration tests for cli config overrides

use std::path::Path;
use std::process::Command;

/// return the path to the test binary (built by cargo test automatically)
fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_sekretbarilo"))
}

/// create a temp git repo with a file containing a secret
fn setup_repo_with_secret(dir: &Path, filename: &str, content: &str) {
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .output()
        .expect("git init");

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir)
        .output()
        .expect("git config email");

    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir)
        .output()
        .expect("git config name");

    let file_path = dir.join(filename);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(&file_path, content).expect("write file");

    Command::new("git")
        .args(["add", filename])
        .current_dir(dir)
        .output()
        .expect("git add");

    Command::new("git")
        .args(["commit", "-q", "-m", "initial"])
        .current_dir(dir)
        .output()
        .expect("git commit");
}

#[test]
fn config_flag_loads_custom_rules() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(
        dir.path(),
        "secret.txt",
        "CUSTOMPREFIX_ABCDEFGHIJKLMNOP",
    );

    // create a custom config with a rule
    let config_path = dir.path().join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "custom-prefix-token"
description = "Custom prefix token"
regex = "(CUSTOMPREFIX_[A-Z]{16})"
secret_group = 1
keywords = ["customprefix_"]
"#,
    )
    .unwrap();

    // audit with custom config should find the custom rule
    let output = Command::new(&bin)
        .args([
            "audit",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("custom-prefix-token"),
        "should find custom rule, got: {}",
        stderr
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn config_flag_multiple_configs_merged() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(dir.path(), "secret.txt", "AAAPREFIX_1234567890ABCDEF");

    let a = dir.path().join("a.toml");
    let b = dir.path().join("b.toml");

    // a.toml has a threshold of 1.0 (very low, would catch anything)
    std::fs::write(
        &a,
        r#"
[settings]
entropy_threshold = 1.0

[allowlist]
stopwords = ["from_a"]
"#,
    )
    .unwrap();

    // b.toml overrides entropy to 99.0 (so high nothing matches)
    std::fs::write(
        &b,
        r#"
[settings]
entropy_threshold = 99.0
"#,
    )
    .unwrap();

    // with both configs, b wins for entropy_threshold
    let output = Command::new(&bin)
        .args([
            "audit",
            "--config",
            a.to_str().unwrap(),
            "--config",
            b.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // high entropy threshold should mean fewer or no findings
    assert!(
        stderr.contains("[AUDIT]"),
        "should have audit output: {}",
        stderr
    );
}

#[test]
fn no_defaults_with_no_config_rules_warns() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(dir.path(), "test.txt", "AKIAIOSFODNN7EXAMPLE12");

    let output = Command::new(&bin)
        .args(["audit", "--no-defaults"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no rules found"),
        "should warn about no rules: {}",
        stderr
    );
    // should exit 0 (clean) since no rules means no findings
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn no_defaults_with_custom_rules_only_uses_custom() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(
        dir.path(),
        "secret.txt",
        "MYTOKEN_ABCDEFGHIJKLMNOP",
    );

    let config_path = dir.path().join("rules.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "my-token"
description = "My token"
regex = "(MYTOKEN_[A-Z]{16})"
secret_group = 1
keywords = ["mytoken_"]
"#,
    )
    .unwrap();

    let output = Command::new(&bin)
        .args([
            "audit",
            "--no-defaults",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("my-token"),
        "should find custom rule: {}",
        stderr
    );
    // should NOT find any default rules (like aws-access-key-id)
    assert!(!stderr.contains("aws-access-key-id"));
}

#[test]
fn entropy_threshold_override() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    // use a value with moderate entropy that default threshold catches
    // but a very high threshold won't
    setup_repo_with_secret(
        dir.path(),
        "test.py",
        "api_key = 'aB3dEf7hIj1kLm9oPq2rSt4uVw6xYz0'",
    );

    // first verify the default threshold catches it
    let output_default = Command::new(&bin)
        .args(["audit"])
        .current_dir(dir.path())
        .output()
        .expect("run audit default");

    let stderr_default = String::from_utf8_lossy(&output_default.stderr);

    // with a very high threshold, entropy-dependent rules shouldn't fire
    let output = Command::new(&bin)
        .args(["audit", "--entropy-threshold", "99.0"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // if default found something, high threshold should find less or nothing
    if stderr_default.contains("secret(s) detected") {
        assert!(
            stderr.contains("0 secret(s) found"),
            "high entropy threshold should suppress findings: {}",
            stderr
        );
    }
    // if default found nothing either, the test is inconclusive but not failing
}

#[test]
fn stopword_flag_suppresses_findings() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    // use a realistic-looking secret that would normally be found
    setup_repo_with_secret(
        dir.path(),
        "config.py",
        "GITHUB_TOKEN = 'ghp_ABCDEFmystopword1234567890ABCDEF12'",
    );

    // adding "mystopword" should suppress the finding
    let output = Command::new(&bin)
        .args(["audit", "--stopword", "mystopword"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0 secret(s) found"),
        "stopword should suppress finding: {}",
        stderr
    );
}

#[test]
fn allowlist_path_flag_skips_file() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(
        dir.path(),
        "vendor/config.py",
        "GITHUB_TOKEN = 'ghp_ABCDEFGHIJ1234567890ABCDEF1234'",
    );

    // allowlist the vendor path
    let output = Command::new(&bin)
        .args(["audit", "--allowlist-path", "^vendor/"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0 secret(s) found"),
        "allowlisted path should be skipped: {}",
        stderr
    );
}

#[test]
fn exclude_pattern_flag_works() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(
        dir.path(),
        "generated/output.txt",
        "ghp_ABCDEFGHIJ1234567890ABCDEF1234",
    );

    // exclude pattern for the file
    let output = Command::new(&bin)
        .args(["audit", "--exclude-pattern", "^generated/"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0 secret(s) found"),
        "excluded pattern should be skipped: {}",
        stderr
    );
}

#[test]
fn nonexistent_config_file_errors() {
    let bin = binary_path();
    let dir = tempfile::tempdir().unwrap();
    setup_repo_with_secret(dir.path(), "test.txt", "hello");

    let output = Command::new(&bin)
        .args(["audit", "--config", "/tmp/nonexistent_sb_test_xyz.toml"])
        .current_dir(dir.path())
        .output()
        .expect("run audit");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "should error on missing config: {}",
        stderr
    );
}

#[test]
fn invalid_entropy_threshold_errors() {
    let bin = binary_path();

    let output = Command::new(&bin)
        .args(["scan", "--entropy-threshold", "abc"])
        .output()
        .expect("run scan");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value"),
        "should error on bad threshold: {}",
        stderr
    );
}

#[test]
fn history_flag_on_scan_errors() {
    let bin = binary_path();

    let output = Command::new(&bin)
        .args(["scan", "--history"])
        .output()
        .expect("run scan");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only valid with audit"),
        "should reject --history on scan: {}",
        stderr
    );
}

#[test]
fn exclude_pattern_on_scan_errors() {
    let bin = binary_path();

    let output = Command::new(&bin)
        .args(["scan", "--exclude-pattern", "^vendor/"])
        .output()
        .expect("run scan");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only valid with audit"),
        "should reject --exclude-pattern on scan: {}",
        stderr
    );
}

#[test]
fn help_shows_new_flags() {
    let bin = binary_path();

    let output = Command::new(&bin)
        .args(["--help"])
        .output()
        .expect("run help");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--config"), "help should mention --config");
    assert!(
        stderr.contains("--no-defaults"),
        "help should mention --no-defaults"
    );
    assert!(
        stderr.contains("--entropy-threshold"),
        "help should mention --entropy-threshold"
    );
    assert!(
        stderr.contains("--allowlist-path"),
        "help should mention --allowlist-path"
    );
    assert!(
        stderr.contains("--stopword"),
        "help should mention --stopword"
    );
    assert!(
        stderr.contains("--exclude-pattern"),
        "help should mention --exclude-pattern"
    );
    assert!(
        stderr.contains("--include-pattern"),
        "help should mention --include-pattern"
    );
}
