// integration tests for --search and --search-regex on the audit command.
// working-tree mode and --history mode, plus search-only mode via --no-defaults.

use std::path::Path;
use std::process::Command;

use sekretbarilo::audit;
use sekretbarilo::config;

/// helper: load default config/rules and call run_audit with given options.
fn run_audit_with_defaults(repo_root: &Path, options: &audit::AuditOptions) -> i32 {
    let config = config::load_project_config(Some(repo_root)).unwrap_or_default();
    let rules = config::load_rules_with_config(&config).unwrap();
    let compiled = sekretbarilo::scanner::rules::compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&config, &rules).unwrap();
    audit::run_audit(repo_root, options, &config, &compiled, &allowlist)
}

/// create a temp git repo with a single initial commit of the given files.
fn init_repo_with_files(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    Command::new("git")
        .args(["init"])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(root)
        .output()
        .unwrap();

    for (path, content) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full, content).unwrap();
    }

    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "--no-verify", "-m", "initial"])
        .current_dir(root)
        .output()
        .unwrap();
    dir
}

/// create a repo with multiple commits, each committing the given snapshot.
fn init_multi_commit_repo(commits: &[(&str, &[(&str, &str)])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    Command::new("git")
        .args(["init"])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(root)
        .output()
        .unwrap();

    for (message, files) in commits {
        for (path, content) in *files {
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, content).unwrap();
        }
        Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "--no-verify", "-m", message])
            .current_dir(root)
            .output()
            .unwrap();
    }
    dir
}

// -- working tree search --

#[test]
fn audit_search_literal_finds_match_in_tracked_file() {
    let dir = init_repo_with_files(&[
        ("src/hello.rs", "fn greet() { println!(\"hi\"); }\n"),
        ("readme.txt", "nothing to see\n"),
    ]);
    let options = audit::AuditOptions {
        search_literals: vec!["greet".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(
        exit, 1,
        "literal search should find 'greet' in tracked file and exit non-zero"
    );
}

#[test]
fn audit_search_regex_finds_match_in_tracked_file() {
    let dir = init_repo_with_files(&[(
        "src/lib.rs",
        "let api_key = \"secret\";\nlet api_token = 1;\n",
    )]);
    let options = audit::AuditOptions {
        search_regexes: vec![r"api_(key|token)".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(exit, 1, "regex search should match api_key/api_token lines");
}

#[test]
fn audit_search_literal_does_not_expand_metachars() {
    // `api.key` must be literal dot, not any char
    let dir = init_repo_with_files(&[("src/a.rs", "let apiXkey = 1;\nlet other = 2;\n")]);
    let options = audit::AuditOptions {
        search_literals: vec!["api.key".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(
        exit, 0,
        "literal 'api.key' must not match 'apiXkey' (dot is literal)"
    );
}

#[test]
fn audit_search_literal_no_match_returns_zero() {
    let dir = init_repo_with_files(&[("src/a.rs", "let answer = 42;\n")]);
    let options = audit::AuditOptions {
        search_literals: vec!["nonexistent_token_xyz".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(exit, 0, "no search match must return clean exit");
}

// -- history search --

#[test]
fn audit_history_search_finds_content_in_past_commit() {
    // commit 1 introduces the phrase; commit 2 removes it.
    let dir = init_multi_commit_repo(&[
        ("add phrase", &[("note.txt", "special_phrase_42 is here\n")]),
        ("remove phrase", &[("note.txt", "<redacted>\n")]),
    ]);
    let options = audit::AuditOptions {
        history: true,
        search_literals: vec!["special_phrase_42".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(
        exit, 1,
        "history search must find phrase in first commit even after removal"
    );
}

#[test]
fn audit_history_search_regex_across_history() {
    let dir = init_multi_commit_repo(&[
        ("introduce", &[("config.rs", "let TOKEN_ABC = 1;\n")]),
        ("rename", &[("config.rs", "let TOKEN_XYZ = 2;\n")]),
    ]);
    let options = audit::AuditOptions {
        history: true,
        search_regexes: vec![r"TOKEN_[A-Z]{3}".to_string()],
        ..Default::default()
    };
    let exit = run_audit_with_defaults(dir.path(), &options);
    assert_eq!(exit, 1, "history regex search must match across commits");
}

// -- search combined with --no-defaults (pure search mode) --

#[test]
fn audit_search_with_no_defaults_only_reports_search_matches() {
    // a file with a plain word and no real secret.
    // --no-defaults disables built-in secret rules, so the only finding
    // should come from the user search.
    let dir = init_repo_with_files(&[("notes.md", "Meeting about widgets\n")]);

    // load config with no rules (simulate --no-defaults)
    let mut cfg = config::ProjectConfig::default();
    cfg.rules.clear();
    let compiled = sekretbarilo::scanner::rules::compile_rules(&[]).unwrap();
    let allowlist = config::build_allowlist(&cfg, &[]).unwrap();

    let options = audit::AuditOptions {
        search_literals: vec!["widgets".to_string()],
        ..Default::default()
    };
    let exit = audit::run_audit(dir.path(), &options, &cfg, &compiled, &allowlist);
    assert_eq!(
        exit, 1,
        "search-only mode must surface the user-search match even with zero secret rules"
    );
}

// -- search pattern validation --

#[test]
fn audit_invalid_search_regex_rejected_before_file_filter_elision() {
    // even when exclude-pattern eliminates every file, an invalid --search-regex
    // must still be reported (exit 2), not silently ignored.
    let dir = init_repo_with_files(&[("src/a.rs", "let x = 1;\n")]);

    let mut cfg = config::ProjectConfig::default();
    cfg.audit.exclude_patterns = vec![".*".to_string()];
    let rules = config::load_rules_with_config(&cfg).unwrap();
    let compiled = sekretbarilo::scanner::rules::compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&cfg, &rules).unwrap();

    let options = audit::AuditOptions {
        search_regexes: vec!["[invalid".to_string()],
        ..Default::default()
    };
    let exit = audit::run_audit(dir.path(), &options, &cfg, &compiled, &allowlist);
    assert_eq!(
        exit, 2,
        "invalid regex must surface even when the filtered file list is empty"
    );
}

#[test]
fn cli_invalid_search_regex_exits_2_via_binary() {
    // exercise the full cli path (parse_cli -> run_audit_cmd), not run_audit directly:
    // an invalid --search-regex must exit 2 with a sanitized error on stderr.
    let dir = init_repo_with_files(&[("src/a.rs", "let x = 1;\n")]);

    let output = Command::new(env!("CARGO_BIN_EXE_sekretbarilo"))
        .args(["audit", "--search-regex", "[invalid"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid --search-regex via the binary must exit 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid regex search pattern"),
        "stderr should explain the invalid regex, got: {}",
        stderr
    );
}
