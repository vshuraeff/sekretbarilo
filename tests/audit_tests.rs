// audit mode integration tests

use std::process::Command;

use sekretbarilo::audit;
use sekretbarilo::config;
use sekretbarilo::scanner::engine::scan;
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

/// create a temp git repo with some tracked files.
/// returns the tempdir (owns the directory lifetime) and the repo root path.
fn create_test_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    Command::new("git")
        .args(["init"])
        .current_dir(root)
        .output()
        .expect("git init failed");

    // configure git user for commits
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
        let full_path = root.join(path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full_path, content).unwrap();
    }

    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();

    Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(root)
        .output()
        .unwrap();

    dir
}

// -- tests --

#[test]
fn audit_finds_secrets_in_tracked_files() {
    // create a repo with a file containing an AWS key
    let dir = create_test_repo(&[
        ("config.py", "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7ABCDEFG\"\n"),
        ("readme.txt", "this is a readme\n"),
    ]);

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(exit_code, 1, "should detect secrets and return exit code 1");
}

#[test]
fn audit_clean_repo_returns_zero() {
    let dir = create_test_repo(&[
        ("src/main.rs", "fn main() {\n    println!(\"hello\");\n}\n"),
        ("readme.md", "# my project\n"),
    ]);

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(exit_code, 0, "clean repo should return exit code 0");
}

#[test]
fn audit_skips_binary_files() {
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

    // write a binary file with a null byte (should be skipped)
    let mut binary_content = b"AKIAIOSFODNN7ABCDEFG".to_vec();
    binary_content.push(0);
    binary_content.extend_from_slice(b"more content");
    std::fs::write(root.join("data.bin"), &binary_content).unwrap();

    // also write a clean text file
    std::fs::write(root.join("readme.txt"), "clean file\n").unwrap();

    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(root)
        .output()
        .unwrap();

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(root, &options);
    assert_eq!(exit_code, 0, "binary files should be skipped");
}

#[test]
fn audit_empty_repo() {
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

    // create an empty commit so git is initialized but no files tracked
    Command::new("git")
        .args(["commit", "--allow-empty", "-m", "empty"])
        .current_dir(root)
        .output()
        .unwrap();

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(root, &options);
    assert_eq!(exit_code, 0, "empty repo should return 0");
}

#[test]
fn audit_exit_codes_match_scan_convention() {
    // 0 = no secrets, 1 = secrets found, 2 = incomplete scan / error
    // test the "secrets found" case
    let dir = create_test_repo(&[(
        "secrets.py",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
    )]);

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(exit_code, 1);

    // test the "clean" case
    let clean_dir = create_test_repo(&[("clean.txt", "nothing secret here\n")]);

    let clean_code = audit::run_audit(clean_dir.path(), &audit::AuditOptions::default());
    assert_eq!(clean_code, 0);
}

#[test]
fn audit_exit_code_2_on_unreadable_file() {
    // exit=2 when no secrets found but some files couldn't be read (incomplete scan)
    let dir = create_test_repo(&[
        ("clean.txt", "nothing secret here\n"),
        ("will_delete.txt", "also clean content\n"),
    ]);

    // remove the file from disk but keep it tracked in git index
    std::fs::remove_file(dir.path().join("will_delete.txt")).unwrap();

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(
        exit_code, 2,
        "should return 2 when files are unreadable (incomplete scan)"
    );
}

#[test]
fn audit_read_file_to_diff_produces_valid_difffile() {
    let dir = tempfile::tempdir().unwrap();
    let content = "line one\nline two\nline three\n";
    std::fs::write(dir.path().join("test.txt"), content).unwrap();

    let diff = audit::read_file_to_diff("test.txt", dir.path(), None).unwrap();
    assert_eq!(diff.path, "test.txt");
    assert!(!diff.is_binary);
    assert!(!diff.is_new);
    assert!(!diff.is_deleted);
    assert_eq!(diff.added_lines.len(), 3);

    // the scanner should be able to process this DiffFile
    let (scanner, allowlist) = default_scanner_and_allowlist();
    let _findings = scan(&[diff], &scanner, &allowlist);
    // just verifying it doesn't panic
}

#[test]
fn audit_list_tracked_files_works() {
    let dir = create_test_repo(&[
        ("src/main.rs", "fn main() {}\n"),
        ("readme.md", "hello\n"),
    ]);

    let (files, skipped) = audit::list_tracked_files(dir.path()).unwrap();
    assert!(files.contains(&"src/main.rs".to_string()));
    assert!(files.contains(&"readme.md".to_string()));
    assert_eq!(skipped, 0);
}

#[test]
fn audit_skips_vendor_and_generated_files() {
    // the existing path filter should skip vendor files during audit
    let dir = create_test_repo(&[
        ("vendor/lib/secret.py", "AWS_SECRET = \"AKIAIOSFODNN7ABCDEFG\"\n"),
        ("node_modules/pkg/index.js", "const key = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\";\n"),
        ("src/clean.rs", "fn main() {}\n"),
    ]);

    let options = audit::AuditOptions::default();
    let exit_code = audit::run_audit(dir.path(), &options);
    // vendor and node_modules paths should be skipped by the default path allowlist
    assert_eq!(exit_code, 0, "vendor/generated paths should be skipped");
}

// -- history scanning tests --

use sekretbarilo::audit::history;

/// create a test repo with multiple commits for history scanning tests.
/// returns the tempdir and a vec of commit hashes in order (oldest first).
fn create_multi_commit_repo(
    commits: &[(&str, &[(&str, &str)])],
) -> (tempfile::TempDir, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    Command::new("git")
        .args(["init"])
        .current_dir(root)
        .output()
        .expect("git init failed");

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(root)
        .output()
        .unwrap();

    let mut hashes = Vec::new();

    for (message, files) in commits {
        for (path, content) in *files {
            let full_path = root.join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full_path, content).unwrap();
        }

        Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", message])
            .current_dir(root)
            .output()
            .unwrap();

        // get the hash of the commit we just made
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .unwrap();
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        hashes.push(hash);
    }

    (dir, hashes)
}

#[test]
fn history_scan_finds_secret_in_past_commit() {
    // commit 1: add a secret
    // commit 2: remove the secret (overwrite with clean content)
    let (dir, _hashes) = create_multi_commit_repo(&[
        (
            "add secret",
            &[("config.py", "AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"\n")],
        ),
        (
            "remove secret",
            &[("config.py", "AWS_KEY = \"<redacted>\"\n")],
        ),
    ]);

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(
        exit_code, 1,
        "history scan should find the secret in the first commit"
    );
}

#[test]
fn history_scan_handles_root_commits() {
    // a repo with a single commit (root commit with a secret)
    let (dir, _hashes) = create_multi_commit_repo(&[(
        "initial with secret",
        &[("secret.py", "TOKEN = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"\n")],
    )]);

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(
        exit_code, 1,
        "should find secret in root commit"
    );
}

#[test]
fn history_scan_deduplication() {
    // same secret committed in two different commits to the same file
    // (append more content but secret stays)
    let (dir, _hashes) = create_multi_commit_repo(&[
        (
            "initial secret",
            &[("config.py", "KEY = \"AKIAIOSFODNN7ABCDEFG\"\n")],
        ),
        (
            "keep secret, add line",
            &[("config.py", "KEY = \"AKIAIOSFODNN7ABCDEFG\"\nother = true\n")],
        ),
    ]);

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };

    // load scanner for direct test of dedup
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();

    let commits = history::list_commits(dir.path(), &options).unwrap();
    assert!(commits.len() >= 2, "should have at least 2 commits");

    // the run_history_audit should deduplicate
    let audit_config = config::AuditConfig::default();
    let exit_code = history::run_history_audit(dir.path(), &options, &scanner, &al, &audit_config);
    assert_eq!(exit_code, 1, "should find the secret");
}

#[test]
fn history_scan_empty_history() {
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

    // no commits at all
    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };

    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();

    let audit_config = config::AuditConfig::default();
    let exit_code = history::run_history_audit(root, &options, &scanner, &al, &audit_config);
    assert_eq!(exit_code, 0, "empty history should return 0");
}

#[test]
fn history_list_commits_returns_correct_info() {
    let (dir, hashes) = create_multi_commit_repo(&[
        ("first commit", &[("a.txt", "hello\n")]),
        ("second commit", &[("b.txt", "world\n")]),
    ]);

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };

    let commits = history::list_commits(dir.path(), &options).unwrap();
    assert_eq!(commits.len(), 2, "should have 2 commits");

    // rev-list returns newest first
    assert_eq!(commits[0].hash, hashes[1]);
    assert_eq!(commits[1].hash, hashes[0]);
    assert_eq!(commits[0].author, "Test User");
    assert_eq!(commits[1].author, "Test User");
    // dates should be non-empty ISO format
    assert!(!commits[0].date.is_empty());
    assert!(!commits[1].date.is_empty());
}

#[test]
fn history_get_commit_diff_returns_diff() {
    let (dir, hashes) = create_multi_commit_repo(&[
        ("add file", &[("test.txt", "line1\nline2\n")]),
    ]);

    let diff = history::get_commit_diff(&hashes[0], true, dir.path()).unwrap();
    // root commit with a file should produce some diff output
    assert!(!diff.is_empty(), "root commit diff should not be empty");

    // the diff should reference the file we added
    let diff_str = String::from_utf8_lossy(&diff);
    assert!(
        diff_str.contains("test.txt"),
        "diff should contain the file name"
    );
}

#[test]
fn history_clean_repo_returns_zero() {
    let (dir, _hashes) = create_multi_commit_repo(&[
        ("clean commit", &[("readme.md", "# project\n")]),
        ("another clean", &[("src/main.rs", "fn main() {}\n")]),
    ]);

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(exit_code, 0, "history scan of clean repo should return 0");
}

// -- audit filter tests (task 6) --

#[test]
fn filter_branch_limits_commits_to_specified_branch() {
    // create a repo, add commits on main, create a feature branch with a secret,
    // then verify branch filter only scans the specified branch
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // init repo
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

    // commit on main: clean
    std::fs::write(root.join("readme.md"), "# clean project\n").unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "clean main"])
        .current_dir(root)
        .output()
        .unwrap();

    // rename default branch to main (in case it's "master")
    Command::new("git")
        .args(["branch", "-M", "main"])
        .current_dir(root)
        .output()
        .unwrap();

    // create feature branch with a secret
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(root)
        .output()
        .unwrap();
    std::fs::write(
        root.join("secret.py"),
        "KEY = \"AKIAIOSFODNN7ABCDEFG\"\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "add secret on feature"])
        .current_dir(root)
        .output()
        .unwrap();

    // go back to main
    Command::new("git")
        .args(["checkout", "main"])
        .current_dir(root)
        .output()
        .unwrap();

    // scan only main branch history: should be clean
    let options_main = audit::AuditOptions {
        history: true,
        branch: Some("main".to_string()),
        ..Default::default()
    };
    let exit_main = audit::run_audit(root, &options_main);
    assert_eq!(
        exit_main, 0,
        "main branch should be clean (secret is on feature branch)"
    );

    // scan feature branch history: should find the secret
    let options_feature = audit::AuditOptions {
        history: true,
        branch: Some("feature".to_string()),
        ..Default::default()
    };
    let exit_feature = audit::run_audit(root, &options_feature);
    assert_eq!(
        exit_feature, 1,
        "feature branch should contain the secret"
    );
}

#[test]
fn filter_date_range_limits_commits() {
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

    // commit with a backdated author date (2023-01-01)
    std::fs::write(
        root.join("old_secret.py"),
        "KEY = \"AKIAIOSFODNN7ABCDEFG\"\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "old secret"])
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2023-01-15T12:00:00")
        .env("GIT_COMMITTER_DATE", "2023-01-15T12:00:00")
        .output()
        .unwrap();

    // commit with a recent date (2025-06-01)
    std::fs::write(root.join("clean.txt"), "no secrets here\n").unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "recent clean"])
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2025-06-01T12:00:00")
        .env("GIT_COMMITTER_DATE", "2025-06-01T12:00:00")
        .output()
        .unwrap();

    // scan only 2025 commits: should be clean
    let options_2025 = audit::AuditOptions {
        history: true,
        since: Some("2025-01-01".to_string()),
        ..Default::default()
    };
    let exit_2025 = audit::run_audit(root, &options_2025);
    assert_eq!(
        exit_2025, 0,
        "2025 commits only should be clean"
    );

    // scan only 2023 commits: should find the secret
    let options_2023 = audit::AuditOptions {
        history: true,
        since: Some("2023-01-01".to_string()),
        until: Some("2023-12-31".to_string()),
        ..Default::default()
    };
    let exit_2023 = audit::run_audit(root, &options_2023);
    assert_eq!(
        exit_2023, 1,
        "2023 commits should contain the secret"
    );
}

#[test]
fn filter_combined_branch_and_date() {
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

    // initial commit on main (early date)
    std::fs::write(root.join("readme.md"), "# project\n").unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2023-01-01T12:00:00")
        .env("GIT_COMMITTER_DATE", "2023-01-01T12:00:00")
        .output()
        .unwrap();

    Command::new("git")
        .args(["branch", "-M", "main"])
        .current_dir(root)
        .output()
        .unwrap();

    // feature branch with secret at a later date
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(root)
        .output()
        .unwrap();
    std::fs::write(
        root.join("config.py"),
        "TOKEN = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "secret on feature"])
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2024-06-15T12:00:00")
        .env("GIT_COMMITTER_DATE", "2024-06-15T12:00:00")
        .output()
        .unwrap();

    Command::new("git")
        .args(["checkout", "main"])
        .current_dir(root)
        .output()
        .unwrap();

    // combined: feature branch + date range covering the secret
    let options = audit::AuditOptions {
        history: true,
        branch: Some("feature".to_string()),
        since: Some("2024-01-01".to_string()),
        until: Some("2024-12-31".to_string()),
        ..Default::default()
    };
    let exit_code = audit::run_audit(root, &options);
    assert_eq!(
        exit_code, 1,
        "combined filter should find the secret on feature in 2024"
    );

    // combined: feature branch + date range NOT covering the secret
    let options_miss = audit::AuditOptions {
        history: true,
        branch: Some("feature".to_string()),
        since: Some("2025-01-01".to_string()),
        ..Default::default()
    };
    let exit_miss = audit::run_audit(root, &options_miss);
    assert_eq!(
        exit_miss, 0,
        "combined filter with wrong date should miss the secret"
    );
}

#[test]
fn filter_invalid_branch_produces_error() {
    let dir = create_test_repo(&[("readme.md", "hello\n")]);

    let options = audit::AuditOptions {
        history: true,
        branch: Some("nonexistent-branch-xyz".to_string()),
        ..Default::default()
    };
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(
        exit_code, 2,
        "invalid branch should return error exit code 2"
    );
}

#[test]
fn filter_without_history_produces_error() {
    let dir = create_test_repo(&[("readme.md", "hello\n")]);

    // branch without --history
    let options_branch = audit::AuditOptions {
        history: false,
        branch: Some("main".to_string()),
        ..Default::default()
    };
    let exit_branch = audit::run_audit(dir.path(), &options_branch);
    assert_eq!(
        exit_branch, 2,
        "branch filter without --history should return error"
    );

    // since without --history
    let options_since = audit::AuditOptions {
        history: false,
        since: Some("2024-01-01".to_string()),
        ..Default::default()
    };
    let exit_since = audit::run_audit(dir.path(), &options_since);
    assert_eq!(
        exit_since, 2,
        "since filter without --history should return error"
    );

    // until without --history
    let options_until = audit::AuditOptions {
        history: false,
        until: Some("2024-12-31".to_string()),
        ..Default::default()
    };
    let exit_until = audit::run_audit(dir.path(), &options_until);
    assert_eq!(
        exit_until, 2,
        "until filter without --history should return error"
    );
}

#[test]
fn history_exit_code_2_on_commit_diff_failure() {
    // exit=2 when no secrets found but some commits failed to diff (incomplete scan).
    // we corrupt a git tree object so that `git diff-tree` fails for one commit.
    let (dir, hashes) = create_multi_commit_repo(&[
        ("first clean commit", &[("readme.md", "# project\n")]),
        ("second clean commit", &[("src/main.rs", "fn main() {}\n")]),
    ]);

    // corrupt the tree object of the second commit so git diff-tree fails.
    // get the tree hash for the second commit
    let output = Command::new("git")
        .args(["rev-parse", &format!("{}^{{tree}}", hashes[1])])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let tree_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // find the loose object file for this tree (objects/<first2>/<rest>)
    let obj_dir = dir
        .path()
        .join(".git/objects")
        .join(&tree_hash[..2]);
    let obj_file = obj_dir.join(&tree_hash[2..]);

    // git makes loose objects read-only; fix permissions before corrupting
    if obj_file.exists() {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&obj_file).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&obj_file, perms).unwrap();
        std::fs::write(&obj_file, b"corrupted").unwrap();
    }

    let options = audit::AuditOptions {
        history: true,
        ..Default::default()
    };
    let exit_code = audit::run_audit(dir.path(), &options);
    assert_eq!(
        exit_code, 2,
        "should return 2 when commit diffs fail (incomplete history scan)"
    );
}
