// configuration failures: a layer that is not UTF-8 is a parse error, `scan` validates its
// configuration even with nothing staged, and the blocking agent hooks fail closed on a trusted
// layer that cannot be read or parsed and on an allowlist that does not compile, without echoing
// config content. untrusted in-workspace layers stay ignored without being parsed.

mod common;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::IsolatedEnv;
use serde_json::json;

const MARKER: &str = "SYNTHETIC_PRIVATE_MARKER";
const ALLOWLIST_CATEGORY: &str = "an allowlist path, stopword, regex or key pattern is invalid";

fn git(env: &IsolatedEnv, repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// a git repository at `<home>/work/repo`, so `<home>/work` is an ancestor layer the hooks trust.
fn repo_under_home(env: &IsolatedEnv) -> PathBuf {
    let repo = env.home().join("work/repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(env, &repo, &["init", "-q"]);
    git(env, &repo, &["config", "user.email", "test@test.invalid"]);
    git(env, &repo, &["config", "user.name", "Test"]);
    std::fs::write(repo.join("notes.txt"), "ordinary text\n").unwrap();
    git(env, &repo, &["add", "notes.txt"]);
    commit(env, &repo, "initial");
    repo
}

fn commit(env: &IsolatedEnv, repo: &Path, message: &str) {
    git(
        env,
        repo,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "--no-verify",
            "-m",
            message,
        ],
    );
}

fn user_layer(env: &IsolatedEnv) -> PathBuf {
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("sekretbarilo.toml")
}

fn run_with_stdin(env: &IsolatedEnv, args: &[&str], cwd: &Path, stdin: &[u8]) -> Output {
    let mut child = env
        .command()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let _ = input.write_all(stdin);
    drop(input);
    let mut output = child.wait_with_output().unwrap();
    output.stdout = reader.join().unwrap();
    output
}

fn check_file(env: &IsolatedEnv, repo: &Path) -> Output {
    let file = repo.join("notes.txt");
    env.command()
        .args(["check-file", file.to_str().unwrap()])
        .current_dir(repo)
        .output()
        .unwrap()
}

fn check_codex(env: &IsolatedEnv, repo: &Path, tool: &str) -> Output {
    let command = if tool == "Bash" {
        "echo hello".to_owned()
    } else {
        "*** Begin Patch\n*** Add File: clean.rs\n+const VALUE: u8 = 1;\n*** End Patch\n".to_owned()
    };
    let payload = serde_json::to_vec(&json!({
        "session_id": "session", "hook_event_name": "PreToolUse", "tool_name": tool,
        "tool_input": {"command": command}, "cwd": repo,
    }))
    .unwrap();
    run_with_stdin(env, &["check-codex", "--stdin-json"], repo, &payload)
}

/// every blocking hook fails closed: check-file and check-codex (Bash and apply_patch) exit 2
/// with a nonempty reason that holds no config content.
fn assert_hooks_fail_closed(env: &IsolatedEnv, repo: &Path, context: &str) -> Vec<String> {
    let mut reasons = Vec::new();
    let outputs = [
        ("check-file", check_file(env, repo)),
        ("check-codex Bash", check_codex(env, repo, "Bash")),
        (
            "check-codex apply_patch",
            check_codex(env, repo, "apply_patch"),
        ),
    ];
    for (hook, output) in outputs {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{context}: {hook}: {stderr}");
        assert!(!stderr.trim().is_empty(), "{context}: {hook}: empty reason");
        assert!(
            !stdout.contains(MARKER) && !stderr.contains(MARKER),
            "{context}: {hook} echoed config content: {stderr}"
        );
        reasons.push(stderr.into_owned());
    }
    reasons
}

fn assert_hooks_allow(env: &IsolatedEnv, repo: &Path, context: &str) {
    for (hook, output) in [
        ("check-file", check_file(env, repo)),
        ("check-codex Bash", check_codex(env, repo, "Bash")),
        (
            "check-codex apply_patch",
            check_codex(env, repo, "apply_patch"),
        ),
    ] {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{context}: {hook}: {stderr}");
        assert!(
            stderr.contains("ignoring untrusted in-workspace config"),
            "{context}: {hook}: {stderr}"
        );
        assert!(!stderr.contains(MARKER), "{context}: {hook}: {stderr}");
    }
}

fn malformed_layers() -> Vec<(&'static str, Vec<u8>)> {
    // a latin-1 byte in a comment: the file is not utf-8, so it is not toml
    let mut latin1 = b"# caf\xe9 ".to_vec();
    latin1.extend_from_slice(MARKER.as_bytes());
    latin1.extend_from_slice(b"\n[settings]\n");
    vec![
        (
            "invalid toml",
            format!("[settings]\nentropy_threshold = '{MARKER}' # {MARKER}\n").into_bytes(),
        ),
        (
            "unknown class",
            format!("[settings.rule_classes]\n'{MARKER}' = true\n").into_bytes(),
        ),
        ("invalid utf-8", latin1),
    ]
}

#[test]
fn malformed_trusted_user_and_ancestor_layers_make_the_hooks_fail_closed() {
    for (label, content) in malformed_layers() {
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(user_layer(&env), &content).unwrap();
        assert_hooks_fail_closed(&env, &repo, &format!("user layer, {label}"));

        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(env.home().join("work/.sekretbarilo.toml"), &content).unwrap();
        assert_hooks_fail_closed(&env, &repo, &format!("ancestor layer, {label}"));
    }
}

#[test]
fn malformed_committed_workspace_layer_makes_the_hooks_fail_closed() {
    for (label, content) in malformed_layers() {
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(repo.join(".sekretbarilo.toml"), &content).unwrap();
        git(&env, &repo, &["add", ".sekretbarilo.toml"]);
        commit(&env, &repo, "commit a malformed layer");
        assert_hooks_fail_closed(&env, &repo, &format!("committed layer, {label}"));
    }
}

#[test]
fn malformed_untrusted_workspace_layer_is_ignored_without_parsing() {
    for (label, content) in malformed_layers() {
        // untracked
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(repo.join(".sekretbarilo.toml"), &content).unwrap();
        assert_hooks_allow(&env, &repo, &format!("untracked layer, {label}"));

        // committed clean, then modified in the working tree
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(repo.join(".sekretbarilo.toml"), "[settings]\n").unwrap();
        git(&env, &repo, &["add", ".sekretbarilo.toml"]);
        commit(&env, &repo, "commit a valid layer");
        std::fs::write(repo.join(".sekretbarilo.toml"), &content).unwrap();
        assert_hooks_allow(&env, &repo, &format!("dirty layer, {label}"));
    }
}

#[test]
fn hook_allowlist_compile_errors_report_a_fixed_category() {
    for config in [
        format!("[allowlist]\npaths = [\"{MARKER}[\"]\n"),
        format!("[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\"{MARKER}(\"]\n"),
    ] {
        // a trusted user layer
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(user_layer(&env), &config).unwrap();
        for reason in assert_hooks_fail_closed(&env, &repo, "user layer allowlist") {
            assert!(reason.contains(ALLOWLIST_CATEGORY), "{reason}");
        }

        // a committed workspace layer
        let env = IsolatedEnv::new();
        let repo = repo_under_home(&env);
        std::fs::write(repo.join(".sekretbarilo.toml"), &config).unwrap();
        git(&env, &repo, &["add", ".sekretbarilo.toml"]);
        commit(&env, &repo, "commit an invalid allowlist");
        for reason in assert_hooks_fail_closed(&env, &repo, "committed layer allowlist") {
            assert!(reason.contains(ALLOWLIST_CATEGORY), "{reason}");
        }
    }
}

/// `scan` in a fresh repository with nothing staged.
fn scan_nothing_staged(env: &IsolatedEnv, repo: &Path, args: &[&str]) -> Output {
    env.command()
        .arg("scan")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap()
}

#[test]
fn scan_validates_configuration_with_nothing_staged() {
    let invalid: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "invalid toml",
            format!("[settings]\nentropy_threshold = '{MARKER}'\n").into_bytes(),
            "invalid TOML syntax or configuration type",
        ),
        (
            "invalid utf-8",
            b"# caf\xe9\n[settings]\n".to_vec(),
            "invalid UTF-8 encoding",
        ),
        (
            "unknown rule id",
            b"[settings.rules]\n\"no-such-rule\" = false\n".to_vec(),
            "no-such-rule",
        ),
    ];
    for (label, content, expected) in invalid {
        for explicit in [false, true] {
            let env = IsolatedEnv::new();
            let repo = env.git_repo();
            let path = repo.join(".sekretbarilo.toml");
            std::fs::write(&path, &content).unwrap();
            let args: Vec<&str> = if explicit {
                vec!["--config", path.to_str().unwrap()]
            } else {
                Vec::new()
            };
            let output = scan_nothing_staged(&env, &repo, &args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{label}: {stderr}");
            assert!(stderr.contains(expected), "{label}: {stderr}");
            assert!(!stderr.contains(MARKER), "{label}: {stderr}");
        }
    }

    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let missing = repo.join("missing.toml");
    let output = scan_nothing_staged(&env, &repo, &["--config", missing.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("not found"), "{stderr}");
}

#[test]
fn scan_with_valid_configuration_and_nothing_staged_succeeds_and_traces() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    std::fs::write(
        repo.join(".sekretbarilo.toml"),
        "[settings.rules]\n\"aws-access-key-id\" = false\n",
    )
    .unwrap();
    let output = scan_nothing_staged(&env, &repo, &["--trace-exemptions"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("[TRACE] rule:disabled generic-high-entropy-value"),
        "{stderr}"
    );
    assert!(
        stderr.contains("[TRACE] rule:disabled aws-access-key-id"),
        "{stderr}"
    );
    let plain = scan_nothing_staged(&env, &repo, &[]);
    assert_eq!(plain.status.code(), Some(0));
    assert!(
        plain.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
}
