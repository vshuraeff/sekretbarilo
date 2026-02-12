// integration tests for agent hooks: check-file and claude code hook installation
//
// these tests exercise the full end-to-end workflows using the compiled binary
// and the library API, including install + doctor verification flows.

use std::process::Command;

/// get the path to the compiled binary
fn bin() -> String {
    env!("CARGO_BIN_EXE_sekretbarilo").to_string()
}

/// create a temp git repo for pre-commit hook install tests.
/// isolates from user's global git config to prevent core.hooksPath leakage.
fn setup_git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // create an empty file to use as global git config, preventing leakage
    // from the user's actual global config (e.g. core.hooksPath)
    let fake_global = root.join(".fake-gitconfig");
    std::fs::write(&fake_global, "").unwrap();

    Command::new("git")
        .args(["init"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .expect("git init failed");

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();

    dir
}

/// get the path to the fake global gitconfig inside a test repo dir
fn fake_gitconfig(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join(".fake-gitconfig")
}

// -- check-file E2E tests --

#[test]
fn e2e_check_file_clean_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("clean.py");
    std::fs::write(&file_path, "x = 42\nprint(x)\n").unwrap();

    let output = Command::new(bin())
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "clean file should exit 0"
    );
}

#[test]
fn e2e_check_file_with_secret() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.py");
    std::fs::write(
        &file_path,
        "aws_key = \"AKIAIOSFODNN7REALKEYZ\"\n",
    )
    .unwrap();

    let output = Command::new(bin())
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "file with secret should exit 2 to block read"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[AGENT]"),
        "should output AGENT prefix in stderr"
    );
    assert!(
        stderr.contains("secret(s) detected"),
        "should report secrets detected"
    );
}

#[test]
fn e2e_check_file_stdin_json() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.py");
    std::fs::write(
        &file_path,
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
    )
    .unwrap();

    let payload = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = Command::new(bin())
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "file with github token should exit 2 via stdin-json to block read"
    );
}

#[test]
fn e2e_check_file_stdin_json_clean() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("clean.rs");
    std::fs::write(&file_path, "fn main() {\n    println!(\"hello\");\n}\n").unwrap();

    let payload = serde_json::json!({
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = Command::new(bin())
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "clean file should exit 0 via stdin-json"
    );
}

#[test]
fn e2e_check_file_no_arg_exits_2() {
    let output = Command::new(bin())
        .args(["check-file"])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "check-file with no arg should exit 2"
    );
}

#[test]
fn e2e_check_file_malformed_stdin_json() {
    let output = Command::new(bin())
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"not valid json{{{")
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed stdin JSON should exit 2"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[ERROR]"),
        "should output error message"
    );
}

#[test]
fn e2e_check_file_binary_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("binary.dat");
    // write binary content with null bytes + a secret pattern
    let mut content = vec![0u8; 100];
    content.extend_from_slice(b"AKIAIOSFODNN7REALKEYZ");
    std::fs::write(&file_path, &content).unwrap();

    let output = Command::new(bin())
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "binary file should be skipped (exit 0)"
    );
}

#[test]
fn e2e_check_file_vendor_path_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_dir = dir.path().join("node_modules").join("pkg");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let file_path = vendor_dir.join("secret.js");
    std::fs::write(
        &file_path,
        "const key = \"AKIAIOSFODNN7REALKEYZ\";\n",
    )
    .unwrap();

    // use stdin-json with cwd context so vendor path is resolved
    let payload = serde_json::json!({
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = Command::new(bin())
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "vendor path should be skipped (exit 0)"
    );
}

// -- install agent-hook claude E2E tests --

#[test]
fn e2e_install_agent_hook_claude_local() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install agent-hook claude should exit 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]"),
        "should output OK status"
    );

    // verify the config was created
    let config_path = dir.path().join(".claude").join("settings.json");
    assert!(config_path.exists(), ".claude/settings.json should exist");

    let content = std::fs::read_to_string(&config_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed["hooks"]["PreToolUse"].is_array());
}

#[test]
fn e2e_install_agent_hook_claude_idempotent() {
    let dir = tempfile::tempdir().unwrap();

    // first install
    Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    // second install
    let output = Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already installed"),
        "second install should report already installed"
    );
}

// -- install pre-commit E2E tests --

#[test]
fn e2e_install_pre_commit_local() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["install", "pre-commit"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install pre-commit should exit 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]"),
        "should output OK status"
    );

    // verify hook file exists
    let hook_file = dir.path().join(".git").join("hooks").join("pre-commit");
    assert!(hook_file.exists(), "pre-commit hook file should exist");

    let content = std::fs::read_to_string(&hook_file).unwrap();
    assert!(content.contains("sekretbarilo"));
}

// -- install all E2E tests --

#[test]
fn e2e_install_all_installs_both() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["install", "all"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install all should exit 0"
    );

    // verify pre-commit hook
    let hook_file = dir.path().join(".git").join("hooks").join("pre-commit");
    assert!(hook_file.exists(), "pre-commit hook should exist after install all");

    // verify claude hook config
    let config_path = dir.path().join(".claude").join("settings.json");
    assert!(config_path.exists(), ".claude/settings.json should exist after install all");
}

// -- install + doctor workflow tests --

#[test]
fn e2e_install_agent_hook_then_doctor() {
    let dir = setup_git_repo();

    // install claude hook
    Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    // run doctor and verify it finds the installed hook
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("claude code hook installed"),
        "doctor should detect installed local claude hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_install_pre_commit_then_doctor() {
    let dir = setup_git_repo();

    // install pre-commit hook
    Command::new(bin())
        .args(["install", "pre-commit"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    // run doctor and verify it finds the installed hook
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("pre-commit hook installed"),
        "doctor should detect installed local pre-commit hook, got:\n{}",
        stderr
    );
}

// -- doctor breakage detection tests --

#[test]
fn e2e_doctor_detects_deleted_hook_after_install() {
    let dir = setup_git_repo();

    // install pre-commit hook
    Command::new(bin())
        .args(["install", "pre-commit"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    // delete the hook file
    let hook_file = dir.path().join(".git").join("hooks").join("pre-commit");
    std::fs::remove_file(&hook_file).unwrap();

    // doctor should detect the missing hook
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[NOT INSTALLED]"),
        "doctor should detect deleted hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_corrupt_claude_config() {
    let dir = setup_git_repo();

    // install claude hook
    Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    // corrupt the JSON config
    let config_path = dir.path().join(".claude").join("settings.json");
    std::fs::write(&config_path, "not valid json{{{").unwrap();

    // doctor should detect the malformed config
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[ERROR]") && stderr.contains("malformed JSON"),
        "doctor should detect corrupt JSON, got:\n{}",
        stderr
    );
}

// -- global flag tests --

#[test]
fn e2e_install_agent_hook_claude_global_flag() {
    // test that --global flag is accepted and creates file in the right location.
    // we can't test actual HOME modification, but we verify the flag is parsed and the
    // command runs without error.
    let dir = setup_git_repo();

    // use HOME override to isolate global install to temp dir
    let output = Command::new(bin())
        .args(["install", "agent-hook", "claude", "--global"])
        .current_dir(dir.path())
        .env("HOME", dir.path().to_str().unwrap())
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install agent-hook claude --global should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // verify the config was created under $HOME/.claude/settings.json
    let config_path = dir.path().join(".claude").join("settings.json");
    assert!(
        config_path.exists(),
        "~/.claude/settings.json should exist after global install"
    );
}

#[test]
fn e2e_install_pre_commit_global_flag() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["install", "pre-commit", "--global"])
        .current_dir(dir.path())
        .env("HOME", dir.path().to_str().unwrap())
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install pre-commit --global should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
