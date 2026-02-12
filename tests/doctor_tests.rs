// integration tests for the doctor command
//
// these tests exercise the doctor command via the compiled binary, verifying
// that it correctly detects installed hooks, missing hooks, and broken configs.

use std::process::Command;

/// get the path to the compiled binary
fn bin() -> String {
    env!("CARGO_BIN_EXE_sekretbarilo").to_string()
}

/// create a temp git repo.
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

// -- basic doctor tests --

#[test]
fn e2e_doctor_runs_without_crash() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo doctor");

    // should not crash (exit 0 or 1 are both valid)
    let code = output.status.code().unwrap();
    assert!(
        code == 0 || code == 1,
        "doctor should exit 0 or 1, got {}",
        code
    );
}

#[test]
fn e2e_doctor_outputs_all_sections() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo doctor");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // verify all diagnostic sections appear
    assert!(
        stderr.contains("git pre-commit hook:"),
        "should have git pre-commit hook section, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("claude code agent hook:"),
        "should have claude code agent hook section, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("configuration:"),
        "should have configuration section, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("sekretbarilo binary:"),
        "should have binary section, got:\n{}",
        stderr
    );
}

// -- detection of installed hooks --

#[test]
fn e2e_doctor_detects_local_git_hook() {
    let dir = setup_git_repo();

    // install pre-commit hook
    let install_output = Command::new(bin())
        .args(["install", "pre-commit"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to install pre-commit hook");
    assert_eq!(install_output.status.code(), Some(0));

    // doctor should detect it
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("local pre-commit hook installed"),
        "doctor should detect installed local git hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_local_claude_hook() {
    let dir = setup_git_repo();

    // install claude hook
    let install_output = Command::new(bin())
        .args(["install", "agent-hook", "claude"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .expect("failed to install claude hook");
    assert_eq!(install_output.status.code(), Some(0));

    // doctor should detect it
    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("claude code hook installed"),
        "doctor should detect installed local claude hook, got:\n{}",
        stderr
    );
}

// -- detection of missing hooks --

#[test]
fn e2e_doctor_detects_missing_hooks() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);

    // without any installation, hooks should be NOT INSTALLED
    assert!(
        stderr.contains("[NOT INSTALLED]"),
        "doctor should report NOT INSTALLED for missing hooks, got:\n{}",
        stderr
    );
}

// -- detection of broken hooks --

#[test]
fn e2e_doctor_detects_wrong_marker_in_git_hook() {
    let dir = setup_git_repo();

    // create a pre-commit hook WITHOUT the sekretbarilo marker
    let hooks_dir = dir.path().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let hook_file = hooks_dir.join("pre-commit");
    std::fs::write(&hook_file, "#!/bin/sh\necho 'other hook'\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_file).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_file, perms).unwrap();
    }

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[NOT INSTALLED]") && stderr.contains("does not contain sekretbarilo"),
        "doctor should detect hook without marker, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_not_executable_git_hook() {
    let dir = setup_git_repo();

    // create hook with marker but NOT executable
    let hooks_dir = dir.path().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let hook_file = hooks_dir.join("pre-commit");
    std::fs::write(
        &hook_file,
        "#!/bin/sh\n# sekretbarilo pre-commit hook\nsekretbarilo scan\n",
    )
    .unwrap();

    // intentionally leave it non-executable (default mode)

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[WARN]") && stderr.contains("not executable"),
        "doctor should warn about non-executable hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_malformed_claude_config() {
    let dir = setup_git_repo();

    // create malformed .claude/settings.json
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(claude_dir.join("settings.json"), "not json{{{").unwrap();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[ERROR]") && stderr.contains("malformed JSON"),
        "doctor should detect malformed JSON, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_settings_without_hook() {
    let dir = setup_git_repo();

    // create valid .claude/settings.json but without hooks
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"model": "claude-sonnet-4-5-20250929"}"#,
    )
    .unwrap();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[NOT INSTALLED]") && stderr.contains("no hooks.PreToolUse"),
        "doctor should detect settings without hook, got:\n{}",
        stderr
    );
}

// -- config validation --

#[test]
fn e2e_doctor_validates_config_and_rules() {
    let dir = setup_git_repo();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);

    // should report rules loaded and compiled
    assert!(
        stderr.contains("rules loaded"),
        "doctor should report rules loaded, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("rules compile"),
        "doctor should report rules compile status, got:\n{}",
        stderr
    );
}

// -- exit codes --

#[test]
fn e2e_doctor_exit_1_when_warnings_found() {
    let dir = setup_git_repo();

    // create a pre-commit hook with the marker but not executable
    let hooks_dir = dir.path().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    std::fs::write(
        hooks_dir.join("pre-commit"),
        "#!/bin/sh\n# sekretbarilo pre-commit hook\nsekretbarilo scan\n",
    )
    .unwrap();
    // intentionally leave it non-executable -> WARN

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "doctor should exit 1 when warnings are found"
    );
}

#[test]
fn e2e_doctor_exit_0_when_all_installed() {
    let dir = setup_git_repo();
    let home = dir.path().to_str().unwrap();

    // install both hooks (local + global)
    Command::new(bin())
        .args(["install", "all"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .env("HOME", home)
        .current_dir(dir.path())
        .output()
        .unwrap();

    Command::new(bin())
        .args(["install", "all", "--global"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .env("HOME", home)
        .current_dir(dir.path())
        .output()
        .unwrap();

    // add the binary directory to PATH so doctor's binary check passes
    let bin_dir = std::path::Path::new(&bin())
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let path_var = format!("{}:{}", bin_dir, std::env::var("PATH").unwrap_or_default());

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .env("HOME", home)
        .env("PATH", &path_var)
        .current_dir(dir.path())
        .output()
        .unwrap();

    let code = output.status.code().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "doctor should exit 0 when all hooks are installed and binary is in PATH, got:\n{}",
        stderr
    );
}

// -- doctor detects outdated command --

#[test]
fn e2e_doctor_detects_outdated_claude_hook_command() {
    let dir = setup_git_repo();

    // create .claude/settings.json with an outdated command
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let config = serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Read",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "sekretbarilo scan-file --old-flag",
                            "timeout": 5
                        }
                    ]
                }
            ]
        }
    });
    std::fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();

    let output = Command::new(bin())
        .args(["doctor"])
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(&dir))
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[WARN]") && stderr.contains("outdated"),
        "doctor should warn about outdated command, got:\n{}",
        stderr
    );
}
