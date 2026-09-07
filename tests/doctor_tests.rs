// integration tests for the doctor command
//
// these tests exercise the doctor command via the compiled binary, verifying
// that it correctly detects installed hooks, missing hooks, and broken configs.

use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

mod common;

use common::{bin, fake_gitconfig, setup_git_repo};

/// return the isolated user-layer Codex home for an end-to-end test.
fn codex_home(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("codex-home")
}

/// run a subcommand without reading the user's actual Codex, Claude, or git configuration.
fn isolated_command(dir: &tempfile::TempDir, args: &[&str]) -> Command {
    let mut command = Command::new(bin());
    command
        .args(args)
        .env("GIT_CONFIG_GLOBAL", fake_gitconfig(dir))
        .env("HOME", dir.path().join("home"))
        .env("CODEX_HOME", codex_home(dir))
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(dir.path());
    command
}

fn isolated_doctor_command(dir: &tempfile::TempDir) -> Command {
    isolated_command(dir, &["doctor"])
}

#[cfg(unix)]
fn claude_version_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let bin = dir.path().join("claude-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let claude = bin.join("claude");
    std::fs::write(
        &claude,
        "#!/bin/sh\nprintf '%s\\n' '2.1.261 (Claude Code)'\n",
    )
    .unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[cfg(unix)]
fn doctor_command_with_claude(dir: &tempfile::TempDir, args: &[&str]) -> Command {
    let bin = claude_version_dir(dir);
    let paths = std::iter::once(bin).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>(),
    );
    let mut command = isolated_command(dir, args);
    command.env("PATH", std::env::join_paths(paths).unwrap());
    command
}

fn claude_block_settings() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Read",
                "hooks": [{
                    "type": "command",
                    "command": "sekretbarilo check-file --stdin-json",
                    "timeout": 10
                }]
            }]
        }
    }))
    .unwrap()
}

fn claude_redact_settings() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "hooks": {
            "PostToolUse": [{
                "matcher": "^(Bash|Read|Grep)$",
                "hooks": [{
                    "type": "command",
                    "command": "sekretbarilo redact-claude --stdin-json",
                    "timeout": 10
                }]
            }]
        }
    }))
    .unwrap()
}

fn write_claude_settings(path: &std::path::Path, settings: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, settings).unwrap();
}

#[cfg(unix)]
fn claude_hook_settings(command: String, mode: &str) -> Vec<u8> {
    let (event, matcher) = match mode {
        "block" => ("PreToolUse", "Read"),
        "redact" => ("PostToolUse", "^(Bash|Read|Grep)$"),
        _ => panic!("unsupported test mode"),
    };
    serde_json::to_vec(&serde_json::json!({
        "hooks": {
            event: [{
                "matcher": matcher,
                "hooks": [{
                    "type": "command",
                    "command": command,
                    "timeout": 10
                }]
            }]
        }
    }))
    .unwrap()
}

#[cfg(unix)]
fn claude_block_settings_with_commands(commands: &[String]) -> Vec<u8> {
    let handlers: Vec<_> = commands
        .iter()
        .map(|command| {
            serde_json::json!({
                "type": "command",
                "command": command,
                "timeout": 10
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Read",
                "hooks": handlers
            }]
        }
    }))
    .unwrap()
}

#[cfg(unix)]
fn marker_binary(
    directory: &std::path::Path,
    behavior: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    std::fs::create_dir_all(directory).unwrap();
    let binary = directory.join("sekretbarilo");
    let marker = directory.join("executed");
    assert!(!marker.to_string_lossy().contains('\''));
    std::fs::write(
        &binary,
        format!("#!/bin/sh\ntouch '{}'\n{behavior}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    (binary, marker)
}

#[cfg(unix)]
fn prepend_path(command: &mut Command, directories: &[std::path::PathBuf]) {
    let current_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = directories
        .iter()
        .cloned()
        .chain(std::env::split_paths(&current_path));
    command.env("PATH", std::env::join_paths(paths).unwrap());
}

#[cfg(unix)]
fn diagnostic_line<'a>(stderr: &'a str, path: &std::path::Path) -> &'a str {
    stderr
        .lines()
        .find(|line| line.contains(&path.display().to_string()))
        .unwrap_or_else(|| panic!("missing diagnostic for {} in:\n{stderr}", path.display()))
}

// -- basic doctor tests --

#[test]
fn e2e_doctor_runs_without_crash() {
    let dir = setup_git_repo();

    let output = isolated_doctor_command(&dir)
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

    let output = isolated_doctor_command(&dir)
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

#[cfg(unix)]
#[test]
fn e2e_doctor_reports_missing_claude_hook_binary() {
    let dir = setup_git_repo();
    let settings = dir.path().join("supplied/settings.json");
    let missing_binary = dir.path().join("home/.cargo/bin/sekretbarilo");
    write_claude_settings(
        &settings,
        &claude_hook_settings(
            format!("{} check-file --stdin-json", missing_binary.display()),
            "block",
        ),
    );

    let output = isolated_command(&dir, &["doctor", "--settings", settings.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "[ERROR] explicit hook binary {} not found",
            missing_binary.display()
        )),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn e2e_doctor_does_not_probe_foreign_version_script() {
    let dir = setup_git_repo();
    let settings = dir.path().join("supplied/settings.json");
    let (binary, marker) = marker_binary(
        &dir.path().join("home/.cargo/bin/foreign"),
        "printf '%s\\n' 'sekretbarilo 0.9.3'",
    );
    write_claude_settings(
        &settings,
        &claude_hook_settings(
            format!("{} redact-claude --stdin-json", binary.display()),
            "redact",
        ),
    );

    let output =
        doctor_command_with_claude(&dir, &["doctor", "--settings", settings.to_str().unwrap()])
            .output()
            .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "[WARN] explicit hook binary {} differs from the running sekretbarilo",
            binary.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("its version is not verified"), "{stderr}");
    assert!(
        !stderr.contains(&format!("hook binary {} is 0.9.3", binary.display())),
        "{stderr}"
    );
    assert!(!marker.exists());
}

#[test]
fn e2e_doctor_outputs_codex_section() {
    let dir = setup_git_repo();

    let output = isolated_doctor_command(&dir)
        .output()
        .expect("failed to run sekretbarilo doctor");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("codex cli agent hook:"),
        "should have codex cli agent hook section, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_warns_when_codex_hook_has_no_approval_entry() {
    let dir = setup_git_repo();
    let hooks_dir = dir.path().join(".codex");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    std::fs::write(
        hooks_dir.join("hooks.json"),
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(apply_patch|Bash)$",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-codex --stdin-json"
          }
        ]
      }
    ]
  }
}"#,
    )
    .unwrap();

    let output = isolated_doctor_command(&dir).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("[WARN] local codex cli hook approval entry not found"),
        "doctor should warn when a Codex approval entry is absent, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_warns_when_codex_hook_approval_is_disabled() {
    let dir = setup_git_repo();
    let hooks_dir = dir.path().join(".codex");
    let hooks_json_path = hooks_dir.join("hooks.json");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    std::fs::write(
        &hooks_json_path,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(apply_patch|Bash)$",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-codex --stdin-json"
          }
        ]
      }
    ]
  }
}"#,
    )
    .unwrap();
    let codex_home = codex_home(&dir);
    std::fs::create_dir_all(&codex_home).unwrap();
    std::fs::write(
        codex_home.join("config.toml"),
        format!(
            "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = false\n",
            hooks_json_path.display()
        ),
    )
    .unwrap();

    let output = isolated_doctor_command(&dir).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("[WARN] local codex cli hook approval entry")
            && stderr.contains("is explicitly disabled"),
        "doctor should warn when a Codex approval entry is disabled, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_reports_enabled_codex_hook_approval_entry() {
    let dir = setup_git_repo();
    let hooks_dir = dir.path().join(".codex");
    let hooks_json_path = hooks_dir.join("hooks.json");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    std::fs::write(
        &hooks_json_path,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(apply_patch|Bash)$",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-codex --stdin-json"
          }
        ]
      }
    ]
  }
}"#,
    )
    .unwrap();
    let codex_home = codex_home(&dir);
    std::fs::create_dir_all(&codex_home).unwrap();
    std::fs::write(
        codex_home.join("config.toml"),
        format!(
            "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = true\n",
            hooks_json_path.display()
        ),
    )
    .unwrap();

    let output = isolated_doctor_command(&dir).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("[OK] local codex cli hook approval entry found")
            && stderr.contains("(group 0, handler 0)")
            && stderr.contains("not proof the hook runs"),
        "doctor should report an enabled Codex approval entry, got:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("[WARN] local codex cli hook approval"),
        "doctor should not warn for the enabled local Codex approval entry, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_reports_missing_local_and_global_codex_hooks() {
    let dir = setup_git_repo();

    let output = isolated_doctor_command(&dir).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("[NOT INSTALLED] local codex cli hook not found"),
        "doctor should report a missing local Codex hook, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("[NOT INSTALLED] global codex cli hook not found"),
        "doctor should report a missing global Codex hook, got:\n{}",
        stderr
    );
}

// -- detection of installed hooks --

#[test]
fn e2e_doctor_detects_local_git_hook() {
    let dir = setup_git_repo();

    // install pre-commit hook
    let install_output = isolated_command(&dir, &["install", "pre-commit"])
        .output()
        .expect("failed to install pre-commit hook");
    assert_eq!(install_output.status.code(), Some(0));

    // doctor should detect it
    let output = isolated_doctor_command(&dir).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("local pre-commit hook installed"),
        "doctor should detect installed local git hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_built_cli_version_and_doctor_hook_identity() {
    let dir = setup_git_repo();

    let version = isolated_command(&dir, &["--version"])
        .output()
        .expect("failed to run sekretbarilo --version");
    assert!(version.status.success());
    assert!(version.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&version.stderr),
        format!("sekretbarilo {}\n", env!("CARGO_PKG_VERSION"))
    );

    let install_output = isolated_command(&dir, &["install", "agent-hook", "claude"])
        .output()
        .expect("failed to install claude hook");
    assert_eq!(install_output.status.code(), Some(0));
    let settings = dir.path().join(".claude/settings.json");
    let settings_before = std::fs::read(&settings).unwrap();

    let output = isolated_doctor_command(&dir).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("claude code hook installed"),
        "doctor should detect installed local claude hook, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("matches the running sekretbarilo"),
        "{stderr}"
    );
    assert!(!stderr.contains("did not report a sekretbarilo version"));
    assert!(!stderr.contains("differs from the running sekretbarilo"));
    assert_eq!(std::fs::read(settings).unwrap(), settings_before);
}

#[cfg(unix)]
#[test]
fn e2e_doctor_never_executes_settings_binaries_from_path_directories() {
    let dir = setup_git_repo();
    assert!(std::path::Path::new(&bin()).is_absolute());
    let directories = [
        dir.path().join("bin"),
        dir.path().join(".direnv/bin"),
        dir.path().join("node_modules/.bin"),
    ];
    let mut commands = Vec::new();
    let mut markers = Vec::new();
    for directory in &directories {
        let (binary, marker) = marker_binary(directory, "printf '%s\\n' 'sekretbarilo 0.9.3'");
        commands.push(format!("{} check-file --stdin-json", binary.display()));
        markers.push((binary, marker));
    }
    write_claude_settings(
        &dir.path().join(".claude/settings.json"),
        &claude_block_settings_with_commands(&commands),
    );

    let mut command = isolated_doctor_command(&dir);
    prepend_path(&mut command, &directories);
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (binary, marker) in markers {
        let line = diagnostic_line(&stderr, &binary);
        assert!(
            line.contains("differs from the running sekretbarilo")
                && line.contains("version is not verified"),
            "{line}"
        );
        assert!(!marker.exists(), "{} was executed", binary.display());
    }
}

#[cfg(unix)]
#[test]
fn e2e_doctor_never_executes_hooks_across_all_scopes_and_positions() {
    let dir = setup_git_repo();
    let (current, current_marker) = marker_binary(
        &dir.path().join("configured/current"),
        "printf '%s\\n' 'sekretbarilo 0.9.3'",
    );
    let (stale, stale_marker) = marker_binary(
        &dir.path().join("configured/stale"),
        "printf '%s\\n' 'sekretbarilo 0.7.9'",
    );
    let settings_bytes = claude_block_settings_with_commands(&[
        format!("{} check-file --stdin-json", current.display()),
        format!("{} scan-file --old-flag", stale.display()),
    ]);
    let settings = [
        ("local", dir.path().join(".claude/settings.json")),
        (
            "local override",
            dir.path().join(".claude/settings.local.json"),
        ),
        ("global", dir.path().join("home/.claude/settings.json")),
        ("explicit", dir.path().join("supplied/settings.json")),
    ];
    for (_, path) in &settings {
        write_claude_settings(path, &settings_bytes);
    }

    let explicit = &settings[3].1;
    let output = isolated_command(&dir, &["doctor", "--settings", explicit.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (scope, path) in &settings {
        assert!(
            stderr.contains(&format!("{scope} claude code hook installed")),
            "{scope}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("{scope} claude code hook: a stale")),
            "{scope}: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "{scope} hook binary {} differs from the running sekretbarilo",
                current.display()
            )),
            "{scope}: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "{scope} hook binary {} differs from the running sekretbarilo",
                stale.display()
            )),
            "{scope}: {stderr}"
        );
        assert_eq!(std::fs::read(path).unwrap(), settings_bytes);
    }
    assert!(!current_marker.exists());
    assert!(!stale_marker.exists());
}

#[cfg(unix)]
#[test]
fn e2e_doctor_matches_cargo_home_symlink_without_executing_entries() {
    let dir = setup_git_repo();
    let cargo_bin = dir.path().join("home/.cargo/bin");
    let marker_dir = cargo_bin.join("marker");
    let alias_dir = cargo_bin.join("alias");
    let (foreign, marker) = marker_binary(&marker_dir, "printf '%s\\n' 'sekretbarilo 0.9.3'");
    std::fs::create_dir_all(&alias_dir).unwrap();
    let alias = alias_dir.join("sekretbarilo");
    std::os::unix::fs::symlink(bin(), &alias).unwrap();
    write_claude_settings(
        &dir.path().join(".claude/settings.json"),
        &claude_block_settings_with_commands(&[
            format!("{} check-file --stdin-json", foreign.display()),
            format!("{} check-file --stdin-json", alias.display()),
        ]),
    );

    let mut command = isolated_doctor_command(&dir);
    command.env("CARGO_HOME", dir.path().join("home/.cargo"));
    prepend_path(&mut command, &[cargo_bin, marker_dir, alias_dir]);
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let foreign_line = diagnostic_line(&stderr, &foreign);
    assert!(
        foreign_line.contains("differs from the running sekretbarilo")
            && foreign_line.contains("version is not verified"),
        "{foreign_line}"
    );
    let alias_line = diagnostic_line(&stderr, &alias);
    assert!(
        alias_line.contains("matches the running sekretbarilo"),
        "{alias_line}"
    );
    assert!(!alias_line.contains("differs"), "{alias_line}");
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn e2e_doctor_does_not_resolve_bare_hook_name_from_path() {
    let dir = setup_git_repo();
    let marker_dir = dir.path().join("path-bin");
    let (_, marker) = marker_binary(&marker_dir, "printf '%s\\n' 'sekretbarilo 0.9.3'");
    write_claude_settings(
        &dir.path().join(".claude/settings.json"),
        &claude_block_settings(),
    );

    let mut command = isolated_doctor_command(&dir);
    prepend_path(&mut command, &[marker_dir]);
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "hook command uses a bare binary name; Claude Code resolves it under its own PATH"
        ),
        "{stderr}"
    );
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn e2e_doctor_distinguishes_hook_binary_filesystem_failures() {
    let dir = setup_git_repo();
    let missing = dir.path().join("missing/sekretbarilo");

    let cellar_target = dir.path().join("cellar/0.9.3/bin/sekretbarilo");
    let dangling = dir.path().join("stable/sekretbarilo");
    std::fs::create_dir_all(dangling.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&cellar_target, &dangling).unwrap();

    let directory = dir.path().join("directory/sekretbarilo");
    std::fs::create_dir_all(&directory).unwrap();

    let unexecutable = dir.path().join("unexecutable/sekretbarilo");
    std::fs::create_dir_all(unexecutable.parent().unwrap()).unwrap();
    std::fs::write(&unexecutable, "not executed").unwrap();
    std::fs::set_permissions(&unexecutable, std::fs::Permissions::from_mode(0o644)).unwrap();

    let loop_a = dir.path().join("loop-a/sekretbarilo");
    let loop_b = dir.path().join("loop-b/sekretbarilo");
    std::fs::create_dir_all(loop_a.parent().unwrap()).unwrap();
    std::fs::create_dir_all(loop_b.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
    std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();

    let denied_parent = dir.path().join("denied");
    let (denied, denied_marker) = marker_binary(&denied_parent, "exit 0");
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o000)).unwrap();

    let commands = [
        &missing,
        &dangling,
        &directory,
        &unexecutable,
        &loop_a,
        &denied,
    ]
    .map(|path| format!("{} check-file --stdin-json", path.display()));
    write_claude_settings(
        &dir.path().join(".claude/settings.json"),
        &claude_block_settings_with_commands(&commands),
    );
    let output = isolated_doctor_command(&dir).output().unwrap();
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    for path in [&missing, &dangling] {
        let line = diagnostic_line(&stderr, path);
        assert!(
            line.contains("not found (reinstall with sekretbarilo install agent-hook claude)"),
            "{line}"
        );
    }
    assert!(
        diagnostic_line(&stderr, &directory).contains("is not a regular file"),
        "{stderr}"
    );
    assert!(
        diagnostic_line(&stderr, &unexecutable).contains("is not executable"),
        "{stderr}"
    );
    let loop_line = diagnostic_line(&stderr, &loop_a);
    assert!(loop_line.contains("[ERROR]"), "{loop_line}");
    assert!(!loop_line.contains("not found"), "{loop_line}");
    let denied_line = diagnostic_line(&stderr, &denied);
    if denied_line.contains("[ERROR]") {
        assert!(
            denied_line
                .to_ascii_lowercase()
                .contains("permission denied"),
            "{denied_line}"
        );
        assert!(!denied_line.contains("not found"), "{denied_line}");
    } else {
        assert!(
            denied_line.contains("differs from the running sekretbarilo"),
            "{denied_line}"
        );
    }
    assert!(!denied_marker.exists());
}

#[cfg(unix)]
#[test]
fn e2e_doctor_never_runs_blocking_or_flooding_hook_binaries() {
    let dir = setup_git_repo();
    let (sleeper, sleeper_marker) = marker_binary(&dir.path().join("sleeper"), "sleep 60");
    let (flooder, flooder_marker) = marker_binary(
        &dir.path().join("flooder"),
        "while :; do printf '%s\\n' 'sekretbarilo 0.9.3'; done",
    );
    write_claude_settings(
        &dir.path().join(".claude/settings.json"),
        &claude_block_settings_with_commands(&[
            format!("{} check-file --stdin-json", sleeper.display()),
            format!("{} check-file --stdin-json", flooder.display()),
        ]),
    );

    let started = Instant::now();
    let output = isolated_doctor_command(&dir).output().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "doctor hook inspection took {elapsed:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!sleeper_marker.exists());
    assert!(!flooder_marker.exists());
}

// -- detection of missing hooks --

#[test]
fn e2e_doctor_detects_missing_hooks() {
    let dir = setup_git_repo();

    let output = isolated_doctor_command(&dir).output().unwrap();

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

    let output = isolated_doctor_command(&dir).output().unwrap();

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

    let output = isolated_doctor_command(&dir).output().unwrap();

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

    let output = isolated_doctor_command(&dir).output().unwrap();

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

    let output = isolated_doctor_command(&dir).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[NOT INSTALLED]") && stderr.contains("no hooks.PreToolUse"),
        "doctor should detect settings without hook, got:\n{}",
        stderr
    );
}

#[cfg(unix)]
#[test]
fn e2e_doctor_inspects_explicit_redact_settings_without_writing() {
    let dir = setup_git_repo();
    let local = dir.path().join(".claude/settings.json");
    let explicit = dir.path().join("supplied/settings.json");
    let local_before = claude_block_settings();
    let explicit_before = claude_redact_settings();
    write_claude_settings(&local, &local_before);
    write_claude_settings(&explicit, &explicit_before);

    let output =
        doctor_command_with_claude(&dir, &["doctor", "--settings", explicit.to_str().unwrap()])
            .output()
            .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK] explicit claude code hook installed (redact mode")
            && stderr.contains(explicit.to_str().unwrap()),
        "{stderr}"
    );
    assert!(
        stderr.contains("Claude redact hook in explicit settings")
            && stderr.contains("blocking Read hook in local settings"),
        "{stderr}"
    );
    assert!(
        stderr.contains("[OK] Claude Code version supports redact (>=2.1.121)"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&local).unwrap(), local_before);
    assert_eq!(std::fs::read(&explicit).unwrap(), explicit_before);
}

#[cfg(unix)]
#[test]
fn e2e_doctor_reports_conflict_when_explicit_settings_blocks_read() {
    let dir = setup_git_repo();
    let local = dir.path().join(".claude/settings.json");
    let explicit = dir.path().join("supplied/settings.json");
    write_claude_settings(&local, &claude_redact_settings());
    write_claude_settings(&explicit, &claude_block_settings());

    let output =
        doctor_command_with_claude(&dir, &["doctor", "--settings", explicit.to_str().unwrap()])
            .output()
            .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Claude redact hook in local settings")
            && stderr.contains("blocking Read hook in explicit settings"),
        "{stderr}"
    );
}

#[test]
fn e2e_doctor_missing_explicit_settings_is_an_issue() {
    let dir = setup_git_repo();
    let explicit = dir.path().join("supplied/missing.json");
    let output = isolated_command(&dir, &["doctor", "--settings", explicit.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("[WARN] explicit claude code settings file not found")
            && stderr.contains(explicit.to_str().unwrap()),
        "{stderr}"
    );
}

#[test]
fn e2e_doctor_missing_local_override_explicit_settings_is_an_issue() {
    let dir = setup_git_repo();
    // canonicalize so the explicit path dedups into the local override scope on macos
    let explicit = dir
        .path()
        .canonicalize()
        .unwrap()
        .join(".claude/settings.local.json");
    let output = isolated_command(&dir, &["doctor", "--settings", explicit.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("[WARN] explicit claude code settings file not found")
            && stderr.contains(explicit.to_str().unwrap()),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn e2e_doctor_deduplicates_explicit_path_matching_local_override_settings() {
    let dir = setup_git_repo();
    let local_override = dir.path().join(".claude/settings.local.json");
    write_claude_settings(&local_override, &claude_block_settings());

    let output = doctor_command_with_claude(
        &dir,
        &["doctor", "--settings", local_override.to_str().unwrap()],
    )
    .output()
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("claude code hook installed").count(),
        1,
        "{stderr}"
    );
    assert!(
        !stderr.contains("explicit claude code settings file not found"),
        "{stderr}"
    );
    assert!(!stderr.contains("conflicts with"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn e2e_doctor_deduplicates_explicit_path_matching_local_settings() {
    let dir = setup_git_repo();
    let local = dir.path().join(".claude/settings.json");
    let global = dir.path().join("home/.claude/settings.json");
    write_claude_settings(&local, &claude_redact_settings());
    write_claude_settings(&global, &claude_block_settings());

    let output =
        doctor_command_with_claude(&dir, &["doctor", "--settings", local.to_str().unwrap()])
            .output()
            .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("conflicts with a blocking Read hook")
            .count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains("Claude redact hook in local settings"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Claude redact hook in explicit settings"),
        "{stderr}"
    );
}

// -- config validation --

#[test]
fn e2e_doctor_validates_config_and_rules() {
    let dir = setup_git_repo();

    let output = isolated_doctor_command(&dir).output().unwrap();

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

    let output = isolated_doctor_command(&dir).output().unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "doctor should exit 1 when warnings are found"
    );
}

#[test]
fn e2e_doctor_exit_0_when_all_installed() {
    let dir = setup_git_repo();
    let codex_home = dir.path().join(".codex");

    // install both hooks (local + global)
    isolated_command(&dir, &["install", "all"])
        .env("HOME", dir.path())
        .env("CODEX_HOME", &codex_home)
        .output()
        .unwrap();

    isolated_command(&dir, &["install", "all", "--global"])
        .env("HOME", dir.path())
        .env("CODEX_HOME", &codex_home)
        .output()
        .unwrap();

    let hooks_json_path = codex_home.join("hooks.json");
    std::fs::write(
        codex_home.join("config.toml"),
        format!(
            "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = true\n",
            hooks_json_path.display()
        ),
    )
    .unwrap();

    // add the binary directory to PATH so doctor's binary check passes
    let bin_dir = std::path::Path::new(&bin())
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let path_var = format!("{}:{}", bin_dir, std::env::var("PATH").unwrap_or_default());

    let output = isolated_doctor_command(&dir)
        .env("HOME", dir.path())
        .env("CODEX_HOME", &codex_home)
        .env("PATH", &path_var)
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

    let output = isolated_doctor_command(&dir).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[WARN]") && stderr.contains("outdated"),
        "doctor should warn about outdated command, got:\n{}",
        stderr
    );
}
