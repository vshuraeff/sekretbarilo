#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

mod common;
use common::IsolatedEnv;

const MATCHER: &str = "^(Bash|Read|Grep)$";

struct Fixture {
    env: IsolatedEnv,
    repo: PathBuf,
    executables: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let env = IsolatedEnv::new();
        let repo = env.git_repo();
        let executables = env.root().join("bin");
        std::fs::create_dir(&executables).unwrap();
        let fixture = Self {
            env,
            repo,
            executables,
        };
        fixture.version("2.1.261 (Claude Code)");
        fixture
    }

    fn version(&self, version: &str) {
        assert!(!version.contains('\''));
        let path = self.executables.join("claude");
        std::fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn command(&self) -> Command {
        self.command_via(Path::new(&common::bin()))
    }

    fn command_via(&self, executable: &Path) -> Command {
        let paths = std::iter::once(self.executables.clone()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .collect::<Vec<_>>(),
        );
        let mut command = Command::new(executable);
        command
            .current_dir(&self.repo)
            .env("HOME", self.env.home())
            .env("CODEX_HOME", self.env.codex_home())
            .env("GIT_CONFIG_GLOBAL", self.env.git_config_global())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env("PATH", std::env::join_paths(paths).unwrap());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn success(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn local(&self) -> PathBuf {
        self.repo.join(".claude/settings.json")
    }

    fn global(&self) -> PathBuf {
        self.env.home().join(".claude/settings.json")
    }

    fn hook_command(&self, args: &str) -> String {
        let path = common::bin();
        let path = path.as_str();
        if path
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._+-".contains(byte))
        {
            return format!("{path} {args}");
        }
        let escaped = path
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('`', "\\`");
        format!("\"{escaped}\" {args}")
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn owned_commands(config: &Value) -> Vec<String> {
    config["hooks"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|groups| groups.as_array().unwrap())
        .flat_map(|group| group["hooks"].as_array().unwrap())
        .filter_map(|handler| handler["command"].as_str())
        .filter(|command| sekretbarilo::agent::is_sekretbarilo_hook_command(command).is_some())
        .map(str::to_owned)
        .collect()
}

fn copied_cli_with_stable_symlink(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let target = fixture.env.root().join("cellar/0.9.4/bin/sekretbarilo");
    let stable = fixture.env.root().join("stable/bin/sekretbarilo");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::create_dir_all(stable.parent().unwrap()).unwrap();
    std::fs::copy(common::bin(), &target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&target, &stable).unwrap();
    (target, stable)
}

#[test]
fn install_switch_reinstall_and_install_all_preserve_mode() {
    let fixture = Fixture::new();
    fixture.success(&["install", "agent-hook", "claude"]);
    assert_eq!(
        owned_commands(&read_json(&fixture.local())),
        [fixture.hook_command("check-file --stdin-json")]
    );
    fixture.success(&["install", "agent-hook", "claude", "--mode", "redact"]);
    let redact = read_json(&fixture.local());
    assert_eq!(
        owned_commands(&redact),
        [fixture.hook_command("redact-claude --stdin-json")]
    );
    assert_eq!(redact["hooks"]["PostToolUse"][0]["matcher"], MATCHER);
    assert_eq!(redact["hooks"]["PostToolUse"][0]["hooks"][0]["timeout"], 10);
    assert!(
        redact["hooks"]["PostToolUse"][0]["hooks"][0]
            .get("async")
            .is_none()
    );
    let before = std::fs::read(fixture.local()).unwrap();
    fixture.success(&["install", "agent-hook", "claude"]);
    assert_eq!(std::fs::read(fixture.local()).unwrap(), before);
    fixture.success(&["install", "all"]);
    assert_eq!(std::fs::read(fixture.local()).unwrap(), before);
    fixture.success(&["install", "agent-hook", "claude", "--mode", "block"]);
    assert_eq!(
        owned_commands(&read_json(&fixture.local())),
        [fixture.hook_command("check-file --stdin-json")]
    );
}

#[test]
fn reinstall_replaces_a_single_quoted_absolute_command_in_place() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.local().parent().unwrap()).unwrap();
    let existing = json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Read",
                "hooks": [{
                    "type": "command",
                    "command": "'/x/y/sekretbarilo' redact-claude --stdin-json",
                    "timeout": 10
                }]
            }]
        }
    });
    std::fs::write(fixture.local(), serde_json::to_vec(&existing).unwrap()).unwrap();

    fixture.success(&["install", "agent-hook", "claude", "--mode", "block"]);

    assert_eq!(
        owned_commands(&read_json(&fixture.local())),
        [fixture.hook_command("check-file --stdin-json")]
    );
}

#[test]
fn old_and_unknown_versions_cannot_replace_existing_protection() {
    let fixture = Fixture::new();
    fixture.success(&["install", "agent-hook", "claude"]);
    let block = std::fs::read(fixture.local()).unwrap();
    for version in ["2.1.120 (Claude Code)", "unknown", "2.1.121-preview"] {
        fixture.version(version);
        let output = fixture.run(&["install", "agent-hook", "claude", "--mode", "redact"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(">=2.1.121"));
        assert_eq!(std::fs::read(fixture.local()).unwrap(), block);
    }
    fixture.version("2.1.121 (Claude Code)");
    fixture.success(&["install", "agent-hook", "claude", "--mode", "redact"]);
    let redact = std::fs::read(fixture.local()).unwrap();
    fixture.version("unknown");
    assert!(
        !fixture
            .run(&["install", "agent-hook", "claude"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(fixture.local()).unwrap(), redact);
    fixture.success(&["install", "agent-hook", "claude", "--mode", "block"]);
}

#[test]
fn installer_and_doctor_warn_about_global_and_local_override_read_blockers() {
    let fixture = Fixture::new();
    fixture.success(&["install", "agent-hook", "claude", "--global"]);
    std::fs::create_dir_all(fixture.local().parent().unwrap()).unwrap();
    let override_path = fixture.repo.join(".claude/settings.local.json");
    let blocker = serde_json::to_vec(&json!({"hooks":{"PreToolUse":[{"matcher":"^(Read|Bash)$", "hooks":[{"type":"command", "command":fixture.hook_command("check-file --stdin-json")}]}]}})).unwrap();
    std::fs::write(&override_path, &blocker).unwrap();
    let global = fixture.env.home().join(".claude/settings.json");
    let global_before = std::fs::read(&global).unwrap();
    let output = fixture.success(&["install", "agent-hook", "claude", "--mode", "redact"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("blocking Read hook in global settings"),
        "{stderr}"
    );
    assert!(
        stderr.contains("blocking Read hook in local override settings"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&global).unwrap(), global_before);
    assert_eq!(std::fs::read(&override_path).unwrap(), blocker);
    let output = fixture.run(&["doctor"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("redact mode"), "{stderr}");
    assert!(
        stderr.contains("blocking Read hook in global settings"),
        "{stderr}"
    );
    assert!(
        stderr.contains("blocking Read hook in local override settings"),
        "{stderr}"
    );
}

#[test]
fn global_redact_preserved_and_global_block_warns_about_local_redact() {
    let fixture = Fixture::new();
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--global",
        "--mode",
        "redact",
    ]);
    let global = fixture.env.home().join(".claude/settings.json");
    let before = std::fs::read(&global).unwrap();
    fixture.success(&["install", "agent-hook", "claude", "--global"]);
    assert_eq!(std::fs::read(&global).unwrap(), before);
    fixture.success(&["install", "agent-hook", "claude", "--mode", "redact"]);
    let local = std::fs::read(fixture.local()).unwrap();
    let output = fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--global",
        "--mode",
        "block",
    ]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("blocking Read hook in global settings")
    );
    assert_eq!(std::fs::read(fixture.local()).unwrap(), local);
}

#[test]
fn malformed_target_settings_are_not_rewritten() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.local().parent().unwrap()).unwrap();
    for malformed in [
        "{broken",
        r#"{"hooks":{"PostToolUse":[{"matcher":"^(Bash|Read|Grep)$","hooks":{}}]}}"#,
    ] {
        std::fs::write(fixture.local(), malformed).unwrap();
        assert!(
            !fixture
                .run(&["install", "agent-hook", "claude", "--mode", "redact"])
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(fixture.local()).unwrap(), malformed);
    }
}

#[test]
fn explicit_settings_support_absolute_and_invocation_relative_paths() {
    let fixture = Fixture::new();
    let absolute = fixture.env.root().join("explicit/absolute.json");
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        absolute.to_str().unwrap(),
        "--mode",
        "block",
    ]);
    let block = read_json(&absolute);
    assert_eq!(
        owned_commands(&block),
        [fixture.hook_command("check-file --stdin-json")]
    );
    assert_eq!(block["hooks"]["PreToolUse"][0]["matcher"], "Read");

    let subdirectory = fixture.repo.join("nested");
    std::fs::create_dir_all(&subdirectory).unwrap();
    let relative = subdirectory.join("settings/claude.json");
    let output = fixture
        .command()
        .current_dir(&subdirectory)
        .args([
            "install",
            "agent-hook",
            "claude",
            "--settings",
            "settings/claude.json",
            "--mode",
            "redact",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let redact = read_json(&relative);
    assert_eq!(
        owned_commands(&redact),
        [fixture.hook_command("redact-claude --stdin-json")]
    );
    assert_eq!(redact["hooks"]["PostToolUse"][0]["matcher"], MATCHER);
    assert_eq!(
        redact["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        fixture.hook_command("redact-claude --stdin-json")
    );
    assert!(!fixture.local().exists());
    assert!(!fixture.global().exists());
}

#[test]
fn explicit_settings_preserve_switch_and_validate_modes_without_touching_defaults() {
    let fixture = Fixture::new();
    let settings = fixture.env.root().join("explicit/settings.json");
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "block",
    ]);
    let block = std::fs::read(&settings).unwrap();
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&settings).unwrap(), block);

    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "redact",
    ]);
    let redact = std::fs::read(&settings).unwrap();
    assert_eq!(
        owned_commands(&read_json(&settings)),
        [fixture.hook_command("redact-claude --stdin-json")]
    );
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&settings).unwrap(), redact);

    fixture.version("2.1.120 (Claude Code)");
    let output = fixture.run(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "redact",
    ]);
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&settings).unwrap(), redact);
    fixture.version("2.1.261 (Claude Code)");
    fixture.success(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "block",
    ]);
    assert_eq!(
        owned_commands(&read_json(&settings)),
        [fixture.hook_command("check-file --stdin-json")]
    );
    assert!(!fixture.local().exists());
    assert!(!fixture.global().exists());
}

#[test]
fn explicit_malformed_settings_are_not_rewritten() {
    let fixture = Fixture::new();
    let settings = fixture.env.root().join("explicit/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let malformed = b"{broken";
    std::fs::write(&settings, malformed).unwrap();
    let output = fixture.run(&[
        "install",
        "agent-hook",
        "claude",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "block",
    ]);
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&settings).unwrap(), malformed);
    assert!(!fixture.local().exists());
    assert!(!fixture.global().exists());
}

#[test]
fn install_all_can_target_explicit_claude_settings_without_changing_other_steps() {
    let fixture = Fixture::new();
    let settings = fixture.env.root().join("explicit/settings.json");
    fixture.success(&[
        "install",
        "all",
        "--settings",
        settings.to_str().unwrap(),
        "--mode",
        "redact",
    ]);
    assert_eq!(
        owned_commands(&read_json(&settings)),
        [fixture.hook_command("redact-claude --stdin-json")]
    );
    assert!(fixture.repo.join(".git/hooks/pre-commit").exists());
    assert!(!fixture.local().exists());

    let rejected = Fixture::new();
    let rejected_settings = rejected.env.root().join("explicit/settings.json");
    let output = rejected.run(&[
        "install",
        "all",
        "--global",
        "--settings",
        rejected_settings.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("[ERROR]"));
    assert!(!rejected.repo.join(".git/hooks/pre-commit").exists());
    assert!(!rejected_settings.exists());
}

#[test]
fn claude_config_dir_redirects_global_install_and_doctor() {
    let fixture = Fixture::new();
    let config_dir = fixture.env.root().join("claude-config");
    let settings = config_dir.join("settings.json");
    let output = fixture
        .command()
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .args(["install", "agent-hook", "claude", "--global"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(settings.exists());
    assert!(!fixture.global().exists());
    let output = fixture
        .command()
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .args(["doctor"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("global claude code hook installed"),
        "{stderr}"
    );
    assert!(stderr.contains(settings.to_str().unwrap()), "{stderr}");
}

#[test]
fn empty_or_unset_claude_config_dir_uses_home_global_settings() {
    for config_dir in [None, Some("")] {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        if let Some(config_dir) = config_dir {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        let output = command
            .args(["install", "agent-hook", "claude", "--global"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fixture.global().exists());
    }
}

#[test]
fn claude_config_dir_does_not_require_home() {
    let fixture = Fixture::new();
    let config_dir = fixture.env.root().join("claude-config");
    let settings = config_dir.join("settings.json");
    let output = fixture
        .command()
        .env_remove("HOME")
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .args(["install", "agent-hook", "claude", "--global"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(settings.exists());
    let output = fixture
        .command()
        .env_remove("HOME")
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .args(["doctor"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains(settings.to_str().unwrap()));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_installer_records_symlink_invocation_path() {
    let fixture = Fixture::new();
    let (_, stable) = copied_cli_with_stable_symlink(&fixture);
    let output = fixture
        .command_via(&stable)
        .args(["install", "agent-hook", "claude", "--mode", "block"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        owned_commands(&read_json(&fixture.local())),
        [format!("{} check-file --stdin-json", stable.display())]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_installer_records_resolved_target_and_reports_removed_target() {
    let fixture = Fixture::new();
    let (target, stable) = copied_cli_with_stable_symlink(&fixture);
    let output = fixture
        .command_via(&stable)
        .args(["install", "agent-hook", "claude", "--mode", "block"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        owned_commands(&read_json(&fixture.local())),
        [format!("{} check-file --stdin-json", target.display())]
    );

    std::fs::remove_file(&target).unwrap();
    let output = fixture.run(&["doctor"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "[ERROR] local hook binary {} not found (reinstall with sekretbarilo install agent-hook claude)",
            target.display()
        )),
        "{stderr}"
    );
}
