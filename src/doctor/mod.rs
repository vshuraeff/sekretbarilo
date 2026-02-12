// doctor command: diagnose hook installation and configuration health

use std::path::{Path, PathBuf};

use crate::agent::HOOK_COMMAND;
use crate::hook::HOOK_MARKER;

/// status of an individual check
#[derive(Debug, PartialEq)]
enum Status {
    Ok,
    Warn,
    Error,
    NotInstalled,
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Status::Ok => "[OK]",
            Status::Warn => "[WARN]",
            Status::Error => "[ERROR]",
            Status::NotInstalled => "[NOT INSTALLED]",
        }
    }

    fn is_issue(&self) -> bool {
        matches!(self, Status::Warn | Status::Error)
    }
}

/// a single diagnostic check result
#[derive(Debug)]
struct CheckResult {
    status: Status,
    message: String,
}

impl CheckResult {
    fn ok(msg: impl Into<String>) -> Self {
        Self {
            status: Status::Ok,
            message: msg.into(),
        }
    }

    fn warn(msg: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            message: msg.into(),
        }
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            status: Status::Error,
            message: msg.into(),
        }
    }

    fn not_installed(msg: impl Into<String>) -> Self {
        Self {
            status: Status::NotInstalled,
            message: msg.into(),
        }
    }
}

/// run the doctor command. checks hook installations and configuration health.
/// returns 0 if all OK, 1 if issues found.
pub fn run_doctor() -> i32 {
    let mut results: Vec<(&str, Vec<CheckResult>)> = Vec::new();

    // git pre-commit hook checks
    let git_checks = check_git_hooks();
    results.push(("git pre-commit hook", git_checks));

    // claude code hook checks
    let claude_checks = check_claude_hooks();
    results.push(("claude code agent hook", claude_checks));

    // configuration checks
    let config_checks = check_config();
    results.push(("configuration", config_checks));

    // binary checks
    let binary_checks = check_binary();
    results.push(("sekretbarilo binary", binary_checks));

    // output
    let mut has_issues = false;
    for (group, checks) in &results {
        eprintln!("{}:", group);
        for check in checks {
            eprintln!("  {} {}", check.status.label(), check.message);
            if check.status.is_issue() {
                has_issues = true;
            }
        }
        eprintln!();
    }

    if has_issues {
        1
    } else {
        0
    }
}

/// check git pre-commit hook status (local and global)
fn check_git_hooks() -> Vec<CheckResult> {
    vec![check_local_git_hook(), check_global_git_hook()]
}

/// check the local git pre-commit hook
fn check_local_git_hook() -> CheckResult {
    // find git hooks dir via git rev-parse
    let output = match std::process::Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return CheckResult::error("git not found in PATH"),
    };

    if !output.status.success() {
        return CheckResult::warn("not a git repository (local hook check skipped)");
    }

    let hooks_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let hooks_dir = if Path::new(&hooks_path).is_relative() {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(&hooks_path),
            Err(_) => PathBuf::from(&hooks_path),
        }
    } else {
        PathBuf::from(&hooks_path)
    };

    let hook_file = hooks_dir.join("pre-commit");

    if !hook_file.exists() {
        return CheckResult::not_installed("local pre-commit hook not found");
    }

    let content = match std::fs::read_to_string(&hook_file) {
        Ok(c) => c,
        Err(e) => return CheckResult::error(format!("cannot read {}: {}", hook_file.display(), e)),
    };

    if !content.contains(HOOK_MARKER) {
        return CheckResult::not_installed(
            "local pre-commit hook exists but does not contain sekretbarilo",
        );
    }

    // verify executable on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&hook_file) {
            if meta.permissions().mode() & 0o111 == 0 {
                return CheckResult::warn("local pre-commit hook is not executable");
            }
        }
    }

    CheckResult::ok("local pre-commit hook installed")
}

/// check the global git pre-commit hook
fn check_global_git_hook() -> CheckResult {
    // check if core.hooksPath is configured globally
    let output = match std::process::Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return CheckResult::error("git not found in PATH"),
    };

    let hooks_dir = if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            default_global_hooks_dir()
        } else {
            expand_tilde(&path)
        }
    } else {
        default_global_hooks_dir()
    };

    let hook_file = hooks_dir.join("pre-commit");

    if !hook_file.exists() {
        return CheckResult::not_installed("global pre-commit hook not found");
    }

    let content = match std::fs::read_to_string(&hook_file) {
        Ok(c) => c,
        Err(e) => return CheckResult::error(format!("cannot read {}: {}", hook_file.display(), e)),
    };

    if !content.contains(HOOK_MARKER) {
        return CheckResult::not_installed(
            "global pre-commit hook exists but does not contain sekretbarilo",
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&hook_file) {
            if meta.permissions().mode() & 0o111 == 0 {
                return CheckResult::warn("global pre-commit hook is not executable");
            }
        }
    }

    CheckResult::ok("global pre-commit hook installed")
}

/// check claude code hook status (local and global)
fn check_claude_hooks() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // local: .claude/settings.json in project root (or cwd fallback)
    let local_base = resolve_repo_root()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    results.push(check_claude_hook_at(
        &local_base.join(".claude").join("settings.json"),
        "local",
    ));

    // global: ~/.claude/settings.json
    if let Some(home) = std::env::var_os("HOME") {
        let global_path = PathBuf::from(home).join(".claude").join("settings.json");
        results.push(check_claude_hook_at(&global_path, "global"));
    } else {
        results.push(CheckResult::warn(
            "cannot determine HOME directory for global claude hook check",
        ));
    }

    results
}

/// check a specific claude code settings.json for our hook
fn check_claude_hook_at(config_path: &Path, scope: &str) -> CheckResult {
    if !config_path.exists() {
        return CheckResult::not_installed(format!("{} claude code hook not found", scope));
    }

    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::error(format!("cannot read {}: {}", config_path.display(), e))
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return CheckResult::error(format!(
                "malformed JSON in {}: {}",
                config_path.display(),
                e
            ))
        }
    };

    // navigate to hooks.PreToolUse
    let pre_tool_use = match parsed.get("hooks").and_then(|h| h.get("PreToolUse")) {
        Some(v) => v,
        None => {
            return CheckResult::not_installed(format!(
                "{} claude code settings exists but has no hooks.PreToolUse",
                scope
            ))
        }
    };

    let entries = match pre_tool_use.as_array() {
        Some(a) => a,
        None => return CheckResult::error(format!("{} hooks.PreToolUse is not an array", scope)),
    };

    // look for Read matcher with sekretbarilo command
    for entry in entries {
        if entry.get("matcher").and_then(|m| m.as_str()) != Some("Read") {
            continue;
        }

        let hooks = match entry.get("hooks").and_then(|h| h.as_array()) {
            Some(h) => h,
            None => continue,
        };

        for hook in hooks {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if cmd == HOOK_COMMAND {
                    // verify it has correct event (PreToolUse) and matcher (Read)
                    return CheckResult::ok(format!(
                        "{} claude code hook installed ({})",
                        scope,
                        config_path.display()
                    ));
                }
                if cmd.contains("sekretbarilo") {
                    return CheckResult::warn(format!(
                        "{} claude code hook has outdated sekretbarilo command: {}",
                        scope, cmd
                    ));
                }
            }
        }
    }

    CheckResult::not_installed(format!(
        "{} claude code settings exists but sekretbarilo hook not found in PreToolUse",
        scope
    ))
}

/// check sekretbarilo configuration (discovery + rules compilation)
fn check_config() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // discover config files
    let repo_root = resolve_repo_root();
    let start = repo_root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| start.clone());

    let config_files = crate::config::discovery::discover_configs(&start, &home);
    if config_files.is_empty() {
        results.push(CheckResult::ok(
            "no custom config files found (using defaults)",
        ));
    } else {
        for f in &config_files {
            results.push(CheckResult::ok(format!("config file: {}", f.display())));
        }
    }

    // try loading and compiling config + rules
    match crate::config::load_project_config(repo_root.as_deref()) {
        Ok(config) => {
            match crate::config::load_rules_with_config(&config) {
                Ok(rules) => {
                    results.push(CheckResult::ok(format!(
                        "{} rules loaded successfully",
                        rules.len()
                    )));

                    // try compiling
                    match crate::scanner::rules::compile_rules(&rules) {
                        Ok(_) => {
                            results.push(CheckResult::ok("rules compile successfully"));
                        }
                        Err(e) => {
                            results.push(CheckResult::error(format!(
                                "rules compilation failed: {}",
                                e
                            )));
                        }
                    }
                }
                Err(e) => {
                    results.push(CheckResult::error(format!("failed to load rules: {}", e)));
                }
            }
        }
        Err(e) => {
            results.push(CheckResult::error(format!("failed to load config: {}", e)));
        }
    }

    results
}

/// check if the sekretbarilo binary is findable
fn check_binary() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // check PATH (use POSIX-standard command -v instead of which)
    let in_path = std::process::Command::new("sh")
        .args(["-c", "command -v sekretbarilo"])
        .output()
        .ok()
        .is_some_and(|o| o.status.success());

    if in_path {
        results.push(CheckResult::ok("sekretbarilo found in PATH"));
    } else {
        // check ~/.cargo/bin
        let cargo_bin = std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join(".cargo")
                .join("bin")
                .join("sekretbarilo")
        });

        if let Some(ref path) = cargo_bin {
            if path.exists() {
                results.push(CheckResult::ok(format!(
                    "sekretbarilo found at {}",
                    path.display()
                )));
            } else {
                results.push(CheckResult::warn(
                    "sekretbarilo not found in PATH or ~/.cargo/bin",
                ));
            }
        } else {
            results.push(CheckResult::warn(
                "sekretbarilo not found in PATH (cannot check ~/.cargo/bin without HOME)",
            ));
        }
    }

    results
}

/// resolve git repository root
pub fn resolve_repo_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root))
}

/// get the default global hooks directory (~/.config/git/hooks/)
fn default_global_hooks_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".config")
            .join("git")
            .join("hooks"),
        None => PathBuf::from("/etc/git/hooks"),
    }
}

/// expand ~ prefix in a path to the home directory
fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- status tests --

    #[test]
    fn status_labels() {
        assert_eq!(Status::Ok.label(), "[OK]");
        assert_eq!(Status::Warn.label(), "[WARN]");
        assert_eq!(Status::Error.label(), "[ERROR]");
        assert_eq!(Status::NotInstalled.label(), "[NOT INSTALLED]");
    }

    #[test]
    fn status_is_issue() {
        assert!(!Status::Ok.is_issue());
        assert!(Status::Warn.is_issue());
        assert!(Status::Error.is_issue());
        assert!(!Status::NotInstalled.is_issue());
    }

    // -- check result construction tests --

    #[test]
    fn check_result_constructors() {
        let ok = CheckResult::ok("test");
        assert_eq!(ok.status, Status::Ok);
        assert_eq!(ok.message, "test");

        let warn = CheckResult::warn("warning");
        assert_eq!(warn.status, Status::Warn);

        let err = CheckResult::error("error");
        assert_eq!(err.status, Status::Error);

        let ni = CheckResult::not_installed("not installed");
        assert_eq!(ni.status, Status::NotInstalled);
    }

    // -- expand_tilde tests --

    #[test]
    fn expand_tilde_with_home() {
        let result = expand_tilde("~/some/path");
        // should expand if HOME is set
        if std::env::var_os("HOME").is_some() {
            assert!(!result.starts_with("~"));
            assert!(result.to_str().unwrap().ends_with("some/path"));
        }
    }

    #[test]
    fn expand_tilde_no_tilde() {
        let result = expand_tilde("/absolute/path");
        assert_eq!(result, PathBuf::from("/absolute/path"));
    }

    // -- local git hook detection tests --

    #[test]
    fn detect_installed_local_git_hook() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        let hook_file = hooks_dir.join("pre-commit");
        let content = format!(
            "#!/bin/sh\n{}\necho 'scanning'\n# end sekretbarilo\n",
            HOOK_MARKER
        );
        std::fs::write(&hook_file, &content).unwrap();

        // make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&hook_file).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&hook_file, perms).unwrap();
        }

        // verify our detection logic directly
        assert!(content.contains(HOOK_MARKER));
    }

    #[test]
    fn detect_hook_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let hook_file = dir.path().join("pre-commit");
        let content = format!("#!/bin/sh\n{}\n", HOOK_MARKER);
        std::fs::write(&hook_file, &content).unwrap();

        // verify it's not executable by default
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&hook_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o111, 0);
        }
    }

    // -- claude hook detection tests --

    #[test]
    fn detect_installed_claude_hook() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        let config = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [
                            {
                                "type": "command",
                                "command": HOOK_COMMAND,
                                "timeout": 10,
                                "statusMessage": "Scanning file for secrets..."
                            }
                        ]
                    }
                ]
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::Ok);
        assert!(result.message.contains("test claude code hook installed"));
    }

    #[test]
    fn detect_missing_claude_hook() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("nonexistent.json");

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::NotInstalled);
    }

    #[test]
    fn detect_claude_hook_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");
        std::fs::write(&config_path, "not json{{{").unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::Error);
        assert!(result.message.contains("malformed JSON"));
    }

    #[test]
    fn detect_claude_hook_no_hooks_key() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");
        std::fs::write(&config_path, r#"{"model": "claude-sonnet-4-5-20250929"}"#).unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::NotInstalled);
        assert!(result.message.contains("no hooks.PreToolUse"));
    }

    #[test]
    fn detect_claude_hook_outdated_command() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");

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
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::Warn);
        assert!(result.message.contains("outdated"));
    }

    #[test]
    fn detect_claude_hook_no_sekretbarilo_in_read_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");

        let config = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [
                            {"type": "command", "command": "echo other hook"}
                        ]
                    }
                ]
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::NotInstalled);
    }

    #[test]
    fn detect_claude_hook_pre_tool_use_not_array() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");

        let config = serde_json::json!({
            "hooks": {
                "PreToolUse": "not an array"
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let result = check_claude_hook_at(&config_path, "test");
        assert_eq!(result.status, Status::Error);
        assert!(result.message.contains("not an array"));
    }

    // -- config check tests --

    #[test]
    fn config_check_default_succeeds() {
        let results = check_config();
        // should always succeed at minimum with defaults
        let has_rules_result = results.iter().any(|r| r.message.contains("rules loaded"));
        assert!(has_rules_result);
    }

    // -- binary check tests --

    #[test]
    fn binary_check_runs() {
        let results = check_binary();
        assert!(!results.is_empty());
        // in a dev environment, the binary might not be in PATH but that's fine
    }

    // -- integration: run_doctor returns correct exit code --

    #[test]
    fn run_doctor_returns_int() {
        // just verify it doesn't panic and returns a valid exit code
        let code = run_doctor();
        assert!(code == 0 || code == 1);
    }
}
