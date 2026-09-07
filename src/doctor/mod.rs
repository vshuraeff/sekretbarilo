// doctor command: diagnose hook installation and configuration health

use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::agent::HOOK_COMMAND;
use crate::agent::claude::{
    ClaudeHookMode, claude_hook_state, claude_scope_conflicts, claude_settings_paths,
    claude_settings_paths_with_explicit, ensure_redact_version, same_resolved_path,
    sekretbarilo_hook_executable,
};
use crate::agent::{
    CODEX_HOOK_COMMAND, CODEX_HOOK_MATCHER, find_hook, is_sekretbarilo_hook_command,
    resolve_codex_home,
};
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
pub fn run_doctor(explicit_claude_settings: Option<PathBuf>) -> i32 {
    let mut results: Vec<(&str, Vec<CheckResult>)> = Vec::new();

    // git pre-commit hook checks
    let git_checks = check_git_hooks();
    results.push(("git pre-commit hook", git_checks));

    // claude code hook checks
    let claude_checks = check_claude_hooks(explicit_claude_settings);
    results.push(("claude code agent hook", claude_checks));

    // codex cli hook checks
    let codex_checks = check_codex_hooks();
    results.push(("codex cli agent hook", codex_checks));

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

    if has_issues { 1 } else { 0 }
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
        if let Ok(meta) = std::fs::metadata(&hook_file)
            && meta.permissions().mode() & 0o111 == 0
        {
            return CheckResult::warn("local pre-commit hook is not executable");
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
        if let Ok(meta) = std::fs::metadata(&hook_file)
            && meta.permissions().mode() & 0o111 == 0
        {
            return CheckResult::warn("global pre-commit hook is not executable");
        }
    }

    CheckResult::ok("global pre-commit hook installed")
}

/// check claude code hook status (local and global)
fn check_claude_hooks(explicit_claude_settings: Option<PathBuf>) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let current_exe = std::env::current_exe().ok();

    let local_base = resolve_repo_root()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut paths = claude_settings_paths(
        &local_base,
        std::env::var_os("CLAUDE_CONFIG_DIR"),
        std::env::var_os("HOME"),
    );
    let explicit_path = explicit_claude_settings.clone();
    if let Some(path) = explicit_claude_settings {
        paths = claude_settings_paths_with_explicit(paths, path);
    }
    let mut has_redact = false;
    for (scope, path) in &paths {
        if *scope != "explicit"
            && !path.exists()
            && explicit_path
                .as_ref()
                .is_some_and(|explicit| same_resolved_path(path, explicit))
        {
            results.push(CheckResult::warn(format!(
                "explicit claude code settings file not found ({})",
                path.display()
            )));
        } else {
            results.extend(check_claude_hook_at(path, scope, current_exe.as_deref()));
        }
        has_redact |= std::fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .and_then(|root| claude_hook_state(&root).ok())
            .is_some_and(|hooks| hooks.iter().any(|hook| hook.mode == ClaudeHookMode::Redact));
    }
    if !paths.iter().any(|(scope, _)| *scope == "global") {
        results.push(CheckResult::warn(
            "cannot determine HOME directory for global claude hook check",
        ));
    }
    results.extend(
        claude_scope_conflicts(&paths)
            .into_iter()
            .map(CheckResult::warn),
    );
    if has_redact {
        match ensure_redact_version() {
            Ok(()) => results.push(CheckResult::ok(
                "Claude Code version supports redact (>=2.1.121)",
            )),
            Err(reason) => results.push(CheckResult::warn(reason)),
        }
    }

    results
}

/// check a specific claude code settings.json for our hook
fn check_claude_hook_at(
    config_path: &Path,
    scope: &str,
    current_exe: Option<&Path>,
) -> Vec<CheckResult> {
    if !config_path.exists() {
        if scope == "explicit" {
            return vec![CheckResult::warn(format!(
                "explicit claude code settings file not found ({})",
                config_path.display()
            ))];
        }
        return vec![CheckResult::not_installed(format!(
            "{} claude code hook not found",
            scope
        ))];
    }

    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            return vec![CheckResult::error(format!(
                "cannot read {}: {}",
                config_path.display(),
                e
            ))];
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return vec![CheckResult::error(format!(
                "malformed JSON in {}: {}",
                config_path.display(),
                e
            ))];
        }
    };

    let hooks = match claude_hook_state(&parsed) {
        Ok(hooks) => hooks,
        Err(reason) => return vec![CheckResult::error(format!("{scope} {reason}"))],
    };
    let active = hooks.iter().find(|hook| hook.current);
    let mut results = if let Some(active) = active {
        vec![CheckResult::ok(format!(
            "{} claude code hook installed ({} mode, {})",
            scope,
            active.mode.name(),
            config_path.display()
        ))]
    } else {
        if !hooks.is_empty() {
            vec![CheckResult::warn(format!(
                "{scope} claude code hook has outdated sekretbarilo command or settings; re-run install with --mode block or --mode redact"
            ))]
        } else {
            let reason = if parsed.get("hooks").is_none() {
                "no hooks.PreToolUse or hooks.PostToolUse"
            } else {
                "sekretbarilo hook not found in PreToolUse or PostToolUse"
            };
            return vec![CheckResult::not_installed(format!(
                "{scope} claude code settings exists but has {reason}"
            ))];
        }
    };
    if let Some(active) = active {
        for hook in &hooks {
            if std::ptr::eq(hook, active) {
                continue;
            }
            let kind = if hook.current { "duplicate" } else { "stale" };
            results.push(CheckResult::warn(format!(
                "{} claude code hook: a {} sekretbarilo handler also exists at group {}, handler {} ({}); remove it by hand from {} or re-run install with an explicit --mode",
                scope, kind, hook.group_index, hook.hook_index, hook.event, config_path.display()
            )));
        }
    }
    for hook in &hooks {
        results.extend(check_claude_hook_binary(
            &hook.command,
            hook.mode,
            scope,
            current_exe,
        ));
    }
    if hooks.iter().any(|hook| hook.mode == ClaudeHookMode::Redact)
        && hooks.iter().any(|hook| hook.blocks_read)
    {
        results.push(CheckResult::warn(format!(
            "{scope} Claude redact hook conflicts with a blocking Read hook in the same settings file"
        )));
    }
    results
}

fn check_claude_hook_binary(
    command: &str,
    mode: ClaudeHookMode,
    scope: &str,
    current_exe: Option<&Path>,
) -> Vec<CheckResult> {
    if is_sekretbarilo_hook_command(command) != Some(mode) {
        return Vec::new();
    }
    let Some(executable) = sekretbarilo_hook_executable(command) else {
        return Vec::new();
    };
    if !executable.is_absolute() {
        return vec![CheckResult::warn(format!(
            "{scope} hook command uses a bare binary name; Claude Code resolves it under its own PATH, reinstall with sekretbarilo install agent-hook claude to pin the absolute path"
        ))];
    }
    if let Err(error) = std::fs::symlink_metadata(&executable) {
        return vec![hook_binary_metadata_error(scope, &executable, error)];
    }
    let metadata = match std::fs::metadata(&executable) {
        Ok(metadata) => metadata,
        Err(error) => return vec![hook_binary_metadata_error(scope, &executable, error)],
    };
    if !metadata.file_type().is_file() {
        return vec![CheckResult::error(format!(
            "{scope} hook binary {} is not a regular file",
            executable.display()
        ))];
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return vec![CheckResult::error(format!(
                "{scope} hook binary {} is not executable",
                executable.display()
            ))];
        }
    }

    vec![classify_hook_binary_identity(
        scope,
        &executable,
        current_exe.map(Path::to_path_buf),
    )]
}

fn hook_binary_metadata_error(
    scope: &str,
    executable: &Path,
    error: std::io::Error,
) -> CheckResult {
    if error.kind() == std::io::ErrorKind::NotFound {
        CheckResult::error(format!(
            "{scope} hook binary {} not found (reinstall with sekretbarilo install agent-hook claude)",
            executable.display()
        ))
    } else {
        CheckResult::error(format!(
            "{scope} hook binary {}: {error}",
            executable.display()
        ))
    }
}

fn classify_hook_binary_identity(
    scope: &str,
    executable: &Path,
    current_exe: Option<PathBuf>,
) -> CheckResult {
    let Some(current_exe) = current_exe else {
        return CheckResult::warn(format!(
            "{scope} hook binary {} identity unavailable",
            executable.display()
        ));
    };
    let Ok(configured_identity) = executable.canonicalize() else {
        return CheckResult::warn(format!(
            "{scope} hook binary {} identity unavailable",
            executable.display()
        ));
    };
    let Ok(running_identity) = current_exe.canonicalize() else {
        return CheckResult::warn(format!(
            "{scope} hook binary {} identity unavailable",
            executable.display()
        ));
    };
    if configured_identity == running_identity {
        CheckResult::ok(format!(
            "{scope} hook binary {} matches the running sekretbarilo",
            executable.display()
        ))
    } else {
        CheckResult::warn(format!(
            "{scope} hook binary {} differs from the running sekretbarilo ({}); its version is not verified, reinstall from the intended binary",
            executable.display(),
            current_exe.display()
        ))
    }
}

/// check codex cli hook status (local and global)
fn check_codex_hooks() -> Vec<CheckResult> {
    check_codex_hooks_with_env(std::env::var_os("CODEX_HOME"), std::env::var_os("HOME"))
}

/// same as `check_codex_hooks`, but with CODEX_HOME/HOME injected for testability.
fn check_codex_hooks_with_env(
    codex_home_env: Option<std::ffi::OsString>,
    home_env: Option<std::ffi::OsString>,
) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // local: .codex/hooks.json in project root (or cwd fallback)
    let local_base = resolve_repo_root()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let local_hooks_json = local_base.join(".codex").join("hooks.json");

    // global: $CODEX_HOME/hooks.json, defaulting to ~/.codex/hooks.json
    match resolve_codex_home(codex_home_env, home_env) {
        Ok(codex_home) => {
            let config_toml_path = codex_home.join("config.toml");
            results.extend(check_codex_hook_at(
                &local_hooks_json,
                &config_toml_path,
                "local",
            ));
            results.extend(check_codex_hook_at(
                &codex_home.join("hooks.json"),
                &config_toml_path,
                "global",
            ));
        }
        Err(_) => {
            let unavailable_config_toml =
                PathBuf::from(".sekretbarilo-doctor-codex-home-unavailable/config.toml");
            results.extend(check_codex_hook_at(
                &local_hooks_json,
                &unavailable_config_toml,
                "local",
            ));
            results.push(CheckResult::warn(
                "cannot determine CODEX_HOME or HOME directory for global codex hook check",
            ));
        }
    }

    // check PATH (use POSIX-standard command -v instead of which)
    let codex_in_path = std::process::Command::new("sh")
        .args(["-c", "command -v codex"])
        .output()
        .ok()
        .is_some_and(|output| output.status.success());

    if codex_in_path {
        let version = std::process::Command::new("codex")
            .arg("--version")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
            });
        let version_suffix = version.map_or_else(String::new, |version| format!(" ({version})"));
        results.push(CheckResult::ok(format!(
            "codex found in PATH{}",
            version_suffix
        )));
    } else {
        results.push(CheckResult::not_installed("codex not found in PATH"));
    }

    results
}

/// check a specific codex hooks.json for our hook and its approval entry
fn check_codex_hook_at(
    hooks_json_path: &Path,
    config_toml_path: &Path,
    scope: &str,
) -> Vec<CheckResult> {
    if !hooks_json_path.exists() {
        return vec![CheckResult::not_installed(format!(
            "{} codex cli hook not found",
            scope
        ))];
    }

    let content = match std::fs::read_to_string(hooks_json_path) {
        Ok(content) => content,
        Err(error) => {
            return vec![CheckResult::error(format!(
                "cannot read {}: {}",
                hooks_json_path.display(),
                error
            ))];
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(error) => {
            return vec![CheckResult::error(format!(
                "malformed JSON in {}: {}",
                hooks_json_path.display(),
                error
            ))];
        }
    };

    let has_unrecognised_top_level_key = parsed.as_object().is_some_and(|root| {
        root.keys()
            .any(|key| key != "hooks" && key != "description")
    });
    let mut results = Vec::new();

    // navigate to hooks.PreToolUse
    let Some(pre_tool_use) = parsed
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
    else {
        results.push(CheckResult::not_installed(format!(
            "{} codex hooks.json exists but has no hooks.PreToolUse",
            scope
        )));
        append_codex_unrecognised_key_warning(&mut results, scope, has_unrecognised_top_level_key);
        return results;
    };

    if pre_tool_use.as_array().is_none() {
        results.push(CheckResult::error(format!(
            "{} hooks.PreToolUse is not an array",
            scope
        )));
        append_codex_unrecognised_key_warning(&mut results, scope, has_unrecognised_top_level_key);
        return results;
    }

    let hook_search = find_hook(&parsed, CODEX_HOOK_MATCHER, CODEX_HOOK_COMMAND);
    if let Some((group_index, hook_index)) = hook_search.first_sekretbarilo_hook {
        let command = parsed["hooks"]["PreToolUse"][group_index]["hooks"][hook_index]["command"]
            .as_str()
            .unwrap_or("<unreadable command>");
        if let Some((exact_group_index, exact_hook_index)) = hook_search.exact_hook {
            results.push(CheckResult::ok(format!(
                "{} codex cli hook installed ({})",
                scope,
                hooks_json_path.display()
            )));
            if (exact_group_index, exact_hook_index) != (group_index, hook_index) {
                results.push(CheckResult::warn(format!(
                    "{} codex cli hook: a stale sekretbarilo handler also exists at group {}, handler {}; remove it by hand from {}",
                    scope,
                    group_index,
                    hook_index,
                    hooks_json_path.display()
                )));
            }
            results.push(check_codex_hook_approval(
                hooks_json_path,
                config_toml_path,
                scope,
                exact_group_index,
                exact_hook_index,
            ));
        } else {
            results.push(CheckResult::warn(format!(
                "{} codex cli hook has outdated sekretbarilo command: {}; re-running the installer will update it",
                scope, command
            )));
        }
    } else {
        results.push(CheckResult::not_installed(format!(
            "{} codex hooks.json exists but no sekretbarilo hook was found under the matcher \"{}\"; if you hand-edited the matcher, doctor cannot see hooks under a different one",
            scope, CODEX_HOOK_MATCHER
        )));
    }

    append_codex_unrecognised_key_warning(&mut results, scope, has_unrecognised_top_level_key);
    results
}

fn append_codex_unrecognised_key_warning(
    results: &mut Vec<CheckResult>,
    scope: &str,
    has_unrecognised_top_level_key: bool,
) {
    if has_unrecognised_top_level_key {
        results.push(CheckResult::warn(format!(
            "{} codex hooks.json has an unrecognised top-level key (only 'hooks' and 'description' are accepted); codex will silently discard this file's hooks entirely",
            scope
        )));
    }
}

/// find the positional Codex approval entry for a hook without validating trusted_hash.
fn check_codex_hook_approval(
    hooks_json_path: &Path,
    config_toml_path: &Path,
    scope: &str,
    group_index: usize,
    hook_index: usize,
) -> CheckResult {
    let hook_path = hooks_json_path.display().to_string();
    // Deliberately not canonicalized: on macOS /var and /private/var alias via a symlink, and
    // canonicalizing here could make this key diverge from the uncanonicalized path Codex used
    // when it wrote the approval entry. Cost: if Codex ever records the key under a
    // canonicalized path that differs from this one, doctor will warn forever with advice that
    // cannot fix it. That is still only ever a WARN, never a false OK, so it is accepted.
    let hook_prefix = format!("{hook_path}:pre_tool_use:");
    let expected_key = format!("{hook_prefix}{group_index}:{hook_index}");
    let approval_entry = std::fs::read_to_string(config_toml_path)
        .ok()
        .map(|content| toml::from_str::<toml::Value>(&content))
        .transpose();

    let config = match approval_entry {
        Ok(Some(config)) => config,
        Ok(None) => return codex_approval_not_found(scope, config_toml_path),
        Err(error) => {
            return CheckResult::warn(format!(
                "{} codex cli hook approval status could not be determined from {}: malformed TOML: {}; approve it with /hooks in the Codex TUI",
                scope,
                config_toml_path.display(),
                error
            ));
        }
    };

    let state = config
        .get("hooks")
        .and_then(toml::Value::as_table)
        .and_then(|hooks| hooks.get("state"))
        .and_then(toml::Value::as_table);
    let entry = state.and_then(|state| state.get(&expected_key));

    let Some(entry) = entry else {
        if state.is_some_and(|state| {
            state
                .keys()
                .any(|key| key != &expected_key && key.starts_with(&hook_prefix))
        }) {
            return CheckResult::warn(format!(
                "{} codex cli hook: an approval entry exists in {} but not for this hook's position (group {}, handler {}); codex silently skips unapproved hooks; the indices may have shifted; re-approve with /hooks in the Codex TUI",
                scope,
                config_toml_path.display(),
                group_index,
                hook_index
            ));
        }
        return codex_approval_not_found(scope, config_toml_path);
    };

    // Codex treats a missing or non-boolean enabled field as enabled by default.
    let enabled = entry
        .as_table()
        .and_then(|entry| entry.get("enabled"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true);
    if enabled {
        CheckResult::ok(format!(
            "{} codex cli hook approval entry found in {} (group {}, handler {}); codex re-checks its own trust hash at run time, so this is not proof the hook runs",
            scope,
            config_toml_path.display(),
            group_index,
            hook_index
        ))
    } else {
        CheckResult::warn(format!(
            "{} codex cli hook approval entry in {} is explicitly disabled; enable it with /hooks in the Codex TUI",
            scope,
            config_toml_path.display()
        ))
    }
}

fn codex_approval_not_found(scope: &str, config_toml_path: &Path) -> CheckResult {
    CheckResult::warn(format!(
        "{} codex cli hook approval entry not found in {}; codex silently skips unapproved hooks; approve it with /hooks in the Codex TUI",
        scope,
        config_toml_path.display()
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
        if let Some(repo_root) = repo_root.as_deref() {
            append_untrusted_inworkspace_config_notes(&mut results, &config_files, repo_root);
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

/// warn about in-workspace config layers the agent hooks (check-file / check-codex) will
/// not trust. those hooks require a layer to be git-tracked and unmodified relative to
/// HEAD before honoring it (see `agent::codex::load_trusted_project_config`), so an
/// untracked or dirty `.sekretbarilo.toml` inside the repo silently loses its allowlist
/// contributions there even though `scan`/`audit` still apply it normally. this check
/// only mirrors that trust rule for visibility; it proves nothing about what will happen
/// on push or in CI, only about the current working tree.
fn append_untrusted_inworkspace_config_notes(
    results: &mut Vec<CheckResult>,
    config_files: &[PathBuf],
    repo_root: &Path,
) {
    let repo_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    for path in config_files {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !canonical.starts_with(&repo_root) {
            continue;
        }
        if !is_committed_in_git(&repo_root, &canonical) {
            results.push(CheckResult::warn(format!(
                "{} is untracked or has uncommitted changes; the check-file/check-codex agent hooks ignore this config layer entirely until it is committed",
                canonical.display()
            )));
        }
    }
}

/// check whether `path` (already inside `repo_root`) is git-tracked and unmodified
/// relative to HEAD. mirrors the trust check in `agent::codex::is_committed_config` for
/// doctor's read-only diagnostics; the two intentionally are not shared code, since a
/// drift between them can only produce a wrong WARN here, never a security gap (doctor
/// does not gate anything).
fn is_committed_in_git(repo_root: &Path, path: &Path) -> bool {
    let Ok(relative_path) = path.strip_prefix(repo_root) else {
        return false;
    };
    let tracked = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(relative_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if !tracked.is_ok_and(|status| status.success()) {
        return false;
    }

    std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--quiet", "HEAD", "--"])
        .arg(relative_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// check if the sekretbarilo binary is findable
fn check_binary() -> Vec<CheckResult> {
    let mut results = Vec::new();

    if sekretbarilo_in_path().is_some() {
        results.push(CheckResult::ok("sekretbarilo found in PATH"));
    } else {
        if let Some(path) = sekretbarilo_in_cargo_bin() {
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

fn sekretbarilo_in_path() -> Option<PathBuf> {
    std::process::Command::new("sh")
        .args(["-c", "command -v sekretbarilo"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| output.lines().next().map(str::trim).map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
}

fn sekretbarilo_in_cargo_bin() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".cargo")
            .join("bin")
            .join("sekretbarilo")
    })
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
    } else if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn check_claude_hook_at(config_path: &Path, scope: &str) -> Vec<CheckResult> {
        let current_exe = std::env::current_exe().ok();
        super::check_claude_hook_at(config_path, scope, current_exe.as_deref())
    }

    fn git_success(repo: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_git_repo() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        git_success(repo.path(), &["init"]);
        git_success(
            repo.path(),
            &["config", "user.email", "fixture@example.invalid"],
        );
        git_success(repo.path(), &["config", "user.name", "Fixture User"]);
        repo
    }

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
    fn invariant_hook_command_accessors_never_panic() {
        // both `find_hook`-derived `["command"].as_str()` accessors (claude and codex paths)
        // must degrade instead of panicking: a malformed hooks.json must never crash doctor,
        // which is the tool users reach for when something is already broken.
        let source = include_str!("mod.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("mod.rs must contain a #[cfg(test)] boundary");
        let lines: Vec<&str> = production_source.lines().collect();
        for window in lines.windows(2) {
            let panics = window[0].trim() == ".as_str()" && window[1].trim() == ".unwrap();";
            assert!(
                !panics,
                "found a bare .as_str().unwrap() in doctor's production code: {:?}",
                window
            );
        }
    }

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

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results[0].status, Status::Ok);
        assert!(
            results[0]
                .message
                .contains("test claude code hook installed")
        );
        assert!(results.iter().any(|result| {
            result
                .message
                .starts_with("test hook command uses a bare binary name")
        }));
    }

    #[test]
    fn bare_hook_binary_is_not_resolved_and_missing_identity_is_reported() {
        let bare = check_claude_hook_binary(HOOK_COMMAND, ClaudeHookMode::Block, "test", None);
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].status, Status::Warn);
        assert!(
            bare[0]
                .message
                .contains("test hook command uses a bare binary name")
        );

        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let binary = dir.path().join("sekretbarilo");
            std::fs::write(&binary, "not executed").unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            let results = check_claude_hook_binary(
                &format!("{} check-file --stdin-json", binary.display()),
                ClaudeHookMode::Block,
                "test",
                None,
            );
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].status, Status::Warn);
            assert!(results[0].message.contains("identity unavailable"));
        }
    }

    #[test]
    fn hook_binary_identity_is_unavailable_without_current_exe() {
        let result =
            classify_hook_binary_identity("test", Path::new("configured/sekretbarilo"), None);
        assert_eq!(result.status, Status::Warn);
        assert_eq!(
            result.message,
            "test hook binary configured/sekretbarilo identity unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hook_binary_metadata_classification_preserves_distinct_causes() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing/sekretbarilo");
        let missing_result = check_claude_hook_binary(
            &format!("{} check-file --stdin-json", missing.display()),
            ClaudeHookMode::Block,
            "test",
            None,
        );
        assert_eq!(missing_result[0].status, Status::Error);
        assert!(
            missing_result[0]
                .message
                .contains("not found (reinstall with")
        );

        let directory = dir.path().join("directory/sekretbarilo");
        std::fs::create_dir_all(&directory).unwrap();
        let directory_result = check_claude_hook_binary(
            &format!("{} check-file --stdin-json", directory.display()),
            ClaudeHookMode::Block,
            "test",
            None,
        );
        assert_eq!(directory_result[0].status, Status::Error);
        assert!(
            directory_result[0]
                .message
                .contains("is not a regular file")
        );

        let unexecutable = dir.path().join("unexecutable/sekretbarilo");
        std::fs::create_dir_all(unexecutable.parent().unwrap()).unwrap();
        std::fs::write(&unexecutable, "not executed").unwrap();
        std::fs::set_permissions(&unexecutable, std::fs::Permissions::from_mode(0o644)).unwrap();
        let unexecutable_result = check_claude_hook_binary(
            &format!("{} check-file --stdin-json", unexecutable.display()),
            ClaudeHookMode::Block,
            "test",
            None,
        );
        assert_eq!(unexecutable_result[0].status, Status::Error);
        assert!(unexecutable_result[0].message.contains("is not executable"));

        let denied = hook_binary_metadata_error(
            "test",
            Path::new("sekretbarilo"),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert_eq!(denied.status, Status::Error);
        assert!(denied.message.contains("permission denied"));
        assert!(!denied.message.contains("not found"));
    }

    #[cfg(unix)]
    #[test]
    fn hook_binary_identity_comparison_canonicalizes_only_for_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let running = dir.path().join("running/sekretbarilo");
        std::fs::create_dir_all(running.parent().unwrap()).unwrap();
        std::fs::write(&running, "not executed").unwrap();
        std::fs::set_permissions(&running, std::fs::Permissions::from_mode(0o755)).unwrap();

        let alias = dir.path().join("alias/sekretbarilo");
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&running, &alias).unwrap();
        let alias_result = check_claude_hook_binary(
            &format!("{} check-file --stdin-json", alias.display()),
            ClaudeHookMode::Block,
            "test",
            Some(&running),
        );
        assert_eq!(alias_result[0].status, Status::Ok);
        assert!(
            alias_result[0]
                .message
                .contains(&alias.display().to_string())
        );
        assert!(
            alias_result[0]
                .message
                .contains("matches the running sekretbarilo")
        );

        let foreign = dir.path().join("foreign/sekretbarilo");
        std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
        std::fs::write(&foreign, "not executed").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
        let foreign_result = check_claude_hook_binary(
            &format!("{} redact-claude --stdin-json", foreign.display()),
            ClaudeHookMode::Redact,
            "test",
            Some(&running),
        );
        assert_eq!(foreign_result[0].status, Status::Warn);
        assert!(
            foreign_result[0]
                .message
                .contains("differs from the running sekretbarilo")
        );
        assert!(
            foreign_result[0]
                .message
                .contains("version is not verified")
        );
    }

    #[test]
    fn detect_claude_redact_and_later_stale_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"hooks": {"PostToolUse": [
                {"matcher": crate::agent::claude::REDACT_HOOK_MATCHER, "hooks": [
                    {"type": "command", "command": crate::agent::claude::REDACT_HOOK_COMMAND, "timeout": 10},
                    {"type": "command", "command": "sekretbarilo redact-claude --old"}
                ]}
            ]}}))
            .unwrap(),
        )
        .unwrap();
        let results = check_claude_hook_at(&path, "test");
        assert_eq!(results[0].status, Status::Ok);
        assert!(results[0].message.contains("redact mode"));
        assert_eq!(results[1].status, Status::Warn);
        assert!(results[1].message.contains("handler 1 (PostToolUse)"));
    }

    #[test]
    fn conditional_or_asynchronous_claude_redact_is_not_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for (field, value) in [
            ("async", serde_json::json!(true)),
            ("asyncRewake", serde_json::json!(true)),
            ("if", serde_json::json!("tool_name == 'Read'")),
            ("args", serde_json::json!(["--old"])),
            ("timeout", serde_json::json!(1)),
        ] {
            let mut handler = serde_json::json!({"type": "command", "command": crate::agent::claude::REDACT_HOOK_COMMAND, "timeout": 10});
            handler[field] = value;
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({"hooks": {"PostToolUse": [
                    {"matcher": crate::agent::claude::REDACT_HOOK_MATCHER, "hooks": [handler]}
                ]}}))
                .unwrap(),
            )
            .unwrap();
            let results = check_claude_hook_at(&path, "test");
            assert_eq!(results[0].status, Status::Warn, "{field}");
            assert!(results[0].message.contains("outdated"), "{field}");
        }
    }

    #[test]
    fn detect_missing_claude_hook() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("nonexistent.json");

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::NotInstalled);
    }

    #[test]
    fn detect_claude_hook_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");
        std::fs::write(&config_path, "not json{{{").unwrap();

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Error);
        assert!(results[0].message.contains("malformed JSON"));
    }

    #[test]
    fn detect_claude_hook_no_hooks_key() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("settings.json");
        std::fs::write(&config_path, r#"{"model": "claude-sonnet-4-5-20250929"}"#).unwrap();

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::NotInstalled);
        assert!(results[0].message.contains("no hooks.PreToolUse"));
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

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results[0].status, Status::Warn);
        assert!(results[0].message.contains("outdated"));
    }

    #[test]
    fn detect_claude_hook_with_stale_duplicate_and_current_command() {
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
                                "command": "sekretbarilo scan-file --old-flag"
                            },
                            {
                                "type": "command",
                                "command": HOOK_COMMAND
                            }
                        ]
                    }
                ]
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let results = check_claude_hook_at(&config_path, "test");

        assert_eq!(results[0].status, Status::Ok);
        assert!(results[0].message.contains("hook installed"));
        assert_eq!(results[1].status, Status::Warn);
        assert!(
            results[1]
                .message
                .contains("a stale sekretbarilo handler also exists at group 0, handler 0")
        );
        assert!(results[1].message.contains("remove it by hand"));
        assert!(
            !results
                .iter()
                .any(|result| result.message.contains("outdated"))
        );
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

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::NotInstalled);
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

        let results = check_claude_hook_at(&config_path, "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Error);
        assert!(results[0].message.contains("not an array"));
    }

    // -- codex cli hook detection tests --

    #[test]
    fn check_codex_hooks_degrades_gracefully_when_home_is_empty() {
        let results = check_codex_hooks_with_env(None, Some(std::ffi::OsString::new()));
        assert!(results.iter().any(|r| {
            r.status == Status::Warn
                && r.message
                    .contains("cannot determine CODEX_HOME or HOME directory")
        }));
    }

    #[test]
    fn check_codex_hooks_treats_empty_codex_home_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let results = check_codex_hooks_with_env(
            Some(std::ffi::OsString::new()),
            Some(dir.path().as_os_str().to_os_string()),
        );
        assert!(
            !results
                .iter()
                .any(|r| r.message.contains("cannot determine CODEX_HOME or HOME"))
        );
    }

    #[test]
    fn check_codex_hooks_uses_default_codex_home_when_only_home_set() {
        let dir = tempfile::tempdir().unwrap();
        let results = check_codex_hooks_with_env(None, Some(dir.path().as_os_str().to_os_string()));
        assert!(
            !results
                .iter()
                .any(|r| r.message.contains("cannot determine CODEX_HOME or HOME"))
        );
    }

    fn codex_hooks_json(command: &str) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [
                            {
                                "type": "command",
                                "command": command
                            }
                        ]
                    }
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn detect_missing_codex_hook() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::NotInstalled);
        assert_eq!(results[0].message, "test codex cli hook not found");
    }

    #[test]
    fn detect_codex_hook_without_sekretbarilo() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json("echo another hook")).unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::NotInstalled);
        assert!(
            results[0]
                .message
                .contains("no sekretbarilo hook was found under the matcher")
        );
        assert!(results[0].message.contains(CODEX_HOOK_MATCHER));
    }

    #[test]
    fn detect_current_codex_hook_without_approval_entry() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(results[1].message.contains("approval entry not found"));
        assert!(!results[1].message.contains("will run"));
        assert!(!results[1].message.contains("is trusted"));
    }

    #[test]
    fn detect_codex_hook_with_disabled_approval_entry() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = false\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(results[1].message.contains("explicitly disabled"));
    }

    #[test]
    fn detect_codex_hook_with_enabled_approval_entry() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Ok);
        assert!(results[1].message.contains("approval entry found"));
        assert!(results[1].message.contains("(group 0, handler 0)"));
        assert!(results[1].message.contains("not proof the hook runs"));
        assert!(!results[1].message.contains("will run"));
    }

    #[test]
    fn detect_codex_hook_rejects_foreign_position_approval_entry() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "echo foreign hook"}
                        ]
                    },
                    {
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [
                            {"type": "command", "command": CODEX_HOOK_COMMAND}
                        ]
                    }
                ]
            }
        });
        std::fs::write(
            &hooks_json_path,
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:0:0\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(
            results[1]
                .message
                .contains("not for this hook's position (group 1, handler 0)")
        );
        assert!(
            results[1]
                .message
                .contains("codex silently skips unapproved hooks")
        );
        assert!(results[1].message.contains("indices may have shifted"));
    }

    #[test]
    fn detect_codex_hook_approval_key_for_different_file_is_not_wrong_position() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        // a key belonging to a different file whose path merely contains ours (e.g. a backup
        // file) must not be mistaken for a shifted-position entry of this hook.
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}.bak:pre_tool_use:0:0\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(results[1].message.contains("approval entry not found"));
        assert!(!results[1].message.contains("not for this hook's position"));
    }

    #[test]
    fn detect_codex_hook_approval_key_for_different_event_is_not_wrong_position() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        // a key for the same file but a different event must not be mistaken for a
        // shifted-position entry of this pre_tool_use hook.
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:post_tool_use:0:0\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(results[1].message.contains("approval entry not found"));
        assert!(!results[1].message.contains("not for this hook's position"));
    }

    #[test]
    fn detect_codex_hook_with_nonzero_position_approval_entry() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "echo foreign hook"}
                        ]
                    },
                    {
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [
                            {"type": "command", "command": CODEX_HOOK_COMMAND}
                        ]
                    }
                ]
            }
        });
        std::fs::write(
            &hooks_json_path,
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:1:0\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Ok);
        assert!(results[1].message.contains("(group 1, handler 0)"));
    }

    #[test]
    fn detect_codex_hook_approval_without_enabled_defaults_to_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:0:0\"]\ntrusted_hash = \"test-hash\"\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Ok);
        assert!(results[1].message.contains("approval entry found"));
    }

    #[test]
    fn detect_codex_hook_with_stale_duplicate_and_current_command() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [
                            {
                                "type": "command",
                                "command": "sekretbarilo check-codex --old-flag"
                            },
                            {
                                "type": "command",
                                "command": CODEX_HOOK_COMMAND
                            }
                        ]
                    }
                ]
            }
        });
        std::fs::write(
            &hooks_json_path,
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &config_toml_path,
            format!(
                "[hooks.state.\"{}:pre_tool_use:0:1\"]\nenabled = true\n",
                hooks_json_path.display()
            ),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].status, Status::Ok);
        assert_eq!(results[1].status, Status::Warn);
        assert!(
            results[1]
                .message
                .contains("a stale sekretbarilo handler also exists at group 0, handler 0")
        );
        assert_eq!(results[2].status, Status::Ok);
        assert!(results[2].message.contains("(group 0, handler 1)"));
        assert!(
            !results
                .iter()
                .any(|result| result.message.contains("outdated"))
        );
    }

    #[test]
    fn detect_outdated_codex_hook() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(
            &hooks_json_path,
            codex_hooks_json("sekretbarilo check-codex --old-flag"),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Warn);
        assert!(results[0].message.contains("outdated"));
        assert!(
            results[0]
                .message
                .contains("re-running the installer will update it")
        );
    }

    #[test]
    fn detect_codex_hook_with_unrecognised_top_level_key() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        let mut config: serde_json::Value =
            serde_json::from_str(&codex_hooks_json(CODEX_HOOK_COMMAND)).unwrap();
        config["bogus"] = serde_json::Value::Bool(true);
        std::fs::write(
            &hooks_json_path,
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert!(results.iter().any(|result| result.status == Status::Warn
            && result.message.contains("unrecognised top-level key")));
    }

    #[test]
    fn detect_codex_hook_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(&hooks_json_path, "not json{{{").unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Error);
        assert!(results[0].message.contains("malformed JSON"));
    }

    #[test]
    fn detect_codex_hook_pre_tool_use_not_array() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_json_path = dir.path().join("hooks.json");
        let config_toml_path = dir.path().join("config.toml");
        std::fs::write(
            &hooks_json_path,
            r#"{"hooks":{"PreToolUse":"not an array"}}"#,
        )
        .unwrap();

        let results = check_codex_hook_at(&hooks_json_path, &config_toml_path, "test");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Error);
        assert!(
            results[0]
                .message
                .contains("hooks.PreToolUse is not an array")
        );
    }

    // -- config check tests --

    #[test]
    fn untrusted_inworkspace_config_notes_warns_when_untracked() {
        let repo = init_git_repo();
        let config_path = repo.path().join(".sekretbarilo.toml");
        std::fs::write(&config_path, "[settings]\n").unwrap();

        let mut results = Vec::new();
        append_untrusted_inworkspace_config_notes(&mut results, &[config_path], repo.path());

        assert!(results.iter().any(|r| r.status == Status::Warn
            && r.message.contains("untracked or has uncommitted changes")));
    }

    #[test]
    fn untrusted_inworkspace_config_notes_warns_when_dirty() {
        let repo = init_git_repo();
        let config_path = repo.path().join(".sekretbarilo.toml");
        std::fs::write(&config_path, "[settings]\n").unwrap();
        git_success(repo.path(), &["add", ".sekretbarilo.toml"]);
        git_success(
            repo.path(),
            &["commit", "--no-verify", "-m", "add fixture config"],
        );
        std::fs::write(&config_path, "[settings]\nentropy_threshold = 3.0\n").unwrap();

        let mut results = Vec::new();
        append_untrusted_inworkspace_config_notes(&mut results, &[config_path], repo.path());

        assert!(results.iter().any(|r| r.status == Status::Warn));
    }

    #[test]
    fn untrusted_inworkspace_config_notes_silent_when_committed_and_clean() {
        let repo = init_git_repo();
        let config_path = repo.path().join(".sekretbarilo.toml");
        std::fs::write(&config_path, "[settings]\n").unwrap();
        git_success(repo.path(), &["add", ".sekretbarilo.toml"]);
        git_success(
            repo.path(),
            &["commit", "--no-verify", "-m", "add fixture config"],
        );

        let mut results = Vec::new();
        append_untrusted_inworkspace_config_notes(&mut results, &[config_path], repo.path());

        assert!(results.is_empty());
    }

    #[test]
    fn untrusted_inworkspace_config_notes_ignores_paths_outside_workspace() {
        let repo = init_git_repo();
        let outside = tempfile::tempdir().unwrap();
        let config_path = outside.path().join(".sekretbarilo.toml");
        std::fs::write(&config_path, "[settings]\n").unwrap();

        let mut results = Vec::new();
        append_untrusted_inworkspace_config_notes(&mut results, &[config_path], repo.path());

        assert!(results.is_empty());
    }

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
        let code = run_doctor(None);
        assert!(code == 0 || code == 1);
    }
}
