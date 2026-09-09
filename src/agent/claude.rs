use std::path::{Path, PathBuf};

use super::hooks_json::{HookInstallResult, find_hook_for_event, write_config};

/// bare hook commands used only when the running executable path is unavailable
pub const HOOK_COMMAND: &str = "sekretbarilo check-file --stdin-json";
pub const REDACT_HOOK_COMMAND: &str = "sekretbarilo redact-claude --stdin-json";
pub const REDACT_HOOK_MATCHER: &str = "^(Bash|Read|Grep)$";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeHookMode {
    Block,
    Redact,
}

pub enum ClaudeSettingsTarget {
    Local,
    Global,
    Explicit(PathBuf),
}

impl ClaudeHookMode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Redact => "redact",
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::Block => "PreToolUse",
            Self::Redact => "PostToolUse",
        }
    }

    fn matcher(self) -> &'static str {
        match self {
            Self::Block => "Read",
            Self::Redact => REDACT_HOOK_MATCHER,
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Block => HOOK_COMMAND,
            Self::Redact => REDACT_HOOK_COMMAND,
        }
    }

    fn args(self) -> &'static str {
        match self {
            Self::Block => "check-file --stdin-json",
            Self::Redact => "redact-claude --stdin-json",
        }
    }
}

/// install claude code hook into settings.json.
/// global: true = ~/.claude/settings.json, false = .claude/settings.json (project root)
pub fn install_claude_hook(global: bool) -> Result<HookInstallResult, String> {
    install_claude_hook_with_mode(global, None)
}

/// omitted mode preserves the mode in the selected settings file.
pub fn install_claude_hook_with_mode(
    global: bool,
    mode: Option<ClaudeHookMode>,
) -> Result<HookInstallResult, String> {
    let target = if global {
        ClaudeSettingsTarget::Global
    } else {
        ClaudeSettingsTarget::Local
    };
    install_claude_hook_to_target(target, mode)
}

pub fn install_claude_hook_to_target(
    target: ClaudeSettingsTarget,
    mode: Option<ClaudeHookMode>,
) -> Result<HookInstallResult, String> {
    let warn_on_cwd_fallback = matches!(&target, ClaudeSettingsTarget::Local);
    let base = match resolve_project_root() {
        Some(root) => root,
        None => {
            let cwd = std::env::current_dir()
                .map_err(|_| "could not determine current directory".to_string())?;
            if warn_on_cwd_fallback {
                eprintln!(
                    "[WARN] not inside a git repository, using current directory for local hook placement: {}",
                    cwd.display()
                );
            }
            cwd
        }
    };
    let mut paths = claude_settings_paths(
        &base,
        std::env::var_os("CLAUDE_CONFIG_DIR"),
        std::env::var_os("HOME"),
    );
    let config_path = match target {
        ClaudeSettingsTarget::Local => paths
            .iter()
            .find(|(label, _)| *label == "local")
            .map(|(_, path)| path.clone())
            .expect("local Claude settings path is always available"),
        ClaudeSettingsTarget::Global => paths
            .iter()
            .find(|(label, _)| *label == "global")
            .map(|(_, path)| path.clone())
            .ok_or_else(|| "could not determine home directory".to_string())?,
        ClaudeSettingsTarget::Explicit(path) => {
            paths = claude_settings_paths_with_explicit(paths, path.clone());
            path
        }
    };
    let result = install_claude_hook_to_path_with_mode(
        &config_path,
        mode,
        ensure_redact_version,
        command_for_running_binary,
    )?;
    for warning in claude_scope_conflicts(&paths) {
        eprintln!("[WARN] {warning}");
    }
    Ok(result)
}

pub(crate) fn claude_settings_paths(
    base: &Path,
    claude_config_dir: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Vec<(&'static str, PathBuf)> {
    let mut paths = vec![
        ("local", base.join(".claude/settings.json")),
        ("local override", base.join(".claude/settings.local.json")),
    ];
    if let Some(config_dir) = claude_config_dir.filter(|config_dir| !config_dir.is_empty()) {
        paths.push(("global", PathBuf::from(config_dir).join("settings.json")));
    } else if let Some(home) = home.filter(|home| !home.is_empty()) {
        paths.push(("global", PathBuf::from(home).join(".claude/settings.json")));
    }
    paths
}

pub(crate) fn claude_settings_paths_with_explicit(
    mut paths: Vec<(&'static str, PathBuf)>,
    explicit: PathBuf,
) -> Vec<(&'static str, PathBuf)> {
    if !paths
        .iter()
        .any(|(_, path)| same_resolved_path(path, &explicit))
    {
        paths.push(("explicit", explicit));
    }
    paths
}

pub(crate) fn same_resolved_path(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left == right
}

/// version is checked before any directory creation or settings replacement.
pub(crate) fn ensure_redact_version() -> Result<(), String> {
    let output = std::process::Command::new("claude")
        .arg("--version")
        .output()
        .map_err(|_| {
            "redact requires Claude Code >=2.1.121; could not determine installed version"
                .to_string()
        })?;
    if !output.status.success() {
        return Err("redact requires Claude Code >=2.1.121; version check failed".to_string());
    }
    validate_redact_version(&String::from_utf8_lossy(&output.stdout))
}

fn validate_redact_version(output: &str) -> Result<(), String> {
    let version = output.split_whitespace().next().unwrap_or("");
    let mut parts = version.split('.');
    let parsed = (|| {
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((major, minor, patch))
    })();
    match parsed {
        Some(version) if version >= (2, 1, 121) => Ok(()),
        Some(_) => Err(
            "redact requires Claude Code >=2.1.121; installed version is unsupported".to_string(),
        ),
        None => Err(
            "redact requires Claude Code >=2.1.121; could not determine installed version"
                .to_string(),
        ),
    }
}

fn read_settings(config_path: &Path) -> Result<serde_json::Value, String> {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| format!("malformed JSON in {}: {}", config_path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(e) => Err(format!("failed to read {}: {}", config_path.display(), e)),
    }
}

pub(crate) struct ClaudeHook {
    pub(crate) event: String,
    pub(crate) group_index: usize,
    pub(crate) hook_index: usize,
    pub(crate) mode: ClaudeHookMode,
    pub(crate) command: String,
    pub(crate) current: bool,
    pub(crate) blocks_read: bool,
}

struct ParsedHookCommand {
    executable: PathBuf,
    mode: ClaudeHookMode,
    current_args: bool,
}

/// returns the hook mode for a recognised sekretbarilo Claude hook command.
pub fn is_sekretbarilo_hook_command(command: &str) -> Option<ClaudeHookMode> {
    parse_sekretbarilo_hook_command(command).map(|parsed| parsed.mode)
}

pub(crate) fn sekretbarilo_hook_executable(command: &str) -> Option<PathBuf> {
    parse_sekretbarilo_hook_command(command).map(|parsed| parsed.executable)
}

fn parse_sekretbarilo_hook_command(command: &str) -> Option<ParsedHookCommand> {
    let (executable, args) = sekretbarilo_command_parts(command)?;

    let (mode, current_args) = match args.trim_end() {
        "check-file --stdin-json" => (ClaudeHookMode::Block, true),
        "redact-claude --stdin-json" => (ClaudeHookMode::Redact, true),
        args if args.split_whitespace().next() == Some("scan-file") => {
            (ClaudeHookMode::Block, false)
        }
        args if args.split_whitespace().next() == Some("redact-claude") => {
            (ClaudeHookMode::Redact, false)
        }
        _ => return None,
    };
    Some(ParsedHookCommand {
        executable,
        mode,
        current_args,
    })
}

pub(crate) fn sekretbarilo_command_parts(command: &str) -> Option<(PathBuf, &str)> {
    let command = command.trim();
    let (executable, args) = parse_hook_executable(command)?;
    let executable = PathBuf::from(executable);
    is_sekretbarilo_executable(&executable).then_some((executable, args))
}

pub(crate) fn sekretbarilo_subcommand_executable(
    command: &str,
    subcommand: &str,
) -> Option<PathBuf> {
    let (executable, args) = sekretbarilo_command_parts(command)?;
    (args.split_whitespace().next() == Some(subcommand)).then_some(executable)
}

pub(crate) fn parse_hook_executable(command: &str) -> Option<(String, &str)> {
    if let Some(quoted) = command.strip_prefix('\'') {
        let end = quoted.find('\'')?;
        let args = quoted.get(end + 1..)?;
        if !args.chars().next().is_some_and(char::is_whitespace) {
            return None;
        }
        return Some((quoted[..end].to_string(), args.trim_start()));
    }
    if let Some(quoted) = command.strip_prefix('"') {
        let mut executable = String::new();
        let mut characters = quoted.char_indices();
        while let Some((index, character)) = characters.next() {
            match character {
                '\\' => executable.push(characters.next()?.1),
                '"' => {
                    let args = quoted.get(index + 1..)?;
                    if !args.chars().next().is_some_and(char::is_whitespace) {
                        return None;
                    }
                    return Some((executable, args.trim_start()));
                }
                _ => executable.push(character),
            }
        }
        return None;
    }
    let (executable, args) = command.split_once(char::is_whitespace)?;
    Some((executable.to_string(), args.trim_start()))
}

pub(crate) fn is_sekretbarilo_executable(executable: &Path) -> bool {
    if executable == Path::new("sekretbarilo") {
        return true;
    }
    if executable.is_absolute()
        && executable
            .file_name()
            .is_some_and(|name| name == "sekretbarilo")
    {
        return true;
    }
    false
}

fn command_for_running_binary(mode: ClaudeHookMode) -> String {
    command_for_running_binary_with_args(mode.args(), mode.command())
}

pub(crate) fn command_for_running_binary_with_args(args: &str, bare_command: &str) -> String {
    match std::env::current_exe() {
        Ok(path) => match command_for_binary_path_with_args(&path, args) {
            Some(command) => command,
            None => {
                eprintln!(
                    "[WARN] running sekretbarilo binary path is not valid UTF-8; installing a bare hook command"
                );
                bare_command.to_string()
            }
        },
        Err(error) => {
            eprintln!(
                "[WARN] could not determine the running sekretbarilo binary; installing a bare hook command: {error}"
            );
            bare_command.to_string()
        }
    }
}

#[cfg(test)]
fn command_for_binary_path(path: &Path, mode: ClaudeHookMode) -> Option<String> {
    command_for_binary_path_with_args(path, mode.args())
}

pub(crate) fn command_for_binary_path_with_args(path: &Path, args: &str) -> Option<String> {
    let path = path.to_str()?;
    let executable = if path
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._+-".contains(byte))
    {
        path.to_string()
    } else {
        let mut quoted = String::with_capacity(path.len() + 2);
        quoted.push('"');
        for character in path.chars() {
            if matches!(character, '"' | '\\' | '$' | '`') {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        quoted.push('"');
        quoted
    };
    Some(format!("{executable} {args}"))
}

/// discover every owned handler without changing event-local positions.
pub(crate) fn claude_hook_state(root: &serde_json::Value) -> Result<Vec<ClaudeHook>, String> {
    if !root.is_object() {
        return Err("settings is not a JSON object".to_string());
    }
    let Some(hooks) = root.get("hooks") else {
        return Ok(Vec::new());
    };
    let hooks = hooks
        .as_object()
        .ok_or_else(|| "hooks is not an object".to_string())?;
    let mut found = Vec::new();
    for (event, groups) in hooks {
        let groups = groups
            .as_array()
            .ok_or_else(|| format!("hooks.{event} is not an array"))?;
        for (group_index, group) in groups.iter().enumerate() {
            if !group.is_object() {
                return Err(format!(
                    "hooks.{event} group {group_index} is not an object"
                ));
            }
            let matcher = group.get("matcher").and_then(serde_json::Value::as_str);
            let Some(handlers) = group.get("hooks") else {
                continue;
            };
            let handlers = handlers.as_array().ok_or_else(|| {
                format!("hooks.{event} group {group_index} has non-array 'hooks' field")
            })?;
            for (hook_index, handler) in handlers.iter().enumerate() {
                let Some(command) = handler.get("command").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(parsed_command) = parse_sekretbarilo_hook_command(command) else {
                    continue;
                };
                let mode = parsed_command.mode;
                let matches_read = matcher.is_none_or(|matcher| {
                    matcher.is_empty()
                        || matcher == "*"
                        || regex::Regex::new(matcher).is_ok_and(|regex| regex.is_match("Read"))
                });
                found.push(ClaudeHook {
                    event: event.clone(),
                    group_index,
                    hook_index,
                    mode,
                    command: command.to_string(),
                    current: event == mode.event()
                        && matcher == Some(mode.matcher())
                        && parsed_command.current_args
                        && handler.get("type").and_then(serde_json::Value::as_str)
                            == Some("command")
                        && handler.get("if").is_none()
                        && handler.get("args").is_none()
                        && (mode != ClaudeHookMode::Redact
                            || (handler.get("timeout").and_then(serde_json::Value::as_u64)
                                == Some(10)
                                && handler.get("async").is_none_or(|value| value == false)
                                && handler
                                    .get("asyncRewake")
                                    .is_none_or(|value| value == false))),
                    blocks_read: mode == ClaudeHookMode::Block
                        && event == "PreToolUse"
                        && matches_read,
                });
            }
        }
    }
    Ok(found)
}

pub(crate) fn claude_scope_conflicts(paths: &[(&str, PathBuf)]) -> Vec<String> {
    let mut states = Vec::new();
    let mut warnings = Vec::new();
    for (scope, path) in paths {
        match read_settings(path).and_then(|root| claude_hook_state(&root)) {
            Ok(hooks) => states.push((*scope, path, hooks)),
            Err(_) => warnings.push(format!(
                "could not inspect {scope} Claude settings for hook conflicts ({})",
                path.display()
            )),
        }
    }
    for (redact_scope, redact_path, hooks) in &states {
        if !hooks.iter().any(|hook| hook.mode == ClaudeHookMode::Redact) {
            continue;
        }
        for (block_scope, block_path, hooks) in &states {
            if redact_path != block_path && hooks.iter().any(|hook| hook.blocks_read) {
                warnings.push(format!("Claude redact hook in {redact_scope} settings ({}) conflicts with a blocking Read hook in {block_scope} settings ({}); switch or remove that hook in its own scope", redact_path.display(), block_path.display()));
            }
        }
    }
    warnings
}

fn install_claude_hook_to_path_with_mode(
    config_path: &Path,
    requested_mode: Option<ClaudeHookMode>,
    check_version: impl FnOnce() -> Result<(), String>,
    command_for_mode: impl FnOnce(ClaudeHookMode) -> String,
) -> Result<HookInstallResult, String> {
    let original = read_settings(config_path)?;
    let installed = claude_hook_state(&original)?;
    let mode = match requested_mode {
        Some(mode) => mode,
        None => {
            let block = installed
                .iter()
                .any(|hook| hook.mode == ClaudeHookMode::Block);
            let redact = installed
                .iter()
                .any(|hook| hook.mode == ClaudeHookMode::Redact);
            if block && redact {
                return Err("both Claude block and redact hooks exist; choose --mode block or --mode redact".to_string());
            }
            if redact {
                ClaudeHookMode::Redact
            } else {
                ClaudeHookMode::Block
            }
        }
    };
    if mode == ClaudeHookMode::Redact {
        check_version()?;
    }

    let command = command_for_mode(mode);
    let search = find_hook_for_event(&original, mode.event(), mode.matcher(), &command);
    let keep = installed.iter().find(|hook| {
        hook.event == mode.event() && Some(hook.group_index) == search.matching_group_index
    });
    let mut root = original.clone();
    let hooks = root
        .as_object_mut()
        .ok_or("settings is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or("hooks is not an object")?;
    // keep empty groups so unrelated event group indices and order stay fixed.
    for position in installed.iter().rev() {
        if keep.is_some_and(|keep| std::ptr::eq(keep, position)) {
            continue;
        }
        if let Some(handlers) = hooks
            .get_mut(&position.event)
            .and_then(|groups| groups.get_mut(position.group_index))
            .and_then(|group| group.get_mut("hooks"))
            .and_then(serde_json::Value::as_array_mut)
        {
            handlers.remove(position.hook_index);
        }
    }
    let groups = hooks
        .entry(mode.event())
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("hook event is not an array")?;
    let group_index = search.matching_group_index.unwrap_or_else(|| {
        groups.push(serde_json::json!({"matcher": mode.matcher(), "hooks": []}));
        groups.len() - 1
    });
    let group = groups
        .get_mut(group_index)
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("hook group is not an object")?;
    let handlers = group
        .entry("hooks")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("hook handlers is not an array")?;
    let retained = handlers.iter_mut().find(|handler| {
        handler
            .get("command")
            .and_then(serde_json::Value::as_str)
            .and_then(is_sekretbarilo_hook_command)
            .is_some()
    });
    let mut handler = retained
        .as_deref()
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let fields = handler
        .as_object_mut()
        .ok_or("hook handler is not an object")?;
    fields.insert("type".to_string(), "command".into());
    fields.insert("command".to_string(), command.into());
    fields.insert("timeout".to_string(), 10.into());
    fields.insert(
        "statusMessage".to_string(),
        match mode {
            ClaudeHookMode::Block => "Scanning file for secrets...",
            ClaudeHookMode::Redact => "Redacting tool output secrets...",
        }
        .into(),
    );
    fields.remove("async");
    fields.remove("asyncRewake");
    fields.remove("if");
    fields.remove("args");
    if let Some(retained) = retained {
        *retained = handler;
    } else {
        handlers.push(handler);
    }
    if root == original {
        return Ok(HookInstallResult::AlreadyInstalled);
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
    }

    write_config(config_path, &root)?;
    Ok(if installed.is_empty() {
        HookInstallResult::Created
    } else {
        HookInstallResult::Updated
    })
}

/// resolve the project root directory via git rev-parse
fn resolve_project_root() -> Option<PathBuf> {
    crate::doctor::resolve_repo_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_json(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn test_binary_path(config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .unwrap()
            .join("bin")
            .join("sekretbarilo")
    }

    fn test_hook_command(config_path: &Path, mode: ClaudeHookMode) -> String {
        command_for_binary_path(&test_binary_path(config_path), mode).unwrap()
    }

    fn install_claude_hook_to_path(config_path: &Path) -> Result<HookInstallResult, String> {
        install_claude_hook_to_path_with_mode_for_test(config_path, None, ensure_redact_version)
    }

    fn install_claude_hook_to_path_with_mode_for_test(
        config_path: &Path,
        requested_mode: Option<ClaudeHookMode>,
        check_version: impl FnOnce() -> Result<(), String>,
    ) -> Result<HookInstallResult, String> {
        install_claude_hook_to_path_with_mode(config_path, requested_mode, check_version, |mode| {
            test_hook_command(config_path, mode)
        })
    }

    #[test]
    fn recognises_bare_and_absolute_claude_hook_commands() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = dir.path().join("sekretbarilo");
        let quoted = dir.path().join("path with spaces").join("sekretbarilo");
        let with_dollar = dir.path().join("path$with$dollars").join("sekretbarilo");

        assert_eq!(
            is_sekretbarilo_hook_command(HOOK_COMMAND),
            Some(ClaudeHookMode::Block)
        );
        assert_eq!(
            is_sekretbarilo_hook_command(&format!(
                "{} redact-claude --stdin-json",
                absolute.display()
            )),
            Some(ClaudeHookMode::Redact)
        );
        assert_eq!(
            is_sekretbarilo_hook_command(&format!(
                "\"{}\" check-file --stdin-json",
                quoted.display()
            )),
            Some(ClaudeHookMode::Block)
        );
        assert_eq!(
            is_sekretbarilo_hook_command(&format!(
                "\"{}\" check-file --stdin-json",
                with_dollar.display().to_string().replace('$', "\\$")
            )),
            Some(ClaudeHookMode::Block)
        );
        assert_eq!(
            is_sekretbarilo_hook_command("'/x/y/sekretbarilo' redact-claude --stdin-json"),
            Some(ClaudeHookMode::Redact)
        );
        assert_eq!(
            is_sekretbarilo_hook_command("other-tool check-file --stdin-json"),
            None
        );
    }

    #[test]
    fn installer_uses_the_unresolved_running_binary_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        install_claude_hook_to_path_with_mode(
            &path,
            None,
            ensure_redact_version,
            command_for_running_binary,
        )
        .unwrap();

        let parsed = read_settings(&path).unwrap();
        let command = parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert_eq!(
            command,
            command_for_binary_path(&std::env::current_exe().unwrap(), ClaudeHookMode::Block)
                .unwrap()
        );
    }

    #[test]
    #[cfg(unix)]
    fn command_builder_preserves_a_symlink_path() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        let link_dir = dir.path().join("link");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::create_dir_all(&link_dir).unwrap();
        let target = target_dir.join("sekretbarilo");
        let link = link_dir.join("sekretbarilo");
        std::fs::write(&target, "stub").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let command = command_for_binary_path(&link, ClaudeHookMode::Block).unwrap();

        assert_eq!(
            command,
            format!("{} check-file --stdin-json", link.display())
        );
        assert!(!command.contains(target.to_str().unwrap()));
    }

    #[test]
    fn command_builder_quotes_a_path_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let spaced = dir.path().join("path with spaces").join("sekretbarilo");

        let spaced_command = command_for_binary_path(&spaced, ClaudeHookMode::Block).unwrap();

        assert_eq!(
            spaced_command,
            format!("\"{}\" check-file --stdin-json", spaced.display())
        );
        assert_eq!(
            is_sekretbarilo_hook_command(&spaced_command),
            Some(ClaudeHookMode::Block)
        );
    }

    #[test]
    fn command_builder_quotes_and_escapes_a_path_with_dollars() {
        let dir = tempfile::tempdir().unwrap();
        let dollar = dir.path().join("path$with$dollars").join("sekretbarilo");

        let dollar_command = command_for_binary_path(&dollar, ClaudeHookMode::Redact).unwrap();

        assert_eq!(
            dollar_command,
            format!(
                "\"{}\" redact-claude --stdin-json",
                dollar.display().to_string().replace('$', "\\$")
            )
        );
        assert_eq!(
            is_sekretbarilo_hook_command(&dollar_command),
            Some(ClaudeHookMode::Redact)
        );
    }

    #[test]
    fn redact_version_requires_known_supported_release() {
        for version in [
            "2.1.121 (Claude Code)",
            "2.1.261 (Claude Code)",
            "2.2.0",
            "3.0.0",
        ] {
            assert!(validate_redact_version(version).is_ok(), "{version}");
        }
        for version in [
            "",
            "unknown",
            "2.1.120 (Claude Code)",
            "1.9.999",
            "2.1",
            "2.1.121-preview",
            "2.1.121.0",
            "99999999999999999999999.0.0",
        ] {
            assert!(validate_redact_version(version).is_err(), "{version}");
        }
    }

    #[test]
    fn rejected_redact_version_preserves_settings_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        install_claude_hook_to_path(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let error = install_claude_hook_to_path_with_mode_for_test(
            &path,
            Some(ClaudeHookMode::Redact),
            || Err("unsupported version".into()),
        );
        assert!(error.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let new = dir.path().join("absent/settings.json");
        assert!(
            install_claude_hook_to_path_with_mode_for_test(
                &new,
                Some(ClaudeHookMode::Redact),
                || Err("unknown version".into())
            )
            .is_err()
        );
        assert!(!new.parent().unwrap().exists());
    }

    #[test]
    fn mode_switch_deduplicates_across_events_and_preserves_foreign_groups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let foreign = serde_json::json!({"type": "command", "command": "echo sekretbarilo", "unknown": [1, 2]});
        let codex = serde_json::json!({"matcher": super::super::CODEX_HOOK_MATCHER, "hooks": [{"command": super::super::CODEX_HOOK_COMMAND}]});
        let original = serde_json::json!({"unknown": {"retained": true}, "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [foreign.clone()]},
                {"matcher": "Read", "hooks": [{"command": HOOK_COMMAND}, foreign.clone(), {"command": "sekretbarilo scan-file --old-flag"}]},
                codex.clone()
            ],
            "PostToolUse": [
                {"matcher": REDACT_HOOK_MATCHER, "unknownGroup": 9, "hooks": [foreign.clone()]},
                {"matcher": REDACT_HOOK_MATCHER, "hooks": [{"command": REDACT_HOOK_COMMAND, "async": true}]}
            ],
            "Stop": [{"hooks": [{"command": "sekretbarilo redact-claude --old"}, foreign.clone()]}]
        }});
        write_json(&path, &original);
        assert_eq!(
            install_claude_hook_to_path_with_mode_for_test(
                &path,
                Some(ClaudeHookMode::Redact),
                || Ok(())
            )
            .unwrap(),
            HookInstallResult::Updated
        );
        let redact = read_settings(&path).unwrap();
        let owned = claude_hook_state(&redact).unwrap();
        assert_eq!(owned.len(), 1);
        assert!(owned[0].current);
        assert_eq!(owned[0].mode, ClaudeHookMode::Redact);
        assert_eq!(redact["unknown"], original["unknown"]);
        assert_eq!(
            redact["hooks"]["PreToolUse"][0],
            original["hooks"]["PreToolUse"][0]
        );
        assert_eq!(
            redact["hooks"]["PreToolUse"][1]["hooks"],
            serde_json::json!([foreign.clone()])
        );
        assert_eq!(redact["hooks"]["PreToolUse"][2], codex);
        assert_eq!(
            redact["hooks"]["Stop"][0]["hooks"],
            serde_json::json!([foreign])
        );
        assert_eq!(redact["hooks"]["PostToolUse"][0]["unknownGroup"], 9);
        assert!(
            redact["hooks"]["PostToolUse"][1]["hooks"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            install_claude_hook_to_path_with_mode_for_test(&path, None, || Ok(())).unwrap(),
            HookInstallResult::AlreadyInstalled
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(
            install_claude_hook_to_path_with_mode_for_test(&path, None, || Err(
                "unsupported".into()
            ))
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            install_claude_hook_to_path_with_mode_for_test(
                &path,
                Some(ClaudeHookMode::Block),
                || panic!("block should not check Claude version")
            )
            .unwrap(),
            HookInstallResult::Updated
        );
        let block = read_settings(&path).unwrap();
        let owned = claude_hook_state(&block).unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].mode, ClaudeHookMode::Block);
        assert!(owned[0].current);
        assert_eq!(block["hooks"]["PreToolUse"][2], codex);
    }

    #[test]
    fn retained_redact_handler_becomes_synchronous_with_unknown_fields_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        write_json(
            &path,
            &serde_json::json!({"hooks": {"PostToolUse": [{"matcher": REDACT_HOOK_MATCHER, "hooks": [
                {"type": "command", "command": REDACT_HOOK_COMMAND, "async": true, "asyncRewake": true, "if": "tool_name == 'Read'", "args": ["--old"], "timeout": 1, "custom": "keep"},
                {"type": "command", "command": REDACT_HOOK_COMMAND}
            ]}]}}),
        );
        install_claude_hook_to_path_with_mode_for_test(&path, None, || Ok(())).unwrap();
        let parsed = read_settings(&path).unwrap();
        let handlers = parsed["hooks"]["PostToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["custom"], "keep");
        assert_eq!(handlers[0]["timeout"], 10);
        assert!(handlers[0].get("async").is_none());
        assert!(handlers[0].get("asyncRewake").is_none());
        assert!(handlers[0].get("if").is_none());
        assert!(handlers[0].get("args").is_none());
    }

    #[test]
    fn malformed_hook_structure_never_replaces_original() {
        for malformed in [
            serde_json::json!({"hooks": {"PostToolUse": {}}}),
            serde_json::json!({"hooks": {"PostToolUse": [5]}}),
            serde_json::json!({"hooks": {"PostToolUse": [{"matcher": REDACT_HOOK_MATCHER, "hooks": {}}]}}),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("settings.json");
            write_json(&path, &malformed);
            let before = std::fs::read(&path).unwrap();
            assert!(
                install_claude_hook_to_path_with_mode_for_test(
                    &path,
                    Some(ClaudeHookMode::Redact),
                    || Ok(())
                )
                .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn detects_conflicts_in_both_other_scopes_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = [
            ("redact", dir.path().join("redact.json")),
            ("global", dir.path().join("global.json")),
            ("local override", dir.path().join("override.json")),
        ];
        install_claude_hook_to_path_with_mode_for_test(
            &paths[0].1,
            Some(ClaudeHookMode::Redact),
            || Ok(()),
        )
        .unwrap();
        for (_, path) in &paths[1..] {
            install_claude_hook_to_path(path).unwrap();
        }
        let before: Vec<_> = paths
            .iter()
            .map(|(_, path)| std::fs::read(path).unwrap())
            .collect();
        let conflicts = claude_scope_conflicts(&paths);
        assert_eq!(conflicts.len(), 2);
        assert!(
            conflicts
                .iter()
                .all(|message| message.contains("blocking Read hook"))
        );
        assert!(
            conflicts
                .iter()
                .any(|message| message.contains("local override"))
        );
        for ((_, path), before) in paths.iter().zip(before) {
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
    }

    #[test]
    fn omitted_mode_does_not_guess_when_both_modes_are_installed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        write_json(
            &path,
            &serde_json::json!({"hooks": {
                "PreToolUse": [{"matcher": "Read", "hooks": [{"command": HOOK_COMMAND}]}],
                "PostToolUse": [{"matcher": REDACT_HOOK_MATCHER, "hooks": [{"command": REDACT_HOOK_COMMAND}]}]
            }}),
        );
        let before = std::fs::read(&path).unwrap();
        assert!(
            install_claude_hook_to_path_with_mode_for_test(&path, None, || Ok(()))
                .unwrap_err()
                .contains("choose --mode")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    // -- claude code hook installation tests --

    #[test]
    fn install_claude_hook_creates_new_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".claude").join("settings.json");

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);

        // verify file was created with correct structure
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        let hooks = &parsed["hooks"]["PreToolUse"];
        assert!(hooks.is_array());
        let arr = hooks.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Read");
        let hook_arr = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hook_arr.len(), 1);
        assert_eq!(
            hook_arr[0]["command"],
            test_hook_command(&config_path, ClaudeHookMode::Block)
        );
        assert_eq!(hook_arr[0]["timeout"], 10);
        assert_eq!(hook_arr[0]["statusMessage"], "Scanning file for secrets...");
    }

    #[test]
    fn install_claude_hook_preserves_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // write existing config with unrelated settings
        let existing = serde_json::json!({
            "model": "claude-sonnet-4-5-20250929",
            "permissions": {"allow": ["Read"]}
        });
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);

        // verify existing settings are preserved
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["model"], "claude-sonnet-4-5-20250929");
        assert!(parsed["permissions"]["allow"].is_array());
        // and hook was added
        assert!(parsed["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn install_claude_hook_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".claude").join("settings.json");

        // first install
        let result1 = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result1, HookInstallResult::Created);

        // second install should detect already installed
        let result2 = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result2, HookInstallResult::AlreadyInstalled);

        // verify only one hook entry
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn install_claude_hook_preserves_other_pre_tool_use_matchers() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // write existing config with another PreToolUse hook
        let existing = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [{"type": "command", "command": "echo write hook"}]
                    }
                ]
            }
        });
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);

        // verify both entries exist
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["matcher"], "Write");
        assert_eq!(arr[1]["matcher"], "Read");
    }

    #[test]
    fn install_claude_hook_appends_to_existing_read_matcher() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // write existing config with Read matcher and another hook
        let existing = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [{"type": "command", "command": "echo other hook"}]
                    }
                ]
            }
        });
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);

        // verify our hook was appended to the existing Read hooks array
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1); // still one Read entry
        let hooks = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2); // two hooks in it
        assert_eq!(hooks[0]["command"], "echo other hook");
        assert_eq!(
            hooks[1]["command"],
            test_hook_command(&config_path, ClaudeHookMode::Block)
        );
    }

    #[test]
    fn install_claude_hook_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        std::fs::write(&config_path, "not valid json{{{").unwrap();

        let result = install_claude_hook_to_path(&config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("malformed JSON"));
    }

    #[test]
    fn install_claude_hook_preserves_other_hook_events() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // config with PostToolUse hooks (should be untouched)
        let existing = serde_json::json!({
            "hooks": {
                "PostToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo done"}]}
                ]
            }
        });
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        // PostToolUse preserved
        assert!(parsed["hooks"]["PostToolUse"].is_array());
        // PreToolUse added
        assert!(parsed["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn install_claude_hook_updates_old_sekretbarilo_command() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // config with an older sekretbarilo command
        let existing = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [{"type": "command", "command": "sekretbarilo scan-file --old-flag", "timeout": 5}]
                    }
                ]
            }
        });
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Updated);

        // verify the command was updated
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        let hooks = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(
            hooks[0]["command"],
            test_hook_command(&config_path, ClaudeHookMode::Block)
        );
        assert_eq!(hooks[0]["timeout"], 10);
        assert_eq!(hooks[0]["statusMessage"], "Scanning file for secrets...");
    }

    #[test]
    fn install_claude_hook_global_path_resolution() {
        // test that install_claude_hook constructs the correct path for global mode
        // we can't easily test the actual HOME-based path, but we can test install_claude_hook_to_path
        // with a path that simulates ~/.claude/settings.json
        let dir = tempfile::tempdir().unwrap();
        let global_claude_dir = dir.path().join(".claude");
        let config_path = global_claude_dir.join("settings.json");

        // should create the .claude directory and settings.json
        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, HookInstallResult::Created);
        assert!(global_claude_dir.exists());
        assert!(config_path.exists());
    }

    #[test]
    fn install_claude_hook_root_not_object() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let config_path = claude_dir.join("settings.json");

        // JSON array instead of object
        std::fs::write(&config_path, "[1, 2, 3]").unwrap();

        let result = install_claude_hook_to_path(&config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a JSON object"));
    }
}
