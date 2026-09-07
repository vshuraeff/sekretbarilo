use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use super::apply_patch;
use super::hooks_json::{HookInstallResult, find_hook, write_config};
use crate::audit::history::sanitize_display;
use crate::config;
use crate::config::allowlist::CompiledAllowlist;
use crate::diff::parser::{AddedLine, DiffFile};
use crate::output::masking::mask_secret;
use crate::scanner::engine::{Finding, scan};
use crate::scanner::rules::{CompiledScanner, compile_rules};

const MAX_PAYLOAD_BYTES: u64 = 10 * 1024 * 1024;
const BASH_SYNTHETIC_PATH: &str = "<bash-command>";
// twenty findings preserve useful variety while bounding hook feedback.
pub(super) const MAX_RENDERED_FINDINGS: usize = 20;

/// Frozen command string consumed by the Codex hook installer follow-up.
pub const CODEX_HOOK_COMMAND: &str = "sekretbarilo check-codex --stdin-json";
pub const CODEX_HOOK_MATCHER: &str = "^(apply_patch|Bash)$";

/// resolve the global Codex home directory from CODEX_HOME (if non-empty) or HOME.
/// an exported-but-empty CODEX_HOME must be treated as unset, matching upstream
/// Codex CLI's own fallback behavior — never treated as a relative path root.
pub(crate) fn resolve_codex_home(
    codex_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    if let Some(value) = codex_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("CODEX_HOME must be an absolute path".to_string());
        }
        return Ok(path);
    }
    let home = home
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "could not determine home directory".to_string())?;
    let path = PathBuf::from(home).join(".codex");
    if !path.is_absolute() {
        return Err("HOME must resolve to an absolute Codex home path".to_string());
    }
    Ok(path)
}

pub fn install_codex_hook(global: bool) -> Result<HookInstallResult, String> {
    let hooks_path = if global {
        let codex_home =
            resolve_codex_home(std::env::var_os("CODEX_HOME"), std::env::var_os("HOME"))?;
        codex_home.join("hooks.json")
    } else {
        let repo_root = match crate::doctor::resolve_repo_root() {
            Some(root) => root,
            None => {
                let current_dir = std::env::current_dir()
                    .map_err(|error| format!("failed to determine current directory: {error}"))?;
                eprintln!(
                    "[WARN] not inside a git repository, using current directory for local hook placement: {}",
                    current_dir.display()
                );
                current_dir
            }
        };
        repo_root.join(".codex").join("hooks.json")
    };

    let result = install_codex_hook_to_path(&hooks_path)?;
    eprintln!("[OK] {}", result.describe("codex cli"));
    print_post_install_notes(&hooks_path);
    Ok(result)
}

fn install_codex_hook_to_path(path: &Path) -> Result<HookInstallResult, String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }

    // read existing config or start fresh (read unconditionally to avoid TOCTOU race)
    let mut config: Value = match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|error| format!("failed to parse {}: {error}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    };

    let hook_match = find_hook(&config, CODEX_HOOK_MATCHER, CODEX_HOOK_COMMAND);
    if hook_match.exact_hook.is_some() {
        return Ok(HookInstallResult::AlreadyInstalled);
    }

    let root = config
        .as_object_mut()
        .ok_or_else(|| format!("{} root is not a JSON object", path.display()))?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| format!("{}.hooks is not a JSON object", path.display()))?;
    let pre_tool_use = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    let pre_tool_use = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| format!("{}.hooks.PreToolUse is not a JSON array", path.display()))?;

    if let Some((group_index, hook_index)) = hook_match.first_sekretbarilo_hook {
        let handler = pre_tool_use[group_index]["hooks"][hook_index]
            .as_object_mut()
            .ok_or_else(|| {
                "existing sekretbarilo codex hook handler is not a JSON object".to_string()
            })?;
        if let Value::Object(pinned) = codex_hook_handler() {
            for (key, value) in pinned {
                handler.insert(key, value);
            }
        }
        write_config(path, &config)?;
        return Ok(HookInstallResult::Updated);
    }

    if let Some(group) = pre_tool_use
        .iter_mut()
        .find(|group| group.get("matcher").and_then(Value::as_str) == Some(CODEX_HOOK_MATCHER))
    {
        let group = group
            .as_object_mut()
            .ok_or_else(|| "Codex hook matcher group is not a JSON object".to_string())?;
        let handlers = group.entry("hooks").or_insert_with(|| json!([]));
        let handlers = handlers
            .as_array_mut()
            .ok_or_else(|| "Codex hook matcher group's hooks field is not an array".to_string())?;
        handlers.push(codex_hook_handler());
    } else {
        pre_tool_use.push(json!({
            "matcher": CODEX_HOOK_MATCHER,
            "hooks": [codex_hook_handler()]
        }));
    }

    write_config(path, &config)?;
    Ok(HookInstallResult::Created)
}

fn codex_hook_handler() -> Value {
    json!({
        "type": "command",
        "command": CODEX_HOOK_COMMAND,
        "timeout": 10,
        "statusMessage": "Scanning tool input for secrets..."
    })
}

fn print_post_install_notes(hooks_path: &Path) {
    eprintln!("[WARN] IMPORTANT: Codex will silently skip this hook until you approve it.");
    eprintln!("       In the Codex TUI, run /hooks and approve the sekretbarilo hook.");
    eprintln!(
        "       For non-interactive automation only, --dangerously-bypass-hook-trust bypasses this protection."
    );

    let config_toml = hooks_path.with_file_name("config.toml");
    if has_hooks_table(&config_toml) {
        eprintln!(
            "[NOTE] a second Codex hook representation exists at {}; Codex will load both representations and warn",
            config_toml.display()
        );
    }

    match Command::new("codex").arg("--version").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let version = if stdout.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            if version.is_empty() {
                eprintln!("[NOTE] Codex was found on PATH, but did not report a version");
            } else {
                eprintln!("[INFO] detected Codex version: {version}");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "[NOTE] hook file was written to {}, but Codex was not found on PATH",
                hooks_path.display()
            );
        }
        Err(error) => {
            eprintln!("[NOTE] hook file was written, but Codex version detection failed: {error}");
        }
    }
}

fn has_hooks_table(config_toml: &Path) -> bool {
    // heuristic: unusual formatting such as `[ hooks ]` is not detected.
    fs::read_to_string(config_toml)
        .map(|content| content.lines().any(|line| line.trim() == "[hooks]"))
        .unwrap_or(false)
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PreToolUsePayload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    turn_id: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    agent_type: Option<String>,
    #[serde(default)]
    transcript_path: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    hook_event_name: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    permission_mode: Option<String>,
    tool_name: String,
    tool_input: Value,
    #[serde(default)]
    tool_use_id: Option<String>,
}

struct ScanContext {
    scanner: CompiledScanner,
    allowlist: CompiledAllowlist,
    bash_allowlist: CompiledAllowlist,
}

#[derive(Debug, PartialEq)]
enum HookDecision {
    Allow,
    Block(String),
}

/// Read and check a Codex `PreToolUse` payload from stdin.
///
/// Returns only 0 (allow) or 2 (block). Every block is emitted to stderr by
/// `finish_decision`; this module deliberately has no stdout write path.
pub fn run_check_codex() -> i32 {
    let decision = evaluate_reader(std::io::stdin().lock());
    finish_decision(decision)
}

fn evaluate_reader(reader: impl Read) -> HookDecision {
    evaluate_reader_with_loader(reader, load_scan_context)
}

fn evaluate_reader_with_loader<F>(reader: impl Read, load_context: F) -> HookDecision
where
    F: FnOnce(Option<&str>) -> Result<ScanContext, String>,
{
    let mut input = Vec::new();
    let mut bounded = reader.take(MAX_PAYLOAD_BYTES + 1);
    if let Err(error) = bounded.read_to_end(&mut input) {
        let error = sanitize_display(&error.to_string());
        return HookDecision::Block(format!("failed to read Codex hook stdin: {error}"));
    }
    if input.len() as u64 > MAX_PAYLOAD_BYTES {
        return HookDecision::Block(format!(
            "Codex hook payload truncated: input exceeds {} bytes",
            MAX_PAYLOAD_BYTES
        ));
    }

    evaluate_payload_with_loader(&input, load_context)
}

fn evaluate_payload_with_loader<F>(input: &[u8], load_context: F) -> HookDecision
where
    F: FnOnce(Option<&str>) -> Result<ScanContext, String>,
{
    let value: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(error) => {
            let error = sanitize_display(&error.to_string());
            return HookDecision::Block(format!("malformed Codex hook JSON: {error}"));
        }
    };

    let payload: PreToolUsePayload = match serde_json::from_value(value) {
        Ok(payload) => payload,
        Err(error) => {
            let error = sanitize_display(&error.to_string());
            return HookDecision::Block(format!("Codex hook payload schema mismatch: {error}"));
        }
    };

    if payload.hook_event_name != "PreToolUse" {
        return HookDecision::Allow;
    }

    match payload.tool_name.as_str() {
        "apply_patch" => {
            let command = match command_from_tool_input(&payload.tool_input, "apply_patch") {
                Ok(command) => command,
                Err(reason) => return HookDecision::Block(reason),
            };
            evaluate_apply_patch(command, payload.cwd.as_deref(), load_context)
        }
        "Bash" => {
            let command = match command_from_tool_input(&payload.tool_input, "Bash") {
                Ok(command) => command,
                Err(reason) => return HookDecision::Block(reason),
            };
            evaluate_bash(command, payload.cwd.as_deref(), load_context)
        }
        _ => HookDecision::Allow,
    }
}

fn command_from_tool_input<'a>(tool_input: &'a Value, tool: &str) -> Result<&'a str, String> {
    let object = tool_input.as_object().ok_or_else(|| {
        format!("Codex {tool} tool_input schema mismatch: expected a JSON object")
    })?;
    let command = object
        .get("command")
        .ok_or_else(|| format!("Codex {tool} tool_input is missing 'command'"))?;
    command
        .as_str()
        .ok_or_else(|| format!("Codex {tool} tool_input.command must be a string"))
}

fn evaluate_apply_patch<F>(command: &str, cwd: Option<&str>, load_context: F) -> HookDecision
where
    F: FnOnce(Option<&str>) -> Result<ScanContext, String>,
{
    let parsed_files = match apply_patch::parse_apply_patch(command.as_bytes()) {
        Ok(files) => files,
        Err(error) => {
            let error = sanitize_display(&error);
            return HookDecision::Block(format!("Codex apply_patch parse error: {error}"));
        }
    };

    for file in &parsed_files {
        if crate::diff::is_blocked_env_file(&file.diff_file.path) {
            return HookDecision::Block(env_policy_reason(&file.diff_file.path));
        }
        if let Some(original_path) = file.original_path.as_deref()
            && crate::diff::is_blocked_env_file(original_path)
        {
            return HookDecision::Block(env_policy_reason(original_path));
        }
    }

    let context = match load_context(cwd) {
        Ok(context) => context,
        Err(error) => {
            let error = sanitize_display(&error);
            return HookDecision::Block(format!("Codex apply_patch scanner setup failed: {error}"));
        }
    };

    let files = parsed_files
        .into_iter()
        .map(|file| file.diff_file)
        .filter(|file| !context.allowlist.is_path_skipped(&file.path))
        .collect::<Vec<_>>();
    let findings = scan(&files, &context.scanner, &context.allowlist);

    findings_decision("apply_patch", &findings)
}

fn evaluate_bash<F>(command: &str, cwd: Option<&str>, load_context: F) -> HookDecision
where
    F: FnOnce(Option<&str>) -> Result<ScanContext, String>,
{
    let context = match load_context(cwd) {
        Ok(context) => context,
        Err(error) => {
            let error = sanitize_display(&error);
            return HookDecision::Block(format!("Codex Bash scanner setup failed: {error}"));
        }
    };

    let diff_file = DiffFile {
        path: BASH_SYNTHETIC_PATH.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: command
            .split('\n')
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    };
    let findings = scan(&[diff_file], &context.scanner, &context.bash_allowlist);

    findings_decision("Bash", &findings)
}

fn findings_decision(tool: &str, findings: &[Finding]) -> HookDecision {
    if findings.is_empty() {
        return HookDecision::Allow;
    }

    let mut reason = format!("[AGENT] Codex {tool} blocked: secret(s) detected\n");
    for finding in findings.iter().take(MAX_RENDERED_FINDINGS) {
        let file = sanitize_display(&finding.file);
        let rule_id = sanitize_display(&finding.rule_id);
        let masked = sanitize_display(&mask_secret(&finding.matched_value));
        let _ = writeln!(reason, "  file: {file}");
        let _ = writeln!(reason, "  line: {}", finding.line);
        let _ = writeln!(reason, "  rule: {rule_id}");
        let _ = writeln!(reason, "  match: {masked}");
    }
    if findings.len() > MAX_RENDERED_FINDINGS {
        let omitted = findings.len() - MAX_RENDERED_FINDINGS;
        let _ = writeln!(reason, "... and {omitted} more finding(s) omitted");
    }
    let _ = write!(
        reason,
        "{tool} action blocked to prevent secret exposure. total findings: {}.",
        findings.len()
    );

    HookDecision::Block(reason)
}

fn env_policy_reason(path: &str) -> String {
    let path = sanitize_display(path);
    format!(
        "[AGENT] Codex apply_patch blocked by .env policy\n  file: {path}\n.env files may contain environment secrets; writing was blocked."
    )
}

/// load only config layers whose provenance the hook can trust.
///
/// an untrusted in-workspace layer is dropped whole because config rules merge by
/// id, so an apparent rule addition can replace and disable a built-in rule.
pub(crate) fn load_trusted_project_config(
    base_dir: &Path,
) -> Result<config::ProjectConfig, String> {
    load_trusted_config(base_dir, false)
}

/// use the same trust boundary, but fail on config errors without logging input.
pub(crate) fn load_trusted_redact_config(base_dir: &Path) -> Result<config::ProjectConfig, String> {
    load_trusted_config(base_dir, true)
}

fn load_trusted_config(base_dir: &Path, strict: bool) -> Result<config::ProjectConfig, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.to_path_buf());
    let config_paths = config::discovery::discover_configs(base_dir, &home);
    if config_paths.is_empty() {
        return Ok(config::ProjectConfig::default());
    }

    let repo_root = resolve_git_repo_root(base_dir);
    let workspace_boundary = repo_root.clone().unwrap_or_else(|| {
        base_dir
            .canonicalize()
            .unwrap_or_else(|_| base_dir.to_path_buf())
    });
    let mut trusted = Vec::new();

    for path in config_paths {
        let path = path.canonicalize().unwrap_or(path);
        let is_in_workspace = path.starts_with(&workspace_boundary);
        let is_trusted = if !is_in_workspace {
            true
        } else if let Some(repo_root) = repo_root.as_deref() {
            is_committed_config(repo_root, &path)
        } else {
            false
        };

        if is_trusted {
            if strict {
                let content = std::fs::read_to_string(&path)
                    .map_err(|_| "could not read trusted configuration".to_string())?;
                let config = toml::from_str::<config::ProjectConfig>(&content)
                    .map_err(|_| "invalid trusted configuration".to_string())?;
                trusted.push(config);
            } else if let Some(config) = config::load_single_config(&path) {
                trusted.push(config);
            }
        } else if strict {
            let _ = writeln!(
                std::io::stderr(),
                "[WARN] ignoring untrusted in-workspace config"
            );
        } else {
            let path = sanitize_display(&path.to_string_lossy());
            let _ = writeln!(
                std::io::stderr(),
                "[WARN] ignoring untrusted in-workspace config: {path}"
            );
        }
    }

    Ok(config::merge::merge_all(trusted))
}

fn resolve_git_repo_root(base_dir: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(base_dir)
        .args(["rev-parse", "--show-toplevel"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let root = String::from_utf8(output.stdout).ok()?;
    let root = root.trim();
    if root.is_empty() {
        return None;
    }
    PathBuf::from(root).canonicalize().ok()
}

fn is_committed_config(repo_root: &Path, path: &Path) -> bool {
    let Ok(relative_path) = path.strip_prefix(repo_root) else {
        return false;
    };
    let tracked = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(relative_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !tracked.is_ok_and(|status| status.success()) {
        return false;
    }

    Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--quiet", "HEAD", "--"])
        .arg(relative_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn load_scan_context(cwd: Option<&str>) -> Result<ScanContext, String> {
    let base_dir = resolve_base_dir(cwd)?;
    let project_config = load_trusted_project_config(&base_dir)
        .map_err(|error| format!("failed to load project config: {error}"))?;
    let rules = config::load_rules_with_config(&project_config)
        .map_err(|error| format!("failed to load scanner rules: {error}"))?;
    let allowlist = config::build_allowlist(&project_config, &rules)
        .map_err(|error| format!("failed to build scanner allowlist: {error}"))?;
    let bash_allowlist = build_bash_allowlist(&project_config, &rules)
        .map_err(|error| format!("failed to build Bash scanner allowlist: {error}"))?;
    let scanner = compile_rules(&rules)
        .map_err(|error| format!("failed to compile scanner rules: {error}"))?;

    Ok(ScanContext {
        scanner,
        allowlist,
        bash_allowlist,
    })
}

fn build_bash_allowlist(
    project_config: &config::ProjectConfig,
    rules: &[crate::scanner::rules::Rule],
) -> Result<CompiledAllowlist, String> {
    let mut bash_config = project_config.clone();
    bash_config.allowlist.paths.clear();
    for rule in &mut bash_config.allowlist.rules {
        rule.paths.clear();
    }

    let mut bash_rules = rules.to_vec();
    for rule in &mut bash_rules {
        rule.allowlist.paths.clear();
    }

    config::build_allowlist(&bash_config, &bash_rules)
}

fn resolve_base_dir(cwd: Option<&str>) -> Result<PathBuf, String> {
    if let Some(cwd) = cwd
        && !cwd.trim().is_empty()
    {
        let path = Path::new(cwd);
        if path.is_dir() {
            return Ok(path.to_path_buf());
        }
    }

    std::env::current_dir()
        .map_err(|error| format!("failed to determine current directory: {error}"))
}

fn finish_decision(decision: HookDecision) -> i32 {
    match decision {
        HookDecision::Allow => 0,
        HookDecision::Block(reason) => block(&reason),
    }
}

fn block(reason: &str) -> i32 {
    let reason = if reason.trim().is_empty() {
        "[ERROR] Codex hook blocked because an internal error produced an empty reason"
    } else {
        reason
    };
    let _ = writeln!(std::io::stderr(), "{reason}");
    2
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};
    use std::process::{Command, Stdio};

    use serde_json::json;

    use super::*;

    fn test_scan_context() -> ScanContext {
        test_scan_context_with_config(config::ProjectConfig::default())
    }

    fn test_scan_context_with_config(config: config::ProjectConfig) -> ScanContext {
        let rules = config::load_rules_with_config(&config).unwrap();
        let allowlist = config::build_allowlist(&config, &rules).unwrap();
        let bash_allowlist = build_bash_allowlist(&config, &rules).unwrap();
        let scanner = compile_rules(&rules).unwrap();
        ScanContext {
            scanner,
            allowlist,
            bash_allowlist,
        }
    }

    fn payload(event: &str, tool: &str, tool_input: Value) -> Vec<u8> {
        payload_with_cwd(event, tool, tool_input, "/tmp")
    }

    fn payload_with_cwd(event: &str, tool: &str, tool_input: Value, cwd: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session_id": "session-1",
            "turn_id": "turn-1",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": event,
            "model": "gpt-test",
            "permission_mode": "default",
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "tool-1",
            "future_field": {"ignored": true}
        }))
        .unwrap()
    }

    fn evaluate(input: &[u8]) -> HookDecision {
        evaluate_payload_with_loader(input, |_| Ok(test_scan_context()))
    }

    fn assert_block_contains(decision: HookDecision, expected: &str) -> String {
        match decision {
            HookDecision::Block(reason) => {
                assert!(!reason.trim().is_empty());
                assert!(
                    reason.contains(expected),
                    "expected {expected:?} in {reason:?}"
                );
                reason
            }
            HookDecision::Allow => panic!("expected a blocking decision"),
        }
    }

    fn read_hook_config(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn compiled_binary() -> PathBuf {
        if let Some(path) = option_env!("CARGO_BIN_EXE_sekretbarilo") {
            return PathBuf::from(path);
        }

        let profile_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .to_path_buf();
        profile_dir.join(format!("sekretbarilo{}", std::env::consts::EXE_SUFFIX))
    }

    fn git_success(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
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

    fn secret_patch_payload(repo: &Path) -> Vec<u8> {
        let patch = "*** Begin Patch\n*** Add File: secret.rs\n+const KEY: &str = \"AKIAIOSFODNN7ABCDEFG\";\n*** End Patch\n";
        payload_with_cwd(
            "PreToolUse",
            "apply_patch",
            json!({"command": patch}),
            repo.to_str().unwrap(),
        )
    }

    fn permissive_config() -> &'static str {
        "[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\".*\"]\n"
    }

    #[test]
    fn resolve_codex_home_treats_empty_codex_home_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().as_os_str().to_os_string();
        let expected = dir.path().join(".codex");

        let empty =
            resolve_codex_home(Some(std::ffi::OsString::new()), Some(home.clone())).unwrap();
        let unset = resolve_codex_home(None, Some(home)).unwrap();

        assert_eq!(empty, expected);
        assert_eq!(unset, expected);
        assert_eq!(empty, unset);
        assert!(empty.is_absolute());
    }

    #[test]
    fn resolve_codex_home_rejects_empty_home() {
        assert!(resolve_codex_home(None, Some(std::ffi::OsString::new())).is_err());
    }

    #[test]
    fn resolve_codex_home_rejects_relative_codex_home() {
        assert!(resolve_codex_home(Some(std::ffi::OsString::from("relative/dir")), None).is_err());
    }

    #[test]
    fn install_codex_hook_creates_new_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".codex").join("hooks.json");

        let result = install_codex_hook_to_path(&path).unwrap();

        assert_eq!(result, HookInstallResult::Created);
        assert_eq!(
            read_hook_config(&path),
            json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": CODEX_HOOK_COMMAND,
                            "timeout": 10,
                            "statusMessage": "Scanning tool input for secrets..."
                        }]
                    }]
                }
            })
        );
    }

    #[test]
    fn install_codex_hook_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Created
        );
        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::AlreadyInstalled
        );

        let config = read_hook_config(&path);
        assert_eq!(config["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(
            config["hooks"]["PreToolUse"][0]["hooks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn install_codex_hook_appends_to_matching_matcher_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "foreign-hook"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Created
        );

        let config = read_hook_config(&path);
        let handlers = config["hooks"]["PreToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0]["command"], "foreign-hook");
        assert_eq!(handlers[1], codex_hook_handler());
    }

    #[test]
    fn install_codex_hook_updates_old_command_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Foo",
                            "hooks": [{"type": "command", "command": "foreign-before"}]
                        },
                        {
                            "matcher": CODEX_HOOK_MATCHER,
                            "hooks": [
                                {"type": "command", "command": "foreign-first"},
                                {
                                    "type": "command",
                                    "command": "sekretbarilo check-codex",
                                    "extra": "preserved"
                                },
                                {"type": "command", "command": "foreign-last"}
                            ]
                        }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Updated
        );

        let config = read_hook_config(&path);
        let groups = config["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        let handlers = groups[1]["hooks"].as_array().unwrap();
        assert_eq!(handlers.len(), 3);
        assert_eq!(handlers[0]["command"], "foreign-first");
        assert_eq!(handlers[1]["command"], CODEX_HOOK_COMMAND);
        assert_eq!(handlers[1]["extra"], "preserved");
        assert_eq!(handlers[2]["command"], "foreign-last");
    }

    #[test]
    fn install_codex_hook_update_in_place_refreshes_all_pinned_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": CODEX_HOOK_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "sekretbarilo check-codex --old-flag",
                            "timeout": 600,
                            "extra": "preserved"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Updated
        );

        let config = read_hook_config(&path);
        let handler = &config["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(handler["command"], CODEX_HOOK_COMMAND);
        assert_eq!(handler["timeout"], 10);
        assert_eq!(
            handler["statusMessage"],
            "Scanning tool input for secrets..."
        );
        assert_eq!(handler["type"], "command");
        assert_eq!(handler["extra"], "preserved");
    }

    #[test]
    fn install_codex_hook_preserves_unrelated_hook_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let post_tool_use = json!([{
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "post-hook", "extra": true}]
        }]);
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "description": "preserved",
                "hooks": {"PostToolUse": post_tool_use}
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Created
        );

        let config = read_hook_config(&path);
        assert_eq!(config["description"], "preserved");
        assert_eq!(config["hooks"]["PostToolUse"], post_tool_use);
    }

    #[test]
    fn install_codex_hook_appends_group_after_foreign_groups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Foo",
                            "hooks": [{"type": "command", "command": "foo-hook"}]
                        },
                        {
                            "matcher": "Bar",
                            "hooks": [{"type": "command", "command": "bar-hook"}]
                        }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            install_codex_hook_to_path(&path).unwrap(),
            HookInstallResult::Created
        );

        let config = read_hook_config(&path);
        let groups = config["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0]["matcher"], "Foo");
        assert_eq!(groups[0]["hooks"][0]["command"], "foo-hook");
        assert_eq!(groups[1]["matcher"], "Bar");
        assert_eq!(groups[1]["hooks"][0]["command"], "bar-hook");
        assert_eq!(groups[2]["matcher"], CODEX_HOOK_MATCHER);
        assert_eq!(groups[2]["hooks"][0], codex_hook_handler());
    }

    #[test]
    fn install_codex_hook_rejects_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(&path, b"{").unwrap();

        assert!(install_codex_hook_to_path(&path).is_err());
    }

    #[test]
    fn install_codex_hook_rejects_non_object_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(&path, b"[]").unwrap();

        let error = install_codex_hook_to_path(&path).unwrap_err();
        assert!(error.contains("root is not a JSON object"));
    }

    #[test]
    fn invariant_i1_run_check_codex_never_writes_stdout() {
        let source = include_str!("codex.rs");
        let forbidden_calls = [
            concat!("print", "ln!"),
            concat!("print", "!"),
            concat!("std::io::std", "out"),
            concat!("io::std", "out"),
        ];

        for line in source.lines().map(str::trim_start) {
            assert!(
                !forbidden_calls
                    .iter()
                    .take(2)
                    .any(|call| line.starts_with(call))
                    && !forbidden_calls
                        .iter()
                        .skip(2)
                        .any(|call| line.contains(call)),
                "stdout write path found: {line}"
            );
        }
    }

    #[test]
    fn invariant_i2_block_funnel_requires_nonempty_stderr_reason() {
        assert_eq!(finish_decision(HookDecision::Block(String::new())), 2);
        assert_eq!(finish_decision(HookDecision::Block("blocked".into())), 2);
        assert_eq!(finish_decision(HookDecision::Allow), 0);
    }

    #[test]
    fn epipe_on_stderr_does_not_change_the_exit_code() {
        use std::io::{Read, Write};

        let secret = "AKIAIOSFODNN7ABCDEFG";
        let mut patch = String::from("*** Begin Patch\n*** Add File: many.rs\n");
        for i in 0..5000 {
            patch.push_str(&format!("+const K{i}: &str = \"{secret}{i}\";\n"));
        }
        patch.push_str("*** End Patch\n");

        let tmp = tempfile::tempdir().unwrap();
        let input = serde_json::to_vec(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
            "cwd": tmp.path().to_string_lossy(),
        }))
        .unwrap();

        let binary = compiled_binary();
        assert!(
            binary.is_file(),
            "compiled binary missing at {}",
            binary.display()
        );
        let mut child = Command::new(binary)
            .args(["check-codex", "--stdin-json"])
            .env("HOME", tmp.path())
            .env("CODEX_HOME", tmp.path().join(".codex"))
            .env("GIT_CONFIG_GLOBAL", tmp.path().join("gitconfig-empty"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        child.stdin.take().unwrap().write_all(&input).unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let stdout_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        });

        let mut stderr = child.stderr.take().unwrap();
        let mut prefix = [0u8; 64];
        let _ = stderr.read(&mut prefix);
        drop(stderr);

        let status = child.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(2),
            "an early-closing stderr reader must not change the exit code"
        );
        assert!(stdout_reader.join().unwrap().is_empty());
    }

    #[test]
    fn apply_patch_report_sanitizes_control_characters() {
        let path = "spoof\x1b[2K\rname\u{202e}.rs";
        let patch = format!(
            "*** Begin Patch\n*** Add File: {path}\n+const KEY: &str = \"AKIAIOSFODNN7ABCDEFG\";\n*** End Patch\n"
        );
        let input = payload("PreToolUse", "apply_patch", json!({"command": patch}));
        let reason = assert_block_contains(evaluate(&input), "secret(s) detected");

        assert!(!reason.contains('\x1b'));
        assert!(!reason.contains('\r'));
        assert!(!reason.contains('\u{202e}'));
    }

    #[test]
    fn findings_decision_sanitizes_all_untrusted_fields() {
        let findings = vec![Finding {
            file: "file\x1b\r\u{202e}.rs".to_string(),
            line: 1,
            rule_id: "rule\x1b\r\u{202e}".to_string(),
            matched_value: "\u{202e}abcde\r".as_bytes().to_vec(),
        }];
        let reason = assert_block_contains(
            findings_decision("apply_patch", &findings),
            "secret(s) detected",
        );

        assert!(!reason.contains('\x1b'));
        assert!(!reason.contains('\r'));
        assert!(!reason.contains('\u{202e}'));
    }

    #[test]
    fn findings_decision_caps_rendered_findings() {
        let total = MAX_RENDERED_FINDINGS + 7;
        let findings = (0..total)
            .map(|index| Finding {
                file: format!("file-{index}.rs"),
                line: index + 1,
                rule_id: "fixture-rule".to_string(),
                matched_value: b"fixture-secret".to_vec(),
            })
            .collect::<Vec<_>>();
        let reason = assert_block_contains(
            findings_decision("apply_patch", &findings),
            "secret(s) detected",
        );

        assert_eq!(reason.matches("  file: ").count(), MAX_RENDERED_FINDINGS);
        assert!(reason.contains("... and 7 more finding(s) omitted"));
        assert!(reason.contains(&format!("total findings: {total}.")));
    }

    #[test]
    fn invariant_i5_apply_patch_findings_are_masked() {
        let secret = "AKIAIOSFODNN7ABCDEFG";
        let patch = format!(
            "*** Begin Patch\n*** Add File: config.rs\n+const KEY: &str = \"{secret}\";\n*** End Patch\n"
        );
        let input = payload("PreToolUse", "apply_patch", json!({"command": patch}));
        let reason = assert_block_contains(evaluate(&input), "secret(s) detected");

        assert!(!reason.contains(secret));
        assert!(reason.contains(&mask_secret(secret.as_bytes())));
    }

    #[test]
    fn invariant_i5_bash_findings_are_masked() {
        let secret = "AKIAIOSFODNN7ABCDEFG";
        let command = format!("export AWS_ACCESS_KEY_ID={secret}");
        let input = payload("PreToolUse", "Bash", json!({"command": command}));
        let reason = assert_block_contains(evaluate(&input), "secret(s) detected");

        assert!(!reason.contains(secret));
        assert!(reason.contains(&mask_secret(secret.as_bytes())));
    }

    #[test]
    fn fail_closed_stdin_read_error_has_specific_reason() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture read failure"))
            }
        }

        let decision = evaluate_reader_with_loader(FailingReader, |_| Ok(test_scan_context()));
        assert_block_contains(decision, "failed to read Codex hook stdin");
    }

    #[test]
    fn fail_closed_malformed_json_has_specific_reason() {
        assert_block_contains(
            evaluate(b"{\"hook_event_name\":"),
            "malformed Codex hook JSON",
        );
    }

    #[test]
    fn fail_closed_schema_drift_has_specific_reason() {
        let input = serde_json::to_vec(&json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "echo clean"}
        }))
        .unwrap();
        assert_block_contains(evaluate(&input), "payload schema mismatch");
    }

    #[test]
    fn fail_closed_non_object_apply_patch_input_has_specific_reason() {
        let input = payload("PreToolUse", "apply_patch", Value::Null);
        assert_block_contains(evaluate(&input), "expected a JSON object");
    }

    #[test]
    fn fail_closed_missing_apply_patch_command_has_specific_reason() {
        let input = payload("PreToolUse", "apply_patch", json!({}));
        assert_block_contains(evaluate(&input), "missing 'command'");
    }

    #[test]
    fn fail_closed_non_string_apply_patch_command_has_specific_reason() {
        let input = payload("PreToolUse", "apply_patch", json!({"command": 7}));
        assert_block_contains(evaluate(&input), "must be a string");
    }

    #[test]
    fn fail_closed_missing_bash_command_has_specific_reason() {
        let input = payload("PreToolUse", "Bash", json!({}));
        assert_block_contains(evaluate(&input), "missing 'command'");
    }

    #[test]
    fn fail_closed_non_string_bash_command_has_specific_reason() {
        let input = payload("PreToolUse", "Bash", json!({"command": false}));
        assert_block_contains(evaluate(&input), "must be a string");
    }

    #[test]
    fn fail_closed_patch_parse_error_has_specific_reason() {
        let input = payload(
            "PreToolUse",
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Add File: file.txt\n+hello\n"}),
        );
        assert_block_contains(evaluate(&input), "apply_patch parse error");
    }

    #[test]
    fn fail_closed_payload_over_cap_mentions_payload_truncated() {
        let oversized = vec![b' '; MAX_PAYLOAD_BYTES as usize + 1];
        let decision =
            evaluate_reader_with_loader(Cursor::new(oversized), |_| Ok(test_scan_context()));
        assert_block_contains(decision, "payload truncated");
    }

    #[test]
    fn fail_closed_scanner_setup_error_has_specific_reason() {
        let input = payload("PreToolUse", "Bash", json!({"command": "echo clean"}));
        let decision =
            evaluate_payload_with_loader(&input, |_| Err("fixture config failure".to_string()));
        assert_block_contains(decision, "scanner setup failed: fixture config failure");
    }

    #[test]
    fn target_env_path_is_blocked_before_scanning() {
        let input = payload(
            "PreToolUse",
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Add File: .env.local\n+CLEAN=value\n*** End Patch\n"}),
        );
        let decision = evaluate_payload_with_loader(&input, |_| {
            panic!("scanner setup must not run before .env policy")
        });
        assert_block_contains(decision, ".env policy");
    }

    #[test]
    fn original_env_path_on_move_is_blocked_before_scanning() {
        let input = payload(
            "PreToolUse",
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Update File: .env\n*** Move to: config.txt\n@@\n-old\n+new\n*** End Patch\n"}),
        );
        let decision = evaluate_payload_with_loader(&input, |_| {
            panic!("scanner setup must not run before .env policy")
        });
        assert_block_contains(decision, ".env policy");
    }

    #[test]
    fn wrong_hook_event_is_silent_allow() {
        let input = payload(
            "PostToolUse",
            "apply_patch",
            json!({"command": "malformed patch"}),
        );
        assert_eq!(evaluate(&input), HookDecision::Allow);
    }

    #[test]
    fn unrecognized_tool_name_is_silent_allow() {
        let input = payload("PreToolUse", "mcp__server__tool", Value::Null);
        assert_eq!(evaluate(&input), HookDecision::Allow);
    }

    #[test]
    fn clean_apply_patch_is_silent_allow() {
        let input = payload(
            "PreToolUse",
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Add File: clean.rs\n+let clean = true;\n*** End Patch\n"}),
        );
        assert_eq!(evaluate(&input), HookDecision::Allow);
    }

    #[test]
    fn clean_bash_command_is_silent_allow() {
        let input = payload("PreToolUse", "Bash", json!({"command": "echo hello\npwd"}));
        assert_eq!(evaluate(&input), HookDecision::Allow);
    }

    #[test]
    fn bash_ignores_project_path_allowlist() {
        let secret = "AKIAIOSFODNN7ABCDEFG";
        let input = payload(
            "PreToolUse",
            "Bash",
            json!({"command": format!("export AWS_ACCESS_KEY_ID={secret}")}),
        );
        let mut project_config = config::ProjectConfig::default();
        project_config.allowlist.paths.push(".*".to_string());
        let decision = evaluate_payload_with_loader(&input, |_| {
            Ok(test_scan_context_with_config(project_config))
        });
        let reason = assert_block_contains(decision, "secret(s) detected");
        assert!(!reason.contains(secret));
    }

    #[test]
    fn apply_patch_honors_project_path_allowlist() {
        let input = payload(
            "PreToolUse",
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Add File: ignored/config.rs\n+const KEY: &str = \"AKIAIOSFODNN7ABCDEFG\";\n*** End Patch\n"}),
        );
        let mut project_config = config::ProjectConfig::default();
        project_config
            .allowlist
            .paths
            .push("ignored/.*".to_string());
        let decision = evaluate_payload_with_loader(&input, |_| {
            Ok(test_scan_context_with_config(project_config))
        });
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn agent_written_inworkspace_config_is_not_trusted() {
        let repo = init_git_repo();
        let input = secret_patch_payload(repo.path());
        assert_block_contains(
            evaluate_payload_with_loader(&input, load_scan_context),
            "secret(s) detected",
        );

        let config_body = permissive_config()
            .lines()
            .map(|line| format!("+{line}\n"))
            .collect::<String>();
        let config_patch = format!(
            "*** Begin Patch\n*** Add File: .sekretbarilo.toml\n{config_body}*** End Patch\n"
        );
        let config_input = payload_with_cwd(
            "PreToolUse",
            "apply_patch",
            json!({"command": config_patch}),
            repo.path().to_str().unwrap(),
        );
        assert_eq!(
            evaluate_payload_with_loader(&config_input, load_scan_context),
            HookDecision::Allow
        );
        fs::write(repo.path().join(".sekretbarilo.toml"), permissive_config()).unwrap();

        assert_block_contains(
            evaluate_payload_with_loader(&input, load_scan_context),
            "secret(s) detected",
        );
    }

    #[test]
    fn committed_inworkspace_config_allowlist_is_honored() {
        let repo = init_git_repo();
        let input = secret_patch_payload(repo.path());
        assert_block_contains(
            evaluate_payload_with_loader(&input, load_scan_context),
            "secret(s) detected",
        );

        fs::write(repo.path().join(".sekretbarilo.toml"), permissive_config()).unwrap();
        git_success(repo.path(), &["add", ".sekretbarilo.toml"]);
        git_success(
            repo.path(),
            &["commit", "--no-verify", "-m", "add fixture config"],
        );

        assert_eq!(
            evaluate_payload_with_loader(&input, load_scan_context),
            HookDecision::Allow
        );
    }

    #[test]
    fn inworkspace_config_without_git_repo_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let marker = "fixture-non-git-config-marker";
        fs::write(
            dir.path().join(".sekretbarilo.toml"),
            format!("[allowlist]\npaths = [\"{marker}\"]\n"),
        )
        .unwrap();

        let config = load_trusted_project_config(dir.path()).unwrap();
        assert!(!config.allowlist.paths.iter().any(|path| path == marker));
    }

    #[test]
    fn payload_accepts_absent_agent_fields_and_unknown_fields() {
        let input = payload("PreToolUse", "Bash", json!({"command": "echo hello"}));
        let payload: PreToolUsePayload = serde_json::from_slice(&input).unwrap();

        assert_eq!(payload.agent_id, None);
        assert_eq!(payload.agent_type, None);
        assert_eq!(payload.transcript_path, None);
    }

    #[test]
    fn bash_command_lines_are_sequential_and_verbatim() {
        let command = "first\r\nsecond\n";
        let diff_file = DiffFile {
            path: BASH_SYNTHETIC_PATH.to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: command
                .split('\n')
                .enumerate()
                .map(|(index, line)| AddedLine {
                    line_number: index + 1,
                    content: line.as_bytes().to_vec(),
                })
                .collect(),
        };

        assert_eq!(diff_file.added_lines.len(), 3);
        assert_eq!(diff_file.added_lines[0].line_number, 1);
        assert_eq!(diff_file.added_lines[0].content, b"first\r");
        assert_eq!(diff_file.added_lines[2].content, b"");
    }
}
