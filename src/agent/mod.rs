// agent hook support: check-file command and hook installation for claude code

use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};

use crate::audit::{read_file_to_diff_result, ReadFileResult};
use crate::config;
use crate::config::allowlist::CompiledAllowlist;
use crate::output::masking::mask_secret;
use crate::scanner::engine::scan;

/// result of claude code hook installation
#[derive(Debug, PartialEq)]
pub enum ClaudeHookResult {
    Created,
    Updated,
    AlreadyInstalled,
}

impl std::fmt::Display for ClaudeHookResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaudeHookResult::Created => write!(f, "created claude code hook configuration"),
            ClaudeHookResult::Updated => write!(f, "updated claude code hook configuration"),
            ClaudeHookResult::AlreadyInstalled => {
                write!(f, "sekretbarilo already installed in claude code hooks")
            }
        }
    }
}

/// the hook command used in claude code settings
pub const HOOK_COMMAND: &str = "sekretbarilo check-file --stdin-json";

/// install claude code hook into settings.json.
/// global: true = ~/.claude/settings.json, false = .claude/settings.json (project root)
pub fn install_claude_hook(global: bool) -> Result<ClaudeHookResult, String> {
    let config_path = if global {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| "could not determine home directory".to_string())?;
        PathBuf::from(home).join(".claude").join("settings.json")
    } else {
        // resolve project root via git, fall back to cwd with warning
        let base = match resolve_project_root() {
            Some(root) => root,
            None => {
                let cwd = std::env::current_dir()
                    .map_err(|_| "could not determine project root or current directory".to_string())?;
                eprintln!(
                    "[WARN] not inside a git repository, using current directory for local hook placement: {}",
                    cwd.display()
                );
                cwd
            }
        };
        base.join(".claude").join("settings.json")
    };

    install_claude_hook_to_path(&config_path)
}

/// install claude code hook into a specific settings file path.
/// creates parent directories if needed.
fn install_claude_hook_to_path(config_path: &Path) -> Result<ClaudeHookResult, String> {
    // create parent directory if needed
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
    }

    // read existing config or start fresh (read unconditionally to avoid TOCTOU race)
    let mut root: serde_json::Value = match std::fs::read_to_string(config_path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| format!("malformed JSON in {}: {}", config_path.display(), e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(format!("failed to read {}: {}", config_path.display(), e)),
    };

    // ensure root is an object
    let obj = root
        .as_object_mut()
        .ok_or_else(|| format!("{} is not a JSON object", config_path.display()))?;

    // navigate to hooks.PreToolUse array, creating path if needed
    if !obj.contains_key("hooks") {
        obj.insert("hooks".to_string(), serde_json::json!({}));
    }
    let hooks = obj
        .get_mut("hooks")
        .unwrap()
        .as_object_mut()
        .ok_or_else(|| "hooks is not an object".to_string())?;

    if !hooks.contains_key("PreToolUse") {
        hooks.insert("PreToolUse".to_string(), serde_json::json!([]));
    }
    let pre_tool_use = hooks
        .get_mut("PreToolUse")
        .unwrap()
        .as_array_mut()
        .ok_or_else(|| "hooks.PreToolUse is not an array".to_string())?;

    // look for existing Read matcher entry that has our hook.
    // two-pass approach: first scan all Read matchers for existing sekretbarilo hooks
    // (already-installed or update cases), then install into the first suitable Read matcher.
    let our_hook_entry = serde_json::json!({
        "type": "command",
        "command": HOOK_COMMAND,
        "timeout": 10,
        "statusMessage": "Scanning file for secrets..."
    });

    // pass 1: check all Read matchers for existing sekretbarilo hooks
    let mut update_target: Option<(usize, usize)> = None; // (entry_idx, hook_idx)
    let mut first_read_idx: Option<usize> = None;

    for (entry_idx, entry) in pre_tool_use.iter().enumerate() {
        if entry.get("matcher").and_then(|m| m.as_str()) != Some("Read") {
            continue;
        }
        if first_read_idx.is_none() {
            first_read_idx = Some(entry_idx);
        }
        if let Some(hooks_array) = entry.get("hooks").and_then(|h| h.as_array()) {
            for (hook_idx, hook) in hooks_array.iter().enumerate() {
                if let Some(cmd_str) = hook.get("command").and_then(|c| c.as_str()) {
                    if cmd_str == HOOK_COMMAND {
                        return Ok(ClaudeHookResult::AlreadyInstalled);
                    }
                    if cmd_str.contains("sekretbarilo") && update_target.is_none() {
                        update_target = Some((entry_idx, hook_idx));
                    }
                }
            }
        }
    }

    // pass 2: apply changes based on what we found
    if let Some((entry_idx, hook_idx)) = update_target {
        // older sekretbarilo version found - update it
        pre_tool_use[entry_idx]["hooks"][hook_idx] = our_hook_entry;
        write_config(config_path, &root)?;
        return Ok(ClaudeHookResult::Updated);
    }

    if let Some(idx) = first_read_idx {
        // Read matcher exists - add our hook to it
        if let Some(hooks_array) = pre_tool_use[idx].get_mut("hooks") {
            let arr = hooks_array.as_array_mut().ok_or_else(|| {
                format!(
                    "malformed settings: hooks.PreToolUse Read matcher has non-array 'hooks' field in {}",
                    config_path.display()
                )
            })?;
            arr.push(our_hook_entry);
        } else {
            // Read matcher exists but has no 'hooks' field - create it
            pre_tool_use[idx]["hooks"] = serde_json::json!([our_hook_entry]);
        }
        write_config(config_path, &root)?;
        return Ok(ClaudeHookResult::Created);
    }

    // no Read matcher found - create new entry
    let new_entry = serde_json::json!({
        "matcher": "Read",
        "hooks": [our_hook_entry]
    });
    pre_tool_use.push(new_entry);

    write_config(config_path, &root)?;
    Ok(ClaudeHookResult::Created)
}

/// resolve the project root directory via git rev-parse
fn resolve_project_root() -> Option<PathBuf> {
    crate::doctor::resolve_repo_root()
}

/// write the JSON config back to disk with pretty printing.
/// uses atomic write (write to temp file, then rename) to prevent corruption.
fn write_config(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let content = serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;
    // use pid + timestamp for unique temp file name to avoid races
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "config".to_string()),
        pid,
        ts,
    );
    let tmp = path.with_file_name(tmp_name);
    // use exclusive create (O_CREAT | O_EXCL) to prevent symlink following and path collisions
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("failed to create {}: {}", tmp.display(), e))?;
    file.write_all((content + "\n").as_bytes())
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("failed to write {}: {}", tmp.display(), e)
        })?;
    file.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to sync {}: {}", tmp.display(), e)
    })?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to rename {} -> {}: {}", tmp.display(), path.display(), e)
    })
}

/// claude code hook stdin payload
#[derive(serde::Deserialize)]
struct HookPayload {
    tool_input: ToolInput,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(serde::Deserialize)]
struct ToolInput {
    file_path: String,
}

/// parse the claude code hook JSON payload from stdin.
/// expects: { "tool_input": { "file_path": "..." }, "cwd": "..." }
fn parse_hook_stdin() -> Result<(String, Option<String>), String> {
    let mut input = String::new();
    // limit stdin to 1MB to prevent unbounded memory consumption
    std::io::stdin()
        .take(1_048_576)
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read stdin: {}", e))?;

    let payload: HookPayload = serde_json::from_str(&input)
        .map_err(|e| format!("failed to parse hook payload: {}", e))?;

    if payload.tool_input.file_path.is_empty() {
        return Err("file_path is empty in hook payload".to_string());
    }

    Ok((payload.tool_input.file_path, payload.cwd))
}

/// resolve file path to (relative_path, base_dir) for scanning.
/// if the path is absolute and cwd is provided, computes relative path from cwd.
/// if the path is absolute without cwd, uses the parent dir as base.
/// if relative, uses the provided cwd or current directory as base.
fn resolve_file_path(
    file_path: &str,
    cwd: Option<&str>,
) -> Result<(String, PathBuf), String> {
    let path = Path::new(file_path);

    if path.is_absolute() {
        // try to compute a relative path from cwd for better vendor/pattern detection
        let base = match cwd {
            Some(dir) => Some(PathBuf::from(dir)),
            None => std::env::current_dir().ok(),
        };

        if let Some(base) = base {
            if let Ok(rel) = path.strip_prefix(&base) {
                let rel_str = rel.to_string_lossy().to_string();
                if !rel_str.is_empty() {
                    return Ok((rel_str, base));
                }
            }
        }

        // fallback: use parent directory and filename
        let parent = path
            .parent()
            .ok_or_else(|| format!("cannot determine parent directory of '{}'", file_path))?;
        let filename = path
            .file_name()
            .ok_or_else(|| format!("cannot determine filename from '{}'", file_path))?
            .to_string_lossy()
            .to_string();
        Ok((filename, parent.to_path_buf()))
    } else {
        let base = match cwd {
            Some(dir) => PathBuf::from(dir),
            None => std::env::current_dir()
                .map_err(|e| format!("failed to determine current directory: {}", e))?,
        };
        // validate that the resolved path stays within the base directory.
        // prevents path traversal via relative paths like "../../etc/passwd".
        let full = base.join(file_path);
        if let (Ok(canonical), Ok(canonical_base)) = (full.canonicalize(), base.canonicalize()) {
            if !canonical.starts_with(&canonical_base) {
                return Err(format!(
                    "file path '{}' resolves outside base directory '{}'",
                    file_path,
                    base.display()
                ));
            }
        }
        Ok((file_path.to_string(), base))
    }
}

/// check if a file should be skipped before reading its contents.
/// this is the fast-path rejection: checks path patterns, binary extensions,
/// and exclude patterns without loading the file.
fn should_skip_file(
    relative_path: &str,
    allowlist: &CompiledAllowlist,
    audit_config: &config::AuditConfig,
) -> Result<bool, String> {
    // check against the compiled allowlist (binary extensions, vendor dirs, etc.)
    if allowlist.is_path_skipped(relative_path) {
        return Ok(true);
    }

    // check against audit exclude patterns (if any)
    if !audit_config.exclude_patterns.is_empty() {
        let exclude_regexes = crate::audit::compile_patterns(&audit_config.exclude_patterns)?;
        for re in &exclude_regexes {
            if re.is_match(relative_path) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// run the check-file command.
/// reads a single file, scans it for secrets, and returns an exit code.
///
/// exit codes:
///   0 = clean (no secrets found)
///   2 = secrets found or error (claude code blocks the read on exit 2)
pub fn run_check_file(stdin_json: bool, file_arg: Option<&str>) -> i32 {
    // step 1: determine the file path
    let (file_path, cwd) = if stdin_json {
        match parse_hook_stdin() {
            Ok((path, cwd)) => (path, cwd),
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                return 2;
            }
        }
    } else {
        match file_arg {
            Some(path) => (path.to_string(), None),
            None => {
                eprintln!("[ERROR] check-file requires a file path argument or --stdin-json");
                return 2;
            }
        }
    };

    // step 2: resolve the file path
    let (relative_path, base_dir) = match resolve_file_path(&file_path, cwd.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    // step 2a: validate base directory exists
    if !base_dir.is_dir() {
        eprintln!("[ERROR] base directory does not exist: {}", base_dir.display());
        return 2;
    }

    // step 2b: block .env files unconditionally (same policy as pre-commit scan).
    // .env files almost always contain secrets; block reading them entirely.
    if crate::diff::is_blocked_env_file(&relative_path) {
        eprintln!();
        eprintln!("[AGENT] .env file blocked: {}", file_path);
        eprintln!("file likely contains environment secrets. reading blocked.");
        return 2;
    }

    // step 3: cheap fast-path rejection using hardcoded patterns only.
    // this avoids loading config/rules for obvious skips (binary, vendor, lock files).
    if let Ok(default_al) = CompiledAllowlist::default_allowlist() {
        if default_al.is_path_skipped(&relative_path) {
            return 0;
        }
    }

    // step 4: load config and build full allowlist for user-configured patterns
    let project_config = match config::load_project_config(Some(&base_dir)) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    let rules_list = match config::load_rules_with_config(&project_config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    let allowlist = match config::build_allowlist(&project_config, &rules_list) {
        Ok(al) => al,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    // step 5: full fast-path rejection with user config patterns
    match should_skip_file(&relative_path, &allowlist, &project_config.audit) {
        Ok(true) => return 0,
        Ok(false) => {}
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    }

    // step 6: read file and convert to DiffFile
    let diff_file = match read_file_to_diff_result(&relative_path, &base_dir) {
        ReadFileResult::Ok(df) => df,
        ReadFileResult::Binary => {
            // binary file - not a secret concern
            return 0;
        }
        ReadFileResult::ReadError(e) => {
            // read errors must block: failing open would let secrets through
            eprintln!("[ERROR] failed to read {}: {}", file_path, e);
            return 2;
        }
    };

    // step 7: compile scanner
    let compiled = match crate::scanner::rules::compile_rules(&rules_list) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] failed to compile rules: {}", e);
            return 2;
        }
    };

    // step 8: scan
    let findings = scan(&[diff_file], &compiled, &allowlist);

    if findings.is_empty() {
        return 0;
    }

    // step 9: report findings to stderr (agent reads stderr for feedback)
    eprintln!();
    eprintln!(
        "[AGENT] secret(s) detected in {}",
        file_path
    );
    eprintln!();
    for finding in &findings {
        let masked = mask_secret(&finding.matched_value);
        eprintln!("  line: {}", finding.line);
        eprintln!("  rule: {}", finding.rule_id);
        eprintln!("  match: {}", masked);
        eprintln!();
    }
    eprintln!(
        "file contains {} secret(s). reading blocked to prevent secret exposure.",
        findings.len()
    );

    2
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// raii guard that restores the working directory on drop (including panics)
    struct CwdGuard(std::path::PathBuf);
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    // -- stdin JSON parsing tests --

    #[test]
    fn parse_hook_payload_valid() {
        let json = r#"{"tool_input": {"file_path": "/path/to/file.txt"}, "cwd": "/project"}"#;
        let payload: HookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.tool_input.file_path, "/path/to/file.txt");
        assert_eq!(payload.cwd, Some("/project".to_string()));
    }

    #[test]
    fn parse_hook_payload_without_cwd() {
        let json = r#"{"tool_input": {"file_path": "/path/to/file.txt"}}"#;
        let payload: HookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.tool_input.file_path, "/path/to/file.txt");
        assert_eq!(payload.cwd, None);
    }

    #[test]
    fn parse_hook_payload_with_extra_fields() {
        let json = r#"{
            "session_id": "abc123",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/path/to/file.txt"},
            "cwd": "/project"
        }"#;
        let payload: HookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.tool_input.file_path, "/path/to/file.txt");
        assert_eq!(payload.cwd, Some("/project".to_string()));
    }

    #[test]
    fn parse_hook_payload_missing_file_path() {
        let json = r#"{"tool_input": {}}"#;
        let result = serde_json::from_str::<HookPayload>(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_hook_payload_missing_tool_input() {
        let json = r#"{"cwd": "/project"}"#;
        let result = serde_json::from_str::<HookPayload>(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_hook_payload_malformed_json() {
        let json = r#"not valid json"#;
        let result = serde_json::from_str::<HookPayload>(json);
        assert!(result.is_err());
    }

    // -- file path resolution tests --

    #[test]
    fn resolve_absolute_path() {
        let (rel, base) = resolve_file_path("/home/user/project/src/config.rs", None).unwrap();
        assert_eq!(rel, "config.rs");
        assert_eq!(base, PathBuf::from("/home/user/project/src"));
    }

    #[test]
    fn resolve_relative_path_with_cwd() {
        let (rel, base) =
            resolve_file_path("src/config.rs", Some("/home/user/project")).unwrap();
        assert_eq!(rel, "src/config.rs");
        assert_eq!(base, PathBuf::from("/home/user/project"));
    }

    #[test]
    fn resolve_relative_path_without_cwd() {
        let (rel, _base) = resolve_file_path("src/config.rs", None).unwrap();
        assert_eq!(rel, "src/config.rs");
        // base will be current directory, which varies - just check it doesn't error
    }

    // -- fast-path rejection tests --

    #[test]
    fn skip_binary_extension_file() {
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig::default();
        assert!(should_skip_file("image.png", &al, &audit).unwrap());
    }

    #[test]
    fn skip_vendor_directory() {
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig::default();
        assert!(should_skip_file("node_modules/lodash/index.js", &al, &audit).unwrap());
    }

    #[test]
    fn skip_lock_file() {
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig::default();
        assert!(should_skip_file("package-lock.json", &al, &audit).unwrap());
    }

    #[test]
    fn dont_skip_source_file() {
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig::default();
        assert!(!should_skip_file("src/main.rs", &al, &audit).unwrap());
    }

    #[test]
    fn skip_audit_exclude_pattern() {
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig {
            exclude_patterns: vec!["^build/".to_string()],
            ..Default::default()
        };
        assert!(should_skip_file("build/output.js", &al, &audit).unwrap());
    }

    // -- integration tests with file scanning --

    #[test]
    fn check_file_clean() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clean.py");
        std::fs::write(&file_path, "x = 42\nprint(x)\n").unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        assert_eq!(result, 0);
    }

    #[test]
    fn check_file_with_secret() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("secret.py");
        std::fs::write(
            &file_path,
            "aws_key = \"AKIAIOSFODNN7REALKEYZ\"\n",
        )
        .unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        assert_eq!(result, 2);
    }

    #[test]
    fn check_file_nonexistent() {
        let result = run_check_file(false, Some("/tmp/nonexistent_sekretbarilo_test_file.py"));
        // nonexistent file is a read error - must block to avoid failing open
        assert_eq!(result, 2);
    }

    #[test]
    fn check_file_binary() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("binary.bin");
        let mut content = vec![0u8; 100];
        content.extend_from_slice(b"AKIAIOSFODNN7REALKEYZ");
        std::fs::write(&file_path, &content).unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        // binary files are skipped, returns 0
        assert_eq!(result, 0);
    }

    #[test]
    fn check_file_no_arg() {
        let result = run_check_file(false, None);
        assert_eq!(result, 2);
    }

    #[test]
    fn check_file_env_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env");
        std::fs::write(&file_path, "DB_PASSWORD=admin123\n").unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        assert_eq!(result, 2, ".env files should be blocked unconditionally");
    }

    #[test]
    fn check_file_env_example_not_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env.example");
        std::fs::write(&file_path, "DB_PASSWORD=changeme\n").unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        assert_eq!(result, 0, ".env.example should not be blocked");
    }

    #[test]
    #[serial]
    fn check_file_vendor_path_skipped_relative() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        let file_path = vendor_dir.join("secret.js");
        std::fs::write(
            &file_path,
            "const key = \"AKIAIOSFODNN7REALKEYZ\";\n",
        )
        .unwrap();

        // use relative path from temp dir root - triggers vendor dir detection
        let _guard = CwdGuard(std::env::current_dir().unwrap());
        std::env::set_current_dir(dir.path()).unwrap();
        let result = run_check_file(false, Some("node_modules/pkg/secret.js"));
        assert_eq!(result, 0);
    }

    #[test]
    fn check_file_vendor_path_skipped_absolute_with_cwd() {
        // simulates claude code hook payload with cwd context
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        let file_path = vendor_dir.join("secret.js");
        std::fs::write(
            &file_path,
            "const key = \"AKIAIOSFODNN7REALKEYZ\";\n",
        )
        .unwrap();

        // absolute path with cwd context resolves to relative "node_modules/pkg/secret.js"
        let (rel, base) = resolve_file_path(
            file_path.to_str().unwrap(),
            Some(dir.path().to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(rel, "node_modules/pkg/secret.js");
        assert_eq!(base, dir.path());

        // verify the allowlist would skip this path
        let al = CompiledAllowlist::default_allowlist().unwrap();
        let audit = config::AuditConfig::default();
        assert!(should_skip_file(&rel, &al, &audit).unwrap());
    }

    // -- claude code hook installation tests --

    #[test]
    fn install_claude_hook_creates_new_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".claude").join("settings.json");

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Created);

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
        assert_eq!(hook_arr[0]["command"], HOOK_COMMAND);
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
        std::fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Created);

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
        assert_eq!(result1, ClaudeHookResult::Created);

        // second install should detect already installed
        let result2 = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result2, ClaudeHookResult::AlreadyInstalled);

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
        std::fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Created);

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
        std::fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Created);

        // verify our hook was appended to the existing Read hooks array
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1); // still one Read entry
        let hooks = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2); // two hooks in it
        assert_eq!(hooks[0]["command"], "echo other hook");
        assert_eq!(hooks[1]["command"], HOOK_COMMAND);
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
        std::fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Created);

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
        std::fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let result = install_claude_hook_to_path(&config_path).unwrap();
        assert_eq!(result, ClaudeHookResult::Updated);

        // verify the command was updated
        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        let hooks = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], HOOK_COMMAND);
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
        assert_eq!(result, ClaudeHookResult::Created);
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
