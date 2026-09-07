// agent hook support: machine-facing checks and hook installation

// codex hook parsing, scanning, and installation are wired through the cli
mod apply_patch;
pub(crate) mod claude;
mod codex;
mod hooks_json;
mod redact;

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
pub use claude::{
    ClaudeHookMode, ClaudeSettingsTarget, HOOK_COMMAND, install_claude_hook,
    install_claude_hook_to_target, install_claude_hook_with_mode, is_sekretbarilo_hook_command,
};
#[allow(unused_imports)]
pub(crate) use codex::resolve_codex_home;
#[allow(unused_imports)]
pub use codex::{CODEX_HOOK_COMMAND, CODEX_HOOK_MATCHER, install_codex_hook, run_check_codex};
#[allow(unused_imports)]
pub use hooks_json::HookInstallResult;
pub use redact::{redact_cli_error, run_redact_claude};

pub(crate) use hooks_json::find_hook;

use crate::audit::history::sanitize_display;
use crate::audit::{ReadFileResult, read_file_to_diff_result};
use crate::config;
use crate::config::allowlist::CompiledAllowlist;
use crate::output::masking::mask_secret;
use crate::scanner::engine::{Finding, scan};

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

    let payload: HookPayload =
        serde_json::from_str(&input).map_err(|e| format!("failed to parse hook payload: {}", e))?;

    if payload.tool_input.file_path.is_empty() {
        return Err("file_path is empty in hook payload".to_string());
    }

    Ok((payload.tool_input.file_path, payload.cwd))
}

/// resolve file path to (relative_path, base_dir) for scanning.
/// if the path is absolute and cwd is provided, computes relative path from cwd.
/// if the path is absolute without cwd, uses the parent dir as base.
/// if relative, uses the provided cwd or current directory as base.
fn resolve_file_path(file_path: &str, cwd: Option<&str>) -> Result<(String, PathBuf), String> {
    let path = Path::new(file_path);

    if path.is_absolute() {
        // try to compute a relative path from cwd for better vendor/pattern detection
        let base = match cwd {
            Some(dir) => Some(PathBuf::from(dir)),
            None => std::env::current_dir().ok(),
        };

        if let Some(base) = base
            && let Ok(rel) = path.strip_prefix(&base)
        {
            let rel_str = rel.to_string_lossy().to_string();
            if !rel_str.is_empty() {
                return Ok((rel_str, base));
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
        if let (Ok(canonical), Ok(canonical_base)) = (full.canonicalize(), base.canonicalize())
            && !canonical.starts_with(&canonical_base)
        {
            return Err(format!(
                "file path '{}' resolves outside base directory '{}'",
                file_path,
                base.display()
            ));
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

fn file_findings_reason(file_path: &str, findings: &[Finding]) -> String {
    let file_path = sanitize_display(file_path);
    let mut reason = String::new();
    let _ = writeln!(reason);
    let _ = writeln!(reason, "[AGENT] secret(s) detected in {file_path}");
    let _ = writeln!(reason);
    for finding in findings.iter().take(codex::MAX_RENDERED_FINDINGS) {
        let file = sanitize_display(&finding.file);
        let rule_id = sanitize_display(&finding.rule_id);
        let masked = sanitize_display(&mask_secret(&finding.matched_value));
        let _ = writeln!(reason, "  file: {file}");
        let _ = writeln!(reason, "  line: {}", finding.line);
        let _ = writeln!(reason, "  rule: {rule_id}");
        let _ = writeln!(reason, "  match: {masked}");
        let _ = writeln!(reason);
    }
    if findings.len() > codex::MAX_RENDERED_FINDINGS {
        let omitted = findings.len() - codex::MAX_RENDERED_FINDINGS;
        let _ = writeln!(reason, "... and {omitted} more finding(s) omitted");
    }
    let _ = writeln!(
        reason,
        "file contains {} secret(s). reading blocked to prevent secret exposure.",
        findings.len()
    );
    reason
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
                let error = sanitize_display(&e);
                let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
                return 2;
            }
        }
    } else {
        match file_arg {
            Some(path) => (path.to_string(), None),
            None => {
                let _ = writeln!(
                    std::io::stderr(),
                    "[ERROR] check-file requires a file path argument or --stdin-json"
                );
                return 2;
            }
        }
    };

    // step 2: resolve the file path
    let (relative_path, base_dir) = match resolve_file_path(&file_path, cwd.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
            return 2;
        }
    };

    // step 2a: validate base directory exists
    if !base_dir.is_dir() {
        let base_dir = sanitize_display(&base_dir.to_string_lossy());
        let _ = writeln!(
            std::io::stderr(),
            "[ERROR] base directory does not exist: {base_dir}"
        );
        return 2;
    }

    // step 2b: block .env files unconditionally (same policy as pre-commit scan).
    // .env files almost always contain secrets; block reading them entirely.
    if crate::diff::is_blocked_env_file(&relative_path) {
        let file_path = sanitize_display(&file_path);
        let _ = writeln!(
            std::io::stderr(),
            "\n[AGENT] .env file blocked: {file_path}\nfile likely contains environment secrets. reading blocked."
        );
        return 2;
    }

    // step 3: cheap fast-path rejection using hardcoded patterns only.
    // this avoids loading config/rules for obvious skips (binary, vendor, lock files).
    if let Ok(default_al) = CompiledAllowlist::default_allowlist()
        && default_al.is_path_skipped(&relative_path)
    {
        return 0;
    }

    // step 4: load config and build full allowlist for user-configured patterns
    let project_config = match codex::load_trusted_project_config(&base_dir) {
        Ok(cfg) => cfg,
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
            return 2;
        }
    };

    let rules_list = match config::load_rules_with_config(&project_config) {
        Ok(r) => r,
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
            return 2;
        }
    };

    let allowlist = match config::build_allowlist(&project_config, &rules_list) {
        Ok(al) => al,
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
            return 2;
        }
    };

    // step 5: full fast-path rejection with user config patterns
    match should_skip_file(&relative_path, &allowlist, &project_config.audit) {
        Ok(true) => return 0,
        Ok(false) => {}
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(std::io::stderr(), "[ERROR] {error}");
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
            let file_path = sanitize_display(&file_path);
            let error = sanitize_display(&e);
            let _ = writeln!(
                std::io::stderr(),
                "[ERROR] failed to read {file_path}: {error}"
            );
            return 2;
        }
    };

    // step 7: compile scanner
    let compiled = match crate::scanner::rules::compile_rules(&rules_list) {
        Ok(c) => c,
        Err(e) => {
            let error = sanitize_display(&e);
            let _ = writeln!(
                std::io::stderr(),
                "[ERROR] failed to compile rules: {error}"
            );
            return 2;
        }
    };

    // step 8: scan
    let findings = scan(&[diff_file], &compiled, &allowlist);

    if findings.is_empty() {
        return 0;
    }

    // step 9: report findings to stderr (agent reads stderr for feedback)
    let reason = file_findings_reason(&file_path, &findings);
    let _ = write!(std::io::stderr(), "{reason}");

    2
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;
    use serial_test::serial;

    /// raii guard that restores the working directory on drop (including panics)
    struct CwdGuard(std::path::PathBuf);
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
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

    fn permissive_config() -> &'static str {
        "[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\".*\"]\n"
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
        let (rel, base) = resolve_file_path("src/config.rs", Some("/home/user/project")).unwrap();
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
        std::fs::write(&file_path, "aws_key = \"AKIAIOSFODNN7REALKEYZ\"\n").unwrap();

        let result = run_check_file(false, Some(file_path.to_str().unwrap()));
        assert_eq!(result, 2);
    }

    #[test]
    fn epipe_on_check_file_stderr_does_not_change_the_exit_code() {
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("many-secrets.rs");
        let secret = "AKIAIOSFODNN7ABCDEFG";
        let mut content = String::new();
        for i in 0..5000 {
            content.push_str(&format!("const K{i}: &str = \"{secret}{i}\";\n"));
        }
        std::fs::write(&file_path, content).unwrap();
        let input = serde_json::to_vec(&serde_json::json!({
            "tool_input": {"file_path": file_path},
            "cwd": dir.path(),
        }))
        .unwrap();

        let binary = compiled_binary();
        assert!(
            binary.is_file(),
            "compiled binary missing at {}",
            binary.display()
        );
        let mut child = Command::new(binary)
            .args(["check-file", "--stdin-json"])
            .env("HOME", dir.path())
            .env("CODEX_HOME", dir.path().join(".codex"))
            .env("GIT_CONFIG_GLOBAL", dir.path().join("gitconfig-empty"))
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
    fn check_file_report_sanitizes_untrusted_fields() {
        let findings = vec![Finding {
            file: "file\x1b\r\u{202e}.rs".to_string(),
            line: 1,
            rule_id: "rule\x1b\r\u{202e}".to_string(),
            matched_value: "\u{202e}abcde\r".as_bytes().to_vec(),
        }];
        let reason = file_findings_reason("name\x1b\r\u{202e}.rs", &findings);

        assert!(!reason.contains('\x1b'));
        assert!(!reason.contains('\r'));
        assert!(!reason.contains('\u{202e}'));
    }

    #[test]
    fn check_file_report_caps_rendered_findings() {
        let total = codex::MAX_RENDERED_FINDINGS + 7;
        let findings = (0..total)
            .map(|index| Finding {
                file: format!("file-{index}.rs"),
                line: index + 1,
                rule_id: "fixture-rule".to_string(),
                matched_value: b"fixture-secret".to_vec(),
            })
            .collect::<Vec<_>>();
        let reason = file_findings_reason("fixture.rs", &findings);

        assert_eq!(
            reason.matches("  file: ").count(),
            codex::MAX_RENDERED_FINDINGS
        );
        assert!(reason.contains("... and 7 more finding(s) omitted"));
        assert!(reason.contains(&format!("file contains {total} secret(s).")));
    }

    #[test]
    fn check_file_agent_written_inworkspace_config_is_not_trusted() {
        let repo = init_git_repo();
        let file_path = repo.path().join("secret.py");
        std::fs::write(&file_path, "aws_key = \"AKIAIOSFODNN7ABCDEFG\"\n").unwrap();
        assert_eq!(run_check_file(false, file_path.to_str()), 2);

        std::fs::write(repo.path().join(".sekretbarilo.toml"), permissive_config()).unwrap();

        assert_eq!(run_check_file(false, file_path.to_str()), 2);
    }

    #[test]
    fn check_file_committed_inworkspace_config_allowlist_is_honored() {
        let repo = init_git_repo();
        let file_path = repo.path().join("secret.py");
        std::fs::write(&file_path, "aws_key = \"AKIAIOSFODNN7ABCDEFG\"\n").unwrap();
        assert_eq!(run_check_file(false, file_path.to_str()), 2);

        std::fs::write(repo.path().join(".sekretbarilo.toml"), permissive_config()).unwrap();
        git_success(repo.path(), &["add", ".sekretbarilo.toml"]);
        git_success(
            repo.path(),
            &["commit", "--no-verify", "-m", "add fixture config"],
        );

        assert_eq!(run_check_file(false, file_path.to_str()), 0);
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
        std::fs::write(&file_path, "const key = \"AKIAIOSFODNN7REALKEYZ\";\n").unwrap();

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
        std::fs::write(&file_path, "const key = \"AKIAIOSFODNN7REALKEYZ\";\n").unwrap();

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
}
