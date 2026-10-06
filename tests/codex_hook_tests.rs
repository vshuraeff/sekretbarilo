mod common;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{IsolatedEnv, bin, fake_gitconfig, setup_git_repo};
use sekretbarilo::agent::CODEX_HOOK_MATCHER;
use serde_json::{Value, json};

const ALL_FIXTURES: &[&str] = &[
    "apply_patch_aws_key.json",
    "apply_patch_clean.json",
    "apply_patch_env_file.json",
    "apply_patch_move_into_env.json",
    "apply_patch_env_example.json",
    "apply_patch_adversarial_directives.json",
    "apply_patch_control_chars_in_path.json",
    "apply_patch_malformed_patch.json",
    "apply_patch_pure_rename.json",
    "bash_bearer_token.json",
    "bash_export_aws.json",
    "bash_clean.json",
    "unknown_tool.json",
    "non_pretooluse.json",
    "malformed.json",
];

fn current_codex_hook_command() -> String {
    format!("{} check-codex --stdin-json", bin())
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/codex")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {name} at {path:?}: {error}"))
}

fn fixture_value(name: &str) -> Value {
    serde_json::from_slice(&fixture_bytes(name))
        .unwrap_or_else(|error| panic!("failed to parse fixture {name}: {error}"))
}

fn fixture_command(name: &str) -> String {
    fixture_value(name)["tool_input"]["command"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture {name} does not contain a string tool_input.command"))
        .to_owned()
}

fn run_check_codex(payload: &[u8]) -> Output {
    let env = IsolatedEnv::new();
    let mut child = env
        .command()
        .args(["check-codex", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-codex");
    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(payload)
        .expect("failed to write payload to child stdin");
    child.wait_with_output().expect("failed to wait on child")
}

fn run_check_codex_in(env: &IsolatedEnv, payload: &[u8], current_dir: &Path) -> Output {
    let mut child = env
        .command()
        .args(["check-codex", "--stdin-json"])
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-codex");
    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(payload)
        .expect("failed to write payload to child stdin");
    child.wait_with_output().expect("failed to wait on child")
}

fn run_check_codex_large(payload: Vec<u8>) -> Output {
    let env = IsolatedEnv::new();
    let mut child = env
        .command()
        .args(["check-codex", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-codex");
    let mut stdin = child.stdin.take().expect("stdin was not piped");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });
    let output = child.wait_with_output().expect("failed to wait on child");
    writer.join().expect("stdin writer thread panicked");
    output
}

fn run_fixture(name: &str) -> Output {
    run_check_codex(&fixture_bytes(name))
}

fn apply_patch_payload(command: String, cwd: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": command},
        "cwd": cwd.to_string_lossy(),
    }))
    .expect("failed to encode apply_patch payload")
}

fn git_success(env: &IsolatedEnv, repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// This literal mirrors codex.rs's private MAX_PAYLOAD_BYTES, which integration tests cannot import.
fn oversized_payload() -> Vec<u8> {
    vec![b' '; 10 * 1024 * 1024 + 1]
}

fn hooks_path(env: &IsolatedEnv) -> PathBuf {
    env.codex_home().join("hooks.json")
}

fn read_json(path: &Path) -> Value {
    let contents = std::fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read JSON at {path:?}: {error}"));
    serde_json::from_slice(&contents)
        .unwrap_or_else(|error| panic!("failed to parse JSON at {path:?}: {error}"))
}

fn write_json(path: &Path, value: &Value) {
    let parent = path
        .parent()
        .unwrap_or_else(|| panic!("JSON path {path:?} has no parent"));
    std::fs::create_dir_all(parent)
        .unwrap_or_else(|error| panic!("failed to create {parent:?}: {error}"));
    std::fs::write(
        path,
        serde_json::to_vec(value).expect("failed to serialize JSON"),
    )
    .unwrap_or_else(|error| panic!("failed to write JSON at {path:?}: {error}"));
}

fn pre_tool_use(config: &Value) -> &[Value] {
    config["hooks"]["PreToolUse"]
        .as_array()
        .expect("hooks.PreToolUse was not an array")
}

fn run_global_install(env: &IsolatedEnv) -> Output {
    env.command()
        .args(["install", "agent-hook", "codex", "--global"])
        .output()
        .expect("failed to run global Codex hook install")
}

/// Pull the substring of `haystack` that follows `marker`, up to the next `"` or
/// end of string. Used to read a fixture's embedded secret value at test time
/// instead of hardcoding a copy that could silently drift from the fixture file.
fn value_after(haystack: &str, marker: &str) -> String {
    let start = haystack
        .find(marker)
        .unwrap_or_else(|| panic!("marker {marker:?} not found in {haystack:?}"))
        + marker.len();
    let rest = &haystack[start..];
    let end = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn check_codex_blocks_apply_patch_aws_key() {
    assert_eq!(
        run_fixture("apply_patch_aws_key.json").status.code(),
        Some(2)
    );
}

#[test]
fn check_codex_allows_apply_patch_clean() {
    assert_eq!(run_fixture("apply_patch_clean.json").status.code(), Some(0));
}

#[test]
fn check_codex_blocks_apply_patch_env_file() {
    assert_eq!(
        run_fixture("apply_patch_env_file.json").status.code(),
        Some(2)
    );
}

#[test]
fn check_codex_blocks_apply_patch_move_into_env() {
    assert_eq!(
        run_fixture("apply_patch_move_into_env.json").status.code(),
        Some(2)
    );
}

#[test]
fn check_codex_allows_apply_patch_env_example() {
    assert_eq!(
        run_fixture("apply_patch_env_example.json").status.code(),
        Some(0)
    );
}

#[test]
fn check_codex_allows_apply_patch_adversarial_directives() {
    assert_eq!(
        run_fixture("apply_patch_adversarial_directives.json")
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn check_codex_blocks_apply_patch_malformed_patch() {
    assert_eq!(
        run_fixture("apply_patch_malformed_patch.json")
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn check_codex_blocks_apply_patch_control_chars_in_path_without_leaking_them() {
    let output = run_fixture("apply_patch_control_chars_in_path.json");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stderr.contains('\x1b'),
        "stderr leaked an ESC character: {stderr}"
    );
    assert!(
        !stderr.contains('\r'),
        "stderr leaked a carriage return: {stderr}"
    );
    assert!(
        !stderr.contains('\u{202e}'),
        "stderr leaked a right-to-left override: {stderr}"
    );
}

#[test]
fn check_codex_allows_pure_rename_with_no_change_lines() {
    assert_eq!(
        run_fixture("apply_patch_pure_rename.json").status.code(),
        Some(0)
    );
}

#[test]
fn check_codex_findings_cap_produces_bounded_stderr_with_accurate_count() {
    let secret = "AKIAIOSFODNN7ABCDEFG";
    let total = 5000;
    let mut patch = String::from("*** Begin Patch\n*** Add File: many.rs\n");
    for i in 0..total {
        patch.push_str(&format!("+const K{i}: &str = \"{secret}{i}\";\n"));
    }
    patch.push_str("*** End Patch\n");

    let payload = apply_patch_payload(patch, Path::new("/tmp"));
    let output = run_check_codex(&payload);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.len() < 20_000,
        "capped findings should keep stderr bounded, got {} bytes",
        output.stderr.len()
    );
    assert!(
        stderr.contains("... and 4980 more finding(s) omitted"),
        "stderr should report the capped finding count, got:\n{stderr}"
    );
    assert!(
        stderr.contains("total findings: 5000."),
        "stderr should report the true finding count, got:\n{stderr}"
    );
}

#[test]
fn check_codex_blocks_bash_with_non_object_tool_input() {
    let payload = serde_json::to_vec(&json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": "not-an-object",
        "cwd": "/tmp",
    }))
    .expect("failed to encode Bash payload");

    let output = run_check_codex(&payload);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !output.stderr.is_empty(),
        "schema-mismatch block should include a reason"
    );
}

#[test]
fn check_codex_exit_code_is_stable_when_stderr_reader_closes_early() {
    let secret = "AKIAIOSFODNN7ABCDEFG";
    let mut patch = String::from("*** Begin Patch\n*** Add File: many.rs\n");
    for i in 0..5000 {
        patch.push_str(&format!("+const K{i}: &str = \"{secret}{i}\";\n"));
    }
    patch.push_str("*** End Patch\n");

    let env = IsolatedEnv::new();
    let input = apply_patch_payload(patch, env.root());
    let mut child = env
        .command()
        .args(["check-codex", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-codex");
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

    // Findings have been capped at MAX_RENDERED_FINDINGS (20) since 876172a, so this no longer
    // forces a blocking write through a full pipe buffer. It instead pins the exit-2 contract
    // upstream Codex depends on, under whichever profile cargo test uses.
    let status = child.wait().expect("failed to wait on sekretbarilo");
    assert_eq!(
        status.code(),
        Some(2),
        "an early-closing stderr reader must not change the exit code"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        assert!(
            status.signal().is_none(),
            "check-codex was killed by signal {:?}",
            status.signal()
        );
    }
    assert!(stdout_reader.join().unwrap().is_empty());
}

#[test]
fn check_codex_untracked_inworkspace_config_ignored_committed_config_honored() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let secret_patch = apply_patch_payload(
        "*** Begin Patch\n*** Add File: config.py\n+AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7ABCDEFG\"\n*** End Patch\n".to_string(),
        &repo,
    );

    let initial = run_check_codex_in(&env, &secret_patch, &repo);
    assert_eq!(
        initial.status.code(),
        Some(2),
        "secret patch should be blocked before an in-workspace config exists"
    );

    std::fs::write(
        repo.join(".sekretbarilo.toml"),
        "[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\".*\"]\n",
    )
    .expect("failed to write untracked config");

    let untracked = run_check_codex_in(&env, &secret_patch, &repo);
    let untracked_stderr = String::from_utf8_lossy(&untracked.stderr);
    assert_eq!(
        untracked.status.code(),
        Some(2),
        "untracked in-workspace config must not relax secret scanning"
    );
    assert!(
        untracked_stderr.contains("ignoring untrusted in-workspace config"),
        "untracked config warning missing from stderr:\n{untracked_stderr}"
    );

    git_success(&env, &repo, &["add", ".sekretbarilo.toml"]);
    git_success(
        &env,
        &repo,
        &["commit", "--no-verify", "-m", "add trusted fixture config"],
    );

    let committed = run_check_codex_in(&env, &secret_patch, &repo);
    assert_eq!(
        committed.status.code(),
        Some(0),
        "committed in-workspace config should be trusted"
    );
}

#[test]
fn check_codex_blocks_apply_patch_when_committed_config_has_invalid_allowlist_regex() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    std::fs::write(
        repo.join(".sekretbarilo.toml"),
        "[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\"(\"]\n",
    )
    .expect("failed to write invalid fixture config");
    git_success(&env, &repo, &["add", ".sekretbarilo.toml"]);
    git_success(
        &env,
        &repo,
        &["commit", "--no-verify", "-m", "add invalid fixture config"],
    );

    let clean_patch = apply_patch_payload(
        "*** Begin Patch\n*** Add File: clean.rs\n+const VALUE: u8 = 1;\n*** End Patch\n"
            .to_string(),
        &repo,
    );
    let output = run_check_codex_in(&env, &clean_patch, &repo);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid committed config must fail closed"
    );
    assert!(
        stderr.contains("scanner setup failed"),
        "scanner setup failure missing from stderr:\n{stderr}"
    );
}

#[test]
fn install_codex_hook_global_rejects_empty_home_and_creates_no_relative_hooks_file() {
    let current_dir = tempfile::tempdir().expect("failed to create empty current directory");
    let git_config_global = current_dir.path().join(".fake-gitconfig");
    std::fs::write(&git_config_global, "").expect("failed to create isolated git config");

    let output = Command::new(bin())
        .args(["install", "agent-hook", "codex", "--global"])
        .env("HOME", "")
        .env_remove("CODEX_HOME")
        .env("GIT_CONFIG_GLOBAL", &git_config_global)
        .current_dir(current_dir.path())
        .output()
        .expect("failed to run global Codex hook install with empty HOME");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("[ERROR]"),
        "empty HOME error should include an error prefix"
    );
    assert!(
        !current_dir.path().join(".codex/hooks.json").exists(),
        "empty HOME must not create a relative .codex/hooks.json"
    );
}

#[test]
fn check_codex_blocks_bash_bearer_token() {
    assert_eq!(run_fixture("bash_bearer_token.json").status.code(), Some(2));
}

#[test]
fn check_codex_blocks_bash_export_aws() {
    assert_eq!(run_fixture("bash_export_aws.json").status.code(), Some(2));
}

#[test]
fn check_codex_allows_bash_clean() {
    assert_eq!(run_fixture("bash_clean.json").status.code(), Some(0));
}

#[test]
fn check_codex_allows_unknown_tool() {
    assert_eq!(run_fixture("unknown_tool.json").status.code(), Some(0));
}

#[test]
fn check_codex_allows_non_pretooluse_event() {
    assert_eq!(run_fixture("non_pretooluse.json").status.code(), Some(0));
}

#[test]
fn check_codex_blocks_malformed_input_with_reason() {
    let output = run_fixture("malformed.json");
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

// The apply_patch parser is private, so this injected canary proves line-level parsing via the CLI.
#[test]
fn check_codex_adversarial_directive_lines_are_scanned_as_sequential_content() {
    let fixture = fixture_value("apply_patch_adversarial_directives.json");
    let command = fixture["tool_input"]["command"]
        .as_str()
        .expect("adversarial fixture command was not a string")
        .to_owned();
    let derived_command = command.replace(
        "+*** Add File: evil.txt\n line2",
        "+*** Add File: evil.txt\n+AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7ABCDEFG\"\n line2",
    );
    assert_ne!(
        derived_command, command,
        "failed to inject canary into fixture"
    );
    let mut payload = fixture;
    payload["tool_input"]["command"] = Value::String(derived_command);

    let output = run_check_codex(&serde_json::to_vec(&payload).expect("failed to encode payload"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("apply_patch blocked"));
    assert!(stderr.contains("line: 3"));
    assert!(!stderr.contains("AKIAIOSFODNN7ABCDEFG"));
}

#[test]
fn invariant_i1_stdout_always_empty() {
    for fixture in ALL_FIXTURES {
        let output = run_fixture(fixture);
        assert!(
            output.stdout.is_empty(),
            "expected empty stdout for fixture {fixture}"
        );
    }

    let output = run_check_codex_large(oversized_payload());
    assert!(
        output.stdout.is_empty(),
        "expected empty stdout for oversized payload"
    );
}

#[test]
fn invariant_i2_every_block_has_nonempty_stderr() {
    // Upstream Codex treats exit 2 with empty stderr as fail-open, making a silent block worse than a clean allow.
    const BLOCKED_FIXTURES: &[&str] = &[
        "apply_patch_aws_key.json",
        "apply_patch_env_file.json",
        "apply_patch_move_into_env.json",
        "apply_patch_control_chars_in_path.json",
        "apply_patch_malformed_patch.json",
        "bash_bearer_token.json",
        "bash_export_aws.json",
        "malformed.json",
    ];

    for fixture in BLOCKED_FIXTURES {
        let output = run_fixture(fixture);
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected block for {fixture}"
        );
        assert!(
            !output.stderr.is_empty(),
            "expected block reason on stderr for {fixture}"
        );
    }

    let output = run_check_codex_large(oversized_payload());
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn invariant_i5_raw_secrets_never_appear_in_stderr() {
    let apply_patch_command = fixture_command("apply_patch_aws_key.json");
    let bearer_command = fixture_command("bash_bearer_token.json");
    let export_command = fixture_command("bash_export_aws.json");
    let cases = [
        (
            "apply_patch_aws_key.json",
            vec![
                value_after(&apply_patch_command, "AWS_ACCESS_KEY_ID = \""),
                value_after(&apply_patch_command, "AWS_SECRET_ACCESS_KEY = \""),
            ],
        ),
        (
            "bash_bearer_token.json",
            vec![value_after(&bearer_command, "Bearer ")],
        ),
        (
            "bash_export_aws.json",
            vec![value_after(&export_command, "AWS_SECRET_ACCESS_KEY=")],
        ),
    ];

    for (fixture, secrets) in cases {
        let output = run_fixture(fixture);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in secrets {
            assert!(
                !stderr.contains(&secret),
                "raw secret from {fixture} appeared in stderr"
            );
        }
    }
}

#[test]
fn invariant_exit_codes_are_only_zero_or_two() {
    for fixture in ALL_FIXTURES {
        let code = run_fixture(fixture).status.code();
        assert!(
            matches!(code, Some(0) | Some(2)),
            "unexpected exit code {code:?} for fixture {fixture}"
        );
    }

    let code = run_check_codex_large(oversized_payload()).status.code();
    assert!(
        matches!(code, Some(0) | Some(2)),
        "unexpected exit code {code:?} for oversized payload"
    );
}

#[test]
fn oversized_payload_is_blocked_with_truncated_message() {
    let output = run_check_codex_large(oversized_payload());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("payload truncated"));
}

#[test]
fn install_codex_hook_exact_shape_on_fresh_codex_home() {
    let env = IsolatedEnv::new();
    let output = run_global_install(&env);
    assert_eq!(output.status.code(), Some(0));

    let config = read_json(&hooks_path(&env));
    // Codex requires this top-level hooks wrapper; a bare PreToolUse object is not a valid hook file.
    assert_eq!(
        config,
        json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": CODEX_HOOK_MATCHER,
                    "hooks": [{
                        "type": "command",
                        "command": current_codex_hook_command(),
                        "timeout": 10,
                        "statusMessage": "Scanning tool input for secrets..."
                    }]
                }],
                "PostToolUse": [{
                    "matcher": "^Bash$",
                    "hooks": [{
                        "type": "command",
                        "command": current_codex_hook_command(),
                        "timeout": 10,
                        "statusMessage": "Scanning tool output for secrets..."
                    }]
                }]
            }
        })
    );
}

#[test]
fn install_codex_hook_is_idempotent_via_cli() {
    let env = IsolatedEnv::new();
    let first = run_global_install(&env);
    let second = run_global_install(&env);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));

    let config = read_json(&hooks_path(&env));
    let groups = pre_tool_use(&config);
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0]["hooks"]
            .as_array()
            .expect("new group hooks was not an array")
            .len(),
        1
    );
    assert!(
        String::from_utf8_lossy(&second.stderr)
            .to_ascii_lowercase()
            .contains("already installed")
    );
}

#[test]
fn install_codex_hook_updates_outdated_command_in_place() {
    let env = IsolatedEnv::new();
    let path = hooks_path(&env);
    write_json(
        &path,
        &json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": CODEX_HOOK_MATCHER,
                    "hooks": [{
                        "type": "command",
                        "command": "sekretbarilo check-codex --old-flag",
                        "timeout": 10
                    }]
                }]
            }
        }),
    );

    let output = run_global_install(&env);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("updated")
    );

    let config = read_json(&path);
    let groups = pre_tool_use(&config);
    assert_eq!(groups.len(), 1);
    let handlers = groups[0]["hooks"]
        .as_array()
        .expect("updated group hooks was not an array");
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["command"], current_codex_hook_command());
}

#[test]
fn install_codex_hook_append_only_preserves_foreign_groups() {
    let env = IsolatedEnv::new();
    let path = hooks_path(&env);
    let read_group = json!({
        "matcher": "Read",
        "hooks": [{
            "type": "command",
            "command": "foreign-read-hook",
            "timeout": 5,
            "note": "keep-me-1"
        }]
    });
    let write_group = json!({
        "matcher": "Write",
        "hooks": [{
            "type": "command",
            "command": "foreign-write-hook",
            "timeout": 7,
            "note": "keep-me-2"
        }]
    });
    write_json(
        &path,
        &json!({
            "hooks": {
                "PreToolUse": [read_group.clone(), write_group.clone()]
            }
        }),
    );

    let output = run_global_install(&env);
    assert_eq!(output.status.code(), Some(0));

    let config = read_json(&path);
    let groups = pre_tool_use(&config);
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0], read_group);
    assert_eq!(groups[1], write_group);
    assert_eq!(groups[2]["matcher"], CODEX_HOOK_MATCHER);
    let handlers = groups[2]["hooks"]
        .as_array()
        .expect("new group hooks was not an array");
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["command"], current_codex_hook_command());

    // Codex approval keys include group and handler indices, so only appending preserves foreign approvals.
}

#[test]
fn install_codex_hook_preserves_description_and_unknown_top_level_keys() {
    let env = IsolatedEnv::new();
    let path = hooks_path(&env);
    write_json(
        &path,
        &json!({
            "description": "existing description",
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Read",
                    "note": "preserve-group-note",
                    "hooks": [{
                        "type": "command",
                        "command": "foreign-read-hook",
                        "timeout": 5,
                        "extra": "preserve-handler-extra"
                    }]
                }]
            }
        }),
    );

    let output = run_global_install(&env);
    assert_eq!(output.status.code(), Some(0));

    let config = read_json(&path);
    assert_eq!(config["description"], "existing description");
    let groups = pre_tool_use(&config);
    assert_eq!(groups[0]["note"], "preserve-group-note");
    assert_eq!(groups[0]["hooks"][0]["extra"], "preserve-handler-extra");
    // Upstream's deny_unknown_fields root accepts only hooks and description; any extra key breaks parsing.
    assert!(
        config
            .as_object()
            .expect("hooks config root was not an object")
            .keys()
            .all(|key| matches!(key.as_str(), "hooks" | "description"))
    );
}

#[test]
fn install_codex_hook_local_default_path_in_git_repo() {
    let repo = setup_git_repo();
    let env = IsolatedEnv::new();
    let fake_global = fake_gitconfig(&repo);
    let output = env
        .command()
        .current_dir(repo.path())
        .args(["install", "agent-hook", "codex"])
        .env("GIT_CONFIG_GLOBAL", fake_global)
        .output()
        .expect("failed to run local Codex hook install");
    assert_eq!(output.status.code(), Some(0));

    let path = repo.path().join(".codex/hooks.json");
    assert!(path.exists(), "local Codex hooks file was not created");
    let config = read_json(&path);
    let groups = pre_tool_use(&config);
    assert_eq!(
        groups[0]["hooks"][0]["command"],
        current_codex_hook_command()
    );
}

/// a PostToolUse Bash payload in the shape codex-cli 0.159.3 sends: tool_response is the
/// model-facing output as one string.
fn post_tool_use_payload(output: &str, cwd: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": "session-post",
        "turn_id": "turn-post",
        "cwd": cwd,
        "hook_event_name": "PostToolUse",
        "model": "gpt-test",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": "cat config/deploy.env"},
        "tool_response": output,
        "tool_use_id": "exec-post"
    }))
    .expect("failed to serialize PostToolUse payload")
}

fn generated_github_token() -> String {
    let body: String = "q7Wm2Kx9Rt4Lp8Vz3Nc6".chars().cycle().take(36).collect();
    format!("ghp_{body}")
}

#[test]
fn check_codex_post_tool_use_withholds_secret_bash_output() {
    let env = IsolatedEnv::new();
    let token = generated_github_token();
    let output = format!("APP_ENV=prod\nGITHUB_TOKEN={token}\n");
    let result = run_check_codex_in(
        &env,
        &post_tool_use_payload(&output, env.home()),
        env.home(),
    );

    assert_eq!(result.status.code(), Some(2));
    assert!(
        result.stdout.is_empty(),
        "check-codex must not write stdout"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!stderr.contains(&token), "the raw token reached the reason");
    assert!(stderr.contains("withheld this Bash output"));
    assert!(stderr.contains("APP_ENV=prod\nGITHUB_TOKEN=[REDACTED]\n"));
}

#[test]
fn check_codex_post_tool_use_counts_one_value_caught_by_two_rules_once() {
    let env = IsolatedEnv::new();
    let token = generated_github_token();
    let result = run_check_codex_in(
        &env,
        &post_tool_use_payload(&format!("GITHUB_TOKEN={token}\n"), env.home()),
        env.home(),
    );

    assert_eq!(result.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(": 1 secret finding(s)."),
        "one token must be one finding: {stderr}"
    );
}

#[test]
fn check_codex_post_tool_use_whole_withhold_lists_one_value_once() {
    let env = IsolatedEnv::new();
    let token = generated_github_token();
    let filler = "x".repeat(70 * 1024);
    let result = run_check_codex_in(
        &env,
        &post_tool_use_payload(&format!("GITHUB_TOKEN={token}\n{filler}\n"), env.home()),
        env.home(),
    );

    assert_eq!(result.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("withheld whole"), "{stderr}");
    assert!(stderr.contains(": 1 secret finding(s)."), "{stderr}");
    assert_eq!(stderr.matches("  match: ").count(), 1, "{stderr}");
    assert!(!stderr.contains(&token));
}

#[test]
fn check_codex_post_tool_use_allows_clean_bash_output_silently() {
    let env = IsolatedEnv::new();
    let result = run_check_codex_in(
        &env,
        &post_tool_use_payload("APP_ENV=prod\nLOG_LEVEL=info\n", env.home()),
        env.home(),
    );

    assert_eq!(result.status.code(), Some(0));
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}

#[test]
fn check_codex_post_tool_use_withholds_output_whose_cwd_vanished_above_a_secret() {
    let env = IsolatedEnv::new();
    let token = generated_github_token();
    let vanished = env.home().join("removed-worktree");
    let result = run_check_codex_in(
        &env,
        &post_tool_use_payload(&format!("GITHUB_TOKEN={token}\n"), &vanished),
        env.home(),
    );

    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(&token));
}

fn bash_payload(command: &str, cwd: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": "session-pre",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }))
    .expect("failed to serialize PreToolUse payload")
}

/// disables the built-in rule that catches `generated_github_token`.
const DISABLE_GITHUB_PAT: &str = "[settings.rules]\n\"github-personal-access-token\" = false\n";

/// a rule no built-in matches, so only the layer carrying it can block its canary.
const CANARY_RULE: &str = "[[rules]]\nid = \"fixture-canary\"\ndescription = \"synthetic canary\"\nregex = 'CANARY=([A-Z0-9]+)'\nkeywords = [\"CANARY=\"]\nsecret_group = 1\n";

fn generated_canary() -> String {
    let body: String = "Q7W2K9R4L8V3".chars().cycle().take(12).collect();
    format!("CANARY={body}")
}

fn write_xdg_layer(env: &IsolatedEnv, content: &str) {
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).expect("failed to create the XDG config directory");
    std::fs::write(dir.join("sekretbarilo.toml"), content).expect("failed to write the XDG layer");
}

#[test]
fn check_codex_inworkspace_config_symlink_is_not_trusted_even_when_committed() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let target = outside.join("permissive.toml");
    std::fs::write(&target, DISABLE_GITHUB_PAT).unwrap();
    std::os::unix::fs::symlink(&target, repo.join(".sekretbarilo.toml")).unwrap();
    let token = generated_github_token();
    let pre = bash_payload(&format!("echo {token}"), &repo);
    let post = post_tool_use_payload(&format!("{token}\n"), &repo);

    for state in ["untracked", "committed"] {
        if state == "committed" {
            git_success(&env, &repo, &["add", ".sekretbarilo.toml"]);
            git_success(
                &env,
                &repo,
                &["commit", "--no-verify", "-m", "add fixture config symlink"],
            );
        }
        for (event, payload) in [("PreToolUse", &pre), ("PostToolUse", &post)] {
            let output = run_check_codex_in(&env, payload, &repo);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{state} {event}: {stderr}");
            assert!(
                stderr.contains("ignoring untrusted in-workspace config"),
                "{state} {event}: {stderr}"
            );
            assert!(!stderr.contains(&token), "{state} {event}: raw token");
        }
    }

    // control: the same file as a trusted layer does disable the rule.
    std::fs::remove_file(repo.join(".sekretbarilo.toml")).unwrap();
    write_xdg_layer(&env, DISABLE_GITHUB_PAT);
    for payload in [&pre, &post] {
        assert_eq!(
            run_check_codex_in(&env, payload, &repo).status.code(),
            Some(0)
        );
    }
}

/// both events catch the canary from `cwd`, so the layer carrying its rule was trusted.
fn assert_canary_rule_applies(env: &IsolatedEnv, cwd: &Path) {
    let canary = generated_canary();

    let pre = run_check_codex_in(env, &bash_payload(&format!("echo {canary}"), cwd), cwd);
    let stderr = String::from_utf8_lossy(&pre.stderr);
    assert_eq!(pre.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("rule: fixture-canary"), "{stderr}");
    assert!(!stderr.contains("ignoring untrusted"), "{stderr}");

    let post = run_check_codex_in(env, &post_tool_use_payload(&canary, cwd), cwd);
    let stderr = String::from_utf8_lossy(&post.stderr);
    assert_eq!(post.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("CANARY=[REDACTED]"), "{stderr}");
    assert!(!stderr.contains("ignoring untrusted"), "{stderr}");
}

#[test]
fn check_codex_keeps_the_user_layer_when_cwd_is_home() {
    let env = IsolatedEnv::new();
    write_xdg_layer(&env, CANARY_RULE);
    assert_canary_rule_applies(&env, env.home());
}

#[test]
fn check_codex_keeps_the_user_layer_when_xdg_config_home_is_under_a_non_git_cwd() {
    // the cwd is the isolated root, which holds HOME and with it XDG_CONFIG_HOME: the shape
    // of a probe whose isolated config sits under the non-git $TMPDIR it scans from.
    let env = IsolatedEnv::new();
    write_xdg_layer(&env, CANARY_RULE);
    assert_canary_rule_applies(&env, env.root());
}

#[test]
fn check_codex_keeps_a_symlinked_user_layer_when_cwd_is_home() {
    // a dotfiles layout: the XDG file links to a file elsewhere in HOME, all inside the
    // workspace when the cwd is HOME.
    let env = IsolatedEnv::new();
    let dotfiles = env.home().join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let target = dotfiles.join("sekretbarilo.toml");
    std::fs::write(&target, CANARY_RULE).unwrap();
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&target, dir.join("sekretbarilo.toml")).unwrap();
    assert_canary_rule_applies(&env, env.home());
}

#[test]
fn check_codex_cwd_through_a_symlinked_workspace_directory_ignores_its_target_layer() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join(".sekretbarilo.toml"), DISABLE_GITHUB_PAT).unwrap();
    let linked = repo.join("linked");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    let token = generated_github_token();

    for (event, payload) in [
        (
            "PreToolUse",
            bash_payload(&format!("echo {token}"), &linked),
        ),
        (
            "PostToolUse",
            post_tool_use_payload(&format!("{token}\n"), &linked),
        ),
    ] {
        let output = run_check_codex_in(&env, &payload, &linked);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{event}: {stderr}");
        assert!(
            stderr.contains("ignoring untrusted in-workspace config"),
            "{event}: {stderr}"
        );
    }
}

/// a second repository under the isolated root with `content` committed as its layer.
fn other_repo_with_committed_layer(env: &IsolatedEnv, content: &str) -> PathBuf {
    let other = env.root().join("other");
    std::fs::create_dir_all(&other).unwrap();
    git_success(env, &other, &["init", "-q"]);
    git_success(env, &other, &["config", "user.email", "test@test.invalid"]);
    git_success(env, &other, &["config", "user.name", "Test"]);
    std::fs::write(other.join(".sekretbarilo.toml"), content).unwrap();
    git_success(env, &other, &["add", ".sekretbarilo.toml"]);
    git_success(
        env,
        &other,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    other
}

#[test]
fn check_codex_cwd_through_a_symlink_into_another_repository_ignores_its_committed_layer() {
    // git resolves the link and finds the other repository, whose committed layer would
    // otherwise vouch for itself in a workspace that never committed it.
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let other = other_repo_with_committed_layer(&env, DISABLE_GITHUB_PAT);
    let linked = repo.join("linked");
    std::os::unix::fs::symlink(&other, &linked).unwrap();
    let token = generated_github_token();

    for cwd in [&linked, &other] {
        for (event, payload) in [
            ("PreToolUse", bash_payload(&format!("echo {token}"), cwd)),
            (
                "PostToolUse",
                post_tool_use_payload(&format!("{token}\n"), cwd),
            ),
        ] {
            let output = run_check_codex_in(&env, &payload, cwd);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if cwd == &linked {
                assert_eq!(output.status.code(), Some(2), "{event}: {stderr}");
                assert!(
                    stderr.contains("ignoring untrusted in-workspace config"),
                    "{event}: {stderr}"
                );
                assert!(!stderr.contains(&token), "{event}: raw token");
            } else {
                // control: in the other repository itself its committed layer applies.
                assert_eq!(output.status.code(), Some(0), "{event}: {stderr}");
            }
        }
    }
}

#[test]
fn check_codex_cwd_through_a_link_into_a_nested_repository_judges_the_holder_layer() {
    // the target nests in the repository holding the link, so the holder's layer lies outside
    // the target; the agent works in the holder, which has not committed it. both sit under
    // HOME, where discovery from the link walks up to the holder.
    let env = IsolatedEnv::new();
    let holder = env.home().join("work");
    let nested = holder.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    for repo in [&holder, &nested] {
        git_success(&env, repo, &["init", "-q"]);
        git_success(&env, repo, &["config", "user.email", "test@test.invalid"]);
        git_success(&env, repo, &["config", "user.name", "Test"]);
    }
    std::fs::write(holder.join(".sekretbarilo.toml"), DISABLE_GITHUB_PAT).unwrap();
    let linked = holder.join("linked");
    std::os::unix::fs::symlink(&nested, &linked).unwrap();
    let token = generated_github_token();
    let pre = bash_payload(&format!("echo {token}"), &linked);
    let post = post_tool_use_payload(&format!("{token}\n"), &linked);

    for (event, payload) in [("PreToolUse", &pre), ("PostToolUse", &post)] {
        let output = run_check_codex_in(&env, payload, &linked);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{event}: {stderr}");
        assert!(
            stderr.contains("ignoring untrusted in-workspace config"),
            "{event}: {stderr}"
        );
        assert!(!stderr.contains(&token), "{event}: raw token");
    }

    // control: committed unmodified in the holder, the layer applies.
    git_success(&env, &holder, &["add", ".sekretbarilo.toml"]);
    git_success(
        &env,
        &holder,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    for (event, payload) in [("PreToolUse", &pre), ("PostToolUse", &post)] {
        let output = run_check_codex_in(&env, payload, &linked);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{event}: {stderr}");
        assert!(!stderr.contains("ignoring untrusted"), "{event}: {stderr}");
    }
}

#[test]
fn check_codex_ignores_a_committed_layer_modified_behind_git_diff() {
    // each way keeps `git diff --quiet HEAD` clean while the working copy disables the rule.
    for hide in ["--assume-unchanged", "--skip-worktree", "replace"] {
        let env = IsolatedEnv::new();
        let repo = env.git_repo();
        let layer = repo.join(".sekretbarilo.toml");
        std::fs::write(&layer, "[settings]\n").unwrap();
        git_success(&env, &repo, &["add", ".sekretbarilo.toml"]);
        git_success(
            &env,
            &repo,
            &["commit", "--no-verify", "-m", "add fixture config"],
        );
        if hide == "replace" {
            std::fs::write(&layer, DISABLE_GITHUB_PAT).unwrap();
            let hashed = Command::new("git")
                .args(["hash-object", "-w", ".sekretbarilo.toml"])
                .env("GIT_CONFIG_GLOBAL", env.git_config_global())
                .current_dir(&repo)
                .output()
                .unwrap();
            let replacement = String::from_utf8(hashed.stdout).unwrap();
            git_success(
                &env,
                &repo,
                &["replace", "HEAD:.sekretbarilo.toml", replacement.trim()],
            );
        } else {
            git_success(&env, &repo, &["update-index", hide, ".sekretbarilo.toml"]);
            std::fs::write(&layer, DISABLE_GITHUB_PAT).unwrap();
        }
        git_success(
            &env,
            &repo,
            &["diff", "--quiet", "HEAD", "--", ".sekretbarilo.toml"],
        );
        let token = generated_github_token();

        for (event, payload) in [
            ("PreToolUse", bash_payload(&format!("echo {token}"), &repo)),
            (
                "PostToolUse",
                post_tool_use_payload(&format!("{token}\n"), &repo),
            ),
        ] {
            let output = run_check_codex_in(&env, &payload, &repo);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{hide} {event}: {stderr}");
            assert!(
                stderr.contains("ignoring untrusted in-workspace config"),
                "{hide} {event}: {stderr}"
            );
        }
    }
}

/// `check-codex` with the given environment overrides on top of the isolated one.
fn run_check_codex_with_env(
    env: &IsolatedEnv,
    payload: &[u8],
    current_dir: &Path,
    vars: &[(&str, &str)],
) -> Output {
    let mut command = env.command();
    command
        .args(["check-codex", "--stdin-json"])
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in vars {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("failed to spawn sekretbarilo");
    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(payload)
        .expect("failed to write payload to child stdin");
    child.wait_with_output().expect("failed to wait on child")
}

#[test]
fn check_codex_ignores_a_relative_xdg_config_home() {
    // the relative value would name a directory under the process cwd, which is not the
    // payload's workspace; the xdg spec says to ignore it and use HOME/.config.
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let process_dir = env.root().join("process");
    let relative_dir = process_dir.join("xdg/sekretbarilo");
    std::fs::create_dir_all(&relative_dir).unwrap();
    std::fs::write(relative_dir.join("sekretbarilo.toml"), DISABLE_GITHUB_PAT).unwrap();
    let token = generated_github_token();
    let payload = bash_payload(&format!("echo {token}"), &repo);
    let vars = [("XDG_CONFIG_HOME", "xdg")];

    let output = run_check_codex_with_env(&env, &payload, &process_dir, &vars);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("github-personal-access-token"), "{stderr}");

    // the HOME fallback is read instead
    write_xdg_layer(&env, DISABLE_GITHUB_PAT);
    let output = run_check_codex_with_env(&env, &payload, &process_dir, &vars);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_codex_with_an_empty_home_reads_the_workspace_layer() {
    // an empty HOME is unset: discovery starts at the workspace instead of finding nothing.
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    std::fs::write(repo.join(".sekretbarilo.toml"), CANARY_RULE).unwrap();
    git_success(&env, &repo, &["add", ".sekretbarilo.toml"]);
    git_success(
        &env,
        &repo,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    let canary = generated_canary();

    let output = run_check_codex_with_env(
        &env,
        &bash_payload(&format!("echo {canary}"), &repo),
        &repo,
        &[("HOME", "")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("rule: fixture-canary"), "{stderr}");
}

#[test]
fn check_codex_still_drops_the_home_hierarchy_layer_when_cwd_is_home() {
    // ~/.sekretbarilo.toml is a hierarchy layer: with cwd = HOME outside git it lies inside
    // the workspace and stays untrusted.
    let env = IsolatedEnv::new();
    write_xdg_layer(&env, CANARY_RULE);
    let canary = generated_canary();
    let body = canary.trim_start_matches("CANARY=");
    std::fs::write(
        env.home().join(".sekretbarilo.toml"),
        format!("[[allowlist.rules]]\nid = \"fixture-canary\"\nregexes = ['^{body}$']\n"),
    )
    .unwrap();
    let payload = |cwd: &Path| bash_payload(&format!("echo {canary}"), cwd);

    let at_home = run_check_codex_in(&env, &payload(env.home()), env.home());
    let stderr = String::from_utf8_lossy(&at_home.stderr);
    assert_eq!(at_home.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("ignoring untrusted in-workspace config"),
        "{stderr}"
    );

    // control: from a subdirectory the same layer lies above the workspace and is honoured.
    let sub = env.home().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(
        run_check_codex_in(&env, &payload(&sub), &sub).status.code(),
        Some(0)
    );
}

#[test]
fn check_codex_pre_tool_use_relative_empty_or_file_cwd_fails_closed() {
    let env = IsolatedEnv::new();
    // the process starts in HOME, where the relative value names a real directory.
    std::fs::create_dir_all(env.home().join("relative/dir")).unwrap();
    let file = env.home().join("file.txt");
    std::fs::write(&file, "").unwrap();
    let patch = "*** Begin Patch\n*** Add File: clean.rs\n+let clean = true;\n*** End Patch\n";
    for cwd in [json!("relative/dir"), json!(""), json!(file)] {
        for (tool, command) in [("Bash", "echo hello"), ("apply_patch", patch)] {
            let payload = serde_json::to_vec(&json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": {"command": command},
                "cwd": cwd,
            }))
            .unwrap();
            let output = run_check_codex_in(&env, &payload, env.home());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{tool} {cwd}: {stderr}");
            assert!(
                stderr.contains(&format!("Codex {tool} scanner setup failed")),
                "{tool} {cwd}: {stderr}"
            );
        }
    }
}

#[test]
fn check_codex_pre_tool_use_vanished_cwd_uses_its_nearest_existing_ancestor() {
    // the layer of the vanished cwd's parent applies, not the layers of the process cwd.
    let env = IsolatedEnv::new();
    let parent = env.home().join("work");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::write(parent.join(".sekretbarilo.toml"), CANARY_RULE).unwrap();
    let process_cwd = env.root().join("elsewhere");
    std::fs::create_dir_all(&process_cwd).unwrap();
    let vanished = parent.join("removed-worktree");
    let canary = generated_canary();

    let bash = run_check_codex_in(
        &env,
        &bash_payload(&format!("echo {canary}"), &vanished),
        &process_cwd,
    );
    let stderr = String::from_utf8_lossy(&bash.stderr);
    assert_eq!(bash.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("rule: fixture-canary"), "{stderr}");

    let patch = apply_patch_payload(
        format!("*** Begin Patch\n*** Add File: notes.txt\n+{canary}\n*** End Patch\n"),
        &vanished,
    );
    let apply = run_check_codex_in(&env, &patch, &process_cwd);
    let stderr = String::from_utf8_lossy(&apply.stderr);
    assert_eq!(apply.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("rule: fixture-canary"), "{stderr}");
}

#[test]
fn check_codex_post_tool_use_structured_response_fails_closed() {
    let env = IsolatedEnv::new();
    let mut payload: Value =
        serde_json::from_slice(&post_tool_use_payload("ignored", env.home())).unwrap();
    payload["tool_response"] = json!({"stdout": "x", "stderr": ""});
    let result = run_check_codex_in(&env, &serde_json::to_vec(&payload).unwrap(), env.home());

    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("tool_response schema mismatch"));
}
