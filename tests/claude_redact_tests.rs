mod common;

use std::io::{Read, Write};
use std::process::{Output, Stdio};

use common::IsolatedEnv;
use serde_json::{Value, json};

const SECRET: &str = "AKIAIOSFODNN7REALKEY";
const SECOND: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const MAX_BYTES: usize = 10 * 1024 * 1024;

fn run_bytes(env: &IsolatedEnv, bytes: &[u8]) -> Output {
    let mut child = env
        .command()
        .args(["redact-claude", "--stdin-json"])
        .env("XDG_CONFIG_HOME", env.home().join(".config"))
        .current_dir(env.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let _ = stdin.write_all(bytes);
    drop(stdin);
    let mut output = child.wait_with_output().unwrap();
    output.stdout = reader.join().unwrap();
    output
}

fn run(env: &IsolatedEnv, tool: &str, response: Value) -> Output {
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    run_bytes(
        env,
        &serde_json::to_vec(&json!({
            "hook_event_name": "PostToolUse", "tool_name": tool,
            "cwd": workspace, "tool_response": response,
            "tool_input": {"file_path": "vendor/.env", "command": "cat vendor/.env"}
        }))
        .unwrap(),
    )
}

fn replacement(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECOND));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    value["hookSpecificOutput"]["updatedToolOutput"].clone()
}

#[test]
fn clean_outputs_are_silent_for_all_three_tools() {
    let env = IsolatedEnv::new();
    for (tool, response) in [
        (
            "Bash",
            json!({"stdout": "hello\r\n", "stderr": "", "interrupted": false}),
        ),
        (
            "Read",
            json!({"type": "text", "file": {"content": "host = localhost\n"}}),
        ),
        (
            "Grep",
            json!({"mode": "files_with_matches", "numFiles": 1, "filenames": ["app.rs"]}),
        ),
        (
            "Grep",
            json!({"mode": "count", "numFiles": 1, "filenames": ["app.rs"], "content": "app.rs:3", "numMatches": 3}),
        ),
    ] {
        let output = run(&env, tool, response);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty(), "{tool}: {:?}", output.stdout);
    }
}

#[test]
fn password_quoting_forms_are_masked_in_all_three_tools() {
    let env = IsolatedEnv::new();
    let password = "h9L!q2N#v7T@r4W$";
    let original = format!(
        "host=localhost\r\npassword={password}\r\npassword=\"{password}\"\r\npasswd='{password}'\r\npwd=`{password}`\r\nport=5432\r\n"
    );
    let masked = original.replace(password, "[REDACTED]");
    for (tool, response, expected) in [
        (
            "Bash",
            json!({"stdout": original, "stderr": format!("password={password}"), "interrupted": false}),
            json!({"stdout": masked, "stderr": "password=[REDACTED]", "interrupted": false}),
        ),
        (
            "Read",
            json!({"type": "text", "file": {"content": original, "numLines": 6}}),
            json!({"type": "text", "file": {"content": masked, "numLines": 6}}),
        ),
        (
            "Grep",
            json!({"mode": "content", "content": original, "numLines": 6, "numFiles": 1, "filenames": ["config.txt"]}),
            json!({"mode": "content", "content": masked, "numLines": 6, "numFiles": 1, "filenames": ["config.txt"]}),
        ),
    ] {
        let output = run(&env, tool, response);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(password));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(password));
        assert_eq!(replacement(&output), expected, "{tool}");
    }
}

#[test]
fn bash_streams_and_text_blocks_preserve_structure_and_unknown_metadata() {
    let env = IsolatedEnv::new();
    let response = json!({
        "stdout": format!("привет {SECRET}\r\n{SECRET}\n"),
        "stderr": format!("notice {SECOND}"), "interrupted": false, "isImage": false,
        "backgroundTaskId": "task-a", "returnCode": 0, "future": {"keep": [true, 17]},
        "structuredContent": [{"type": "text", "text": SECRET, "extra": "keep"}, {"type": "image", "data": "untouched"}],
        "content": [{"type": "text", "text": SECOND}]
    });
    let mut expected = response.clone();
    expected["stdout"] = json!("привет [REDACTED]\r\n[REDACTED]\n");
    expected["stderr"] = json!("notice [REDACTED]");
    expected["structuredContent"][0]["text"] = json!("[REDACTED]");
    expected["content"][0]["text"] = json!("[REDACTED]");
    assert_eq!(replacement(&run(&env, "Bash", response)), expected);
}

#[test]
fn text_read_preserves_file_and_metadata_even_for_env_and_vendor_paths() {
    let env = IsolatedEnv::new();
    let path = env.home().join(".env");
    let original = format!("host = localhost\r\naws_key = {SECRET}\r\nport = 5432\r\n");
    std::fs::write(&path, &original).unwrap();
    let mut response = json!({"type": "text", "file": {
        "filePath": path, "content": original, "numLines": 3, "startLine": 1, "totalLines": 3, "future": true
    }, "extra": [1, 2]});
    let output = run(&env, "Read", response.clone());
    response["file"]["content"] = json!(original.replace(SECRET, "[REDACTED]"));
    assert_eq!(replacement(&output), response);
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[test]
fn grep_modes_and_alternate_lines_redact_values_without_changing_counts() {
    let env = IsolatedEnv::new();
    for mode in ["content", "count", "files_with_matches"] {
        let response = json!({"mode": mode, "numFiles": 1, "filenames": [format!("{SECRET}.txt")],
            "content": format!("file:17:{SECOND}\r\n"), "numLines": 1, "numMatches": 3,
            "lines": [SECRET.to_string(), {"line": 17, "text": SECOND, "path": "file"}],
            "matches": [{"line": SECRET, "lineNumber": 8}], "future": "preserved"});
        let updated = replacement(&run(&env, "Grep", response));
        assert_eq!(updated["numMatches"], 3);
        assert_eq!(updated["numLines"], 1);
        assert_eq!(updated["filenames"][0], "[REDACTED].txt");
        assert_eq!(updated["lines"][1]["line"], 17);
        assert_eq!(updated["lines"][1]["text"], "[REDACTED]");
        assert_eq!(updated["matches"][0]["line"], "[REDACTED]");
        assert_eq!(updated["future"], "preserved");
    }
}

#[test]
fn trusted_custom_rules_and_value_allowlist_apply_but_path_exclusions_do_not() {
    let env = IsolatedEnv::new();
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("sekretbarilo.toml"),
        r#"
[allowlist]
paths = [".*"]
[[rules]]
id = "custom-value"
description = "synthetic value"
regex = 'CUSTOM=([^\s]+)'
keywords = ["CUSTOM="]
secret_group = 1
[rules.allowlist]
regexes = ['^allowed$']
paths = [".*"]
"#,
    )
    .unwrap();
    let result = run(
        &env,
        "Bash",
        json!({"stdout": "CUSTOM=allowed CUSTOM=Z9x4T2p7V8q3", "stderr": "", "interrupted": false}),
    );
    assert_eq!(
        replacement(&result)["stdout"],
        "CUSTOM=allowed CUSTOM=[REDACTED]"
    );
}

#[test]
fn invalid_trusted_config_stops_and_erases_all_supported_text_without_diagnostics() {
    let env = IsolatedEnv::new();
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    for invalid in [
        format!("invalid = {SECRET}"),
        "[[rules]]\nid='bad'\ndescription='invalid regex'\nsecret_group=0\nregex='['\nkeywords=['bad']".to_string(),
        "[[allowlist.rules]]\nid='aws-access-key-id'\nkeys=['TMPDIR']".to_string(),
    ] {
        std::fs::write(dir.join("sekretbarilo.toml"), invalid).unwrap();
        let output = run(
            &env,
            "Bash",
            json!({"stdout": format!("innocent\r\n{SECRET}"), "stderr": "notice", "interrupted": false}),
        );
        let updated = replacement(&output);
        assert_eq!(updated["stdout"], "[REDACTED]\r\n");
        assert_eq!(updated["stderr"], "[REDACTED]");
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["continue"], false);
    }
}

#[test]
fn workspace_config_requires_committed_and_unmodified_provenance() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let config = repo.join(".sekretbarilo.toml");
    let content = "[[rules]]\nid='custom'\ndescription='synthetic custom value'\nregex='CUSTOM=([A-Z0-9]+)'\nkeywords=['CUSTOM']\nsecret_group=1\n";
    std::fs::write(&config, content).unwrap();
    let payload = json!({"hook_event_name":"PostToolUse", "tool_name":"Bash", "cwd":repo,
        "tool_response":{"stdout":"CUSTOM=Z9X4T2P7V8Q3", "stderr":"", "interrupted":false}});
    let bytes = serde_json::to_vec(&payload).unwrap();
    let untracked = run_bytes(&env, &bytes);
    assert!(untracked.stdout.is_empty());
    assert!(String::from_utf8_lossy(&untracked.stderr).contains("ignoring untrusted"));
    for args in [
        vec!["add", ".sekretbarilo.toml"],
        vec![
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-m",
            "trusted fixture",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_GLOBAL", env.git_config_global())
            .output()
            .unwrap();
        assert!(output.status.success());
    }
    assert_eq!(
        replacement(&run_bytes(&env, &bytes))["stdout"],
        "CUSTOM=[REDACTED]"
    );
    std::fs::write(config, format!("{content}\n# changed\n")).unwrap();
    assert!(run_bytes(&env, &bytes).stdout.is_empty());
}

#[test]
fn malformed_input_and_schema_drift_stop_with_fixed_safe_reason() {
    let env = IsolatedEnv::new();
    for bytes in [
        format!("not-json {SECRET}").into_bytes(),
        vec![0xff],
        b"{}".to_vec(),
    ] {
        let output = run_bytes(&env, &bytes);
        assert_eq!(output.status.code(), Some(0));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["continue"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    }
    let output = run(&env, "Bash", json!({"stdout": SECRET, "stderr": SECOND}));
    let updated = replacement(&output);
    assert_eq!(updated["stdout"], "[REDACTED]");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["continue"],
        false
    );
}

#[test]
fn oversized_input_and_serialized_replacement_stop_with_bounded_output() {
    let env = IsolatedEnv::new();
    let output = run_bytes(&env, &vec![b' '; MAX_BYTES + 1]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["continue"],
        false
    );
    // near-limit input with a short custom secret expands beyond the output cap.
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("sekretbarilo.toml"),
        "[[rules]]\nid='short'\ndescription='synthetic short value'\nsecret_group=0\nregex='Q7'\nkeywords=['Q7']",
    )
    .unwrap();
    let preflight = run(
        &env,
        "Bash",
        json!({"stdout":"Q7", "stderr":"", "interrupted":false}),
    );
    let value: Value = serde_json::from_slice(&preflight.stdout).unwrap();
    assert!(
        value.get("continue").is_none(),
        "custom rule must compile before the limit test"
    );
    assert_eq!(
        value["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[REDACTED]"
    );
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut payload = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
        "tool_response": {"stdout": "Q7 ".repeat(1000), "stderr": "", "interrupted": false, "padding": ""}});
    let initial = serde_json::to_vec(&payload).unwrap().len();
    payload["tool_response"]["padding"] = json!("p".repeat(MAX_BYTES - initial));
    let bytes = serde_json::to_vec(&payload).unwrap();
    assert_eq!(bytes.len(), MAX_BYTES);
    let output = run_bytes(&env, &bytes);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.len() <= MAX_BYTES);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Q7"));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["continue"], false);
    assert_eq!(
        value["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[REDACTED]"
    );
}

#[test]
fn drifted_text_containers_are_erased_on_failure() {
    let env = IsolatedEnv::new();
    for (tool, response) in [
        (
            "Bash",
            json!({"stdout":[{"unexpected":SECRET}], "stderr":"", "interrupted":false}),
        ),
        (
            "Bash",
            json!({"stdout":"", "stderr":"", "interrupted":false, "content":[{"text":SECRET}]}),
        ),
        (
            "Bash",
            json!({"stdout":"", "stderr":"", "interrupted":false, "structuredContent":[{"type":"future_text", "text":SECRET}]}),
        ),
        (
            "Bash",
            json!({"stdout":"", "stderr":"", "interrupted":false, "content":[SECRET]}),
        ),
        ("Read", json!({"type":"text", "file":[SECRET]})),
        (
            "Read",
            json!({"type":"text", "file":{"content":{"future":SECRET}, "filePath":"keep.txt"}}),
        ),
    ] {
        let output = run(&env, tool, response);
        let _ = replacement(&output);
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["continue"],
            false
        );
    }
    let output = run_bytes(
        &env,
        &serde_json::to_vec(&json!({"tool_response":{"stdout":SECRET}})).unwrap(),
    );
    let _ = replacement(&output);
}

#[test]
fn nontext_read_is_outside_scope_and_cli_errors_use_stop_protocol() {
    let env = IsolatedEnv::new();
    for kind in ["image", "pdf", "parts", "notebook", "file_unchanged"] {
        let output = run(
            &env,
            "Read",
            json!({"type": kind, "file": {"base64": "unchanged"}}),
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
    }
    let output = env
        .command()
        .args(["redact-claude", "--unknown", SECRET])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["continue"],
        false
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn closed_stdout_and_stderr_do_not_abort_the_binary() {
    let env = IsolatedEnv::new();
    let mut child = env
        .command()
        .args(["redact-claude", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    drop(child.stderr.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"invalid json")
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(1));
}
