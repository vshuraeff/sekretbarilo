mod common;

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};

use common::IsolatedEnv;
use serde_json::{Value, json};

const SECRET: &str = "AKIAIOSFODNN7REALKEY";
const SECOND: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const MAX_BYTES: usize = 10 * 1024 * 1024;

fn synthetic_hex(length: usize, seed: u64) -> String {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            char::from_digit((state >> 60) as u32, 16).unwrap()
        })
        .collect()
}

fn check_bash_redaction(env: &IsolatedEnv, text: &str, expected: &str) {
    let mut response =
        json!({"stdout": text, "stderr": "notice", "interrupted": false, "returnCode": 0});
    let output = run(env, "Bash", response.clone());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    if text == expected {
        assert!(
            output.stdout.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    } else {
        let envelope: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{text:?}: {error}"));
        assert!(
            envelope.get("continue").is_none(),
            "unexpected fail-closed envelope"
        );
        assert!(envelope.get("stopReason").is_none());
        response["stdout"] = json!(expected);
        assert_eq!(replacement(&output), response);
    }
}

#[test]
fn digest_records_preserve_bash_output() {
    let env = IsolatedEnv::with_heuristic();
    for eol in ["\n", "\r\n"] {
        for (label, algorithm) in [
            ("Digest:    ", "sha256:"),
            ("Digest: ", "sha-256="),
            ("digest: ", "sha256:"),
            ("X-Checksum-Sha256: ", "sha-256="),
        ] {
            let digest = format!("{algorithm}{}", synthetic_hex(64, 3));
            let clean = format!("before {label}{digest} after{eol}");
            check_bash_redaction(&env, &clean, &clean);
            for gap in [" ", eol] {
                for line in [
                    format!("{label}{digest}{gap}{SECOND} tail{eol}"),
                    format!("{SECOND}{gap}{label}{digest} tail{eol}"),
                ] {
                    check_bash_redaction(&env, &line, &line.replace(SECOND, "[REDACTED]"));
                }
            }
        }
    }
}

#[test]
fn digest_records_keep_malformed_and_credential_values_redacted() {
    let env = IsolatedEnv::with_heuristic();
    let opaque: String = (b'A'..=b'Z').chain(b'a'..=b'f').map(char::from).collect();
    for eol in ["\n", "\r\n"] {
        let balanced: String = (0..32)
            .map(|index| char::from_digit(index % 16, 16).unwrap())
            .collect();
        for value in [format!("sha256:{}", synthetic_hex(64, 3)), balanced] {
            let line = format!("CHECKSUM={value}{eol}");
            check_bash_redaction(&env, &line, &line.replace(&value, "[REDACTED]"));
        }
        for value in [
            format!("sha256:{}0", synthetic_hex(64, 3)),
            format!("sha256:{}Z", synthetic_hex(63, 3)),
            format!("sha999:{}", synthetic_hex(64, 3)),
            format!("sha-256={}suffix", synthetic_hex(64, 3)),
        ] {
            let line = format!("Digest: {value} tail{eol}");
            check_bash_redaction(&env, &line, &line.replace(&value, "[REDACTED]"));
        }
        for (key, value) in [
            ("API_KEY", synthetic_hex(40, 7)),
            ("token", synthetic_hex(64, 7)),
            ("secret", opaque.clone()),
            ("password", opaque.clone()),
        ] {
            let line = format!("{key}={value}{eol}");
            check_bash_redaction(&env, &line, &line.replace(&value, "[REDACTED]"));
        }
        for value in [
            opaque.clone(),
            format!("/work/{opaque}/diagnostic.log"),
            format!("./{opaque}.md"),
            format!("{opaque}.invalid"),
        ] {
            let line = format!("{value}{eol}");
            check_bash_redaction(&env, &line, &format!("[REDACTED]{eol}"));
        }
        let line = format!("https://user:{opaque}@service.invalid/path{eol}");
        let output = run(
            &env,
            "Bash",
            json!({"stdout": line, "stderr": "notice", "interrupted": false, "returnCode": 0}),
        );
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(envelope.get("continue").is_none());
        assert!(
            !replacement(&output)["stdout"]
                .as_str()
                .unwrap()
                .contains(&opaque)
        );
    }
}

fn run_bytes(env: &IsolatedEnv, bytes: &[u8]) -> Output {
    run_command(env.command(), env, bytes)
}

fn run_command(mut command: Command, env: &IsolatedEnv, bytes: &[u8]) -> Output {
    let mut child = command
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

#[test]
fn mktemp_output_record_preserves_bash_whitespace_and_nearby_secrets() {
    let env = IsolatedEnv::with_heuristic();
    let two_id_path = "task/q8Vn3sY6Kp4Zr9Tw/a7B2q9/lead";
    let long_id = format!("{}{}", "q8Vn3sY6Kp4Zr9Tw", "a7B2q9");
    let long_id_path = format!("task/{long_id}/integrator/lead");
    for eol in ["\n", "\r\n"] {
        let clean = format!(" \t./hitlr-request.a7B2q9\t {eol}");
        check_bash_redaction(&env, &clean, &clean);
        let text = format!("before{eol}{clean}{SECOND}{eol}after{eol}");
        check_bash_redaction(&env, &text, &text.replace(SECOND, "[REDACTED]"));
        let text = format!("task/q8Vn3sY6Kp4Zr9Tw/integrator/lead{eol}");
        check_bash_redaction(&env, &text, &text);
        for value in [
            two_id_path,
            long_id_path.as_str(),
            "background-execution.md",
            "./hitlr-request.a7B2q9Z",
        ] {
            let text = format!("{value}{eol}");
            check_bash_redaction(&env, &text, &format!("[REDACTED]{eol}"));
        }
        for text in [
            "secret=./hitlr-request.a7B2q9",
            "note: ./hitlr-request.a7B2q9",
        ] {
            let text = format!("{text}{eol}");
            check_bash_redaction(
                &env,
                &text,
                &text.replace("./hitlr-request.a7B2q9", "[REDACTED]"),
            );
        }
        let text = format!("Workspace: /Users/name/work/.worktrees/repo/unit-1{eol}");
        check_bash_redaction(&env, &text, &text);
    }
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

#[test]
fn shell_directory_expression_preserves_bash_quotes_and_neighbours() {
    let env = IsolatedEnv::with_heuristic();
    let expression = "$STATE_DIR/diagnostic.log";
    for eol in ["\n", "\r\n"] {
        let clean = format!(" \t\"{expression}\"\t {eol}");
        check_bash_redaction(&env, &clean, &clean);
        for gap in [" ", eol] {
            let text = format!("\"{expression}\"{gap}{SECOND}{eol}");
            check_bash_redaction(&env, &text, &text.replace(SECOND, "[REDACTED]"));
        }
    }
}

#[test]
fn shell_directory_expression_keeps_bash_secrets_redacted() {
    let env = IsolatedEnv::with_heuristic();
    let opaque: String = (b'A'..=b'Z').chain(b'a'..=b'f').map(char::from).collect();
    for eol in ["\n", "\r\n"] {
        for value in [
            format!("$STATE_DIR/{opaque}"),
            format!("$STATE_DIR/{opaque}.log"),
            format!("$STATE_DIR/{opaque}/diagnostic.log"),
            format!("${opaque}/diagnostic.log"),
            format!("${{STATE_DIR:-{opaque}}}/diagnostic.log"),
        ] {
            let text = format!("\"{value}\"{eol}");
            check_bash_redaction(&env, &text, &text.replace(&value, "[REDACTED]"));
        }
        let value = "$STATE_DIR/diagnostic.log";
        // the path step judges a reference path by its value alone, so a quoted wordy reference
        // path passes through like the standalone one; the opaque controls stay redacted, and a
        // `secret` or `password` key keeps the value redacted by its tier-2 assignment rule.
        let text = format!("'{value}'{eol}");
        check_bash_redaction(&env, &text, &text);
        for text in [
            format!("secret=\"{value}\""),
            format!("password=\"{value}\""),
        ] {
            let text = format!("{text}{eol}");
            check_bash_redaction(&env, &text, &text.replace(value, "[REDACTED]"));
        }
        let text = format!("hashlib.sha256(x.encode(){eol}");
        // an open call at the line end is source syntax and passes through unchanged
        check_bash_redaction(&env, &text, &text);
    }
}

#[test]
fn shell_directory_separator_attacks_are_redacted_in_bash() {
    let env = IsolatedEnv::with_heuristic();
    let left = "q8Vn3sY6Kp4Zr9Tw";
    let right = "u2Jc5Hm7Rx1Bd6Q";
    let lowercase: String = (0..32)
        .map(|index| char::from(b'a' + ((index * 11 + 3) % 26) as u8))
        .collect();
    for eol in ["\n", "\r\n"] {
        for separator in ["_", "-", ".", "/"] {
            for path in [
                format!("{left}{separator}{right}/diagnostic.log"),
                format!("{left}{separator}{right}.log"),
                format!("diagnostic-{left}{separator}{right}.log"),
                format!(
                    "{}{separator}{}/diagnostic.log",
                    &lowercase[..16],
                    &lowercase[16..]
                ),
            ] {
                let value = format!("$STATE_DIR/{path}");
                let text = format!(" \t\"{value}\"\t {eol}");
                check_bash_redaction(&env, &text, &text.replace(&value, "[REDACTED]"));
            }
        }
        for path in [
            "diagnostic.log",
            "logs/diagnostic.log",
            "2026/diagnostic.log",
            "v-2/diagnostic.log",
        ] {
            let text = format!("\"$STATE_DIR/{path}\"{eol}");
            check_bash_redaction(&env, &text, &text);
        }
    }
}

#[test]
fn mktemp_separator_attacks_are_redacted_in_bash() {
    let env = IsolatedEnv::with_heuristic();
    let opaque: String = (0..32)
        .map(|index| char::from(b'a' + ((index * 11 + 3) % 26) as u8))
        .collect();
    for eol in ["\n", "\r\n"] {
        for value in [
            format!("./{}-{}.a7B2q9", &opaque[..16], &opaque[16..]),
            format!(
                "./{}-{}-{}.a7B2q9",
                &opaque[..11],
                &opaque[11..22],
                &opaque[22..]
            ),
            format!("./{}-{}.{}", &opaque[..7], &opaque[7..14], &opaque[14..20]),
            "./hitlr-download.a7B2q9".to_owned(),
        ] {
            let text = format!(" \t{value}\t {eol}");
            check_bash_redaction(&env, &text, &text.replace(&value, "[REDACTED]"));
        }
    }
}

#[test]
fn digest_records_reject_separator_split_payloads_in_bash() {
    let env = IsolatedEnv::with_heuristic();
    for eol in ["\n", "\r\n"] {
        for separator in ["-", "_"] {
            let digest = synthetic_hex(64, 3);
            let inserted = format!("{}{separator}{}", &digest[..32], &digest[32..]);
            let mut replaced = digest;
            replaced.replace_range(31..32, separator);
            for payload in [inserted, replaced] {
                let value = format!("sha256:{payload}");
                let text = format!("before Digest: {value} after{eol}");
                check_bash_redaction(&env, &text, &text.replace(&value, "[REDACTED]"));
            }
        }
    }
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
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
    let env = IsolatedEnv::with_heuristic();
    // the guarded behaviour is the child seeing EPIPE on a reader this process has closed. a
    // sibling test spawning at the same moment can inherit that read end through the window
    // between pipe() and its close-on-exec mark, which keeps the pipe writable for as long as
    // that unrelated process lives and lets the child exit 0. such an attempt measures the
    // leak rather than the binary, so it is retried instead of asserted. a read-only or
    // /dev/null descriptor is no alternative: std's stdout handle maps EBADF to a successful
    // write of the whole buffer, so only EPIPE ever reaches the guard.
    let mut code = None;
    for _ in 0..10 {
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
        code = child.wait().unwrap().code();
        if code == Some(1) {
            break;
        }
    }
    assert_eq!(code, Some(1));
}

#[test]
fn vanished_cwd_uses_its_nearest_existing_ancestor() {
    // `git worktree remove` run inside the worktree reports the removed directory as cwd.
    let env = IsolatedEnv::with_heuristic();
    let cwd = env.root().join("worktrees/repo/unit-1");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::remove_dir(&cwd).unwrap();
    let listing = format!(
        "/work/.worktrees/repo/unit-1  {} [task/unit-1]\n",
        synthetic_hex(40, 11)
    );
    let payload = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": cwd,
        "tool_response": {"stdout": format!("{listing}{SECRET}\n"), "stderr": "", "interrupted": false}});
    let output = run_bytes(&env, &serde_json::to_vec(&payload).unwrap());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        envelope.get("continue").is_none(),
        "unexpected fail-closed envelope"
    );
    assert_eq!(
        replacement(&output)["stdout"],
        format!("{listing}[REDACTED]\n")
    );
}

#[test]
fn relative_empty_non_string_and_non_directory_cwd_still_stop() {
    let env = IsolatedEnv::with_heuristic();
    // run_bytes starts the binary in HOME, where the relative value names a real directory.
    std::fs::create_dir_all(env.home().join("workspace")).unwrap();
    let file = env.home().join("workspace/file.txt");
    std::fs::write(&file, "").unwrap();
    for cwd in [
        json!("workspace"),
        json!(""),
        json!(17),
        json!(file),
        json!(file.join("gone")),
    ] {
        let payload = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": cwd,
            "tool_response": {"stdout": "clean\n", "stderr": "", "interrupted": false}});
        let output = run_bytes(&env, &serde_json::to_vec(&payload).unwrap());
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["continue"], false, "{cwd}");
        assert_eq!(replacement(&output)["stdout"], "[REDACTED]\n", "{cwd}");
    }
}

/// a rule no built-in matches, so only the layer carrying it can mask the payload below.
const CUSTOM_RULE: &str = "[[rules]]\nid='custom'\ndescription='synthetic custom value'\nregex='CUSTOM=([A-Z0-9]+)'\nkeywords=['CUSTOM']\nsecret_group=1\n";
const ALLOW_CUSTOM: &str = "[[allowlist.rules]]\nid='custom'\nregexes=['^Z9X4T2P7V8Q3$']\n";

fn custom_value_payload(cwd: &std::path::Path) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": cwd,
        "tool_response": {"stdout": "CUSTOM=Z9X4T2P7V8Q3", "stderr": "", "interrupted": false}}),
    )
    .unwrap()
}

/// masked by the custom rule itself, not by a fail-closed stop that erases everything.
fn assert_custom_value_masked(output: &Output) {
    assert!(
        !output.stdout.is_empty(),
        "the custom rule's layer was dropped"
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        envelope.get("continue").is_none(),
        "unexpected fail-closed envelope"
    );
    assert_eq!(replacement(output)["stdout"], "CUSTOM=[REDACTED]");
}

#[test]
fn home_as_cwd_keeps_the_user_layer() {
    // outside git the workspace boundary is the cwd, which then covers the XDG layer.
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let output = run_bytes(&env, &custom_value_payload(env.home()));
    assert_custom_value_masked(&output);
    assert!(output.stderr.is_empty());
}

#[test]
fn user_layer_under_a_non_git_cwd_is_kept() {
    // the cwd holds HOME and with it XDG_CONFIG_HOME, as for a probe whose isolated config
    // sits under the non-git $TMPDIR it reads from.
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let output = run_bytes(&env, &custom_value_payload(env.root()));
    assert_custom_value_masked(&output);
    assert!(output.stderr.is_empty());
}

#[test]
fn symlinked_user_layer_is_kept_with_home_as_cwd() {
    let env = IsolatedEnv::new();
    let dotfiles = env.home().join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let target = dotfiles.join("sekretbarilo.toml");
    std::fs::write(&target, CUSTOM_RULE).unwrap();
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&target, dir.join("sekretbarilo.toml")).unwrap();
    let output = run_bytes(&env, &custom_value_payload(env.home()));
    assert_custom_value_masked(&output);
    assert!(output.stderr.is_empty());
}

#[test]
fn cwd_through_a_symlinked_workspace_directory_ignores_its_target_layer() {
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let repo = env.git_repo();
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join(".sekretbarilo.toml"), ALLOW_CUSTOM).unwrap();
    let linked = repo.join("linked");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    let output = run_bytes(&env, &custom_value_payload(&linked));
    assert_custom_value_masked(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("ignoring untrusted"));
}

#[test]
fn workspace_config_symlink_is_not_trusted_even_when_committed() {
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let repo = env.git_repo();
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let target = outside.join("allow.toml");
    std::fs::write(&target, ALLOW_CUSTOM).unwrap();
    std::os::unix::fs::symlink(&target, repo.join(".sekretbarilo.toml")).unwrap();
    let payload = custom_value_payload(&repo);

    let untracked = run_bytes(&env, &payload);
    assert_custom_value_masked(&untracked);
    assert!(String::from_utf8_lossy(&untracked.stderr).contains("ignoring untrusted"));

    for args in [
        vec!["add", ".sekretbarilo.toml"],
        vec![
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-m",
            "fixture symlink",
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
    let committed = run_bytes(&env, &payload);
    assert_custom_value_masked(&committed);
    assert!(String::from_utf8_lossy(&committed.stderr).contains("ignoring untrusted"));

    // control: the same allowlist in a trusted layer lets the value through.
    std::fs::remove_file(repo.join(".sekretbarilo.toml")).unwrap();
    env.write_user_config(&format!("{CUSTOM_RULE}{ALLOW_CUSTOM}"));
    assert!(run_bytes(&env, &payload).stdout.is_empty());
}

#[test]
fn cwd_through_a_link_into_a_nested_repository_judges_the_holder_layer() {
    // the target nests in the repository holding the link, so the holder's layer lies outside
    // the target; the agent works in the holder, which has not committed it. both sit under
    // HOME, where discovery from the link walks up to the holder.
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let holder = env.home().join("work");
    let nested = holder.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let git = |repo: &std::path::Path, args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", env.git_config_global())
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}");
    };
    for repo in [&holder, &nested] {
        git(repo, &["init", "-q"]);
        git(repo, &["config", "user.email", "test@test.invalid"]);
        git(repo, &["config", "user.name", "Test"]);
    }
    std::fs::write(holder.join(".sekretbarilo.toml"), ALLOW_CUSTOM).unwrap();
    let linked = holder.join("linked");
    std::os::unix::fs::symlink(&nested, &linked).unwrap();
    let payload = custom_value_payload(&linked);

    let uncommitted = run_bytes(&env, &payload);
    assert_custom_value_masked(&uncommitted);
    assert!(String::from_utf8_lossy(&uncommitted.stderr).contains("ignoring untrusted"));

    // control: committed unmodified in the holder, the allowlist lets the value through.
    git(&holder, &["add", ".sekretbarilo.toml"]);
    git(
        &holder,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    let committed = run_bytes(&env, &payload);
    assert!(
        committed.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
}

#[test]
fn vanished_cwd_keeps_the_user_layer_of_a_non_git_home() {
    // the nearest existing ancestor is HOME, which holds the XDG layer.
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let output = run_bytes(&env, &custom_value_payload(&env.home().join("gone")));
    assert_custom_value_masked(&output);
}

#[test]
fn vanished_cwd_keeps_the_layer_of_a_non_git_parent() {
    let env = IsolatedEnv::new();
    let parent = env.home().join("work");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::write(parent.join(".sekretbarilo.toml"), CUSTOM_RULE).unwrap();
    let output = run_bytes(&env, &custom_value_payload(&parent.join("repo-gone")));
    assert_custom_value_masked(&output);
}

#[test]
fn vanished_cwd_stops_on_an_uncommitted_layer_of_the_ancestor_repository() {
    // a removed nested checkout would have trusted this layer and a removed plain subdirectory
    // would not, so neither reading is safe.
    let env = IsolatedEnv::new();
    let repo = env.home().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let init = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .status()
        .unwrap();
    assert!(init.success());
    std::fs::write(repo.join(".sekretbarilo.toml"), CUSTOM_RULE).unwrap();
    let output = run_bytes(&env, &custom_value_payload(&repo.join(".worktrees/gone")));
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["continue"], false);
    assert_eq!(replacement(&output)["stdout"], "[REDACTED]");
}

#[test]
fn vanished_cwd_outside_home_never_reads_its_ancestor_layer() {
    // outside HOME discovery reads only the start directory's own layer, so the vanished path
    // never read the allowlist its ancestor holds.
    let env = IsolatedEnv::new();
    env.write_user_config(CUSTOM_RULE);
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join(".sekretbarilo.toml"), ALLOW_CUSTOM).unwrap();
    let payload = custom_value_payload(&outside.join("gone"));
    assert_custom_value_masked(&run_bytes(&env, &payload));
    // control: the same allowlist in a trusted layer lets the value through.
    env.write_user_config(&format!("{CUSTOM_RULE}{ALLOW_CUSTOM}"));
    assert!(run_bytes(&env, &payload).stdout.is_empty());
}

fn clean_payload(cwd: &std::path::Path) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": cwd,
        "tool_response": {"stdout": "clean\n", "stderr": "", "interrupted": false}}),
    )
    .unwrap()
}

fn assert_stopped(output: &Output, cwd: &std::path::Path) {
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["continue"], false, "{}", cwd.display());
    assert_eq!(
        replacement(output)["stdout"],
        "[REDACTED]\n",
        "{}",
        cwd.display()
    );
}

#[test]
fn vanished_cwd_without_home_stops() {
    // the loader's fallback home would be the ancestor, whose layers the vanished path never read.
    let env = IsolatedEnv::new();
    let parent = env.root().join("w");
    std::fs::create_dir_all(&parent).unwrap();
    let without_home = || {
        let mut command = env.command();
        command.env_remove("HOME");
        command
    };
    let cwd = parent.join("gone");
    assert_stopped(
        &run_command(without_home(), &env, &clean_payload(&cwd)),
        &cwd,
    );
    // control: without HOME an existing cwd still passes clean output through.
    let output = run_command(without_home(), &env, &clean_payload(&parent));
    assert!(
        output.stdout.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn vanished_cwd_spelled_with_dot_segments_stops() {
    // the walk is lexical: from `gone/..` it lands on `proj`, whose layer the boundary would
    // then judge to lie outside the workspace.
    let env = IsolatedEnv::new();
    let proj = env.home().join("proj");
    std::fs::create_dir_all(proj.join("sub")).unwrap();
    for cwd in [
        proj.join("gone/.."),
        proj.join("gone/."),
        proj.join("./gone"),
    ] {
        assert_stopped(&run_bytes(&env, &clean_payload(&cwd)), &cwd);
    }
    // control: an existing cwd spelled with `..` is used as it is.
    let output = run_bytes(&env, &clean_payload(&proj.join("sub/..")));
    assert!(
        output.stdout.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn vanished_cwd_through_a_dangling_symlink_stops() {
    // walking past `alias` would land on HOME and never read the layers above its target.
    let env = IsolatedEnv::new();
    let alias = env.home().join("alias");
    std::os::unix::fs::symlink(env.home().join("work/gone"), &alias).unwrap();
    for cwd in [alias.clone(), alias.join("sub")] {
        assert_stopped(&run_bytes(&env, &clean_payload(&cwd)), &cwd);
    }
}
