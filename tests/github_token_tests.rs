mod common;

use common::IsolatedEnv;
use serde_json::json;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

fn generated_flat_token(prefix: &str) -> String {
    let body: String = (0..36)
        .map(|index| b"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7"[index % 27] as char)
        .collect();
    format!("{prefix}{body}")
}

fn generated_stateless_token() -> String {
    let header = "eyJ".to_owned() + &"aB3dE6".repeat(5);
    let payload = "eyJ".to_owned() + &"gH9jK2_mN5pQ8-sT1vW4yZ7".repeat(15);
    let signature = "qR6_sT9-uV2".repeat(8);
    format!("ghs_123456_{header}.{payload}.{signature}")
}

fn redact(env: &IsolatedEnv, cwd: &Path, text: &str) -> Output {
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "cwd": cwd,
        "tool_input": {"command": "show-result"},
        "tool_response": {"stdout": text, "stderr": "", "interrupted": false}
    });
    let mut child = env
        .command()
        .args(["redact-claude", "--stdin-json"])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start redaction");
    child
        .stdin
        .take()
        .expect("redaction stdin")
        .write_all(&serde_json::to_vec(&payload).expect("serialize payload"))
        .expect("write payload");
    child.wait_with_output().expect("wait for redaction")
}

fn check_surfaces(value: &str, rule_id: Option<&str>) {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let path = repo.join("result.txt");
    std::fs::write(&path, format!("result: {value}\n")).expect("write input");
    let staged = std::process::Command::new("git")
        .args(["-C"])
        .arg(&repo)
        .args(["add", "result.txt"])
        .output()
        .expect("stage input");
    assert!(staged.status.success(), "stage input failed");

    for args in [
        vec!["scan"],
        vec!["audit"],
        vec!["check-file", path.to_str().expect("utf8 test path")],
    ] {
        let output = env
            .command()
            .args(&args)
            .current_dir(&repo)
            .output()
            .expect("run scanner");
        let report = String::from_utf8_lossy(&output.stderr).to_string()
            + &String::from_utf8_lossy(&output.stdout);
        if let Some(rule_id) = rule_id {
            let expected_exit = if args[0] == "check-file" { 2 } else { 1 };
            assert_eq!(
                output.status.code(),
                Some(expected_exit),
                "{args:?} must detect"
            );
            assert!(report.contains(rule_id), "{args:?} must report rule");
        } else {
            assert!(output.status.success(), "{args:?} must stay clean");
        }
        assert!(!report.contains(value), "scanner must mask input");
    }

    let output = redact(&env, &repo, value);
    assert!(output.status.success(), "redaction must succeed");
    if rule_id.is_some() {
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse redaction response");
        assert!(
            response["hookSpecificOutput"]["updatedToolOutput"]["stdout"].as_str()
                == Some("[REDACTED]"),
            "redact the complete token without retaining a prefix or suffix"
        );
    } else {
        assert!(output.stdout.is_empty(), "clean redaction needs no update");
    }
}

#[test]
fn stateless_installation_token_is_detected_and_fully_redacted() {
    check_surfaces(&generated_stateless_token(), Some("github-app-token"));
}

#[test]
fn flat_installation_token_remains_detected() {
    check_surfaces(&generated_flat_token("ghs_"), Some("github-app-token"));
}

#[test]
fn user_to_server_token_is_detected_and_fully_redacted() {
    check_surfaces(
        &generated_flat_token("ghu_"),
        Some("github-user-to-server-token"),
    );
}

#[test]
fn github_prefixes_in_prose_and_identifiers_stay_clean() {
    for value in [
        "ghs_",
        "ghu_",
        "ghs_installation_token",
        "ghu_user_token",
        "ghs_12345_documented_token_shape",
        "ghs_12345_header.payload.signature",
        "ghs_12345_short",
    ] {
        check_surfaces(value, None);
    }
}
