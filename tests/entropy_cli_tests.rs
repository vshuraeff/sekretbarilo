mod common;

use common::bin;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn alphabetic_token(len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    (0..len)
        .map(|index| ALPHABET[index % ALPHABET.len()])
        .collect()
}

fn hex_token(len: usize) -> Vec<u8> {
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len).map(|index| HEX[index % HEX.len()]).collect()
}

fn run_entropy(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo entropy");
    let mut stdin = child.stdin.take().expect("child stdin was not piped");
    stdin
        .write_all(input)
        .expect("failed to write entropy input");
    drop(stdin);
    child
        .wait_with_output()
        .expect("failed to wait for sekretbarilo entropy")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn reports_passing_length_and_entropy_gates_for_mixed_case_token() {
    let output = run_entropy(&["entropy"], &alphabetic_token(32));

    assert_eq!(output.status.code(), Some(0));
    let stderr = stderr(&output);
    assert!(stderr.contains("length_gate: pass"));
    assert!(stderr.contains("entropy_gate: pass"));
}

#[test]
fn reports_failing_length_gate_for_short_value() {
    let output = run_entropy(&["entropy"], &alphabetic_token(12));

    assert_eq!(output.status.code(), Some(0));
    assert!(stderr(&output).contains("length_gate: fail"));
}

#[test]
fn reports_eligible_hex_policy_for_32_hex_value() {
    let output = run_entropy(&["entropy"], &hex_token(32));

    assert_eq!(output.status.code(), Some(0));
    assert!(stderr(&output).contains("hex_policy: eligible"));
}

#[test]
fn trims_one_trailing_newline() {
    let token = alphabetic_token(32);
    let mut with_newline = token.clone();
    with_newline.push(b'\n');

    let without_newline = run_entropy(&["entropy"], &token);
    let with_newline = run_entropy(&["entropy"], &with_newline);

    assert_eq!(without_newline.status.code(), Some(0));
    assert_eq!(with_newline.status.code(), Some(0));
    assert!(stderr(&without_newline).contains("bytes: 32"));
    assert!(stderr(&with_newline).contains("bytes: 32"));
}

#[test]
fn accepts_non_utf8_input() {
    let input = vec![0xff; 32];
    let output = run_entropy(&["entropy"], &input);

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn rejects_empty_input() {
    let output = run_entropy(&["entropy"], b"");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("empty input"));
}

#[test]
fn rejects_positional_argument() {
    let output = run_entropy(&["entropy", "somepositional"], b"");

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn rejects_config_flag() {
    let output = run_entropy(&["entropy", "--config", "x"], b"");

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn does_not_print_raw_input() {
    let token = alphabetic_token(32);
    let output = run_entropy(&["entropy"], &token);
    let raw_token = String::from_utf8(token).expect("alphabetic token must be utf-8");

    assert_eq!(output.status.code(), Some(0));
    assert!(!stderr(&output).contains(&raw_token));
}
