mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::IsolatedEnv;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::scanner::engine::{redact_text, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::compile_rules;
use serde_json::{Value, json};

const API: &str = "generic-api-key";
const SECRET: &str = "generic-secret-assignment";
const TOKEN: &str = "generic-token-assignment";

fn opaque(length: usize, seed: u64, alphabet: &[u8]) -> String {
    let mut state = seed | 1;
    for _ in 0..10_000 {
        let value: String = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                char::from(alphabet[(state % alphabet.len() as u64) as usize])
            })
            .collect();
        let lower = value.to_ascii_lowercase();
        if !lower
            .as_bytes()
            .windows(3)
            .any(|run| run[0] == run[1] && run[1] == run[2])
            && ![
                "test", "fake", "dummy", "your", "example", "sample", "changeme",
            ]
            .iter()
            .any(|word| lower.contains(word))
            && shannon_entropy(value.as_bytes()) >= if alphabet.len() == 16 { 3.3 } else { 4.2 }
        {
            return value;
        }
    }
    panic!("could not generate opaque value");
}

fn alnum(seed: u64) -> String {
    opaque(
        32,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}

fn hex(length: usize, seed: u64) -> String {
    opaque(length, seed, b"0123456789abcdef")
}

fn assert_detected(text: &str, value: &str, rule: &str) {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    let start = text.find(value).unwrap();
    let range = start..start + value.len();
    assert!(
        scan_text(text, &scanner, &allowlist)
            .iter()
            .any(|finding| finding.rule_id == rule && finding.range == range),
        "{rule} missed value in {text:?}"
    );
    assert_eq!(
        redact_text(text, &scanner, &allowlist),
        text.replace(value, "[REDACTED]")
    );
}

fn assert_clear(text: &str) {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    assert!(scan_text(text, &scanner, &allowlist).is_empty(), "{text:?}");
    assert_eq!(redact_text(text, &scanner, &allowlist), text);
}

fn assert_bash_redaction(env: &IsolatedEnv, text: &str, expected: &str) {
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let response = json!({"stdout": text, "stderr": "", "interrupted": false, "returnCode": 0});
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "cwd": workspace,
        "tool_response": response,
        "tool_input": {"command": "printf output"}
    });
    let mut command: Command = env.command();
    let mut child = command
        .args(["redact-claude", "--stdin-json"])
        .current_dir(env.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&payload).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    if text == expected {
        assert!(output.stdout.is_empty(), "{text:?}");
    } else {
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            envelope["hookSpecificOutput"]["updatedToolOutput"]["stdout"], expected,
            "{text:?}"
        );
    }
}

#[test]
fn quoted_json_and_dict_keys_find_entire_values() {
    let value = alnum(101);
    for (key, rule) in [
        ("api_key", API),
        ("apiKey", API),
        ("secret", SECRET),
        ("client_secret", SECRET),
        ("token", TOKEN),
        ("access_token", TOKEN),
    ] {
        for separator in [":", ": "] {
            assert_detected(
                &format!("{{\"{key}\"{separator}\"{value}\"}}"),
                &value,
                rule,
            );
        }
        assert_detected(&format!("{{'{key}': '{value}'}}"), &value, rule);
    }
    for placeholder in ["YOUR_API_KEY_HERE", "<token>", "${API_KEY}", "changeme"] {
        assert_clear(&format!("{{\"api_key\": \"{placeholder}\"}}"));
    }
}

#[test]
fn quoted_values_keep_reading_across_line_breaks_around_the_separator() {
    let value = alnum(111);
    for (key, rule) in [("secret", SECRET), ("api_key", API), ("token", TOKEN)] {
        for text in [
            format!("{key}:\n  \"{value}\""),
            format!("\"{key}\":\r\n\t\"{value}\""),
            format!("\"{key}\"\n  = '{value}'"),
        ] {
            assert_detected(&text, &value, rule);
        }
        if key == "token" {
            // a bare token followed by a line break can be a slice index, not an assignment.
            assert_clear(&format!("window[\n token\n :\n \"{value}\"\n]"));
            assert_clear(&format!("token\n  = '{value}'"));
        } else {
            assert_detected(&format!("{key}\n  = '{value}'"), &value, rule);
        }
    }
}

#[test]
fn signature_payload_guards_preserve_prefix_length_and_entropy_boundaries() {
    let openai_payload = alnum(511);
    let openai = format!("sk-proj-{openai_payload}");
    assert_detected(&openai, &openai, "openai-api-key");
    assert_clear(&format!("sk-proj-{}", &openai_payload[..19]));
    assert_clear(&format!("sk-proj-{}", "A".repeat(32)));

    let facebook_payload = alnum(512);
    let facebook = format!("EAA{facebook_payload}");
    assert_detected(&facebook, &facebook, "facebook-access-token");
    assert_clear(&format!("EAA{}", &facebook_payload[..19]));
    assert_clear(&format!("EAA{}", hex(32, 513)));
}

#[test]
fn named_hex_keys_accept_bounded_lengths_and_preserve_digest_exemptions() {
    for (index, length) in [32, 36, 40, 48, 56, 64, 128].into_iter().enumerate() {
        let value = hex(length, 201 + index as u64);
        for (prefix, rule) in [
            ("API_KEY=", API),
            ("VAST_AI_API_KEY=", API),
            ("API_TOKEN=", API),
        ] {
            assert_detected(&format!("{prefix}{value}"), &value, rule);
        }
        assert_detected(&format!("\"api_key\":\"{value}\""), &value, API);
        assert_detected(&format!("API_KEY=0x{value}"), &format!("0x{value}"), API);
    }
    let outside = hex(129, 320);
    assert_clear(&format!("API_KEY={outside}"));
    let digest = hex(64, 321);
    assert_clear(&format!("sha256={digest}"));
    assert_clear(&format!("CHECKSUM_API_KEY={digest}"));
    assert_clear(&format!("CHECKSUM_API_KEY=0x{digest}"));
    let earlier = hex(64, 322);
    assert_detected(
        &format!("CHECKSUM={earlier} API_KEY={digest}"),
        &digest,
        API,
    );
}

#[test]
fn assignment_boundaries_and_reference_names() {
    let value = alnum(401);
    for (text, rule) in [
        (format!("A=1\0API_KEY={value}\0B=2"), API),
        (format!("\"API_KEY={value}\""), API),
        (format!("--set a=1,API_TOKEN={value}"), API),
        (format!("API_KEY:={value}"), API),
        (format!("ENV API_KEY {value}"), API),
        (format!("ENV TOKEN {value}"), TOKEN),
        (format!("SECRET_KEY_BASE={value}"), SECRET),
    ] {
        assert_detected(&text, &value, rule);
    }
    assert_clear(&format!("--token={value}"));
    assert_clear("api_key=get_key()");
    let reference_name = ["fjord", "vexing", "campers"].join("-");
    for key in [
        "existingSecret",
        "existingClientSecret",
        "dbSecretName",
        "dbSecretRef",
        "secretKeyRef",
    ] {
        assert_clear(&format!("{key}: {reference_name}"));
    }
    assert_detected(&format!("existingSecret: {value}"), &value, SECRET);
    assert_detected(
        &format!("secret: {reference_name}"),
        &reference_name,
        SECRET,
    );
    assert_detected(
        &format!("client_secret: {reference_name}"),
        &reference_name,
        SECRET,
    );
}

#[test]
fn bash_redact_covers_json_hex_overlap_and_nul_dump() {
    let env = IsolatedEnv::new();
    let value = alnum(501);
    let json_pair = format!("{{\"api_key\":\"{value}\"}}");
    assert_bash_redaction(&env, &json_pair, &json_pair.replace(&value, "[REDACTED]"));

    let hex48 = hex(48, 502);
    let akia = format!("AKIA{}", hex(16, 503).to_ascii_uppercase());
    let line = format!("api_key=\"{hex48}\" {akia}");
    let expected = line
        .replace(&hex48, "[REDACTED]")
        .replace(&akia, "[REDACTED]");
    assert_bash_redaction(&env, &line, &expected);

    let nul_dump = format!("USER=service\0API_KEY={value}\0HOME=/work");
    assert_bash_redaction(&env, &nul_dump, &nul_dump.replace(&value, "[REDACTED]"));
}

#[test]
fn redact_argv_masks_named_environment_values() {
    let env = IsolatedEnv::new();
    let client = hex(32, 601);
    let client_id = format!(
        "{}-{}-{}-{}-{}",
        &client[..8],
        &client[8..12],
        &client[12..16],
        &client[16..20],
        &client[20..]
    );
    let entries = [
        ("INFISICAL_CLIENT_ID", client_id),
        ("VAST_AI_API_KEY", hex(64, 602)),
        ("ZEROENTROPY_API_KEY", alnum(603)),
        ("PUSHOVER_APP_TOKEN", alnum(604)),
    ];
    let binary = std::env::var_os("SEKRETBARILO_PROBE_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_sekretbarilo").into());
    let mut misses = Vec::new();
    for (name, value) in entries {
        for surface in ["pgrep -fl", "ps -o command"] {
            let text = format!("4321 /usr/bin/env {name}={value} jekyll serve\n");
            let payload = json!({
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "cwd": env.home(),
                "tool_response": {"stdout": text, "stderr": "", "interrupted": false, "returnCode": 0},
                "tool_input": {"command": surface}
            });
            let mut child = Command::new(&binary)
                .args(["redact-claude", "--stdin-json"])
                .current_dir(env.home())
                .env("HOME", env.home())
                .env("CODEX_HOME", env.codex_home())
                .env("GIT_CONFIG_GLOBAL", env.git_config_global())
                .env("XDG_CONFIG_HOME", env.home().join(".config"))
                .env_remove("CLAUDE_CONFIG_DIR")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&payload).unwrap())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(0), "{name} on {surface}");
            assert!(output.stderr.is_empty(), "{name} on {surface}");
            let redacted = if output.stdout.is_empty() {
                text.clone()
            } else {
                let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
                envelope["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            if redacted != text.replace(&value, "[REDACTED]") {
                misses.push(format!("{name} on {surface}"));
            }
        }
    }
    assert!(misses.is_empty(), "not fully redacted: {misses:?}");
}
