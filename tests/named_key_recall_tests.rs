mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::IsolatedEnv;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::scanner::engine::{redact_text, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules};
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
    let (scanner, allowlist) = &*DEFAULT_SCANNER;
    assert!(scan_text(text, scanner, allowlist).is_empty(), "{text:?}");
    assert_eq!(redact_text(text, scanner, allowlist), text);
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

/// run one agent hook on `payload` from the isolated home and return its exit code.
fn hook_exit(env: &IsolatedEnv, args: &[&str], payload: Option<&Value>) -> Option<i32> {
    let mut child = env
        .command()
        .args(args)
        .current_dir(env.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    if let Some(payload) = payload {
        stdin
            .write_all(&serde_json::to_vec(payload).unwrap())
            .unwrap();
    }
    drop(stdin);
    child.wait_with_output().unwrap().status.code()
}

/// a `"token="` string literal closes on the quote the quoted alternative would open the value
/// with, and the call's argument tail after it is code. the whole-text pass of the agent hooks
/// used to read that tail across the line break up to the next line's quote, which the per-line
/// diff surface of check-file never sees.
#[test]
fn a_named_string_literal_before_an_argument_tail_is_no_value() {
    let value = alnum(701);
    for key in ["token", "api_key", "secret"] {
        for text in [
            format!(
                "    XCTAssertFalse(output.contains(\"{key}=\"), file: file, line: line)\n    XCTAssertTrue(output.contains(\"done\"), file: file, line: line)\n"
            ),
            format!("expect(out.includes(\"{key}=\"), message, \"{value}\")\n"),
            format!("assert \"{key}:\" , \"{value}\"\n"),
            format!("{key} = \"\n{value}\"\n"),
        ] {
            assert_clear(&text);
        }
    }
    for (key, rule) in [("token", TOKEN), ("api_key", API), ("secret", SECRET)] {
        assert_detected(
            &format!("{key} = \"{value}\"\nnext(\"x\", file: file, line: line)\n"),
            &value,
            rule,
        );
    }

    let env = IsolatedEnv::new();
    let text = "func check(_ output: String) {\n    XCTAssertFalse(output.contains(\"token=\"), file: file, line: line)\n    XCTAssertTrue(output.contains(\"done\"), file: file, line: line)\n}\n";
    let source = env.home().join("OutputTests.swift");
    std::fs::write(&source, text).unwrap();
    assert_eq!(
        hook_exit(&env, &["check-file", source.to_str().unwrap()], None),
        Some(0)
    );
    assert_eq!(
        hook_exit(
            &env,
            &["check-codex", "--stdin-json"],
            Some(&bash_output(&env, text))
        ),
        Some(0)
    );
    let with_token = format!("{text}GITHUB_TOKEN={value}\n");
    assert_eq!(
        hook_exit(
            &env,
            &["check-codex", "--stdin-json"],
            Some(&bash_output(&env, &with_token))
        ),
        Some(2)
    );
}

/// a value made of shell parameter expansions and punctuation alone is whatever the variables
/// hold; an opaque literal beside the expansions, or as an operand of one, is still a credential.
#[test]
fn a_named_value_of_expansions_alone_is_no_credential() {
    for text in [
        "token=\"[${TASK_ID:0:8}]\"",
        "token='${PREFIX}-${TASK_ID:0:8}'",
        "GITHUB_TOKEN=[${TASK_ID:0:8}]",
        "GITHUB_TOKEN=\"${TOKEN_PREFIX}${RUN_ID}\"",
        "export ACCESS_TOKEN=${PREFIX}/${#ITEMS[@]}/${ITEMS[0]}",
        "api_key=\"${API_KEY_PREFIX}:${API_KEY_SUFFIX:-}\"",
        "client_secret=\"${CLIENT_SECRET:-${FALLBACK_CLIENT_SECRET}}\"",
        "{\"stdout\":\"x\\ntoken=[${TASK_ID:0:8}]-${RUN_ID}\"}",
    ] {
        assert_clear(text);
    }
    let value = alnum(801);
    for (text, rule) in [
        (format!("token=\"${{PREFIX}}{value}\""), TOKEN),
        (format!("token=\"[${{TASK_ID:0:8}}]-{value}\""), TOKEN),
        (
            format!("token=\"${{GITHUB_TOKEN:-{value}}}-${{RUN_ID}}\""),
            TOKEN,
        ),
        (format!("GITHUB_TOKEN=${{PREFIX}}-{value}"), TOKEN),
        (format!("api_key=\"${{API_KEY_PREFIX}}-{value}\""), API),
        (format!("client_secret=\"${{CLIENT_ID}}:{value}\""), SECRET),
        (format!("token=\"{value}\""), TOKEN),
        (format!("GITHUB_TOKEN={value}"), TOKEN),
    ] {
        assert!(
            reports(&text, &value, rule),
            "{rule} missed the value in {text:?}"
        );
    }
}

/// whether the default scanner reports `literal` under `rule` somewhere in `text`.
fn reports(text: &str, literal: &str, rule: &str) -> bool {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    scan_text(text, &scanner, &allowlist)
        .iter()
        .any(|found| found.rule_id == rule && text[found.range.clone()].contains(literal))
}

/// a codex `PostToolUse` payload whose Bash output is `text`.
fn bash_output(env: &IsolatedEnv, text: &str) -> Value {
    json!({
        "session_id": "session-post",
        "turn_id": "turn-post",
        "cwd": env.home(),
        "hook_event_name": "PostToolUse",
        "model": "gpt-test",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": "cat fixture.txt"},
        "tool_response": text,
        "tool_use_id": "exec-post"
    })
}

/// exit codes of check-file over `text` written to a file and of check-codex over it as Bash output.
fn surface_exits(env: &IsolatedEnv, text: &str) -> (Option<i32>, Option<i32>) {
    let source = env.home().join("fixture.txt");
    std::fs::write(&source, text).unwrap();
    (
        hook_exit(env, &["check-file", source.to_str().unwrap()], None),
        hook_exit(
            env,
            &["check-codex", "--stdin-json"],
            Some(&bash_output(env, text)),
        ),
    )
}

/// a quoted value may open on any byte: only a quote that closes the name's own string literal
/// opens none. `)`, `,` and a space leading a real value are part of it, and a later assignment
/// behind a dropped literal is still read.
#[test]
fn a_quoted_value_may_open_on_a_parenthesis_comma_or_space() {
    let value = alnum(901);
    let env = IsolatedEnv::new();
    let mut failures = Vec::new();
    for (key, rule) in [("token", TOKEN), ("api_key", API), ("secret", SECRET)] {
        for prefix in [")", ",", " "] {
            let literal = format!("{prefix}{value}");
            for text in [
                format!("{key}=\"{literal}\"\n"),
                format!("{key} = '{literal}'\n"),
                format!("request({key}=\"{literal}\", retry: true)\n"),
            ] {
                if !reports(&text, &literal, rule) {
                    failures.push(format!("scan_text {rule} {prefix:?} {}", text.len()));
                }
                let exits = surface_exits(&env, &text);
                if exits != (Some(2), Some(2)) {
                    failures.push(format!("hooks {rule} {prefix:?} {exits:?}"));
                }
            }
        }
        let text = format!(
            "assert(out.contains(\"{key}=\"), message); let {key} = \"{value}\"\nnext(\"x\", file: file)\n"
        );
        if !reports(&text, &value, rule) {
            failures.push(format!("scan_text {rule} behind a literal"));
        }
        let exits = surface_exits(&env, &text);
        if exits != (Some(2), Some(2)) {
            failures.push(format!("hooks {rule} behind a literal {exits:?}"));
        }
        for text in [
            format!("expect(out.includes(\"{key}=\"), message, \"{value}\")\n"),
            format!("expect(out.includes('{key}: '), message, '{value}')\n"),
            format!("assert(out.contains(\"GITHUB_{key}=\"), message, \"{value}\")\n"),
        ] {
            let exits = surface_exits(&env, &text);
            if exits != (Some(0), Some(0)) {
                failures.push(format!("hooks {rule} literal tail {exits:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// a literal beside the expansions or as a default operand is the value while it is read or the
/// variable is unset, whatever its alphabet: non-ascii letters and a symbols-only fallback are
/// no separators.
#[test]
fn a_non_ascii_or_symbol_literal_beside_expansions_is_still_a_credential() {
    let mut state = 0x5EED_0907_u64;
    let mut step = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let cjk: String = (0..48)
        .map(|_| char::from_u32(0x4E00 + (step() % 0x51FF) as u32).unwrap())
        .collect();
    let symbol_set = b"!@#%^&*_-+=:;,.?/~";
    let symbols: String = (0..64)
        .map(|_| char::from(symbol_set[(step() % symbol_set.len() as u64) as usize]))
        .collect();
    let env = IsolatedEnv::new();
    let mut failures = Vec::new();
    for (key, rule) in [("token", TOKEN), ("api_key", API), ("secret", SECRET)] {
        for (case, literal, text) in [
            ("cjk beside", &cjk, format!("{key}=\"{cjk}-${{RUN_ID}}\"\n")),
            (
                "cjk default",
                &cjk,
                format!("{key}=\"${{TOKEN:-{cjk}}}-${{RUN_ID}}\"\n"),
            ),
            (
                "symbol default",
                &symbols,
                format!("{key}=\"${{TOKEN:-{symbols}}}-${{RUN_ID}}\"\n"),
            ),
        ] {
            if !reports(&text, literal, rule) {
                failures.push(format!("scan_text {rule} {case}"));
            }
            let exit = hook_exit(
                &env,
                &["check-codex", "--stdin-json"],
                Some(&bash_output(&env, &text)),
            );
            if exit != Some(2) {
                failures.push(format!("check-codex {rule} {case} {exit:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn separator_literals_split_by_references_are_still_credentials() {
    let symbols = opaque(68, 0x5EED_1102, b"-_.:/@+,=~[]()#%");
    let split: String = symbols
        .as_bytes()
        .chunks(4)
        .map(|chunk| {
            format!(
                "${{UNSET_separator}}{}",
                std::str::from_utf8(chunk).unwrap()
            )
        })
        .collect();
    let env = IsolatedEnv::new();
    let mut failures = Vec::new();
    for (key, rule) in [("token", TOKEN), ("api_key", API), ("secret", SECRET)] {
        for (case, value) in [
            ("beside", split.clone()),
            ("default", format!("${{TOKEN:-{split}}}-${{RUN_ID}}")),
        ] {
            let text = format!("{key}=\"{value}\"\n");
            if !reports(&text, &value, rule) {
                failures.push(format!("scan_text {rule} {case}"));
            }
            let exit = hook_exit(
                &env,
                &["check-codex", "--stdin-json"],
                Some(&bash_output(&env, &text)),
            );
            if exit != Some(2) {
                failures.push(format!("check-codex {rule} {case} {exit:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reference_compositions_within_the_separator_limit_stay_clear() {
    let env = IsolatedEnv::new();
    let mut failures = Vec::new();
    for key in ["token", "api_key", "secret"] {
        for (case, value) in [
            ("host and path", "${HOST}:${PORT}/${PATH}"),
            ("named parts", "${A}-${B}_${C}"),
            ("scheme", "${SCHEME}://${HOST}"),
            ("empty and reference defaults", "${A:-}${B:=${C}}"),
            ("sibling defaults", "${A:-[${B}]}${C:-[${D}]}"),
            ("nested defaults", "${A:-[${B:-[${C}]}]}"),
        ] {
            let text = format!("{key}=\"{value}\"\n");
            assert_clear(&text);
            let exit = hook_exit(
                &env,
                &["check-codex", "--stdin-json"],
                Some(&bash_output(&env, &text)),
            );
            if exit != Some(0) {
                failures.push(format!("check-codex {key} {case} {exit:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// the default scanner, compiled once for the tests that scan thousands of samples.
static DEFAULT_SCANNER: std::sync::LazyLock<(CompiledScanner, CompiledAllowlist)> =
    std::sync::LazyLock::new(|| {
        let config = ProjectConfig::default();
        let rules = load_rules_with_config(&config).unwrap();
        (
            compile_rules(&rules).unwrap(),
            build_allowlist(&config, &rules).unwrap(),
        )
    });

fn scanned_values(text: &str, rule: &str) -> Vec<String> {
    let (scanner, allowlist) = &*DEFAULT_SCANNER;
    scan_text(text, scanner, allowlist)
        .into_iter()
        .filter(|finding| finding.rule_id == rule)
        .map(|finding| text[finding.range].to_owned())
        .collect()
}

#[test]
fn an_opaque_shell_operand_is_the_value_and_the_only_part_reported() {
    let value = alnum(1301);
    for (key, rule) in [
        ("token", TOKEN),
        ("GITHUB_TOKEN", TOKEN),
        ("api_key", API),
        ("client_secret", SECRET),
        ("SECRET_KEY", SECRET),
    ] {
        for operator in [":-", ":=", ":+", ":?"] {
            for name in ["SOME_VAR", "TEST_EXAMPLE_TOKEN"] {
                let expansion = format!("${{{name}{operator}{value}}}");
                for text in [
                    format!("{key}={expansion}"),
                    format!("{key}=\"{expansion}\""),
                    format!("{key}: {expansion}"),
                ] {
                    assert_eq!(
                        scanned_values(&text, rule),
                        [value.as_str()],
                        "{rule} in {text:?}"
                    );
                }
            }
        }
    }
    // the unquoted password value stops at a brace, so only the quoted form reaches the rule.
    for operator in [":-", ":=", ":+", ":?"] {
        assert_eq!(
            scanned_values(
                &format!("PASSWORD=\"${{SOME_VAR{operator}{value}}}\""),
                "generic-password-assignment"
            ),
            [value.as_str()]
        );
    }
    let hex_key = hex(40, 1302);
    assert_eq!(
        scanned_values(&format!("token=${{SOME_VAR:-{hex_key}}}"), TOKEN),
        [hex_key.as_str()]
    );
    let (scanner, allowlist) = &*DEFAULT_SCANNER;
    assert_eq!(
        redact_text(&format!("token=${{SOME_VAR:-{value}}}"), scanner, allowlist),
        "token=${SOME_VAR:-[REDACTED]}"
    );
}

#[test]
fn a_chunked_shell_operand_is_still_a_credential() {
    let value = opaque(32, 1401, b"abcdefghijklmnopqrstuvwxyz");
    let cut = value
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    assert!(shannon_entropy(cut.as_bytes()) >= 4.0);
    assert_eq!(
        scanned_values(&format!("token=${{SOME_VAR:-{cut}}}"), TOKEN),
        [cut.as_str()]
    );
}

#[test]
fn a_reference_or_word_operand_stays_exempt() {
    for operand in [
        "",
        "changeme",
        "fallback",
        "defaultpass",
        "default-secret-key",
        "dev-secret-key-change-me",
        "your-access-token-here",
        "/var/lib/app/state",
        "/run/secrets/x7k2-state/token",
        "$OTHER_TOKEN",
        "$(cat /run/secrets/token)",
        "$(openssl rand -hex 32)",
        "http://localhost:8080",
        "SECRET_KEY must be set",
        "toĸen is required, see the guide",
        "8080",
    ] {
        for key in ["token", "api_key", "client_secret", "PASSWORD"] {
            for operator in [":-", ":=", ":+", ":?"] {
                let expansion = format!("${{SOME_VAR{operator}{operand}}}");
                assert_clear(&format!("{key}=\"{expansion}\""));
                if !operand.contains([' ', '(']) {
                    assert_clear(&format!("{key}={expansion}"));
                }
            }
        }
    }
    for reference in [
        "${SOME_VAR}",
        "$SOME_VAR",
        "%SOME_VAR%",
        "${var.some_token}",
        "${{ secrets.SOME_TOKEN }}",
    ] {
        for key in ["token", "api_key", "client_secret", "PASSWORD"] {
            assert_clear(&format!("{key}=\"{reference}\""));
        }
    }
}

/// the operand is a concrete literal the way a quoted bare value is, so the password branches that
/// only a concrete literal reaches read it too.
#[test]
fn a_literal_password_operand_is_judged_as_a_quoted_password() {
    const PASSWORD: &str = "generic-password-assignment";
    let digits_between = "x7k2m9q4v1n8";
    let four_classes = "xQ7rT2!mK9";
    for value in [digits_between, four_classes] {
        assert_eq!(
            scanned_values(&format!("password=\"{value}\""), PASSWORD),
            [value],
            "bare {value}"
        );
        assert_eq!(
            scanned_values(&format!("password=\"${{DB_PW:-{value}}}\""), PASSWORD),
            [value],
            "operand {value}"
        );
    }
    // a word or a reference is no literal credential, whatever the branches would say.
    assert_clear("password=\"${DB_PW:-defaultpass}\"");
    assert_clear("password=\"${DB_PW:-$OTHER_PASSWORD}\"");
}

/// the steps that read a bare value read the operand, not the variable's name beside it.
#[test]
fn the_operand_is_judged_without_the_name_beside_it() {
    let mut samples = 0;
    for seed in 1..=200_u64 {
        let run = opaque(
            64,
            seed.wrapping_mul(0x9E37_79B9),
            b"abcdefghijklmnopqrstuvwxyz",
        );
        let value = format!("{}.{}", &run[..10], &run[10..20]);
        if value.starts_with('.')
            || value.ends_with('.')
            || !scanned_values(&format!("token={value}"), TOKEN).contains(&value)
        {
            continue;
        }
        samples += 1;
        for text in [
            format!("token=${{SOME_VAR:-{value}}}"),
            format!("token=\"${{SOME_VAR:-{value}}}\""),
        ] {
            assert_eq!(scanned_values(&text, TOKEN), [value.as_str()], "{text:?}");
        }
    }
    assert!(samples > 20, "only {samples} samples are reported bare");

    let chunks = opaque(32, 1601, b"abcdefghijklmnopqrstuvwxyz")
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    let path = format!("/tmp/{chunks}/state.lock");
    assert_eq!(
        scanned_values(&format!("token=\"${{SOME_VAR:-{path}}}\""), TOKEN),
        [path.as_str()]
    );
}

#[test]
fn a_user_allowlist_judges_the_operand_of_an_expansion() {
    let value = alnum(1501);
    let toml = format!("[[allowlist.rules]]\nid = \"{TOKEN}\"\nregexes = [\"^{value}$\"]\n");
    let config: ProjectConfig = toml::from_str(&toml).unwrap();
    let rules = load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    let text = format!("token=${{SOME_VAR:-{value}}}");
    assert!(scan_text(&text, &scanner, &allowlist).is_empty());
}
