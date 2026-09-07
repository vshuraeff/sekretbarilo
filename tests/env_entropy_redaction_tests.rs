//! this suite specifies the generic-high-entropy-value contract end-to-end at the binary and
//! hook level. several tests are expected to fail until the tier-3 rule itself lands on a
//! sibling branch/worktree; do not weaken these assertions to make them pass early.

mod common;

use std::io::{Read, Write};
use std::process::{Output, Stdio};

use common::IsolatedEnv;
use serde_json::{Value, json};

const TOKEN_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const JWT_SENTINEL: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3N5bnRoZXRpY19ieXRlcw";

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn value(&mut self, len: usize) -> String {
        (0..len)
            .map(|_| TOKEN_ALPHABET[(self.next_u64() as usize) % TOKEN_ALPHABET.len()] as char)
            .collect()
    }
}

fn shannon_entropy(value: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in value {
        counts[byte as usize] += 1;
    }
    let len = value.len() as f64;
    counts
        .into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn high_entropy_value(generator: &mut SplitMix64, len: usize) -> String {
    loop {
        let value = generator.value(len);
        if shannon_entropy(value.as_bytes()) >= 4.0 {
            assert!(
                shannon_entropy(value.as_bytes()) >= 4.0,
                "generated fixture must qualify independently of the scanner: {value:?}"
            );
            return value;
        }
    }
}

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
        .expect("failed to start redact-claude");
    let mut stdin = child.stdin.take().expect("missing child stdin");
    let mut stdout = child.stdout.take().expect("missing child stdout");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .read_to_end(&mut bytes)
            .expect("failed to read stdout");
        bytes
    });
    stdin
        .write_all(bytes)
        .expect("failed to write hook payload");
    drop(stdin);
    let mut output = child.wait_with_output().expect("failed to wait for hook");
    output.stdout = reader.join().expect("stdout reader panicked");
    output
}

fn run_bash(env: &IsolatedEnv, stdout: &str) -> Output {
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).expect("failed to create workspace");
    run_bytes(
        env,
        &serde_json::to_vec(&json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "cwd": workspace,
            "tool_input": {"command": "env"},
            "tool_response": {"stdout": stdout, "stderr": "", "interrupted": false}
        }))
        .expect("failed to serialize hook payload"),
    )
}

fn write_user_config(env: &IsolatedEnv, config: &str) {
    let config_dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
    std::fs::write(config_dir.join("sekretbarilo.toml"), config)
        .expect("failed to write user config");
}

fn write_disabled_entropy_rule_config(env: &IsolatedEnv) {
    write_user_config(
        env,
        "[[rules]]\nid = \"generic-high-entropy-value\"\ndescription = \"Disabled\"\nregex = \"(?-u:^$a)\"\nsecret_group = 1\nkeywords = [\"__never_match__\"]\n",
    );
}

fn updated_stdout(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(0));
    let response: Value = serde_json::from_slice(&output.stdout)
        .expect("redacted hook output must be replacement JSON");
    assert!(
        response.get("continue").is_none(),
        "successful redaction must not set a top-level continue field"
    );
    response["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .expect("replacement must contain hookSpecificOutput.updatedToolOutput.stdout")
        .to_owned()
}

fn assert_hook_envelope(output: &Output, expected_stdout: &str) {
    assert_eq!(updated_stdout(output), expected_stdout);
    let response: Value = serde_json::from_slice(&output.stdout)
        .expect("redacted hook output must be replacement JSON");
    assert_eq!(
        response["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PostToolUse")
    );
    let updated = &response["hookSpecificOutput"]["updatedToolOutput"];
    assert_eq!(updated["stderr"].as_str(), Some(""));
    assert_eq!(updated["interrupted"].as_bool(), Some(false));
    assert_eq!(updated["stdout"].as_str(), Some(expected_stdout));
}

fn assert_values_absent(output: &Output, values: &[String]) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for value in values {
        assert!(
            !stdout.contains(value),
            "secret value leaked through hook stdout: {value:?}"
        );
        assert!(
            !stderr.contains(value),
            "secret value leaked through hook stderr: {value:?}"
        );
    }
}

fn assert_clean_redaction(output: &Output) {
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "clean hook output should be silent: {:?}",
        output.stdout
    );
    assert!(
        output.stderr.is_empty(),
        "clean hook stderr should be empty: {:?}",
        output.stderr
    );
}

fn assert_new_rule_detects(
    env: &IsolatedEnv,
    stdout: &str,
    expected_redacted: &str,
    expected_when_disabled: &str,
    secret_values: &[String],
) {
    let output = run_bash(env, stdout);
    assert_values_absent(&output, secret_values);
    assert_hook_envelope(&output, expected_redacted);

    write_disabled_entropy_rule_config(env);
    let disabled_output = run_bash(env, stdout);
    if disabled_output.stdout.is_empty() {
        assert!(
            disabled_output.stderr.is_empty(),
            "disabling the generic rule produced no stdout but non-empty stderr: {:?}",
            disabled_output.stderr
        );
        assert_eq!(
            expected_when_disabled, stdout,
            "a fully clean disabled run implies the disabled expectation is the raw input unchanged"
        );
    } else {
        assert_hook_envelope(&disabled_output, expected_when_disabled);
        let disabled_stdout = updated_stdout(&disabled_output);
        for value in secret_values {
            assert!(
                disabled_stdout.contains(value),
                "disabling the generic rule unexpectedly changed this value: {value:?}"
            );
        }
    }
}

#[test]
fn env_dump_high_entropy_values_redacted_regardless_of_name() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x5e9d_2ab1_c04f_7713);
    let values: Vec<String> = (0..5)
        .map(|_| high_entropy_value(&mut generator, 32))
        .collect();
    let stdout = format!(
        "ALPHA={}\nBRAVO={}\nCHARLIE={}\nDELTA={}\nECHO={}\nJWT={JWT_SENTINEL}\nGREETING=hello world\nNUMBER=12345\nPATHLIKE=/usr/local/bin/tooling\nWORD=configuration\n",
        values[0], values[1], values[2], values[3], values[4]
    );
    let expected_redacted = "ALPHA=[REDACTED]\nBRAVO=[REDACTED]\nCHARLIE=[REDACTED]\nDELTA=[REDACTED]\nECHO=[REDACTED]\nJWT=[REDACTED]\nGREETING=hello world\nNUMBER=12345\nPATHLIKE=/usr/local/bin/tooling\nWORD=configuration\n";
    let expected_when_disabled = format!(
        "ALPHA={}\nBRAVO={}\nCHARLIE={}\nDELTA={}\nECHO={}\nJWT=[REDACTED]\nGREETING=hello world\nNUMBER=12345\nPATHLIKE=/usr/local/bin/tooling\nWORD=configuration\n",
        values[0], values[1], values[2], values[3], values[4]
    );

    assert_new_rule_detects(
        &env,
        &stdout,
        expected_redacted,
        &expected_when_disabled,
        &values,
    );
}

#[test]
fn name_independent_redaction_across_benign_variable_names() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x2a8c_1f5e_9374_b6d0);
    let value = high_entropy_value(&mut generator, 32);
    let stdout = format!(
        "PATH={value}\nMANPATH={value}\nLS_COLORS={value}\nTERM_SESSION_ID={value}\nDB_TOKEN={value}\nJWT={JWT_SENTINEL}\n"
    );
    let expected_redacted = "PATH=[REDACTED]\nMANPATH=[REDACTED]\nLS_COLORS=[REDACTED]\nTERM_SESSION_ID=[REDACTED]\nDB_TOKEN=[REDACTED]\nJWT=[REDACTED]\n";
    let expected_when_disabled = format!(
        "PATH={value}\nMANPATH={value}\nLS_COLORS={value}\nTERM_SESSION_ID={value}\nDB_TOKEN={value}\nJWT=[REDACTED]\n"
    );

    assert_new_rule_detects(
        &env,
        &stdout,
        expected_redacted,
        &expected_when_disabled,
        std::slice::from_ref(&value),
    );
}

#[test]
fn realistic_mixed_env_corpus_exact_expectations() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x7139_c0ad_58e2_4b16);
    let ls_colors = "rs=0:di=01;34:ln=01";
    // expected to survive: 19 bytes and entropy about 3.537; no 20-byte candidate exists.
    assert_eq!(ls_colors.len(), 19);
    assert!((shannon_entropy(ls_colors.as_bytes()) - 3.536_887).abs() < 0.000_001);

    let git_sha = "0123456789abcdef0123456789abcdef00000000";
    // expected to survive: 40 bytes and entropy about 3.741, below the 4.0 threshold.
    assert_eq!(git_sha.len(), 40);
    assert!((shannon_entropy(git_sha.as_bytes()) - 3.741_446).abs() < 0.000_001);

    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    // expected to survive: 36 bytes and entropy about 3.391, below the 4.0 threshold.
    assert_eq!(uuid.len(), 36);
    assert!((shannon_entropy(uuid.as_bytes()) - 3.390_540).abs() < 0.000_001);

    let short_base64 = "YWJjZGVmZ2hpamts";
    // expected to survive: 16 bytes and entropy 3.75; the length gate rejects it first.
    assert_eq!(short_base64.len(), 16);
    assert!((shannon_entropy(short_base64.as_bytes()) - 3.75).abs() < f64::EPSILON);

    let base64url_value = high_entropy_value(&mut generator, 32);
    // expected to redact: 32 bytes, with entropy at least 4.0 asserted by the generator.
    assert_eq!(base64url_value.len(), 32);

    let path_value = loop {
        let candidate = format!("/opt/{}", generator.value(24));
        if shannon_entropy(candidate.as_bytes()) >= 4.0 {
            break candidate;
        }
    };
    // expected to redact: 29 bytes and entropy at least 4.0; path syntax has no exemption.
    assert_eq!(path_value.len(), 29);
    assert!(shannon_entropy(path_value.as_bytes()) >= 4.0);

    let checksum = "00112233445566778899aabbccddeeff";
    // expected to redact: 32 bytes and exactly entropy 4.0; checksum context is bypassed.
    assert_eq!(checksum.len(), 32);
    assert!((shannon_entropy(checksum.as_bytes()) - 4.0).abs() < f64::EPSILON);

    let stdout = format!(
        "PATH=/usr/bin:/bin\nSHELL=/usr/local/bin/fish\nLANG=en_US.UTF-8\nTERM=xterm-256color\nHOME=/Users/tester\nRCPATH=${{HOME}}/bin\nLS_COLORS={ls_colors}\nGIT_SHA={git_sha}\nUUID={uuid}\nSHORT_BASE64={short_base64}\nBASE64URL={base64url_value}\nPATH_VALUE={path_value}\nCHECKSUM={checksum}\n"
    );
    let expected = format!(
        "PATH=/usr/bin:/bin\nSHELL=/usr/local/bin/fish\nLANG=en_US.UTF-8\nTERM=xterm-256color\nHOME=/Users/tester\nRCPATH=${{HOME}}/bin\nLS_COLORS={ls_colors}\nGIT_SHA={git_sha}\nUUID={uuid}\nSHORT_BASE64={short_base64}\nBASE64URL=[REDACTED]\nPATH_VALUE=[REDACTED]\nCHECKSUM=[REDACTED]\n"
    );
    let expected_when_disabled = format!(
        "PATH=/usr/bin:/bin\nSHELL=/usr/local/bin/fish\nLANG=en_US.UTF-8\nTERM=xterm-256color\nHOME=/Users/tester\nRCPATH=${{HOME}}/bin\nLS_COLORS={ls_colors}\nGIT_SHA={git_sha}\nUUID={uuid}\nSHORT_BASE64={short_base64}\nBASE64URL={base64url_value}\nPATH_VALUE={path_value}\nCHECKSUM={checksum}\n"
    );

    assert_new_rule_detects(
        &env,
        &stdout,
        &expected,
        &expected_when_disabled,
        &[base64url_value, path_value, checksum.to_owned()],
    );
}

#[test]
fn jwt_shaped_value_is_covered_by_existing_jwt_rule_not_new_rule() {
    let env = IsolatedEnv::new();
    // jwt-token uses (eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}).
    let stdout = format!("JWT={JWT_SENTINEL}\n");
    let output = run_bash(&env, &stdout);
    assert_values_absent(&output, &[JWT_SENTINEL.to_owned()]);
    assert_hook_envelope(&output, "JWT=[REDACTED]\n");

    write_disabled_entropy_rule_config(&env);
    let disabled_output = run_bash(&env, &stdout);
    assert_values_absent(&disabled_output, &[JWT_SENTINEL.to_owned()]);
    assert_hook_envelope(&disabled_output, "JWT=[REDACTED]\n");
}

#[test]
fn check_file_masks_high_entropy_env_dump() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0xbac4_397e_12d0_6f85);
    let values: Vec<String> = (0..3)
        .map(|_| high_entropy_value(&mut generator, 32))
        .collect();
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).expect("failed to create workspace");
    let file_path = workspace.join("env-dump");
    std::fs::write(
        &file_path,
        format!(
            "ALPHA={}\nBRAVO={}\nCHARLIE={}\n",
            values[0], values[1], values[2]
        ),
    )
    .expect("failed to write env dump");

    let output = env
        .command()
        .args(["check-file", file_path.to_str().expect("non-utf8 path")])
        .env("XDG_CONFIG_HOME", env.home().join(".config"))
        .output()
        .expect("failed to run check-file");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "check-file stdout must be empty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (index, value) in values.iter().enumerate() {
        assert!(
            !stderr.contains(value),
            "check-file stderr exposed a complete secret value: {value:?}"
        );
        let expected_finding = format!(
            "  line: {}\n  rule: generic-high-entropy-value\n",
            index + 1
        );
        assert!(
            stderr.contains(&expected_finding),
            "check-file diagnostic missing the expected finding: {expected_finding:?}"
        );
    }
    assert_eq!(
        stderr
            .matches("  rule: generic-high-entropy-value\n")
            .count(),
        3
    );

    write_disabled_entropy_rule_config(&env);
    let disabled_output = env
        .command()
        .args(["check-file", file_path.to_str().expect("non-utf8 path")])
        .env("XDG_CONFIG_HOME", env.home().join(".config"))
        .output()
        .expect("failed to run check-file with the rule disabled");
    assert_eq!(disabled_output.status.code(), Some(0));
    assert!(disabled_output.stdout.is_empty());
    assert!(disabled_output.stderr.is_empty());
}

#[test]
fn boundary_19_bytes_not_redacted() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x6df1_4782_be95_30ac);
    let value = high_entropy_value(&mut generator, 19);
    assert_eq!(value.len(), 19);
    assert!(shannon_entropy(value.as_bytes()) >= 4.0);

    assert_clean_redaction(&run_bash(&env, &format!("SESSION={value}\n")));
}

#[test]
fn boundary_20_bytes_high_entropy_redacted() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x1ca7_8e53_94b0_d26f);
    let value = high_entropy_value(&mut generator, 20);
    assert_eq!(value.len(), 20);
    assert!(shannon_entropy(value.as_bytes()) >= 4.0);

    let stdout = format!("SESSION={value}\n");
    let expected_when_disabled = format!("SESSION={value}\n");

    assert_new_rule_detects(
        &env,
        &stdout,
        "SESSION=[REDACTED]\n",
        &expected_when_disabled,
        std::slice::from_ref(&value),
    );
}

#[test]
fn boundary_32_bytes_low_entropy_not_redacted() {
    let env = IsolatedEnv::new();
    let value = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";
    assert_eq!(value.len(), 32);
    assert!(shannon_entropy(value.as_bytes()) < 2.0);

    assert_clean_redaction(&run_bash(&env, &format!("SESSION={value}\n")));
}

#[test]
fn assignment_shapes_redact_the_captured_value() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x8fe0_64b3_1a59_c27d);
    let values: Vec<String> = (0..7)
        .map(|_| high_entropy_value(&mut generator, 32))
        .collect();
    let stdout = format!(
        "NAME={}\r\nexport NAME={}\nNAME: {}\nname = \"{}\"\nname = '{}'\n{{\"name\": \"{}\", \"other\": \"metadata\", \"extra\": \"{}\"}}\n",
        values[0], values[1], values[2], values[3], values[4], values[5], values[6]
    );
    let expected = "NAME=[REDACTED]\r\nexport NAME=[REDACTED]\nNAME: [REDACTED]\nname = \"[REDACTED]\"\nname = '[REDACTED]'\n{\"name\": \"[REDACTED]\", \"other\": \"metadata\", \"extra\": \"[REDACTED]\"}\n";
    let expected_when_disabled = stdout.clone();

    assert_new_rule_detects(&env, &stdout, expected, &expected_when_disabled, &values);
}

#[test]
fn standalone_bare_and_padded_base64_values_are_redacted() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x4a12_b3de_7f80_69c5);
    let bare = high_entropy_value(&mut generator, 32);
    let quoted = high_entropy_value(&mut generator, 32);
    let padded = format!("{}==", high_entropy_value(&mut generator, 30));
    assert!(shannon_entropy(padded.as_bytes()) >= 4.0);
    let stdout = format!("{bare}\n  \"{padded}\"  \n'{quoted}'\n");

    let expected_when_disabled = stdout.clone();

    assert_new_rule_detects(
        &env,
        &stdout,
        "[REDACTED]\n  \"[REDACTED]\"  \n'[REDACTED]'\n",
        &expected_when_disabled,
        &[bare, padded, quoted],
    );
}

#[test]
fn per_rule_allowlist_preserves_high_entropy_value() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0x29df_5a41_c80b_7e36);
    let value = high_entropy_value(&mut generator, 32);
    let stdout = format!("SESSION={value}\n");
    let output = run_bash(&env, &stdout);
    assert_values_absent(&output, std::slice::from_ref(&value));
    assert_hook_envelope(&output, "SESSION=[REDACTED]\n");

    write_user_config(
        &env,
        &format!(
            "[[allowlist.rules]]\nid = \"generic-high-entropy-value\"\nregexes = [\"^{value}$\"]\npaths = []\n"
        ),
    );

    assert_clean_redaction(&run_bash(&env, &stdout));
}

#[test]
fn key_allowlist_preserves_tmpdir_in_redact_and_check_file() {
    let env = IsolatedEnv::new();
    let mut generator = SplitMix64::new(0xc431_4aa6_d41e_f36b);
    let path_value = format!(
        "/var/folders/xx/{}/T/",
        high_entropy_value(&mut generator, 32)
    );
    let token = high_entropy_value(&mut generator, 32);
    let input = format!("TMPDIR={path_value}\nCLAUDE_CODE_MESSAGING_TOKEN={token}\n");

    write_user_config(
        &env,
        "[[allowlist.rules]]\nid = \"generic-high-entropy-value\"\nkeys = [\"TMPDIR\"]\n",
    );

    let redacted = run_bash(&env, &input);
    assert_values_absent(&redacted, std::slice::from_ref(&token));
    assert_hook_envelope(
        &redacted,
        &format!("TMPDIR={path_value}\nCLAUDE_CODE_MESSAGING_TOKEN=[REDACTED]\n"),
    );

    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let file_path = workspace.join("env-dump");
    std::fs::write(&file_path, &input).unwrap();
    let checked = env
        .command()
        .args(["check-file", file_path.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", env.home().join(".config"))
        .output()
        .unwrap();
    assert_eq!(checked.status.code(), Some(2));
    assert!(checked.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&checked.stderr);
    assert!(!stderr.contains(&token));
    assert_eq!(stderr.matches("  line:").count(), 1, "{stderr}");
    assert!(
        stderr.contains("  line: 2\n  rule: generic-high-entropy-value\n"),
        "{stderr}"
    );
}
