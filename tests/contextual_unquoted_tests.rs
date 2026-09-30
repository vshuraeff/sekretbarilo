// the unquoted alternative of generic-api-key, generic-secret-assignment and
// generic-token-assignment: a credential-named assignment wherever one can start on a line
// (`KEY=value` after line start, whitespace, `;`, `&`, `|` or `(`; yaml `key: value` at logical
// line start or in a list item), under the key word alone or a longer name ending in it
// (`HF_TOKEN`, `DJANGO_SECRET_KEY`, `openaiApiKey`), is detected by these contextual rules with the
// heuristic rule off, the whole word is masked, and paths, references, code, word values and
// near-miss names stay clear. opaque values are generated here, never written literally, except
// the synthetic lowercase word salad of the round-03 review.

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::IsolatedEnv;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules};
use serde_json::{Value, json};

const API: &str = "generic-api-key";
const SECRET: &str = "generic-secret-assignment";
const TOKEN: &str = "generic-token-assignment";

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SEPARATED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+-_.";

/// the built-in selection with no config: signature and contextual on, heuristic off.
fn defaults() -> (CompiledScanner, CompiledAllowlist) {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    assert!(
        !rules
            .iter()
            .any(|rule| rule.id == "generic-high-entropy-value"),
        "the heuristic rule is off by default"
    );
    (
        compile_rules(&rules).unwrap(),
        build_allowlist(&config, &rules).unwrap(),
    )
}

/// a deterministic opaque value: xorshift over `alphabet`, redrawn until it carries no
/// placeholder word or repeated run the stopword filter drops and, from the 20 bytes the entropy
/// gate measures, clears that gate with margin. shorter pieces are joined into longer values.
fn opaque(length: usize, seed: u64, alphabet: &[u8]) -> String {
    const WORDS: &[&str] = &[
        "example",
        "test",
        "sample",
        "placeholder",
        "dummy",
        "changeme",
        "fake",
        "mock",
        "todo",
        "fixme",
        "lorem",
        "default",
        "replace",
        "insert",
        "your",
        "my_",
        "my-",
    ];
    let floor = if length >= 20 { 4.2 } else { 0.0 };
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
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
        // case-insensitive, as the placeholder filter reads `xXX` as `xxx`
        let repeated = lower
            .as_bytes()
            .windows(3)
            .any(|run| run[0] == run[1] && run[1] == run[2]);
        if shannon_entropy(value.as_bytes()) >= floor
            && !repeated
            && !WORDS.iter().any(|word| lower.contains(word))
        {
            return value;
        }
    }
    panic!("no opaque value of length {length} for seed {seed:#x}");
}

/// every named key form of the acceptance list, with the rule that owns it.
fn named_forms() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("export API_TOKEN=", "", API),
        ("API_KEY=", "", API),
        ("apikey=", "", API),
        ("api-key: ", "", API),
        ("SECRET_KEY=", "", SECRET),
        ("client_secret=", "", SECRET),
        ("export\tSECRET = ", "", SECRET),
        ("auth_token=", "", TOKEN),
        ("ACCESS_TOKEN=", "", TOKEN),
        ("GITHUB_TOKEN=", "", TOKEN),
        ("token: ", "", TOKEN),
        ("  token: ", "  # rotated weekly", TOKEN),
        ("\tSECRET_TOKEN=", "", TOKEN),
        // round 03: an assignment anywhere it can start on a line, under a longer name
        ("  - API_KEY=", "", API),
        ("  - api_key: ", "", API),
        ("HF_TOKEN=", "", TOKEN),
        ("NPM_TOKEN=", "", TOKEN),
        ("AWS_SESSION_TOKEN=", "", TOKEN),
        ("DJANGO_SECRET_KEY=", "", SECRET),
        ("STRIPE_API_KEY=", "", API),
        ("x-api-key: ", "", API),
        ("_API_KEY=", "", API),
        ("openaiApiKey: ", "", API),
        ("  jwtSecret: ", "", SECRET),
        ("env API_KEY=", "", API),
        ("sudo API_KEY=", " ./deploy.sh", API),
        ("cmd; API_KEY=", "", API),
        ("cmd;API_KEY=", "", API),
        ("make build && TOKEN=", " make release", TOKEN),
        ("make build&&TOKEN=", "", TOKEN),
        ("printenv | grep x || GITHUB_TOKEN=", "", TOKEN),
        ("(export CLIENT_SECRET=", " ; run)", SECRET),
        ("docker run -e API_KEY=", " img", API),
        ("docker run --rm -e HF_TOKEN=", " -e MODEL=base img", TOKEN),
        ("A=1 B=2 WEBHOOK_SECRET=", " ./serve", SECRET),
    ]
}

fn masked(text: &str, value: &str) -> String {
    text.replace(value, "[REDACTED]")
}

/// the text surface reports `rule` and every match on exactly the value (a provider rule may
/// match the same value too), and redaction replaces exactly the value; the diff surface reports
/// the same rule with the value as its whole match.
fn assert_detected(
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    line: &str,
    value: &str,
    rule: &str,
) {
    for eol in ["", "\n", "\r\n"] {
        let text = if eol.is_empty() {
            line.to_owned()
        } else {
            format!("before{eol}{line}{eol}after{eol}")
        };
        let start = text.find(value).unwrap();
        let reported: Vec<(String, std::ops::Range<usize>)> = scan_text(&text, scanner, allowlist)
            .into_iter()
            .map(|found| (found.rule_id, found.range))
            .collect();
        assert!(
            reported.iter().any(|(id, _)| id == rule),
            "{rule} missing: {reported:?}"
        );
        assert!(
            reported
                .iter()
                .all(|(_, range)| *range == (start..start + value.len())),
            "{reported:?}"
        );
        assert_eq!(
            redact_text(&text, scanner, allowlist),
            masked(&text, value),
            "{text:?}"
        );
    }
    for content in [line.to_owned(), format!("{line}\r")] {
        let file = DiffFile {
            path: "deploy/settings.txt".into(),
            is_new: true,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            context: None,
            added_lines: vec![AddedLine {
                line_number: 1,
                content: content.clone().into_bytes(),
            }],
        };
        let findings: Vec<(String, Vec<u8>)> = scan(&[file], scanner, allowlist)
            .into_iter()
            .map(|finding| (finding.rule_id, finding.matched_value))
            .collect();
        assert!(
            findings.iter().any(|(id, _)| id == rule),
            "{rule} missing: {:?}",
            findings.iter().map(|(id, _)| id).collect::<Vec<_>>()
        );
        assert!(
            findings
                .iter()
                .all(|(_, matched)| matched == value.as_bytes()),
            "a finding reports other bytes than the whole value"
        );
    }
}

fn assert_clear(scanner: &CompiledScanner, allowlist: &CompiledAllowlist, line: &str) {
    for text in [line.to_owned(), format!("{line}\r\n")] {
        assert_eq!(
            scan_text(&text, scanner, allowlist),
            [],
            "{text:?} should stay clear"
        );
        assert_eq!(redact_text(&text, scanner, allowlist), text);
    }
}

#[test]
fn named_unquoted_assignments_are_masked_whole_without_the_heuristic_rule() {
    let (scanner, allowlist) = defaults();
    for (index, (prefix, suffix, rule)) in named_forms().into_iter().enumerate() {
        let value = opaque(24, 0x51f1 + index as u64, ALNUM);
        assert_detected(
            &scanner,
            &allowlist,
            &format!("{prefix}{value}{suffix}"),
            &value,
            rule,
        );
    }
}

/// round 02 of the review: expression-shaped suppression must not drop opaque values that merely
/// end in `;`/`,`, carry a dot or an index. the arm consumes the whole shell word, so the reported
/// value excludes one trailing `;`/`,` separator.
#[test]
fn opaque_values_in_expression_shapes_stay_detected() {
    let (scanner, allowlist) = defaults();
    let v = opaque(24, 0x0e01, ALNUM);
    let cases = [
        (format!("export API_KEY={v}; ./run"), v.clone(), API),
        (format!("export API_KEY={v};"), v.clone(), API),
        (format!("API_KEY={v},"), v.clone(), API),
        (
            format!(
                "client_secret={}.{}",
                opaque(12, 0x0e02, ALNUM),
                opaque(12, 0x0e03, ALNUM)
            ),
            String::new(),
            SECRET,
        ),
        (
            format!(
                "api_token: {}.{}",
                opaque(22, 0x0e04, ALNUM),
                opaque(18, 0x0e05, ALNUM)
            ),
            String::new(),
            API,
        ),
        (format!("token: {v}[1]"), format!("{v}[1]"), TOKEN),
    ];
    for (line, value, rule) in cases {
        let value = if value.is_empty() {
            line.split_once(['=', ' ']).unwrap().1.trim().to_owned()
        } else {
            value
        };
        assert_detected(&scanner, &allowlist, &line, &value, rule);
    }
}

#[test]
fn opaque_values_with_separators_stay_detected() {
    let (scanner, allowlist) = defaults();
    let values = [
        opaque(32, 0xa11ce, SEPARATED),
        opaque(40, 0xb0b, SEPARATED),
        // rooted like a path, but no segment reads as a word
        format!(
            "/{}/{}/{}",
            opaque(9, 0xc1, ALNUM),
            opaque(9, 0xc2, ALNUM),
            opaque(9, 0xc3, ALNUM)
        ),
        // three dotted opaque segments
        format!(
            "{}.{}.{}",
            opaque(10, 0xd1, ALNUM),
            opaque(10, 0xd2, ALNUM),
            opaque(10, 0xd3, ALNUM)
        ),
        // a shell word carrying list operators is consumed whole, never cut before them
        format!("{}&&{}", opaque(20, 0xe1, ALNUM), opaque(6, 0xe2, ALNUM)),
    ];
    for value in &values {
        assert!(
            shannon_entropy(value.as_bytes()) >= 4.0,
            "control {value:?} must clear the rules' own gate"
        );
        for (prefix, rule) in [
            ("API_KEY=", API),
            ("client_secret: ", SECRET),
            ("export GITHUB_TOKEN=", TOKEN),
        ] {
            assert_detected(
                &scanner,
                &allowlist,
                &format!("{prefix}{value}"),
                value,
                rule,
            );
        }
    }
}

/// round 03 of the review: a dotted value whose two pieces each pass as a lowercase word is not
/// taken for a member chain when the whole value could be a token standing alone (21 bytes, all
/// distinct, 4.39 bits). a synthetic word salad, written literally as the review wrote it.
const DOTTED_WORD_SALAD: &str = "plmoknijuh.bqygtverfc";

#[test]
fn a_dotted_value_of_token_length_is_not_taken_for_a_member_chain() {
    let (scanner, allowlist) = defaults();
    assert!(shannon_entropy(DOTTED_WORD_SALAD.as_bytes()) >= 4.0);
    for (prefix, rule) in [
        ("API_KEY=", API),
        ("export GITHUB_TOKEN=", TOKEN),
        ("client_secret: ", SECRET),
    ] {
        assert_detected(
            &scanner,
            &allowlist,
            &format!("{prefix}{DOTTED_WORD_SALAD}"),
            DOTTED_WORD_SALAD,
            rule,
        );
    }
    // member chains of the same length or longer keep their suppression: their letters repeat
    for line in [
        "secret=app.config.SECRET_KEY",
        "api_key=config.providers.anthropic.api_key,",
        "GITHUB_TOKEN=os.environ.GITHUB_TOKEN",
        "SECRET_KEY=settings.DJANGO_SECRET_KEY",
    ] {
        assert_clear(&scanner, &allowlist, line);
    }
}

#[test]
fn the_dotted_word_salad_is_blocked_and_masked_by_the_hooks() {
    let env = IsolatedEnv::new();
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let text = format!("host=localhost\nAPI_KEY={DOTTED_WORD_SALAD}\n");
    let file = workspace.join("settings.txt");
    std::fs::write(&file, &text).unwrap();
    let checked = env
        .command()
        .args(["check-file", file.to_str().unwrap()])
        .current_dir(&workspace)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&checked.stderr);
    assert_eq!(checked.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(API), "{stderr}");
    assert!(!stderr.contains(DOTTED_WORD_SALAD), "{stderr}");
    let payload = serde_json::to_vec(&json!({
        "hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
        "tool_input": {"command": "env"},
        "tool_response": {"stdout": text, "stderr": "", "interrupted": false}
    }))
    .unwrap();
    let output = run_with_stdin(
        &env,
        &["redact-claude", "--stdin-json"],
        env.home(),
        &payload,
    );
    assert_eq!(output.status.code(), Some(0));
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        envelope["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        json!(masked(&text, DOTTED_WORD_SALAD))
    );
}

/// the wider assignment start reads several assignments on one line, each value whole.
#[test]
fn every_assignment_on_a_line_is_read() {
    let (scanner, allowlist) = defaults();
    let values: Vec<String> = (0..3).map(|i| opaque(24, 0x6a00 + i, ALNUM)).collect();
    let line = format!(
        "TOKEN={} API_KEY={}; CLIENT_SECRET={}",
        values[0], values[1], values[2]
    );
    // the statement `;` that ends the api key is a separator: it stays visible
    assert_eq!(
        redact_text(&line, &scanner, &allowlist),
        "TOKEN=[REDACTED] API_KEY=[REDACTED]; CLIENT_SECRET=[REDACTED]"
    );
    let found = scan_text(&line, &scanner, &allowlist);
    for (value, rule) in values.iter().zip([TOKEN, API, SECRET]) {
        assert!(
            found.iter().any(|found| found.rule_id == rule
                && line[found.range.clone()].starts_with(value.as_str())),
            "{rule} missing: {found:?}"
        );
    }
}

/// sixteen symbols cap a hex value's shannon entropy at 4.0 bits, under the api and token rules'
/// 4.0-bit gate; an exact-length hex key under a credential name is measured by its hex symbols,
/// quoted or not, while a digest with hash context on its line stays clear.
#[test]
fn exact_length_hex_keys_under_credential_names_are_detected() {
    let (scanner, allowlist) = defaults();
    // xorshift hex digits, redrawn on a run of three equal digits the placeholder filter drops
    let hex = |length: usize, seed: u64| -> String {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        loop {
            let value: String = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    char::from(b"0123456789abcdef"[(state % 16) as usize])
                })
                .collect();
            if !value
                .as_bytes()
                .windows(3)
                .any(|run| run[0] == run[1] && run[1] == run[2])
            {
                return value;
            }
        }
    };
    for (index, length) in [32, 40, 64].into_iter().enumerate() {
        let value = hex(length, 0x4e00 + index as u64);
        assert!(shannon_entropy(value.as_bytes()) < 4.0, "{length}");
        for (prefix, rule) in [
            ("API_KEY=", API),
            ("docker run -e HF_TOKEN=", TOKEN),
            ("  - webhook_secret: ", SECRET),
        ] {
            assert_detected(
                &scanner,
                &allowlist,
                &format!("{prefix}{value}"),
                &value,
                rule,
            );
        }
        let quoted = format!("api_key = \"{value}\"");
        let start = quoted.find(&value).unwrap();
        assert!(
            scan_text(&quoted, &scanner, &allowlist)
                .iter()
                .any(|found| found.rule_id == API && found.range == (start..start + value.len())),
            "{quoted}"
        );
        // hash context is read from the assignment itself: a digest or a hash word elsewhere
        // on the line cannot veto a named key (round 04 of the review)
        let digest = hex(length, 0x5e00 + index as u64);
        let line = format!("CHECKSUM={digest} API_KEY={value}");
        let start = line.rfind(&value).unwrap();
        assert!(
            scan_text(&line, &scanner, &allowlist)
                .iter()
                .any(|found| found.rule_id == API && found.range == (start..start + value.len())),
            "{line}"
        );
    }
    // a repeated pattern falls under the 2.0-bit hex symbol floor
    assert_clear(
        &scanner,
        &allowlist,
        &format!("API_KEY={}", "ab".repeat(16)),
    );
}

#[test]
fn quoted_forms_keep_working() {
    let (scanner, allowlist) = defaults();
    let value = opaque(32, 0x9e37, ALNUM);
    for (line, rule) in [
        (format!("api_key = \"{value}\""), API),
        (format!("config.api_token = '{value}'"), API),
        (format!("client_secret = \"{value}\""), SECRET),
        (format!("access_token: \"{value}\""), TOKEN),
        (format!("export AUTH_TOKEN=\"{value}\""), TOKEN),
    ] {
        let start = line.find(&value).unwrap();
        let found = scan_text(&line, &scanner, &allowlist);
        assert!(
            found
                .iter()
                .any(|found| found.rule_id == rule && found.range == (start..start + value.len())),
            "{line}: {found:?}"
        );
        assert_eq!(
            redact_text(&line, &scanner, &allowlist),
            masked(&line, &value)
        );
    }
}

#[test]
fn references_expressions_paths_and_near_misses_stay_clear() {
    let (scanner, allowlist) = defaults();
    let value = opaque(24, 0x7777, ALNUM);
    for line in [
        "API_KEY=${API_KEY}".to_owned(),
        "API_KEY=${API_KEY_FROM_THE_VAULT}".to_owned(),
        "access_token: ${ACCESS_TOKEN:-}".to_owned(),
        "GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}".to_owned(),
        "api_key=get_key()".to_owned(),
        "api_key=load_api_key_from(vault_path)".to_owned(),
        "TOKEN=changeme".to_owned(),
        "SECRET_KEY=$(cat f)".to_owned(),
        "SECRET_KEY=$(cat /run/secrets/app_key)".to_owned(),
        "SECRET_KEY=`cat /run/secrets/app_key`".to_owned(),
        "SECRET_KEY=/run/secrets/key".to_owned(),
        "client_secret: /etc/acme-app/secrets/client_secret".to_owned(),
        "export API_TOKEN=$HOME/.config/acme-service/api_token".to_owned(),
        "access_token: ${XDG_STATE_HOME}/acme-service/access_token".to_owned(),
        "API_KEY=your_api_key_here".to_owned(),
        format!("MY_TOKENIZER={value}"),
        "MY_TOKENIZER=bert-base-uncased".to_owned(),
        "token_count: 12".to_owned(),
        format!("token_count: {value}"),
        format!("tokens: {value}"),
        format!("xapi_key={value}"),
        format!("api_key_file={value}"),
        format!("secret_name={value}"),
        format!("xsecret={value}"),
        format!("mytoken={value}"),
        format!("x.API_KEY={value}"),
        format!("self.token = {value}"),
        format!("run --token={value}"),
        format!("ALPHA={value}"),
        value.clone(),
    ] {
        assert_clear(&scanner, &allowlist, &line);
    }
}

#[test]
fn a_quote_backtick_or_paren_in_the_word_rejects_the_arm_instead_of_cutting_it() {
    let (scanner, allowlist) = defaults();
    let value = opaque(24, 0x4242, ALNUM);
    for tail in ["\"x\"", "'x'", "`x`", "(x)"] {
        let line = format!("API_KEY={value}{tail}");
        let word_end = line.len();
        for found in scan_text(&line, &scanner, &allowlist) {
            assert!(
                found.range.end >= word_end,
                "{line}: {found:?} reports a prefix of the word"
            );
        }
    }
}

fn run_with_stdin(env: &IsolatedEnv, args: &[&str], cwd: &Path, stdin: &[u8]) -> Output {
    let mut child = env
        .command()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let _ = input.write_all(stdin);
    drop(input);
    let mut output = child.wait_with_output().unwrap();
    output.stdout = reader.join().unwrap();
    output
}

/// the acceptance lines as one output block, each with its own generated value.
fn acceptance_block(eol: &str) -> (String, Vec<String>) {
    let mut text = String::from("host=localhost");
    text.push_str(eol);
    let mut values = Vec::new();
    for (index, (prefix, suffix, _)) in named_forms().into_iter().enumerate() {
        let value = opaque(24, 0x3000 + index as u64, ALNUM);
        text.push_str(&format!("{prefix}{value}{suffix}{eol}"));
        values.push(value);
    }
    text.push_str(&format!(
        "API_KEY=${{API_KEY}}{eol}SECRET_KEY=/run/secrets/key{eol}"
    ));
    (text, values)
}

#[test]
fn redact_claude_masks_named_values_with_no_config() {
    let env = IsolatedEnv::new();
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    for eol in ["\n", "\r\n"] {
        let (text, values) = acceptance_block(eol);
        let mut expected = text.clone();
        for value in &values {
            expected = masked(&expected, value);
        }
        let payload = serde_json::to_vec(&json!({
            "hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
            "tool_input": {"command": "env"},
            "tool_response": {"stdout": text, "stderr": "", "interrupted": false}
        }))
        .unwrap();
        let output = run_with_stdin(
            &env,
            &["redact-claude", "--stdin-json"],
            env.home(),
            &payload,
        );
        assert_eq!(output.status.code(), Some(0));
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            envelope["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
            json!(expected)
        );
        for value in &values {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(value.as_str()));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(value.as_str()));
        }
    }
}

#[test]
fn check_file_blocks_named_values_with_no_config() {
    let env = IsolatedEnv::new();
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    for (index, (prefix, suffix, rule)) in named_forms().into_iter().enumerate() {
        let value = opaque(24, 0x5000 + index as u64, ALNUM);
        let file = workspace.join("settings.txt");
        std::fs::write(
            &file,
            format!("host=localhost\r\n{prefix}{value}{suffix}\r\n"),
        )
        .unwrap();
        let output = env
            .command()
            .args(["check-file", file.to_str().unwrap()])
            .current_dir(&workspace)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{prefix}: {stderr}");
        assert!(stderr.contains(rule), "{prefix}: {stderr}");
        assert!(!stderr.contains(value.as_str()), "{prefix}: {stderr}");
    }
    let file = workspace.join("settings.txt");
    std::fs::write(
        &file,
        "API_KEY=${API_KEY}\nSECRET_KEY=$(cat f)\nSECRET_KEY=/run/secrets/key\ntoken_count: 12\n",
    )
    .unwrap();
    let clean = env
        .command()
        .args(["check-file", file.to_str().unwrap()])
        .current_dir(&workspace)
        .output()
        .unwrap();
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

#[test]
fn check_codex_blocks_a_named_value_in_a_bash_command() {
    let env = IsolatedEnv::new();
    let workspace = env.home().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let value = opaque(24, 0x6006, ALNUM);
    let run = |command: String| {
        let payload = serde_json::to_vec(&json!({
            "session_id": "session", "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": workspace,
        }))
        .unwrap();
        run_with_stdin(&env, &["check-codex", "--stdin-json"], &workspace, &payload)
    };
    let blocked = run(format!("export GITHUB_TOKEN={value}\ngh release list"));
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert_eq!(blocked.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(TOKEN), "{stderr}");
    assert!(!stderr.contains(value.as_str()), "{stderr}");
    let clean = run("export GITHUB_TOKEN=${GH_TOKEN}\ngh release list".to_owned());
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

#[test]
fn scan_and_audit_report_a_named_value_with_no_config() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let value = opaque(24, 0x8008, ALNUM);
    std::fs::write(
        repo.join("deploy.txt"),
        format!("region=eu-central\nACCESS_TOKEN={value}\n"),
    )
    .unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .env("GIT_CONFIG_GLOBAL", env.git_config_global())
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}");
    };
    git(&["add", "deploy.txt"]);
    for args in [&["scan"][..], &["audit"][..]] {
        let output = env
            .command()
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(TOKEN), "{args:?}: {stderr}");
        assert!(!stderr.contains(value.as_str()), "{args:?}: {stderr}");
    }
}
