//! `http-basic-auth`: selected lowercase slash prose stays clear and a generated credential stays
//! reported on every surface. the prose used to be hidden only where the documentation entropy
//! bonus applied (a doc path scanned with path filters), so each surface is checked on a doc and a
//! plain path. the rule's `base64_credential` check keeps a value only when it decodes to
//! bytes containing a colon and no ascii control; some capitalized prose also passes. the
//! check-codex branch that scans an outside-workspace path
//! without path filters is covered end to end in `codex_hook_tests.rs`.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use common::{
    ALNUM, IsolatedEnv, WINDOWS_1251_C1_RANGE_LETTERS, base64, base64_decode,
    generated_basic_credential, generated_basic_noncredentials, generated_user_pass,
    iso_8859_1_basic_credential, lowercase_slash_basic_credential, reviewed_basic_credentials,
    utf8_basic_credential, windows_1251_basic_credential,
};
use regex::Regex;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, Rule, compile_rules, load_default_rules};
use serde_json::{Value, json};

const RULE: &str = "http-basic-auth";

/// a doc path (bonus applies), plain text, and source.
const PATHS: &[&str] = &["docs/notes.md", "notes.txt", "src/client.rs"];

/// the paths without the documentation bonus, for credentials whose entropy is below 4.0.
const PLAIN_PATHS: &[&str] = &["notes.txt", "src/client.rs"];

const WORDS: &[&str] = &[
    "comments",
    "highlighting",
    "structure",
    "navigation",
    "completion",
    "signatures",
    "formatting",
    "diagnostics",
    "queries",
    "injections",
    "operators",
    "precedence",
    "tokenizer",
    "examples",
    "walkthroughs",
    "interpolation",
];

fn default_rules() -> Vec<Rule> {
    load_default_rules().expect("default rules load")
}

fn surface(rules: &[Rule]) -> (CompiledScanner, CompiledAllowlist) {
    (
        compile_rules(rules).expect("rules compile"),
        build_allowlist(&ProjectConfig::default(), rules).expect("allowlist builds"),
    )
}

fn without_credential_check() -> Vec<Rule> {
    let mut rules = default_rules();
    let rule = rules
        .iter_mut()
        .find(|rule| rule.id == RULE)
        .expect("rule exists");
    assert_eq!(
        rule.base64_credential,
        Some(true),
        "the rule checks its value decodes"
    );
    rule.base64_credential = Some(false);
    rules
}

fn file(path: &str, line: &str) -> DiffFile {
    DiffFile {
        path: path.to_owned(),
        is_new: true,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.as_bytes().to_vec(),
        }],
    }
}

fn reported(
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    path: &str,
    line: &str,
) -> bool {
    scan(&[file(path, line)], scanner, allowlist)
        .iter()
        .any(|finding| finding.rule_id == RULE)
}

fn reported_in_text(scanner: &CompiledScanner, allowlist: &CompiledAllowlist, text: &str) -> bool {
    scan_text(text, scanner, allowlist)
        .iter()
        .any(|found| found.rule_id == RULE)
}

/// every `basic a/b` pair of distinct words whose value reaches the rule's 20-byte length and
/// clears its 3.0 entropy gate, the shape the sightings carried.
fn prose_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for first in WORDS {
        for second in WORDS {
            let value = format!("{first}/{second}");
            if first != second && value.len() >= 20 && shannon_entropy(value.as_bytes()) > 3.0 {
                lines.push(format!("The release keeps Basic {value} stable."));
            }
        }
    }
    assert!(lines.len() >= 40, "only {} prose lines", lines.len());
    lines
}

#[test]
fn prose_word_pairs_fire_without_the_credential_check() {
    // the control: the same lines are reported on every non-doc surface once the check is off,
    // which is what the default rule did before it.
    let (scanner, allowlist) = surface(&without_credential_check());
    for line in prose_lines() {
        assert!(reported(&scanner, &allowlist, "notes.txt", &line), "{line}");
        assert!(reported_in_text(&scanner, &allowlist, &line), "{line}");
    }
}

#[test]
fn prose_word_pairs_are_clear_on_every_library_surface() {
    let (scanner, allowlist) = surface(&default_rules());
    for line in prose_lines() {
        for path in PATHS {
            assert!(
                !reported(&scanner, &allowlist, path, &line),
                "{path}: {line}"
            );
        }
        assert!(!reported_in_text(&scanner, &allowlist, &line), "{line}");
        assert_eq!(redact_text(&line, &scanner, &allowlist), line);
    }
}

/// this fixed word list measures 6/172 capitalized and 5/172 mixed-case residuals with byte-only
/// checks. a 4% ceiling leaves a margin while detecting an increase beyond the accepted residual.
#[test]
fn capitalised_and_mixed_prose_have_a_bounded_residual_on_every_library_surface() {
    let capitalised = |word: &str| format!("{}{}", word[..1].to_uppercase(), &word[1..]);
    let (scanner, allowlist) = surface(&default_rules());
    let (unchecked_scanner, unchecked_allowlist) = surface(&without_credential_check());
    for mixed in [false, true] {
        let (mut fired_before, mut residual) = (0, 0);
        for first in WORDS {
            for second in WORDS {
                let value = format!(
                    "{}/{}",
                    capitalised(first),
                    if mixed {
                        (*second).to_owned()
                    } else {
                        capitalised(second)
                    }
                );
                if first == second || !meets_rule_gates(&value) {
                    continue;
                }
                let line = format!("See Basic {value} in the guide.");
                fired_before += usize::from(reported(
                    &unchecked_scanner,
                    &unchecked_allowlist,
                    "notes.txt",
                    &line,
                ));
                let text_fires = reported_in_text(&scanner, &allowlist, &line);
                residual += usize::from(text_fires);
                for path in PLAIN_PATHS {
                    assert_eq!(
                        reported(&scanner, &allowlist, path, &line),
                        text_fires,
                        "{path}"
                    );
                }
                assert!(!reported(&scanner, &allowlist, PATHS[0], &line) || text_fires);
                assert_eq!(redact_text(&line, &scanner, &allowlist) != line, text_fires);
            }
        }
        assert!(fired_before >= 40, "only {fired_before} fired before");
        assert!(
            residual * 100 <= fired_before * 4,
            "{residual}/{fired_before} residuals, mixed={mixed}"
        );
    }
}

#[test]
fn generated_credentials_are_reported_on_every_library_surface() {
    let (scanner, allowlist) = surface(&default_rules());
    for seed in 0..200 {
        let credential = generated_basic_credential(seed);
        for line in [
            format!("Authorization: Basic {credential}"),
            format!("curl -H 'Authorization: Basic {credential}' https://api.example.com"),
            format!("auth = \"basic {credential}\""),
        ] {
            for path in PATHS {
                assert!(
                    reported(&scanner, &allowlist, path, &line),
                    "{path}: seed {seed}"
                );
            }
            assert!(reported_in_text(&scanner, &allowlist, &line), "seed {seed}");
            assert!(!redact_text(&line, &scanner, &allowlist).contains(&credential));
        }
    }
}

/// the value meets the rule's own gates (20 symbols before the padding, entropy above 3.0), so
/// only the credential check can decide it.
fn meets_rule_gates(value: &str) -> bool {
    value.trim_end_matches('=').len() >= 20 && shannon_entropy(value.as_bytes()) > 3.0
}

fn assert_reported_off_doc_paths(
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    credential: &str,
    paths: &[&str],
    label: &str,
) {
    for line in [
        format!("Authorization: Basic {credential}"),
        format!("curl -H 'Authorization: Basic {credential}' https://api.example.com"),
        format!("auth = \"basic {credential}\""),
    ] {
        for path in paths {
            assert!(reported(scanner, allowlist, path, &line), "{path}: {label}");
        }
        assert!(reported_in_text(scanner, allowlist, &line), "{label}");
        assert!(
            !redact_text(&line, scanner, allowlist).contains(credential),
            "{label}"
        );
    }
}

/// the review's family: printable ascii `user:pass` whose base64 is lowercase letters and slashes
/// only, with colons and punctuation in the password. the earlier lowercase-words value veto
/// matched these values and cleared them.
#[test]
fn lowercase_slash_credentials_round_trip_and_are_reported() {
    let earlier_veto = Regex::new("^[a-z]+(?:/[a-z]+)+$").expect("pattern compiles");
    let (scanner, allowlist) = surface(&default_rules());
    let (mut kept, mut veto_matched) = (0, 0);
    for seed in 0..300 {
        let (user_pass, encoded) = lowercase_slash_basic_credential(seed, 10);
        assert_eq!(base64_decode(&encoded), user_pass.as_bytes(), "seed {seed}");
        assert!(
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'/'),
            "seed {seed}"
        );
        assert!(user_pass.bytes().all(|byte| (0x20..0x7F).contains(&byte)));
        let (_, password) = user_pass.split_once(':').expect("a colon");
        let punctuated = password.contains(':')
            && password
                .bytes()
                .any(|byte| byte.is_ascii_punctuation() && byte != b':');
        if !punctuated || !meets_rule_gates(&encoded) {
            continue;
        }
        kept += 1;
        veto_matched += usize::from(earlier_veto.is_match(&encoded));
        assert_reported_off_doc_paths(
            &scanner,
            &allowlist,
            &encoded,
            PLAIN_PATHS,
            &format!("seed {seed}"),
        );
    }
    assert!(kept >= 200, "only {kept} credentials kept");
    assert!(veto_matched >= 30, "only {veto_matched} matched the veto");
}

/// rfc 7617 allows a utf-8 user and password; the decoded text is not required to be ascii.
#[test]
fn utf8_credentials_round_trip_and_are_reported_on_every_library_surface() {
    let (scanner, allowlist) = surface(&default_rules());
    for seed in 0..200 {
        let (user_pass, encoded) = utf8_basic_credential(seed);
        assert_eq!(base64_decode(&encoded), user_pass.as_bytes(), "seed {seed}");
        assert!(!user_pass.is_ascii(), "seed {seed}");
        assert!(
            shannon_entropy(encoded.as_bytes()) > 4.0,
            "seed {seed} needs the doc path bonus cleared"
        );
        assert_reported_off_doc_paths(
            &scanner,
            &allowlist,
            &encoded,
            PATHS,
            &format!("seed {seed}"),
        );
    }
}

/// random printable user/password pairs: every value that meets the rule's own gates and holds no
/// stopword is reported.
#[test]
fn generated_printable_credentials_are_all_reported() {
    let (scanner, allowlist) = surface(&default_rules());
    let printable: Vec<u8> = (0x20..0x7F).collect();
    let alphabets: [&[u8]; 4] = [
        &printable,
        b"abcdefghijklmnopqrstuvwxyz",
        b"abcdefghijklmnopqrstuvwxyz0123456789-_.:!",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    ];
    let (mut checked, mut stopworded) = (0, 0);
    for alphabet in alphabets {
        for seed in 0..3_000 {
            let user = 1 + (seed % 12) as usize;
            let pass = 6 + (seed % 25) as usize;
            let value = base64(generated_user_pass(seed, alphabet, user, pass).as_bytes());
            if !meets_rule_gates(&value) {
                continue;
            }
            // the rule's stopword step drops a value holding a stopword such as `test`, with or
            // without the credential check; random base64 sometimes spells one.
            if allowlist.contains_stopword(value.as_bytes()) {
                stopworded += 1;
                continue;
            }
            checked += 1;
            let line = format!("Authorization: Basic {value}");
            assert!(
                reported_in_text(&scanner, &allowlist, &line),
                "seed {seed}, length {}",
                value.len()
            );
            assert!(
                reported(&scanner, &allowlist, "notes.txt", &line),
                "seed {seed}"
            );
        }
    }
    assert!(checked > 10_000, "only {checked} credentials checked");
    assert!(
        stopworded * 100 < checked,
        "{stopworded} values held a stopword"
    );
}

/// a credential with its `=` padding stripped is still read; a length of 1 mod 4 and padding that
/// does not complete the last group are no base64.
#[test]
fn padding_is_optional_but_must_complete_the_last_group() {
    let (scanner, allowlist) = surface(&default_rules());
    let unchecked = surface(&without_credential_check());
    let mut paddings = Vec::new();
    for pass in [20, 21, 22] {
        let padded = base64(generated_user_pass(7, ALNUM, 9, pass).as_bytes());
        let unpadded = padded.trim_end_matches('=').to_owned();
        let padding = padded.len() - unpadded.len();
        paddings.push(padding);
        let malformed = match padding {
            // one symbol too many leaves a length of 1 mod 4
            0 => vec![format!("{unpadded}Q"), format!("{unpadded}==")],
            1 => vec![format!("{unpadded}=="), format!("{unpadded}Q=")],
            _ => vec![format!("{unpadded}=")],
        };
        let cases = [(padded, true), (unpadded, true)]
            .into_iter()
            .chain(malformed.into_iter().map(|value| (value, false)));
        for (value, expected) in cases {
            let line = format!("Authorization: Basic {value}");
            let label = format!("padding {padding}, length {}", value.len());
            assert_eq!(
                reported_in_text(&scanner, &allowlist, &line),
                expected,
                "{label}"
            );
            assert!(
                reported_in_text(&unchecked.0, &unchecked.1, &line),
                "unchecked {label}"
            );
            assert_eq!(
                reported(&scanner, &allowlist, "notes.txt", &line),
                expected,
                "{label}"
            );
        }
    }
    paddings.sort_unstable();
    assert_eq!(paddings, [0, 1, 2]);
}

/// the decoded bytes decide the check. a value that decodes to something other than `user:pass`
/// text is dropped while the same value is reported once the check is off, so the check alone
/// decides it. the charset is not inferred, and the user-id may be empty or non-ascii.
#[test]
fn decoded_bytes_decide_the_credential_check() {
    let checked = surface(&default_rules());
    let unchecked = surface(&without_credential_check());
    for seed in 0..50 {
        let user_pass = generated_user_pass(seed, ALNUM, 10, 20);
        // one byte replaced: index 14 is in the password, index 0 in the user-id
        let swap_at = |index: usize, replacement: &[u8]| -> Vec<u8> {
            [
                &user_pass.as_bytes()[..index],
                replacement,
                &user_pass.as_bytes()[index + 1..],
            ]
            .concat()
        };
        let swap = |replacement: &[u8]| swap_at(14, replacement);
        let c1_range_letter =
            WINDOWS_1251_C1_RANGE_LETTERS[seed as usize % WINDOWS_1251_C1_RANGE_LETTERS.len()];
        let password_only = [b":".as_slice(), &swap(&[0xE4])[11..]].concat();
        // (name, bytes, valid utf-8, kept)
        for (name, bytes, utf8, kept) in [
            (
                "no colon",
                user_pass.replace(':', "x").into_bytes(),
                true,
                false,
            ),
            ("tab", swap(b"\t"), true, false),
            ("nul", swap(&[0x00]), true, false),
            ("del", swap(&[0x7F]), true, false),
            (
                "utf-8 c1 / printable windows-1251",
                swap("\u{85}".as_bytes()),
                true,
                true,
            ),
            // an iso-8859-1 letter, and a windows-1251 letter in the iso-8859-1 c1 range
            ("latin-1 letter", swap(&[0xE4]), false, true),
            ("windows-1251 letter", swap(&[c1_range_letter]), false, true),
            ("legacy non-ascii user-id", swap_at(0, &[0xE4]), false, true),
            ("legacy empty user-id", password_only, false, true),
        ] {
            assert_eq!(std::str::from_utf8(&bytes).is_ok(), utf8, "{name}");
            let value = base64(&bytes);
            assert!(meets_rule_gates(&value), "{name}");
            let line = format!("Authorization: Basic {value}");
            let label = format!("{name}, seed {seed}");
            assert_eq!(
                reported_in_text(&checked.0, &checked.1, &line),
                kept,
                "{label}"
            );
            assert_eq!(
                reported(&checked.0, &checked.1, "notes.txt", &line),
                kept,
                "{label}"
            );
            assert!(
                reported_in_text(&unchecked.0, &unchecked.1, &line),
                "{label}"
            );
            assert_eq!(
                !redact_text(&line, &checked.0, &checked.1).contains(&value),
                kept,
                "{label}"
            );
        }
    }
}

#[test]
fn reviewed_legacy_credentials_are_retained_on_every_library_surface() {
    let checked = surface(&default_rules());
    let unchecked = surface(&without_credential_check());
    for seed in 0..200 {
        for (name, _, encoded) in reviewed_basic_credentials(seed) {
            assert!(meets_rule_gates(&encoded), "{name}, seed {seed}");
            assert_reported_off_doc_paths(
                &checked.0,
                &checked.1,
                &encoded,
                paths_for(&encoded),
                &format!("{name}, seed {seed}"),
            );
            let line = format!("Authorization: Basic {encoded}");
            assert!(
                reported_in_text(&unchecked.0, &unchecked.1, &line),
                "{name}, seed {seed}"
            );
        }
    }
}

#[test]
fn noncredentials_drop_on_every_library_surface_and_fire_without_the_check() {
    let checked = surface(&default_rules());
    let unchecked = surface(&without_credential_check());
    for seed in 0..50 {
        for (name, encoded) in generated_basic_noncredentials(seed) {
            assert!(meets_rule_gates(&encoded), "{name}, seed {seed}");
            let line = format!("Authorization: Basic {encoded}");
            for path in PLAIN_PATHS {
                assert!(
                    !reported(&checked.0, &checked.1, path, &line),
                    "{name}, seed {seed}"
                );
                assert!(
                    reported(&unchecked.0, &unchecked.1, path, &line),
                    "{name}, seed {seed}"
                );
            }
            assert!(
                !reported_in_text(&checked.0, &checked.1, &line),
                "{name}, seed {seed}"
            );
            assert!(
                reported_in_text(&unchecked.0, &unchecked.1, &line),
                "{name}, seed {seed}"
            );
            assert!(
                redact_text(&line, &checked.0, &checked.1) == line,
                "{name}, seed {seed}"
            );
            assert!(
                !redact_text(&line, &unchecked.0, &unchecked.1).contains(&encoded),
                "{name}, seed {seed}"
            );
        }
    }
}

/// generated iso-8859-1 and windows-1251 credentials: their bytes are no utf-8, the windows-1251
/// ones always hold a letter of 0x80..=0x9f, and both are reported like the utf-8 family.
fn legacy_charset_credentials() -> Vec<(&'static str, u64, Vec<u8>, String)> {
    let mut credentials = Vec::new();
    for seed in 0..200 {
        for (charset, (bytes, encoded)) in [
            ("iso-8859-1", iso_8859_1_basic_credential(seed)),
            ("windows-1251", windows_1251_basic_credential(seed)),
        ] {
            assert_eq!(base64_decode(&encoded), bytes, "{charset} seed {seed}");
            assert!(
                std::str::from_utf8(&bytes).is_err(),
                "{charset} seed {seed}"
            );
            assert!(
                !bytes.iter().any(u8::is_ascii_control),
                "{charset} seed {seed}"
            );
            assert_eq!(
                bytes.iter().any(|byte| (0x80..=0x9F).contains(byte)),
                charset == "windows-1251",
                "{charset} seed {seed}"
            );
            assert!(meets_rule_gates(&encoded), "{charset} seed {seed}");
            credentials.push((charset, seed, bytes, encoded));
        }
    }
    credentials
}

/// the documentation bonus lifts the entropy gate to 4.0 on a doc path scanned with path filters,
/// so a value below it is checked on the plain paths only, as on base.
fn paths_for(encoded: &str) -> &'static [&'static str] {
    if shannon_entropy(encoded.as_bytes()) > 4.0 {
        PATHS
    } else {
        PLAIN_PATHS
    }
}

#[test]
fn legacy_charset_credentials_round_trip_and_are_reported_on_every_library_surface() {
    let (scanner, allowlist) = surface(&default_rules());
    let mut on_doc_paths = 0;
    for (charset, seed, _, encoded) in legacy_charset_credentials() {
        let paths = paths_for(&encoded);
        on_doc_paths += usize::from(paths.len() == PATHS.len());
        assert_reported_off_doc_paths(
            &scanner,
            &allowlist,
            &encoded,
            paths,
            &format!("{charset} seed {seed}"),
        );
    }
    assert!(on_doc_paths >= 300, "only {on_doc_paths} on doc paths");
}

fn run_hook(env: &IsolatedEnv, args: &[&str], payload: &Value, cwd: &Path) -> Output {
    let mut child = env
        .command()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sekretbarilo");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("wait on sekretbarilo")
}

#[test]
fn check_file_clears_prose_and_blocks_a_credential_on_doc_and_plain_paths() {
    let env = IsolatedEnv::new();
    let workspace = env.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let prose = "The release keeps Basic comments/highlighting stable.";
    let credential = format!("Authorization: Basic {}", generated_basic_credential(7));
    for name in ["report.md", "report.txt"] {
        for (line, expected) in [(prose, 0), (credential.as_str(), 2)] {
            let path = workspace.join(name);
            std::fs::write(&path, format!("{line}\n")).unwrap();
            let payload = json!({"tool_input": {"file_path": path}, "cwd": workspace});
            let output = run_hook(&env, &["check-file", "--stdin-json"], &payload, &workspace);
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn redact_claude_leaves_prose_and_masks_a_credential_in_bash_output() {
    let env = IsolatedEnv::new();
    let workspace = env.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bash = |stdout: &str| {
        json!({
            "hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
            "tool_input": {"command": "cat report.md"},
            "tool_response": {"stdout": stdout, "stderr": "", "interrupted": false},
        })
    };
    let prose = "The release keeps Basic comments/highlighting stable.\n";
    let output = run_hook(
        &env,
        &["redact-claude", "--stdin-json"],
        &bash(prose),
        &workspace,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "prose was rewritten");

    let credential = generated_basic_credential(11);
    let line = format!("Authorization: Basic {credential}\n");
    let output = run_hook(
        &env,
        &["redact-claude", "--stdin-json"],
        &bash(&line),
        &workspace,
    );
    assert_eq!(output.status.code(), Some(0));
    let replaced: Value = serde_json::from_slice(&output.stdout).expect("replacement envelope");
    let stdout = replaced["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .expect("replaced stdout");
    assert!(!stdout.contains(&credential), "credential left in output");
}

/// a lowercase-slash credential (entropy below 4.0, so on a plain path), a utf-8 credential (on a
/// doc path as well), and iso-8859-1 and windows-1251 credentials (on a doc path where their
/// entropy clears the bonus), through the check-file and redact-claude binaries.
fn hook_regression_credentials() -> Vec<(String, &'static [&'static str])> {
    let (_, lowercase_slash) = lowercase_slash_basic_credential(5, 10);
    let (_, utf8) = utf8_basic_credential(5);
    assert!(meets_rule_gates(&lowercase_slash) && shannon_entropy(utf8.as_bytes()) > 4.0);
    let mut credentials: Vec<(String, &'static [&'static str])> = vec![
        (lowercase_slash, &["report.txt"]),
        (utf8, &["report.txt", "report.md"]),
    ];
    // four seeds, each in both charsets
    for (_, _, _, encoded) in legacy_charset_credentials().into_iter().take(8) {
        let names: &'static [&'static str] = if shannon_entropy(encoded.as_bytes()) > 4.0 {
            &["report.txt", "report.md"]
        } else {
            &["report.txt"]
        };
        credentials.push((encoded, names));
    }
    for seed in 0..2 {
        for (_, _, encoded) in reviewed_basic_credentials(seed) {
            assert!(shannon_entropy(encoded.as_bytes()) > 4.0);
            credentials.push((encoded, &["report.txt", "report.md"]));
        }
    }
    credentials
}

#[test]
fn check_file_blocks_lowercase_slash_utf8_and_legacy_charset_credentials() {
    let env = IsolatedEnv::new();
    let workspace = env.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    for (credential, names) in hook_regression_credentials() {
        for name in names {
            let path = workspace.join(name);
            std::fs::write(&path, format!("Authorization: Basic {credential}\n")).unwrap();
            let payload = json!({"tool_input": {"file_path": path}, "cwd": workspace});
            let output = run_hook(&env, &["check-file", "--stdin-json"], &payload, &workspace);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{name}: {stderr}");
            assert!(stderr.contains("rule: http-basic-auth"), "{name}: {stderr}");
            assert!(!stderr.contains(&credential), "{name}: credential leaked");
        }
    }
}

#[test]
fn redact_claude_masks_lowercase_slash_utf8_and_legacy_charset_credentials() {
    let env = IsolatedEnv::new();
    let workspace = env.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    for (credential, _) in hook_regression_credentials() {
        let payload = json!({
            "hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
            "tool_input": {"command": "cat report.txt"},
            "tool_response": {
                "stdout": format!("Authorization: Basic {credential}\n"),
                "stderr": "", "interrupted": false,
            },
        });
        let output = run_hook(
            &env,
            &["redact-claude", "--stdin-json"],
            &payload,
            &workspace,
        );
        assert_eq!(output.status.code(), Some(0));
        let replaced: Value = serde_json::from_slice(&output.stdout).expect("replacement envelope");
        let stdout = replaced["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
            .as_str()
            .expect("replaced stdout");
        assert!(!stdout.contains(&credential), "credential left in output");
    }
}

#[test]
fn check_file_and_redact_claude_drop_generated_noncredentials() {
    let env = IsolatedEnv::new();
    let workspace = env.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    for (name, value) in generated_basic_noncredentials(5) {
        let line = format!("Authorization: Basic {value}\n");
        for filename in ["report.txt", "report.md"] {
            let path = workspace.join(filename);
            std::fs::write(&path, &line).unwrap();
            let payload = json!({"tool_input": {"file_path": path}, "cwd": workspace});
            let output = run_hook(&env, &["check-file", "--stdin-json"], &payload, &workspace);
            assert_eq!(output.status.code(), Some(0), "{name}, {filename}");
        }
        let payload = json!({
            "hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": workspace,
            "tool_input": {"command": "fixture"},
            "tool_response": {"stdout": line, "stderr": "", "interrupted": false},
        });
        let output = run_hook(
            &env,
            &["redact-claude", "--stdin-json"],
            &payload,
            &workspace,
        );
        assert_eq!(output.status.code(), Some(0), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
    }
}
