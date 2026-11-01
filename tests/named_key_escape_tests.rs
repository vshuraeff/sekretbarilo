//! named-key contextual rules on json-printed command output, where a line break is the literal
//! `\n` (or `\r\n`, `\t`) escape: every unquoted value under a credential name is a finding of its
//! rule with exactly its range, on the text surface of the agent hooks and on the diff surface,
//! whether it is the first or a later assignment of the output. every value is generated here, so
//! the repository never stores one.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn defaults() -> (CompiledScanner, CompiledAllowlist) {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    (compile_rules(&rules).unwrap(), allowlist)
}

/// 32 random alphanumeric bytes, an opaque credential of the kind every rule here reads.
fn value(seed: u64) -> String {
    let mut state = seed | 1;
    (0..32)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(ALNUM[(state >> 58) as usize % ALNUM.len()])
        })
        .collect()
}

fn diff_file(text: &str) -> DiffFile {
    DiffFile {
        path: "deploy/output.log".to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: text
            .lines()
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    }
}

/// the failures of one text: each value missing a finding of `rule` with exactly its range on
/// the text surface or its bytes on the diff surface, and a redaction that does not replace
/// exactly the values.
fn misses(text: &str, rule: &str, values: &[&str]) -> Vec<String> {
    let (scanner, allowlist) = defaults();
    let found = scan_text(text, &scanner, &allowlist);
    let findings = scan(&[diff_file(text)], &scanner, &allowlist);
    let mut failures = Vec::new();
    let mut expected = text.to_string();
    for (index, value) in values.iter().enumerate() {
        let start = text.find(value).unwrap();
        if !found
            .iter()
            .any(|matched| matched.rule_id == rule && matched.range == (start..start + value.len()))
        {
            failures.push(format!(
                "{rule}: text scan missed value #{} in {text:?}; found {:?}",
                index + 1,
                found
                    .iter()
                    .map(|matched| (&matched.rule_id, &matched.range))
                    .collect::<Vec<_>>()
            ));
        }
        if !findings
            .iter()
            .any(|finding| finding.rule_id == rule && finding.matched_value == value.as_bytes())
        {
            failures.push(format!(
                "{rule}: diff scan missed value #{} in {text:?}",
                index + 1
            ));
        }
        expected = expected.replace(value, "[REDACTED]");
    }
    if redact_text(text, &scanner, &allowlist) != expected {
        failures.push(format!(
            "{rule}: redaction of {text:?} is not exactly the values"
        ));
    }
    failures
}

/// the json-printed shapes of two consecutive unquoted assignments, `{N1}`/`{N2}` the names and
/// `{A}`/`{B}` the values.
const SHAPES: &[&str] = &[
    r#"{"stdout":"{N1}={A}\n{N2}={B}"}"#,
    r#"{"stdout": "x\n{N1}={A}\n{N2}={B}\n"}"#,
    r#"{"stdout": "x\r\n{N1}={A}\r\n{N2}={B}\r\n"}"#,
    r#"{"stdout": "export {N1}={A}\nexport {N2}={B}"}"#,
    r#"{"stdout": "{N1}={A}\t{N2}={B}"}"#,
];

/// rule id and two names its unquoted arm reads.
const RULES: &[(&str, &str, &str)] = &[
    (
        "generic-secret-assignment",
        "DJANGO_SECRET_KEY",
        "client_secret",
    ),
    ("generic-api-key", "STRIPE_API_KEY", "api_key"),
    ("generic-token-assignment", "GITHUB_TOKEN", "accessToken"),
];

/// json-printed shapes of one unquoted assignment, `{N1}` the name and `{A}` the value: alone in
/// the string, after an escaped line break, before one, and as a yaml `name: value` line.
const SINGLE_SHAPES: &[&str] = &[
    r#"{"stdout":"{N1}={A}"}"#,
    r#"{"stdout": "x\n{N1}={A}"}"#,
    r#"{"stdout": "x\n{N1}={A}\n", "rc": 0}"#,
    r#"{"stdout": "x\n{N1}: {A}\ny: 1"}"#,
    r#"["{N1}={A}", "PATH=/usr/bin"]"#,
];

#[test]
fn one_unquoted_named_value_in_json_printed_output_is_detected() {
    let first = value(0x5EED_1005);
    let mut failures = Vec::new();
    for (rule, n1, _) in RULES {
        for shape in SINGLE_SHAPES {
            let text = shape.replace("{N1}", n1).replace("{A}", &first);
            failures.extend(misses(&text, rule, &[&first]));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// an escape ends the value but lends it no length, a value that is a path, a reference or the
/// prefix of a quoted word stays what it was, and a closing quote outside any string ends nothing.
#[test]
fn escaped_shapes_that_are_no_credential_stay_clear() {
    let token = value(0x5EED_1006);
    let short = &token[..10];
    let (scanner, allowlist) = defaults();
    for text in [
        format!(r#"{{"stdout":"API_KEY={short}\n{token}"}}"#),
        format!(r#"{{"stdout":"GITHUB_TOKEN={short}\tx"}}"#),
        r#"{"stdout":"x\nSECRET_KEY=/run/secrets/django/key\n"}"#.to_string(),
        r#"{"stdout":"x\nAPI_KEY=${STRIPE_API_KEY_FROM_VAULT}\n"}"#.to_string(),
        format!(r#"{{"stdout":"x\nAPI_KEY={token}"x}}"#),
        format!(r#"API_KEY={token}" rest"#),
        format!(r#"x\"API_KEY={token}\""#),
    ] {
        let found = scan_text(&text, &scanner, &allowlist);
        assert!(
            found.is_empty(),
            "unexpected finding in {text:?}: {found:?}"
        );
        let findings = scan(&[diff_file(&text)], &scanner, &allowlist);
        assert!(findings.is_empty(), "unexpected diff finding in {text:?}");
    }
}

/// the same two assignments on two real lines: the baseline the escaped shapes must match.
#[test]
fn consecutive_unquoted_named_values_on_real_lines_are_each_detected() {
    let (first, second) = (value(0x5EED_1001), value(0x5EED_1002));
    let mut failures = Vec::new();
    for (rule, n1, n2) in RULES {
        let text = format!("{n1}={first}\n{n2}={second}\n");
        failures.extend(misses(&text, rule, &[&first, &second]));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// the unquoted password value ends at a `\n`, `\r` or `\t` escape as the other named values do,
/// so two passwords of json-printed output are two findings and the name between them stays.
#[test]
fn consecutive_unquoted_passwords_behind_literal_escapes_are_each_detected() {
    let (first, second) = (value(0x5EED_1007), value(0x5EED_1008));
    let mut failures = Vec::new();
    for shape in SHAPES {
        let text = shape
            .replace("{N1}", "DB_PASSWORD")
            .replace("{N2}", "ADMIN_PASSWORD")
            .replace("{A}", &first)
            .replace("{B}", &second);
        failures.extend(misses(
            &text,
            "generic-password-assignment",
            &[&first, &second],
        ));
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn consecutive_unquoted_named_values_behind_literal_escapes_are_each_detected() {
    let (first, second) = (value(0x5EED_1003), value(0x5EED_1004));
    let mut failures = Vec::new();
    for (rule, n1, n2) in RULES {
        for shape in SHAPES {
            let text = shape
                .replace("{N1}", n1)
                .replace("{N2}", n2)
                .replace("{A}", &first)
                .replace("{B}", &second);
            failures.extend(misses(&text, rule, &[&first, &second]));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
