//! search-pattern alternations and the word-structure step of `generic-high-entropy-value`.
//!
//! an alternation of words or short ids is exempt on the file and the text surface alike, while
//! one long opaque item keeps the whole value reported. every opaque value here is generated.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use sekretbarilo::scanner::wordshape::is_word_structured;
use std::path::Path;
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
const WORDSHAPE: &str = "exempt:wordshape";
const PATH: &str = "notes/search.txt";

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    compile_rules(&load_default_rules().expect("default rules load"))
        .expect("default rules compile")
});

fn allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().expect("default allowlist")
}

fn traced() -> CompiledAllowlist {
    let mut al = allowlist();
    al.trace_exemptions = true;
    al
}

/// xorshift64* over base62, so the opaque items are identical on every run.
fn base62(length: usize, state: &mut u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            *state ^= *state >> 12;
            *state ^= *state << 25;
            *state ^= *state >> 27;
            let next = state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32;
            char::from(ALPHABET[next as usize % ALPHABET.len()])
        })
        .collect()
}

/// the same pattern body quoted as shell, python, rust, js and json tool input write it.
fn quoted_forms(body: &str) -> Vec<String> {
    vec![
        format!("rg --regexp='{body}' src/"),
        format!("PATTERN = \"{body}\""),
        format!("NOISE = re.compile(r\"{body}\")"),
        format!("let pattern = Regex::new(r\"{body}\")?;"),
        format!("const filter = {{ pattern: '{body}' }};"),
        format!("{{\"pattern\": \"{body}\", \"path\": \"src\"}}"),
    ]
}

fn make_file(line: &str) -> DiffFile {
    DiffFile {
        path: PATH.to_owned(),
        is_new: false,
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

fn scan_line(line: &str, al: &CompiledAllowlist) -> Vec<Finding> {
    scan(&[make_file(line)], &SCANNER, al)
}

/// the line is clean on both surfaces, and the trace names the word step for the whole body.
fn assert_exempt(line: &str, body: &str) {
    let al = allowlist();
    let findings = scan_line(line, &al);
    assert!(
        findings.is_empty(),
        "diff scan reported {findings:?} :: {line}"
    );
    let matches = scan_text(line, &SCANNER, &al);
    assert!(
        matches.is_empty(),
        "text scan reported {matches:?} :: {line}"
    );
    assert_eq!(
        redact_text(line, &SCANNER, &al),
        line,
        "redaction :: {line}"
    );

    let traced = scan_line(line, &traced());
    assert!(
        traced
            .iter()
            .any(|finding| finding.rule_id == WORDSHAPE && finding.matched_value == body.as_bytes()),
        "no {WORDSHAPE} trace for {body}, got {traced:?} :: {line}"
    );
    assert!(
        traced.iter().all(|finding| finding.rule_id != ENTROPY),
        "tracing reintroduced a finding :: {line}"
    );
}

/// the whole body is reported on both surfaces and masked by redaction.
fn assert_reported(line: &str, body: &str) {
    let al = allowlist();
    let findings = scan_line(line, &al);
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == ENTROPY && finding.matched_value == body.as_bytes()),
        "diff scan missed {body}, got {findings:?} :: {line}"
    );
    let start = line.find(body).expect("body occurs in the line");
    let matches = scan_text(line, &SCANNER, &al);
    assert!(
        matches
            .iter()
            .any(|matched| matched.rule_id == ENTROPY
                && matched.range == (start..start + body.len())),
        "text scan missed {body}, got {matches:?} :: {line}"
    );
    assert_eq!(
        redact_text(line, &SCANNER, &al),
        line.replacen(body, "[REDACTED]", 1),
        "redaction :: {line}"
    );
}

#[test]
fn fixture_alternations_are_claimed_by_the_word_step() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("false_positives")
        .join("alternation.txt");
    let text = std::fs::read_to_string(&path).expect("alternation fixture");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with("# "))
    {
        checked += 1;
        assert!(
            scan_line(line, &allowlist()).is_empty(),
            "reported :: {line}"
        );
        let traced = scan_line(line, &traced());
        assert!(
            traced.iter().all(|finding| finding.rule_id != ENTROPY),
            "tracing reintroduced a finding :: {line}"
        );
        let claimed: Vec<&Finding> = traced
            .iter()
            .filter(|finding| finding.rule_id == WORDSHAPE)
            .collect();
        assert!(
            !claimed.is_empty(),
            "no {WORDSHAPE} trace, got {traced:?} :: {line}"
        );
        // each claimed body clears the entropy gate, so it was a finding before the word step.
        for finding in claimed {
            assert!(
                shannon_entropy(&finding.matched_value) >= 4.0,
                "below the entropy gate :: {line}"
            );
        }
    }
    assert!(checked >= 8, "checked only {checked} fixture lines");
}

#[test]
fn generated_short_id_alternations_are_exempt_in_every_quoting() {
    let mut state = 0x9E37_79B9_7F4A_7C15;
    let ids: Vec<String> = (0..4).map(|_| base62(16, &mut state)).collect();
    for body in [
        ids[..3].join("|"),
        format!("(?:{})", ids.join("|")),
        format!(r"\b({}|{})\b", ids[0], ids[1]),
        format!("^({}|legacy_api_v2|DeprecationWarning)$", ids[2]),
    ] {
        assert!(
            shannon_entropy(body.as_bytes()) >= 4.0,
            "below the gate: {body}"
        );
        for line in quoted_forms(&body) {
            assert_exempt(&line, &body);
        }
    }
}

#[test]
fn switching_the_layer_off_restores_the_finding() {
    let mut state = 0x5555_5555_5555_5555;
    let ids: Vec<String> = (0..3).map(|_| base62(16, &mut state)).collect();
    let body = ids.join("|");
    let mut off = allowlist();
    off.exemption_layer = false;
    for line in [
        format!("rg --regexp='{body}' src/"),
        format!("{{\"pattern\": \"{body}\", \"path\": \"src\"}}"),
    ] {
        assert!(
            scan_line(&line, &allowlist()).is_empty(),
            "reported :: {line}"
        );
        assert!(
            scan_line(&line, &off)
                .iter()
                .any(|finding| finding.rule_id == ENTROPY
                    && finding.matched_value == body.as_bytes()),
            "layer off missed {body} :: {line}"
        );
    }
}

#[test]
fn one_long_opaque_item_keeps_the_alternation_reported() {
    let mut state = 0x2545_F491_4F6C_DD1D;
    let opaque = base62(32, &mut state);
    let split = base62(40, &mut state);
    let id = base62(16, &mut state);
    for body in [
        format!("{opaque}|word"),
        format!("word|{opaque}"),
        opaque.clone(),
        format!("{}|{}", &split[..20], &split[20..]),
        format!("^({opaque}|word)$"),
        format!(r"\b(?:legacy_api|{opaque})\b"),
        format!("{id}|DeprecationWarning|{opaque}"),
    ] {
        assert!(!is_word_structured(body.as_bytes()), "{body}");
        for line in quoted_forms(&body) {
            assert_reported(&line, &body);
        }
    }
}

#[test]
fn regex_syntax_inside_an_item_is_not_a_word_alternation() {
    let mut state = 0x0123_4567_89AB_CDEF;
    let id = base62(16, &mut state);
    for body in [
        format!(r"{id}\|DeprecationWarning|removeAfter"),
        format!("{id}||DeprecationWarning"),
        format!("{id}.*|DeprecationWarning"),
        format!("(?i){id}|DeprecationWarning"),
        format!("({id}|legacy)(_api|_client)"),
    ] {
        assert!(!is_word_structured(body.as_bytes()), "{body}");
        let traced = scan_line(&format!("rg --regexp='{body}' src/"), &traced());
        assert!(
            traced.iter().all(|finding| finding.rule_id != WORDSHAPE),
            "unexpected {WORDSHAPE} trace for {body}"
        );
    }
}

#[test]
fn a_pipe_inside_a_single_case_letter_run_keeps_the_token_reported() {
    let uppercase: String = (b'A'..=b'Z').take(24).map(char::from).collect();
    for token in [uppercase.clone(), uppercase.to_ascii_lowercase()] {
        let body = format!("{}|{}", &token[..7], &token[7..]);
        assert!(shannon_entropy(body.as_bytes()) >= 4.0, "{body}");
        for line in quoted_forms(&body) {
            assert_reported(&line, &body);
        }
    }
}
