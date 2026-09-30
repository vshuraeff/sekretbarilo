//! fixture-driven corpus of real-world shapes.
//!
//! `tests/fixtures/false_positives/*.txt` holds one shape per line that must produce no finding.
//! `tests/fixtures/true_positives/*.txt` holds `<rule id>` TAB `<line>` pairs that must produce a
//! finding of that rule covering the value. every line is synthetic, and an opaque value is written
//! as a placeholder that this file expands, so the repository never stores one.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, SourcePosture, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// legacy shapes use an ordinary data path, exempt from nothing and scanned in full posture.
const FIXTURE_PATH: &str = "corpus/shapes.txt";

/// a false-positive file describes a class, so it carries at least this many distinct shapes.
const MIN_SHAPES_PER_CLASS: usize = 8;

/// a floor under the whole corpus, so a deleted file cannot silently empty the suite.
const MIN_TOTAL_SHAPES: usize = 100;

const SUPPORTED_PLACEHOLDERS: &[&str] = &[
    "S32", "S36", "S40", "HEX32", "HEX40", "HEX64", "B64_44", "UUID",
];

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    compile_rules(&load_default_rules().expect("default rules load"))
        .expect("default rules compile")
});

static ALLOWLIST: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let rules = load_default_rules().expect("default rules load");
    build_allowlist(&ProjectConfig::default(), &rules).expect("default allowlist")
});

// deterministic generators. the corpus stores placeholders, so the values below are the only
// opaque bytes in the suite and they are identical on every machine and every run.

const GENERATOR_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// xorshift64*
fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    *state = (*state).wrapping_mul(0x2545_F491_4F6C_DD1D);
    *state
}

fn hex(length: usize) -> String {
    let mut state = GENERATOR_SEED;
    (0..length)
        .map(|_| char::from_digit((next(&mut state) >> 60) as u32, 16).expect("hex digit"))
        .collect()
}

/// alternating A-Z / a-z by index, with a digit at every fifth one. no word structure, entropy
/// above the tier-3 gate, and the three character classes the password heuristic asks for.
fn sequence(length: usize) -> String {
    (0..length)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + (index % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

/// a base64 body, ending in the padding a 32-byte digest carries.
fn base64_body(length: usize) -> String {
    let mut state = GENERATOR_SEED ^ 0x5555_5555_5555_5555;
    let mut value: String = (0..length - 1)
        .map(|_| char::from(B64_ALPHABET[(next(&mut state) >> 58) as usize]))
        .collect();
    value.push('=');
    value
}

fn uuid() -> String {
    let raw = hex(32);
    format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    )
}

fn placeholder_value(name: &str) -> Option<String> {
    match name {
        "S32" => Some(sequence(32)),
        "S36" => Some(sequence(36)),
        "S40" => Some(sequence(40)),
        "HEX32" => Some(hex(32)),
        "HEX40" => Some(hex(40)),
        "HEX64" => Some(hex(64)),
        "B64_44" => Some(base64_body(44)),
        "UUID" => Some(uuid()),
        _ => None,
    }
}

/// the placeholder grammar. a brace group named like a placeholder must be one the expander knows,
/// while `${TOKEN}` and `{{ secrets.X }}` are ordinary fixture text and are left alone.
fn looks_like_placeholder(name: &str) -> bool {
    if name == "UUID" {
        return true;
    }
    ["S", "HEX", "B64_"].into_iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

struct Expansion {
    text: String,
    /// byte ranges of the expanded values inside `text`
    spans: Vec<Range<usize>>,
}

fn expand(line: &str) -> Expansion {
    assert!(line.is_ascii(), "fixture lines are ascii: {line}");
    let bytes = line.as_bytes();
    let mut text = String::with_capacity(line.len());
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some(offset) = line[index + 1..].find('}')
        {
            let name = &line[index + 1..index + 1 + offset];
            if let Some(value) = placeholder_value(name) {
                let start = text.len();
                text.push_str(&value);
                spans.push(start..text.len());
                index += offset + 2;
                continue;
            }
            assert!(
                !looks_like_placeholder(name),
                "unknown placeholder {{{name}}}, supported: {SUPPORTED_PLACEHOLDERS:?}"
            );
        }
        text.push(char::from(bytes[index]));
        index += 1;
    }
    Expansion { text, spans }
}

/// every brace group of a line, whether or not it is a placeholder.
fn brace_groups(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some(offset) = line[index + 1..].find('}')
        {
            names.push(&line[index + 1..index + 1 + offset]);
            index += offset + 2;
            continue;
        }
        index += 1;
    }
    names
}

fn corpus_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(kind)
}

fn corpus_files(kind: &str) -> Vec<PathBuf> {
    let dir = corpus_dir(kind);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()))
        .map(|entry| entry.expect("fixture directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixtures in {}", dir.display());
    files
}

/// a comment is `#` followed by a space, a tab, or nothing, so `#include` and `#id` stay shapes.
fn is_skipped(line: &str) -> bool {
    line.trim().is_empty() || line == "#" || line.starts_with("# ") || line.starts_with("#\t")
}

/// the shapes of one fixture file, with their 1-based line numbers. leading whitespace is part of
/// the shape: an indented line matches different alternatives of the tier-3 rule than a bare one.
fn shapes(path: &Path) -> Vec<(usize, String)> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.to_owned()))
        .filter(|(_, line)| !is_skipped(line))
        .collect()
}

fn label(path: &Path) -> String {
    path.file_name()
        .expect("fixture file name")
        .to_string_lossy()
        .into_owned()
}

fn fixture_file(line: &str) -> DiffFile {
    DiffFile {
        path: FIXTURE_PATH.to_owned(),
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

fn scanned_rules(line: &str) -> Vec<String> {
    scan(&[fixture_file(line)], &SCANNER, &ALLOWLIST)
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

fn go_tag_fixture(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "go-struct-tag.txt")
}

fn scan_go_tag(line: &str) -> Vec<sekretbarilo::scanner::engine::Finding> {
    let mut file = fixture_file(line);
    file.path = "pkg/sample.go".to_owned();
    let mut allowlist = CompiledAllowlist::default_allowlist().expect("default allowlist");
    allowlist.source_posture = Some(SourcePosture::Literals);
    scan(&[file], &SCANNER, &allowlist)
}

/// rule and byte range of every file finding, on the same surface as the scan assertions.
fn reported_spans(line: &str) -> Vec<String> {
    scan(&[fixture_file(line)], &SCANNER, &ALLOWLIST)
        .iter()
        .map(|matched| {
            let value = &matched.matched_value;
            let start = (!value.is_empty())
                .then(|| {
                    line.as_bytes()
                        .windows(value.len())
                        .position(|window| window == value)
                })
                .flatten();
            match start {
                Some(start) => format!("{} at {}..{}", matched.rule_id, start, start + value.len()),
                None => format!("{} with unmatched raw value {value:?}", matched.rule_id),
            }
        })
        .collect()
}

/// split `<rule id>` TAB `<line>`.
fn expectation<'a>(path: &Path, number: usize, line: &'a str) -> (&'a str, &'a str) {
    let (rule_id, shape) = line.split_once('\t').unwrap_or_else(|| {
        panic!(
            "{}:{number}: a true-positive line is `<rule id>` TAB `<line>`: {line}",
            label(path)
        )
    });
    (rule_id, shape)
}

#[test]
fn false_positive_corpus_produces_no_findings() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for path in corpus_files("false_positives") {
        let shapes = shapes(&path);
        assert!(
            shapes.len() >= MIN_SHAPES_PER_CLASS,
            "{} carries {} shapes, at least {MIN_SHAPES_PER_CLASS} are expected",
            label(&path),
            shapes.len()
        );
        for (number, line) in shapes {
            checked += 1;
            let expanded = expand(&line);
            let go_tag = go_tag_fixture(&path);
            let rules = if go_tag {
                scan_go_tag(&expanded.text)
                    .into_iter()
                    .map(|finding| finding.rule_id)
                    .collect()
            } else {
                scanned_rules(&expanded.text)
            };
            if !rules.is_empty() {
                let report = if go_tag {
                    format!("{rules:?}")
                } else {
                    format!("{:?}", reported_spans(&expanded.text))
                };
                failures.push(format!(
                    "{}:{number}: scan reported {report} :: {line}",
                    label(&path),
                ));
            }
            if !go_tag && redact_text(&expanded.text, &SCANNER, &ALLOWLIST) != expanded.text {
                failures.push(format!(
                    "{}:{number}: redact_text masked the line via {:?} :: {line}",
                    label(&path),
                    reported_spans(&expanded.text)
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} false-positive shape(s) regressed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked >= MIN_TOTAL_SHAPES,
        "the corpus shrank to {checked}"
    );
}

#[test]
fn true_positive_corpus_is_detected() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for path in corpus_files("true_positives") {
        for (number, line) in shapes(&path) {
            checked += 1;
            let (rule_id, shape) = expectation(&path, number, &line);
            let expanded = expand(shape);
            let findings = if go_tag_fixture(&path) {
                scan_go_tag(&expanded.text)
            } else {
                scan(&[fixture_file(&expanded.text)], &SCANNER, &ALLOWLIST)
            };
            let rules: Vec<&str> = findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect();
            if !rules.contains(&rule_id) {
                failures.push(format!(
                    "{}:{number}: scan reported {:?}, expected {rule_id} :: {shape}",
                    label(&path),
                    reported_spans(&expanded.text)
                ));
                continue;
            }
            // the diff surface reports matched bytes rather than a range, so covering means some
            // finding of the rule carries the whole expanded value.
            for span in &expanded.spans {
                let value = expanded.text[span.clone()].as_bytes();
                let carried = findings.iter().any(|finding| {
                    finding.rule_id == rule_id
                        && finding
                            .matched_value
                            .windows(value.len())
                            .any(|window| window == value)
                });
                if !carried {
                    failures.push(format!(
                        "{}:{number}: no {rule_id} finding carries the value at {span:?} :: {shape}",
                        label(&path)
                    ));
                }
            }
            let matches = scan_text(&expanded.text, &SCANNER, &ALLOWLIST);
            let spans: Vec<Range<usize>> = matches
                .iter()
                .filter(|matched| matched.rule_id == rule_id)
                .map(|matched| matched.range.clone())
                .collect();
            for span in &expanded.spans {
                if !spans
                    .iter()
                    .any(|found| found.start <= span.start && found.end >= span.end)
                {
                    failures.push(format!(
                        "{}:{number}: no {rule_id} span covers the value at {span:?}, got {spans:?} :: {shape}",
                        label(&path)
                    ));
                }
            }
            let redacted = redact_text(&expanded.text, &SCANNER, &ALLOWLIST);
            if label(&path) == "call-argument-secrets.txt" {
                assert_eq!(spans, expanded.spans, "exact call spans: {number}: {shape}");
                assert_eq!(
                    matches.len(),
                    expanded.spans.len(),
                    "call duplicates: {shape}"
                );
                assert_eq!(
                    findings.len(),
                    expanded.spans.len(),
                    "diff call duplicates: {shape}"
                );
                let mut expected = expanded.text.clone();
                for span in expanded.spans.iter().rev() {
                    expected.replace_range(span.clone(), "[REDACTED]");
                }
                assert_eq!(redacted, expected, "call delimiters: {number}: {shape}");
            }
            if expanded.spans.is_empty() {
                if redacted == expanded.text {
                    failures.push(format!(
                        "{}:{number}: redact_text left the line untouched :: {shape}",
                        label(&path)
                    ));
                }
            } else {
                for span in &expanded.spans {
                    if redacted.contains(&expanded.text[span.clone()]) {
                        failures.push(format!(
                            "{}:{number}: redact_text left the value in place :: {shape}",
                            label(&path)
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} true-positive shape(s) regressed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checked > 0, "the true-positive corpus is empty");
}

#[test]
fn source_posture_fixture_matrix() {
    const RULE: &str = "generic-high-entropy-value";
    for (name, source_path, test_path) in [
        ("rust", "src/sample.rs", "tests/sample.rs"),
        ("go", "pkg/sample.go", "tests/sample.go"),
        ("python", "pkg/sample.py", "tests/sample.py"),
        ("javascript", "src/sample.js", "tests/sample.js"),
        ("javascript", "src/sample.ts", "tests/sample.ts"),
        ("javascript", "src/sample.tsx", "tests/sample.tsx"),
        ("c", "src/sample.c", "tests/sample.c"),
        ("c", "src/sample.cpp", "tests/sample.cpp"),
        ("swift", "src/sample.swift", "tests/sample.swift"),
    ] {
        let path = corpus_dir("source_posture").join(format!("{name}.txt"));
        let rows = shapes(&path);
        assert!(rows.len() >= 2, "{name}: missing literal/bare controls");
        for (index, (number, row)) in rows.iter().enumerate() {
            let (outcome, shape) = row
                .split_once('\t')
                .unwrap_or_else(|| panic!("{name}:{number}: expected outcome TAB shape: {row}"));
            let fire = match outcome {
                "fire" => true,
                "clean" => false,
                _ => panic!("{name}:{number}: unknown outcome {outcome}"),
            };
            if index < 2 {
                let expected = if matches!(name, "python" | "javascript" | "c" | "swift") {
                    true
                } else {
                    index == 0
                };
                assert_eq!(fire, expected, "{name}: expected literal/bare controls");
            }
            let expanded = expand(shape);
            assert!(!expanded.spans.is_empty(), "{name}:{number}: no value");
            for scenario in [
                "default",
                "all",
                "layer-off",
                "testpath",
                "testpath-skip-off",
            ] {
                // settings controls are the first literal and bare-code shapes in each file.
                if index >= 2 && scenario != "default" {
                    continue;
                }
                let mut al = CompiledAllowlist::default_allowlist().expect("default allowlist");
                let (scan_path, expected) = match scenario {
                    "all" => {
                        al.source_posture = Some(SourcePosture::All);
                        (source_path, true)
                    }
                    "layer-off" => {
                        al.exemption_layer = false;
                        (source_path, true)
                    }
                    "testpath" => (test_path, false),
                    "testpath-skip-off" => {
                        al.heuristic_skip_test_paths = false;
                        (test_path, fire)
                    }
                    _ => (source_path, fire),
                };
                let mut file = fixture_file(&expanded.text);
                file.path = scan_path.to_owned();
                let files = [file];
                let found = scan(&files, &SCANNER, &al);
                let context = format!("{name}:{number}, {scenario}, {scan_path} :: {shape}");
                if expected {
                    for span in &expanded.spans {
                        let value = &expanded.text.as_bytes()[span.clone()];
                        assert!(
                            found.iter().any(|finding| finding.rule_id == RULE
                                && finding
                                    .matched_value
                                    .windows(value.len())
                                    .any(|part| part == value)),
                            "{context}: no {RULE} finding carries {span:?}, got {found:?}"
                        );
                    }
                } else {
                    assert!(found.is_empty(), "{context}: unexpected findings {found:?}");
                }
                if index < 2 && !expected && (scenario != "testpath" || fire) {
                    al.trace_exemptions = true;
                    let traced = scan(&files, &SCANNER, &al);
                    let label = if scenario == "testpath" {
                        "exempt:testpath"
                    } else {
                        "exempt:code"
                    };
                    assert!(
                        traced.iter().any(|finding| finding.rule_id == label),
                        "{context}: missing {label} trace, got {traced:?}"
                    );
                    assert!(
                        traced.iter().all(|finding| finding.rule_id != RULE),
                        "{context}: tracing reintroduced a finding"
                    );
                }
            }
        }
    }
}

#[test]
fn corpus_placeholders_and_rule_ids_are_known() {
    let known: Vec<String> = load_default_rules()
        .expect("default rules load")
        .into_iter()
        .map(|rule| rule.id)
        .collect();
    let mut failures = Vec::new();
    for kind in ["false_positives", "true_positives"] {
        for path in corpus_files(kind) {
            for (number, line) in shapes(&path) {
                let shape = if kind == "true_positives" {
                    let (rule_id, shape) = expectation(&path, number, &line);
                    if !known.iter().any(|id| id == rule_id) {
                        failures.push(format!(
                            "{}:{number}: unknown rule id {rule_id}",
                            label(&path)
                        ));
                    }
                    shape
                } else {
                    line.as_str()
                };
                if !shape.is_ascii() {
                    failures.push(format!("{}:{number}: line is not ascii", label(&path)));
                    continue;
                }
                for name in brace_groups(shape) {
                    if looks_like_placeholder(name) && !SUPPORTED_PLACEHOLDERS.contains(&name) {
                        failures.push(format!(
                            "{}:{number}: unknown placeholder {{{name}}}",
                            label(&path)
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} corpus problem(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
