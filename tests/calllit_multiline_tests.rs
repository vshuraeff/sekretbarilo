//! call-argument literals of a call that spans several lines.
//!
//! the text surface carries paren context across line breaks, so a continuation-line argument
//! is a call candidate exactly like its single-line form. the diff surface scans one added line
//! at a time and gets the same context only through the rust/go literal tracker.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::ops::Range;
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
const WORD: &str = "reliable-backup-rotation-schedule";
const RELATIVE_PATH: &str = "internal/scanner/engine_multiline.go";
const ROOTED_PATH: &str = "/usr/local/share/tooling/config";

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

fn token(seed: usize) -> String {
    (0..32)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + ((index + seed) % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7 + seed) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

fn allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().unwrap()
}

fn traced() -> CompiledAllowlist {
    let mut al = allowlist();
    al.trace_exemptions = true;
    al
}

/// the single-line call first, then the same call broken across two, three and four lines.
const SHAPES: &[&str] = &[
    "build(\"{V}\")",
    "build(\n    \"{V}\")",
    "build(\n    \"{V}\",\n)",
    "build(\n    other,\n    \"{V}\",\n)",
    "let handle = client.connect(\n    endpoint,\n    \"{V}\",\n    retries,\n);",
    "outer(build(\n    \"{V}\",\n))",
];

/// rule id and exact range of every text-surface match on the body, as the single-line form
/// would report it: the body's own offsets, independent of where the line breaks fall.
fn body_matches(text: &str, value: &str, al: &CompiledAllowlist) -> Vec<(String, Range<usize>)> {
    let start = text.find(value).unwrap();
    scan_text(text, &SCANNER, al)
        .into_iter()
        .map(|found| {
            assert!(
                found.range.start >= start && found.range.end <= start + value.len(),
                "a match outside the argument body in {text:?}"
            );
            (
                found.rule_id,
                found.range.start - start..found.range.end - start,
            )
        })
        .collect()
}

fn with_line_endings(shape: &str) -> [String; 3] {
    [
        shape.to_owned(),
        shape.replace('\n', "\r\n"),
        shape.replace('\n', "\r"),
    ]
}

#[test]
fn multiline_calls_match_their_single_line_form_on_the_text_surface() {
    let opaque = token(3);
    for value in [opaque.as_str(), WORD, RELATIVE_PATH, ROOTED_PATH] {
        let single = SHAPES[0].replace("{V}", value);
        let expected = body_matches(&single, value, &allowlist());
        let expected_trace = body_matches(&single, value, &traced());
        for shape in SHAPES {
            for text in with_line_endings(&shape.replace("{V}", value)) {
                assert_eq!(
                    body_matches(&text, value, &allowlist()),
                    expected,
                    "{text:?}"
                );
                assert_eq!(
                    body_matches(&text, value, &traced()),
                    expected_trace,
                    "traced {text:?}"
                );
            }
        }
    }
    // the controls: the opaque body is reported whole, the word and path bodies are exempt.
    let single = SHAPES[0].replace("{V}", &opaque);
    assert_eq!(
        body_matches(&single, &opaque, &allowlist()),
        [(ENTROPY.to_owned(), 0..opaque.len())]
    );
    for value in [WORD, RELATIVE_PATH] {
        let single = SHAPES[0].replace("{V}", value);
        assert!(body_matches(&single, value, &allowlist()).is_empty());
        assert_eq!(
            body_matches(&single, value, &traced()),
            [("exempt:wordshape".to_owned(), 0..value.len())]
        );
    }
    let single = SHAPES[0].replace("{V}", ROOTED_PATH);
    assert!(body_matches(&single, ROOTED_PATH, &traced()).is_empty());
}

#[test]
fn multiline_opaque_arguments_are_redacted_in_place() {
    let s = token(5);
    for shape in SHAPES {
        for text in with_line_endings(&shape.replace("{V}", &s)) {
            let expected = text.replace(&s, "[REDACTED]");
            assert_eq!(redact_text(&text, &SCANNER, &allowlist()), expected);
        }
    }
}

#[test]
fn collected_arguments_never_hide_regex_candidates() {
    let s = token(7);
    let t = token(11);
    let u = token(13);
    // s is a continuation-line argument only the collector claims, t a keyed argument the
    // assignment grammar captures, and u a whole-line literal both of them reach.
    let text = format!("configure(\n    \"{s}\",\n    label=\"{t}\",\n    \"{u}\"\n)\n");
    let matches = scan_text(&text, &SCANNER, &allowlist());
    let ranges: Vec<_> = [&s, &t, &u]
        .into_iter()
        .map(|value| {
            let start = text.find(value.as_str()).unwrap();
            start..start + value.len()
        })
        .collect();
    assert_eq!(
        matches
            .iter()
            .map(|found| (found.rule_id.as_str(), found.range.clone()))
            .collect::<Vec<_>>(),
        ranges
            .iter()
            .map(|range| (ENTROPY, range.clone()))
            .collect::<Vec<_>>()
    );
    let mut expected = text.clone();
    for value in [&s, &t, &u] {
        expected = expected.replace(value.as_str(), "[REDACTED]");
    }
    assert_eq!(redact_text(&text, &SCANNER, &allowlist()), expected);
}

#[test]
fn line_breaks_carry_only_balanced_call_context() {
    let s = token(17);
    let t = token(19);
    for (text, reported) in [
        // an unclosed literal resets the open call, so the next line starts outside it.
        (format!("build(\"{t}\n, \"{s}\")"), false),
        (format!("it's (\n, \"{s}\")"), false),
        // comma-terminated standalone literals are now direct regex candidates, even without
        // call context; a following argument prevents that direct reading.
        (format!("[\n    \"safe\",\n    \"{s}\",\n]"), true),
        (format!("{{\n    \"safe\",\n    \"{s}\",\n}}"), true),
        (format!("[\n    \"safe\",\n    \"{s}\", next\n]"), false),
        // a closed call carries nothing into the next line.
        (format!("build(\"safe\")\n, \"{s}\""), false),
        (format!("build(\"safe\"),\n    \"{s}\","), true),
    ] {
        let expected = if reported {
            vec![(ENTROPY.to_owned(), 0..s.len())]
        } else {
            Vec::new()
        };
        assert_eq!(body_matches(&text, &s, &allowlist()), expected, "{text:?}");
    }
}

fn reports(text: &str, value: &str) -> bool {
    let start = text.find(value).unwrap();
    scan_text(text, &SCANNER, &allowlist())
        .iter()
        .any(|found| found.rule_id == ENTROPY && found.range == (start..start + value.len()))
}

#[test]
fn call_context_crosses_lines_only_within_the_span_and_depth_bounds() {
    let s = token(23);
    let filler = "    another_positional_argument,\n";
    for (lines, reported) in [(100, true), (200, false)] {
        let text = format!("build(\n{}    \"{s}\", next\n)", filler.repeat(lines));
        assert_eq!(
            text.find(&s).unwrap() <= 4096,
            reported,
            "the span fixture must straddle the bound"
        );
        assert_eq!(reports(&text, &s), reported, "{lines} filler lines");
    }
    for (depth, reported) in [(16, true), (17, false)] {
        let text = format!(
            "{}\n    \"{s}\", next\n{}",
            "call(".repeat(depth),
            ")".repeat(depth)
        );
        assert_eq!(reports(&text, &s), reported, "depth {depth}");
    }
    // a single line keeps its unbounded form: the bounds apply only at a line break.
    let text = format!("{}\"{s}\"{}", "call(".repeat(40), ")".repeat(40));
    assert!(reports(&text, &s));
}

fn added_file(path: &str, text: &str, with_context: bool) -> DiffFile {
    DiffFile {
        path: path.to_owned(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: with_context.then(|| text.as_bytes().to_vec()),
        added_lines: text
            .split('\n')
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    }
}

/// matched values of the diff findings, without the bare-code traces of the call's own lines.
fn diff_values(path: &str, text: &str, with_context: bool, al: &CompiledAllowlist) -> Vec<String> {
    scan(&[added_file(path, text, with_context)], &SCANNER, al)
        .into_iter()
        .filter(|finding| finding.rule_id != "exempt:code")
        .map(|finding| {
            format!(
                "{} {}",
                finding.rule_id,
                String::from_utf8_lossy(&finding.matched_value)
            )
        })
        .collect()
}

#[test]
fn diff_surface_carries_multiline_calls_through_the_literal_tracker() {
    let opaque = token(29);
    for path in ["src/sample.rs", "pkg/sample.go"] {
        for value in [opaque.as_str(), WORD, RELATIVE_PATH, ROOTED_PATH] {
            let single = SHAPES[0].replace("{V}", value);
            for with_context in [false, true] {
                let expected = diff_values(path, &single, with_context, &allowlist());
                let expected_trace = diff_values(path, &single, with_context, &traced());
                for shape in &SHAPES[1..] {
                    let text = shape.replace("{V}", value);
                    let context = format!("{path} context={with_context} {text:?}");
                    assert_eq!(
                        diff_values(path, &text, with_context, &allowlist()),
                        expected,
                        "{context}"
                    );
                    assert_eq!(
                        diff_values(path, &text, with_context, &traced()),
                        expected_trace,
                        "traced {context}"
                    );
                }
            }
        }
        let single = SHAPES[0].replace("{V}", &opaque);
        assert_eq!(
            diff_values(path, &single, true, &allowlist()),
            [format!("{ENTROPY} {opaque}")]
        );
    }
}

// known limitation: the diff loop hands scan_matches one added line with no call state from the
// lines before it, so a path without a literal tracker sees a continuation-line argument with no
// `(` or `,` in front of it. flip this when the per-file loop carries call state.
#[test]
fn diff_surface_without_a_literal_tracker_sees_one_line_at_a_time() {
    let s = token(31);
    let direct = format!("build(\n    \"{s}\",\n)");
    let contextual = format!("build(\n    \"{s}\", another\n)");
    for path in ["notes/shapes.txt", "config/settings.yaml"] {
        for with_context in [false, true] {
            assert_eq!(
                diff_values(path, &direct, with_context, &allowlist()),
                [format!("{ENTROPY} {s}")],
                "direct {path} context={with_context}"
            );
            assert!(
                diff_values(path, &contextual, with_context, &allowlist()).is_empty(),
                "contextual {path} context={with_context}"
            );
        }
        assert_eq!(
            diff_values(path, &format!("build(\"{s}\")"), false, &allowlist()),
            [format!("{ENTROPY} {s}")]
        );
    }
}
