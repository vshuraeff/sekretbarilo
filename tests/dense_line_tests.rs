//! one long line holding many candidates: its findings are those of its pieces, and its scan
//! time grows with its length, not with its length times its candidate count.

use std::time::{Duration, Instant};

use sekretbarilo::config::{self, ProjectConfig, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{TextMatch, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules};

fn defaults() -> (CompiledScanner, CompiledAllowlist) {
    let rules = sekretbarilo::scanner::rules::load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    (scanner, allowlist)
}

/// deterministic opaque values: `alphabet` bytes from a linear congruential generator.
fn values(count: usize, length: usize, alphabet: &[u8], seed: u64) -> Vec<String> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            (0..length)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    char::from(alphabet[(state >> 33) as usize % alphabet.len()])
                })
                .collect()
        })
        .collect()
}

const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// a dense line shape: the text before the pieces, one piece per value, the separator between
/// pieces and the text after them.
struct Shape {
    name: &'static str,
    head: &'static str,
    piece: fn(&str) -> String,
    separator: &'static str,
    tail: &'static str,
}

const SHAPES: [Shape; 3] = [
    // the evidence shape of the stall: url passwords (`password-in-url`).
    Shape {
        name: "url",
        head: "",
        piece: |value| format!("https://user:{value}@host.example/"),
        separator: " ",
        tail: "",
    },
    // shell assignments (`generic-password-assignment`, env-style prefix reading).
    Shape {
        name: "assignment",
        head: "",
        piece: |value| format!("password={value}Q7!"),
        separator: " ",
        tail: "",
    },
    // a container environment list (named-key rules, the quote state of `ends_quoted_string`).
    Shape {
        name: "env-list",
        head: "[",
        piece: |value| format!("\"API_KEY={value}\""),
        separator: ", ",
        tail: "]",
    },
];

fn dense_line(shape: &Shape, values: &[String]) -> (String, Vec<std::ops::Range<usize>>) {
    let mut line = shape.head.to_owned();
    let mut pieces = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            line.push_str(shape.separator);
        }
        let piece = (shape.piece)(value);
        pieces.push(line.len()..line.len() + piece.len());
        line.push_str(&piece);
    }
    line.push_str(shape.tail);
    line.push('\n');
    (line, pieces)
}

/// the findings each piece gives on a line of its own, moved to the piece's place in `line`.
fn piecewise(
    shape: &Shape,
    line: &str,
    pieces: &[std::ops::Range<usize>],
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<TextMatch> {
    pieces
        .iter()
        .flat_map(|piece| {
            let alone = format!("{}{}{}\n", shape.head, &line[piece.clone()], shape.tail);
            let shift = piece.start - shape.head.len();
            scan_text(&alone, scanner, allowlist)
                .into_iter()
                .map(move |found| TextMatch {
                    range: found.range.start + shift..found.range.end + shift,
                    rule_id: found.rule_id,
                })
        })
        .collect()
}

#[test]
fn a_dense_line_reports_what_its_pieces_report() {
    let (scanner, allowlist) = defaults();
    for shape in &SHAPES {
        let generated = values(300, 32, ALNUM, 11);
        let (line, pieces) = dense_line(shape, &generated);
        let found = scan_text(&line, &scanner, &allowlist);
        assert_eq!(
            found,
            piecewise(shape, &line, &pieces, &scanner, &allowlist),
            "{}",
            shape.name
        );
        // nearly every piece holds a finding (a value may read as words), so the comparison
        // covers the late candidates of the line and not only an empty result.
        let covered = pieces
            .iter()
            .zip(&generated)
            .filter(|(piece, value)| {
                let start = piece.start + line[(*piece).clone()].find(value.as_str()).unwrap();
                found
                    .iter()
                    .any(|found| found.range.start <= start && start < found.range.end)
            })
            .count();
        assert!(
            covered * 10 >= pieces.len() * 9,
            "{}: {covered}",
            shape.name
        );
    }
}

#[test]
fn a_template_line_and_a_hash_context_still_hold_for_every_candidate() {
    let (scanner, allowlist) = defaults();
    let url = &SHAPES[0];
    let passwords = values(300, 20, ALNUM, 13);
    let (line, _) = dense_line(url, &passwords);
    let urls = |found: &[TextMatch]| {
        found
            .iter()
            .filter(|found| found.rule_id == "password-in-url")
            .count()
    };
    assert_eq!(
        urls(&scan_text(&line, &scanner, &allowlist)),
        passwords.len()
    );
    // the template skip of step 6.5 reads the whole line: a tag at its start drops every url.
    let templated = format!("{{{{ host }}}} {line}");
    assert_eq!(urls(&scan_text(&templated, &scanner, &allowlist)), 0);

    // a hash-length hex value is a hash when its line carries a context word; the word at the
    // start of the line drops every candidate, and only the line it is on.
    let digests = values(300, 40, b"0123456789abcdef", 17);
    let (line, _) = dense_line(url, &digests);
    let plain = urls(&scan_text(&line, &scanner, &allowlist));
    assert_eq!(plain, digests.len());
    let hashed = format!("commit {line}");
    assert_eq!(urls(&scan_text(&hashed, &scanner, &allowlist)), 0);
    let next_line = format!("commit\n{line}");
    assert_eq!(urls(&scan_text(&next_line, &scanner, &allowlist)), plain);
}

#[test]
fn a_dense_diff_line_reports_every_url_password() {
    let (scanner, allowlist) = defaults();
    let passwords = values(300, 20, ALNUM, 19);
    let (line, _) = dense_line(&SHAPES[0], &passwords);
    let file = DiffFile {
        path: "deploy/urls.txt".into(),
        is_new: true,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.trim_end().as_bytes().to_vec(),
        }],
    };
    let found: Vec<Vec<u8>> = scan(&[file], &scanner, &allowlist)
        .into_iter()
        .filter(|found| found.rule_id == "password-in-url")
        .map(|found| found.matched_value)
        .collect();
    let expected: Vec<Vec<u8>> = passwords.iter().map(|p| p.as_bytes().to_vec()).collect();
    assert_eq!(found, expected);
}

/// the fastest of three scans of the dense line of `count` values.
fn scan_time(
    shape: &Shape,
    count: usize,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Duration {
    let (line, _) = dense_line(shape, &values(count, 20, ALNUM, 23));
    (0..3)
        .map(|_| {
            let start = Instant::now();
            let found = scan_text(&line, scanner, allowlist);
            let elapsed = start.elapsed();
            assert!(found.len() >= count, "{}", shape.name);
            elapsed
        })
        .min()
        .unwrap()
}

// eight times the candidates on one line: a linear scan takes about eight times as long, the
// per-candidate whole-line reading this guards against took about 44 times as long between 8000
// and 64000 urls (0.12.2: 1.2 s and 51 s). the bound of 24 sits between the two with room for a
// loaded runner, the minimum of three runs absorbs single stalls, and the absolute ceiling fails
// a stall fast. the small line is long enough that fixed costs do not decide the ratio.
#[test]
fn a_dense_line_scans_in_time_linear_in_its_length() {
    const SMALL: usize = 2_000;
    const LARGE: usize = 8 * SMALL;
    let (scanner, allowlist) = defaults();
    for shape in &SHAPES {
        let small = scan_time(shape, SMALL, &scanner, &allowlist);
        let large = scan_time(shape, LARGE, &scanner, &allowlist);
        let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
        eprintln!("{}: {small:?} -> {large:?}, ratio {ratio:.1}", shape.name);
        assert!(
            large < Duration::from_secs(10),
            "{}: {LARGE} candidates took {large:?}",
            shape.name
        );
        assert!(
            ratio < 24.0,
            "{}: {SMALL} candidates {small:?}, {LARGE} candidates {large:?}, ratio {ratio:.1}",
            shape.name
        );
    }
}
