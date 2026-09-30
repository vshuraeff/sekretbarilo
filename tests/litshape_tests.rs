//! engine coverage of the symbol-table and format-template exemption steps: the observed source
//! lines, the fixture shapes, and the credential values the rule must keep reporting beside them.
//! opaque values are generated here, never written literally.

use sekretbarilo::config::SourcePosture;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::{MIN_ENTROPY_LENGTH, shannon_entropy};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::path::Path;
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
const SYMBOLS: &str = "exempt:symbols";
const TEMPLATE: &str = "exempt:template";
/// the corpus surface: an ordinary data path, scanned in full posture.
const DATA_PATH: &str = "corpus/shapes.txt";

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

fn allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().unwrap()
}

fn traced() -> CompiledAllowlist {
    let mut al = allowlist();
    al.trace_exemptions = true;
    al
}

/// literal bodies stay candidates while every exemption step is off: the rule's base verdict.
fn literal_base() -> CompiledAllowlist {
    let mut al = allowlist();
    al.exemption_layer = false;
    al.source_posture = Some(SourcePosture::Literals);
    al
}

fn findings(path: &str, line: &str, al: &CompiledAllowlist) -> Vec<Finding> {
    let file = DiffFile {
        path: path.to_owned(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.as_bytes().to_vec(),
        }],
    };
    scan(&[file], &SCANNER, al)
}

fn carries(found: &[Finding], rule: &str, value: &[u8]) -> bool {
    found.iter().any(|finding| {
        finding.rule_id == rule
            && finding
                .matched_value
                .windows(value.len())
                .any(|window| window == value)
    })
}

fn claimed_by_literal_shape(found: &[Finding]) -> bool {
    found
        .iter()
        .any(|finding| matches!(finding.rule_id.as_str(), SYMBOLS | TEMPLATE))
}

/// letters and digits collapse to one byte per class, so a report never carries a sample.
fn skeleton(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' => 'a',
            b'A'..=b'Z' => 'A',
            b'0'..=b'9' => '9',
            _ => char::from(byte),
        })
        .collect()
}

struct XorShift64Star(u64);

impl XorShift64Star {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn token(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

fn base62_with(extra: &[u8]) -> Vec<u8> {
    (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .chain(extra.iter().copied())
        .collect()
}

#[test]
fn observed_source_lines_are_exempted_by_their_literal_shape() {
    let (default, tracing, base) = (allowlist(), traced(), literal_base());
    for (path, line, body, label) in [
        (
            "src/scanner/syntax.rs",
            r#"    ascii_whitespace(byte) || b"()[]{}<>,;:?!&*=\\'\"`|.".contains(&byte)"#,
            r#"()[]{}<>,;:?!&*=\\'\"`|."#,
            SYMBOLS,
        ),
        (
            "src/scanner/literals.rs",
            r#"            self.expression = b"(,=:[!&|?{};+-*%<>~^".contains(&byte);"#,
            "(,=:[!&|?{};+-*%<>~^",
            SYMBOLS,
        ),
        (
            "fuzz/fuzz_targets/config_load.rs",
            r#"            "sekretbarilo-fuzz-config-{}-{id}","#,
            "sekretbarilo-fuzz-config-{}-{id}",
            TEMPLATE,
        ),
    ] {
        let reported = findings(path, line, &base);
        assert!(
            carries(&reported, ENTROPY, body.as_bytes()),
            "{path}: the base rule no longer reports the body: {reported:?}"
        );
        assert!(findings(path, line, &default).is_empty(), "{path}");
        let traced = findings(path, line, &tracing);
        assert!(
            traced
                .iter()
                .any(|finding| finding.rule_id == label && finding.matched_value == body.as_bytes()),
            "{path}: missing {label}: {traced:?}"
        );
        assert!(traced.iter().all(|finding| finding.rule_id != ENTROPY));
    }
}

fn fixture_shapes(name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/false_positives")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .lines()
        .filter(|line| {
            !(line.trim().is_empty()
                || *line == "#"
                || line.starts_with("# ")
                || line.starts_with("#\t"))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn fixture_shapes_reach_their_step_with_reportable_values() {
    let (default, tracing) = (allowlist(), traced());
    let mut failures = Vec::new();
    for (name, label) in [
        ("symbol-table.txt", SYMBOLS),
        ("format-template.txt", TEMPLATE),
    ] {
        let shapes = fixture_shapes(name);
        assert!(shapes.len() >= 8, "{name} carries {} shapes", shapes.len());
        for (shape, line) in shapes.iter().enumerate() {
            let traced = findings(DATA_PATH, line, &tracing);
            let exempted: Vec<&[u8]> = traced
                .iter()
                .filter(|finding| finding.rule_id == label)
                .map(|finding| finding.matched_value.as_slice())
                .collect();
            if exempted.is_empty() {
                let rules: Vec<&str> = traced.iter().map(|f| f.rule_id.as_str()).collect();
                failures.push(format!(
                    "{name} shape {shape}: no {label} trace, got {rules:?}"
                ));
            }
            // without the step each value would clear the rule's length and entropy gate.
            for value in exempted {
                if value.len() < MIN_ENTROPY_LENGTH || shannon_entropy(value) < 4.0 {
                    failures.push(format!(
                        "{name} shape {shape}: {label} value below the gate, {} bytes at {:.2} bits",
                        value.len(),
                        shannon_entropy(value)
                    ));
                }
            }
            if traced.iter().any(|finding| finding.rule_id == ENTROPY) {
                failures.push(format!("{name} shape {shape}: reported"));
            }
            if redact_text(line, &SCANNER, &default) != *line {
                failures.push(format!("{name} shape {shape}: redacted"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// every generated value the base rule would report stays reported in plain, template and
/// source-literal forms, and neither step ever claims one. an opaque token is placed as a literal
/// segment between template placeholders; printable passwords are left to the tier-3 grid, whose
/// forms tolerate their quotes.
#[test]
fn credential_values_beside_templates_stay_reported() {
    const SAMPLES: usize = 200;
    // (path, text before the value, text after it, literal body before it, literal body after it)
    const FORMS: [(&str, &str, &str, &str, &str); 8] = [
        (DATA_PATH, "value = \"", "\"", "", ""),
        (DATA_PATH, "let path = format!(\"{}-", "\", id);", "{}-", ""),
        (
            DATA_PATH,
            "dsn := fmt.Sprintf(\"%s@",
            "/%s\", user, name)",
            "%s@",
            "/%s",
        ),
        (
            DATA_PATH,
            "LOG_FILE=\"${LOG_DIR}/",
            ".log\"",
            "${LOG_DIR}/",
            ".log",
        ),
        (
            DATA_PATH,
            "row = \"{name:>8}|",
            "|{unit}\".format(**values)",
            "{name:>8}|",
            "|{unit}",
        ),
        (
            DATA_PATH,
            "snprintf(line, sizeof line, \"%-10s|",
            "|%d\\n\", name, count);",
            "%-10s|",
            "|%d\\n",
        ),
        (
            "src/lib.rs",
            "let path = format!(\"{}/",
            "/{}\", root, leaf);",
            "{}/",
            "/{}",
        ),
        ("src/lib.rs", "let key = \"", "\";", "", ""),
    ];
    let alphabets: [(&str, Vec<u8>); 5] = [
        ("base64", base62_with(b"+/")),
        ("base64url", base62_with(b"-_")),
        ("hex", b"0123456789abcdef".to_vec()),
        ("alnum", base62_with(b"")),
        ("strong-password", base62_with(b"!@#$%^&*")),
    ];
    let (default, tracing) = (allowlist(), traced());
    let mut prng = XorShift64Star(0x9e37_79b9_7f4a_7c15);
    let mut failures = Vec::new();
    for (name, alphabet) in &alphabets {
        let mut eligible_total = 0;
        for (path, before, after, body_before, body_after) in FORMS {
            let (mut eligible, mut reported) = (0, 0);
            for _ in 0..SAMPLES {
                let length = 20 + prng.below(21);
                let token = prng.token(alphabet, length);
                let line = format!("{before}{token}{after}");
                let body = format!("{body_before}{token}{body_after}");
                if claimed_by_literal_shape(&findings(path, &line, &tracing)) {
                    failures.push(format!("{name}: claimed :: {}", skeleton(&line)));
                }
                if body.len() < MIN_ENTROPY_LENGTH || shannon_entropy(body.as_bytes()) < 4.0 {
                    continue;
                }
                eligible += 1;
                let start = line.find(&token).unwrap_or(usize::MAX);
                let text_covered = scan_text(&line, &SCANNER, &default).iter().any(|matched| {
                    matched.rule_id == ENTROPY
                        && matched.range.start <= start
                        && start.saturating_add(token.len()) <= matched.range.end
                });
                if carries(&findings(path, &line, &default), ENTROPY, token.as_bytes())
                    && text_covered
                    && !redact_text(&line, &SCANNER, &default).contains(&token)
                {
                    reported += 1;
                } else {
                    failures.push(format!("{name}: not reported :: {}", skeleton(&line)));
                }
            }
            eprintln!("{name} {before}S{after}: eligible={eligible} reported={reported}");
            eligible_total += eligible;
        }
        assert!(eligible_total > 0, "{name}: no sample cleared the gate");
    }
    assert!(
        failures.is_empty(),
        "{} failures: {failures:#?}",
        failures.len()
    );
}

#[test]
fn url_shaped_templates_are_left_to_the_url_step() {
    let tracing = traced();
    let mut prng = XorShift64Star(0x5851_f42d_4c95_7f2d);
    let token = prng.token(&base62_with(b""), 32);
    let line = format!("endpoint = \"https://api.example.com/%s/{token}\"");
    let found = findings(DATA_PATH, &line, &tracing);
    assert!(!claimed_by_literal_shape(&found), "{found:?}");
    assert!(carries(&found, ENTROPY, token.as_bytes()), "{found:?}");
    let benign = "endpoint = \"https://{host}:{port}/api/v{version}/items?page={page}\"";
    let found = findings(DATA_PATH, benign, &tracing);
    assert!(!claimed_by_literal_shape(&found), "{found:?}");
}

#[test]
fn switching_the_layer_off_restores_the_base_verdict() {
    let default = allowlist();
    let mut off = allowlist();
    off.exemption_layer = false;
    for line in [
        "DELIMITERS = \"()[]{}<>,;:?!&*=|.~^%\"",
        "dsn = \"{user}@{host}:{port:05d}/{db}?timeout={secs:.1f}\".format(**cfg)",
    ] {
        assert!(findings(DATA_PATH, line, &default).is_empty(), "{line}");
        let base = findings(DATA_PATH, line, &off);
        let rules: Vec<&str> = base.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&ENTROPY), "{}: {rules:?}", skeleton(line));
    }
}
