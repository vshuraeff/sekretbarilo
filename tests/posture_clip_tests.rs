//! parser-posture clip and value-grammar contracts of the tier-3 rule: interpolation holes, string
//! prefixes and regex delimiters never lend their bytes to a value, a regex body reaches the regex
//! step, a misread key is dropped without losing the text behind it, hash context belongs to one
//! assignment, and `&&` ends an unquoted value. every opaque value is generated at run time. the
//! monte-carlo guards hold the recall contract of each new exemption path: random tokens of 20 to
//! 64 bytes from six encodings, at least 1e5 samples per guard (2e4 per chunked-token cell), and
//! no reportable token lost. only a token that reports standing alone is scanned in its form, and
//! a file the value grammar reads as the pathless text is scanned for one token in ten where the
//! text surface scans them all.

use sekretbarilo::config::{SourcePosture, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, scan, scan_text};
use sekretbarilo::scanner::entropy::passes_entropy_check;
use sekretbarilo::scanner::hash_detect::is_digest_record;
use sekretbarilo::scanner::regexshape::is_regex_shaped;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::ops::Range;
use std::sync::LazyLock;
use std::time::Instant;

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());
static PLAIN: LazyLock<CompiledAllowlist> = LazyLock::new(|| allowlist(None, false));
static TRACED: LazyLock<CompiledAllowlist> = LazyLock::new(|| allowlist(None, true));
static POSTURE: LazyLock<CompiledAllowlist> =
    LazyLock::new(|| allowlist(Some(SourcePosture::Literals), false));
static POSTURE_TRACED: LazyLock<CompiledAllowlist> =
    LazyLock::new(|| allowlist(Some(SourcePosture::Literals), true));
/// the rule without its exemption layer: what the gates alone report.
static LAYER_OFF: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = allowlist(None, false);
    allowlist.exemption_layer = false;
    allowlist
});

fn allowlist(posture: Option<SourcePosture>, trace: bool) -> CompiledAllowlist {
    let mut allowlist = CompiledAllowlist::default_allowlist().unwrap();
    allowlist.source_posture = posture;
    allowlist.trace_exemptions = trace;
    allowlist
}

const RULE: &str = "generic-high-entropy-value";
const THRESHOLD: f64 = 4.0;
/// samples per monte-carlo guard.
const MC_SAMPLES: usize = 100_000;
/// lines per generated file, so one parse serves many samples.
const BATCH: usize = 1_000;

const ALPHABETS: [(&str, &[u8]); 6] = [
    (
        "base62",
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ),
    (
        "base64",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
    (
        "base64url",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ),
    ("hex", b"0123456789abcdef"),
    ("base32", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    ("base36", b"0123456789abcdefghijklmnopqrstuvwxyz"),
];

/// xorshift64*
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }

    /// a random token of 20 to 64 bytes from one of the six encodings.
    fn token(&mut self) -> String {
        let alphabet = ALPHABETS[self.below(ALPHABETS.len())].1;
        let length = 20 + self.below(45);
        self.string(alphabet, length)
    }

    /// a token of one encoding that clears the plain tier-3 gates on its own.
    fn reportable(&mut self, alphabet: &[u8], length: usize) -> String {
        loop {
            let token = self.string(alphabet, length);
            if passes_entropy_check(token.as_bytes(), THRESHOLD) {
                return token;
            }
        }
    }

    /// an identifier no dialect reserves: a keyword such as swift `is` or `in` in a hole is a
    /// syntax error, which leaves the whole generated file unparsed.
    fn identifier(&mut self) -> String {
        let tail = 1 + self.below(8);
        format!(
            "x{}",
            self.string(b"abcdefghijklmnopqrstuvwxyz0123456789_", tail)
        )
    }

    /// a piece of 2 to 5 bytes: lowercase letters, letters beside a digit run, or alternating
    /// consonants and vowels.
    fn chunk(&mut self) -> String {
        const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
        const VOWELS: &[u8] = b"aeiou";
        const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        let length = 2 + self.below(4);
        match self.below(3) {
            0 => self.string(LETTERS, length),
            1 => {
                let digits = 1 + self.below(length - 1);
                let letters = self.string(LETTERS, length - digits);
                let number = self.string(b"0123456789", digits);
                if self.below(2) == 0 {
                    format!("{letters}{number}")
                } else {
                    format!("{number}{letters}")
                }
            }
            _ => (0..length)
                .map(|index| {
                    let set = if index % 2 == 0 { CONSONANTS } else { VOWELS };
                    char::from(set[self.below(set.len())])
                })
                .collect(),
        }
    }

    /// a token of 20 to 64 bytes cut into pieces (`chunk`) joined by `separator`: the pieces alone
    /// carry the token's length, the separators come on top.
    fn chunked(&mut self, separator: &str) -> String {
        let target = 20 + self.below(45);
        let mut pieces = Vec::new();
        let mut length = 0;
        while length < target {
            let piece = self.chunk();
            length += piece.len();
            pieces.push(piece);
        }
        pieces.join(separator)
    }

    /// the expression of an interpolation hole: a name, a member access or a call.
    fn hole(&mut self) -> String {
        match self.below(3) {
            0 => self.identifier(),
            1 => format!("{}.{}", self.identifier(), self.identifier()),
            _ => format!("{}({})", self.identifier(), self.identifier()),
        }
    }
}

fn file(path: &str, source: &str) -> DiffFile {
    DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: Some(source.as_bytes().to_vec()),
        added_lines: source
            .split('\n')
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    }
}

fn scan_source(path: &str, source: &str, allowlist: &CompiledAllowlist) -> Vec<Finding> {
    scan(&[file(path, source)], &SCANNER, allowlist)
}

/// rule findings of a pathless scan, as byte ranges of `text`.
fn text_ranges(text: &str, allowlist: &CompiledAllowlist) -> Vec<(String, Range<usize>)> {
    scan_text(text, &SCANNER, allowlist)
        .into_iter()
        .map(|found| (found.rule_id, found.range))
        .collect()
}

fn values(findings: &[Finding], rule: &str) -> Vec<Vec<u8>> {
    findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .map(|finding| finding.matched_value.clone())
        .collect()
}

fn covers(ranges: &[(String, Range<usize>)], rule: &str, target: &Range<usize>) -> bool {
    ranges
        .iter()
        .any(|(id, range)| id == rule && range.start <= target.start && target.end <= range.end)
}

/// the byte range of `needle` inside `haystack`, which must hold it once.
fn locate(haystack: &str, needle: &str) -> Range<usize> {
    let start = haystack
        .find(needle)
        .expect("generated line holds its token");
    start..start + needle.len()
}

/// whether each token clears the gates as a plain literal body on the pathless surface: at least
/// the entropy gate, and no exemption the layer applies to the value itself (a path-shaped or
/// regex-shaped token, say). a monte-carlo guard holds a form to what this control reports, so it
/// measures the form and not the predicates every value already faces.
fn controls(tokens: &[String]) -> Vec<bool> {
    // a token below the entropy gate reports nothing, so only the others are scanned.
    let passing: Vec<bool> = tokens
        .iter()
        .map(|token| passes_entropy_check(token.as_bytes(), THRESHOLD))
        .collect();
    let lines: Vec<String> = tokens
        .iter()
        .zip(&passing)
        .filter(|(_, passes)| **passes)
        .map(|(token, _)| format!("control(\"{token}\")"))
        .collect();
    let text = lines.join("\n");
    let ranges = text_ranges(&text, &PLAIN);
    let mut offset = 0;
    let mut lines = lines.iter();
    tokens
        .iter()
        .zip(passing)
        .map(|(token, passes)| {
            if !passes {
                return false;
            }
            let line = lines.next().expect("one control line per passing token");
            let target = locate(line, token);
            let target = offset + target.start..offset + target.end;
            offset += line.len() + 1;
            covers(&ranges, RULE, &target)
        })
        .collect()
}

fn base62_token(rng: &mut Rng, length: usize) -> String {
    rng.reportable(ALPHABETS[0].1, length)
}

/// a hex value of `length` bytes below the entropy gate, the shape the hex bypass exists for.
fn low_entropy_hex(rng: &mut Rng, length: usize) -> String {
    loop {
        let value = rng.string(b"0123456789abcdef", length);
        if !passes_entropy_check(value.as_bytes(), THRESHOLD) {
            return value;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// interpolation holes: one line per dialect, the token before or after a hole.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Dialect {
    Swift,
    SwiftRaw,
    TypeScript,
    PythonF,
    CppRaw,
}

impl Dialect {
    const ALL: [Dialect; 5] = [
        Dialect::Swift,
        Dialect::SwiftRaw,
        Dialect::TypeScript,
        Dialect::PythonF,
        Dialect::CppRaw,
    ];

    fn path(self) -> &'static str {
        match self {
            Self::Swift | Self::SwiftRaw => "src/value.swift",
            Self::TypeScript => "src/value.ts",
            Self::PythonF => "src/value.py",
            Self::CppRaw => "src/value.cpp",
        }
    }

    /// one statement assigning a string whose literal text is the token beside a hole. a c++ raw
    /// string has no hole: its `(` `)` delimiters straddle the value instead.
    fn line(self, index: usize, token: &str, hole: &str, after: bool) -> String {
        let (before, behind) = if after { ("", token) } else { (token, "") };
        match self {
            Self::Swift => format!("let k{index} = \"{before}\\({hole}){behind}\""),
            Self::SwiftRaw => format!("let k{index} = #\"{before}\\#({hole}){behind}\"#"),
            // a value opening on `${` is read as a whole reference, so literal text leads the hole.
            Self::TypeScript if after => format!("const k{index} = `token=v${{{hole}}}{token}`;"),
            Self::TypeScript => format!("const k{index} = `token={token}${{{hole}}}`;"),
            Self::PythonF => format!("k{index} = f\"{before}{{{hole}}}{behind}\""),
            Self::CppRaw => format!("auto k{index} = R\"({token})\";"),
        }
    }
}

#[test]
fn interpolation_holes_clip_to_the_literal_token_in_every_dialect() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0001);
    for dialect in Dialect::ALL {
        for after in [false, true] {
            let token = base62_token(&mut rng, 40);
            let line = dialect.line(0, &token, "session.label", after);
            let findings = scan_source(dialect.path(), &line, &POSTURE_TRACED);
            assert!(
                values(&findings, RULE).contains(&token.as_bytes().to_vec()),
                "{dialect:?} after={after}: token not reported exactly: {:?}",
                findings
                    .iter()
                    .map(|finding| (&finding.rule_id, finding.matched_value.len()))
                    .collect::<Vec<_>>()
            );
            assert!(
                values(&findings, RULE)
                    .iter()
                    .all(|value| value == token.as_bytes()),
                "{dialect:?} after={after}: a finding carries hole or delimiter bytes"
            );
            // an f-string body whose holes are code of words is read around them before any gate,
            // unless its bytes, the token's included, show a run of short groups; every other
            // dialect, and such a body, clips a straddling finding to the parser's literal bodies.
            let labels: &[&str] = match dialect {
                Dialect::PythonF => &["exempt:hole", "exempt:clip"],
                _ => &["exempt:clip"],
            };
            assert!(
                labels
                    .iter()
                    .any(|label| !values(&findings, label).is_empty()),
                "{dialect:?} after={after}: the straddling value was not traced as {labels:?}"
            );
        }
    }
}

/// a diff file with no blob context: no parser posture, so the value grammar alone reads the line.
fn file_without_context(path: &str, source: &str) -> DiffFile {
    DiffFile {
        context: None,
        ..file(path, source)
    }
}

#[test]
fn python_fstring_holes_are_code_on_python_files_only() {
    // shapes observed in the wild: literal words around holes holding member calls. each body
    // clears the plain gates as a whole. on a python file the holes are code: the parser posture
    // clips the value to its literal text, and without a parse the value grammar reads a body
    // whose holes are code of words around them. on the pathless surface an f-string prefix proves
    // nothing, so no hole is read there. without a parse, a body is judged whole when its words run
    // in short groups a chunked token also shows (`scope`, `name`, `date`, `today`), and when its
    // holes hold a quoted string or a format spec, which are not code of words.
    let word_holes = [true, true, false, false, false, false];
    for (line, word_holes) in [
        "    run_name = f\"peer_chat_{session.agent.label()}_history\"",
        "    assert_bundle_has(output, label=f\"{items.count(1)}=expected_total\", verbose)",
        "        path = f\"backup_{scope_name}_{str(date.today())}\"",
        "        path = rf\"backup_{scope_name}_{str(date.today())}\"",
        "        path = t\"backup_{scope_name}_{str(date.today())}\"",
        "    key = f'{prefix}_{item[\"name\"]}_{index:04d}_suffix'",
    ]
    .into_iter()
    .zip(word_holes)
    {
        let quote = if line.contains('\'') { '\'' } else { '"' };
        let body = &line[line.find(quote).unwrap() + 1..line.rfind(quote).unwrap()];
        assert!(
            passes_entropy_check(body.as_bytes(), THRESHOLD) && body.len() >= 20,
            "vacuous shape: {line}"
        );
        assert!(
            scan_source("src/value.py", line, &POSTURE).is_empty(),
            "posture finding: {line}"
        );
        assert!(
            text_ranges(line, &TRACED)
                .iter()
                .all(|(id, _)| id != "exempt:hole"),
            "pathless hole reading: {line}"
        );
        let unparsed = scan(
            &[file_without_context("src/value.py", line)],
            &SCANNER,
            &TRACED,
        );
        assert_eq!(
            !values(&unparsed, "exempt:hole").is_empty(),
            word_holes,
            "python hole reading: {line}"
        );
        if word_holes {
            assert!(
                values(&unparsed, RULE).is_empty(),
                "python finding beside word holes: {line}"
            );
        }
        let shell = scan(
            &[file_without_context("scripts/value.sh", line)],
            &SCANNER,
            &TRACED,
        );
        assert!(
            values(&shell, "exempt:hole").is_empty(),
            "shell hole reading: {line}"
        );
    }
}

#[test]
fn a_format_spec_hole_stands_whole_only_off_the_mini_language() {
    // an attribute chain of short words before a mini-language specification reads as a run of
    // short groups, but such a specification holds no token: the value is clipped to its literal
    // text, and none of it is reported.
    for line in [
        "    header = f\"{self.name!r:>{self.width}}|{self.kind.value:^12}|\"",
        "    line = f\"{user.first_name:.1}{user.last_name:.1}{user.id:08x}\"",
        "    name = f\"{self.base.name.stem:>12}_{self.part.index:03d}\"",
        "    hexid = f\"{node.left.hash:016x}{node.right.hash:016x}\"",
    ] {
        assert!(
            values(&scan_source("src/value.py", line, &POSTURE), RULE).is_empty(),
            "posture finding: {line}"
        );
    }
    // a token cut into groups by `:` whose first group is the hole's expression and whose other
    // groups are the specification stands whole on the parsed surface.
    let mut rng = Rng(0x51A7_E5C0_FFEE_000D);
    let mut checked = 0;
    while checked < 32 {
        let payload = rng.chunked(":");
        if !leads_with_name(&payload) || !controls(std::slice::from_ref(&payload))[0] {
            continue;
        }
        checked += 1;
        for form in ["value = f\"{TOKEN}\"", "value = f\"x{TOKEN}y\""] {
            let line = form.replace("TOKEN", &payload);
            assert!(
                values(&scan_source("src/value.py", &line, &POSTURE), RULE)
                    .iter()
                    .any(|value| value
                        .windows(payload.len())
                        .any(|part| part == payload.as_bytes())),
                "chunked specification lost: {}",
                skeleton(&line)
            );
        }
    }
}

#[test]
fn fstring_text_in_rust_and_go_code_stays_code() {
    // rust and go have no f-strings: the tracker's body check still owns text that looks like one,
    // so a comment is not read piece by piece into literal segments.
    let mut rng = Rng(0x51A7_E5C0_FFEE_000B);
    let token = base62_token(&mut rng, 32);
    for (path, comment) in [("src/value.rs", "//"), ("pkg/value.go", "//")] {
        let source = format!("{comment} key = f\"{{name}}{token}\"\n");
        let findings = scan_source(path, &source, &POSTURE_TRACED);
        assert!(
            values(&findings, RULE).is_empty(),
            "{path}: comment text reported"
        );
        assert!(
            !values(&findings, "exempt:code").is_empty(),
            "{path}: comment text not traced as code"
        );
    }
}

#[test]
fn python_fstring_segments_keep_tokens_beside_holes() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0002);
    for (index, template) in [
        "key = f\"{name}TOKEN\"",
        "key = f\"TOKEN{name}\"",
        "key = f\"{a}TOKEN{b.c()}\"",
        "key = F'TOKEN{name!r}'",
        "key = rf\"TOKEN{name:>{width}}\"",
        "key = f\"{lookup('TOKEN')}\"",
    ]
    .into_iter()
    .enumerate()
    {
        let token = base62_token(&mut rng, 20 + index * 7);
        let line = template.replace("TOKEN", &token);
        let target = locate(&line, &token);
        // pathless and in a python file without a parse, the token is reported, alone or inside
        // the whole body.
        assert!(
            covers(&text_ranges(&line, &PLAIN), RULE, &target),
            "pathless token lost: {template}"
        );
        assert!(
            values(
                &scan(
                    &[file_without_context("src/value.py", &line)],
                    &SCANNER,
                    &PLAIN
                ),
                RULE
            )
            .iter()
            .any(|value| value
                .windows(token.len())
                .any(|part| part == token.as_bytes())),
            "unparsed python token lost: {template}"
        );
        let findings = scan_source("src/value.py", &line, &POSTURE);
        assert_eq!(
            values(&findings, RULE),
            vec![token.as_bytes().to_vec()],
            "posture segment: {template}"
        );
    }
    // holes of code of words in a python file: the value grammar reads the literal text beside them.
    for line in [
        "key = f\"{name}_quarterly_revenue_summary\"",
        "key = f\"quarterly_revenue_{item.label()}\"",
        "key = f\"{report.owner}_quarterly_{period[0]}\"",
        "key = f\"{format_name(year=2026)!r}_quarterly\"",
    ] {
        let unparsed = scan(
            &[file_without_context("src/value.py", line)],
            &SCANNER,
            &POSTURE_TRACED,
        );
        assert!(
            !values(&unparsed, "exempt:hole").is_empty(),
            "no hole reading: {line}"
        );
    }
    // an escaped brace is no hole and an unclosed hole is unreadable: the body stays whole.
    for template in ["key = f\"{{literal}}TOKEN\"", "key = f\"{nameTOKEN\""] {
        let token = base62_token(&mut rng, 32);
        let line = template.replace("TOKEN", &token);
        assert!(
            covers(&text_ranges(&line, &PLAIN), RULE, &locate(&line, &token)),
            "whole body lost: {template}"
        );
    }
}

/// the counts of one monte-carlo shard.
#[derive(Default)]
struct Tally {
    samples: usize,
    reportable: usize,
    shaped: usize,
    audit_misses: usize,
    text_misses: usize,
    examples: Vec<String>,
}

impl Tally {
    fn miss(&mut self, surface: &str, line: &str) {
        if self.examples.len() < 5 {
            self.examples.push(format!("{surface}: {}", skeleton(line)));
        }
    }

    fn merge(tallies: Vec<Tally>) -> Tally {
        tallies
            .into_iter()
            .fold(Tally::default(), |mut total, part| {
                total.samples += part.samples;
                total.reportable += part.reportable;
                total.shaped += part.shaped;
                total.audit_misses += part.audit_misses;
                total.text_misses += part.text_misses;
                total.examples.extend(part.examples);
                total
            })
    }
}

/// shards per monte-carlo guard, each on its own thread with its own seed.
const SHARDS: usize = 8;

/// runs `run` on `SHARDS` threads, each with its own seed and an even share of `MC_SAMPLES`.
fn shard_results<T: Send>(run: impl Fn(u64, usize) -> T + Sync) -> Vec<T> {
    let per_shard = MC_SAMPLES.div_ceil(SHARDS);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..SHARDS)
            .map(|shard| {
                let run = &run;
                scope.spawn(move || run(shard as u64, per_shard))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("monte-carlo shard"))
            .collect()
    })
}

fn shards(run: impl Fn(u64, usize) -> Tally + Sync) -> Tally {
    Tally::merge(shard_results(run))
}

#[test]
fn interpolation_hole_recall_montecarlo() {
    let started = Instant::now();
    // each batch of tokens, holes and sides is placed in every dialect, so one control scan serves
    // the five forms.
    let results = shard_results(|shard, quota| {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (shard + 1) << 32);
        let mut tallies: Vec<Tally> = Dialect::ALL.iter().map(|_| Tally::default()).collect();
        let mut done = 0;
        while done < quota {
            let draws: Vec<(String, String, bool)> = (0..BATCH)
                .map(|_| {
                    let token = rng.token();
                    let hole = rng.hole();
                    (token, hole, rng.below(2) == 1)
                })
                .collect();
            let all_tokens: Vec<String> = draws.iter().map(|draw| draw.0.clone()).collect();
            let expected = controls(&all_tokens);
            done += BATCH;
            for (dialect, tally) in Dialect::ALL.into_iter().zip(&mut tallies) {
                tally.samples += BATCH;
                // only a token that reports standing alone is measured, so only its line is
                // scanned.
                let (lines, tokens): (Vec<String>, Vec<String>) = draws
                    .iter()
                    .zip(&expected)
                    .filter(|(_, reportable)| **reportable)
                    .enumerate()
                    .map(|(index, ((token, hole, after), _))| {
                        (dialect.line(index, token, hole, *after), token.clone())
                    })
                    .unzip();
                let source = lines.join("\n");
                let findings = scan_source(dialect.path(), &source, &POSTURE);
                let mut reported = vec![Vec::new(); lines.len()];
                for finding in findings.iter().filter(|finding| finding.rule_id == RULE) {
                    reported[finding.line - 1].push(finding.matched_value.clone());
                }
                let ranges = text_ranges(&source, &PLAIN);
                let mut offset = 0;
                for (index, (line, token)) in lines.iter().zip(&tokens).enumerate() {
                    let target = locate(line, token);
                    let target = offset + target.start..offset + target.end;
                    offset += line.len() + 1;
                    tally.reportable += 1;
                    // the audit surface keeps exactly the literal token, not the hole beside it.
                    if !reported[index].contains(&token.as_bytes().to_vec()) {
                        tally.audit_misses += 1;
                        tally.miss("audit", line);
                    }
                    if !covers(&ranges, RULE, &target) {
                        tally.text_misses += 1;
                        tally.miss("text", line);
                    }
                }
            }
        }
        tallies
    });
    let mut per_dialect: Vec<Vec<Tally>> = Dialect::ALL.iter().map(|_| Vec::new()).collect();
    for tallies in results {
        for (parts, tally) in per_dialect.iter_mut().zip(tallies) {
            parts.push(tally);
        }
    }
    let mut report = Vec::new();
    for (dialect, parts) in Dialect::ALL.into_iter().zip(per_dialect) {
        let tally = Tally::merge(parts);
        println!(
            "{dialect:?}: samples={} reportable={} audit_misses={} text_misses={}",
            tally.samples, tally.reportable, tally.audit_misses, tally.text_misses
        );
        assert!(tally.samples >= MC_SAMPLES);
        if tally.audit_misses + tally.text_misses > 0 {
            report.push(format!("{dialect:?}: {:?}", tally.examples));
        }
    }
    println!("elapsed={:.1}s", started.elapsed().as_secs_f64());
    assert!(report.is_empty(), "recall lost beside holes: {report:#?}");
}

/// a shape-only rendering for failure messages: letters, digits and punctuation classes.
fn skeleton(line: &str) -> String {
    line.chars()
        .map(|character| match character {
            'a'..='z' => 'a',
            'A'..='Z' => 'A',
            '0'..='9' => '9',
            other => other,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// regex bodies.
// ---------------------------------------------------------------------------------------------

#[test]
fn regex_bodies_reach_the_regex_step_on_every_surface() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0003);
    let pattern = r"^[A-Za-z0-9_]{20,64}(?:\.[a-z]{2,8})?$";
    // a typescript regex literal: the parser marks its body, the clip routes it to the regex step.
    let line = format!("const re = /{pattern}/iu;");
    assert!(
        values(&scan_source("src/value.ts", &line, &POSTURE), RULE).is_empty(),
        "regex literal body reported"
    );
    let token = base62_token(&mut rng, 36);
    let line = format!("const re = /{token}/i;");
    assert_eq!(
        values(&scan_source("src/value.ts", &line, &POSTURE), RULE),
        vec![token.as_bytes().to_vec()],
        "opaque regex body is reported without its delimiters"
    );
    // pathless: a delimited `/body/flags` value and the pattern of a regex-taking command.
    for line in [
        format!("pattern = /{pattern}/i"),
        format!("grep -E 'account_id={pattern}' audit.log"),
        format!("rg route={pattern} src"),
    ] {
        assert!(
            text_ranges(&line, &PLAIN).is_empty(),
            "pathless regex reported: {}",
            skeleton(&line)
        );
        assert!(
            text_ranges(&line, &TRACED)
                .iter()
                .any(|(id, _)| id == "exempt:regex"),
            "pathless regex not traced: {}",
            skeleton(&line)
        );
    }
    for template in [
        "pattern = /TOKEN/i",
        "grep -E api_key=TOKEN audit.log",
        "sed -n key=TOKEN",
    ] {
        let line = template.replace("TOKEN", &token);
        assert!(
            covers(&text_ranges(&line, &PLAIN), RULE, &locate(&line, &token)),
            "opaque body lost: {template}"
        );
    }
    // an unquoted value is no regex outside those forms, even when its bytes read as one.
    let line = format!("api_key={token}+");
    assert!(covers(
        &text_ranges(&line, &PLAIN),
        RULE,
        &locate(&line, &token)
    ));
}

#[test]
fn regex_class_payloads_keep_detection_and_redaction() {
    let mut rng = Rng(5131);
    for _ in 0..64 {
        let token = base62_token(&mut rng, 40);
        let chunks = token
            .as_bytes()
            .chunks(4)
            .map(|part| std::str::from_utf8(part).unwrap())
            .collect::<Vec<_>>()
            .join(".");
        for body in [
            format!("[^{chunks}]+"),
            format!("[a-z{chunks}]+"),
            format!("[a-z]+{chunks}"),
        ] {
            for line in [format!("value=\"{body}\""), format!("value=/{body}/i")] {
                assert!(
                    covers(&text_ranges(&line, &PLAIN), RULE, &locate(&line, &chunks)),
                    "regex class payload lost"
                );
                let redacted = sekretbarilo::scanner::engine::redact_text(&line, &SCANNER, &PLAIN);
                assert!(!redacted.contains(&chunks), "regex class payload retained");
            }
            let line = format!("value=/{body}/i");
            assert!(
                values(&scan_source("src/value.py", &line, &POSTURE), RULE)
                    .iter()
                    .any(|value| value
                        .windows(chunks.len())
                        .any(|part| part == chunks.as_bytes())),
                "source regex class payload lost"
            );
        }
    }
}

/// a token escaped before every `stride`-th byte, the first one included, as a regex literal
/// writes it: a `/` is escaped wherever it stands, since it would end the literal.
fn escaped_payload(token: &str, stride: usize) -> String {
    let mut payload = String::with_capacity(token.len() * 2);
    for (index, character) in token.chars().enumerate() {
        if index % stride == 0 || character == '/' {
            payload.push('\\');
        }
        payload.push(character);
    }
    payload
}

/// what one allowlist makes of the bytes `span` of `line`: whether `rule` claims some of them on
/// the text surface and on the file at `path`, and whether redaction leaves them in place.
struct Seen {
    text: bool,
    file: bool,
    retained: bool,
}

fn seen(
    line: &str,
    span: &Range<usize>,
    allowlist: &CompiledAllowlist,
    rule: &str,
    path: Option<&str>,
) -> Seen {
    let overlaps = |range: &Range<usize>| range.start < span.end && span.start < range.end;
    let text = scan_text(line, &SCANNER, allowlist)
        .iter()
        .any(|found| found.rule_id == rule && overlaps(&found.range));
    let file = path.is_some_and(|path| {
        scan_source(path, line, allowlist)
            .iter()
            .filter(|found| found.rule_id == rule && !found.matched_value.is_empty())
            .any(|found| {
                line.as_bytes()
                    .windows(found.matched_value.len())
                    .enumerate()
                    .any(|(start, window)| {
                        window == found.matched_value.as_slice()
                            && overlaps(&(start..start + window.len()))
                    })
            })
    });
    let retained = rule == RULE
        && sekretbarilo::scanner::engine::redact_text(line, &SCANNER, allowlist)
            .contains(&line[span.clone()]);
    Seen {
        text,
        file,
        retained,
    }
}

/// whether the regex step drops `span` of `line`: it claims the bytes on a surface where the rule
/// without the layer reports them and the rule with the layer does not, or where the layer's
/// redaction leaves the payload that the plain gates would mask.
fn lost_to_regex(line: &str, span: &Range<usize>, path: Option<&str>) -> (bool, bool) {
    let off = seen(line, span, &LAYER_OFF, RULE, path);
    if !off.text && !off.file {
        return (false, false);
    }
    let claim = seen(line, span, &TRACED, "exempt:regex", path);
    if !claim.text && !claim.file {
        return (true, false);
    }
    let on = seen(line, span, &PLAIN, RULE, path);
    let lost = (claim.text && off.text && !on.text)
        || (claim.file && off.file && !on.file)
        || (claim.text && on.retained && !off.retained);
    (true, lost)
}

/// the forms of an escaped regex payload, and the file its unquoted forms are also scanned in. a
/// quoted value on a file surface is the regex reading of the base release, which the token guard
/// never applied to, so it is measured on the pathless text only.
const ESCAPED_FORMS: [(&str, Option<&str>); 3] = [
    ("value=\"[^x]+TOKEN\"", None),
    ("/[^x]+TOKEN/i", Some("src/Probe.java")),
    ("k=/[^x]+TOKEN/i", Some("src/Probe.java")),
];
/// base62, base64, base36 and hex.
const ESCAPED_ALPHABETS: [usize; 4] = [0, 1, 5, 3];
const ESCAPED_SAMPLES: usize = 2_000;

#[test]
fn escaped_regex_payloads_keep_detection_and_redaction_montecarlo() {
    // a token escaped before every second or third byte: an escaped letter or digit is a byte of
    // the value, so neither the run check nor the chunk check of the widened regex reading may lose
    // what the plain gates report.
    let started = Instant::now();
    let mut cells = Vec::new();
    for (form, path) in ESCAPED_FORMS {
        for alphabet in ESCAPED_ALPHABETS {
            for stride in [2, 3] {
                cells.push((form, path, alphabet, stride));
            }
        }
    }
    let results: Vec<(usize, usize, Vec<String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(index, &(form, path, alphabet, stride))| {
                scope.spawn(move || {
                    let mut rng = Rng(0xE5CA_9ED0_0000_0001 ^ ((index as u64 + 1) << 32));
                    let (mut reported, mut lost, mut examples) = (0, 0, Vec::new());
                    for _ in 0..ESCAPED_SAMPLES {
                        let length = 20 + rng.below(45);
                        let token = rng.string(ALPHABETS[alphabet].1, length);
                        let payload = escaped_payload(&token, stride);
                        let line = form.replacen("TOKEN", &payload, 1);
                        let span = locate(&line, &payload);
                        let (off, dropped) = lost_to_regex(&line, &span, path);
                        reported += usize::from(off);
                        if dropped {
                            lost += 1;
                            if examples.len() < 3 {
                                examples.push(skeleton(&line));
                            }
                        }
                    }
                    (reported, lost, examples)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("escaped regex cell"))
            .collect()
    });
    let mut failures = Vec::new();
    for ((form, _, alphabet, stride), (reported, lost, examples)) in cells.iter().zip(&results) {
        let name = ALPHABETS[*alphabet].0;
        println!(
            "{} {name} escape every {stride}: samples={ESCAPED_SAMPLES} reported_without_layer={reported} lost={lost}",
            skeleton(form)
        );
        if *lost > 0 {
            failures.push(format!("{form} {name} every {stride}: {lost} {examples:?}"));
        }
    }
    println!("elapsed={:.1}s", started.elapsed().as_secs_f64());
    // the base62 and base36 cells escaped every second byte are the reviewer's lossy cells; the
    // plain gates report most of them, so the guard is not vacuous.
    for ((form, _, alphabet, stride), (reported, _, _)) in cells.iter().zip(&results) {
        if matches!(alphabet, 0 | 5) && *stride == 2 {
            assert!(
                *reported * 2 > ESCAPED_SAMPLES,
                "{form} {}: only {reported} reportable",
                ALPHABETS[*alphabet].0
            );
        }
    }
    assert!(
        failures.is_empty(),
        "escaped regex payloads lost: {failures:#?}"
    );
}

#[test]
fn regex_class_escapes_stay_pattern_syntax() {
    // the class, boundary and anchor escapes are pattern syntax, and a pattern built of them keeps
    // its exemption on the pathless text.
    for line in [
        r"pattern = /^\d{3}-\d{4}\s\w+[A-Za-z]{2,8}$/i",
        r#"value="(?:\b[A-Z][a-z]+\s){2,4}\d{1,3}[^\s]+""#,
        r"rule=/^[\w.-]+@[\w-]+\.[a-z]{2,}(?:\s\S+)?$/",
    ] {
        assert!(
            text_ranges(line, &PLAIN).is_empty(),
            "class escapes reported: {}",
            skeleton(line)
        );
        assert!(
            text_ranges(line, &TRACED)
                .iter()
                .any(|(id, _)| id == "exempt:regex"),
            "class escapes not traced as regex: {}",
            skeleton(line)
        );
    }
}

#[test]
fn regex_body_recall_montecarlo() {
    let started = Instant::now();
    let tally = shards(|shard, quota| {
        let mut rng = Rng(0x0DDB_A11C_AFE5_7EA1 ^ (shard + 1) << 32);
        let mut tally = Tally::default();
        while tally.samples < quota {
            let mut tokens = Vec::with_capacity(BATCH);
            while tokens.len() < BATCH {
                // a javascript regex literal cannot hold an unescaped `/`.
                let token = rng.token();
                if !token.contains('/') {
                    tokens.push(token);
                }
            }
            let audit: Vec<String> = tokens
                .iter()
                .enumerate()
                .map(|(index, token)| format!("const re{index} = /{token}/g;"))
                .collect();
            let findings = scan_source("src/value.ts", &audit.join("\n"), &POSTURE);
            let mut reported = vec![Vec::new(); BATCH];
            for finding in findings.iter().filter(|finding| finding.rule_id == RULE) {
                reported[finding.line - 1].push(finding.matched_value.clone());
            }
            let text: Vec<String> = tokens
                .iter()
                .enumerate()
                .map(|(index, token)| match index % 3 {
                    0 => format!("pattern = /{token}/i"),
                    1 => format!("grep -E api_key={token} audit.log"),
                    _ => format!("rg 'route={token}' src"),
                })
                .collect();
            let joined = text.join("\n");
            let ranges = text_ranges(&joined, &PLAIN);
            let expected = controls(&tokens);
            let mut offset = 0;
            for (index, token) in tokens.iter().enumerate() {
                let target = locate(&text[index], token);
                let target = offset + target.start..offset + target.end;
                offset += text[index].len() + 1;
                tally.samples += 1;
                if !passes_entropy_check(token.as_bytes(), THRESHOLD) {
                    continue;
                }
                tally.reportable += 1;
                // the regex step claims a regex-shaped body by design; any other body is reported.
                if is_regex_shaped(token.as_bytes()) {
                    tally.shaped += 1;
                    continue;
                }
                if !expected[index] {
                    continue;
                }
                if !reported[index].contains(&token.as_bytes().to_vec()) {
                    tally.audit_misses += 1;
                    tally.miss("audit", &audit[index]);
                }
                if !covers(&ranges, RULE, &target) {
                    tally.text_misses += 1;
                    tally.miss("text", &text[index]);
                }
            }
        }
        tally
    });
    println!(
        "regex bodies: samples={} reportable={} regex_shaped={} audit_misses={} text_misses={} elapsed={:.1}s",
        tally.samples,
        tally.reportable,
        tally.shaped,
        tally.audit_misses,
        tally.text_misses,
        started.elapsed().as_secs_f64()
    );
    assert!(tally.samples >= MC_SAMPLES);
    assert_eq!(
        tally.audit_misses + tally.text_misses,
        0,
        "opaque regex bodies lost: {:#?}",
        tally.examples
    );
}

// ---------------------------------------------------------------------------------------------
// value grammar: misread keys, `&&`, prefixes, schemes, digests and markdown targets.
// ---------------------------------------------------------------------------------------------

#[test]
fn misread_keys_are_dropped_and_the_text_behind_them_is_read() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0004);
    for line in [
        "apt-get -o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true update",
        "    let entries: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();",
        "    EVP_CIPHER_CTX_ptr ctx = std::unique_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());",
        "value=$(printf '%s' \"$raw\" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')",
        "grep -E '^[[:alnum:]_]+=[[:print:]]+$' settings.env",
        "        \"script\": \"set -eu\\n: \\\"${DEPLOY_TARGET:?deploy target unset}\\\" && run\"",
        "printf 'header\\t= ${CONFIG_ROOT:-/opt/default/config}/bin\\n'",
    ] {
        assert!(
            text_ranges(line, &PLAIN).is_empty(),
            "misread key reported: {}",
            skeleton(line)
        );
    }
    for template in [
        "use std::collections::HashMap; api_key=TOKEN",
        "Acquire::Check-Valid-Until=false; api_key=TOKEN",
        "Config::Path::Leaf=TOKEN",
        "tr -d '[:space:]' ; SECRET_VALUE=TOKEN",
        "printf 'a\\n: b' ; SECRET_VALUE=TOKEN",
        "echo \"header\\ntoken=TOKEN\"",
        "echo \"a\\\\n: TOKEN\"",
    ] {
        let token = base62_token(&mut rng, 32);
        let line = template.replace("TOKEN", &token);
        let target = locate(&line, &token);
        assert!(
            covers(&text_ranges(&line, &PLAIN), RULE, &target),
            "token behind a misread key lost: {template}"
        );
        assert!(
            values(&scan_source("config/value.txt", &line, &PLAIN), RULE)
                .iter()
                .any(|value| value
                    .windows(token.len())
                    .any(|part| part == token.as_bytes())),
            "diff surface lost the token: {template}"
        );
    }
}

#[test]
fn double_ampersand_ends_an_unquoted_value() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0005);
    let hex = low_entropy_hex(&mut rng, 40);
    let token = base62_token(&mut rng, 32);
    for (template, value) in [
        ("TOKEN=VALUE&&echo done", &hex),
        ("export TOKEN=VALUE&&make build", &hex),
        ("TOKEN=VALUE&& echo done", &token),
        ("TOKEN=VALUE&&true", &token),
        ("TOKEN=VALUE&", &token),
    ] {
        let line = template.replace("VALUE", value);
        let target = locate(&line, value);
        let ranges = text_ranges(&line, &PLAIN);
        assert!(
            ranges
                .iter()
                .any(|(id, range)| id == RULE && *range == target),
            "span is not exactly the value: {template}"
        );
        assert_eq!(
            values(&scan_source("scripts/run.sh", &line, &PLAIN), RULE),
            vec![value.as_bytes().to_vec()],
            "diff span: {template}"
        );
    }
    // `&` inside a value is data: only a trailing run or a `&&` list operator ends it.
    let line = format!("TOKEN={token}&x=1");
    let ranges = text_ranges(&line, &PLAIN);
    assert!(
        ranges
            .iter()
            .any(|(id, range)| id == RULE && range.end == line.len()),
        "an inner ampersand cut the value"
    );
}

#[test]
fn hash_context_belongs_to_its_own_assignment() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0006);
    for _ in 0..32 {
        let digest = low_entropy_hex(&mut rng, 64);
        let secret = low_entropy_hex(&mut rng, 40);
        for (template, reported) in [
            ("sha256=DIGEST api_key=SECRET", true),
            ("api_key=SECRET sha256=DIGEST", true),
            ("sha256=DIGEST; api_key=SECRET", true),
            ("checksum_sha256=SECRET", false),
            ("api_key=SECRET # sha1 of the release", false),
        ] {
            let line = template
                .replace("DIGEST", &digest)
                .replace("SECRET", &secret);
            let target = locate(&line, &secret);
            let ranges = text_ranges(&line, &PLAIN);
            assert_eq!(
                ranges
                    .iter()
                    .any(|(id, range)| id == RULE && *range == target),
                reported,
                "{template}"
            );
            assert!(
                !line.contains(&digest) || !covers(&ranges, RULE, &locate(&line, &digest)),
                "digest reported: {template}"
            );
            assert_eq!(
                values(&scan_source("config/value.txt", &line, &PLAIN), RULE)
                    .contains(&secret.as_bytes().to_vec()),
                reported,
                "diff surface: {template}"
            );
        }
    }
}

#[test]
fn string_prefixes_and_raw_strings_capture_their_body() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0007);
    // (template, the source file whose language owns the prefix, the shell word of an env-style
    // assignment)
    for (template, source, shell_word) in [
        ("key = rb\"TOKEN\"", "src/value.py", Some("rb\"TOKEN\"")),
        ("key = b'TOKEN'", "src/value.py", Some("b'TOKEN'")),
        (
            "    key = u8\"TOKEN\";",
            "src/value.cpp",
            Some("u8\"TOKEN\""),
        ),
        ("    key = L\"TOKEN\";", "src/value.cpp", Some("L\"TOKEN\"")),
        ("key = f\"TOKEN\"", "src/value.py", Some("f\"TOKEN\"")),
        ("key = t'TOKEN'", "src/value.py", Some("t'TOKEN'")),
        ("    key: b\"TOKEN\",", "src/value.rs", Some("b\"TOKEN\"")),
        ("let k = #\"TOKEN\"#", "src/value.swift", None),
        ("let k = ##\"TOKEN\"##", "src/value.swift", None),
        ("configure(token: #\"TOKEN\"#)", "src/value.swift", None),
        ("    let key = b\"TOKEN\";", "src/value.rs", None),
    ] {
        let token = base62_token(&mut rng, 32);
        let line = template.replace("TOKEN", &token);
        let target = locate(&line, &token);
        // a source file of the prefix's language reports the body, and so does every surface for
        // a line that is no env-style assignment. a c++ statement is parsed inside a function.
        let unit = if source.ends_with(".cpp") {
            format!("void f() {{\n{line}\n}}")
        } else {
            line.clone()
        };
        assert_eq!(
            values(&scan_source(source, &unit, &PLAIN), RULE),
            vec![token.as_bytes().to_vec()],
            "source surface: {template}"
        );
        // the pathless surface, a shell script and a file of unknown language read an env-style
        // assignment as the shell word it is, prefix and quotes included.
        for surface in [None, Some("scripts/value.sh"), Some("config/value.txt")] {
            let ranges = match surface {
                None => text_ranges(&line, &PLAIN),
                Some(path) => scan_source(path, &line, &PLAIN)
                    .into_iter()
                    .filter(|finding| finding.rule_id == RULE)
                    .map(|finding| {
                        let start =
                            locate(&line, std::str::from_utf8(&finding.matched_value).unwrap());
                        (finding.rule_id, start)
                    })
                    .collect(),
            };
            if let Some(word) = shell_word {
                let word = locate(&line, &word.replace("TOKEN", &token));
                assert!(
                    ranges
                        .iter()
                        .any(|(id, range)| id == RULE && *range == word),
                    "{surface:?}: shell word not read whole: {template}"
                );
            } else {
                assert!(
                    ranges
                        .iter()
                        .any(|(id, range)| id == RULE && *range == target),
                    "{surface:?}: body not captured exactly: {template}"
                );
            }
        }
    }
}

#[test]
fn a_word_after_a_prefixed_string_keeps_the_shell_value() {
    // a shell concatenates `b"short"<word>` into one word, and no source language continues a
    // string with a bare word, so the value is the whole word on every surface.
    let mut rng = Rng(0x51A7_E5C0_FFEE_000C);
    for template in [
        "VALUE=b\"short\"TOKEN",
        "VALUE=b\"\"TOKEN",
        "VALUE=r\"short\"TOKEN",
        "VALUE=f\"short\"TOKEN",
        "VALUE=u8\"short\"TOKEN",
        "VALUE=#\"short\"#TOKEN",
        "export VALUE=rb'x'TOKEN",
        "VALUE=b\"short\",TOKEN",
        "VALUE=b\"short\";TOKEN",
        "VALUE=f\"{TOKEN}\"",
    ] {
        let token = base62_token(&mut rng, 40);
        let line = template.replace("TOKEN", &token);
        let target = locate(&line, &token);
        assert!(
            covers(&text_ranges(&line, &PLAIN), RULE, &target),
            "pathless token lost: {template}"
        );
        for path in ["scripts/value.sh", "config/.env", "config/value.txt"] {
            assert!(
                values(&scan_source(path, &line, &PLAIN), RULE)
                    .iter()
                    .any(|value| value
                        .windows(token.len())
                        .any(|part| part == token.as_bytes())),
                "{path}: token lost: {template}"
            );
        }
    }
}

#[test]
fn a_scheme_read_as_a_key_reports_the_whole_url() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0008);
    for template in [
        "see https://ci.example.test/hooks/callback?token=TOKEN for the hook",
        "<loc>https://ci.example.test/hooks/callback?token=TOKEN</loc>",
        "fetch https://deploy:TOKEN@registry.example.test/v2/ now",
    ] {
        let token = base62_token(&mut rng, 32);
        let line = template.replace("TOKEN", &token);
        let token_range = locate(&line, &token);
        let ranges = text_ranges(&line, &PLAIN);
        let url_start = line.find("https://").unwrap();
        assert!(
            ranges.iter().any(|(id, range)| id == RULE
                && range.start == url_start
                && range.end >= token_range.end),
            "not reported from the scheme: {template}"
        );
        assert!(
            ranges
                .iter()
                .all(|(id, range)| id != RULE || !line[range.clone()].starts_with("//")),
            "a split value was reported: {template}"
        );
    }
    // a split value the path check drops keeps that outcome.
    for line in [
        "see https://docs.example.test/guides/getting-started/installation for more",
        "source: https://github.com/example-org/example-repository/tree/main/docs",
    ] {
        assert!(
            text_ranges(line, &PLAIN).is_empty(),
            "path-shaped url reported: {line}"
        );
    }
}

#[test]
fn quoted_digest_records_are_hashes_and_their_twins_fire() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_0009);
    for _ in 0..32 {
        let md5 = low_entropy_hex(&mut rng, 32);
        let sha256 = low_entropy_hex(&mut rng, 64);
        for line in [
            format!("checksum = \"{sha256}\""),
            format!("    \"checksum\": \"{md5}\","),
            format!("digest: 'sha256:{sha256}'"),
            format!("X-Checksum-Sha256: \"{sha256}\""),
        ] {
            assert!(
                text_ranges(&line, &PLAIN).is_empty(),
                "digest record reported: {}",
                skeleton(&line)
            );
        }
        let secret = low_entropy_hex(&mut rng, 40);
        let token = base62_token(&mut rng, 32);
        for (line, value) in [
            // a digest-shaped value under a key that names no digest is an assignment secret.
            (format!("api_key = \"{secret}\""), &secret),
            // a digest key does not make a non-hex value a digest.
            (format!("checksum = \"{token}\""), &token),
            (format!("    \"digest\": \"{token}\","), &token),
        ] {
            assert!(
                covers(&text_ranges(&line, &PLAIN), RULE, &locate(&line, value)),
                "twin lost: {}",
                skeleton(&line)
            );
        }
    }
}

#[test]
fn markdown_targets_inside_call_literals_are_unwrapped() {
    let mut rng = Rng(0x51A7_E5C0_FFEE_000A);
    for line in [
        "render(\"[guide](https://github.com/example-org/example-repository/blob/main/README.md)\")",
        "notify(\"[notes](https://github.com/example-org/example-repository/releases)\")",
    ] {
        assert!(
            text_ranges(line, &PLAIN).is_empty(),
            "markdown target reported: {line}"
        );
    }
    let token = base62_token(&mut rng, 36);
    let line = format!("render(\"[download]({token})\")");
    let target = locate(&line, &token);
    assert!(
        text_ranges(&line, &PLAIN)
            .iter()
            .any(|(id, range)| id == RULE && *range == target),
        "opaque markdown target lost"
    );
}

#[test]
fn grammar_recall_montecarlo() {
    // every new drop or boundary of the value grammar, with a random token where a secret sits:
    // behind a scope separator, a posix class or an escape; before `&&`; after a digest assignment;
    // as a markdown target in a call; as a quoted value under a digest key.
    const FORMS: [&str; 10] = [
        "use std::io::Read; api_key=TOKEN",
        "Acquire::Check-Valid-Until=false; api_key=TOKEN",
        "tr -d '[:space:]' ; SECRET_VALUE=TOKEN",
        "printf 'a\\n: b' ; SECRET_VALUE=TOKEN",
        "echo \"header\\ntoken=TOKEN\"",
        "SECRET_VALUE=TOKEN&&echo done",
        "sha256=e3b0c44298fc1c14 api_key=TOKEN",
        "render(\"[download](TOKEN)\")",
        "checksum = \"TOKEN\"",
        "key = f\"{name}TOKEN\"",
    ];
    const CONTROLS: [&str; 10] = [
        "api_key=TOKEN",
        "api_key=TOKEN",
        "SECRET_VALUE=TOKEN",
        "SECRET_VALUE=TOKEN",
        "echo \"ntoken=TOKEN\"",
        "SECRET_VALUE=TOKEN",
        "api_key=TOKEN",
        "render(\"TOKEN\")",
        "value = \"TOKEN\"",
        "render(\"TOKEN\")",
    ];
    let started = Instant::now();
    let tally = shards(|shard, quota| {
        let mut rng = Rng(0xC0FF_EE15_600D_F00D ^ (shard + 1) << 32);
        let mut tally = Tally::default();
        while tally.samples < quota {
            let mut lines = Vec::with_capacity(BATCH);
            let mut tokens = Vec::with_capacity(BATCH);
            for index in 0..BATCH {
                let token = rng.token();
                lines.push(FORMS[index % FORMS.len()].replace("TOKEN", &token));
                tokens.push(token);
            }
            let text = lines.join("\n");
            let ranges = text_ranges(&text, &PLAIN);
            // each form is held to its own value context without the grammar feature under
            // test, so a predicate every such value already faces is not counted as a loss.
            let control_lines: Vec<String> = tokens
                .iter()
                .enumerate()
                .map(|(index, token)| CONTROLS[index % FORMS.len()].replace("TOKEN", token))
                .collect();
            let control_text = control_lines.join("\n");
            let control_ranges = text_ranges(&control_text, &PLAIN);
            let mut control_offset = 0;
            let mut offset = 0;
            for (index, (line, token)) in lines.iter().zip(&tokens).enumerate() {
                let target = locate(line, token);
                let target = offset + target.start..offset + target.end;
                offset += line.len() + 1;
                let control = locate(&control_lines[index], token);
                let control = control_offset + control.start..control_offset + control.end;
                control_offset += control_lines[index].len() + 1;
                tally.samples += 1;
                // a digest-shaped value under a digest key is a hash by design.
                let digest_key = FORMS[index % FORMS.len()].starts_with("checksum")
                    && is_digest_record(Some(b"checksum"), token.as_bytes());
                if !passes_entropy_check(token.as_bytes(), THRESHOLD)
                    || !covers(&control_ranges, RULE, &control)
                    || digest_key
                {
                    continue;
                }
                tally.reportable += 1;
                if !covers(&ranges, RULE, &target) {
                    tally.text_misses += 1;
                    tally.miss("text", line);
                }
            }
        }
        tally
    });
    println!(
        "grammar forms: samples={} reportable={} misses={} elapsed={:.1}s",
        tally.samples,
        tally.reportable,
        tally.text_misses,
        started.elapsed().as_secs_f64()
    );
    assert!(tally.samples >= MC_SAMPLES);
    assert_eq!(
        tally.text_misses, 0,
        "tokens lost to the grammar: {:#?}",
        tally.examples
    );
}

// ---------------------------------------------------------------------------------------------
// inverse monte-carlo: the payload inside each structural position a reader accepts, not only
// between structural pieces. a random token (1e5 per cell) or a token cut into 2-5-byte pieces
// joined by a separator the reader accepts (2e4 per cell) takes the place of `TOKEN`, and the
// form may lose no payload that the same payload reports standing alone (`controls`).
// ---------------------------------------------------------------------------------------------

/// payloads per chunked inverse cell.
const CHUNK_SAMPLES: usize = 20_000;

/// a surface a generated line is scanned on.
#[derive(Clone, Copy, Debug)]
enum Surface {
    /// the pathless text of the redact hook.
    Text,
    /// a diff file with its blob, so the parser posture reads a supported source file.
    File(&'static str),
    /// a diff file without blob context: no parser posture, the value grammar alone.
    Unparsed(&'static str),
}

impl Surface {
    /// a file the value grammar reads as it reads the pathless text: no parser, no tracker and no
    /// python hole reading.
    fn reads_as_text(self) -> bool {
        matches!(self, Surface::File(path) if [SH, ENV, TXT].contains(&path))
    }
}

/// a surface that reads as the text (`Surface::reads_as_text`) is scanned for one payload in this
/// many when its cell scans the text surface too, so each such cell keeps its share of file
/// samples: the text surface scans every payload through the same readers, and each file scan adds
/// the cost of a whole surface.
const FILE_SURFACE_STRIDE: usize = 10;

/// whether each payload is covered by a tier-3 finding on its own line, the lines scanned together
/// on one surface.
fn coverage(surface: Surface, lines: &[String], payloads: &[String]) -> Vec<bool> {
    let source = lines.join("\n");
    let findings = match surface {
        Surface::Text => {
            let ranges = text_ranges(&source, &PLAIN);
            let mut offset = 0;
            return lines
                .iter()
                .zip(payloads)
                .map(|(line, payload)| {
                    let target = locate(line, payload);
                    let target = offset + target.start..offset + target.end;
                    offset += line.len() + 1;
                    covers(&ranges, RULE, &target)
                })
                .collect();
        }
        Surface::File(path) => scan(&[file(path, &source)], &SCANNER, &PLAIN),
        Surface::Unparsed(path) => scan(&[file_without_context(path, &source)], &SCANNER, &PLAIN),
    };
    let mut reported = vec![Vec::new(); lines.len()];
    for finding in findings
        .into_iter()
        .filter(|finding| finding.rule_id == RULE)
    {
        reported[finding.line - 1].push(finding.matched_value);
    }
    reported
        .iter()
        .zip(payloads)
        .map(|(values, payload)| {
            values.iter().any(|value| {
                value
                    .windows(payload.len())
                    .any(|part| part == payload.as_bytes())
            })
        })
        .collect()
}

/// one inverse cell: the form, the separator of a chunked payload (`None` for a random token) and
/// the surfaces it is measured on.
struct InverseCell {
    form: &'static str,
    separator: Option<&'static str>,
    surfaces: &'static [Surface],
}

const PY: &str = "src/value.py";
const SH: &str = "scripts/value.sh";
const ENV: &str = "config/.env";
const TXT: &str = "config/value.txt";

/// a random token inside each position. the expression positions of a hole (`obj.TOKEN`,
/// `call(TOKEN)`, `items[TOKEN]`) are measured without a parse: the parser proves a name there
/// to be code, while the value grammar has to show it.
const TOKEN_CELLS: &[InverseCell] = &[
    // a python f-string hole: bare, a quoted string with escaped quotes, a format spec, the
    // expression positions, and literal text between holes.
    InverseCell {
        form: "value = f\"{TOKEN}\"",
        separator: None,
        surfaces: &[Surface::Text, Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{'a\\'TOKEN\\'b'}\"",
        separator: None,
        surfaces: &[Surface::Text, Surface::File(PY)],
    },
    InverseCell {
        form: "value = f\"{'\\'TOKEN\\''}\"",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{name:TOKEN}\"",
        separator: None,
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{name!r:TOKEN}\"",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    // the specification of a nested replacement field, after the field.
    InverseCell {
        form: "value = f\"{x:{y}TOKEN}\"",
        separator: None,
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{obj.TOKEN}\"",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{call(TOKEN)}\"",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{items[TOKEN]}\"",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{a}TOKEN{b}\"",
        separator: None,
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    // a language string prefix: a word after the string, and a hole on a surface that is no
    // python source.
    InverseCell {
        form: "VALUE=b\"short\"TOKEN",
        separator: None,
        surfaces: &[Surface::Text, Surface::File(SH)],
    },
    InverseCell {
        form: "VALUE=b\"\"TOKEN",
        separator: None,
        surfaces: &[Surface::Text, Surface::File(ENV)],
    },
    InverseCell {
        form: "VALUE=r\"short\"TOKEN",
        separator: None,
        surfaces: &[Surface::Text, Surface::File(TXT)],
    },
    InverseCell {
        form: "VALUE=f\"short\"TOKEN",
        separator: None,
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "export VALUE=rb'x'TOKEN",
        separator: None,
        surfaces: &[Surface::File(SH)],
    },
    InverseCell {
        form: "VALUE=f\"{TOKEN}\"",
        separator: None,
        surfaces: &[
            Surface::Text,
            Surface::File(SH),
            Surface::File(ENV),
            Surface::File(TXT),
        ],
    },
    InverseCell {
        form: "key = b\"TOKEN\"",
        separator: None,
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY), Surface::File(TXT)],
    },
    // a misread key: the text behind a scope separator, a posix class or an escape letter.
    InverseCell {
        form: "X::TOKEN",
        separator: None,
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "tr -d '[[:alnum:]]TOKEN'",
        separator: None,
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "printf 'a\\n: TOKEN'",
        separator: None,
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "Acquire::TOKEN=true",
        separator: None,
        surfaces: &[Surface::Text],
    },
    // the command word after a shell `&&`.
    InverseCell {
        form: "KEY=short&&TOKEN",
        separator: None,
        surfaces: &[Surface::Text, Surface::File(SH)],
    },
];

/// a token cut into pieces and joined by each separator a reader accepts: f-string holes, the
/// member chain and the identifier of one hole, the expression and format specification of one
/// hole, the separators behind a misread key, and the characters of a command word after `&&`.
/// pieces joined by `::` or `/` behind `X::` are left out: the chunk guard keeps that capture, and
/// the value `:<pieces>` it keeps meets the entropy gate and the keyed relative-path step, which
/// judged it the same way before the misread key was recognized, and which a call literal never
/// meets.
const CHUNK_CELLS: &[InverseCell] = &[
    InverseCell {
        form: "value = f\"TOKEN\"",
        separator: Some("{x}"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{a}TOKEN{b}\"",
        separator: Some("{c.d}"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{TOKEN}\"",
        separator: Some("."),
        surfaces: &[Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{TOKEN}\"",
        separator: Some("_"),
        surfaces: &[Surface::Unparsed(PY)],
    },
    // a format specification: a token cut into groups inside it, and a token whose first group
    // is the hole's expression, before a `:` or a conversion, and the rest the specification.
    InverseCell {
        form: "value = f\"{name:TOKEN}\"",
        separator: Some(":"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{name:TOKEN}\"",
        separator: Some("."),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{name:TOKEN}\"",
        separator: Some("_"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{name:TOKEN}\"",
        separator: Some("-"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"{TOKEN}\"",
        separator: Some(":"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "value = f\"x{TOKEN}y\"",
        separator: Some("!r:"),
        surfaces: &[Surface::File(PY), Surface::Unparsed(PY)],
    },
    InverseCell {
        form: "X::TOKEN",
        separator: Some("."),
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "X::TOKEN",
        separator: Some("+"),
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "tr -d '[[:alnum:]]TOKEN'",
        separator: Some("_"),
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "printf 'a\\n: TOKEN'",
        separator: Some("-"),
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "Acquire::TOKEN=true",
        separator: Some("-"),
        surfaces: &[Surface::Text],
    },
    InverseCell {
        form: "KEY=short&&TOKEN",
        separator: Some("-"),
        surfaces: &[Surface::Text, Surface::File(SH)],
    },
    InverseCell {
        form: "KEY=short&&TOKEN",
        separator: Some("_"),
        surfaces: &[Surface::Text],
    },
];

/// the counts of one cell in one shard.
#[derive(Clone, Default)]
struct CellTally {
    reportable: usize,
    /// reportable payloads scanned, per surface (`FILE_SURFACE_STRIDE`).
    scanned: Vec<usize>,
    misses: Vec<usize>,
    examples: Vec<String>,
}

/// whether a cell's payload opens an f-string hole in a python file the parser reads: its first
/// piece is then the hole's expression, and a piece no python name can be (`12ab`, `if`) is a
/// syntax error that would leave the whole generated file unparsed.
fn opens_parsed_hole(cell: &InverseCell) -> bool {
    cell.form.contains("{TOKEN")
        && cell
            .surfaces
            .iter()
            .any(|surface| matches!(surface, Surface::File(path) if path.ends_with(".py")))
}

/// whether a payload opens with a python name that no keyword takes.
fn leads_with_name(payload: &str) -> bool {
    const KEYWORDS: [&str; 35] = [
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield",
    ];
    let name = &payload[..payload
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(payload.len())];
    name.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_')
        && !KEYWORDS.contains(&name)
}

/// runs every cell over `samples` payloads per cell, on all cores, each payload held to what it
/// reports standing alone (`controls`); only a payload that reports standing alone is scanned in
/// its form. cells with the same separator share each batch of payloads and its controls, drawn
/// to lead with a python name when one of those cells opens a parsed hole (`opens_parsed_hole`).
/// returns one line per cell that lost a payload.
fn inverse_montecarlo(cells: &[InverseCell], samples: usize, seed: u64) -> Vec<String> {
    let started = Instant::now();
    let shards = std::thread::available_parallelism().map_or(SHARDS, |cores| cores.get());
    let per_shard = samples.div_ceil(shards);
    let results: Vec<(usize, Vec<CellTally>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..shards)
            .map(|shard| {
                scope.spawn(move || {
                    let mut rng = Rng(seed ^ ((shard as u64 + 1) << 32));
                    let mut tallies: Vec<CellTally> = cells
                        .iter()
                        .map(|cell| CellTally {
                            scanned: vec![0; cell.surfaces.len()],
                            misses: vec![0; cell.surfaces.len()],
                            ..CellTally::default()
                        })
                        .collect();
                    let mut done = 0;
                    while done < per_shard {
                        let batch = BATCH.min(per_shard - done);
                        let mut streams: Vec<(Option<&str>, Vec<String>, Vec<bool>)> = Vec::new();
                        for (cell, tally) in cells.iter().zip(&mut tallies) {
                            let stream = match streams
                                .iter()
                                .position(|stream| stream.0 == cell.separator)
                            {
                                Some(position) => position,
                                None => {
                                    let named = cells.iter().any(|other| {
                                        other.separator == cell.separator
                                            && opens_parsed_hole(other)
                                    });
                                    let payloads: Vec<String> = (0..batch)
                                        .map(|_| {
                                            loop {
                                                let payload = match cell.separator {
                                                    None => rng.token(),
                                                    Some(separator) => rng.chunked(separator),
                                                };
                                                if !named || leads_with_name(&payload) {
                                                    break payload;
                                                }
                                            }
                                        })
                                        .collect();
                                    let expected = controls(&payloads);
                                    streams.push((cell.separator, payloads, expected));
                                    streams.len() - 1
                                }
                            };
                            let (_, payloads, expected) = &streams[stream];
                            let payloads: Vec<String> = payloads
                                .iter()
                                .zip(expected)
                                .filter(|(_, reportable)| **reportable)
                                .map(|(payload, _)| payload.clone())
                                .collect();
                            let lines: Vec<String> = payloads
                                .iter()
                                .map(|payload| cell.form.replacen("TOKEN", payload, 1))
                                .collect();
                            tally.reportable += payloads.len();
                            let text_scanned = cell
                                .surfaces
                                .iter()
                                .any(|surface| matches!(surface, Surface::Text));
                            for (index, &surface) in cell.surfaces.iter().enumerate() {
                                let stride = if text_scanned && surface.reads_as_text() {
                                    FILE_SURFACE_STRIDE
                                } else {
                                    1
                                };
                                let picked: Vec<usize> = (0..lines.len()).step_by(stride).collect();
                                let pick = |values: &[String]| -> Vec<String> {
                                    picked.iter().map(|&at| values[at].clone()).collect()
                                };
                                let picked_lines = pick(&lines);
                                let hits = coverage(surface, &picked_lines, &pick(&payloads));
                                tally.scanned[index] += picked.len();
                                for (line, hit) in picked_lines.iter().zip(hits) {
                                    if !hit {
                                        tally.misses[index] += 1;
                                        if tally.examples.len() < 3 {
                                            tally
                                                .examples
                                                .push(format!("{surface:?}: {}", skeleton(line)));
                                        }
                                    }
                                }
                            }
                        }
                        done += batch;
                    }
                    (done, tallies)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("monte-carlo shard"))
            .collect()
    });
    let total: usize = results.iter().map(|(done, _)| done).sum();
    assert!(total >= samples, "short run: {total}");
    let mut failures = Vec::new();
    for (index, cell) in cells.iter().enumerate() {
        let reportable: usize = results
            .iter()
            .map(|(_, tallies)| tallies[index].reportable)
            .sum();
        let sum = |count: fn(&CellTally, usize) -> usize| -> Vec<usize> {
            (0..cell.surfaces.len())
                .map(|surface| {
                    results
                        .iter()
                        .map(|(_, tallies)| count(&tallies[index], surface))
                        .sum()
                })
                .collect()
        };
        let scanned = sum(|tally, surface| tally.scanned[surface]);
        let misses = sum(|tally, surface| tally.misses[surface]);
        assert!(
            scanned
                .iter()
                .all(|&count| count * FILE_SURFACE_STRIDE >= reportable),
            "{} sep={:?}: a surface scanned too few payloads: {scanned:?} of {reportable}",
            skeleton(cell.form),
            cell.separator
        );
        println!(
            "{} sep={:?} samples={total} reportable={reportable} scanned={scanned:?} misses={:?}",
            skeleton(cell.form),
            cell.separator,
            cell.surfaces.iter().zip(&misses).collect::<Vec<_>>()
        );
        if misses.iter().any(|&count| count > 0) {
            let examples: Vec<&String> = results
                .iter()
                .flat_map(|(_, tallies)| &tallies[index].examples)
                .take(3)
                .collect();
            failures.push(format!(
                "{} sep={:?}: misses {misses:?} {examples:?}",
                skeleton(cell.form),
                cell.separator
            ));
        }
    }
    println!("elapsed={:.1}s", started.elapsed().as_secs_f64());
    failures
}

#[test]
fn token_inside_structure_recall_montecarlo() {
    let failures = inverse_montecarlo(TOKEN_CELLS, MC_SAMPLES, 0x1A7E_5EED_0000_0001);
    assert!(
        failures.is_empty(),
        "tokens lost inside structure: {failures:#?}"
    );
}

#[test]
fn chunked_token_across_structure_recall_montecarlo() {
    let failures = inverse_montecarlo(CHUNK_CELLS, CHUNK_SAMPLES, 0x1A7E_5EED_0000_0002);
    assert!(
        failures.is_empty(),
        "chunked tokens lost across structure: {failures:#?}"
    );
}
