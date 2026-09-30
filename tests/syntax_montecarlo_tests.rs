//! monte-carlo guard for the syntax exemption. random tokens are placed in every position the
//! recognizer reads since the macro, member-chain, type, enclosing-expression, tuple, go-type and
//! interpolation readings were added, and none may be covered by an expression span. on the text
//! surface, none may be claimed by an `exempt:syntax` decision. only tokens the rule would report
//! on their own are drawn, since the layer traces a decision before the entropy gate runs.
//!
//! the payload is also placed inside each position those readings treat as structure (a macro or
//! attribute name, a member, a type, a generic argument, a labelled argument read from its
//! enclosing call, text between interpolation holes), unchunked, cut into short groups joined by
//! `.`, `?.`, `::` or `->`, and cut into long one-word members. no expression span may cover such a
//! payload, and on the text and diff surfaces no `exempt:syntax` decision may drop one that the
//! same payload standing alone keeps reported.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use sekretbarilo::scanner::syntax::expression_span;
use sekretbarilo::scanner::wordshape::is_word_structured;
use std::ops::Range;
use std::sync::LazyLock;

/// predicate samples per position, spread over the alphabets.
const PREDICATE_SAMPLES: usize = 100_000;
/// text-surface samples per position and alphabet.
const ENGINE_SAMPLES: usize = 300;
/// the largest random-exemption rate accepted for a word-shaped alphabet.
const WORD_SHAPED_MAX_RATE: f64 = 0.001;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX: &[u8] = b"0123456789abcdef";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// lowercase letters and digits, the alphabet of many generated ids, split into letter runs by its
/// digits alone.
const BASE36_LOWER: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
/// the bytes an identifier segment may hold, the alphabet the recognizer itself accepts.
const IDENTIFIER: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
/// lowercase letters alone read like words more often than any encoding alphabet.
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

const OPAQUE_ALPHABETS: [(&str, &[u8]); 7] = [
    ("base62", BASE62),
    ("base64", BASE64),
    ("base64url", BASE64URL),
    ("hex", HEX),
    ("base32", BASE32),
    ("base36-lower", BASE36_LOWER),
    ("identifier", IDENTIFIER),
];
const WORD_SHAPED_ALPHABETS: [(&str, &[u8]); 1] = [("lowercase", LOWER)];

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

/// xorshift64*
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    /// a token the rule would report on its own: 20 to 64 bytes with entropy at the 4.0 gate, or
    /// for hex an exact 32, 40 or 64 digits, the lengths the hex policy and the syntax veto read.
    fn token(&mut self, alphabet: &[u8]) -> String {
        loop {
            let length = if alphabet == HEX {
                [32, 40, 64][self.below(3)]
            } else {
                20 + self.below(45)
            };
            let token: String = (0..length)
                .map(|_| char::from(alphabet[self.below(alphabet.len())]))
                .collect();
            if alphabet == HEX || shannon_entropy(token.as_bytes()) >= 4.0 {
                return token;
            }
        }
    }
}

/// one placement: the line, where the capture the engine evaluates begins, and the token range.
struct Placement {
    line: String,
    capture_start: usize,
    token: Range<usize>,
}

fn place(prefix: &str, capture_start: usize, token: &str, suffix: &str) -> Placement {
    Placement {
        line: format!("{prefix}{token}{suffix}"),
        capture_start,
        token: prefix.len()..prefix.len() + token.len(),
    }
}

type Position = (&'static str, fn(&str, &mut Prng) -> Placement);

/// every position a token can take in the readings the syntax step gained.
const POSITIONS: [Position; 26] = [
    ("macro argument", |t, _| place("#expect(", 0, t, ")")),
    ("macro member argument", |t, _| {
        place("#expect(settings.", 0, t, ")")
    }),
    ("attribute argument", |t, _| place("@Attribute(", 0, t, ")")),
    ("macro name", |t, _| place("#", 0, t, "(value)")),
    ("attribute item", |t, _| place("#[", 0, t, "]")),
    ("attribute argument item", |t, _| {
        place("#[derive(", 0, t, ")]")
    }),
    ("closure parameter member call", |t, _| {
        place("$0.", 0, t, "()")
    }),
    ("closure parameter member", |t, _| place("$0.", 0, t, "")),
    ("chain tail", |t, _| place("name: settings.", 6, t, "")),
    ("chain head", |t, _| place("name: ", 6, t, ".configuration")),
    ("chain middle", |t, _| {
        place("name: self.", 6, t, ".configuration")
    }),
    ("optional chain tail", |t, _| {
        place("name: settings?.", 6, t, "")
    }),
    ("split chain", |t, rng| {
        let cut = 1 + rng.below(t.len() - 1);
        let dotted = format!("{}.{}", &t[..cut], &t[cut..]);
        place("name: ", 6, &dotted, "")
    }),
    ("optional type", |t, _| place("let value: ", 11, t, "?")),
    ("unwrapped type", |t, _| place("let value: ", 11, t, "!")),
    ("enclosed argument", |t, _| {
        place("foo(key: ", 9, t, ").configuration")
    }),
    ("enclosed optional argument", |t, _| {
        place("store.update(key: ", 18, t, ")?.configuration = value")
    }),
    ("enclosed macro argument", |t, _| {
        place("#expect(foo(key: ", 17, t, ").configuration == nil)")
    }),
    ("enclosed call argument", |t, _| {
        place("value = handler.process(", 24, t, ")")
    }),
    ("bare call argument", |t, _| place("process(", 0, t, ")")),
    ("interpolated text", |t, _| {
        place("let x = build(\"", 8, t, "-\\(value)\")")
    }),
    ("text after a hole", |t, _| {
        place("let x = build(\"${value}", 8, t, "\")")
    }),
    ("tuple member", |t, _| place("self.0.", 0, t, "()")),
    ("go slice type", |t, _| place("[]", 0, t, "{value}")),
    ("go map type", |t, _| place("map[string]", 0, t, "{}")),
    ("macro bang call", |t, _| place("", 0, t, "!(value)")),
];

/// the letter case and digit shape of a failing line, so a report carries no generated value.
fn case_shape(line: &str) -> String {
    line.chars()
        .map(|c| match c {
            'a'..='z' => 'a',
            'A'..='Z' => 'A',
            '0'..='9' => '9',
            other => other,
        })
        .collect()
}

fn covers(placement: &Placement) -> bool {
    expression_span(placement.line.as_bytes(), placement.capture_start, 4096).is_some_and(|span| {
        span.start <= placement.capture_start && span.end >= placement.token.end
    })
}

#[test]
fn syntax_spans_never_cover_random_tokens() {
    let mut rng = Prng(0x9E37_79B9_7F4A_7C15);
    let mut failures = Vec::new();
    let mut per_alphabet = [0_usize; OPAQUE_ALPHABETS.len()];
    for (name, position) in POSITIONS {
        let mut exempt = 0;
        let mut first = None;
        for sample in 0..PREDICATE_SAMPLES {
            let index = sample % OPAQUE_ALPHABETS.len();
            let token = rng.token(OPAQUE_ALPHABETS[index].1);
            let placement = position(&token, &mut rng);
            per_alphabet[index] += 1;
            if covers(&placement) {
                exempt += 1;
                first.get_or_insert_with(|| {
                    format!(
                        "{} {}",
                        OPAQUE_ALPHABETS[index].0,
                        case_shape(&placement.line)
                    )
                });
            }
        }
        eprintln!("syntax predicate {name:<30} samples={PREDICATE_SAMPLES} exemptions={exempt}");
        if exempt > 0 {
            failures.push(format!("{name}: {exempt} exemptions, first {first:?}"));
        }
    }
    for ((name, _), samples) in OPAQUE_ALPHABETS.iter().zip(per_alphabet) {
        eprintln!("syntax predicate alphabet {name:<10} samples={samples}");
        assert!(samples >= 100_000, "{name}: {samples} samples");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn syntax_spans_rarely_cover_word_shaped_tokens() {
    let mut rng = Prng(0xD1B5_4A32_D192_ED03);
    for (alphabet, letters) in WORD_SHAPED_ALPHABETS {
        let mut total = 0;
        let mut exempt_total = 0;
        for (name, position) in POSITIONS {
            let mut exempt = 0;
            for _ in 0..PREDICATE_SAMPLES / 4 {
                let token = rng.token(letters);
                exempt += usize::from(covers(&position(&token, &mut rng)));
            }
            total += PREDICATE_SAMPLES / 4;
            exempt_total += exempt;
            eprintln!(
                "syntax word-shaped {alphabet} {name:<30} samples={} exemptions={exempt}",
                PREDICATE_SAMPLES / 4
            );
        }
        let rate = exempt_total as f64 / total as f64;
        eprintln!(
            "syntax word-shaped {alphabet} samples={total} exemptions={exempt_total} rate={:.5}%",
            rate * 100.0
        );
        assert!(
            rate < WORD_SHAPED_MAX_RATE,
            "{alphabet}: rate {rate} over {total} samples"
        );
    }
}

#[test]
fn text_surface_never_claims_random_tokens_as_syntax() {
    let mut traced = CompiledAllowlist::default_allowlist().unwrap();
    traced.trace_exemptions = true;
    let mut rng = Prng(0x94D0_49BB_1331_11EB);
    let mut failures = Vec::new();
    for (name, position) in POSITIONS {
        let mut claimed = 0;
        for (alphabet, letters) in OPAQUE_ALPHABETS {
            for _ in 0..ENGINE_SAMPLES {
                let token = rng.token(letters);
                let placement = position(&token, &mut rng);
                let syntax = scan_text(&placement.line, &SCANNER, &traced)
                    .into_iter()
                    .any(|found| {
                        found.rule_id == "exempt:syntax"
                            && found.range.start < placement.token.end
                            && placement.token.start < found.range.end
                    });
                if syntax {
                    claimed += 1;
                    failures.push(format!("{name} {alphabet}"));
                }
            }
        }
        eprintln!(
            "syntax text surface {name:<30} samples={} claimed={claimed}",
            ENGINE_SAMPLES * OPAQUE_ALPHABETS.len()
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// the payload inside the positions the widened readings take for structure.

/// predicate samples per chunk or long-member cell.
const CHUNK_SAMPLES: usize = 20_000;
/// text- and diff-surface samples per position and payload family.
const INSIDE_ENGINE_SAMPLES: usize = 60;
/// the rule the syntax step exempts from.
const RULE: &str = "generic-high-entropy-value";
/// the diff surface scans an ordinary data path, in full posture.
const FILE_PATH: &str = "corpus/shapes.txt";

/// positions of the widened readings with the payload inside the position: an attribute name, an
/// inner attribute, a go type assertion and pointer, a map key, an array and a package-qualified
/// element type, the generic argument of an open call, an open macro call, a labelled argument read
/// from its enclosing call (bare, with a member after it, inside a string), a call ended by a quote
/// and the text between two interpolation holes.
const INSIDE_POSITIONS: [Position; 14] = [
    ("attribute name", |t, _| place("@", 0, t, "(value)")),
    ("inner attribute item", |t, _| place("#![", 0, t, "]")),
    ("type assertion", |t, _| {
        place("value.(", 0, t, ").Transition(state)")
    }),
    ("pointer assertion", |t, _| place("value.(*", 0, t, ")")),
    ("map key type", |t, _| place("map[", 0, t, "]int{}")),
    ("array type", |t, _| place("[4]", 0, t, "{}")),
    ("package element type", |t, _| {
        place("[]pkg.", 0, t, "{value}")
    }),
    ("open generic call", |t, _| {
        place("std::make_unique<", 0, t, ">(")
    }),
    ("open macro call", |t, _| {
        place("#expect(first, ", 0, t, ", ")
    }),
    ("labelled argument", |t, _| place("make(for: ", 10, t, ")")),
    ("labelled member argument", |t, _| {
        place("update(key: ", 12, t, ").configuration")
    }),
    ("labelled argument in a string", |t, _| {
        place("setting=\"make(for: ", 19, t, ")\"")
    }),
    ("call before a quote", |t, _| {
        place("foo(", 0, t, ")\"rest\"")
    }),
    ("text between holes", |t, _| {
        place("build(\"${a}", 0, t, "${b}\")")
    }),
];

/// positions a chunked payload or a run of long members takes: the value itself, a member, a type,
/// a macro or attribute name or argument, a closure or tuple member, a go type, a labelled argument,
/// a call ended by a quote and the text between two interpolation holes.
const CHUNK_POSITIONS: [Position; 13] = [
    ("standalone value", |t, _| place("License: ", 9, t, "")),
    ("chain tail", |t, _| place("name: settings.", 6, t, "")),
    ("optional type", |t, _| place("let value: ", 11, t, "?")),
    ("macro name", |t, _| place("#", 0, t, "(value)")),
    ("macro argument", |t, _| place("#expect(", 0, t, ")")),
    ("attribute argument item", |t, _| {
        place("#[derive(", 0, t, ")]")
    }),
    ("closure parameter member", |t, _| place("$0.", 0, t, "")),
    ("tuple member call", |t, _| place("self.0.", 0, t, "()")),
    ("go map value type", |t, _| place("map[string]", 0, t, "{}")),
    ("type assertion", |t, _| {
        place("value.(", 0, t, ").Transition(state)")
    }),
    ("labelled argument", |t, _| place("make(for: ", 10, t, ")")),
    ("labelled argument in a string", |t, _| {
        place("setting=\"make(for: ", 19, t, ")\"")
    }),
    ("text between holes", |t, _| {
        place("build(\"${a}", 0, t, "${b}\")")
    }),
];

/// the joints of a member chain.
const CHUNK_SEPARATORS: [&str; 4] = [".", "?.", "::", "->"];

/// the groups a token is cut into: two to five lowercase letters, consonant-vowel groups in lower
/// and capitalized case, and one to three letters with a run of one or two digits. every group
/// opens with a letter, so an identifier reader takes it.
#[derive(Clone, Copy)]
enum Chunk {
    Letters,
    ConsonantVowel,
    Capitalized,
    DigitRun,
}

const CHUNKS: [(&str, Chunk); 4] = [
    ("letters", Chunk::Letters),
    ("consonant-vowel", Chunk::ConsonantVowel),
    ("capitalized", Chunk::Capitalized),
    ("digit-run", Chunk::DigitRun),
];

/// long members: two to four runs of random letters joined by `.`, in lower or upper case.
const LONG_MEMBERS: [(&str, bool, usize, usize); 4] = [
    ("lower 6-11", false, 6, 11),
    ("lower 12-19", false, 12, 19),
    ("upper 6-11", true, 6, 11),
    ("upper 12-19", true, 12, 19),
];

const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
const VOWELS: &[u8] = b"aeiouy";
const DIGITS: &[u8] = b"0123456789";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

impl Prng {
    fn pick(&mut self, alphabet: &[u8]) -> char {
        char::from(alphabet[self.below(alphabet.len())])
    }

    fn group(&mut self, chunk: Chunk) -> String {
        let width = 2 + self.below(4);
        match chunk {
            Chunk::Letters => (0..width).map(|_| self.pick(LOWER)).collect(),
            Chunk::ConsonantVowel | Chunk::Capitalized => (0..width)
                .map(|index| {
                    let byte = if index % 2 == 0 {
                        self.pick(CONSONANTS)
                    } else {
                        self.pick(VOWELS)
                    };
                    if index == 0 && matches!(chunk, Chunk::Capitalized) {
                        byte.to_ascii_uppercase()
                    } else {
                        byte
                    }
                })
                .collect(),
            Chunk::DigitRun => {
                let letters = 1 + self.below(3);
                let digits = 1 + self.below(2);
                let mut group: String = (0..letters).map(|_| self.pick(LOWER)).collect();
                group.extend((0..digits).map(|_| self.pick(DIGITS)));
                group
            }
        }
    }

    /// a token of 20 to 64 bytes cut into groups and joined by `separator`.
    fn chunked(&mut self, chunk: Chunk, separator: &str) -> String {
        let target = 20 + self.below(45);
        let mut groups = Vec::new();
        let mut content = 0;
        while content < target {
            let group = self.group(chunk);
            content += group.len();
            groups.push(group);
        }
        groups.join(separator)
    }

    /// two to four long members of at least 20 letters together, joined by `.`.
    fn long_members(&mut self, upper: bool, shortest: usize, longest: usize) -> String {
        loop {
            let count = 2 + self.below(3);
            let members: Vec<String> = (0..count)
                .map(|_| {
                    let length = shortest + self.below(longest - shortest + 1);
                    (0..length)
                        .map(|_| self.pick(if upper { UPPER } else { LOWER }))
                        .collect()
                })
                .collect();
            if members.iter().map(String::len).sum::<usize>() >= 20 {
                return members.join(".");
            }
        }
    }
}

/// counts the placements of `payload` a position's expression span covers, beyond the payloads the
/// word-structure step exempts standing alone (`is_word_structured`), which are counted apart.
fn covered_samples(
    positions: &[Position],
    samples: usize,
    rng: &mut Prng,
    mut payload: impl FnMut(&mut Prng) -> String,
    label: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, position) in positions {
        let mut exempt = 0;
        let mut word_structured = 0;
        let mut first = None;
        for _ in 0..samples {
            let token = payload(rng);
            let placement = position(&token, rng);
            if covers(&placement) {
                if is_word_structured(token.as_bytes()) {
                    word_structured += 1;
                    continue;
                }
                exempt += 1;
                first.get_or_insert_with(|| case_shape(&placement.line));
            }
        }
        eprintln!(
            "syntax predicate {label:<28} {name:<30} samples={samples} exemptions={exempt} \
             word-structured={word_structured}"
        );
        if exempt > 0 {
            failures.push(format!(
                "{label} {name}: {exempt} exemptions, first {first:?}"
            ));
        }
    }
    failures
}

#[test]
fn syntax_spans_never_cover_a_payload_inside_a_position() {
    let mut rng = Prng(0x6A09_E667_F3BC_C908);
    let mut index = 0;
    let failures = covered_samples(
        &INSIDE_POSITIONS,
        PREDICATE_SAMPLES,
        &mut rng,
        |rng| {
            index += 1;
            rng.token(OPAQUE_ALPHABETS[index % OPAQUE_ALPHABETS.len()].1)
        },
        "inside",
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn syntax_spans_never_cover_a_chunked_payload() {
    let mut rng = Prng(0xBB67_AE85_84CA_A73B);
    let mut failures = Vec::new();
    for separator in CHUNK_SEPARATORS {
        let mut index = 0;
        failures.extend(covered_samples(
            &CHUNK_POSITIONS,
            CHUNK_SAMPLES,
            &mut rng,
            |rng| {
                index += 1;
                rng.chunked(CHUNKS[index % CHUNKS.len()].1, separator)
            },
            &format!("chunks joined by {separator:?}"),
        ));
    }
    for (label, upper, shortest, longest) in LONG_MEMBERS {
        failures.extend(covered_samples(
            &CHUNK_POSITIONS,
            CHUNK_SAMPLES,
            &mut rng,
            |rng| rng.long_members(upper, shortest, longest),
            &format!("long members {label}"),
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn overlaps(range: &Range<usize>, span: &Range<usize>) -> bool {
    range.start < span.end && span.start < range.end
}

fn diff_file(line: &str) -> DiffFile {
    DiffFile {
        path: FILE_PATH.to_owned(),
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

/// whether the rule reports bytes of `span` on the text surface and on the diff surface.
fn reported(line: &str, span: &Range<usize>, allowlist: &CompiledAllowlist) -> (bool, bool) {
    let text = scan_text(line, &SCANNER, allowlist)
        .iter()
        .any(|found| found.rule_id == RULE && overlaps(&found.range, span));
    let file = scan(&[diff_file(line)], &SCANNER, allowlist)
        .iter()
        .filter(|found| found.rule_id == RULE && !found.matched_value.is_empty())
        .any(|found| {
            line.as_bytes()
                .windows(found.matched_value.len())
                .enumerate()
                .any(|(start, window)| {
                    window == found.matched_value.as_slice()
                        && overlaps(&(start..start + window.len()), span)
                })
        });
    (text, file)
}

static DEFAULT: LazyLock<CompiledAllowlist> =
    LazyLock::new(|| CompiledAllowlist::default_allowlist().unwrap());
static TRACED: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = CompiledAllowlist::default_allowlist().unwrap();
    allowlist.trace_exemptions = true;
    allowlist
});
static LAYER_OFF: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = CompiledAllowlist::default_allowlist().unwrap();
    allowlist.exemption_layer = false;
    allowlist
});

/// whether an `exempt:syntax` decision drops `payload` in `placement` on a surface where the same
/// payload standing alone, in an unquoted assignment, stays reported.
fn dropped_beyond_alone(placement: &Placement, payload: &str) -> bool {
    let span = &placement.token;
    let claimed = scan_text(&placement.line, &SCANNER, &TRACED)
        .iter()
        .any(|found| found.rule_id == "exempt:syntax" && overlaps(&found.range, span));
    if !claimed {
        return false;
    }
    let off = reported(&placement.line, span, &LAYER_OFF);
    let on = reported(&placement.line, span, &DEFAULT);
    let alone = format!("VALUE={payload}");
    let alone = reported(&alone, &(6..alone.len()), &DEFAULT);
    (off.0 && !on.0 && alone.0) || (off.1 && !on.1 && alone.1)
}

fn dropped_samples(
    positions: &[Position],
    rng: &mut Prng,
    mut payload: impl FnMut(&mut Prng) -> String,
    label: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, position) in positions {
        let mut dropped = 0;
        for _ in 0..INSIDE_ENGINE_SAMPLES {
            let token = payload(rng);
            let placement = position(&token, rng);
            if dropped_beyond_alone(&placement, &token) {
                dropped += 1;
                failures.push(format!("{label} {name}: {}", case_shape(&placement.line)));
            }
        }
        eprintln!(
            "syntax surfaces {label:<28} {name:<30} samples={INSIDE_ENGINE_SAMPLES} dropped={dropped}"
        );
    }
    failures
}

#[test]
fn surfaces_never_drop_a_payload_inside_a_position_beyond_the_payload_alone() {
    let mut rng = Prng(0x3C6E_F372_FE94_F82B);
    let mut failures = Vec::new();
    for (alphabet, letters) in OPAQUE_ALPHABETS {
        failures.extend(dropped_samples(
            &INSIDE_POSITIONS,
            &mut rng,
            |rng| rng.token(letters),
            alphabet,
        ));
    }
    for separator in CHUNK_SEPARATORS {
        for (kind, chunk) in CHUNKS {
            failures.extend(dropped_samples(
                &CHUNK_POSITIONS,
                &mut rng,
                |rng| rng.chunked(chunk, separator),
                &format!("{kind} joined by {separator:?}"),
            ));
        }
    }
    for (label, upper, shortest, longest) in LONG_MEMBERS {
        failures.extend(dropped_samples(
            &CHUNK_POSITIONS,
            &mut rng,
            |rng| rng.long_members(upper, shortest, longest),
            &format!("long members {label}"),
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// the rule reports `payload` in `line` on both surfaces, and redaction removes it.
fn assert_reported(line: &str, payload: &str) {
    let start = line.find(payload).unwrap();
    let span = start..start + payload.len();
    let shape = case_shape(line);
    assert_eq!(reported(line, &span, &DEFAULT), (true, true), "{shape}");
    assert!(
        !redact_text(line, &SCANNER, &DEFAULT).contains(payload),
        "{shape}"
    );
}

/// the reviewer's shapes and the reported recall losses, each with a generated payload: a 19-byte
/// macro name, dotted chunks standing alone after a label, and long members as a labelled
/// argument inside a string. a generated payload counts when the rule reports it with the layer
/// off and it is not word-structured, the value the layer let through before the widened readings.
#[test]
fn widened_reading_twins_stay_reported_and_redacted() {
    let name: String = (0..19_u8)
        .map(|index| {
            let base = if index % 2 == 0 { b'A' } else { b'a' };
            char::from(base + index % 26)
        })
        .collect();
    assert_reported(&format!("VALUE=#{name}(value)"), &name);
    assert_reported(&format!("VALUE=@{name}(value)"), &name);

    let mut rng = Prng(0xA54F_F53A_5F1D_36F1);
    type Shape = (&'static str, &'static str, fn(&mut Prng) -> String);
    let shapes: [Shape; 4] = [
        ("License: ", "", |rng| rng.chunked(Chunk::Capitalized, ".")),
        ("VALUE=#expect(", ")", |rng| {
            rng.chunked(Chunk::ConsonantVowel, "?.")
        }),
        ("setting=\"make(for: ", ")\"", |rng| {
            rng.long_members(false, 6, 11)
        }),
        // any base32 token, below the entropy gate on its own too: the capture around it may pass.
        ("setting=\"make(for: ", ")\"", |rng| {
            let length = 20 + rng.below(45);
            (0..length).map(|_| rng.pick(BASE32)).collect()
        }),
    ];
    for (prefix, suffix, payload) in shapes {
        let mut checked = 0;
        while checked < 20 {
            let token = payload(&mut rng);
            let line = format!("{prefix}{token}{suffix}");
            let span = prefix.len()..prefix.len() + token.len();
            if reported(&line, &span, &LAYER_OFF) != (true, true)
                || is_word_structured(token.as_bytes())
            {
                continue;
            }
            checked += 1;
            assert_reported(&line, &token);
        }
    }
}

// numeric literal lists and random tokens in the argument list of an attribute, annotation or
// macro head. list separators end the chunk run and the words test sets numbers aside, so the
// numbers of a region are held to the length of a value instead. a payload alone of digits and
// separators never clears the entropy gate, so each sample is held to what the rule without the
// layer reports on the same line.

/// samples per numeric cell.
const NUMERIC_SAMPLES: usize = 2_000;

/// heads whose argument list a widened reading claims: two words, whose words alone outweigh the
/// short pieces of a list, and one word.
const NUMERIC_HEADS: [(&str, &str); 3] = [
    ("@JsonAlias(", ")"),
    ("#[secret_bytes(", ")]"),
    ("#payload(", ")"),
];

#[derive(Clone, Copy, Debug)]
enum NumericPayload {
    /// decimal groups of one to sixteen digits each.
    Decimal,
    /// hex bytes written `0x` and two digits.
    HexBytes,
    /// a random token of one alphabet.
    Token(&'static str, &'static [u8]),
}

impl Prng {
    /// a list of 20 to 64 bytes joined by `separator`.
    fn numeric_list(&mut self, kind: NumericPayload, separator: &str) -> String {
        let target = 20 + self.below(45);
        let mut list = String::new();
        while list.len() < target {
            if !list.is_empty() {
                list.push_str(separator);
            }
            match kind {
                NumericPayload::Decimal => {
                    let width = 1 + self.below(16);
                    list.extend((0..width).map(|_| self.pick(DIGITS)));
                }
                NumericPayload::HexBytes => {
                    list.push_str("0x");
                    list.extend((0..2).map(|_| self.pick(HEX)));
                }
                NumericPayload::Token(_, alphabet) => {
                    list.extend((0..target).map(|_| self.pick(alphabet)));
                }
            }
        }
        list
    }
}

/// whether the syntax step drops bytes of `span` in `line`: it claims them on a surface where the
/// rule without the layer reports them and the rule with the layer does not, or where the layer's
/// redaction leaves the payload that the plain gates mask. returns whether the plain gates report
/// the payload at all, and whether it is lost.
fn lost_to_syntax(line: &str, span: &Range<usize>) -> (bool, bool) {
    let off = reported(line, span, &LAYER_OFF);
    if off == (false, false) {
        return (false, false);
    }
    let claimed_text = scan_text(line, &SCANNER, &TRACED)
        .iter()
        .any(|found| found.rule_id == "exempt:syntax" && overlaps(&found.range, span));
    let claimed_file = scan(&[diff_file(line)], &SCANNER, &TRACED)
        .iter()
        .any(|found| found.rule_id == "exempt:syntax");
    if !claimed_text && !claimed_file {
        return (true, false);
    }
    let on = reported(line, span, &DEFAULT);
    let payload = &line[span.clone()];
    let retained = redact_text(line, &SCANNER, &DEFAULT).contains(payload)
        && !redact_text(line, &SCANNER, &LAYER_OFF).contains(payload);
    let lost = (claimed_text && off.0 && !on.0)
        || (claimed_file && off.1 && !on.1)
        || (claimed_text && retained);
    (true, lost)
}

#[test]
fn numeric_lists_inside_widened_heads_stay_reported() {
    let payloads = [
        NumericPayload::Decimal,
        NumericPayload::HexBytes,
        NumericPayload::Token("base62", BASE62),
        NumericPayload::Token("base64", BASE64),
        NumericPayload::Token("base36", BASE36_LOWER),
        NumericPayload::Token("hex", HEX),
    ];
    let mut cells = Vec::new();
    for (open, close) in NUMERIC_HEADS {
        for keyed in [false, true] {
            for payload in payloads {
                let separators: &[&str] = match payload {
                    NumericPayload::Token(..) => &[""],
                    _ => &[",", ";", "."],
                };
                for &separator in separators {
                    cells.push((open, close, keyed, payload, separator));
                }
            }
        }
    }
    let started = std::time::Instant::now();
    let results: Vec<(usize, usize, Vec<String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(index, &(open, close, keyed, payload, separator))| {
                scope.spawn(move || {
                    let mut rng = Prng(0x510B_7E57_0000_0001 ^ ((index as u64 + 1) << 32));
                    let (mut reported, mut lost, mut examples) = (0, 0, Vec::new());
                    for _ in 0..NUMERIC_SAMPLES {
                        let list = rng.numeric_list(payload, separator);
                        let prefix = format!("{}{open}", if keyed { "k=" } else { "" });
                        let placement = place(&prefix, 0, &list, close);
                        let (off, dropped) = lost_to_syntax(&placement.line, &placement.token);
                        reported += usize::from(off);
                        if dropped {
                            lost += 1;
                            if examples.len() < 3 {
                                examples.push(case_shape(&placement.line));
                            }
                        }
                    }
                    (reported, lost, examples)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("numeric cell"))
            .collect()
    });
    let mut failures = Vec::new();
    let mut decimal_reported = 0;
    for ((open, close, keyed, payload, separator), (reported, lost, examples)) in
        cells.iter().zip(&results)
    {
        let payload = match payload {
            NumericPayload::Token(name, _) => format!("token {name}"),
            other => format!("{other:?} sep {separator:?}"),
        };
        eprintln!(
            "syntax numeric {}{open}..{close} {payload}: samples={NUMERIC_SAMPLES} \
             reported_without_layer={reported} lost={lost}",
            if *keyed { "k=" } else { "" }
        );
        if payload.starts_with("Decimal") && *open != "#payload(" {
            decimal_reported += reported;
        }
        if *lost > 0 {
            failures.push(format!("{open} {payload}: {lost} lost, {examples:?}"));
        }
    }
    eprintln!(
        "syntax numeric elapsed={:.1}s",
        started.elapsed().as_secs_f64()
    );
    // the plain gates report most decimal lists under a two-word head, so the guard is not vacuous.
    assert!(
        decimal_reported * 2 > NUMERIC_SAMPLES * 12,
        "only {decimal_reported} decimal lists reportable"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn short_numeric_arguments_stay_syntax() {
    // numbers that make no value of their own keep the widened reading: an alignment, bounds and a
    // list of names.
    for line in [
        "#[repr(align(64))]",
        "@Size(max = 255)",
        "#[derive(Debug,Clone,Copy,Hash)]",
        "@Range(from = 1024, to = 65535)",
        "#[cfg_attr(test, derive(Debug, Default))]",
    ] {
        assert_eq!(
            expression_span(line.as_bytes(), 0, 4096),
            Some(0..line.len()),
            "{line}"
        );
        assert_eq!(
            reported(line, &(0..line.len()), &DEFAULT),
            (false, false),
            "{line}"
        );
    }
}
