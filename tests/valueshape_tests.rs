//! recall guards for the value shapes of the word and template steps: framework-prefixed and
//! numbered camel identifiers, search patterns, environment entries and key chords, interpolation
//! holes, currency conversions and escaped string bodies.
//!
//! every new position of each shape is filled with random tokens of 20 to 64 bytes from the
//! credential alphabets and from the alphabet the shape itself accepts. a position the shape judges
//! itself never exempts a credential and exempts the shape's alphabet below 0.1%; a position that
//! hands the token to a judgement that existed before (the same token in a reference form) never
//! exempts a token that form does not. a random token cut into chunks of two to five letters and
//! joined by the bytes each shape accepts between its items is never exempted. the inverse cells
//! put the token, whole or in chunks, inside the positions a shape reads as structure: a hole's
//! members, calls and arguments, a placeholder's, a conversion's or a posix class's name, a chord's
//! key and an entry's flag. neither the predicates nor the engine, on the agent and the diff
//! surface, claim it where the token alone is not claimed. the fixture file of the new word-list
//! class reaches its step on both surfaces. every value is generated at run time from a seeded
//! prng; none is stored in the repository.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::{MIN_ENTROPY_LENGTH, shannon_entropy};
use sekretbarilo::scanner::litshape::is_format_template;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use sekretbarilo::scanner::wordshape::is_word_structured;
use std::path::Path;
use std::sync::LazyLock;

const RULE: &str = "generic-high-entropy-value";

/// samples per position and alphabet of the random-token grid.
const SAMPLES: usize = 100_000;

/// samples per position, chunk alphabet and chunk width of the chunking attack, and per cell of
/// the chunks placed inside a shape.
const CHUNK_SAMPLES: usize = 20_000;

/// the samples of an inside cell also judged at the engine, for whole tokens and for chunked
/// payloads: a debug build scans about two lines a millisecond, so a cell judges all its samples
/// by the predicates and the first of them at the engine as well.
const ENGINE_SAMPLES: usize = 2_000;
const ENGINE_CHUNK_SAMPLES: usize = 1_000;

/// the rate a word-shaped alphabet may reach in a new position: 0.1%.
const WORD_SHAPED_LIMIT: usize = SAMPLES / 1_000;

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

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

    fn token(&mut self, alphabet: &[u8], length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }
}

fn base62() -> Vec<u8> {
    (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .collect()
}

fn with(base: &[u8], extra: &[u8]) -> Vec<u8> {
    base.iter().chain(extra).copied().collect()
}

fn lower() -> Vec<u8> {
    (b'a'..=b'z').collect()
}

/// the encodings a credential is drawn from.
fn credential_alphabets() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("base62", base62()),
        ("base64", with(&base62(), b"+/")),
        ("base64url", with(&base62(), b"-_")),
        ("hex", b"0123456789abcdef".to_vec()),
        ("base32", (b'A'..=b'Z').chain(b'2'..=b'7').collect()),
        ("base36-lower", (b'0'..=b'9').chain(b'a'..=b'z').collect()),
    ]
}

/// letters and digits collapse to one byte per class, so a report never carries a sample.
fn skeleton(value: &[u8]) -> String {
    value
        .iter()
        .map(|&byte| match byte {
            b'a'..=b'z' => 'a',
            b'A'..=b'Z' => 'A',
            b'0'..=b'9' => '9',
            _ => char::from(byte),
        })
        .collect()
}

#[derive(Clone, Copy)]
enum Step {
    Word,
    Template,
}

fn judged(step: Step, value: &[u8]) -> bool {
    match step {
        Step::Word => is_word_structured(value),
        Step::Template => is_format_template(value),
    }
}

/// how a word-shaped alphabet is bounded in a position.
#[derive(Clone, Copy)]
enum Bound {
    /// below `WORD_SHAPED_LIMIT` exemptions.
    Rate,
    /// never exempted where the same token in the reference form (`P` stands for it) is not: the
    /// position hands the token to a judgement that existed before.
    NoWorseThan(&'static str),
}

/// a place for a token: `P` in `form` stands for it.
struct Position {
    step: Step,
    form: &'static str,
    /// the bytes the shape accepts in this position.
    alphabet: &'static str,
    bound: Bound,
}

const LOWER_SEP: &str = "lower+sep";
const LOWER_SEP_ESC: &str = "lower+sep+esc";
const IDENT: &str = "identifier";
const CAMEL: &str = "camel";
const LOWER_PIPE: &str = "lower+pipe";
const UPPER_SNAKE: &str = "upper+snake";
const LOWER_SNAKE: &str = "lower+snake";
const LOWER_WORD: &str = "lower";

fn shape_alphabet(name: &str) -> Vec<u8> {
    match name {
        LOWER_SEP => with(&lower(), b"-_./:"),
        LOWER_SEP_ESC => with(&lower(), b"-_=\\\\\""),
        IDENT => (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b"_.".iter().copied())
            .collect(),
        // capitals at a quarter of the letters, as in camel-case words
        CAMEL => (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'a'..=b'z')
            .chain(b'a'..=b'z')
            .collect(),
        LOWER_PIPE => with(&lower(), b"_-|"),
        UPPER_SNAKE => (b'A'..=b'Z').chain(b"_".iter().copied()).collect(),
        LOWER_SNAKE => with(&lower(), b"_-.:"),
        LOWER_WORD => lower(),
        other => panic!("unknown shape alphabet {other}"),
    }
}

const POSITIONS: &[Position] = &[
    // literal text beside a hole or a conversion, next to the brace field that form had before
    Position {
        step: Step::Template,
        form: r"\(session.id)-P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("{}-P"),
    },
    Position {
        step: Step::Template,
        form: r"P-\(tab.index)",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("P-{}"),
    },
    Position {
        step: Step::Template,
        form: r"\#(surface.id):P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("{}:P"),
    },
    Position {
        step: Step::Template,
        form: "#{user.name}-P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("{}-P"),
    },
    // a hole holds at most one short name outside the vocabulary, so `${f(x)}` is no hole
    Position {
        step: Step::Template,
        form: "${format(x)}/P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("{}/P"),
    },
    Position {
        step: Step::Template,
        form: "($name)&token=P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("{}&token=P"),
    },
    Position {
        step: Step::Template,
        form: "$%(price).2f/P",
        alphabet: LOWER_SEP,
        bound: Bound::NoWorseThan("%(price).2f/P"),
    },
    // the expression of a hole
    Position {
        step: Step::Template,
        form: r"\(P)",
        alphabet: IDENT,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Template,
        form: "#{P}-detail",
        alphabet: IDENT,
        bound: Bound::Rate,
    },
    // an escaped string body
    Position {
        step: Step::Template,
        form: r#"\"release-notes-summary\"\nP"#,
        alphabet: LOWER_SEP_ESC,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Template,
        form: r"P\nstatus=running",
        alphabet: LOWER_SEP_ESC,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Template,
        form: "P",
        alphabet: LOWER_SEP_ESC,
        bound: Bound::Rate,
    },
    // a camel identifier behind a framework prefix, a hungarian `k`, or before closing digits
    Position {
        step: Step::Word,
        form: "NSP",
        alphabet: CAMEL,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Word,
        form: "kAXP",
        alphabet: CAMEL,
        bound: Bound::Rate,
    },
    // the closing digits hand the identifier before them to the camel rule, with the chunk guard
    Position {
        step: Step::Word,
        form: "P2",
        alphabet: CAMEL,
        bound: Bound::NoWorseThan("P"),
    },
    // an item of a search pattern, next to the plain alternation of the same items
    Position {
        step: Step::Word,
        form: "(^|/)(target|P)$",
        alphabet: LOWER_PIPE,
        bound: Bound::NoWorseThan("target|P"),
    },
    Position {
        step: Step::Word,
        form: "^(P|claude)([[:space:]]|$)",
        alphabet: LOWER_PIPE,
        bound: Bound::NoWorseThan("P|claude"),
    },
    Position {
        step: Step::Word,
        form: "(deprecated|legacy)(P|_client)",
        alphabet: LOWER_PIPE,
        bound: Bound::NoWorseThan("deprecated|legacy|P|_client"),
    },
    Position {
        step: Step::Word,
        form: "start|stop|P)",
        alphabet: LOWER_PIPE,
        bound: Bound::NoWorseThan("start|stop|P"),
    },
    // an environment entry's flag and name, a key chord's key and action
    Position {
        step: Step::Word,
        form: "GOFLAGS=-mod=P",
        alphabet: LOWER_SEP,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Word,
        form: "TOKEN=--P",
        alphabet: LOWER_SEP,
        bound: Bound::Rate,
    },
    Position {
        step: Step::Word,
        form: "P=1",
        alphabet: UPPER_SNAKE,
        bound: Bound::NoWorseThan("P"),
    },
    Position {
        step: Step::Word,
        form: "super+shift+t=P",
        alphabet: LOWER_SNAKE,
        bound: Bound::NoWorseThan("P"),
    },
    Position {
        step: Step::Word,
        form: "super+P=toggle_quick_terminal",
        alphabet: LOWER_SNAKE,
        bound: Bound::Rate,
    },
];

fn place(form: &str, token: &[u8]) -> Vec<u8> {
    let (before, after) = form.split_once('P').expect("a form carries P");
    [before.as_bytes(), token, after.as_bytes()].concat()
}

#[test]
fn random_tokens_in_new_positions_are_bounded() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut failures = Vec::new();
    for position in POSITIONS {
        let mut alphabets = credential_alphabets();
        alphabets.push((position.alphabet, shape_alphabet(position.alphabet)));
        for (index, (name, alphabet)) in alphabets.iter().enumerate() {
            let shape_alphabet = index + 1 == alphabets.len();
            let (mut samples, mut exempted, mut beyond, mut draws) = (0, 0, 0, 0);
            let mut shown = Vec::new();
            while samples < SAMPLES && draws < SAMPLES * 20 {
                draws += 1;
                let length = 20 + rng.below(45);
                let token = rng.token(alphabet, length);
                // a separator sends the value down the identifier rule's separator path, which
                // the camel positions leave as it was; they count only tokens the camel rule reads.
                if position.alphabet == CAMEL && token.iter().any(|byte| b"-_./:".contains(byte)) {
                    continue;
                }
                samples += 1;
                if !judged(position.step, &place(position.form, &token)) {
                    continue;
                }
                exempted += 1;
                let reference = match position.bound {
                    Bound::NoWorseThan(form) => judged(position.step, &place(form, &token)),
                    Bound::Rate => false,
                };
                if !reference {
                    beyond += 1;
                    if shown.len() < 3 {
                        shown.push(skeleton(&token));
                    }
                }
            }
            eprintln!(
                "{:<34} {name:<14} samples={samples} exempted={exempted} beyond-reference={beyond}",
                position.form
            );
            let allowed = if !shape_alphabet {
                0
            } else {
                match position.bound {
                    Bound::Rate => WORD_SHAPED_LIMIT,
                    Bound::NoWorseThan(_) => 0,
                }
            };
            // a position that hands the token to an earlier judgement answers only for what it
            // adds: the identifier rule alone exempts about one random credential in 1e5.
            let counted = match position.bound {
                Bound::Rate => exempted,
                Bound::NoWorseThan(_) => beyond,
            };
            if counted > allowed || samples < SAMPLES {
                failures.push(format!(
                    "{} {name}: {counted} > {allowed} or {samples} samples, e.g. {shown:?}",
                    position.form
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// the chunk alphabets of the attack: random lowercase, random mixed case, consonant-vowel
/// syllables, lowercase letters with a run of one to three digits, and random capitals.
#[derive(Clone, Copy, Debug)]
enum Chunks {
    Lower,
    Mixed,
    Pronounceable,
    Digits,
    Upper,
}

const CHUNK_KINDS: [Chunks; 5] = [
    Chunks::Lower,
    Chunks::Mixed,
    Chunks::Pronounceable,
    Chunks::Digits,
    Chunks::Upper,
];

const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxyz";
const VOWELS: &[u8] = b"aeiou";

fn chunk(rng: &mut Rng, kind: Chunks, width: usize, capitalize: bool) -> Vec<u8> {
    let start = rng.below(2);
    let mut out: Vec<u8> = (0..width)
        .map(|index| match kind {
            Chunks::Mixed => {
                let byte = b'a' + rng.below(26) as u8;
                if rng.below(2) == 0 {
                    byte.to_ascii_uppercase()
                } else {
                    byte
                }
            }
            Chunks::Pronounceable if (index + start).is_multiple_of(2) => {
                CONSONANTS[rng.below(CONSONANTS.len())]
            }
            Chunks::Pronounceable => VOWELS[rng.below(VOWELS.len())],
            Chunks::Lower | Chunks::Digits => b'a' + rng.below(26) as u8,
            Chunks::Upper => b'A' + rng.below(26) as u8,
        })
        .collect();
    if matches!(kind, Chunks::Digits) {
        let at = rng.below(width + 1);
        let digits: Vec<u8> = (0..1 + rng.below(3))
            .map(|_| b'0' + rng.below(10) as u8)
            .collect();
        out.splice(at..at, digits);
    }
    if capitalize {
        out[0] = out[0].to_ascii_uppercase();
    }
    out
}

/// chunks of a payload of 20 to 64 bytes at entropy 4.0 or more, or none after 64 draws.
fn payload(rng: &mut Rng, kind: Chunks, width: Option<usize>, camel: bool) -> Option<Vec<Vec<u8>>> {
    for _ in 0..64 {
        let target = 20 + rng.below(45);
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut length = 0;
        while length < target {
            let width = width.unwrap_or_else(|| 2 + rng.below(4));
            let part = chunk(rng, kind, width, camel && !parts.is_empty());
            length += part.len();
            parts.push(part);
        }
        let joined = parts.concat();
        if joined.len() <= 64 && shannon_entropy(&joined) >= 4.0 {
            return Some(parts);
        }
    }
    None
}

/// a place for a chunked payload: its chunks joined by `join`, between `before` and `after`.
struct ChunkPosition {
    step: Step,
    before: &'static str,
    join: &'static str,
    after: &'static str,
    camel: bool,
}

// the positions come in groups, one test each, so that the groups run side by side.

/// each join is a hole of one short name outside the vocabulary at most, the most a hole holds.
const HOLE_JOIN_POSITIONS: &[ChunkPosition] = &[
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\(x.size)",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\#(value)",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: "#{name}",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: "${format(x)}",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: "($x.size)",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: "$%(n).2f",
        after: "",
        camel: false,
    },
];

/// escapes of a string body between the chunks.
const ESCAPE_JOIN_POSITIONS: &[ChunkPosition] = &[
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\n",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\t",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: r#"\""#,
        join: r#"\"\n\""#,
        after: r#"\""#,
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\r",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\\",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: "",
        join: r"\'",
        after: "",
        camel: false,
    },
];

/// chunks as the names of currency conversions, of placeholders beside a hole and of posix
/// classes behind three long words.
const NAME_POSITIONS: &[ChunkPosition] = &[
    ChunkPosition {
        step: Step::Template,
        before: "$%(",
        join: ").2f$%(",
        after: ").2f",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: r"\(item.size){",
        join: "}{",
        after: "}",
        camel: false,
    },
    ChunkPosition {
        step: Step::Template,
        before: r"\(item.size)${",
        join: "}${",
        after: "}",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "(deprecated|legacy|obsolete)[[:",
        join: ":]][[:",
        after: ":]]",
        camel: false,
    },
];

/// camel humps behind a framework prefix or before a trailing digit, and search pattern items.
const PATTERN_POSITIONS: &[ChunkPosition] = &[
    ChunkPosition {
        step: Step::Word,
        before: "NS",
        join: "",
        after: "",
        camel: true,
    },
    ChunkPosition {
        step: Step::Word,
        before: "kAX",
        join: "",
        after: "",
        camel: true,
    },
    ChunkPosition {
        step: Step::Word,
        before: "",
        join: "",
        after: "2",
        camel: true,
    },
    ChunkPosition {
        step: Step::Word,
        before: "(^|/)(",
        join: "|",
        after: ")$",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "^(",
        join: "|",
        after: ")([[:space:]]|$)",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "",
        join: "|",
        after: ")",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "(deprecated|",
        join: ")(",
        after: "|_client)",
        camel: false,
    },
];

/// key chords, entries and lists.
const ENTRY_POSITIONS: &[ChunkPosition] = &[
    ChunkPosition {
        step: Step::Word,
        before: "super+shift+t=",
        join: "_",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "ctrl+k=",
        join: ".",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "",
        join: ",",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "",
        join: "+",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "",
        join: "=",
        after: "",
        camel: false,
    },
    ChunkPosition {
        step: Step::Word,
        before: "--flag=",
        join: ",",
        after: "",
        camel: false,
    },
];

#[test]
fn chunked_tokens_between_holes_are_never_exempted() {
    assert_chunked_never_exempted(HOLE_JOIN_POSITIONS, 0x6A09_E667_F3BC_C908);
}

#[test]
fn chunked_tokens_between_escapes_are_never_exempted() {
    assert_chunked_never_exempted(ESCAPE_JOIN_POSITIONS, 0x9B05_688C_2B3E_6C1F);
}

#[test]
fn chunked_tokens_as_names_are_never_exempted() {
    assert_chunked_never_exempted(NAME_POSITIONS, 0x1F83_D9AB_FB41_BD6B);
}

#[test]
fn chunked_tokens_in_pattern_positions_are_never_exempted() {
    assert_chunked_never_exempted(PATTERN_POSITIONS, 0x5BE0_CD19_137E_2179);
}

#[test]
fn chunked_tokens_in_entry_positions_are_never_exempted() {
    assert_chunked_never_exempted(ENTRY_POSITIONS, 0x510E_527F_ADE6_82D1);
}

fn assert_chunked_never_exempted(positions: &[ChunkPosition], seed: u64) {
    let mut rng = Rng(seed);
    let mut failures = Vec::new();
    for position in positions {
        for kind in CHUNK_KINDS {
            for width in [Some(2), Some(3), Some(4), Some(5), None] {
                let (mut samples, mut exempted) = (0, 0);
                let mut shown = Vec::new();
                let mut draws = 0;
                while samples < CHUNK_SAMPLES && draws < CHUNK_SAMPLES * 20 {
                    draws += 1;
                    let Some(parts) = payload(&mut rng, kind, width, position.camel) else {
                        continue;
                    };
                    let value = [
                        position.before.as_bytes(),
                        &parts.join(position.join.as_bytes()),
                        position.after.as_bytes(),
                    ]
                    .concat();
                    samples += 1;
                    if judged(position.step, &value) {
                        exempted += 1;
                        if shown.len() < 3 {
                            shown.push(skeleton(&value));
                        }
                    }
                }
                let width = width.map_or("2-5".to_owned(), |width| width.to_string());
                eprintln!(
                    "{}P{}P{} {kind:?} width {width}: samples={samples} exempted={exempted}",
                    position.before, position.join, position.after
                );
                if exempted > 0 {
                    failures.push(format!(
                        "{}P{}P{} {kind:?} width {width}: {exempted}, e.g. {shown:?}",
                        position.before, position.join, position.after
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn chunked_entry_names_are_never_exempted() {
    let mut rng = Rng(0x3C6E_F372_FE94_F82B);
    let mut failures = Vec::new();
    for kind in [Chunks::Lower, Chunks::Pronounceable, Chunks::Digits] {
        for width in [Some(2), Some(3), Some(4), Some(5), None] {
            let (mut samples, mut exempted) = (0, 0);
            let mut draws = 0;
            while samples < CHUNK_SAMPLES && draws < CHUNK_SAMPLES * 20 {
                draws += 1;
                let Some(parts) = payload(&mut rng, kind, width, false) else {
                    continue;
                };
                let name = parts.join(&b'_').to_ascii_uppercase();
                samples += 1;
                for tail in [b"=1".as_slice(), b"=-mod=readonly"] {
                    exempted += usize::from(is_word_structured(&[name.as_slice(), tail].concat()));
                }
            }
            eprintln!("P_P=1 {kind:?} width {width:?}: samples={samples} exempted={exempted}");
            if exempted > 0 {
                failures.push(format!("{kind:?} width {width:?}: {exempted}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// the layer as shipped, and the layer switched off: a line the second reports on a surface where
/// the first does not is exempted there.
static LAYER_ON: LazyLock<CompiledAllowlist> =
    LazyLock::new(|| CompiledAllowlist::default_allowlist().unwrap());
static LAYER_OFF: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = CompiledAllowlist::default_allowlist().unwrap();
    allowlist.exemption_layer = false;
    allowlist
});

/// whether the rule reports a line on the agent surface (`scan_text`) and on the diff surface.
fn engine_reports(line: &str, allowlist: &CompiledAllowlist) -> [bool; 2] {
    [
        scan_text(line, &SCANNER, allowlist)
            .iter()
            .any(|found| found.rule_id == RULE),
        findings(line, allowlist)
            .iter()
            .any(|found| found.rule_id == RULE),
    ]
}

fn assignment(value: &[u8]) -> String {
    format!("setting=\"{}\"", String::from_utf8_lossy(value))
}

/// whether the word or the template step claims a value.
fn shape_judged(value: &[u8]) -> bool {
    is_word_structured(value) || is_format_template(value)
}

/// the tally of an inverse cell. every sample is judged by the two predicates, next to the payload
/// standing alone; the first `engine_samples` are judged at the engine as well, the value of an
/// assignment on the agent and the diff surface: the layer exempts it where the layer off reports
/// it and the layer on does not, beyond the payload alone where that is reported there.
#[derive(Default)]
struct InsideTally {
    samples: usize,
    claimed: usize,
    claimed_beyond: usize,
    engine_samples: usize,
    exempted: usize,
    beyond: usize,
    shown: Vec<String>,
}

impl InsideTally {
    fn judge(&mut self, value: &[u8], alone: &[u8], at_engine: bool) {
        self.samples += 1;
        if shape_judged(value) {
            self.claimed += 1;
            if !shape_judged(alone) {
                self.claimed_beyond += 1;
                if self.shown.len() < 3 {
                    self.shown.push(skeleton(value));
                }
            }
        }
        if at_engine {
            self.engine_samples += 1;
            self.judge_at_engine(value, alone);
        }
    }

    fn judge_at_engine(&mut self, value: &[u8], alone: &[u8]) {
        let line = assignment(value);
        let on = engine_reports(&line, &LAYER_ON);
        if on == [true, true] {
            return;
        }
        let off = engine_reports(&line, &LAYER_OFF);
        let exempted = [off[0] && !on[0], off[1] && !on[1]];
        if exempted == [false, false] {
            return;
        }
        self.exempted += 1;
        let alone = engine_reports(&assignment(alone), &LAYER_ON);
        if (exempted[0] && alone[0]) || (exempted[1] && alone[1]) {
            self.beyond += 1;
            if self.shown.len() < 3 {
                self.shown.push(skeleton(value));
            }
        }
    }

    fn report(&self, cell: &str, expected: usize, failures: &mut Vec<String>) {
        eprintln!(
            "{cell:<44} samples={} claimed={} beyond-alone={} | engine samples={} exempted={} \
             beyond-alone={}",
            self.samples,
            self.claimed,
            self.claimed_beyond,
            self.engine_samples,
            self.exempted,
            self.beyond
        );
        if self.claimed_beyond + self.beyond > 0 || self.samples < expected {
            failures.push(format!(
                "{cell}: {} claimed and {} exempted beyond the payload alone in {} samples, e.g. \
                 {:?}",
                self.claimed_beyond, self.beyond, self.samples, self.shown
            ));
        }
    }
}

/// the interpolation holes, each opened and closed around one expression.
const HOLES: [(&str, &str); 5] = [
    (r"\(", ")"),
    (r"\#(", ")"),
    ("#{", "}"),
    ("${", "}"),
    ("($", ")"),
];

/// the joins a hole expression accepts between its identifiers.
#[derive(Clone, Copy, Debug)]
enum Join {
    /// `a.b`
    Member,
    /// `a?.b`
    Optional,
    /// `a!.b`
    Unwrap,
    /// `a(b)(c)`
    Call,
    /// `a(b,c)`
    Arguments,
    /// `a(b:c,d:e)`
    Labels,
    /// `a_b.c_d`
    Snake,
    /// `aB.cD`
    Camel,
}

const JOINS: [Join; 8] = [
    Join::Member,
    Join::Optional,
    Join::Unwrap,
    Join::Call,
    Join::Arguments,
    Join::Labels,
    Join::Snake,
    Join::Camel,
];

/// the chunks as the identifiers of one hole expression.
fn hole_expression(join: Join, parts: &[Vec<u8>]) -> Vec<u8> {
    let names: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let pairs = |separator: &[u8], camel: bool| -> Vec<u8> {
        let names: Vec<Vec<u8>> = names
            .chunks(2)
            .map(|pair| {
                let mut name = pair[0].to_vec();
                if let Some(second) = pair.get(1) {
                    name.extend_from_slice(separator);
                    let hump = name.len();
                    name.extend_from_slice(second);
                    if camel {
                        name[hump] = name[hump].to_ascii_uppercase();
                    }
                }
                name
            })
            .collect();
        names.join(&b"."[..])
    };
    match join {
        Join::Member => names.join(&b"."[..]),
        Join::Optional => names.join(&b"?."[..]),
        Join::Unwrap => names.join(&b"!."[..]),
        Join::Call => {
            let mut out = names[0].to_vec();
            for name in &names[1..] {
                out.push(b'(');
                out.extend_from_slice(name);
                out.push(b')');
            }
            out
        }
        Join::Arguments => [names[0], b"(", &names[1..].join(&b","[..]), b")"].concat(),
        Join::Labels => {
            let arguments: Vec<Vec<u8>> = names[1..]
                .chunks(2)
                .map(|pair| pair.join(&b":"[..]))
                .collect();
            [names[0], b"(", &arguments.join(&b","[..]), b")"].concat()
        }
        Join::Snake => pairs(b"_", false),
        Join::Camel => pairs(b"", true),
    }
}

/// a chunked payload of a random kind and width whose chunks open with a letter, as identifiers
/// do: the digits a chunk opens with move to its end. a camel join of two capital chunks shows
/// no hump, so it writes one run of four to ten capitals, a long member rather than two chunks:
/// the camel join draws its chunks without `capitals`, from the kinds with a lowercase letter.
fn identifier_payload(rng: &mut Rng, capitals: bool) -> Option<Vec<Vec<u8>>> {
    let kinds: Vec<Chunks> = CHUNK_KINDS
        .into_iter()
        .filter(|kind| capitals || !matches!(kind, Chunks::Upper))
        .collect();
    let kind = kinds[rng.below(kinds.len())];
    let width = [Some(2), Some(3), Some(4), Some(5), None][rng.below(5)];
    let mut parts = payload(rng, kind, width, false)?;
    for part in &mut parts {
        let digits = part.iter().take_while(|byte| byte.is_ascii_digit()).count();
        part.rotate_left(digits);
    }
    Some(parts)
}

#[test]
fn numeric_hole_members_keep_detection_and_redaction() {
    let mut rng = Rng(0x5dee_ce66_d1ce_4e5b);
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    for width in [4, 5, 6, 8, 12] {
        let mut reported = 0;
        for _ in 0..1_000 {
            let members = ["id", "os", "ui", "db", "ip", "fs"]
                .map(|name| {
                    let digits = String::from_utf8(rng.token(b"0123456789", width)).unwrap();
                    format!("{name}_{digits}")
                })
                .join(".");
            let value = format!("\\({members})");
            assert!(
                !is_format_template(value.as_bytes()),
                "numeric members exempt: width={width}"
            );
            let line = format!("setting=\"{value}\"");
            let found = scan_text(&line, &SCANNER, &allowlist)
                .iter()
                .any(|m| m.rule_id == RULE);
            reported += usize::from(found);
            if found {
                assert!(
                    !redact_text(&line, &SCANNER, &allowlist).contains(&members),
                    "numeric members retained: width={width}"
                );
            }
        }
        assert!(
            reported >= 950,
            "numeric members lost: width={width}, reported={reported}"
        );
    }
    assert!(is_format_template(br"\(session_2026.name)"));
}

/// the inverse of the grids above: a payload cut into chunks of two to five letters (lowercase,
/// mixed case, consonant-vowel, capitals, or letters with a digit run, drawn per sample; capitals
/// sit out the camel join, whose hump they would hide, see `identifier_payload`) placed inside a
/// hole as its members, calls, arguments, labels, snake and camel names, one cell per hole syntax
/// and join (`InsideTally`). a hole holds at most one short name outside the vocabulary, and its
/// identifiers join the literal text in the chunk guard, so neither the predicates nor the engine
/// claim one of these values where the payload alone is not claimed.
#[test]
fn chunked_tokens_inside_holes_are_reported_at_the_engine() {
    let mut rng = Rng(0xBB67_AE85_84CA_A73B);
    let mut failures = Vec::new();
    for (open, close) in HOLES {
        for join in JOINS {
            let mut tally = InsideTally::default();
            let mut draws = 0;
            while tally.samples < CHUNK_SAMPLES && draws < CHUNK_SAMPLES * 20 {
                draws += 1;
                let Some(parts) = identifier_payload(&mut rng, !matches!(join, Join::Camel)) else {
                    continue;
                };
                let value = [
                    open.as_bytes(),
                    &hole_expression(join, &parts),
                    close.as_bytes(),
                ]
                .concat();
                let at_engine = tally.samples < ENGINE_CHUNK_SAMPLES;
                tally.judge(&value, &parts.concat(), at_engine);
            }
            let cell = format!("{open}P{close} {join:?}");
            tally.report(&cell, CHUNK_SAMPLES, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// a place inside another shape the value-shape change reads, for a chunked payload.
struct InsideCell {
    name: &'static str,
    build: fn(&[Vec<u8>]) -> Option<Vec<u8>>,
}

fn wrap_each(parts: &[Vec<u8>], open: &[u8], close: &[u8]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|part| [open, part.as_slice(), close].concat())
        .collect()
}

fn lowered(parts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_ascii_lowercase()).collect()
}

fn currency_names(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some(wrap_each(parts, b"$%(", b").2f"))
}

fn brace_names_beside_a_hole(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some([br"\(item.size)".as_slice(), &wrap_each(parts, b"{", b"}")].concat())
}

fn substitutions_beside_a_hole(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some([br"\(item.size)".as_slice(), &wrap_each(parts, b"${", b"}")].concat())
}

/// camel names opened by capitals: each pair of chunks as an acronym and a capitalized word.
fn acronym_names(parts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    parts
        .chunks(2)
        .map(|pair| {
            let mut name = pair[0].to_ascii_uppercase();
            if let Some(second) = pair.get(1) {
                let mut word = second.to_ascii_lowercase();
                word[0] = word[0].to_ascii_uppercase();
                name.extend_from_slice(&word);
            }
            name
        })
        .collect()
}

fn acronym_brace_names(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some(wrap_each(&acronym_names(parts), b"{", b"}"))
}

fn acronym_hole_members(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some(
        [
            br"\(".as_slice(),
            &acronym_names(parts).join(&b"."[..]),
            b")",
        ]
        .concat(),
    )
}

fn posix_class_names(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some(
        [
            b"(deprecated|legacy|obsolete)".as_slice(),
            &wrap_each(&lowered(parts), b"[[:", b":]]"),
        ]
        .concat(),
    )
}

fn pattern_items(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    Some([b"(^|/)(".as_slice(), &lowered(parts).join(&b"|"[..]), b")$"].concat())
}

/// as many chunks as twelve bytes hold in the key, the rest in the action.
fn chord_key_and_action(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    let parts = lowered(parts);
    let mut used = 1;
    let mut key = parts[0].clone();
    while used + 1 < parts.len() && key.len() + 1 + parts[used].len() <= 12 {
        key.push(b'_');
        key.extend_from_slice(&parts[used]);
        used += 1;
    }
    (used < parts.len()).then(|| {
        [
            b"ctrl+shift+".as_slice(),
            &key,
            b"=",
            &parts[used..].join(&b"_"[..]),
        ]
        .concat()
    })
}

/// the last two chunks as the words of a flag, the rest as the name.
fn entry_name_and_flag(parts: &[Vec<u8>]) -> Option<Vec<u8>> {
    let (name, flag) = parts.split_at(parts.len().checked_sub(2).filter(|&at| at > 0)?);
    let flag = lowered(flag);
    Some(
        [
            name.join(&b"_"[..]).to_ascii_uppercase().as_slice(),
            b"=--",
            &flag[0],
            b"=",
            &flag[1],
        ]
        .concat(),
    )
}

fn escaped_by(parts: &[Vec<u8>], escape: &[u8]) -> Vec<u8> {
    parts.join(escape)
}

const INSIDE_CELLS: &[InsideCell] = &[
    InsideCell {
        name: "$%(P).2f$%(P).2f",
        build: currency_names,
    },
    InsideCell {
        name: r"\(item.size){P}{P}",
        build: brace_names_beside_a_hole,
    },
    InsideCell {
        name: r"\(item.size)${P}${P}",
        build: substitutions_beside_a_hole,
    },
    InsideCell {
        name: "{ACRWord}{ACRWord}",
        build: acronym_brace_names,
    },
    InsideCell {
        name: r"\(ACRWord.ACRWord)",
        build: acronym_hole_members,
    },
    InsideCell {
        name: "(deprecated|legacy|obsolete)[[:P:]][[:P:]]",
        build: posix_class_names,
    },
    InsideCell {
        name: "(^|/)(P|P)$",
        build: pattern_items,
    },
    InsideCell {
        name: "ctrl+shift+P_P=P_P",
        build: chord_key_and_action,
    },
    InsideCell {
        name: "P_P=--P=P",
        build: entry_name_and_flag,
    },
    InsideCell {
        name: r"P\nP",
        build: |parts| Some(escaped_by(parts, br"\n")),
    },
    InsideCell {
        name: r"P\rP",
        build: |parts| Some(escaped_by(parts, br"\r")),
    },
    InsideCell {
        name: r"P\\P",
        build: |parts| Some(escaped_by(parts, br"\\")),
    },
    InsideCell {
        name: r"P\'P",
        build: |parts| Some(escaped_by(parts, br"\'")),
    },
    InsideCell {
        name: r#"P\"P"#,
        build: |parts| Some(escaped_by(parts, br#"\""#)),
    },
];

/// the same inverse cells for the other shapes of the value-shape change: a payload's chunks as
/// the names of currency conversions and of placeholders beside a hole, as camel names opened by
/// capitals, as posix class names and pattern items, split between a chord's key and action or an
/// entry's name and flag, and joined by each string escape.
#[test]
fn chunked_tokens_inside_other_shapes_are_reported_at_the_engine() {
    let mut rng = Rng(0x3C6E_F372_FE94_F82B);
    let mut failures = Vec::new();
    for cell in INSIDE_CELLS {
        let mut tally = InsideTally::default();
        let mut draws = 0;
        while tally.samples < CHUNK_SAMPLES && draws < CHUNK_SAMPLES * 20 {
            draws += 1;
            let Some(parts) = identifier_payload(&mut rng, true) else {
                continue;
            };
            let Some(value) = (cell.build)(&parts) else {
                continue;
            };
            let at_engine = tally.samples < ENGINE_CHUNK_SAMPLES;
            tally.judge(&value, &parts.concat(), at_engine);
        }
        tally.report(cell.name, CHUNK_SAMPLES, &mut failures);
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// a whole token of a credential alphabet inside each position: a hole's operand, member, call
/// argument, label, optional and unwrapped member, one cell per hole syntax, and a posix class
/// name, a currency conversion's name, a placeholder's name beside a hole, a chord's key and
/// action, an entry's name and flag and an escaped body's line. the position and the alphabet are
/// drawn per sample. a label follows its colon without a space here: a space splits the capture,
/// and the syntax step then reads the call around the token on its own terms.
#[test]
fn tokens_inside_positions_are_reported_at_the_engine() {
    const FORMS: [&str; 7] = [
        "P",
        "item.P",
        "make(P)",
        "make(for:P)",
        "item?.P",
        "item!.P",
        "make().P",
    ];
    const OTHER_FORMS: [&str; 8] = [
        "(deprecated|legacy|obsolete)[[:P:]]",
        "$%(P).2f/gb/month",
        r"\(item.size){P}",
        "ctrl+P=toggle_quick_terminal",
        "super+shift+t=P",
        "P=1234",
        "GOFLAGS=-mod=P",
        r#"\"release-notes-summary\"\nP"#,
    ];
    let mut rng = Rng(0xA54F_F53A_5F1D_36F1);
    let alphabets = credential_alphabets();
    let mut failures = Vec::new();
    let mut cells: Vec<(String, Vec<String>)> = HOLES
        .iter()
        .map(|(open, close)| {
            (
                format!("{open}P{close}"),
                FORMS
                    .iter()
                    .map(|form| format!("{open}{form}{close}"))
                    .collect(),
            )
        })
        .collect();
    cells.push((
        "other shapes".to_owned(),
        OTHER_FORMS.iter().map(|form| (*form).to_owned()).collect(),
    ));
    for (cell, forms) in cells {
        let mut tally = InsideTally::default();
        while tally.samples < SAMPLES {
            let (_, alphabet) = &alphabets[rng.below(alphabets.len())];
            let length = 20 + rng.below(45);
            let token = rng.token(alphabet, length);
            let form = &forms[rng.below(forms.len())];
            let at_engine = tally.samples < ENGINE_SAMPLES;
            tally.judge(&place(form, &token), &token, at_engine);
        }
        tally.report(&cell, SAMPLES, &mut failures);
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn findings(line: &str, al: &CompiledAllowlist) -> Vec<sekretbarilo::scanner::engine::Finding> {
    let file = DiffFile {
        path: "corpus/shapes.txt".to_owned(),
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

/// each shape of the new classes is claimed by its step on the diff surface with a value the rule
/// would report without it, and is left untouched by redaction on the agent surface.
#[test]
fn fixture_shapes_of_the_new_classes_reach_their_step() {
    let default = CompiledAllowlist::default_allowlist().unwrap();
    let mut traced = CompiledAllowlist::default_allowlist().unwrap();
    traced.trace_exemptions = true;
    let mut failures = Vec::new();
    for (name, label) in [("word-list.txt", "exempt:wordshape")] {
        let shapes = fixture_shapes(name);
        assert!(shapes.len() >= 8, "{name} carries {} shapes", shapes.len());
        for (shape, line) in shapes.iter().enumerate() {
            let found = findings(line, &traced);
            let exempted: Vec<&[u8]> = found
                .iter()
                .filter(|finding| finding.rule_id == label)
                .map(|finding| finding.matched_value.as_slice())
                .collect();
            if exempted.is_empty() {
                let rules: Vec<&str> = found.iter().map(|f| f.rule_id.as_str()).collect();
                failures.push(format!(
                    "{name} shape {shape}: no {label} trace, got {rules:?}"
                ));
            }
            for value in exempted {
                if value.len() < MIN_ENTROPY_LENGTH || shannon_entropy(value) < 4.0 {
                    failures.push(format!(
                        "{name} shape {shape}: {label} value below the gate, {} bytes at {:.2} bits",
                        value.len(),
                        shannon_entropy(value)
                    ));
                }
            }
            if found.iter().any(|finding| finding.rule_id == RULE) {
                failures.push(format!("{name} shape {shape}: reported"));
            }
            if redact_text(line, &SCANNER, &default) != *line {
                failures.push(format!("{name} shape {shape}: redacted"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
