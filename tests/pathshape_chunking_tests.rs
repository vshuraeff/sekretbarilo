//! chunked-payload regression guards for the structural path shapes of the tier-3 rule
//! (`generic-high-entropy-value`): a variable-rooted path and the parameter expansions, lists and
//! globs it reads, a keyed relative path with its usage placeholders, a host-rooted module path, a
//! scheme-less url, a dated file name, a json pointer with a schema keyword, and one separator
//! between two camel-case segments.
//!
//! an opaque payload of 20 to 64 bytes at shannon entropy 4.0 or more is cut into chunks of two to
//! five letters by one separator and placed in every position of each shape: a path component, a
//! reference name, a default, an error message, a pattern, a replacement, a subscript, a list item,
//! a glob, an escaped path, a module or url segment, a placeholder, the tail of a dated name, the
//! leaf and a suffix. random lowercase, random mixed-case and pronounceable (consonant-vowel) chunks
//! are never exempted. the one documented gap is a
//! payload cut by `/` into chunks of four or five letters: it reads as a path of short directory
//! names (`$HOME/.local/share/nvim/site`), and its rooted twin is exempt at base; the test measures
//! it and checks that the separator alone opens it. a scheme-less url keeps the rooted path's
//! reading of groups of four or five letters, which a url slug of short words shares
//! (`//host/docs/when-to-use-this`); the test measures those samples apart and prints them, while
//! groups of two or three letters under a host are never exempted. every value is generated at run
//! time from a seeded prng; none is stored in the repository.
//!
//! the engine cells put the chunks inside every position a reader accepts - a bracket expression,
//! a quoted string, a pattern, a subscript, an offset, an arithmetic body, a count, a module or url
//! segment, a placeholder, git's exclude magic and a possessive among them - cut every two to five
//! bytes into letters, letters with a digit run, or consonant-vowel groups, and joined by every
//! separator the readers accept, bare (`_ - . + : |`) or escaped (`\_ \- \. \+ \: \|`). each cell
//! is one kind of chunk and one separator, 20 000 payloads pooled over the positions, scanned on
//! the text surface, and on every tenth pass over the positions on the file surface too, which
//! runs the same steps: the path and relative-path steps never claim one. a `/` or an escaped `\/` between chunks cuts
//! a path into directories, the documented gap, and so does a bare `\` in a path of plain
//! references, as a windows path is written (`%APPDATA%\Tool`); those cells are measured, and each
//! claimed payload is reported again once its separators become `_`. anywhere else - an operand, a
//! pattern, a command, a list, a glob, an escaped value - a bare `\` is an escape that joins the
//! chunks around it, and none is claimed.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::{
    is_keyed_relative_path, is_path_shaped, is_reference_rooted, is_relative_id_path,
    shannon_entropy,
};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use sekretbarilo::scanner::wordshape::is_word_structured;
use std::sync::LazyLock;

const RULE: &str = "generic-high-entropy-value";

/// samples per random-letter alphabet and chunk width outside the `/` gap.
const SAMPLES: usize = 100_000;

/// samples per chunk width for the pronounceable alphabet, whose payloads seldom reach entropy 4.0
/// and so cost the most to draw: none exempted in 25 000 bounds its rate below 0.012% (95%), well
/// under the 0.1% a pronounceable alphabet is allowed.
const PRONOUNCEABLE_SAMPLES: usize = 25_000;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const MIXED: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxyz";
const VOWELS: &[u8] = b"aeiou";

/// xorshift64*
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alphabet {
    Lower,
    Mixed,
    Pronounceable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Widths {
    Fixed(usize),
    /// every chunk draws its own width from two to five.
    Mixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reference,
    Keyed,
    Pointer,
    Camel,
    /// a module path or a scheme-less url.
    Host,
    /// a dated file name, keyed or bare.
    Dated,
}

/// a place for the payload: `P` in `template` stands for it.
struct Position {
    shape: Shape,
    template: &'static str,
    separators: &'static [u8],
}

const REFERENCE_SEPARATORS: &[u8] = b"_-./";
const KEYED_SEPARATORS: &[u8] = b"_-.+:/";
/// the joins of an expansion operand, a list or a glob, `|` included.
const EXPANSION_SEPARATORS: &[u8] = b"_-.+:|";

const POSITIONS: &[Position] = &[
    // a variable-rooted path: a component, a name in each reference form, a default, a pattern,
    // the leaf and an extension-like suffix.
    Position {
        shape: Shape::Reference,
        template: "$VAR/P",
        separators: REFERENCE_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/P/settings.log",
        separators: REFERENCE_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${P}/settings.log",
        separators: b"_.",
    },
    Position {
        shape: Shape::Reference,
        template: "$P/settings.log",
        separators: b"_",
    },
    Position {
        shape: Shape::Reference,
        template: "$(P)/objects/release",
        separators: b"_",
    },
    Position {
        shape: Shape::Reference,
        template: "{P}/logs/run.txt",
        separators: b"_.",
    },
    Position {
        shape: Shape::Reference,
        template: "%P%\\Tool\\settings.json",
        separators: b"_",
    },
    Position {
        shape: Shape::Reference,
        template: "${VAR:-P}/settings.log",
        separators: REFERENCE_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${VAR%P}.log",
        separators: REFERENCE_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/.cache/P",
        separators: REFERENCE_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/settings.P",
        separators: REFERENCE_SEPARATORS,
    },
    // the parameter expansion grammar: a default, a message, a pattern, a replacement, a subscript,
    // a nested default and a pid-stamped name; then a glob, a list item and an escaped path.
    Position {
        shape: Shape::Reference,
        template: "${STATE_DIR:-P}/settings.log",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${STATE_DIR:?P}/run.log",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${config_path/#P/$HOME}",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${display_name//P/}",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${config_path/#$HOME/P}/run.log",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${cleanup_patterns[P]}",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${EDITOR:-${VISUAL:-P}}",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "${XDG_STATE_HOME:-/var/tmp}/P_$$.log",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/Library/Caches/P*",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/Library/Caches|P|backups",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/.cargo/bin:P",
        separators: EXPANSION_SEPARATORS,
    },
    Position {
        shape: Shape::Reference,
        template: "\\\"$HOME/.config/P\\\"",
        separators: EXPANSION_SEPARATORS,
    },
    // a module path, a scheme-less url, a usage placeholder and a dated file name.
    Position {
        shape: Shape::Host,
        template: "github.com/example/P",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Host,
        template: "golang.org/x/P/v2",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Host,
        template: "//cdn.example.com/assets/P/app.js",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/<P>/notes.md",
        separators: b"_-",
    },
    Position {
        shape: Shape::Dated,
        template: "2026-09-10-P.md",
        separators: b"_-.",
    },
    // a keyed relative path: a component, the leaf, the `:` suffix, beside a letter-and-digit part.
    Position {
        shape: Shape::Keyed,
        template: "docs/P/notes.md",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/notes/P",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/notes.md:P",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/run7/P/notes.md",
        separators: KEYED_SEPARATORS,
    },
    // a json pointer with a schema keyword: the leaf, a middle segment, the keyword segment.
    Position {
        shape: Shape::Pointer,
        template: "#/$defs/P",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Pointer,
        template: "#/$defs/P/properties/name",
        separators: KEYED_SEPARATORS,
    },
    Position {
        shape: Shape::Pointer,
        template: "#/$P/name",
        separators: KEYED_SEPARATORS,
    },
    // two camel-case segments around one separator.
    Position {
        shape: Shape::Camel,
        template: "P",
        separators: b".-_/:",
    },
];

fn push_chunk(rng: &mut Rng, alphabet: Alphabet, width: usize, out: &mut Vec<u8>) {
    match alphabet {
        Alphabet::Lower => out.extend((0..width).map(|_| LOWER[rng.below(LOWER.len())])),
        Alphabet::Mixed => out.extend((0..width).map(|_| MIXED[rng.below(MIXED.len())])),
        Alphabet::Pronounceable => {
            let start = rng.below(2);
            out.extend((0..width).map(|index| {
                if (index + start).is_multiple_of(2) {
                    CONSONANTS[rng.below(CONSONANTS.len())]
                } else {
                    VOWELS[rng.below(VOWELS.len())]
                }
            }));
        }
    }
}

/// shannon entropy of an ascii value; `shannon_entropy` with a table sized for ascii, since the
/// monte-carlo below evaluates tens of millions of candidate payloads.
fn ascii_entropy(value: &[u8]) -> f64 {
    let mut counts = [0_u32; 128];
    for &byte in value {
        counts[usize::from(byte & 0x7F)] += 1;
    }
    let length = value.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let share = f64::from(count) / length;
            -share * share.log2()
        })
        .sum()
}

/// an opaque payload of 20 to 64 bytes at shannon entropy 4.0 or more, cut into chunks by
/// `separator`. a camel payload capitalizes every chunk but the first of each of its two segments
/// and puts `separator` between the segments only. `None` when no draw qualified.
fn payload(
    rng: &mut Rng,
    alphabet: Alphabet,
    widths: Widths,
    separator: u8,
    camel: bool,
) -> Option<String> {
    let mut value = Vec::with_capacity(80);
    let mut starts = Vec::with_capacity(32);
    for _ in 0..64 {
        value.clear();
        starts.clear();
        let target = 20 + rng.below(45);
        while value.len() + usize::from(camel) < target {
            if !camel && !starts.is_empty() {
                value.push(separator);
            }
            starts.push(value.len());
            let width = match widths {
                Widths::Fixed(width) => width,
                Widths::Mixed => 2 + rng.below(4),
            };
            push_chunk(rng, alphabet, width, &mut value);
        }
        if camel {
            if starts.len() < 2 {
                continue;
            }
            let split = starts.len() / 2;
            if alphabet != Alphabet::Mixed {
                for (index, &start) in starts.iter().enumerate() {
                    if index != 0 && index != split {
                        value[start] = value[start].to_ascii_uppercase();
                    }
                }
            }
            value.insert(starts[split], separator);
        }
        if (20..=64).contains(&value.len()) && ascii_entropy(&value) >= 4.0 {
            return Some(String::from_utf8(value).expect("ascii payload"));
        }
    }
    None
}

/// whether the step that owns `shape` exempts `value`.
fn exempts(shape: Shape, value: &[u8]) -> bool {
    match shape {
        Shape::Reference => is_path_shaped(value) || is_reference_rooted(value),
        Shape::Keyed => is_keyed_relative_path(value),
        Shape::Pointer | Shape::Host => is_path_shaped(value),
        Shape::Camel => is_word_structured(value),
        Shape::Dated => is_keyed_relative_path(value) || is_relative_id_path(value),
    }
}

fn masked(value: &str) -> String {
    format!(
        "{}..{} ({} bytes)",
        &value[..2],
        &value[value.len() - 2..],
        value.len()
    )
}

#[test]
fn random_lowercase_chunks_never_pass_as_path_shapes() {
    assert_no_chunked_exemption(Alphabet::Lower, SAMPLES, 1);
}

#[test]
fn random_mixed_case_chunks_never_pass_as_path_shapes() {
    assert_no_chunked_exemption(Alphabet::Mixed, SAMPLES, 2);
}

#[test]
fn pronounceable_chunks_never_pass_as_path_shapes() {
    assert_no_chunked_exemption(Alphabet::Pronounceable, PRONOUNCEABLE_SAMPLES, 3);
}

/// draws `samples` qualifying payloads per chunk width outside the `/` gap, over every position,
/// and fails on any exemption; inside the gap it counts exemptions and checks that each one is
/// reported once its `/` separators become `_`. each width runs on its own thread; the counts go
/// to stderr (`--nocapture`).
fn assert_no_chunked_exemption(alphabet: Alphabet, samples: usize, seed: u64) {
    let widths = [
        Widths::Fixed(2),
        Widths::Fixed(3),
        Widths::Fixed(4),
        Widths::Fixed(5),
        Widths::Mixed,
    ];
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = widths
            .iter()
            .enumerate()
            // two-letter chunks of 26 or fewer letters with a separator in every third byte
            // rarely reach entropy 4.0, so those classes have no payload to test.
            .filter(|(_, width)| **width != Widths::Fixed(2) || alphabet == Alphabet::Mixed)
            .map(|(index, &width)| {
                scope.spawn(move || {
                    measure(
                        alphabet,
                        width,
                        samples,
                        0x9E37_79B9_7F4A_7C15 ^ (seed << 40) ^ index as u64,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("measurement thread"))
            .collect()
    });
    assert!(
        failures.is_empty(),
        "chunked payloads exempted:\n{}",
        failures.join("\n")
    );
}

fn measure(alphabet: Alphabet, width: Widths, wanted: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng::new(seed);
    let mut failures = Vec::new();
    let (mut samples, mut exempt, mut gap_samples, mut gap_exempt) = (0, 0, 0, 0);
    let (mut slug_samples, mut slug_exempt) = (0, 0);
    let mut draws = 0;
    while samples < wanted {
        draws += 1;
        assert!(
            draws < wanted * 20,
            "{alphabet:?} {width:?}: too few qualifying payloads"
        );
        let position = &POSITIONS[rng.below(POSITIONS.len())];
        let separator = position.separators[rng.below(position.separators.len())];
        let camel = position.shape == Shape::Camel;
        let Some(payload) = payload(&mut rng, alphabet, width, separator, camel) else {
            continue;
        };
        let value = position.template.replacen('P', &payload, 1);
        let is_exempt = exempts(position.shape, value.as_bytes());
        let wide = !matches!(width, Widths::Fixed(2) | Widths::Fixed(3));
        let in_gap = separator == b'/' && !camel && wide;
        if !in_gap && wide && position.template.starts_with("//") {
            // a scheme-less url keeps the rooted path's reading of groups of four or five
            // letters, a url slug of short words.
            slug_samples += 1;
            slug_exempt += usize::from(is_exempt);
            continue;
        }
        if in_gap {
            gap_samples += 1;
            if is_exempt {
                gap_exempt += 1;
                // the gap is the separator alone: the same chunks cut by `_` are reported.
                // under a host the rejoined groups fall in the url slug gap below.
                let rejoined = value.replacen(&payload, &payload.replace('/', "_"), 1);
                if exempts(position.shape, rejoined.as_bytes())
                    && !position.template.starts_with("//")
                    && failures.len() < 20
                {
                    failures.push(format!(
                        "{alphabet:?} {width:?} {}: exempt with `_` too: {}",
                        position.template,
                        masked(&rejoined)
                    ));
                }
            }
            continue;
        }
        samples += 1;
        if is_exempt {
            exempt += 1;
            if failures.len() < 20 {
                failures.push(format!(
                    "{alphabet:?} {width:?} {} sep {}: {}",
                    position.template,
                    char::from(separator),
                    masked(&value)
                ));
            }
        }
    }
    eprintln!(
        "{alphabet:?} {width:?}: {samples} samples, {exempt} exempt; `/` gap: {gap_samples} \
         samples, {gap_exempt} exempt; url slug gap: {slug_samples} samples, {slug_exempt} exempt"
    );
    failures
}

#[test]
fn a_leaf_of_two_letter_words_is_wordy_only_while_short() {
    let mut rng = Rng::new(0x5DEE_CE66_D1CE_4E5B);
    for pieces in 2..=12 {
        for _ in 0..200 {
            let mut leaf = Vec::new();
            for piece in 0..pieces {
                if piece > 0 {
                    leaf.push(b'-');
                }
                push_chunk(&mut rng, Alphabet::Pronounceable, 2, &mut leaf);
            }
            let value = format!("/data/cache/{}", String::from_utf8(leaf).expect("ascii"));
            assert_eq!(
                is_path_shaped(value.as_bytes()),
                pieces <= 4,
                "{pieces} pieces: {}",
                masked(&value)
            );
        }
    }
}

#[test]
fn chunked_reference_paths_are_detected_and_redacted() {
    let scanner = compile_rules(&load_default_rules().expect("rules")).expect("scanner");
    let allowlist = CompiledAllowlist::default_allowlist().expect("allowlist");
    let mut rng = Rng::new(123_456_789);
    let mut checked = 0;
    for draw in 0..300 {
        // the reviewer's shape: 36 random lowercase letters in twelve chunks of three; then chunks
        // of four and five letters, random and pronounceable, cut by `-`.
        let (alphabet, width, separator) = match draw % 3 {
            0 => (Alphabet::Lower, 3, b'_'),
            1 => (Alphabet::Lower, 4 + draw % 2, b'-'),
            _ => (Alphabet::Pronounceable, 4 + draw % 2, b'-'),
        };
        let mut chunks = Vec::new();
        for index in 0..36 / width {
            if index > 0 {
                chunks.push(separator);
            }
            push_chunk(&mut rng, alphabet, width, &mut chunks);
        }
        let chunks = String::from_utf8(chunks).expect("ascii");
        for value in [
            format!("$VAR/{chunks}"),
            format!("${{VAR:-{chunks}}}/settings.log"),
            format!("${{{}}}/settings.log", chunks.replace('-', "_")),
        ] {
            if shannon_entropy(value.as_bytes()) < 4.0 {
                continue;
            }
            checked += 1;
            let line = format!("VALUE=\"{value}\"\n");
            assert!(
                scan_text(&line, &scanner, &allowlist)
                    .iter()
                    .any(|found| found.rule_id == RULE),
                "not detected: {}",
                masked(&value)
            );
            let redacted = redact_text(&line, &scanner, &allowlist);
            assert!(
                redacted.contains("[REDACTED]") && !redacted.contains(&value),
                "not redacted: {}",
                masked(&value)
            );
        }
    }
    assert!(
        checked > 600,
        "too few generated values reached entropy 4.0: {checked}"
    );
}

#[test]
fn digit_bearing_chunks_are_not_exempted() {
    let scanner = compile_rules(&load_default_rules().expect("rules")).expect("scanner");
    let allowlist = CompiledAllowlist::default_allowlist().expect("allowlist");
    let mut rng = Rng::new(867_530_921);
    let mut checked = 0;
    let mut scanned = 0;
    for draw in 0..600 {
        let width = 2 + draw % 4;
        let mut payload = Vec::new();
        for index in 0..8 {
            if index > 0 {
                payload.push(b'_');
            }
            let mut letters = Vec::new();
            push_chunk(&mut rng, Alphabet::Pronounceable, width, &mut letters);
            let digit_at = (draw / 4) % (width + 1);
            payload.extend_from_slice(&letters[..digit_at]);
            for _ in 0..1 + (draw / 24) % 4 {
                payload.push(b'0' + rng.below(10) as u8);
            }
            payload.extend_from_slice(&letters[digit_at..]);
        }
        let payload = String::from_utf8(payload).expect("ascii");
        for position in POSITIONS.iter().filter(|p| p.shape != Shape::Camel) {
            for &separator in position.separators.iter().filter(|&&s| s != b'/') {
                let cut = payload.replace('_', &char::from(separator).to_string());
                let value = position.template.replace('P', &cut);
                if shannon_entropy(value.as_bytes()) < 4.0 {
                    continue;
                }
                checked += 1;
                assert!(
                    !exempts(position.shape, value.as_bytes()),
                    "exempt: {}",
                    masked(&value)
                );
            }
        }
        // the end-to-end comparison targets payloads detected without a wrapper; other existing
        // exemption steps can accept some pronounceable bare values.
        let bare = format!("VALUE=\"{payload}\"\n");
        if !scan_text(&bare, &scanner, &allowlist)
            .iter()
            .any(|f| f.rule_id == RULE)
        {
            continue;
        }
        for value in [
            format!("$VAR/{payload}/settings.log"),
            format!("${{VAR:-{payload}}}/settings.log"),
            format!("${{{payload}}}/settings.log"),
            format!("#/$defs/{payload}/settings"),
        ] {
            if shannon_entropy(value.as_bytes()) < 4.0 {
                continue;
            }
            scanned += 1;
            let line = format!("VALUE=\"{value}\"\n");
            assert!(
                scan_text(&line, &scanner, &allowlist)
                    .iter()
                    .any(|f| f.rule_id == RULE),
                "not detected: {}",
                masked(&value)
            );
            let redacted = redact_text(&line, &scanner, &allowlist);
            assert!(
                redacted.contains("[REDACTED]") && !redacted.contains(&value),
                "not redacted: {}",
                masked(&value)
            );
        }
    }
    assert!(checked > 20_000, "too few qualified shape cases: {checked}");
    assert!(scanned > 1_000, "too few qualified scan cases: {scanned}");
    eprintln!("digit-bearing chunks: {checked} predicate cases, {scanned} scan/redact cases");
}

/// payloads per engine cell: one kind of chunk joined by one separator, pooled over every inside
/// position.
const INSIDE_SAMPLES: usize = 20_000;

/// the steps whose predicates read path shapes.
const PATH_STEPS: &[&str] = &["exempt:path", "exempt:relpath"];

/// the separators the readers accept between the words of a value; each cell writes them bare or
/// escaped (`\-`), the payload drawn first with the bare separator, so an escaped cell holds the
/// same chunks as the bare one.
const INSIDE_SEPARATORS: &[&str] = &["_", "-", ".", "+", ":", "|"];

/// the separators that cut a path into directories: `/`, bare or escaped (`\/`), and a bare `\`,
/// which reads as a path separator only in a path of plain references (`directory_position`) and
/// as an escape everywhere else.
const DIRECTORY_SEPARATORS: &[(&str, bool)] = &[("/", false), ("/", true), ("\\", false)];

/// the file surface is scanned on one pass over the positions in this many, so every position has
/// its share: the text surface scans every payload through the same steps, and the file scan
/// doubles the cost of a cell.
const FILE_SURFACE_STRIDE: usize = 10;

/// whether a bare `\` in the position reads as a windows directory separator: the position is a
/// path of plain references and literal pieces (`$HOME/.cache/P`, `$P/settings.log`), with no
/// expansion operator, command, list, glob, escape, placeholder or host.
fn directory_position(template: &str) -> bool {
    template.contains('$')
        && template
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"$/._-".contains(&byte))
}

static ENGINE_SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().expect("rules")).expect("scanner"));

/// the default allowlist, with each decision of the layer reported as an `exempt:<step>`
/// pseudo-finding.
static TRACED: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = CompiledAllowlist::default_allowlist().expect("allowlist");
    allowlist.trace_exemptions = true;
    allowlist
});

/// a position inside the syntax a reader accepts, keyed (`setting="…"`) or bare on its own line:
/// the one `P` with no letter or digit beside it stands for the payload.
const INSIDE: &[(bool, &str)] = &[
    (false, "$HOME/.config/P/settings.json"),
    (false, "$HOME/.cache/P"),
    (false, "${P}/settings.log"),
    (false, "$P/settings.log"),
    (false, "{P}/logs/run.txt"),
    (false, "%P%\\Tool\\settings.json"),
    (false, "$(P)/objects/release"),
    (false, "${XDG_CONFIG_HOME:-P}/settings.json"),
    (false, "${WORKSPACE_ROOT:?P}/scripts/run.sh"),
    (false, "${BUNDLE_NAME:+P}/settings.json"),
    (false, "${ARCHIVE_NAME%P}.log"),
    (false, "${ARCHIVE_NAME##P}.log"),
    (false, "${display_name//P/}"),
    (false, "${display_name/#\\~/P}"),
    (false, "${display_name^^P}"),
    (false, "${BUNDLE_PATH_NAME%[P]}/settings.log"),
    (false, "${display_name//[$'P']/}"),
    (false, "${display_name//$'P'/}"),
    (false, "${display_name//['P']/}"),
    (false, "${cleanup_patterns[P]}"),
    (false, "${display_name:P}"),
    (false, "${display_name:2:P}"),
    (false, "$((P))"),
    (false, "$[P]"),
    (false, "${OUTER_ROOT:-${INNER_ROOT:-P}}"),
    (false, "${#P[@]}"),
    (false, "${!P}"),
    (false, "\\\"$HOME/.config/P\\\""),
    (false, "\\$HOME/P/settings.json"),
    (false, "$HOME/Library/P/*.log"),
    (false, "$HOME/.cargo/bin:P"),
    (false, "P:$HOME/.local/bin"),
    (false, "$HOME/Library/Caches|P|default"),
    (false, "/Library/Caches/$P.plist"),
    (false, "${BUNDLE_NAME%.P}"),
    (false, "github.com/P"),
    (false, "github.com/acme/P/v2"),
    (false, "golang.org/x/P/v2"),
    (false, "//cdn.example.com/P"),
    (false, "//cdn.example.com/assets/P/app.js"),
    (false, "docs/<P>/notes.md"),
    (false, "docs/notes/<P>"),
    (false, ":!docs/P/notes.md"),
    (false, "docs/P/notes.md's"),
    (false, "2026-09-10-P.md"),
    (true, "2026-09-10-P.md"),
];

/// the kind of chunk a payload is cut into.
#[derive(Clone, Copy, Debug)]
enum Chunk {
    Letters,
    /// letters with a run of one to three digits somewhere in the chunk (`ab12c`).
    DigitRuns,
    ConsonantVowel,
}

/// an opaque payload of 20 to 64 bytes at shannon entropy 4.0 or more, cut every two to five
/// letters and joined by `separator`; `None` when no draw qualified.
fn inside_payload(rng: &mut Rng, chunk: Chunk, separator: &str) -> Option<String> {
    let mut value = Vec::with_capacity(96);
    for _ in 0..64 {
        value.clear();
        let target = 20 + rng.below(45);
        while value.len() < target {
            if !value.is_empty() {
                value.extend_from_slice(separator.as_bytes());
            }
            let width = 2 + rng.below(4);
            match chunk {
                Chunk::Letters => push_chunk(rng, Alphabet::Lower, width, &mut value),
                Chunk::ConsonantVowel => {
                    push_chunk(rng, Alphabet::Pronounceable, width, &mut value)
                }
                Chunk::DigitRuns => {
                    let mut letters = Vec::with_capacity(width);
                    push_chunk(rng, Alphabet::Lower, width, &mut letters);
                    let at = rng.below(width + 1);
                    value.extend_from_slice(&letters[..at]);
                    for _ in 0..1 + rng.below(3) {
                        value.push(b'0' + rng.below(10) as u8);
                    }
                    value.extend_from_slice(&letters[at..]);
                }
            }
        }
        if value.len() <= 64 && ascii_entropy(&value) >= 4.0 {
            return Some(String::from_utf8(value).expect("ascii payload"));
        }
    }
    None
}

/// the template with the payload in place of its marker.
fn place_inside(template: &str, payload: &str) -> String {
    let bytes = template.as_bytes();
    let marker = (0..bytes.len())
        .find(|&index| {
            bytes[index] == b'P'
                && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
                && bytes
                    .get(index + 1)
                    .is_none_or(|next| !next.is_ascii_alphanumeric())
        })
        .expect("template marker");
    format!(
        "{}{payload}{}",
        &template[..marker],
        &template[marker + 1..]
    )
}

/// whether a path step claims the value on the text surface, or on the file surface when `file`,
/// or the rooted path check drops it before the layer runs, which leaves no decision to trace.
fn claimed_as_path(bare: bool, value: &str, file: bool) -> bool {
    let line = if bare {
        format!("{value}\n")
    } else {
        format!("setting=\"{value}\"\n")
    };
    if is_path_shaped(value.as_bytes())
        || scan_text(&line, &ENGINE_SCANNER, &TRACED)
            .iter()
            .any(|found| PATH_STEPS.contains(&found.rule_id.as_str()))
    {
        return true;
    }
    if !file {
        return false;
    }
    let file = DiffFile {
        path: "corpus/shapes.txt".to_owned(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.trim_end().as_bytes().to_vec(),
        }],
    };
    scan(&[file], &ENGINE_SCANNER, &TRACED)
        .iter()
        .any(|found| PATH_STEPS.contains(&found.rule_id.as_str()))
}

/// draws `INSIDE_SAMPLES` payloads of one chunk kind and separator, `escaped` or bare, over every
/// inside position. outside the directory gap a claimed payload is a failure; inside it the claims
/// are counted, and a payload still claimed once its separators become `_` is a failure. a bare
/// `\` cuts directories only in a `directory_position`; anywhere else its claims fail.
fn measure_inside(chunk: Chunk, separator: &str, escaped: bool, seed: u64) -> (usize, Vec<String>) {
    let directory = DIRECTORY_SEPARATORS.contains(&(separator, escaped));
    let backslash = separator == "\\" && !escaped;
    let written = if escaped {
        format!("\\{separator}")
    } else {
        separator.to_owned()
    };
    let mut rng = Rng::new(seed);
    let (mut samples, mut claimed, mut draws) = (0, 0, 0);
    let (mut gap_samples, mut gap_claimed) = (0, 0);
    let (mut slug_samples, mut slug_claimed) = (0, 0);
    let mut failures = Vec::new();
    while samples + gap_samples + slug_samples < INSIDE_SAMPLES {
        draws += 1;
        assert!(
            draws < INSIDE_SAMPLES * 20,
            "{chunk:?} {written}: too few qualifying payloads"
        );
        let Some(bare_payload) = inside_payload(&mut rng, chunk, separator) else {
            continue;
        };
        let payload = bare_payload.replace(separator, &written);
        let drawn = samples + gap_samples + slug_samples;
        let (bare, template) = INSIDE[drawn % INSIDE.len()];
        let value = place_inside(template, &payload);
        let file = (drawn / INSIDE.len()).is_multiple_of(FILE_SURFACE_STRIDE);
        if template.starts_with("//") {
            // a scheme-less url keeps the rooted path's reading of groups of four or five
            // letters, a url slug of short words, at base as here.
            slug_samples += 1;
            slug_claimed += usize::from(claimed_as_path(bare, &value, file));
            continue;
        }
        let gap = directory && (!backslash || directory_position(template));
        if gap {
            gap_samples += 1;
        } else {
            samples += 1;
        }
        if !claimed_as_path(bare, &value, file) {
            continue;
        }
        let twin = place_inside(template, &bare_payload.replace(separator, "_"));
        let failed = if gap {
            gap_claimed += 1;
            claimed_as_path(bare, &twin, file)
        } else {
            claimed += 1;
            true
        };
        if failed && failures.len() < 20 {
            failures.push(format!(
                "{chunk:?} {written} {template}: claimed{}: {}",
                if gap { " with `_` too" } else { "" },
                masked(&value)
            ));
        }
    }
    eprintln!(
        "inside {chunk:?} {written}: {samples} samples, {claimed} claimed as a path; directory \
         gap: {gap_samples} samples, {gap_claimed} claimed; url slug gap: {slug_samples} samples, \
         {slug_claimed} claimed"
    );
    (claimed, failures)
}

#[test]
fn chunks_inside_every_position_are_never_claimed_as_paths() {
    let separators: Vec<(&str, bool)> = INSIDE_SEPARATORS
        .iter()
        .flat_map(|&separator| [(separator, false), (separator, true)])
        .chain(DIRECTORY_SEPARATORS.iter().copied())
        .collect();
    let cells: Vec<(Chunk, &str, bool)> = [Chunk::Letters, Chunk::DigitRuns, Chunk::ConsonantVowel]
        .into_iter()
        .flat_map(|chunk| {
            separators
                .iter()
                .map(move |&(separator, escaped)| (chunk, separator, escaped))
        })
        .collect();
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(index, &(chunk, separator, escaped))| {
                scope.spawn(move || {
                    let seed = 0xD1B5_4A32_D192_ED03 ^ index as u64;
                    measure_inside(chunk, separator, escaped, seed).1
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("engine thread"))
            .collect()
    });
    assert!(
        failures.is_empty(),
        "chunks inside a position claimed as a path:\n{}",
        failures.join("\n")
    );
}
