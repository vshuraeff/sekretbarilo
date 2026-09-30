//! random-alphabet recall guards for the path shapes the tier-3 rule (`generic-high-entropy-value`)
//! reads through parameter expansion, reference lists, globs, escaped paths, host-rooted module
//! paths, scheme-less urls, usage placeholders and dated file names.
//!
//! a random token of 20 to 64 bytes is placed in every position those shapes read: a default, an
//! error message, a pattern, a replacement, a name, a subscript, an arithmetic or command body, a
//! glob, a list item, an escaped path, a module segment, a url segment, a placeholder and the tail
//! of a dated name. the encoded alphabets (base62, base64, base64url, hex, base32 and lowercase
//! base36) are never exempted in 100 000 samples each. the recognizer's own alphabet, the letters,
//! digits and joins a path piece is made of, reads as words now and then; its rate stays below
//! 0.1%. the one documented gap is a base64 token whose `/` cuts it into directory names where the
//! value is a path (`$DIR/<a>/<b>_$$.log`): the rooted path rule reads it so at base, and the test
//! measures it and checks that the `/` alone opens it. every value is generated at run time from a
//! seeded prng; none is stored in the repository.
//!
//! the engine cells put the token inside every position a reader accepts - a bracket expression,
//! an ansi-c or single-quoted string, a pattern, a subscript, an offset, an arithmetic body, a
//! count or an indirection, a module or url segment, a placeholder, git's exclude magic, a
//! possessive and a dated name among them - as it is, with a backslash before every byte, and with
//! one before every other byte. each cell is one way of writing one alphabet, 100 000 tokens pooled
//! over the positions, scanned on the text surface (`scan_text`), and on every tenth pass over the
//! positions on the file surface (`scan`) too, which runs the same steps: the path and
//! relative-path steps never claim one, and the rooted path check never drops one, so none is
//! exempted beyond what the same token gets standing alone, where no path step reads it.
//!
//! the member cells join random words or a cut token by `.` or `?.` into a member chain and put it
//! in a reference: alone (`${P}`, `{P}`, `$(P)`), beside another reference or in a default, where
//! a member chain is a template hole and no path, and inside a path. optional chaining and a
//! command that opens on a member are never claimed, nor is a chain in references alone; a dotted
//! name inside a path keeps the reading a path gave it before the shell grammar, and is measured.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{scan, scan_text};
use sekretbarilo::scanner::entropy::{
    is_keyed_relative_path, is_path_shaped, is_reference_rooted, is_relative_id_path,
    shannon_entropy,
};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// samples per alphabet, pooled over every position, outside the `/` gap; the gap's samples come on
/// top.
const SAMPLES: usize = 100_000;

/// the rate a word-shaped alphabet may reach, in samples per million: 0.1%.
const WORD_SHAPED_PER_MILLION: usize = 1_000;

const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX: &[u8] = b"0123456789abcdef";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE36: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const PATH_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";
const PATH_MIXED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";

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

/// the recognizer that owns a position.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// a reference path, list or expansion: the path step.
    Reference,
    /// a module path or a scheme-less url: the rooted path step.
    Host,
    /// a keyed relative path with a usage placeholder.
    Keyed,
    /// a dated file name, keyed or bare.
    Dated,
}

/// a place for the token: the one `P` with no letter or digit beside it stands for it.
struct Position {
    shape: Shape,
    template: &'static str,
    /// whether a `/` in the token cuts a path into directories here, rather than ending a pattern.
    path: bool,
}

const POSITIONS: &[Position] = &[
    Position {
        shape: Shape::Reference,
        template: "${STATE_DIR:-P}/settings.log",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${STATE_DIR:?P}/run.log",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${config_path/#P/$HOME}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${display_name//P/}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${bundle_name%P}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${archive_name##P}.log",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${config_path/#\\~/P}",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${config_path/#$HOME/P}/run.log",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${P[@]}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${#P[@]}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${cleanup_patterns[P]}",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "${EDITOR:-${VISUAL:-P}}",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${9:-P}",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "$(P)",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "$((P))",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "$[P]",
        path: false,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/Library/Caches/P*",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/Library/P/*.log",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/Library/Caches|P|backups",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "P|$HOME/.cache|backups",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "$HOME/.cargo/bin:P",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "P:$HOME/.local/bin",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "\\\"$HOME/.config/P\\\"",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "\\$HOME/P",
        path: true,
    },
    Position {
        shape: Shape::Reference,
        template: "${XDG_STATE_HOME:-/var/tmp}/P_$$.log",
        path: true,
    },
    Position {
        shape: Shape::Host,
        template: "github.com/P",
        path: true,
    },
    Position {
        shape: Shape::Host,
        template: "github.com/example/P",
        path: true,
    },
    Position {
        shape: Shape::Host,
        template: "golang.org/x/P/v2",
        path: true,
    },
    Position {
        shape: Shape::Host,
        template: "//cdn.example.com/P",
        path: true,
    },
    Position {
        shape: Shape::Host,
        template: "//cdn.example.com/assets/P/app.js",
        path: true,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/<P>/notes.md",
        path: true,
    },
    Position {
        shape: Shape::Keyed,
        template: "docs/notes/<P>",
        path: true,
    },
    Position {
        shape: Shape::Dated,
        template: "2026-09-10-P.md",
        path: true,
    },
];

/// the template with the token in place of its marker.
fn place(template: &str, token: &str) -> String {
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
    format!("{}{token}{}", &template[..marker], &template[marker + 1..])
}

/// whether the step that owns `shape` exempts `value`.
fn exempts(shape: Shape, value: &[u8]) -> bool {
    match shape {
        Shape::Reference => is_path_shaped(value) || is_reference_rooted(value),
        Shape::Host => is_path_shaped(value),
        Shape::Keyed => is_keyed_relative_path(value),
        Shape::Dated => is_keyed_relative_path(value) || is_relative_id_path(value),
    }
}

/// a token of 20 to 64 bytes from `alphabet` at shannon entropy 4.0 or more. sixteen symbols carry
/// at most 4.0 bits, so a hex token is taken at any entropy: the recognizers must refuse it anyway.
fn token(rng: &mut Rng, alphabet: &[u8]) -> String {
    loop {
        let length = 20 + rng.below(45);
        let value: Vec<u8> = (0..length)
            .map(|_| alphabet[rng.below(alphabet.len())])
            .collect();
        if alphabet.len() <= 16 || shannon_entropy(&value) >= 4.0 {
            return String::from_utf8(value).expect("ascii token");
        }
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

/// the outcome of one alphabet over every position.
struct Tally {
    samples: usize,
    exempt: usize,
    gap_samples: usize,
    gap_exempt: usize,
    failures: Vec<String>,
}

fn measure(name: &str, alphabet: &[u8], seed: u64) -> Tally {
    let mut rng = Rng::new(seed);
    let mut tally = Tally {
        samples: 0,
        exempt: 0,
        gap_samples: 0,
        gap_exempt: 0,
        failures: Vec::new(),
    };
    let mut draw = 0;
    while tally.samples < SAMPLES {
        let position = &POSITIONS[draw % POSITIONS.len()];
        draw += 1;
        let token = token(&mut rng, alphabet);
        let value = place(position.template, &token);
        let exempt = exempts(position.shape, value.as_bytes());
        if position.path && token.contains('/') {
            // the gap is the separator alone: the same token without its `/` is reported.
            tally.gap_samples += 1;
            if exempt {
                tally.gap_exempt += 1;
                let joined = place(position.template, &token.replace('/', "_"));
                if exempts(position.shape, joined.as_bytes()) && tally.failures.len() < 20 {
                    tally.failures.push(format!(
                        "{name} {}: exempt without its `/` too: {}",
                        position.template,
                        masked(&joined)
                    ));
                }
            }
            continue;
        }
        tally.samples += 1;
        if exempt {
            tally.exempt += 1;
            if tally.failures.len() < 20 {
                tally
                    .failures
                    .push(format!("{name} {}: {}", position.template, masked(&value)));
            }
        }
    }
    eprintln!(
        "{name}: {} samples, {} exempt; `/` gap: {} samples, {} exempt",
        tally.samples, tally.exempt, tally.gap_samples, tally.gap_exempt
    );
    tally
}

#[test]
fn encoded_alphabets_are_never_read_as_reference_shapes() {
    let alphabets: [(&str, &[u8]); 6] = [
        ("base62", BASE62),
        ("base64", BASE64),
        ("base64url", BASE64URL),
        ("hex", HEX),
        ("base32", BASE32),
        ("base36", BASE36),
    ];
    let tallies: Vec<(&str, Tally)> = std::thread::scope(|scope| {
        let handles: Vec<_> = alphabets
            .iter()
            .enumerate()
            .map(|(index, &(name, alphabet))| {
                scope.spawn(move || {
                    (
                        name,
                        measure(name, alphabet, 0x9E37_79B9_7F4A_7C15 ^ index as u64),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("measurement thread"))
            .collect()
    });
    let mut failures = Vec::new();
    for (name, tally) in &tallies {
        failures.extend(tally.failures.iter().cloned());
        // the `/` gap stays a rare reading of directory names, not a way through.
        assert!(
            tally.gap_exempt * 1_000_000 < tally.gap_samples.max(1) * WORD_SHAPED_PER_MILLION,
            "{name}: {} of {} `/`-cut tokens exempted",
            tally.gap_exempt,
            tally.gap_samples
        );
    }
    assert!(
        failures.is_empty(),
        "encoded tokens exempted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn the_recognizer_alphabet_reads_as_words_below_one_in_a_thousand() {
    for (index, (name, alphabet)) in [("path-lower", PATH_LOWER), ("path-mixed", PATH_MIXED)]
        .into_iter()
        .enumerate()
    {
        let tally = measure(name, alphabet, 0x5DEE_CE66_D1CE_4E5B ^ index as u64);
        assert!(
            tally.exempt * 1_000_000 < tally.samples * WORD_SHAPED_PER_MILLION,
            "{name}: {} of {} tokens exempted, at or above 0.1%",
            tally.exempt,
            tally.samples
        );
    }
}

const RULE: &str = "generic-high-entropy-value";

/// engine samples per cell: one way of writing one alphabet, pooled over every inside position.
const ENGINE_SAMPLES: usize = 100_000;

/// the steps whose predicates read path shapes: a token inside a position must never be claimed
/// by one of them.
const PATH_STEPS: &[&str] = &["exempt:path", "exempt:relpath"];

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().expect("rules")).expect("scanner"));

/// the default allowlist, with each decision of the layer reported as an `exempt:<step>`
/// pseudo-finding.
static TRACED: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist = CompiledAllowlist::default_allowlist().expect("allowlist");
    allowlist.trace_exemptions = true;
    allowlist
});

/// how a value is assigned: after a key (`setting="…"`), or bare on its own line, as a dated file
/// name is judged.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Assigned {
    Keyed,
    Bare,
}

/// a position inside the syntax a reader accepts: the one `P` with no letter or digit beside it
/// stands for the token.
const INSIDE: &[(Assigned, &str)] = &[
    (Assigned::Keyed, "$HOME/.config/P/settings.json"),
    (Assigned::Keyed, "$HOME/.cache/P"),
    (Assigned::Keyed, "${P}/settings.log"),
    (Assigned::Keyed, "$P/settings.log"),
    (Assigned::Keyed, "{P}/logs/run.txt"),
    (Assigned::Keyed, "%P%\\Tool\\settings.json"),
    (Assigned::Keyed, "$(P)/objects/release"),
    (Assigned::Keyed, "${XDG_CONFIG_HOME:-P}/settings.json"),
    (Assigned::Keyed, "${WORKSPACE_ROOT:?P}/scripts/run.sh"),
    (Assigned::Keyed, "${BUNDLE_NAME:+P}/settings.json"),
    (Assigned::Keyed, "${ARCHIVE_NAME%P}.log"),
    (Assigned::Keyed, "${ARCHIVE_NAME##P}.log"),
    (Assigned::Keyed, "${display_name//P/}"),
    (Assigned::Keyed, "${display_name/#\\~/P}"),
    (Assigned::Keyed, "${display_name^^P}"),
    (Assigned::Keyed, "${BUNDLE_PATH_NAME%[P]}/settings.log"),
    (Assigned::Keyed, "${display_name//[$'P']/}"),
    (Assigned::Keyed, "${display_name//$'P'/}"),
    (Assigned::Keyed, "${display_name//['P']/}"),
    (Assigned::Keyed, "${cleanup_patterns[P]}"),
    (Assigned::Keyed, "${display_name:P}"),
    (Assigned::Keyed, "${display_name:2:P}"),
    (Assigned::Keyed, "$((P))"),
    (Assigned::Keyed, "$[P]"),
    (Assigned::Keyed, "${OUTER_ROOT:-${INNER_ROOT:-P}}"),
    (Assigned::Keyed, "${#P[@]}"),
    (Assigned::Keyed, "${!P}"),
    (Assigned::Keyed, "\\\"$HOME/.config/P\\\""),
    (Assigned::Keyed, "\\$HOME/P/settings.json"),
    (Assigned::Keyed, "$HOME/Library/P/*.log"),
    (Assigned::Keyed, "$HOME/.cargo/bin:P"),
    (Assigned::Keyed, "P:$HOME/.local/bin"),
    (Assigned::Keyed, "$HOME/Library/Caches|P|default"),
    (Assigned::Keyed, "/Library/Caches/$P.plist"),
    (Assigned::Keyed, "${BUNDLE_NAME%.P}"),
    (Assigned::Keyed, "github.com/P"),
    (Assigned::Keyed, "github.com/acme/P/v2"),
    (Assigned::Keyed, "golang.org/x/P/v2"),
    (Assigned::Keyed, "//cdn.example.com/P"),
    (Assigned::Keyed, "//cdn.example.com/assets/P/app.js"),
    (Assigned::Keyed, "docs/<P>/notes.md"),
    (Assigned::Keyed, "docs/notes/<P>"),
    (Assigned::Keyed, ":!docs/P/notes.md"),
    (Assigned::Keyed, "docs/P/notes.md's"),
    (Assigned::Keyed, "2026-09-10-P.md"),
    (Assigned::Bare, "2026-09-10-P.md"),
];

/// how the token is written inside a position.
#[derive(Clone, Copy, Debug)]
enum Written {
    Plain,
    /// a backslash before every byte (`\a\b\c`).
    EachEscaped,
    /// a backslash before every other byte (`a\bc\d`).
    OtherEscaped,
}

fn written(token: &str, how: Written) -> String {
    let mut out = String::with_capacity(token.len() * 2);
    for (index, byte) in token.chars().enumerate() {
        let escaped = match how {
            Written::Plain => false,
            Written::EachEscaped => true,
            Written::OtherEscaped => index % 2 == 1,
        };
        if escaped {
            out.push('\\');
        }
        out.push(byte);
    }
    out
}

fn assigned(how: Assigned, value: &str) -> String {
    match how {
        Assigned::Keyed => format!("setting=\"{value}\"\n"),
        Assigned::Bare => format!("{value}\n"),
    }
}

/// the tier-3 finding and the exemption decisions of one scan of a line.
struct Surface {
    reported: bool,
    decisions: Vec<String>,
}

impl Surface {
    fn of(rule_ids: impl Iterator<Item = String>) -> Self {
        let mut surface = Surface {
            reported: false,
            decisions: Vec::new(),
        };
        for id in rule_ids {
            if id == RULE {
                surface.reported = true;
            } else if id.starts_with("exempt:") {
                surface.decisions.push(id);
            }
        }
        surface
    }
}

fn text_surface(line: &str) -> Surface {
    Surface::of(
        scan_text(line, &SCANNER, &TRACED)
            .into_iter()
            .map(|found| found.rule_id),
    )
}

fn file_surface(line: &str) -> Surface {
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
    Surface::of(
        scan(&[file], &SCANNER, &TRACED)
            .into_iter()
            .map(|found| found.rule_id),
    )
}

/// the file surface is scanned on one pass over the positions in this many, so every position has
/// its share: the text surface scans every token through the same steps, and the file scan
/// doubles the cost of a cell.
const FILE_SURFACE_STRIDE: usize = 10;

/// the outcome of one cell.
#[derive(Default)]
struct EngineTally {
    samples: usize,
    /// samples scanned on the file surface too.
    file_samples: usize,
    /// samples the rule reported on the text surface, and on the file surface where it was scanned.
    reported: usize,
    /// samples lost to a path-shape reading.
    lost: usize,
    /// samples whose token holds a `/`, and those of them a path reading claims.
    gap_samples: usize,
    gap_claimed: usize,
    /// decisions of other steps, which this cell does not judge, counted by step.
    other_steps: BTreeMap<String, usize>,
    failures: Vec<String>,
}

/// whether a path step claims the value on the text surface, or on the file surface when `file`,
/// or the rooted path check drops it before the layer runs, which leaves no decision to trace; the
/// surfaces scanned come back too.
fn claimed_as_path(assign: Assigned, value: &str, file: bool) -> (bool, Surface, Option<Surface>) {
    let line = assigned(assign, value);
    let text = text_surface(&line);
    let file = file.then(|| file_surface(&line));
    let claimed = |surface: &Surface| {
        surface
            .decisions
            .iter()
            .any(|decision| PATH_STEPS.contains(&decision.as_str()))
    };
    let lost =
        is_path_shaped(value.as_bytes()) || claimed(&text) || file.as_ref().is_some_and(claimed);
    (lost, text, file)
}

/// draws `ENGINE_SAMPLES` tokens of one alphabet, written one way, over every inside position. a
/// path step that claims one on a surface scanned (the file surface on every
/// `FILE_SURFACE_STRIDE`th pass), or the rooted path check dropping one, is a failure whether or
/// not the rule reports the token standing alone, where no path step reads it.
/// a token whose `/` cuts it into directories is the documented gap: it is counted, and it fails
/// only when the same token with `_` in place of each `/` is claimed too.
fn measure_inside(name: &str, alphabet: &[u8], how: Written, seed: u64) -> EngineTally {
    let mut rng = Rng::new(seed);
    let mut tally = EngineTally::default();
    while tally.samples < ENGINE_SAMPLES {
        let token = token(&mut rng, alphabet);
        let (assign, template) = INSIDE[tally.samples % INSIDE.len()];
        let scan_file = (tally.samples / INSIDE.len()).is_multiple_of(FILE_SURFACE_STRIDE);
        tally.samples += 1;
        tally.file_samples += usize::from(scan_file);
        let value = place(template, &written(&token, how));
        let (lost, text, file) = claimed_as_path(assign, &value, scan_file);
        tally.reported +=
            usize::from(text.reported && file.as_ref().is_none_or(|file| file.reported));
        let file_decisions = file.iter().flat_map(|file| &file.decisions);
        for decision in text.decisions.iter().chain(file_decisions) {
            if !PATH_STEPS.contains(&decision.as_str()) {
                *tally.other_steps.entry(decision.clone()).or_default() += 1;
            }
        }
        let gap = token.contains('/');
        tally.gap_samples += usize::from(gap);
        if !lost {
            continue;
        }
        if gap {
            tally.gap_claimed += 1;
            let joined = place(template, &written(&token.replace('/', "_"), how));
            if !claimed_as_path(assign, &joined, scan_file).0 {
                continue;
            }
        }
        tally.lost += 1;
        if tally.failures.len() < 20 {
            tally.failures.push(format!(
                "{name} {how:?} {template}: text {:?}, file {:?}, rooted path {}{}: {}",
                text.decisions,
                file.map(|file| file.decisions),
                is_path_shaped(value.as_bytes()),
                if gap { ", claimed with `_` too" } else { "" },
                masked(&value)
            ));
        }
    }
    tally
}

#[test]
fn tokens_inside_every_position_are_never_claimed_as_paths() {
    let alphabets: [(&str, &[u8]); 6] = [
        ("base62", BASE62),
        ("base64", BASE64),
        ("base64url", BASE64URL),
        ("hex", HEX),
        ("base32", BASE32),
        ("base36", BASE36),
    ];
    let cells: Vec<(&str, &[u8], Written)> =
        [Written::Plain, Written::EachEscaped, Written::OtherEscaped]
            .into_iter()
            .flat_map(|how| {
                alphabets
                    .iter()
                    .map(move |&(name, alphabet)| (name, alphabet, how))
            })
            .collect();
    let tallies: Vec<(String, EngineTally)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(index, &(name, alphabet, how))| {
                scope.spawn(move || {
                    (
                        format!("{name} {how:?}"),
                        measure_inside(name, alphabet, how, 0xA076_1D64_78BD_642F ^ index as u64),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("engine thread"))
            .collect()
    });
    let mut failures = Vec::new();
    for (cell, tally) in &tallies {
        eprintln!(
            "{cell}: {} samples ({} on the file surface too), {} reported on every surface \
             scanned, lost to a path reading {}; `/` gap: {} samples, {} claimed; other steps {:?}",
            tally.samples,
            tally.file_samples,
            tally.reported,
            tally.lost,
            tally.gap_samples,
            tally.gap_claimed,
            tally.other_steps
        );
        failures.extend(tally.failures.iter().cloned());
        // the `/` gap stays a rare reading of directory names, not a way through.
        assert!(
            tally.gap_claimed * 1_000_000 < tally.gap_samples.max(1) * WORD_SHAPED_PER_MILLION,
            "{cell}: {} of {} `/`-cut tokens claimed",
            tally.gap_claimed,
            tally.gap_samples
        );
    }
    assert!(
        failures.is_empty(),
        "tokens inside a position lost to a path reading:\n{}",
        failures.join("\n")
    );
}

/// member-chain samples per cell: one kind of member and one access operator, pooled over every
/// member position; a chain is a token cut into members, as the chunk cells cut theirs.
const MEMBER_SAMPLES: usize = 20_000;

/// a place for a member chain, `P` standing for it: references alone, where a member chain is a
/// template hole and no path, and a path around it, where a dotted name is read as the path read
/// it before the shell grammar.
const MEMBER_POSITIONS: &[&str] = &[
    "${P}",
    "{P}",
    "${P}${HOME}",
    "${HOME:-${P}}",
    "$(P)",
    "$(P)/objects/release",
    "${P}/settings.log",
    "{P}/logs/run.txt",
    "$HOME/.cache/${P}",
];

/// the kind of member a chain is made of.
#[derive(Clone, Copy)]
enum Member {
    /// two to four random words of the given length range, lowercase or capitals.
    Long(usize, usize, bool),
    /// a token of the alphabet cut every two to fourteen bytes, each member opening on a letter.
    Cut(&'static [u8]),
}

fn member_chain(rng: &mut Rng, member: Member) -> Vec<String> {
    match member {
        Member::Long(low, high, capitals) => loop {
            let letters: &[u8] = if capitals {
                &BASE62[..26]
            } else {
                &BASE62[26..52]
            };
            let members: Vec<String> = (0..2 + rng.below(3))
                .map(|_| {
                    (0..low + rng.below(high - low + 1))
                        .map(|_| char::from(letters[rng.below(26)]))
                        .collect()
                })
                .collect();
            if members.concat().len() >= 20 {
                return members;
            }
        },
        Member::Cut(alphabet) => {
            let token = token(rng, alphabet);
            let mut members = Vec::new();
            let mut at = 0;
            while at < token.len() {
                let width = (2 + rng.below(13)).min(token.len() - at);
                let mut piece = token.as_bytes()[at..at + width].to_vec();
                // a member is an identifier: its leading digits move to its end.
                let digits = piece
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
                piece.rotate_left(digits);
                members.push(String::from_utf8(piece).expect("ascii member"));
                at += width;
            }
            members
        }
    }
}

/// whether a path reading of the chain in the position was already the reading of a dotted name
/// in a path: `.` joins the members, and a path separator stands outside the reference. optional
/// chaining, a command opening on a member and references alone are never paths.
fn read_as_dotted_name(position: &str, access: &str) -> bool {
    access == "." && !position.starts_with("$(") && position.contains('/')
}

#[test]
fn member_chains_in_a_reference_are_never_claimed_as_paths() {
    let mut members: Vec<(String, Member)> = vec![
        ("lower 6-11".to_owned(), Member::Long(6, 11, false)),
        ("lower 12-19".to_owned(), Member::Long(12, 19, false)),
        ("capitals 6-11".to_owned(), Member::Long(6, 11, true)),
        ("capitals 12-19".to_owned(), Member::Long(12, 19, true)),
    ];
    for (name, alphabet) in [
        ("base62", BASE62),
        ("base64", BASE64),
        ("base64url", BASE64URL),
        ("hex", HEX),
        ("base32", BASE32),
        ("base36", BASE36),
    ] {
        members.push((format!("{name} cut"), Member::Cut(alphabet)));
    }
    let cells: Vec<(String, Member, &str)> = members
        .iter()
        .flat_map(|(name, member)| {
            ["?.", "."]
                .into_iter()
                .map(move |access| (format!("{name} {access}"), *member, access))
        })
        .collect();
    let tallies: Vec<(String, EngineTally, usize, usize)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(index, (cell, member, access))| {
                scope.spawn(move || {
                    let mut rng = Rng::new(0xC2B2_AE3D_27D4_EB4F ^ index as u64);
                    let mut tally = EngineTally::default();
                    let (mut dotted_samples, mut dotted_claimed) = (0, 0);
                    while tally.samples < MEMBER_SAMPLES {
                        let position = MEMBER_POSITIONS[tally.samples % MEMBER_POSITIONS.len()];
                        let scan_file = (tally.samples / MEMBER_POSITIONS.len())
                            .is_multiple_of(FILE_SURFACE_STRIDE);
                        tally.samples += 1;
                        tally.file_samples += usize::from(scan_file);
                        let chain = member_chain(&mut rng, *member).join(access);
                        let value = place(position, &chain);
                        let dotted = read_as_dotted_name(position, access);
                        dotted_samples += usize::from(dotted);
                        // a base64 member's `/` is a separator or an operator of its own: the
                        // `/` gap of the cells above, judged the same way.
                        let gap = chain.contains('/');
                        tally.gap_samples += usize::from(gap && !dotted);
                        if !claimed_as_path(Assigned::Keyed, &value, scan_file).0 {
                            continue;
                        }
                        if dotted {
                            dotted_claimed += 1;
                            continue;
                        }
                        if gap {
                            tally.gap_claimed += 1;
                            let joined = place(position, &chain.replace('/', "_"));
                            if !claimed_as_path(Assigned::Keyed, &joined, scan_file).0 {
                                continue;
                            }
                        }
                        tally.lost += 1;
                        if tally.failures.len() < 20 {
                            tally
                                .failures
                                .push(format!("{cell} {position}: {}", masked(&value)));
                        }
                    }
                    (cell.clone(), tally, dotted_samples, dotted_claimed)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("member thread"))
            .collect()
    });
    let mut failures = Vec::new();
    for (cell, tally, dotted_samples, dotted_claimed) in &tallies {
        eprintln!(
            "members {cell}: {} samples ({} on the file surface too), {} claimed as a path; `/` \
             gap: {} samples, {} claimed; dotted name in a path: {dotted_samples} samples, \
             {dotted_claimed} claimed",
            tally.samples, tally.file_samples, tally.lost, tally.gap_samples, tally.gap_claimed
        );
        failures.extend(tally.failures.iter().cloned());
        assert!(
            tally.gap_claimed * 1_000_000 < tally.gap_samples.max(1) * WORD_SHAPED_PER_MILLION,
            "{cell}: {} of {} `/`-cut chains claimed",
            tally.gap_claimed,
            tally.gap_samples
        );
    }
    assert!(
        failures.is_empty(),
        "member chains claimed as a path:\n{}",
        failures.join("\n")
    );
}

#[test]
fn bracket_ranges_control_escapes_and_positional_digits_are_bounded() {
    let mut rng = Rng::new(0x2545_F491_4F6C_DD1D);
    // a bracket of ranges within one class, as a character class is written, and the control
    // escapes of ansi-c quoting read as the syntax they are.
    for value in [
        "${bundle_display_name//[^a-zA-Z0-9]/}",
        "${bundle_display_name//[$'\\n\\r\\t']/}",
        "${bundle_display_name//[[:space:]]/}",
    ] {
        assert!(is_reference_rooted(value.as_bytes()), "{value}");
    }
    for _ in 0..1_000 {
        // more ranges than a character class needs, or ranges out of order or across classes,
        // carry letters no piece accounts for.
        let pair = |rng: &mut Rng| {
            let (first, last) = (BASE62[rng.below(62)], BASE62[rng.below(62)]);
            format!("{}-{}", char::from(first), char::from(last))
        };
        let ranges: String = (0..7).map(|_| pair(&mut rng)).collect::<Vec<_>>().join("/");
        let value = format!("${{bundle_display_name//[{ranges}]/}}");
        assert!(!is_reference_rooted(value.as_bytes()), "{}", masked(&value));
        let first = pair(&mut rng);
        let bytes = first.as_bytes();
        let ordered = bytes[0] < bytes[2]
            && (bytes[0].is_ascii_lowercase() == bytes[2].is_ascii_lowercase())
            && (bytes[0].is_ascii_digit() == bytes[2].is_ascii_digit());
        let value = format!("${{bundle_display_name//[{first}]/}}");
        assert_eq!(is_reference_rooted(value.as_bytes()), ordered, "{value}");
        // a letter a backslash escapes is a letter of the value, in a bracket, a plain or an
        // ansi-c quoted string alike.
        let letters: String = (0..20)
            .map(|_| format!("\\{}", char::from(BASE36[rng.below(26)])))
            .collect();
        for value in [
            format!("${{bundle_display_name//[{letters}]/}}"),
            format!("${{bundle_display_name//['{letters}']/}}"),
            format!("${{bundle_display_name//$'{letters}'/}}"),
        ] {
            assert!(!is_reference_rooted(value.as_bytes()), "{}", masked(&value));
        }
        // positional digits are numbers of the value.
        let digits: String = (0..20)
            .map(|_| char::from(b'0' + rng.below(10) as u8))
            .collect();
        let dollars: String = digits.chars().map(|digit| format!("${digit}")).collect();
        for value in [
            format!("$HOME/.config/${{{digits}}}/settings.json"),
            format!("$HOME/.config/{dollars}/settings.json"),
        ] {
            assert!(!is_reference_rooted(value.as_bytes()), "{}", masked(&value));
        }
    }
}
