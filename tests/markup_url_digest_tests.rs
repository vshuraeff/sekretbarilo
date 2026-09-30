//! markup elements, url wrappers, tag-pinned action references and labelled digest records at the
//! engine. the exemption layer reads through each wrapper to the value inside it; these tests show
//! that the wrapper is exempt when its value is a name, a url or a digest, and that an opaque value
//! inside it is reported wherever the same value on its own is. the payload is also placed inside
//! the positions the readers take apart as structure (an action's owner, repository, path and
//! branch word, a badge's label tail and relative target, a slug, a fragment, an email address, a
//! form list, tag names and later element texts), whole and cut into short groups.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::ops::Range;
use std::sync::LazyLock;

const RULE: &str = "generic-high-entropy-value";

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

static ALLOWLIST: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    build_allowlist(&ProjectConfig::default(), &load_default_rules().unwrap()).unwrap()
});

static TRACED: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist =
        build_allowlist(&ProjectConfig::default(), &load_default_rules().unwrap()).unwrap();
    allowlist.trace_exemptions = true;
    allowlist
});

/// data files of the kinds the shapes come from; none selects a source posture.
const PATHS: &[&str] = &[
    "myapp/Info.plist",
    "site/docs.html",
    ".github/workflows/ci.yml",
    "docs/guide.md",
    "go.sum.txt",
];

/// every printable ascii byte, `!` to `~`: the alphabet that carries markup, link and quote
/// syntax by chance.
const PRINTABLE: [u8; 94] = {
    let mut bytes = [0; 94];
    let mut index = 0;
    while index < bytes.len() {
        bytes[index] = b'!' + index as u8;
        index += 1;
    }
    bytes
};

const ALPHABETS: [(&str, &[u8]); 7] = [
    (
        "base62",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
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
    (
        "letters",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ),
    ("printable", &PRINTABLE),
];

/// tokens per alphabet and wrapper at the engine; the predicates behind each wrapper are sampled
/// at 1e5 per position in their own module tests.
const PER_ALPHABET: usize = 2_000;

/// xorshift64 over `alphabet`, so the suite stores no opaque value.
fn token(alphabet: &[u8], len: usize, state: &mut u64) -> String {
    (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            char::from(alphabet[(*state % alphabet.len() as u64) as usize])
        })
        .collect()
}

fn file(path: &str, line: &str) -> DiffFile {
    DiffFile {
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
    }
}

/// the default allowlist with the exemption layer switched off.
static LAYER_OFF: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let mut allowlist =
        build_allowlist(&ProjectConfig::default(), &load_default_rules().unwrap()).unwrap();
    allowlist.exemption_layer = false;
    allowlist
});

/// whether a finding of the tier-3 rule covers `value` inside `line` on the text surface.
fn reported(line: &str, value: &str) -> bool {
    reported_with(line, value, &ALLOWLIST)
}

fn reported_with(line: &str, value: &str, allowlist: &CompiledAllowlist) -> bool {
    let Some(start) = line.find(value) else {
        return false;
    };
    let end = start + value.len();
    scan_text(line, &SCANNER, allowlist)
        .iter()
        .any(|found| found.rule_id == RULE && found.range.start <= start && found.range.end >= end)
}

fn assert_exempt(line: &str, label: &str) {
    for path in PATHS {
        let findings = scan(&[file(path, line)], &SCANNER, &ALLOWLIST);
        assert!(findings.is_empty(), "{path}: {findings:?} :: {line}");
    }
    assert!(
        scan_text(line, &SCANNER, &ALLOWLIST).is_empty(),
        "text surface :: {line}"
    );
    let traced: Vec<String> = scan_text(line, &SCANNER, &TRACED)
        .into_iter()
        .map(|found| found.rule_id)
        .collect();
    assert!(
        traced.iter().any(|rule| rule == label),
        "expected {label}, traced {traced:?} :: {line}"
    );
}

#[test]
fn wrappers_around_names_urls_and_digests_are_exempt_by_their_step() {
    let digest = {
        let mut state = 0x2545_f491_4f6c_dd1d;
        let mut body = token(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            43,
            &mut state,
        );
        body.push('=');
        body
    };
    for (line, label) in [
        (
            "\t<string>com.example.widget.helper-tool</string>",
            "exempt:wordshape",
        ),
        ("                >{session_name}</code", "exempt:markdown"),
        (
            "                >{widget_session_name}</code",
            "exempt:path",
        ),
        (
            "- Bug reports: <https://github.example.internal/acme/widget/issues/new>",
            "exempt:url",
        ),
        (
            "custom: ['https://www.example.org/sponsors/widget.html?user=acme']",
            "exempt:url",
        ),
        (
            "[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)",
            "exempt:url",
        ),
        (
            "Signing identity: Apple Development: jane.appleseed@example.com (ABCDE12345)",
            "exempt:url",
        ),
        (
            "      - uses: acme-labs-internal/widget-release-publisher@v1",
            "exempt:pin",
        ),
        (
            "        uses: pypa/gh-action-pypi-publish@release/v1",
            "exempt:pin",
        ),
    ] {
        assert_exempt(line, label);
    }
    assert_exempt(
        &format!("example.com/widget v1.4.2 h1:{digest}"),
        "exempt:digest",
    );
    assert_exempt(&format!("integrity: sha256-{digest}"), "exempt:digest");
}

/// a wrapper never hides a token the engine reports on its own: for every random token reported
/// alone, in a capture of the same kind, the wrapped line reports it whenever the engine without
/// the exemption layer does (a printable token can change what the value grammar captures, which is
/// no decision of the layer). these are the wrappers the layer reads through, so the value it
/// evaluates is narrower than the capture; the email, tag and digest recognizers only answer yes or
/// no about the whole value, and their random-token cells live in the module tests.
#[test]
fn random_tokens_inside_wrappers_are_reported_wherever_they_are_reported_alone() {
    type Build = fn(&str) -> String;
    let cells: [(&str, Build, Build); 8] = [
        (
            "element text",
            |t| format!("\t<string>{t}</string>"),
            |t| format!("\t{t}"),
        ),
        (
            "key element",
            |t| format!("\t<key>{t}</key>"),
            |t| format!("\t{t}"),
        ),
        (
            "element residue",
            |t| format!("                >{t}</code"),
            |t| format!("                {t}"),
        ),
        (
            "url before a close tag",
            |t| {
                format!(
                    "  <url><loc>https://github.example.internal/acme/{t}</loc><lastmod>2026-09-01</lastmod></url>"
                )
            },
            |t| format!("  https://github.example.internal/acme/{t}"),
        ),
        (
            "flow item",
            |t| format!("custom: ['https://github.example.internal/acme/{t}']"),
            |t| format!("custom: https://github.example.internal/acme/{t}"),
        ),
        (
            "cut autolink",
            |t| format!("- Bug: <https://github.example.internal/acme/{t}>"),
            |t| format!("- Bug: https://github.example.internal/acme/{t}"),
        ),
        (
            "badge chain target",
            |t| {
                format!(
                    "[![CI](https://img.shields.io/badge/ci.svg)](https://github.example.internal/acme/{t})"
                )
            },
            |t| format!("see https://github.example.internal/acme/{t}"),
        ),
        (
            "badge chain relative target",
            |t| format!("[![License: MIT](https://img.shields.io/badge/mit.svg)]({t})"),
            |t| format!("License: {t}"),
        ),
    ];
    let mut state = 0x9e37_79b9_7f4a_7c15;
    for (position, wrapped, alone) in cells {
        for (alphabet, bytes) in ALPHABETS {
            let mut alone_reported = 0;
            let mut lost = 0;
            for index in 0..PER_ALPHABET {
                let value = token(bytes, 20 + index % 45, &mut state);
                if reported(&alone(&value), &value) {
                    alone_reported += 1;
                    let line = wrapped(&value);
                    if reported_with(&line, &value, &LAYER_OFF) && !reported(&line, &value) {
                        lost += 1;
                    }
                }
            }
            assert_eq!(
                lost, 0,
                "{position}, {alphabet}: {lost} of {alone_reported} reported tokens lost"
            );
        }
    }
}

/// a digest record is exempt only at the exact encoded length its label names: at any other length
/// the digest step never claims the record, which then meets the ordinary gates.
#[test]
fn random_tokens_in_digest_records_are_never_digests_off_the_exact_length() {
    let records = [
        "example.com/widget v1.4.2 h1:",
        "integrity: sha256-",
        "integrity: sha384-",
    ];
    let mut state = 0x6c07_8965_6c07_8965;
    for (alphabet, bytes) in ALPHABETS {
        for index in 0..PER_ALPHABET {
            let length = 20 + index % 45;
            if length == 44 || length == 64 {
                continue;
            }
            let value = token(bytes, length, &mut state);
            for record in records {
                let line = format!("{record}{value}");
                assert!(
                    scan_text(&line, &SCANNER, &TRACED)
                        .iter()
                        .all(|found| found.rule_id != "exempt:digest"),
                    "{alphabet}, length {length}, {record}"
                );
            }
        }
    }
}

// payload inside the positions the readers take apart.

/// payload samples per reader cell, spread over its positions and the encoded alphabets.
const POSITION_SAMPLES: usize = 100_000;

/// chunked samples per reader cell and chunk shape, spread over its positions, the separator
/// rotating through `_`, `-` and `.`.
const CHUNK_SAMPLES: usize = 20_000;

/// threads per cell, each with its own seed; fixed, so every machine draws the same samples.
const SHARDS: usize = 16;

const WORKFLOW: &str = ".github/workflows/ci.yml";
const README: &str = "docs/README.md";
const PLIST: &str = "myapp/Info.plist";
const SITEMAP: &str = "site/sitemap.xml";
const SETTINGS: &str = "config/settings.yml";
const GO_SUM: &str = "go.sum.txt";

const BASE36: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";

/// the encoded alphabets of the payload cells: base62, base64, base64url, hex, base32 and lowercase
/// base36.
fn encoded_alphabets() -> Vec<(&'static str, &'static [u8])> {
    let mut alphabets = ALPHABETS[..5].to_vec();
    alphabets.push(("base36", BASE36));
    alphabets
}

/// xorshift64, seeded per shard.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

/// the chunk shapes: four-byte letter-digit groups (`a9a9`), letter groups of two to five, and
/// letter-digit groups of two or three (`a9a`, `9a`), the mix a form list admits once.
#[derive(Clone, Copy)]
enum Chunks {
    LetterDigit,
    Letters,
    ShortMixes,
}

impl Chunks {
    fn name(self) -> &'static str {
        match self {
            Self::LetterDigit => "a9a9 groups",
            Self::Letters => "2-5 letter groups",
            Self::ShortMixes => "2-3 byte letter-digit groups",
        }
    }

    fn group(self, rng: &mut Rng) -> String {
        match self {
            Self::LetterDigit => (0..4)
                .map(|index| {
                    let alphabet = if index % 2 == 0 { LOWER } else { DIGITS };
                    char::from(alphabet[rng.below(alphabet.len())])
                })
                .collect(),
            Self::Letters => {
                let len = 2 + rng.below(4);
                rng.string(LOWER, len)
            }
            Self::ShortMixes => {
                let len = 2 + rng.below(2);
                let first = rng.below(2);
                (0..len)
                    .map(|index| {
                        let alphabet = if (index + first).is_multiple_of(2) {
                            LOWER
                        } else {
                            DIGITS
                        };
                        char::from(alphabet[rng.below(alphabet.len())])
                    })
                    .collect()
            }
        }
    }

    /// groups joined by `separator` until they carry `content` bytes of letters and digits.
    fn value(self, rng: &mut Rng, separator: char, content: usize) -> String {
        let mut groups = Vec::new();
        let mut carried = 0;
        while carried < content {
            let group = self.group(rng);
            carried += group.len();
            groups.push(group);
        }
        groups.join(&separator.to_string())
    }
}

/// a line with the byte ranges of the payload pieces placed in it.
struct Placed {
    line: String,
    spans: Vec<Range<usize>>,
}

impl Placed {
    fn new(text: &str) -> Self {
        Self {
            line: text.to_owned(),
            spans: Vec::new(),
        }
    }

    fn text(mut self, text: &str) -> Self {
        self.line.push_str(text);
        self
    }

    fn payload(mut self, payload: &str) -> Self {
        let start = self.line.len();
        self.line.push_str(payload);
        self.spans.push(start..self.line.len());
        self
    }
}

/// the pieces of `value` of at most `width` bytes.
fn cut(value: &str, width: usize) -> Vec<&str> {
    (0..value.len())
        .step_by(width)
        .map(|start| &value[start..value.len().min(start + width)])
        .collect()
}

/// one reader position: where the payload goes, the file it is scanned in on the diff surface, and
/// the text in front of the same payload standing alone, in the capture context of the position.
struct Position {
    name: &'static str,
    path: &'static str,
    place: fn(&str) -> Placed,
    alone: &'static str,
    /// the encoded length a labelled digest record claims: a drop at that length is the digest
    /// step's documented cost, counted apart.
    exact_length: Option<usize>,
    /// the payload stands in a url path, where a `/` of the token cuts it into path segments that
    /// the url step reads by its own segment rule, which predates these readers. such a drop is
    /// counted apart, and the same token with `_` for `/` must not be dropped.
    slash_gap: bool,
}

fn position(
    name: &'static str,
    path: &'static str,
    place: fn(&str) -> Placed,
    alone: &'static str,
) -> Position {
    Position {
        name,
        path,
        place,
        alone,
        exact_length: None,
        slash_gap: false,
    }
}

/// one cell per reader: the positions it takes apart, and the chunk shapes cut to fit it.
struct Reader {
    name: &'static str,
    positions: Vec<Position>,
    chunks: &'static [Chunks],
}

const CHUNKS: &[Chunks] = &[Chunks::LetterDigit, Chunks::Letters];

fn readers() -> Vec<Reader> {
    let mut positions = reader_positions().into_iter();
    let mut take = |count: usize| positions.by_ref().take(count).collect::<Vec<_>>();
    vec![
        Reader {
            name: "action reference names",
            positions: take(5),
            chunks: CHUNKS,
        },
        Reader {
            name: "badge chain relative target and label tail",
            positions: take(4),
            chunks: CHUNKS,
        },
        Reader {
            name: "url slug and fragment",
            positions: take(2),
            chunks: CHUNKS,
        },
        Reader {
            name: "autolink and flow item",
            positions: take(2),
            chunks: CHUNKS,
        },
        // a form list read letter words before the letter-digit mix was admitted, so letter groups
        // are no new reading there; the mixes are.
        Reader {
            name: "form list",
            positions: take(1),
            chunks: &[Chunks::LetterDigit, Chunks::ShortMixes],
        },
        Reader {
            name: "email address",
            positions: take(2),
            chunks: CHUNKS,
        },
        Reader {
            name: "markup element",
            positions: take(6),
            chunks: CHUNKS,
        },
        // `_`, `-` and `.` are outside the base64 alphabet a digest record holds.
        Reader {
            name: "labelled digest record",
            positions: take(4),
            chunks: &[],
        },
    ]
}

fn reader_positions() -> Vec<Position> {
    vec![
        position(
            "action repository",
            WORKFLOW,
            |t| Placed::new("      - uses: acme/").payload(t).text("@v1"),
            "      - uses: ",
        ),
        position(
            "action owner",
            WORKFLOW,
            |t| Placed::new("      - uses: ").payload(t).text("/widget@v4"),
            "      - uses: ",
        ),
        position(
            "action path",
            WORKFLOW,
            |t| {
                Placed::new("      - uses: acme/widget/")
                    .payload(t)
                    .text("@v3.2.1")
            },
            "      - uses: ",
        ),
        position(
            "action on a release branch",
            WORKFLOW,
            |t| {
                Placed::new("      - uses: acme/")
                    .payload(t)
                    .text("@release/v1")
            },
            "      - uses: ",
        ),
        position(
            "action names and branch word",
            WORKFLOW,
            |t| {
                let pieces = cut(t, 12);
                let (last, names) = pieces.split_last().expect("a payload");
                let mut placed = Placed::new("      - uses: ");
                for (index, name) in names.iter().enumerate() {
                    if index > 0 {
                        placed = placed.text("/");
                    }
                    placed = placed.payload(name);
                }
                match names.len() {
                    0 => placed.payload(last).text("/widget@v1"),
                    1 => placed.text("/").payload(last).text("@v1"),
                    _ => placed.text("@").payload(last).text("/v1"),
                }
            },
            "      - uses: ",
        ),
        position(
            "badge relative leaf",
            README,
            |t| {
                Placed::new("[![License: MIT](https://img.example.org/badge.svg)](docs/")
                    .payload(t)
                    .text(")")
            },
            "License: ",
        ),
        position(
            "badge relative directories",
            README,
            |t| {
                let mut placed =
                    Placed::new("[![License: MIT](https://img.example.org/badge.svg)](docs/");
                for piece in cut(t, 5) {
                    placed = placed.payload(piece).text("/");
                }
                placed.text("guide.md)")
            },
            "License: ",
        ),
        position(
            "badge relative fragment",
            README,
            |t| {
                Placed::new("[![License: MIT](https://img.example.org/badge.svg)](docs/guide.md#")
                    .payload(t)
                    .text(")")
            },
            "License: ",
        ),
        position(
            "badge label tail and relative leaf",
            README,
            |t| {
                let split = t.len().min(19);
                Placed::new("[![License: ")
                    .payload(&t[..split])
                    .text("](https://img.example.org/badge.svg)](docs/")
                    .payload(&t[split..])
                    .text(")")
            },
            "License: ",
        ),
        Position {
            slash_gap: true,
            ..position(
                "url path slug",
                README,
                |t| Placed::new("url: https://docs.example.org/blog/").payload(t),
                "url: ",
            )
        },
        position(
            "url fragment",
            README,
            |t| Placed::new("url: https://docs.example.org/guide.md#").payload(t),
            "url: ",
        ),
        position(
            "cut autolink",
            README,
            |t| {
                Placed::new("- Bug: <https://github.example.internal/acme/")
                    .payload(t)
                    .text(">")
            },
            "- Bug: https://github.example.internal/acme/",
        ),
        position(
            "flow item",
            SETTINGS,
            |t| {
                Placed::new("custom: ['https://github.example.internal/acme/")
                    .payload(t)
                    .text("']")
            },
            "custom: https://github.example.internal/acme/",
        ),
        position(
            "form list field",
            PLIST,
            |t| {
                Placed::new("fonts: https://fonts.example.internal/css2?family=")
                    .payload(t)
                    .text("+Mono")
            },
            "fonts: ",
        ),
        position(
            "email local part",
            SETTINGS,
            |t| Placed::new("contact: ").payload(t).text("@example.com"),
            "contact: ",
        ),
        position(
            "email host label",
            SETTINGS,
            |t| {
                Placed::new("contact: jane@")
                    .payload(t)
                    .text(".example.com")
            },
            "contact: ",
        ),
        position(
            "element text",
            PLIST,
            |t| Placed::new("\t<string>").payload(t).text("</string>"),
            "\t",
        ),
        position(
            "element texts",
            PLIST,
            |t| {
                let mut placed = Placed::new("\t");
                for (index, piece) in cut(t, 16).into_iter().enumerate() {
                    let tag = ["key", "string", "date"][index % 3];
                    placed = placed
                        .text(&format!("<{tag}>"))
                        .payload(piece)
                        .text(&format!("</{tag}>"));
                }
                placed
            },
            "\t",
        ),
        position(
            "tag names",
            PLIST,
            |t| {
                let names = cut(t, 19);
                let mut placed = Placed::new("\t");
                for name in &names {
                    placed = placed.text("<").payload(name).text(">");
                }
                placed = placed.text("widget");
                for name in names.iter().rev() {
                    placed = placed.text("</").payload(name).text(">");
                }
                placed
            },
            "\t",
        ),
        position(
            "element residue",
            PLIST,
            |t| Placed::new("                >").payload(t).text("</code"),
            "                ",
        ),
        position(
            "url before a close tag",
            SITEMAP,
            |t| {
                Placed::new("    https://github.example.internal/acme/")
                    .payload(t)
                    .text("</loc>")
            },
            "    https://github.example.internal/acme/",
        ),
        // texts too long to drop leave the value whole, which the url step then reads as a url
        // whose path runs on through the markup after it.
        Position {
            slash_gap: true,
            ..position(
                "element texts after a url",
                SITEMAP,
                |t| {
                    let mut placed =
                        Placed::new("    https://github.example.internal/acme/guide</loc>");
                    for piece in cut(t, 16) {
                        placed = placed.text("<lastmod>").payload(piece).text("</lastmod>");
                    }
                    placed.text("</url>")
                },
                "\t",
            )
        },
        Position {
            exact_length: Some(44),
            ..position(
                "go.sum h1 digest",
                GO_SUM,
                |t| Placed::new("example.com/widget v1.4.2 h1:").payload(t),
                "token: ",
            )
        },
        Position {
            exact_length: Some(44),
            ..position(
                "sri sha256 digest",
                SETTINGS,
                |t| Placed::new("integrity: sha256-").payload(t),
                "token: ",
            )
        },
        Position {
            exact_length: Some(64),
            ..position(
                "sri sha384 digest",
                SETTINGS,
                |t| Placed::new("integrity: sha384-").payload(t),
                "token: ",
            )
        },
        Position {
            exact_length: Some(88),
            ..position(
                "sri sha512 digest",
                SETTINGS,
                |t| Placed::new("integrity: sha512-").payload(t),
                "token: ",
            )
        },
    ]
}

/// the byte ranges of the tier-3 findings of `line` on the text surface.
fn text_findings(line: &str, allowlist: &CompiledAllowlist) -> Vec<Range<usize>> {
    scan_text(line, &SCANNER, allowlist)
        .into_iter()
        .filter(|found| found.rule_id == RULE)
        .map(|found| found.range)
        .collect()
}

/// the byte ranges of the tier-3 findings of `line` on the diff surface, where a finding carries its
/// matched bytes rather than a range: every place those bytes stand in the line.
fn file_findings(line: &str, path: &str, allowlist: &CompiledAllowlist) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut ranges = Vec::new();
    for finding in scan(&[file(path, line)], &SCANNER, allowlist) {
        let value = &finding.matched_value;
        if finding.rule_id != RULE || value.is_empty() || value.len() > bytes.len() {
            continue;
        }
        for start in 0..=bytes.len() - value.len() {
            if &bytes[start..start + value.len()] == value.as_slice() {
                ranges.push(start..start + value.len());
            }
        }
    }
    ranges
}

/// whether the findings cover every payload byte.
fn covers(findings: &[Range<usize>], spans: &[Range<usize>]) -> bool {
    spans.iter().all(|span| {
        span.clone()
            .all(|index| findings.iter().any(|found| found.contains(&index)))
    })
}

/// what the engine made of one payload in one position.
enum Outcome {
    /// the payload standing alone is not reported, so its position decides nothing.
    NotAlone,
    Kept,
    /// dropped in position, with the exemption labels the traced engine gives the line.
    Lost(Vec<String>),
}

/// a payload counts only when the engine reports it standing alone; it is lost when the engine
/// without the exemption layer reports it in position on a surface where the layered engine does
/// not, so what the value grammar cuts differently is no decision of the layer.
fn judge(position: &Position, payload: &str) -> Outcome {
    let alone = format!("{}{payload}", position.alone);
    let alone_span = position.alone.len()..alone.len();
    if !covers(&text_findings(&alone, &ALLOWLIST), &[alone_span]) {
        return Outcome::NotAlone;
    }
    let placed = (position.place)(payload);
    let text = covers(&text_findings(&placed.line, &ALLOWLIST), &placed.spans);
    let diff = covers(
        &file_findings(&placed.line, position.path, &ALLOWLIST),
        &placed.spans,
    );
    let dropped = (!text && covers(&text_findings(&placed.line, &LAYER_OFF), &placed.spans))
        || (!diff
            && covers(
                &file_findings(&placed.line, position.path, &LAYER_OFF),
                &placed.spans,
            ));
    if !dropped {
        return Outcome::Kept;
    }
    Outcome::Lost(
        scan_text(&placed.line, &SCANNER, &TRACED)
            .into_iter()
            .map(|found| found.rule_id)
            .collect(),
    )
}

/// the counts of one position within a cell.
#[derive(Default)]
struct Tally {
    samples: usize,
    alone: usize,
    lost: usize,
    /// payloads that open the value with `//`, which makes the value a url of its own.
    url_opening: usize,
    /// drops of payloads whose `/` cuts a url path, and of those at a digest's exact length.
    slash_gap: usize,
    exact_length: usize,
    failures: Vec<String>,
}

impl Tally {
    fn add(&mut self, other: Self) {
        self.samples += other.samples;
        self.alone += other.alone;
        self.lost += other.lost;
        self.url_opening += other.url_opening;
        self.slash_gap += other.slash_gap;
        self.exact_length += other.exact_length;
        self.failures.extend(other.failures);
    }
}

/// places `samples` payloads drawn by `draw` in the reader's positions in turn, over `SHARDS`
/// threads, and returns one tally per position. a drop is a failure unless it is a documented cost:
/// a digest record at its exact encoded length, or a `/` gap whose token is kept once `_` stands
/// for its `/`. failures name the position, the draw, the length and the exemption labels, never
/// the payload.
fn run_cell(
    reader: &Reader,
    seed: u64,
    samples: usize,
    draw: impl Fn(&mut Rng) -> (String, &'static str) + Sync,
) -> Vec<Tally> {
    let per_shard = samples.div_ceil(SHARDS);
    let positions = &reader.positions;
    let parts: Vec<Vec<Tally>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..SHARDS as u64)
            .map(|shard| {
                let draw = &draw;
                scope.spawn(move || {
                    let mut rng = Rng(seed ^ (shard + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
                    let mut tallies: Vec<Tally> =
                        positions.iter().map(|_| Tally::default()).collect();
                    for sample in 0..per_shard {
                        let index = sample % positions.len();
                        let (position, tally) = (&positions[index], &mut tallies[index]);
                        let (payload, label) = draw(&mut rng);
                        tally.samples += 1;
                        if payload.starts_with("//") {
                            tally.url_opening += 1;
                            continue;
                        }
                        let labels = match judge(position, &payload) {
                            Outcome::NotAlone => continue,
                            Outcome::Kept => {
                                tally.alone += 1;
                                continue;
                            }
                            Outcome::Lost(labels) => {
                                tally.alone += 1;
                                labels
                            }
                        };
                        if position.exact_length == Some(payload.len()) {
                            tally.exact_length += 1;
                            continue;
                        }
                        if position.slash_gap && payload.contains('/') {
                            tally.slash_gap += 1;
                            if !matches!(
                                judge(position, &payload.replace('/', "_")),
                                Outcome::Lost(_)
                            ) {
                                continue;
                            }
                        }
                        tally.lost += 1;
                        if tally.failures.len() < 5 {
                            tally.failures.push(format!(
                                "{}, {label}, {} bytes, traced {labels:?}",
                                position.name,
                                payload.len()
                            ));
                        }
                    }
                    tallies
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("monte-carlo shard"))
            .collect()
    });
    let mut totals: Vec<Tally> = positions.iter().map(|_| Tally::default()).collect();
    for part in parts {
        for (total, tally) in totals.iter_mut().zip(part) {
            total.add(tally);
        }
    }
    totals
}

/// prints a cell's tallies and collects its failures.
fn report(reader: &Reader, cell: &str, tallies: Vec<Tally>, failures: &mut Vec<String>) {
    for (position, tally) in reader.positions.iter().zip(tallies) {
        eprintln!(
            "{} / {} / {cell}: {} samples, {} reported alone, {} lost, {} `/` gap, {} exact \
             digest length, {} opening with `//`",
            reader.name,
            position.name,
            tally.samples,
            tally.alone,
            tally.lost,
            tally.slash_gap,
            tally.exact_length,
            tally.url_opening
        );
        if tally.lost > 0 {
            failures.push(format!(
                "{} / {cell}: {} of {} lost: {:?}",
                position.name, tally.lost, tally.alone, tally.failures
            ));
        }
    }
}

/// a random token of 20 to 64 bytes from the encoded alphabets, placed whole inside every position
/// of every reader: no position drops a token the engine reports on its own, on the text surface
/// or the diff surface. the documented costs are counted apart, never judged: a labelled digest
/// record of the exact encoded length its algorithm names, and a base64 `/` that cuts a url path
/// into the short segments the url step accepts by the rule that predates these readers (the same
/// token with `_` for its `/` must stay reported). a base64 token opening the value with `//`
/// makes the value a url of its own and is skipped.
#[test]
fn random_tokens_inside_reader_positions_are_reported_wherever_they_are_reported_alone() {
    let alphabets = encoded_alphabets();
    let mut failures = Vec::new();
    for (index, reader) in readers().iter().enumerate() {
        let tallies = run_cell(
            reader,
            0x5851_f42d_4c95_7f2d ^ index as u64,
            POSITION_SAMPLES,
            |rng| {
                let (name, alphabet) = alphabets[rng.below(alphabets.len())];
                let len = 20 + rng.below(45);
                (rng.string(alphabet, len), name)
            },
        );
        report(reader, "whole token", tallies, &mut failures);
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// a token cut into short groups, four-byte letter-digit groups or letter groups of two to five,
/// joined by `_`, `-` or `.`, inside every position of every reader: the aggregate chunk guard
/// keeps each reader from reading the groups as names, words, slugs, addresses or element parts.
/// a form list is cut into the letter-digit groups of two or three bytes it now admits once.
#[test]
fn chunked_tokens_inside_reader_positions_are_reported_wherever_they_are_reported_alone() {
    let mut failures = Vec::new();
    for (index, reader) in readers().iter().enumerate() {
        for &chunks in reader.chunks {
            let tallies = run_cell(
                reader,
                0x2545_f491_4f6c_dd1d ^ (index as u64) << 8 ^ chunks as u64,
                CHUNK_SAMPLES,
                |rng| {
                    let separator = ['_', '-', '.'][rng.below(3)];
                    let content = 20 + rng.below(45);
                    (chunks.value(rng, separator, content), chunks.name())
                },
            );
            report(reader, chunks.name(), tallies, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// the two consumers of the reference-name reading, with a token cut into ten four-byte
/// letter-digit groups (and into letter groups) in the repository of a tag-pinned action and in the
/// leaf of a badge's relative target: both surfaces report it and the redaction masks it. a benign
/// directory in front of the leaf (`docs/`) does not vouch for it.
#[test]
fn chunked_reference_names_are_reported_and_redacted() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut checked = 0;
    for separator in ['_', '-', '.'] {
        for chunks in [Chunks::LetterDigit, Chunks::Letters] {
            for _ in 0..40 {
                let value = match chunks {
                    Chunks::LetterDigit => (0..10)
                        .map(|_| chunks.group(&mut rng))
                        .collect::<Vec<_>>()
                        .join(&separator.to_string()),
                    _ => chunks.value(&mut rng, separator, 32),
                };
                for (line, path) in [
                    (format!("      - uses: acme/{value}@v1"), WORKFLOW),
                    (
                        format!("MIT](https://img.example.org/badge.svg)](docs/{value}"),
                        README,
                    ),
                    (
                        format!(
                            "[![License: MIT](https://img.example.org/badge.svg)](docs/{value})"
                        ),
                        README,
                    ),
                ] {
                    // a letter-group value can fall below the entropy gate on its own; the
                    // reviewer's letter-digit shape never does and is checked unconditionally.
                    if matches!(chunks, Chunks::Letters)
                        && !reported_with(&line, &value, &LAYER_OFF)
                    {
                        continue;
                    }
                    checked += 1;
                    assert!(
                        reported(&line, &value),
                        "text surface, {} joined by {separator:?}, {path}",
                        chunks.name()
                    );
                    let carried =
                        scan(&[file(path, &line)], &SCANNER, &ALLOWLIST)
                            .iter()
                            .any(|found| {
                                found.rule_id == RULE
                                    && found
                                        .matched_value
                                        .windows(value.len())
                                        .any(|window| window == value.as_bytes())
                            });
                    assert!(
                        carried,
                        "diff surface, {} joined by {separator:?}, {path}",
                        chunks.name()
                    );
                    let redacted = redact_text(&line, &SCANNER, &ALLOWLIST);
                    assert!(
                        redacted != line && !redacted.contains(&value),
                        "redaction, {} joined by {separator:?}, {path}",
                        chunks.name()
                    );
                }
            }
        }
    }
    assert!(checked >= 500, "only {checked} twins checked");
}
