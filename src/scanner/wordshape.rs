// word-structure recognition for exemption-layer filtering

use super::entropy::MIN_ENTROPY_LENGTH;

// com is the common domain abbreviation; wui abbreviates web user interface; ctl abbreviates
// control, the suffix of a control tool's name (`sysctl`).
const SHORT_WORDS: &str = "id ids db io os ui ux ip by to of in at is on or if no go do up as an it my we api url uri get set add del new key val var str int num max min sum avg len idx src dst dir cfg env tmp log err msg cmd arg obj ptr ref res req ctx mod lib bin dev app web css js ts py rs md sh txt xml yml row col tab div img btn nav pos end run map fn mut pub use let for and not all any one two out off low top fs tcp udp dns tls ssl ssh git npm pip cli gui sql orm jwt uid gid pid sec ms ns kb mb gb hz ok com wui ctl";

struct Word<'a> {
    bytes: &'a [u8],
    start: usize,
}

fn checked_value(value: &[u8]) -> Option<&[u8]> {
    let value = trim_delimiter(value);
    has_word_bytes_only(value).then_some(value)
}

fn trim_delimiter(value: &[u8]) -> &[u8] {
    match value.last() {
        Some(b',' | b';') => &value[..value.len() - 1],
        _ => value,
    }
}

fn has_word_bytes_only(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || is_separator(byte))
        && !value.windows(3).any(|bytes| bytes == b"://")
}

/// items of a search-pattern alternation such as `^(word-a|word_b|ID-42)$`: at least two
/// `|`-joined items, optionally inside one `(` or `(?:` group, with `^`, `$`, `\b` and
/// string-escaped `\\b` anchors stripped around the value and around each item. every item must
/// be a non-empty run of word bytes, so an escaped `\|`, an empty item, a nested group or any
/// other regex syntax rejects the whole value.
fn alternation_items(value: &[u8]) -> Option<Vec<&[u8]>> {
    let value = strip_anchors(trim_delimiter(value));
    let value = value
        .strip_prefix(b"(?:")
        .or_else(|| value.strip_prefix(b"("))
        .and_then(|inner| inner.strip_suffix(b")"))
        .unwrap_or(value);
    let items: Vec<&[u8]> = value
        .split(|&byte| byte == b'|')
        .map(strip_anchors)
        .collect();
    (items.len() >= 2
        && items
            .iter()
            .all(|item| !item.is_empty() && has_word_bytes_only(item)))
    .then_some(items)
}

/// an item below the entropy minimum is harmless when it reads as a short id, with a digit or both
/// cases, or as words; a single-case letter run with no vowel or five consonants in a row is
/// neither, so a pipe inserted into such a token does not split it into harmless items.
fn is_short_item_structured(item: &[u8]) -> bool {
    item.iter().any(u8::is_ascii_digit)
        || (item.iter().any(u8::is_ascii_uppercase) && item.iter().any(u8::is_ascii_lowercase))
        || words(item)
            .iter()
            .all(|word| word.bytes.len() < 4 || has_wordlike_vowels(word.bytes))
}

fn strip_anchors(mut value: &[u8]) -> &[u8] {
    while let Some(rest) = value
        .strip_prefix(b"^")
        .or_else(|| value.strip_prefix(br"\\b"))
        .or_else(|| value.strip_prefix(br"\b"))
        .or_else(|| value.strip_suffix(b"$"))
        .or_else(|| value.strip_suffix(br"\\b"))
        .or_else(|| value.strip_suffix(br"\b"))
    {
        value = rest;
    }
    value
}

fn is_separator(byte: u8) -> bool {
    matches!(byte, b'.' | b'-' | b'_' | b'/' | b':')
}

fn is_lowercase_word(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_lowercase)
}

fn is_capitalized_word(bytes: &[u8]) -> bool {
    bytes[0].is_ascii_uppercase() && bytes[1..].iter().all(u8::is_ascii_lowercase)
}

pub(crate) fn has_wordlike_vowels(bytes: &[u8]) -> bool {
    let mut has_vowel = false;
    let mut consonants = 0;
    for byte in bytes {
        if matches!(
            byte.to_ascii_lowercase(),
            b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
        ) {
            has_vowel = true;
            consonants = 0;
        } else {
            consonants += 1;
            if consonants > 4 {
                return false;
            }
        }
    }
    has_vowel
}

/// judges a path piece, a run of ascii letters and digits between separators, as words or a short
/// number rather than an opaque chunk. it is shorter than the entropy minimum, holds at most one
/// digit run of at most four digits, has no two letter words under three letters side by side, and
/// every letter word of five or more letters has a vowel and no run of five consonants unless it is
/// an acronym of at most five capitals. `Library`, `HTTPStorages`, `python3`, `x86` and `k8s` pass;
/// a letter-digit alternation such as `q8Vn3sY6`, a mixed-case run of short words such as `KpZrTw`
/// and a consonant run such as `dozkvgrcnyjufqbm` do not. `None` rejects the piece; an accepted
/// piece reports its letter words, so a caller can bound the vowel-less four-letter words
/// (`html`, `xlsx`) it admits and ask for real words where the value has no other structure. a
/// word that fails the vowel rule only where a vowel-less vocabulary word joins it (`launchctl`)
/// is rejected as well: without a dictionary the word it joins is any random run that passes the
/// vowel rule, so a token cut into such pieces would read as words.
pub(crate) fn wordlike_piece(piece: &[u8]) -> Option<PieceWords> {
    if piece.is_empty()
        || piece.len() >= MIN_ENTROPY_LENGTH
        || !piece.iter().all(u8::is_ascii_alphanumeric)
    {
        return None;
    }
    let mut counts = PieceWords::default();
    let mut digit_runs = 0;
    let mut previous_short = false;
    for word in words(piece) {
        let bytes = word.bytes;
        if bytes[0].is_ascii_digit() {
            digit_runs += 1;
            if digit_runs > 1 || bytes.len() > 4 {
                return None;
            }
            previous_short = false;
            counts.numbers += 1;
        } else if bytes.len() < 4 {
            if bytes.len() < 3 && previous_short {
                return None;
            }
            previous_short = bytes.len() < 3;
            counts.short += 1;
            counts.known += usize::from(is_known_short_word(bytes));
        } else {
            previous_short = false;
            let acronym = bytes.len() <= 5 && bytes.iter().all(u8::is_ascii_uppercase);
            if acronym || has_wordlike_vowels(bytes) {
                counts.long += 1;
            } else if bytes.len() == 4 {
                counts.vowelless += 1;
            } else {
                return None;
            }
        }
    }
    Some(counts)
}

/// the letter words and digit runs of a piece `wordlike_piece` accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PieceWords {
    /// words of four or more letters that read as words, acronyms included.
    pub(crate) long: usize,
    /// words of one to three letters.
    pub(crate) short: usize,
    /// the short words that belong to the short-word vocabulary (`bin`, `log`, `id`); a subset of
    /// `short`.
    pub(crate) known: usize,
    /// four-letter words that carry no vowel, acronyms aside (`html`, `xlsx`).
    pub(crate) vowelless: usize,
    /// runs of digits (`2026`, the `2` of `v2`).
    pub(crate) numbers: usize,
}

impl PieceWords {
    pub(crate) fn add(&mut self, other: Self) {
        self.long += other.long;
        self.short += other.short;
        self.known += other.known;
        self.vowelless += other.vowelless;
        self.numbers += other.numbers;
    }

    /// whether the words of a whole value outweigh its opaque-looking pieces: at most one vowel-less
    /// four-letter word, at least two long words, and no fewer long words than short words outside
    /// the vocabulary plus every run of digits after the first. short random chunks joined by
    /// separators are short words outside the vocabulary, so they outnumber the words of the path
    /// that carries them.
    pub(crate) fn outweigh_short_pieces(&self) -> bool {
        self.vowelless <= 1
            && self.long >= 2
            && self.long >= self.short - self.known + self.numbers.saturating_sub(1)
    }
}

/// the widest group a chunked value is cut into: a proquint, a grouped recovery or license code, a
/// random value split every two to five letters.
const CHUNK_WIDTH: usize = 5;

/// the fewest groups, and the fewest letters in them, that a value of `MIN_ENTROPY_LENGTH` bytes
/// cut into groups of at most `CHUNK_WIDTH` letters by one-byte separators carries: four groups of
/// five letters, or seven of two.
const MIN_CHUNKS: usize = 4;
const MIN_CHUNK_LETTERS: usize = 14;

/// whether a value is cut into short groups: at least `MIN_CHUNKS` letter words of at most
/// `CHUNK_WIDTH` letters in a row, carrying at least `MIN_CHUNK_LETTERS` letters, read across the
/// value's separators and camel-case humps. a word of the short-word vocabulary (`com`, `app`) is
/// passed over, neither a group nor the end of a run. digit runs also preserve accumulated groups,
/// so adding digits to each short word cannot hide a chunked value. a longer letter word and
/// every byte of `run_breaks` end the run. an opaque value of 20 or more bytes cut every two to five
/// letters shows such a run whatever its alphabet, pronounceable groups included, while the words
/// of a path or an identifier vary in length (`agentCoreTests`, `oh-my-pi`, `app.min.js.map`,
/// `com.apple.dock.plist` stay clear). a path passes `/` and `\` as `run_breaks`, so short directory
/// names in a row (`$HOME/code/work/repo`) stay a path; a value cut by `/` is not recognized.
pub(crate) fn is_chunked(value: &[u8], run_breaks: &[u8]) -> bool {
    has_chunk_run(value, run_breaks, false)
}

/// `is_chunked`, with each run of at most `CHUNK_WIDTH` digits counted as a group of its own and
/// its digits as letters, so a token whose chunks carry digits (`ab12`, `c7de`) cannot fall below
/// `MIN_CHUNK_LETTERS` by trading letters for digits, and with the two-letter vocabulary words
/// (`id`, `os`, `to`) counted as groups too: about one pair of random letters in seventeen is one,
/// so a token cut every two letters would otherwise hide enough of its groups to stay below the
/// run. the three-letter vocabulary words are still passed over (`com.apple.dock.plist`). the shapes
/// that join items by entries, placeholders, escapes and alternation groups use it; a longer digit
/// run ends the run of groups.
pub(crate) fn is_chunked_with_digits(value: &[u8], run_breaks: &[u8]) -> bool {
    has_chunk_run(value, run_breaks, true)
}

fn has_chunk_run(value: &[u8], run_breaks: &[u8], count_digits: bool) -> bool {
    for segment in value.split(|byte| run_breaks.contains(byte)) {
        let (mut groups, mut letters) = (0, 0);
        for piece in segment
            .split(|byte| !byte.is_ascii_alphanumeric())
            .filter(|piece| !piece.is_empty())
        {
            for word in words(piece) {
                let digits = word.bytes.iter().all(u8::is_ascii_digit);
                let passed_over = is_known_short_word(word.bytes)
                    && !(count_digits && word.bytes.len() < MAX_SHORT_WORD);
                if passed_over || (digits && !count_digits) {
                    continue;
                }
                if word.bytes.len() <= CHUNK_WIDTH
                    && (digits || word.bytes.iter().all(u8::is_ascii_alphabetic))
                {
                    groups += 1;
                    letters += word.bytes.len();
                    if groups >= MIN_CHUNKS && letters >= MIN_CHUNK_LETTERS {
                        return true;
                    }
                } else {
                    (groups, letters) = (0, 0);
                }
            }
        }
    }
    false
}

/// the longest word of the short-word vocabulary.
const MAX_SHORT_WORD: usize = 3;

/// the short-word vocabulary, sorted for lookup.
static SORTED_SHORT_WORDS: std::sync::LazyLock<Vec<&'static [u8]>> =
    std::sync::LazyLock::new(|| {
        let mut words: Vec<&[u8]> = SHORT_WORDS
            .split_ascii_whitespace()
            .map(str::as_bytes)
            .collect();
        words.sort_unstable();
        words
    });

/// whether a word belongs to the short-word vocabulary, in any case.
fn is_known_short_word(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_SHORT_WORD {
        return false;
    }
    let mut lower = [0; MAX_SHORT_WORD];
    for (slot, byte) in lower.iter_mut().zip(bytes) {
        *slot = byte.to_ascii_lowercase();
    }
    SORTED_SHORT_WORDS
        .binary_search(&&lower[..bytes.len()])
        .is_ok()
}

fn words(value: &[u8]) -> Vec<Word<'_>> {
    let mut words = Vec::new();
    let mut start = 0;
    for i in 0..value.len() {
        if is_separator(value[i]) {
            if start < i {
                words.push(Word {
                    bytes: &value[start..i],
                    start,
                });
            }
            start = i + 1;
        } else if i > start {
            let previous = value[i - 1];
            let current = value[i];
            let boundary = previous.is_ascii_digit() != current.is_ascii_digit()
                || (previous.is_ascii_lowercase() && current.is_ascii_uppercase())
                || (previous.is_ascii_uppercase()
                    && current.is_ascii_uppercase()
                    && value.get(i + 1).is_some_and(u8::is_ascii_lowercase));
            if boundary {
                words.push(Word {
                    bytes: &value[start..i],
                    start,
                });
                start = i;
            }
        }
    }
    if start < value.len() {
        words.push(Word {
            bytes: &value[start..],
            start,
        });
    }
    words
}

/// splits an identifier-shaped value into its camel, snake and dotted words (digit runs are words
/// of their own); none when the value holds a byte outside identifiers and separators.
pub(crate) fn identifier_words(value: &[u8]) -> Option<Vec<&[u8]>> {
    checked_value(value).map(|value| words(value).into_iter().map(|word| word.bytes).collect())
}

/// whether a word is one of the common short identifier words.
pub(crate) fn is_short_word(bytes: &[u8]) -> bool {
    SHORT_WORDS
        .split_ascii_whitespace()
        .any(|allowed| bytes.eq_ignore_ascii_case(allowed.as_bytes()))
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// summarizes the byte-level word structure of a candidate value.
pub struct WordStructure {
    pub words: usize,
    pub short_words: usize,
    pub longest_word: usize,
    pub digit_bytes: usize,
    pub rejected_byte: bool,
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// analyzes the byte-level word structure of a candidate value.
pub fn analyze(value: &[u8]) -> WordStructure {
    let mut report = WordStructure {
        words: 0,
        short_words: 0,
        longest_word: 0,
        digit_bytes: 0,
        rejected_byte: true,
    };
    let Some(value) = checked_value(value) else {
        return report;
    };
    report.rejected_byte = false;
    for word in words(value) {
        report.words += 1;
        report.longest_word = report.longest_word.max(word.bytes.len());
        if word.bytes[0].is_ascii_digit() {
            report.digit_bytes += word.bytes.len();
        } else if word.bytes.len() < 4 {
            report.short_words += 1;
        }
    }
    report
}

/// sums `analyze` over every maximal run of word bytes, so a value `analyze` rejects for its
/// syntax bytes (an alternation, a search pattern) still reports the words its verdict rests on.
pub fn analyze_word_runs(value: &[u8]) -> WordStructure {
    let mut total = WordStructure {
        words: 0,
        short_words: 0,
        longest_word: 0,
        digit_bytes: 0,
        rejected_byte: true,
    };
    for run in value
        .split(|&byte| !(byte.is_ascii_alphanumeric() || is_separator(byte)))
        .filter(|run| !run.is_empty())
    {
        let report = analyze(run);
        total.words += report.words;
        total.short_words += report.short_words;
        total.longest_word = total.longest_word.max(report.longest_word);
        total.digit_bytes += report.digit_bytes;
        total.rejected_byte = false;
    }
    total
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// recognizes identifier structure, or a search-pattern alternation whose every item is either a
/// short id or word run below the entropy minimum or itself identifier-structured, so one long
/// opaque item keeps the whole value reported. an environment entry or a key chord whose value is
/// a short scalar or a name (`is_word_entry`) and a search pattern of alternation groups and anchors
/// whose literal runs are words (`is_word_pattern`) are recognized too. human-style passphrases
/// are a documented blind spot, and so is a credential chunked by `|` into short id-shaped items in
/// the plain alternation; no encoded-token alphabet uses `|`.
pub fn is_word_structured(value: &[u8]) -> bool {
    if trim_delimiter(value).len() < MIN_ENTROPY_LENGTH {
        return false;
    }
    match alternation_items(value) {
        Some(items) => items.iter().all(|item| {
            if item.len() < MIN_ENTROPY_LENGTH {
                is_short_item_structured(item)
            } else {
                is_identifier_structured(item)
            }
        }),
        None => is_identifier_structured(value) || is_word_entry(value) || is_word_pattern(value),
    }
}

/// the modifier keys that open a key chord (`super+shift+t`, `ctrl+alt+delete`).
const MODIFIER_KEYS: &[&[u8]] = &[
    b"ctrl", b"control", b"shift", b"alt", b"opt", b"option", b"cmd", b"command", b"super",
    b"meta", b"hyper", b"fn",
];

/// the fewest bytes of an environment variable name an entry accepts.
const MIN_ENTRY_NAME: usize = 4;

/// the longest word of an entry flag (`-mod=readonly`) and the longest key of a key chord
/// (`grave_accent`): neither position can hold a token of `MIN_ENTROPY_LENGTH` bytes.
const MAX_ENTRY_WORD: usize = 8;
const MAX_CHORD_KEY: usize = 12;

/// recognizes a name-value entry whose head has a form random tokens do not produce and whose
/// every variable position is either too short to hold a token or judged by the identifier rule:
///
/// - an environment entry `NAME=value` (`GOFLAGS=-mod=readonly`,
///   `NODE_EXTRA_MEMORY_LIMIT_MB=4096`): a name of at least `MIN_ENTRY_NAME` capitals, digits and
///   `_` that opens with a capital and is either a single word (`wordlike_piece`, below
///   `MIN_ENTROPY_LENGTH` bytes) or a snake name the identifier rule accepts
///   (`is_identifier_structured`), then a number of at most four digits or a flag
///   (`is_entry_scalar`). a bare word value (`NAME=word`) stays reported: a string
///   literal holding `SERVICE_SECRET=<eight letters>` is a whole tier-3 candidate, and a random
///   lowercase word reads as a word about half the time;
/// - a key chord `modifier+key=action` (`super+shift+t=toggle_quick_terminal`): one or more
///   modifier keys (`MODIFIER_KEYS`, a closed vocabulary) joined by `+`, a
///   key name of at most `MAX_CHORD_KEY` lowercase letters, digits and `_`, and an action the
///   identifier rule accepts.
///
/// no run of four short groups crosses an entry's name and value or a chord's key and action
/// (`is_chunked_with_digits`), so a token cut into chunks by `_` stays reported wherever its chunks
/// sit, and a name or an action is exempted no more often than the same token standing alone. the
/// single-word name, the flag words and the key are shorter than `MIN_ENTROPY_LENGTH`, so none
/// holds a whole token. a list value (`--query-gpu=memory.used,name`, `status,branch,event`) and a
/// chord with no modifier head (`a+b=c_d`) are indistinguishable from random lowercase letters cut
/// by `,`, `+` and `=`, and stay reported.
fn is_word_entry(value: &[u8]) -> bool {
    let value = trim_delimiter(value);
    let Some(join) = value.iter().position(|&byte| byte == b'=') else {
        return false;
    };
    let (head, rest) = (&value[..join], &value[join + 1..]);
    if head.first().is_some_and(u8::is_ascii_uppercase) {
        // the name and the flag are read as one run, so a token cut into chunks cannot keep two of
        // them in the flag's words (`AB_CD_EF=--gh=ij`).
        is_entry_name(head) && is_entry_scalar(rest) && !is_chunked_with_digits(value, b"")
    } else {
        // the key joins the action, as the flag joins the name; the modifiers are a closed
        // vocabulary and stay out of the run (`ctrl+ab_cd=ef_gh_ij`).
        let key = head.rsplit(|&byte| byte == b'+').next().unwrap_or_default();
        is_key_chord(head)
            && is_structured_name(rest)
            && !is_chunked_with_digits(&[key, b" ", rest].concat(), b"")
    }
}

/// an environment variable name: capitals, digits and `_`, opened by a capital, a single word or a
/// snake name the identifier rule accepts.
fn is_entry_name(name: &[u8]) -> bool {
    if name.len() < MIN_ENTRY_NAME
        || !name
            .iter()
            .all(|&byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return false;
    }
    if name.contains(&b'_') {
        return is_structured_name(name);
    }
    let letters = name
        .iter()
        .take_while(|byte| byte.is_ascii_uppercase())
        .count();
    let mut lower = name.to_vec();
    lower.make_ascii_lowercase();
    name[letters..].iter().all(u8::is_ascii_digit)
        && wordlike_piece(&lower).is_some_and(|words| words.long == 1 && words.short == 0)
}

/// a snake, kebab or dotted name the identifier rule accepts, with no run of short groups.
fn is_structured_name(name: &[u8]) -> bool {
    is_identifier_structured(name) && !is_chunked_with_digits(name, b"")
}

/// the value of an environment entry: a number of at most four digits, or a flag (`-` or `--`, an
/// entry word, and optionally `=` and an entry word).
fn is_entry_scalar(value: &[u8]) -> bool {
    if (1..=4).contains(&value.len()) && value.iter().all(u8::is_ascii_digit) {
        return true;
    }
    let Some(flag) = value
        .strip_prefix(b"--")
        .or_else(|| value.strip_prefix(b"-"))
    else {
        return false;
    };
    match flag.iter().position(|&byte| byte == b'=') {
        Some(join) => is_entry_word(&flag[..join]) && is_entry_word(&flag[join + 1..]),
        None => is_entry_word(flag),
    }
}

/// a lowercase word of at most `MAX_ENTRY_WORD` bytes, optionally followed by a number, that reads
/// as a word (`wordlike_piece`).
fn is_entry_word(word: &[u8]) -> bool {
    let letters = word
        .iter()
        .take_while(|byte| byte.is_ascii_lowercase())
        .count();
    (1..=MAX_ENTRY_WORD).contains(&word.len())
        && letters > 0
        && word[letters..].iter().all(u8::is_ascii_digit)
        && wordlike_piece(word).is_some()
}

/// the head of a key chord (`super+shift+t`): one or more `MODIFIER_KEYS`, each followed by `+`,
/// then a key name of at most `MAX_CHORD_KEY` lowercase letters, digits and `_`.
fn is_key_chord(head: &[u8]) -> bool {
    let parts: Vec<&[u8]> = head.split(|&byte| byte == b'+').collect();
    let Some((key, modifiers)) = parts.split_last() else {
        return false;
    };
    !modifiers.is_empty()
        && modifiers
            .iter()
            .all(|modifier| MODIFIER_KEYS.contains(modifier))
        && (1..=MAX_CHORD_KEY).contains(&key.len())
        && key
            .iter()
            .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// recognizes a search pattern built from alternation groups, anchors and posix classes whose
/// literal runs are words: `(^|/)(target|node_modules)$`, `^(claude|claude-code)([[:space:]]|$)`,
/// `(\.cache|build|artifacts)/`, `(deprecated|legacy)(_api|_client)`, or a shell case pattern
/// closed by `)` (`start|stop|restart)`). the pattern is a sequence of `(` or `(?:` groups of
/// `|`-separated alternatives, top-level `|`, the anchors `^`, `$`, `\b`, posix classes of the
/// closed set (`[[:space:]]`, `POSIX_CLASSES`) with an optional `*`, `+` or `?`, whose names carry
/// no payload, escaped `.`, `-` and `/`, and literal runs of word bytes; no group nests and no
/// alternative is empty. at least one group or the top level holds two alternatives. every literal
/// run passes the judgement a plain alternation gives its item (`is_short_item_structured` below
/// `MIN_ENTROPY_LENGTH` bytes, the identifier rule from there on), so a pattern is exempted no more
/// often than the plain alternation of its runs, and a token that fills one run is judged as it is
/// standing alone. beyond that, and unlike the short
/// ids a plain alternation admits, the runs read as words (`wordlike_piece`), at least three of
/// four or more letters, that outweigh their short pieces, and no run of four short groups crosses
/// them (`is_chunked_with_digits`), so an opaque or chunked item keeps the value reported.
fn is_word_pattern(value: &[u8]) -> bool {
    let value = trim_delimiter(value);
    let mut literals = Vec::new();
    let mut alternations = 0;
    let mut top_alternatives = 1;
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'(' {
            let Some((end, alternatives)) = pattern_group_end(value, index, &mut literals) else {
                return false;
            };
            alternations += usize::from(alternatives >= 2);
            index = end;
        } else if value[index] == b'|' {
            // no empty top-level alternative.
            if index == 0 || matches!(value.get(index + 1), None | Some(b'|' | b')')) {
                return false;
            }
            top_alternatives += 1;
            index += 1;
        } else if value[index] == b')' && index + 1 == value.len() && top_alternatives >= 2 {
            // the closing parenthesis of a shell case pattern.
            index += 1;
        } else if let Some(end) = pattern_atom_end(value, index, &mut literals) {
            index = end;
        } else {
            return false;
        }
    }
    if alternations == 0 && top_alternatives < 2 {
        return false;
    }
    let mut words = PieceWords::default();
    let mut text = Vec::with_capacity(value.len());
    for literal in &literals {
        // each run passes the judgement a plain alternation gives its item.
        let item_structured = if literal.len() < MIN_ENTROPY_LENGTH {
            is_short_item_structured(literal)
        } else {
            is_identifier_structured(literal)
        };
        if !item_structured {
            return false;
        }
        text.extend_from_slice(literal);
        text.push(b' ');
        for piece in literal
            .split(|&byte| is_separator(byte))
            .filter(|piece| !piece.is_empty())
        {
            if piece.len() >= MIN_ENTROPY_LENGTH && is_identifier_structured(piece) {
                words.long += 1;
            } else if let Some(piece_words) = wordlike_piece(piece) {
                words.add(piece_words);
            } else {
                return false;
            }
        }
    }
    words.long >= 3 && words.outweigh_short_pieces() && !is_chunked_with_digits(&text, b"")
}

/// end of a pattern group opened at `start` and the number of its alternatives: `(` or `(?:`,
/// alternatives of pattern atoms separated by `|`, then `)` and an optional `?`. the literal runs
/// of the alternatives are appended to `literals`.
fn pattern_group_end<'a>(
    value: &'a [u8],
    start: usize,
    literals: &mut Vec<&'a [u8]>,
) -> Option<(usize, usize)> {
    let mut index = start + 1;
    if value[index..].starts_with(b"?:") {
        index += 2;
    }
    let mut alternatives = 1;
    let mut atoms = 0;
    loop {
        match value.get(index) {
            Some(b')') if atoms > 0 => {
                index += 1;
                index += usize::from(value.get(index) == Some(&b'?'));
                return Some((index, alternatives));
            }
            Some(b'|') if atoms > 0 => {
                alternatives += 1;
                atoms = 0;
                index += 1;
            }
            Some(_) => {
                index = pattern_atom_end(value, index, literals)?;
                atoms += 1;
            }
            None => return None,
        }
    }
}

/// the posix character classes, and the `word` class of gnu and pcre: a closed vocabulary like
/// `MODIFIER_KEYS`, since the name of a class is read as syntax rather than as a literal run.
const POSIX_CLASSES: &[&[u8]] = &[
    b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower", b"print", b"punct",
    b"space", b"upper", b"xdigit", b"word",
];

/// end of one pattern atom at `start`: an anchor (`^`, `$`, `\b`, `\\b`), a posix class
/// (`POSIX_CLASSES`) with an optional quantifier, an escaped `.`, `-` or `/`, or a literal run of
/// word bytes, which is appended to `literals`.
fn pattern_atom_end<'a>(
    value: &'a [u8],
    start: usize,
    literals: &mut Vec<&'a [u8]>,
) -> Option<usize> {
    let tail = &value[start..];
    for anchor in [b"\\\\b".as_slice(), b"\\b"] {
        if tail.starts_with(anchor) {
            return Some(start + anchor.len());
        }
    }
    // `^` opens and `$` closes an alternative; elsewhere they are no anchors.
    if tail[0] == b'^' && (start == 0 || matches!(value[start - 1], b'(' | b'|' | b':')) {
        return Some(start + 1);
    }
    if tail[0] == b'$' && matches!(value.get(start + 1), None | Some(b'|' | b')')) {
        return Some(start + 1);
    }
    for escape in [b"\\\\".as_slice(), b"\\"] {
        if let Some(rest) = tail.strip_prefix(escape)
            && rest
                .first()
                .is_some_and(|byte| matches!(byte, b'.' | b'-' | b'/'))
        {
            return Some(start + escape.len() + 1);
        }
    }
    if let Some(rest) = tail.strip_prefix(b"[[:") {
        let name = rest
            .iter()
            .take_while(|byte| byte.is_ascii_lowercase())
            .count();
        // the class name is no literal run, so only a name of the closed posix set stands there.
        if POSIX_CLASSES.contains(&&rest[..name]) && rest[name..].starts_with(b":]]") {
            let end = start + 3 + name + 3;
            return Some(end + usize::from(matches!(value.get(end), Some(b'*' | b'+' | b'?'))));
        }
        return None;
    }
    let length = tail
        .iter()
        .take_while(|&&byte| byte.is_ascii_alphanumeric() || is_separator(byte))
        .count();
    if length == 0 {
        return None;
    }
    literals.push(&tail[..length]);
    Some(start + length)
}

/// the class-name prefixes of the platform frameworks (`NSWindow`, `CGSConnection`, `kAXTitle`,
/// `OSAllocatedUnfairLock`): a closed vocabulary like `MODIFIER_KEYS`. with the vocabulary
/// acronyms, a pair of random capitals opens an identifier about one time in twelve, and a run of
/// three about one time in a hundred and fifty.
const FRAMEWORK_PREFIXES: &[&[u8]] = &[
    b"NS", b"UI", b"CF", b"CG", b"CGS", b"CA", b"CT", b"CV", b"CM", b"CI", b"CL", b"AV", b"AX",
    b"MK", b"SK", b"WK", b"GK", b"HK", b"EK", b"CN", b"PH", b"UN", b"LS", b"SC", b"SF", b"SM",
    b"IO", b"OS", b"MTL",
];

/// the acronym that opens a camel identifier: a framework prefix (`NS`, `CGS`), a vocabulary
/// acronym (`URL`, `DNS`), or a framework prefix and a vocabulary acronym run together (`NSURL`).
/// the template step reads the names of placeholders and holes with it too.
pub(crate) fn is_leading_acronym(bytes: &[u8]) -> bool {
    is_known_short_word(bytes)
        || FRAMEWORK_PREFIXES.iter().any(|prefix| {
            bytes
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.is_empty() || is_known_short_word(rest))
        })
}

/// a camel-case identifier with no separator: `noteLifecycleChangeHappened`,
/// `NSAppleEventsUsageDescription`, `kSecAttrAccessGroup`, `sourceDNSRecordType`,
/// `defaultWindowFrameWidth2`. an optional hungarian `k` before a capital opens it; then comes a
/// lowercase or capitalized word or a leading acronym (`is_leading_acronym`), then capitalized
/// words and acronyms of the short-word vocabulary (`URL`, `ID`, `DNS`), and at most one run of at
/// most four digits closes it. every other word of fewer than four letters belongs to the
/// short-word vocabulary too. at least four words have
/// four or more letters, as the path step's contract for a 20-byte segment requires, they are no
/// fewer than the other words, and they keep the vowel rule of `is_identifier_structured`. an
/// identifier that uses the `k`, an acronym or the closing digits shows no run of four short groups
/// across its humps (`is_chunked_with_digits`), so a token cut into short chunks at camel humps and
/// dressed in those forms stays reported whether or not its chunks are pronounceable. a plain
/// camel identifier (`libcPosixSpawnFileActions`) keeps the judgement it had before those forms
/// existed, without that guard.
fn is_camel_identifier(value: &[u8], words: &[Word<'_>]) -> bool {
    let mut words = words;
    let mut widened = false;
    if words.len() > 1 && words[0].bytes == b"k" && words[1].bytes[0].is_ascii_uppercase() {
        words = &words[1..];
        widened = true;
    }
    if let Some((last, rest)) = words.split_last()
        && last.bytes[0].is_ascii_digit()
    {
        if last.bytes.len() > 4 {
            return false;
        }
        words = rest;
        widened = true;
    }
    widened |= words
        .iter()
        .any(|word| word.bytes.iter().all(u8::is_ascii_uppercase));
    // a framework prefix (`NS`, `CGS`) carries the identifier's namespace, so three long words
    // after it name as much as four in a plain identifier.
    let prefixed = words
        .first()
        .is_some_and(|word| word.bytes.iter().all(u8::is_ascii_uppercase));
    let (mut long_words, mut other_words, mut implausible_words) = (0, 0, 0);
    let (mut shortest_long_word, mut longest_long_word) = (usize::MAX, 0);
    for (index, word) in words.iter().enumerate() {
        let bytes = word.bytes;
        if bytes.iter().all(u8::is_ascii_uppercase) {
            // a framework prefix or a vocabulary acronym opens the identifier (`NS`, `CGS`,
            // `NSURL`, `DNS`); inside it only a vocabulary acronym stands (`URL`, `ID`, `DNS`).
            let known = if index == 0 {
                is_leading_acronym(bytes)
            } else {
                is_known_short_word(bytes)
            };
            if !(2..=5).contains(&bytes.len()) || !known {
                return false;
            }
            other_words += 1;
        } else if !(is_capitalized_word(bytes) || (index == 0 && is_lowercase_word(bytes))) {
            return false;
        } else if bytes.len() < 4 {
            if !is_known_short_word(bytes) {
                return false;
            }
            other_words += 1;
        } else {
            long_words += 1;
            shortest_long_word = shortest_long_word.min(bytes.len());
            longest_long_word = longest_long_word.max(bytes.len());
            implausible_words += usize::from(!has_wordlike_vowels(bytes));
        }
    }
    (long_words >= 4 || (prefixed && long_words >= 3))
        && long_words >= other_words
        && implausible_words * 4 <= long_words
        && !(implausible_words > 0 && longest_long_word - shortest_long_word <= 1)
        && !(widened && is_chunked_with_digits(value, b""))
}

/// the identifier rule. no bound on length is assumed: `is_word_structured` hands it values of at
/// least `MIN_ENTROPY_LENGTH` bytes, and an entry hands it a name or a chord action of any length,
/// which then needs the same words as a long identifier.
fn is_identifier_structured(value: &[u8]) -> bool {
    let Some(value) = checked_value(value) else {
        return false;
    };
    let words = words(value);
    if words.iter().any(|word| word.bytes.len() >= 20) {
        return false;
    }
    let digit_bytes: usize = words
        .iter()
        .filter(|word| word.bytes[0].is_ascii_digit())
        .map(|word| word.bytes.len())
        .sum();
    if digit_bytes > 8 {
        return false;
    }
    let separator_count = value.iter().filter(|&&byte| is_separator(byte)).count();
    if separator_count == 0 {
        return is_camel_identifier(value, &words);
    }
    let mut numeric_words = 0;
    let mut alphabetic_words = 0;
    let mut long_words = 0;
    let mut implausible_words = 0;
    let mut shortest_long_word = usize::MAX;
    let mut longest_long_word = 0;
    let has_separator = separator_count > 0;
    let mut i = 0;
    while i < words.len() {
        let word = &words[i];
        let bytes = word.bytes;
        if bytes[0].is_ascii_digit() {
            numeric_words += 1;
            if numeric_words > 2 || bytes.len() > 4 {
                return false;
            }
        } else {
            if bytes.len() == 1 {
                if words.get(i + 1).is_some_and(|next| {
                    next.start == word.start + 1
                        && next.bytes[0].is_ascii_digit()
                        && next.bytes.len() <= 4
                }) {
                    i += 2;
                    continue;
                }
                return false;
            }
            if !(is_lowercase_word(bytes)
                || bytes.iter().all(u8::is_ascii_uppercase)
                || is_capitalized_word(bytes))
            {
                return false;
            }
            alphabetic_words += 1;
            if bytes.len() >= 4 {
                long_words += 1;
                shortest_long_word = shortest_long_word.min(bytes.len());
                longest_long_word = longest_long_word.max(bytes.len());
                if !has_wordlike_vowels(bytes) {
                    implausible_words += 1;
                }
            } else if !is_known_short_word(bytes) {
                return false;
            }
        }
        i += 1;
    }
    // camel case is judged per separator-delimited segment: one separator between two camel-case
    // segments (`hookSpecificOutput.hookEventName`) counts like a camel-only value unless a run of
    // short words spans the value (`is_chunked`), as camel-cased short chunks do, while two or more
    // separators keep their own path below. a value with no separator took `is_camel_identifier`.
    let is_camel_segment = |segment: &[Word<'_>]| {
        segment.iter().enumerate().all(|(index, word)| {
            (index == 0 && is_lowercase_word(word.bytes)) || is_capitalized_word(word.bytes)
        })
    };
    let camel_only = separator_count == 1 && {
        let separator = value
            .iter()
            .position(|&byte| is_separator(byte))
            .unwrap_or(value.len());
        let split = words.partition_point(|word| word.start < separator);
        0 < split
            && split < words.len()
            && is_camel_segment(&words[..split])
            && is_camel_segment(&words[split..])
            && !is_chunked(value, b"")
    };
    if separator_count < 2 && !camel_only {
        return false;
    }
    if camel_only && long_words < 4 {
        return false;
    }
    // require three quarters of long words to contain a vowel (including y) and
    // at most four consecutive consonants, allowing occasional acronyms or compounds.
    // near-uniform long-word lengths (spread <= 1) get no such allowance, since
    // mechanically chunked tokens must not qualify merely by having short chunks.
    if implausible_words * 4 > long_words
        || (implausible_words > 0 && longest_long_word - shortest_long_word <= 1)
    {
        return false;
    }
    // multiplication implements a ceiling for half of an odd alphabetic count.
    long_words >= 3 && long_words * 2 >= alphabetic_words && (long_words >= 4 || has_separator)
}

#[cfg(test)]
mod tests {
    use super::{
        PieceWords, analyze, analyze_word_runs, is_chunked, is_chunked_with_digits,
        is_known_short_word, is_word_structured, wordlike_piece,
    };
    use crate::scanner::entropy::shannon_entropy;

    const SAMPLES: usize = 5_000;

    struct XorShift64Star(u64);

    impl XorShift64Star {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u32 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
        }

        fn byte_from(&mut self, alphabet: &[u8]) -> u8 {
            alphabet[(self.next() as usize) % alphabet.len()]
        }
    }

    fn random_string(prng: &mut XorShift64Star, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(prng.byte_from(alphabet)))
            .collect()
    }

    fn uuid_v4(prng: &mut XorShift64Star, dashed: bool) -> String {
        let mut value = String::with_capacity(if dashed { 36 } else { 32 });
        for (group, length) in [8, 4, 4, 4, 12].into_iter().enumerate() {
            for position in 0..length {
                let byte = if group == 2 && position == 0 {
                    b'4'
                } else if group == 3 && position == 0 {
                    prng.byte_from(b"89ab")
                } else {
                    prng.byte_from(b"0123456789abcdef")
                };
                value.push(char::from(byte));
            }
            if dashed && group < 4 {
                value.push('-');
            }
        }
        value
    }

    #[test]
    fn analyze_reports_raw_word_structure() {
        let report = analyze(b"XMLParser/v2");
        assert_eq!(report.words, 4);
        assert_eq!(report.short_words, 2);
        assert_eq!(report.longest_word, 6);
        assert_eq!(report.digit_bytes, 1);
        assert!(!report.rejected_byte);
        assert!(analyze(b"invalid+byte").rejected_byte);
    }

    #[test]
    fn benign_identifier_table_meets_threshold() {
        let benign = [
            "hummingbot.strategy.strategy_v2_base.ExecutorOrchestrator",
            "noteLifecycleChangeHappened",
            "CloseType.STOP_LOSS_TRIGGERED_EVENT",
            ".wui-candlestick-chart__something",
            "lv.font_montserrat_compressed",
            "some/dir/config-file.toml",
            "getUserAccessTokenFromCache",
            "unittest.mock.patch.object",
            "CompiledAllowlist::from_config",
            "github.com/owner/repo/internal/scan",
            "rbac.authorization.k8s.io/v1beta1",
            "docs/plans/redact-claude-masks.md",
            "strategy_v2_base.ExecutorOrchestrator",
            "node_modules/.bin/eslint-config-next",
            "internal/scan/libsecp256k1/src/precomputed",
        ];
        let passed = benign
            .iter()
            .filter(|value| is_word_structured(value.as_bytes()))
            .count();
        for value in benign {
            eprintln!("benign {value}: {}", is_word_structured(value.as_bytes()));
        }
        eprintln!("benign pass rate: {passed}/{}", benign.len());
        assert!(
            passed >= 13,
            "benign pass rate was {passed}/{}",
            benign.len()
        );
        assert!(!is_word_structured(b"application/vnd.api+json"));
    }

    #[test]
    fn opaque_and_credential_shaped_values_are_not_exempted() {
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);
        let uppercase_then_lowercase: String =
            (b'A'..=b'Z').chain(b'a'..=b'f').map(char::from).collect();
        let lowercase: String = (b'a'..=b'z').map(char::from).collect();
        let alternating: String = (0..26)
            .map(|index| {
                let byte = b'a' + index as u8;
                char::from(if index % 2 == 0 {
                    byte.to_ascii_uppercase()
                } else {
                    byte
                })
            })
            .collect();
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let lower_hex = b"0123456789abcdef";
        let random_identifier = random_string(&mut prng, base62, 16);
        let jwt_header = random_string(&mut prng, base62, 10);
        let jwt_payload = random_string(&mut prng, base62, 12);
        let jwt_signature = random_string(&mut prng, base62, 15);
        let values = vec![
            uppercase_then_lowercase,
            lowercase,
            alternating,
            random_string(&mut prng, base62, 32),
            random_string(&mut prng, lower_hex, 32),
            uuid_v4(&mut prng, true),
            uuid_v4(&mut prng, false),
            format!("task/{random_identifier}/main/unit/detector"),
            format!("{jwt_header}.{jwt_payload}.{jwt_signature}"),
            "https://x".to_owned(),
            "foo(bar)".to_owned(),
            "a+b".to_owned(),
            "x=y".to_owned(),
            "name@host".to_owned(),
            "rate%value".to_owned(),
            "internationalization".to_owned(),
            "2026-09-08-1234-5678".to_owned(),
        ];
        for value in values {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn random_credentials_are_never_exempted() {
        let alphabets: [(&str, &[u8]); 8] = [
            ("hex-lower", b"0123456789abcdef"),
            ("hex-upper", b"0123456789ABCDEF"),
            ("base32", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            ("base36-lower", b"0123456789abcdefghijklmnopqrstuvwxyz"),
            (
                "base58",
                b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            ),
            (
                "base62",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            ),
            (
                "base64url",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            ),
            (
                "mixed-alpha",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            ),
        ];
        let lengths = [20, 24, 32, 40, 64];
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);

        for (name, alphabet) in alphabets {
            for length in lengths {
                let exempted = (0..SAMPLES)
                    .filter(|_| {
                        is_word_structured(random_string(&mut prng, alphabet, length).as_bytes())
                    })
                    .count();
                eprintln!("{name}\t{length}\t{SAMPLES}\t{exempted}");
                assert_eq!(exempted, 0, "{name} length {length}");
            }
        }

        for dashed in [true, false] {
            let name = if dashed {
                "uuid-v4-dashed"
            } else {
                "uuid-v4-dashless"
            };
            let exempted = (0..SAMPLES)
                .filter(|_| is_word_structured(uuid_v4(&mut prng, dashed).as_bytes()))
                .count();
            let length = if dashed { 36 } else { 32 };
            eprintln!("{name}\t{length}\t{SAMPLES}\t{exempted}");
            assert_eq!(exempted, 0, "{name}");
        }

        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let separators = b".-_";
        let exempted = (0..SAMPLES)
            .filter(|_| {
                let length = 24 + (prng.next() as usize % 17);
                let mut value = random_string(&mut prng, base62, length);
                let position = prng.next() as usize % (value.len() + 1);
                value.insert(position, char::from(prng.byte_from(separators)));
                is_word_structured(value.as_bytes())
            })
            .count();
        eprintln!("base62-separated\t24-40\t{SAMPLES}\t{exempted}");
        assert_eq!(exempted, 0, "base62 with one separator");
    }

    #[test]
    fn human_passphrases_are_exempted_documented_cost() {
        let passphrases = [
            "MyVeryLongPassphraseForProduction",
            "correct-horse-battery-staple",
            "SuperSecretAdminPassword",
            "winter_meadow_sunrise_memory",
            "ReliableBackupRotationSchedule",
            "MountainRiverCedarForest",
            "orchard-lantern-morning-walk",
            "GentleNotebookCoffeeBreak",
            "archive_index_cleanup_plan",
            "secure-vault-rotation-checklist",
            "ProductReleaseValidationNotes",
            "telescope-garden-midnight-rain",
            "HelpfulAssistantDocumentReview",
            "network_backup_storage_policy",
            "CalendarMeetingReminderWorkflow",
            "copper-bridge-evening-window",
            "DocumentedMigrationSafetySteps",
            "morning_coffee_reading_journal",
            "PrivacyFocusedAccessControl",
            "library-catalog-search-index",
            "ServiceHealthMonitoringDashboard",
            "orange-violet-silver-garden",
            "ProjectPlanningSessionNotes",
            "friendly-neighbor-weekend-market",
        ];
        for value in passphrases {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
        let high_entropy = passphrases
            .iter()
            .filter(|value| shannon_entropy(value.as_bytes()) >= 4.0)
            .count();
        eprintln!(
            "human passphrases at entropy >= 4.0: {high_entropy}/{}",
            passphrases.len()
        );
    }

    #[test]
    fn analyze_word_runs_counts_the_runs_of_an_alternation() {
        let value = b"^(ERROR|WARNING|FATAL|panicked|timeout)$";
        assert!(is_word_structured(value));
        assert_eq!(analyze(value).words, 0);
        let report = analyze_word_runs(value);
        assert_eq!(report.words, 5);
        assert_eq!(report.longest_word, 8);
        assert!(!report.rejected_byte);
        assert!(analyze_word_runs(b"()|").rejected_byte);
    }

    #[test]
    fn word_and_short_id_alternations_are_word_structured() {
        let mut prng = XorShift64Star::new(0x2545_f491_4f6c_dd1d);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let ids: Vec<String> = (0..4)
            .map(|_| random_string(&mut prng, base62, 16))
            .collect();
        let values = [
            "DeprecationWarning|legacy_api_v2|removeAfter|OBSOLETE".to_owned(),
            "^(ERROR|WARNING|FATAL|panicked|timeout)$".to_owned(),
            r"\b(FIXME|todo|Hack|XXX|workaround|kludge)\b".to_owned(),
            r"\\b(TODO|FIXME|Hack|XXX|workaround)\\b".to_owned(),
            "(?:JIRA-4417|JIRA-4502|SEC-88|OPS-1203)".to_owned(),
            r"^foo_bar$|\bbaz-qux\b|^quux.corge$".to_owned(),
            "hummingbot.strategy.strategy_v2_base|ExecutorConfig".to_owned(),
            "alpha_beta|gamma_delta|epsilon_zeta,".to_owned(),
            ids.join("|"),
            format!("(?:{})", ids.join("|")),
        ];
        for value in values {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
    }

    #[test]
    fn alternations_with_an_opaque_or_foreign_item_are_not_exempted() {
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let opaque = random_string(&mut prng, base62, 32);
        let split = random_string(&mut prng, base62, 40);
        let values = [
            format!("{opaque}|word"),
            format!("word|{opaque}"),
            format!("^({opaque}|word)$"),
            format!(r"\b(?:word|legacy_api|{opaque})\b"),
            opaque.clone(),
            format!("{}|{}", &split[..20], &split[20..]),
            r"DeprecationWarning\|legacy_api|removeAfter".to_owned(),
            "alpha_beta||gamma_delta".to_owned(),
            "|alpha_beta|gamma_delta".to_owned(),
            "alpha_beta|gamma_delta|".to_owned(),
            "deprecated.*|legacy_api|removeAfter".to_owned(),
            "[a-z]+_api|legacy_client|removeAfter".to_owned(),
            "(?i)deprecated|legacy_api|removeAfter".to_owned(),
            "https://example.com|legacy_client_v2".to_owned(),
            "foo|bar|baz|qux".to_owned(),
        ];
        for value in values {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn a_pipe_inside_a_single_case_letter_run_is_not_an_item_boundary() {
        let uppercase: String = (b'A'..=b'Z').take(24).map(char::from).collect();
        let lowercase = uppercase.to_ascii_lowercase();
        for token in [uppercase, lowercase] {
            for position in [7, 12] {
                let value = format!("{}|{}", &token[..position], &token[position..]);
                assert!(
                    !is_word_structured(value.as_bytes()),
                    "unexpected exemption: {value}"
                );
            }
        }
    }

    #[test]
    fn one_separator_between_camel_case_segments_is_word_structured() {
        for value in [
            "hookSpecificOutput.hookEventName",
            "sessionPayload.workspaceFolderPath",
            "toolInputSchema/filePathPattern",
            "RequestContext.AuthorizerClaims",
        ] {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }

        let mut prng = XorShift64Star::new(0x2545_f491_4f6c_dd1d);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let opaque = random_string(&mut prng, base62, 20);
        for value in [
            format!("hookSpecificOutput.{opaque}"),
            format!("{opaque}.hookEventName"),
            // fewer than four long camel words, a digit word, or a segment that is not camel case.
            "config.maxRetryCount".to_owned(),
            "hookSpecificOutput.hookEventNameV2".to_owned(),
            "hookSpecificOutput.HOOKEVENT".to_owned(),
            "hookSpecificOutput.".to_owned(),
            ".hookSpecificOutputEventName".to_owned(),
            "hookSpecificOutput.hookEventNameKpZrTw".to_owned(),
        ] {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn short_word_vocabulary_is_lowercase_and_short() {
        for word in super::SHORT_WORDS.split_ascii_whitespace() {
            assert!(
                (1..=super::MAX_SHORT_WORD).contains(&word.len())
                    && word.bytes().all(|byte| byte.is_ascii_lowercase()),
                "{word}"
            );
            assert!(is_known_short_word(word.as_bytes()), "{word}");
            assert!(
                is_known_short_word(word.to_ascii_uppercase().as_bytes()),
                "{word}"
            );
        }
        for word in ["", "x", "xdg", "apple", "HOMEx"] {
            assert!(!is_known_short_word(word.as_bytes()), "{word}");
        }
    }

    #[test]
    fn runs_of_short_groups_read_as_chunked() {
        for (value, breaks) in [
            ("agentCoreTests/SessionStoreTests", b"/".as_slice()),
            ("oh-my-pi-zsh", b"/"),
            ("app.min.js.map", b"/"),
            ("com.apple.dock.plist", b"/"),
            ("com.apple.WebKit.WebContent", b"/"),
            ("hookSpecificOutput.hookEventName", b""),
            ("widget.core.esm.production.min.js", b"/"),
            ("$HOME/code/work/repo/main", b"/"),
            ("${XDG_CACHE_HOME:-$HOME/.cache}/example", b"/${}"),
        ] {
            assert!(!is_chunked(value.as_bytes(), breaks), "{value}");
        }

        let mut prng = XorShift64Star::new(0x6A09_E667_F3BC_C908);
        let lower = b"abcdefghijklmnopqrstuvwxyz";
        for width in 2..=5 {
            for separator in ["-", "_", ".", ":", "+"] {
                // the fewest groups of `width` letters that fill 20 bytes with their separators.
                let groups = 21_usize.div_ceil(width + 1);
                // a group that happens to be a vocabulary word is drawn again: it would be passed
                // over as a word.
                let value: Vec<String> = (0..groups)
                    .map(|_| {
                        loop {
                            let group = random_string(&mut prng, lower, width);
                            if !is_known_short_word(group.as_bytes()) {
                                break group;
                            }
                        }
                    })
                    .collect();
                let value = value.join(separator);
                assert!(value.len() >= 20, "{value}");
                assert!(
                    is_chunked(value.as_bytes(), b"/"),
                    "width {width} separator {separator}"
                );
                // a path separator between the groups ends the run.
                assert!(!is_chunked(value.replace(separator, "/").as_bytes(), b"/"));
            }
        }
    }

    #[test]
    fn wordlike_pieces_read_as_words_or_short_numbers() {
        for (piece, long, short, known, vowelless, numbers) in [
            ("Library", 1, 0, 0, 0, 0),
            ("HTTPStorages", 2, 0, 0, 0, 0),
            ("python3", 1, 0, 0, 0, 1),
            ("x86", 0, 1, 0, 0, 1),
            ("k8s", 0, 2, 0, 0, 1),
            ("v2", 0, 1, 0, 0, 1),
            ("2026", 0, 0, 0, 0, 1),
            ("XCTest", 1, 1, 0, 0, 0),
            ("tmp", 0, 1, 1, 0, 0),
            ("binDir", 0, 2, 2, 0, 0),
            ("html", 0, 0, 0, 1, 0),
            ("indexHtml", 1, 0, 0, 1, 0),
        ] {
            let words = PieceWords {
                long,
                short,
                known,
                vowelless,
                numbers,
            };
            assert_eq!(wordlike_piece(piece.as_bytes()), Some(words), "{piece}");
        }
        for piece in [
            "",
            "q8Vn3sY6",
            "KpZrTwXyQm",
            "dozkvgrcnyjufqbm",
            "abc12de34",
            "20260908",
            "internationalization",
            "strengths",
            "file-name",
        ] {
            assert_eq!(wordlike_piece(piece.as_bytes()), None, "{piece}");
        }
    }

    #[test]
    fn random_alternations_with_a_long_opaque_item_are_never_exempted() {
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let exempted = (0..SAMPLES)
            .filter(|_| {
                let length = 20 + prng.next() as usize % 21;
                let opaque = random_string(&mut prng, base62, length);
                let value = match prng.next() % 3 {
                    0 => format!("{opaque}|word"),
                    1 => format!("(?:legacy_api|{opaque})"),
                    _ => format!("{opaque}|{}", random_string(&mut prng, base62, length)),
                };
                is_word_structured(value.as_bytes())
            })
            .count();
        assert_eq!(exempted, 0);
    }

    #[test]
    fn search_patterns_of_word_groups_are_word_structured() {
        for value in [
            "(^|/)(target|node_modules|coverage)$",
            "^(claude|claude-code|cc-wrapper)([[:space:]]|$)",
            r"(\.cache|build|artifacts|coverage)/",
            "(deprecated|legacy)(_api|_client)",
            "(deprecated|legacy|obsolete)(_api|_client|_v2)",
            "(deprecated|legacy|obsolete)([[:alpha:]]+|$)",
            "start|stop|reload|status|configure|version|help)",
        ] {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
        let mut prng = XorShift64Star::new(0x2545_f491_4f6c_dd1d);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let opaque = random_string(&mut prng, base62, 24);
        let short = random_string(&mut prng, base62, 12);
        for value in [
            format!("(^|/)(target|{opaque})$"),
            format!("^({opaque}|claude)([[:space:]]|$)"),
            format!("(deprecated|{short})(_api|_client)"),
            // fewer than three words of four or more letters
            "(^|/)(target|dist|out)$".to_owned(),
            // a nested group, an empty alternative, and four short alternatives in a row
            "((deprecated|legacy)|obsolete)_api".to_owned(),
            "(deprecated||legacy)(_api|_client)".to_owned(),
            "(ls|cat|head|less|grep)(_api|_client)".to_owned(),
            // regex syntax beyond anchors, groups and posix classes
            "(deprecated|legacy.*)(_api|_client)".to_owned(),
            // a class name outside the posix set is a position no literal run judges
            "(deprecated|legacy|obsolete)([[:notaclassname:]]|$)".to_owned(),
        ] {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn framework_prefixed_and_numbered_camel_identifiers_are_word_structured() {
        for value in [
            "NSAppleEventsUsageDescription",
            "NSCameraUsageDescription",
            "kAXFocusedUIElementChangedNotification",
            "kSecAttrAccessGroupValue",
            "kCFBundleShortVersionString",
            "CGSDefaultConnectionForThread",
            "NSURLSessionDataTask",
            "OSAllocatedUnfairLock",
            "sourceNumberDNSRecordType",
            "defaultWindowFrameWidth2",
            // a plain camel identifier keeps its judgement without the chunk guard
            "libcPosixSpawnFileActionsAddopen",
        ] {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
        for value in [
            // a digit run of five, an acronym inside that is no vocabulary word, a bare prefix, an
            // opening acronym that is neither a framework prefix nor a vocabulary word
            "defaultWindowFrameWidth20260",
            "defaultXYZWindowFrameWidth",
            "NSUsageDescriptionAB",
            "QZTitlebarContainerView",
            "NSQZTitlebarContainerView",
            // three long words need a framework prefix
            "cameraUsageDescription",
            // short pronounceable chunks dressed in the widened forms
            "NSBakoTineMuraSolaVeku",
            "kBakoTineMuraSolaVekuPilo",
            "bakoTineMuraSolaVekuPilo2",
        ] {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn environment_entries_and_key_chords_are_word_structured() {
        for value in [
            "GOFLAGS=-mod=readonly",
            "APP_SPIKE_EXEC_BACKGROUND=1",
            "NODE_EXTRA_MEMORY_LIMIT_MB=4096",
            "DOCKER_BUILDKIT_PROGRESS=--plain",
            "super+shift+t=toggle_quick_terminal",
            "cmd+grave_accent=toggle_quick_terminal",
            "ctrl+alt+escape=goto_split:previous",
        ] {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
        // a key and an action, or a name and a flag, of short words read as one run of short
        // groups, as a token cut into chunks with some of them in the key or the flag does
        // (`left`, `goto`, `split`, `left`)
        for value in [
            "ctrl+alt+left=goto_split:left",
            "ctrl+abcd=efgh_ijkl_mnop",
            "ABCD_EFGH_IJKL=--mnop=qrst",
        ] {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
        let mut prng = XorShift64Star::new(0x6a09_e667_f3bc_c908);
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let lower = b"abcdefghijklmnopqrstuvwxyz";
        let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let opaque = random_string(&mut prng, base62, 24);
        let word = random_string(&mut prng, lower, 20);
        let name = random_string(&mut prng, upper, 20);
        for value in [
            // a bare word value, a list value, a flag of more than a word
            "CARGO_TERM_COLOR=always".to_owned(),
            "SERVICE_ACCOUNT_SECRET=vakimoru".to_owned(),
            "--query-gpu=utilization.gpu,memory.used,memory.total".to_owned(),
            "NODE_OPTIONS=--max-old-space-size=4096".to_owned(),
            "status,pipeline,branch,event,commit,author".to_owned(),
            // a chord with no modifier head, a two-word action, a list action
            "left+right=toggle_quick_terminal".to_owned(),
            "super+shift+enter=toggle_fullscreen".to_owned(),
            "super+shift+t=toggle_quick_terminal,split".to_owned(),
            // an opaque value in each position
            format!("GOFLAGS=-mod={opaque}"),
            format!("GOFLAGS=-mod={word}"),
            format!("APP_SPIKE_{name}=1"),
            format!("{name}=1"),
            format!("super+shift+t={opaque}"),
            format!("super+shift+t={word}"),
            format!("super+{word}=toggle_quick_terminal"),
        ] {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn vowel_less_vocabulary_joins_keep_the_vowel_rule() {
        // a join whose consonant run stays within four reads as a word as it stands
        for piece in ["ctlmanager", "cfgloader"] {
            assert!(
                wordlike_piece(piece.as_bytes()).is_some_and(|words| words.long == 1),
                "{piece}"
            );
        }
        // a join that makes a run of five is refused like any consonant run: the other word could
        // be any random run that passes the vowel rule (`bodrk` + `ctl`)
        for piece in [
            "launchctl",
            "dstblock",
            "bodrkctl",
            "xqzvbctl",
            "ctlxqzvbw",
            "brtkwctl",
            "ctlrmpst",
        ] {
            assert_eq!(wordlike_piece(piece.as_bytes()), None, "{piece}");
        }
    }

    #[test]
    fn digit_runs_count_as_groups_only_where_asked() {
        let value = b"ab12.cd34.ef56.gh78.ij90";
        assert!(!is_chunked(value, b""));
        assert!(is_chunked_with_digits(value, b""));
        // a longer digit run ends the run of groups either way
        assert!(!is_chunked_with_digits(b"ab.cd.ef123456.gh.ij.kl", b""));
        assert!(!is_chunked_with_digits(
            b"agentCoreTests/SessionStoreTests",
            b"/"
        ));
    }
}
