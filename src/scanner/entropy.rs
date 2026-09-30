// shannon entropy calculation

use super::wordshape::{
    PieceWords, identifier_words, is_chunked, is_chunked_with_digits, is_short_word,
    is_word_structured, wordlike_piece,
};

/// minimum string length for entropy evaluation
pub const MIN_ENTROPY_LENGTH: usize = 20;

/// calculate shannon entropy of a byte slice (generic, all 256 byte values)
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// return whether a rooted value has the lexical shape of a wordy filesystem path.
/// a scheme-less url (`//cdn.example.com/…`) must also pass `is_scheme_less_url`, and a module
/// path rooted at a host (`github.com/owner/repo/pkg`) takes the stricter `is_host_path`.
/// this is a documented lexical heuristic, not proof the value is non-secret.
pub fn is_path_shaped(value: &[u8]) -> bool {
    if value.starts_with(b"//") && !value.starts_with(b"///") && !is_scheme_less_url(value) {
        return false;
    }
    if !is_rooted_path(value) && host_root_length(value).is_some() {
        return is_host_path(value);
    }

    // json-pointer references permit their leading # marker, and a json schema keyword such as
    // `$defs` or `$ref` may open a pointer segment.
    let pointer = value.strip_prefix(b"#/");
    let path_bytes = pointer.unwrap_or(value);

    if !is_rooted_path(value)
        || value.windows(3).any(|window| window == b"://")
        || path_bytes.iter().enumerate().any(|(index, &byte)| {
            !is_path_byte(byte)
                && !(pointer.is_some()
                    && byte == b'$'
                    && (index == 0 || path_bytes[index - 1] == b'/'))
        })
        || value
            .iter()
            .filter(|&&byte| matches!(byte, b'/' | b'\\'))
            .count()
            < 2
        || (pointer.is_some() && path_bytes.contains(&b'$') && !is_keyword_pointer(path_bytes))
    {
        return false;
    }

    has_wordy_path_leaf(value, pointer.is_some())
}

/// judges a json pointer that carries a schema keyword segment (`#/$defs/retry_policy`): each `$`
/// opens a segment that is one word of letters, no segment is cut into short letter groups
/// (`wordshape::is_chunked`), and the words of the whole pointer outweigh its short pieces
/// (`PieceWords::outweigh_short_pieces`), as a reference path's must. a separator-free part of 20
/// or more bytes counts as one word when it is word-structured, as the leaf check admits it. a
/// pointer without a keyword keeps the plain path rule.
fn is_keyword_pointer(path: &[u8]) -> bool {
    if is_chunked(path, b"/")
        || !path
            .split(|&byte| byte == b'/')
            .filter_map(|segment| segment.strip_prefix(b"$"))
            .all(|keyword| {
                (1..MIN_ENTROPY_LENGTH).contains(&keyword.len())
                    && keyword.iter().all(u8::is_ascii_alphabetic)
            })
    {
        return false;
    }
    let mut words = PieceWords::default();
    for piece in path
        .split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|piece| !piece.is_empty())
    {
        if piece.len() >= MIN_ENTROPY_LENGTH && is_word_structured(piece) {
            words.long += 1;
        } else if let Some(piece_words) = wordlike_piece(piece) {
            words.add(piece_words);
        } else {
            return false;
        }
    }
    words.outweigh_short_pieces()
}

/// recognize a relative path with one short opaque id among wordy segments, or a bare dated file
/// name (`is_dated_file_name`).
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
pub fn is_relative_id_path(value: &[u8]) -> bool {
    if is_dated_file_name(value) {
        return true;
    }
    if is_rooted_path(value)
        || value.windows(3).any(|window| window == b"://")
        || value.iter().any(|&byte| {
            !byte.is_ascii_alphanumeric() && !matches!(byte, b'/' | b'.' | b'-' | b'_')
        })
    {
        return false;
    }

    let segments: Vec<_> = value.split(|&byte| byte == b'/').collect();
    if segments.len() < 3 || segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    if !has_wordy_path_leaf(value, false) {
        return false;
    }

    let mut id_index = None;
    for (index, segment) in segments[..segments.len() - 1].iter().enumerate() {
        let has_digit = segment.iter().any(u8::is_ascii_digit);
        let has_upper = segment.iter().any(u8::is_ascii_uppercase);
        let has_lower = segment.iter().any(u8::is_ascii_lowercase);
        let is_id = segment.len() < MIN_ENTROPY_LENGTH
            && segment.iter().all(u8::is_ascii_alphanumeric)
            && (has_digit || (has_upper && has_lower));
        if is_id && id_index.replace(index).is_some() {
            return false;
        }
    }
    let Some(id_index) = id_index else {
        return false;
    };

    let mut remainder = Vec::with_capacity(value.len() - segments[id_index].len());
    for (index, segment) in segments.iter().enumerate() {
        if index == id_index {
            continue;
        }
        if !remainder.is_empty() {
            remainder.push(b'/');
        }
        remainder.extend_from_slice(segment);
    }
    crate::scanner::wordshape::is_word_structured(&remainder)
}

/// the longest numeric part, or mixed letter-and-digit part, a keyed relative path may carry.
const SHORT_PART: usize = 8;

/// recognize an assignment value that is a relative path of words: `path: docs/some-note.md`,
/// `model: vendor/name-5-variant:effort`, `where: dir/Type+Extension.swift:function`.
/// the value is not rooted and carries a `/`; every part between `/ . - _ + :` is a word piece
/// (`wordshape::wordlike_piece`), a number of at most `SHORT_PART` digits, or the one part of at
/// most `SHORT_PART` letters and digits the value may hold, which has one run of digits and letter
/// runs that are each lowercase, capitalized or all capitals. across the value there are at least
/// two words of four or more letters, no fewer than words of one to three letters, and at most one
/// vowel-less four-letter word, which keeps a base64 value whose `/` and `+` cut it into short
/// letter runs reported; the leaf, read before any `:` suffix, is wordy. a mixed part longer than
/// `SHORT_PART`, as the short id of a printed branch name is, keeps a keyed value reported, and so
/// does a segment cut into short letter groups (`wordshape::is_chunked`), four or more words of at
/// most five letters in a row. a usage placeholder reads as the words it holds
/// (`Tests/<Class>/<method>`), an English possessive after the leaf (`notes.md's`) is set aside
/// (`keyed_path_words`), and a dated file name needs no `/` (`is_dated_file_name`).
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
pub fn is_keyed_relative_path(value: &[u8]) -> bool {
    const SEPARATORS: &[u8] = b"/.-_+:";

    let Some(words) = keyed_path_words(value) else {
        return false;
    };
    let value: &[u8] = &words;
    if is_dated_file_name(value) {
        return true;
    }
    if is_rooted_path(value)
        || value.first() == Some(&b'~')
        || !value.contains(&b'/')
        || value.windows(3).any(|window| window == b"://")
        || value
            .iter()
            .any(|&byte| !byte.is_ascii_alphanumeric() && !SEPARATORS.contains(&byte))
        || value.split(|&byte| byte == b'/').any(<[u8]>::is_empty)
        || crate::scanner::wordshape::is_chunked(value, b"/")
    {
        return false;
    }

    let mut mixed_parts = 0;
    let mut words = crate::scanner::wordshape::PieceWords::default();
    for part in value
        .split(|byte| SEPARATORS.contains(byte))
        .filter(|part| !part.is_empty())
    {
        let digits = part.iter().filter(|byte| byte.is_ascii_digit()).count();
        let accepted = if digits == part.len() {
            digits <= SHORT_PART
        } else if digits > 0 {
            // a version, an index or a short id (`v2`, `run7`, `x86`, `Python3`) holds one run of
            // digits, and each run of letters is lowercase, capitalized or all capitals.
            mixed_parts += 1;
            let coherent = part
                .split(u8::is_ascii_digit)
                .filter(|run| !run.is_empty())
                .all(|run| {
                    run[1..].iter().all(u8::is_ascii_lowercase)
                        || run.iter().all(u8::is_ascii_uppercase)
                });
            let digit_runs = part
                .windows(2)
                .filter(|pair| !pair[0].is_ascii_digit() && pair[1].is_ascii_digit())
                .count()
                + usize::from(part[0].is_ascii_digit());
            mixed_parts == 1 && part.len() <= SHORT_PART && digit_runs == 1 && coherent
        } else {
            crate::scanner::wordshape::wordlike_piece(part).is_some_and(|piece| {
                words.long += piece.long;
                words.short += piece.short;
                words.vowelless += piece.vowelless;
                true
            })
        };
        if !accepted {
            return false;
        }
    }
    // a base64 value carries `/` and `+` too, and its chunks split into short letter runs: the
    // words of a path outnumber them.
    if words.vowelless > 1 || words.long < 2 || words.long < words.short {
        return false;
    }

    let leaf = value.rsplit(|&byte| byte == b'/').next().unwrap_or(value);
    let leaf = leaf.split(|&byte| byte == b':').next().unwrap_or(leaf);
    is_wordy_leaf(leaf, b"-_+")
}

/// a keyed relative path as its words read: each `<placeholder>` loses its angle brackets
/// (`Tests/<Class>/<method>` reads as `Tests/Class/method`), git's exclude magic before a pathspec
/// (`:!docs/drafts.md`, `:^docs/drafts.md`) and an English possessive `'s` after the leaf
/// (`hooks/notes.md's`) are set aside. `None` when a bracket is unpaired, empty, nested, holds
/// anything but letters, digits, `-` and `_`, or touches a letter or digit outside it, so removing
/// the brackets never joins two pieces into one, and when it holds `MIN_ENTROPY_LENGTH` bytes or
/// more: a placeholder names one thing in a word or two, shorter than a credential.
fn keyed_path_words(value: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    let value = value
        .strip_prefix(b":!")
        .or_else(|| value.strip_prefix(b":^"))
        .unwrap_or(value);
    let value = value
        .strip_suffix(b"'s")
        .filter(|stem| stem.last().is_some_and(u8::is_ascii_alphanumeric))
        .unwrap_or(value);
    if !value.iter().any(|&byte| matches!(byte, b'<' | b'>')) {
        return Some(std::borrow::Cow::Borrowed(value));
    }
    let mut words = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'<' => {
                let close = index + 1 + value[index + 1..].iter().position(|&byte| byte == b'>')?;
                let inner = &value[index + 1..close];
                if inner.is_empty()
                    || !inner
                        .iter()
                        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || inner.len() >= MIN_ENTROPY_LENGTH
                    || index
                        .checked_sub(1)
                        .is_some_and(|before| value[before].is_ascii_alphanumeric())
                    || value.get(close + 1).is_some_and(u8::is_ascii_alphanumeric)
                {
                    return None;
                }
                words.extend_from_slice(inner);
                index = close + 1;
            }
            b'>' => return None,
            byte => {
                words.push(byte);
                index += 1;
            }
        }
    }
    Some(std::borrow::Cow::Owned(words))
}

/// recognize a bare dated file name, as notes, posts and plans are named: a `YYYY-MM-DD-` date,
/// then words (`2026-09-10-docs-site-redesign.md`). every part after the date between `- _ .` is
/// a word piece (`wordshape::wordlike_piece`), at most one of them setting digits beside
/// chunk-sized letters; the words outweigh the short pieces (`PieceWords::outweigh_short_pieces`);
/// no run of short letter groups crosses the name (`wordshape::is_chunked`); the whole name reads
/// as a file name (`run_reads_as_words`); and the leaf is wordy.
/// so a date before an opaque id, a base64 tail or short chunks stays reported.
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
fn is_dated_file_name(value: &[u8]) -> bool {
    let [y1, y2, y3, y4, b'-', m1, m2, b'-', d1, d2, b'-', name @ ..] = value else {
        return false;
    };
    if ![y1, y2, y3, y4, m1, m2, d1, d2]
        .iter()
        .all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let month = (m1 - b'0') * 10 + (m2 - b'0');
    let day = (d1 - b'0') * 10 + (d2 - b'0');
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !name
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || is_chunked(name, b"")
        || !run_reads_as_words(value)
    {
        return false;
    }
    let mut tally = Tally::default();
    name.split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .all(|part| tally.piece(part))
        && tally.mixed <= 1
        && tally.incoherent == 0
        && tally.words.outweigh_short_pieces()
        && is_wordy_leaf(name, b"-_")
}

fn is_rooted_path(value: &[u8]) -> bool {
    value.starts_with(b"/")
        || value.starts_with(b"#/")
        || value.starts_with(b"~/")
        || value.starts_with(b"./")
        || value.starts_with(b"../")
        || (value.len() >= 3
            && value[0].is_ascii_alphabetic()
            && value[1] == b':'
            && matches!(value[2], b'/' | b'\\'))
}

/// recognize a single mktemp-style leaf with a wordy prefix and six-character suffix.
pub fn is_mktemp_path(value: &[u8]) -> bool {
    let Some(name) = value.strip_prefix(b"./") else {
        return false;
    };
    let Some(dot) = name.iter().position(|&byte| byte == b'.') else {
        return false;
    };
    let (stem, suffix) = (&name[..dot], &name[dot + 1..]);
    // bound the combined stem and suffix, so separators cannot hide an eligible opaque payload.
    suffix.len() == 6
        && stem.len() + suffix.len() < MIN_ENTROPY_LENGTH
        && suffix.iter().all(u8::is_ascii_alphanumeric)
        && stem.contains(&b'-')
        && stem.split(|&byte| byte == b'-').all(|word| {
            (3..MIN_ENTROPY_LENGTH).contains(&word.len()) && word.iter().all(u8::is_ascii_lowercase)
        })
        && has_wordy_path_leaf(value, false)
}

/// the word a reference stands for when the leaf of a reference path is judged.
const REFERENCE_WORD: &[u8] = b"ref";

/// the deepest nesting of reference defaults (`${A:-${B:-/tmp}}`) the reference reader follows.
const MAX_REFERENCE_DEPTH: usize = 4;

/// the bytes that end a run of short groups in a reference path: the path separators and the
/// reference syntax, since a reference stands for one word of the path
/// (`${XDG_CACHE_HOME:-$HOME/.cache}` is not a run of four short words).
const REFERENCE_RUN_BREAKS: &[u8] = b"/\\${}()%";

/// the longest letter word a chunk of a cut value carries: `wordshape::is_chunked` reads a run of
/// such words as a value cut into short groups.
const CHUNK_LETTERS: usize = 5;

/// the character classes a bracket expression may name (`[[:space:]]`).
const POSIX_CLASSES: &[&[u8]] = &[
    b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower", b"print", b"punct",
    b"space", b"upper", b"word", b"xdigit",
];

/// the letters of the control escapes of ansi-c quoting (`$'\n\r\t'`): each names a control byte,
/// not a letter of the text. nine letters carry at most log2(9) < 3.2 bits a byte, under the
/// tier-3 entropy gate, so no token hides in them.
const CONTROL_ESCAPES: &[u8] = b"abeEfnrtv";

/// the most bracket ranges (`a-z`, `A-F`, `0-9`) a value may hold. an endpoint counts neither way,
/// so the bound keeps the bytes they carry, twice this, under `MIN_ENTROPY_LENGTH`.
const MAX_BRACKET_RANGES: usize = 6;

/// what follows an operator of a `${NAME…}` expansion.
#[derive(Clone, Copy)]
enum Operand {
    /// a default, an alternative or an error message, read as text (`:-`, `:?`, `+`).
    Text,
    /// a glob pattern to remove or to change the case of (`%`, `##`, `^^`).
    Pattern,
    /// a glob pattern, then `/` and a replacement read as text (`/`, `//`, `/#`, `/%`).
    Substitution,
    /// an offset and a length (`${NAME:2:4}`).
    Arithmetic,
}

/// the operators of a `${NAME…}` expansion, each longest form before its prefix.
const EXPANSION_OPERATORS: &[(&[u8], Operand)] = &[
    (b":-", Operand::Text),
    (b":=", Operand::Text),
    (b":+", Operand::Text),
    (b":?", Operand::Text),
    (b"//", Operand::Substitution),
    (b"/#", Operand::Substitution),
    (b"/%", Operand::Substitution),
    (b"/", Operand::Substitution),
    (b"%%", Operand::Pattern),
    (b"##", Operand::Pattern),
    (b"%", Operand::Pattern),
    (b"#", Operand::Pattern),
    (b"^^", Operand::Pattern),
    (b"^", Operand::Pattern),
    (b",,", Operand::Pattern),
    (b",", Operand::Pattern),
    (b"-", Operand::Text),
    (b"=", Operand::Text),
    (b"+", Operand::Text),
    (b"?", Operand::Text),
    (b":", Operand::Arithmetic),
];

/// recognize a path rooted at a variable reference, a rooted path carrying one, a list of such
/// paths, or references alone: `"$HOME/.cache/tool"`, `"${WORKSPACE}/target/release"`,
/// `"${ARCHIVE%.*}.log"`, `$(BUILD_DIR)/obj`, `{root}/logs/{name}.txt`,
/// `%APPDATA%\Tool\settings.json`, `/Library/Caches/$bundle_id.plist`, `$HOME/Library/Caches/*.log`,
/// `$HOME/.cargo/bin:$PATH`, `"${expanded_path/#\~/$HOME}"`, `"${cleanup_patterns[@]}"`.
/// the reader follows the shell's parameter expansion: `${NAME}` with a subscript (`[@]`, `[*]`,
/// `[n]`, `[$i]`), a `#` length or a `!` indirection, the default, alternative and error
/// operators, the pattern removals, substitutions and case changes, an offset, nested references,
/// `$(command)`, `$((arithmetic))` and `$[…]` with balanced brackets, `$$` and the other special
/// and positional parameters (never `$2y$10$…`, whose `$2` runs into a letter), and an escaped
/// `\$`. every literal piece between the separators `/ \ . - _`, the glob bytes `* ?` and the list
/// joins `| :`, every piece of a reference name, and every piece of a default, pattern,
/// replacement, subscript or message must read as a word or a short number
/// (`wordshape::wordlike_piece`), which also keeps each separator-free run under 20 bytes; a
/// positional digit is a number, and a letter or digit a backslash escapes in a pattern, a bracket
/// expression or a quoted string is a piece of its own, bar the control escapes of `$'…'`
/// (`CONTROL_ESCAPES`). the endpoints of a bracket range, at most `MAX_BRACKET_RANGES` ranges in
/// the value, and the name of a POSIX class are the only other letters left out. the
/// words of all of them together must then outweigh the short pieces
/// (`PieceWords::outweigh_short_pieces`): one rule for the whole value, in which a reference whose
/// name reads as words counts as one long word, so short random chunks anywhere outnumber the
/// words of the path; references with no separator between them carry no path, so there each name
/// counts word by word, one word must be longer than any chunk (`CHUNK_LETTERS`), and no name may
/// be a member chain (`${item.name}`, `{self.root}`), a template hole rather than a shell
/// reference; optional chaining (`${item?.name}`) and a command that opens on a member access
/// (`$(item.name)`) are never read as references. four or more
/// words of at most five letters in a row inside one segment (`wordshape::is_chunked`, the list
/// joins and globs continuing a run) read as a value cut into short groups, and at most one piece
/// may set digits beside chunk-sized letters (`x86`, `run7`), so chunks that each carry a digit
/// run stay reported too. an operand and a counter are written in uniform case
/// (`is_uniform_case`); a list, a glob, an escaped value and references alone in coherent case
/// (`is_coherent`). a run of 20 or more bytes between the separators, joins, globs and reference
/// syntax must read as words on its own (`long_runs_read_as_words`). a value with a backslash is
/// also read as the shell reads its escapes (`unescaped`): there a backslash joins the bytes around
/// it, so an escape before every byte leaves one run to judge and an escaped separator (`\-`,
/// `\.`) continues a run of short groups (`wordshape::is_chunked_with_digits`). read as written, a
/// backslash separates directories and ends a run as `/` does only outside any reference in a
/// value written as a windows path is, with plain references and no shell syntax
/// (`%APPDATA%\Tool\settings.json`); in an operand, a pattern or a quoted string, and anywhere in
/// a value with an expansion operator, a list, a glob, a command or an escape, it is an escape
/// that joins the short groups around it into one run (`escapes_as_joins`). an
/// unrooted value opens on a reference, or is a list one of whose items does. the leaf of every
/// list item, each reference
/// read as a word and globs set aside, must be wordy, a reference or a bare glob. so
/// `X="$VAR/<opaque32>"`, an opaque name, default, pattern, replacement or list item, and short
/// opaque chunks joined by separators all stay reported.
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
pub fn is_reference_rooted(value: &[u8]) -> bool {
    // a value quoted inside a quoted string keeps its escaped quotes (`"\"$HOME/.config/x\""`).
    let unquoted = value
        .strip_prefix(br#"\""#)
        .and_then(|inner| inner.strip_suffix(br#"\""#));
    let escaped = unquoted.is_some() || value.windows(2).any(|pair| pair == br"\$");
    let value = unquoted.unwrap_or(value);
    // a backslash is a path separator (`%APPDATA%\Tool`) or an escape (`\-`, `[\a\b]`), and the
    // escape reading drops it: the runs of that reading are judged too, so neither an escaped
    // separator between chunks nor an escape before every byte splits a payload.
    if value.windows(3).any(|window| window == b"://")
        || is_chunked(value, REFERENCE_RUN_BREAKS)
        || !long_runs_read_as_words(value)
        || unescaped(value).is_some_and(|runs| {
            is_chunked_with_digits(&runs, REFERENCE_RUN_BREAKS) || !long_runs_read_as_words(&runs)
        })
    {
        return false;
    }
    let body = [b"../".as_slice(), b"./", b"~/", b"/"]
        .into_iter()
        .find_map(|root| value.strip_prefix(root))
        .unwrap_or(value);
    let rooted = body.len() < value.len();

    let mut reader = ReferenceReader {
        normalized: value[..value.len() - body.len()].to_vec(),
        separators: usize::from(rooted),
        // a value inside an escaped quote is text of a quoted string, where a backslash escapes.
        shell: escaped,
        ..ReferenceReader::default()
    };
    if reader.read(body, 0, None) != Some(body.len())
        || reader.references == 0
        || !(rooted || reader.opens)
        || escapes_as_joins(value, value.len() - body.len(), &reader)
            .is_some_and(|runs| is_chunked_with_digits(&runs, REFERENCE_RUN_BREAKS))
    {
        return false;
    }
    let tally = reader.tally;
    let references_only = reader.separators == 0;
    // references alone carry no path, and a member chain among them (`${item.name}`) is a template
    // hole, not a shell reference: the value is not a path.
    let balanced = if references_only {
        !reader.members
            && tally.raw.outweigh_short_pieces()
            && tally.longest > CHUNK_LETTERS
            && tally.incoherent_names == 0
    } else {
        tally.words.outweigh_short_pieces()
    };
    // a list, a glob, an escaped path or references alone are written in coherent case, unlike a
    // random value whose mixed case splits into word-like humps.
    let coherent =
        tally.incoherent == 0 || !(references_only || escaped || reader.joins + reader.globs > 0);
    if !balanced || !coherent || tally.mixed > 1 {
        return false;
    }

    reader
        .normalized
        .split(|byte| matches!(byte, b'|' | b':'))
        .all(|item| {
            let mut end = item.len();
            while end > 0 && matches!(item[end - 1], b'/' | b'\\') {
                end -= 1;
            }
            let leaf = item[..end]
                .rsplit(|&byte| matches!(byte, b'/' | b'\\'))
                .next()
                .unwrap_or_default();
            let named: Vec<u8> = leaf
                .iter()
                .copied()
                .filter(|byte| !matches!(byte, b'*' | b'?'))
                .collect();
            // a bare glob (`*`, `.*`) names every entry of the directory before it, and a glob
            // after vocabulary words (`io.*`, `com.*`) every name under that prefix.
            let globbed = named.len() < leaf.len();
            let bare_glob = globbed
                && named
                    .split(|byte| !byte.is_ascii_alphanumeric())
                    .all(|part| part.is_empty() || is_short_word(part));
            bare_glob || is_wordy_leaf(&named, b"-_")
        })
}

/// the bytes that join the pieces of one run of a reference value.
const RUN_JOINS: &[u8] = b".-_+";

/// a value as the shell reads its escapes, every backslash dropped before the byte it escapes
/// (`ab\-cd` reads `ab-cd`, `\a\b` reads `ab`, `\\` reads `\`); `None` when it holds no backslash.
fn unescaped(value: &[u8]) -> Option<Vec<u8>> {
    if !value.contains(&b'\\') {
        return None;
    }
    let mut runs = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' && index + 1 < value.len() {
            index += 1;
        }
        runs.push(value[index]);
        index += 1;
    }
    Some(runs)
}

/// a reference value as the chunk guard reads its backslashes: each one becomes a join (`-`), so
/// the short groups on both sides of it stay one run, bar a windows directory separator, one the
/// reader read outside any reference (`ReferenceReader::directories`) in a value with no shell
/// syntax (`ReferenceReader::shell`), which ends a run as `/` does. inside an operand, a pattern,
/// a bracket expression or a quoted string, and anywhere in a value written in the shell's syntax
/// (a list, a glob, an escaped path, a message, a replacement, a command), the shell reads a
/// backslash as an escape, never as a directory separator. `root` is the length of the root the
/// reader did not read (`../`, `~/`). `None` when no backslash became a join.
fn escapes_as_joins(value: &[u8], root: usize, reader: &ReferenceReader) -> Option<Vec<u8>> {
    let mut joined = false;
    let runs = value
        .iter()
        .enumerate()
        .map(|(index, &byte)| {
            let directory = !reader.shell
                && index
                    .checked_sub(root)
                    .is_some_and(|offset| reader.directories.binary_search(&offset).is_ok());
            if byte == b'\\' && !directory {
                joined = true;
                b'-'
            } else {
                byte
            }
        })
        .collect();
    joined.then_some(runs)
}

/// whether every run of a reference value reads as words on its own (`run_reads_as_words`). a run
/// is a stretch of letters, digits and the joins `. - _ +`, cut by the path separators, the list
/// joins, the glob bytes and the reference syntax, and read without its leading and trailing joins.
/// the syntax of a reference vouches for nothing inside a name, a default, a pattern or a list
/// item, so a run long enough to be a credential is judged as one, whatever the words around it.
fn long_runs_read_as_words(value: &[u8]) -> bool {
    value
        .split(|&byte| !byte.is_ascii_alphanumeric() && !RUN_JOINS.contains(&byte))
        .all(|run| {
            let start = run
                .iter()
                .position(|byte| !RUN_JOINS.contains(byte))
                .unwrap_or(run.len());
            let end = run
                .iter()
                .rposition(|byte| !RUN_JOINS.contains(byte))
                .map_or(start, |last| last + 1);
            run_reads_as_words(&run[start..end])
        })
}

/// whether a run of letters, digits and joins is too short to be a credential, reads as a file
/// name, or reads as an identifier on its own (`wordshape::is_word_structured`:
/// `CLAUDE_CODE_MAX_CONCURRENT`), as the tier-3 rule would read it bare. a file name joins its
/// parts one join at a time, and each part is a number, or a word with at most a number closing it
/// (`x86_64-unknown-linux-gnu`, `python3.11`, `2026-09-10-release-notes.md`); a word with capitals
/// is camel case of lowercase and capitalized humps of three or more letters, an acronym of at most
/// `CHUNK_LETTERS` capitals opening a hump (`com.apple.WebKit.WebContent`, `Cookies.binarycookies`,
/// `com.apple.UIKitSystem`). a random value of `MIN_ENTROPY_LENGTH` bytes sets digits inside its
/// words and, in mixed case, capitals that close a word or humps of one or two letters.
fn run_reads_as_words(run: &[u8]) -> bool {
    if run.len() < MIN_ENTROPY_LENGTH {
        return true;
    }
    let file_name = run.split(|byte| RUN_JOINS.contains(byte)).all(|part| {
        let letters = part
            .iter()
            .position(u8::is_ascii_digit)
            .unwrap_or(part.len());
        let word = &part[..letters];
        !part.is_empty()
            && part[letters..].iter().all(u8::is_ascii_digit)
            && (!word.iter().any(u8::is_ascii_uppercase)
                || identifier_words(word).is_some_and(|humps| {
                    humps.iter().enumerate().all(|(index, hump)| {
                        (hump.len() >= 3 && hump[1..].iter().all(u8::is_ascii_lowercase))
                            // an acronym opening the next hump (`UIKit`, `HTTPStorages`).
                            || (index + 1 < humps.len()
                                && (2..=CHUNK_LETTERS).contains(&hump.len())
                                && hump.iter().all(u8::is_ascii_uppercase))
                    })
                }))
    });
    file_name || is_word_structured(run)
}

/// the length of the host that roots a module path: two or more dot-separated labels of
/// lowercase letters, digits and inner hyphens, the last one two to six letters (`github.com`,
/// `golang.org`, `gopkg.in`, `k8s.io`), then a `/`.
fn host_root_length(value: &[u8]) -> Option<usize> {
    let slash = value.iter().position(|&byte| byte == b'/')?;
    let labels: Vec<&[u8]> = value[..slash].split(|&byte| byte == b'.').collect();
    let tld = labels.last()?;
    (labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with(b"-")
                && !label.ends_with(b"-")
                && label
                    .iter()
                    .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && (2..=6).contains(&tld.len())
        && tld.iter().all(u8::is_ascii_lowercase))
    .then_some(slash + 1)
}

/// a `vN` major-version segment or piece (`v2`, `v14`).
fn is_major_version(part: &[u8]) -> bool {
    part.len() >= 2
        && part.len() <= 4
        && part[0] == b'v'
        && part[1..].iter().all(u8::is_ascii_digit)
}

/// judges a scheme-less url (`//cdn.example.com/assets/app.js`,
/// `//www.example.com/DTDs/PropertyList-1.0.dtd`), which the rooted path rule reads as a path. a
/// host vouches for nothing after it, so beyond that rule the authority carries no userinfo
/// (`//user:secret@host/…`); every part between the separators of the authority and of every
/// segment, not only the leaf, is a number or a word piece (`wordshape::wordlike_piece`) in
/// coherent case (`is_coherent`), or else a letter run no longer than a chunk (`CHUNK_LETTERS`, an
/// abbreviation such as `DTDs`) counted as a short word; the words of the whole url outweigh its
/// short pieces (`PieceWords::outweigh_short_pieces`); at most one part sets digits beside
/// chunk-sized letters; and a run of 20 or more bytes reads as words on its own
/// (`long_runs_read_as_words`). an opaque token, a base64 or base64url value, a random value of the
/// path alphabet and chunks of two or three letters under a host therefore stay reported, as a
/// credential in the authority does. groups of four or five letters pass, as they do in a rooted
/// path: a url slug of short words (`/blob/main/docs/when-to-use-this`) is such a run to
/// `wordshape::is_chunked` too, and the rooted path rule does not ask. a url holds no backslash,
/// which would cut an escaped value into one-byte parts.
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
fn is_scheme_less_url(value: &[u8]) -> bool {
    let rest = &value[2..];
    let authority = rest.split(|&byte| byte == b'/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains(&b'@')
        || rest.contains(&b'\\')
        || !long_runs_read_as_words(rest)
    {
        return false;
    }
    let mut tally = Tally::default();
    rest.split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .all(|part| {
            if part.iter().all(u8::is_ascii_digit) {
                return part.len() < MIN_ENTROPY_LENGTH;
            }
            let before = tally;
            if tally.piece(part) && is_coherent(part) {
                return true;
            }
            // an abbreviation counts as a short word outside the vocabulary.
            tally = before;
            tally.words.short += 1;
            part.len() <= CHUNK_LETTERS && part.iter().all(u8::is_ascii_alphabetic)
        })
        && tally.mixed <= 1
        && tally.words.outweigh_short_pieces()
}

/// judges a module path rooted at a host (`github.com/charmbracelet/x/ansi`, `gopkg.in/yaml.v3`,
/// `golang.org/x/sys/unix`). a host vouches for nothing after it, so every segment must read as
/// words: every part between `/ . - _ ~` is a word piece or a short number
/// (`wordshape::wordlike_piece`) in coherent case (`is_coherent`), or a single letter or a `vN`
/// major version, which count neither way; at most one part sets digits beside chunk-sized letters
/// (`k8s`, `http2`); the words of the whole value outweigh its short pieces
/// (`PieceWords::outweigh_short_pieces`); no run of short letter groups crosses the value, `/`
/// included (`wordshape::is_chunked` with no run breaks), so a payload cut by `/` into short
/// directory names is not a module path; a run of 20 or more bytes reads as words on its own
/// (`long_runs_read_as_words`); and the leaf, a trailing `vN` segment and a number closing it
/// (`http2`) set aside, is wordy. an
/// opaque segment, a base64 or base64url value cut by `/`, `-` or `_`, and short chunks under a
/// host all stay reported.
/// this is a byte-level lexical heuristic, not proof the value is non-secret.
fn is_host_path(value: &[u8]) -> bool {
    let rest = value.strip_suffix(b"/").unwrap_or(value);
    if rest.is_empty()
        || !rest.iter().all(|&byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'~')
        })
        || rest.split(|&byte| byte == b'/').any(<[u8]>::is_empty)
        || is_chunked(rest, b"")
        || !long_runs_read_as_words(rest)
    {
        return false;
    }
    let mut tally = Tally::default();
    for part in rest
        .split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
    {
        let neutral = (part.len() == 1 && part[0].is_ascii_alphabetic()) || is_major_version(part);
        if !neutral && !tally.piece(part) {
            return false;
        }
    }
    if tally.mixed > 1 || tally.incoherent > 0 || !tally.words.outweigh_short_pieces() {
        return false;
    }
    let leaf = rest
        .rsplit(|&byte| byte == b'/')
        .find(|segment| !is_major_version(segment))
        .unwrap_or_default();
    // a package named for a protocol or an encoding closes its word with a number (`http2`).
    let named = leaf
        .iter()
        .rposition(|byte| !byte.is_ascii_digit())
        .map_or(leaf, |last| &leaf[..=last]);
    is_wordy_leaf(named, b"-_")
}

/// whether every letter run of a piece is lowercase, capitalized or all capitals (`appextension`,
/// `Caches`, `HOME`, `run7`), as the words of a default, a pattern, a replacement or a counter are.
fn is_uniform_case(piece: &[u8]) -> bool {
    piece
        .split(u8::is_ascii_digit)
        .filter(|run| !run.is_empty())
        .all(|run| {
            run[1..].iter().all(u8::is_ascii_lowercase) || run.iter().all(u8::is_ascii_uppercase)
        })
}

/// whether a piece is written in coherent case, as the words of a list, a glob, a module path or a
/// snake-case name are: in uniform case (`is_uniform_case`), or camel case whose every word has
/// three letters or more (`JetBrains`, `SafariTechnologyPreview`, `HTTPStorages`). a random
/// mixed-case run splits into shorter humps.
fn is_coherent(piece: &[u8]) -> bool {
    is_uniform_case(piece)
        || identifier_words(piece).is_some_and(|words| {
            words
                .iter()
                .all(|word| word[0].is_ascii_digit() || word.len() >= 3)
        })
}

/// the words of a value read piece by piece (`wordshape::wordlike_piece`).
#[derive(Clone, Copy, Default)]
struct Tally {
    /// the words of every piece, a reference whose name reads as words counted as one long word.
    words: PieceWords,
    /// the same words with every reference name counted word by word.
    raw: PieceWords,
    /// distinct pieces, in any case, that set a digit run beside letter words of at most
    /// `CHUNK_LETTERS` (`x86`, `run7`): `VST3/$name.vst3` holds one.
    mixed: usize,
    /// the first such piece, lowercased and hashed.
    first_mixed: u64,
    /// the longest letter word met.
    longest: usize,
    /// pieces whose letter runs mix case at random (`is_coherent`).
    incoherent: usize,
    /// reference names carrying such a piece (`workspaceRoot`).
    incoherent_names: usize,
    /// the bracket ranges met (`a-z`), bounded by `MAX_BRACKET_RANGES`.
    ranges: usize,
}

impl Tally {
    /// accepts a word piece, admitting one vowel-less four-letter word per value.
    fn piece(&mut self, piece: &[u8]) -> bool {
        let Some(words) = wordlike_piece(piece) else {
            return false;
        };
        self.words.add(words);
        self.raw.add(words);
        self.incoherent += usize::from(!is_coherent(piece));
        let longest = identifier_words(piece)
            .unwrap_or_default()
            .iter()
            .filter(|word| word[0].is_ascii_alphabetic())
            .map(|word| word.len())
            .max()
            .unwrap_or(0);
        self.longest = self.longest.max(longest);
        if longest > 0 && longest <= CHUNK_LETTERS && piece.iter().any(u8::is_ascii_digit) {
            // fnv-1a over the lowercased piece, so a word repeated in another case counts once.
            let hash = piece.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                (hash ^ u64::from(byte.to_ascii_lowercase())).wrapping_mul(0x0100_0000_01b3)
            });
            if self.mixed == 0 {
                self.first_mixed = hash;
                self.mixed = 1;
            } else if hash != self.first_mixed {
                self.mixed += 1;
            }
        }
        self.words.vowelless <= 1
    }
}

/// reads the literal pieces, separators and references of a reference path, keeping a copy in
/// which each reference is replaced by `REFERENCE_WORD` for the leaf check.
#[derive(Default)]
struct ReferenceReader {
    normalized: Vec<u8>,
    references: usize,
    /// the path separators `/ \ .` and the list joins `| :` read outside any reference.
    separators: usize,
    /// the list joins and glob bytes read outside any reference.
    joins: usize,
    globs: usize,
    /// whether a reference opens the value or one of its list items.
    opens: bool,
    /// whether this reader reads an operand (a default, a replacement, a message, a command),
    /// whose pieces must be in uniform case (`is_uniform_case`).
    operand: bool,
    /// the words met anywhere in the value: literal pieces, names, defaults, patterns,
    /// replacements, subscripts and messages alike.
    tally: Tally,
    /// the offsets, in the text this reader reads, of the backslashes it read as path separators
    /// outside any reference (`%APPDATA%\Tool`); an operand reader records none.
    directories: Vec<usize>,
    /// whether the value is written in the shell's own syntax, beyond the plain references
    /// (`$NAME`, `${NAME}`, `$(NAME)`, `{name}`, `%NAME%`) a windows path is written with: an
    /// expansion operator, a subscript, a length or an indirection, a special or positional
    /// parameter, a command, arithmetic, a glob, a list, an escaped dollar or escaped quotes around
    /// the value.
    shell: bool,
    /// whether a reference holds a dotted name (`${item.name}`, `{self.root}`), the member chain
    /// of a template hole.
    members: bool,
}

impl ReferenceReader {
    /// returns the bytes read before the end of `text` or, inside a reference, before its
    /// `closing` byte; `None` when a byte, a piece or a reference is not accepted.
    fn read(&mut self, text: &[u8], depth: usize, closing: Option<u8>) -> Option<usize> {
        let mut index = 0;
        let mut item_start = true;
        while index < text.len() {
            let byte = text[index];
            if Some(byte) == closing {
                return Some(index);
            }
            let opening = std::mem::replace(&mut item_start, false);
            if matches!(byte, b'$' | b'{' | b'%') {
                index += self.reference_length(&text[index..], depth)?;
                self.references += 1;
                self.opens |= opening;
                self.normalized.extend_from_slice(REFERENCE_WORD);
            } else if byte == b'\\' && text.get(index + 1) == Some(&b'$') {
                // an escaped dollar (`\$HOME` in an echoed string) still opens a reference.
                index += 1;
                item_start = opening;
                self.shell = true;
            } else if byte.is_ascii_alphanumeric() {
                let piece_end = text[index..]
                    .iter()
                    .position(|byte| !byte.is_ascii_alphanumeric())
                    .map_or(text.len(), |offset| index + offset);
                let piece = &text[index..piece_end];
                if !self.tally.piece(piece) || (self.operand && !is_uniform_case(piece)) {
                    return None;
                }
                self.normalized.extend_from_slice(piece);
                index = piece_end;
            } else if matches!(byte, b'/' | b'\\' | b'.' | b'-' | b'_' | b'*' | b'?' | b'|' | b':')
                // a home root opens a list item (`$PATH:~/bin`) or a replacement (`/#$HOME/~`).
                || (byte == b'~' && opening)
            {
                if matches!(byte, b'/' | b'\\' | b'.' | b'|' | b':') {
                    self.separators += 1;
                }
                if byte == b'\\' && !self.operand {
                    self.directories.push(index);
                }
                self.shell |= matches!(byte, b'*' | b'?' | b'|' | b':' | b'~');
                item_start = matches!(byte, b'|' | b':');
                self.joins += usize::from(item_start);
                self.globs += usize::from(matches!(byte, b'*' | b'?'));
                self.normalized.push(byte);
                index += 1;
            } else {
                return None;
            }
        }
        closing.is_none().then_some(index)
    }

    /// the length of the reference opening `bytes`: `$NAME`, `${…}` (`expansion_length`),
    /// `$(NAME)` or another `$(command)`, `$((arithmetic))`, `$[…]`, a special or positional
    /// parameter, `{name}` or `%NAME%`. braces admit dotted names (`${ctx.root}`, `{self.root}`).
    fn reference_length(&mut self, bytes: &[u8], depth: usize) -> Option<usize> {
        match bytes {
            [b'$', b'{', rest @ ..] => self.expansion_length(rest, depth).map(|length| length + 2),
            [b'$', b'(', b'(', rest @ ..] => {
                self.shell = true;
                let length = self.arithmetic_length(rest, depth, b')')?;
                (rest.get(length..length + 2) == Some(b"))".as_slice())).then_some(length + 5)
            }
            [b'$', b'(', rest @ ..] => {
                // a make variable `$(NAME)` counts as a name; any other command is read as text.
                let before = self.tally;
                if let Some(name) = self.name_length(rest, false)
                    && rest.get(name) == Some(&b')')
                {
                    return Some(name + 3);
                }
                self.tally = before;
                self.shell = true;
                // a command that opens on a member access (`$(item.name)`, `$(item?.name)`) is a
                // template hole, not a command.
                if rest
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                {
                    let identifier = rest
                        .iter()
                        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                        .count();
                    let access = &rest[identifier..];
                    let access = access.strip_prefix(b"?").unwrap_or(access);
                    if access.first() == Some(&b'.')
                        && access
                            .get(1)
                            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                    {
                        return None;
                    }
                }
                let length = self.nested_length(rest, depth, b')')?;
                Some(length + 3)
            }
            [b'$', b'[', rest @ ..] => {
                self.shell = true;
                let length = self.arithmetic_length(rest, depth, b']')?;
                (rest.get(length) == Some(&b']')).then_some(length + 3)
            }
            // `$$`, the other special parameters and a positional one, which must not run into a
            // name: `$2y$10$…` is not a reference. a positional digit counts as a number.
            [b'$', b'$', ..] => {
                self.shell = true;
                Some(2)
            }
            [b'$', special, rest @ ..]
                if matches!(special, b'!' | b'?' | b'#' | b'@' | b'*')
                    || special.is_ascii_digit() =>
            {
                self.shell = true;
                (!rest
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    && (!special.is_ascii_digit() || self.tally.piece(&[*special])))
                .then_some(2)
            }
            [b'$', rest @ ..] => self.name_length(rest, false).map(|name| name + 1),
            [b'{', rest @ ..] => {
                let name = self.name_length(rest, true)?;
                (rest.get(name) == Some(&b'}')).then_some(name + 2)
            }
            [b'%', rest @ ..] => {
                let name = self.name_length(rest, false)?;
                (rest.get(name) == Some(&b'%')).then_some(name + 2)
            }
            _ => None,
        }
    }

    /// the length of the identifier opening `bytes`, `[A-Za-z_][A-Za-z0-9_]*`, continued across
    /// dots when `dotted`; every piece of it between `_` and `.` must be a word piece. a name whose
    /// short words all belong to the short-word vocabulary (`HOME`, `STATE_DIR`, `run_id`) reads as
    /// words and counts as one long word of the path; any other name (`XDG_CONFIG_HOME`, or short
    /// random chunks joined by `_`) adds its words as they are.
    fn name_length(&mut self, bytes: &[u8], dotted: bool) -> Option<usize> {
        let mut length = 0;
        loop {
            if !bytes
                .get(length)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                return None;
            }
            length += bytes[length..]
                .iter()
                .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                .unwrap_or(bytes.len() - length);
            if !(dotted && bytes.get(length) == Some(&b'.')) {
                break;
            }
            self.members = true;
            length += 1;
        }
        let before = self.tally;
        if !bytes[..length]
            .split(|byte| matches!(byte, b'_' | b'.'))
            .filter(|piece| !piece.is_empty())
            .all(|piece| self.tally.piece(piece))
        {
            return None;
        }
        let (after, prior) = (self.tally.words, before.words);
        let mut words = PieceWords {
            long: after.long - prior.long,
            short: after.short - prior.short,
            known: after.known - prior.known,
            vowelless: after.vowelless - prior.vowelless,
            numbers: after.numbers - prior.numbers,
        };
        if words.short == words.known {
            words = PieceWords {
                long: 1,
                vowelless: words.vowelless,
                numbers: words.numbers,
                ..Default::default()
            };
        }
        self.tally.words = prior;
        self.tally.words.add(words);
        // a name may be camel case; only `incoherent_names` records it.
        self.tally.incoherent_names += usize::from(self.tally.incoherent > before.incoherent);
        self.tally.incoherent = before.incoherent;
        (self.tally.words.vowelless <= 1).then_some(length)
    }

    /// the length of a `${…}` expansion after its `${`, closing brace included: an optional `#`
    /// length or `!` indirection, a name, a positional digit run or a special parameter, an
    /// optional subscript (`[@]`, `[*]`, or an arithmetic index such as `[$i]` or `[2]`), then the
    /// closing brace or one of `EXPANSION_OPERATORS` and its operand.
    fn expansion_length(&mut self, text: &[u8], depth: usize) -> Option<usize> {
        // `${#}` is the argument count, not a length.
        let prefix = matches!(text.first(), Some(b'#' | b'!')) && text.get(1) != Some(&b'}');
        // only `${NAME}` is a plain reference: a length, an indirection, a special or positional
        // parameter, a subscript and every operator are the shell's own syntax.
        self.shell |= prefix
            || !text
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
        let mut index = usize::from(prefix);
        index += match *text.get(index)? {
            // a positional digit run counts as a number (`${10}`).
            digit if digit.is_ascii_digit() => {
                let digits = text[index..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
                if !self.tally.piece(&text[index..index + digits]) {
                    return None;
                }
                digits
            }
            b'@' | b'*' | b'#' | b'?' | b'$' | b'!' => 1,
            _ => self.name_length(&text[index..], true)?,
        };
        if text.get(index) == Some(&b'[') {
            self.shell = true;
            index += 1;
            index += match text.get(index..index + 2) {
                Some(b"@]" | b"*]") => 1,
                _ => self.arithmetic_length(&text[index..], depth, b']')?,
            };
            if text.get(index) != Some(&b']') {
                return None;
            }
            index += 1;
        }
        if prefix {
            // `${!prefix*}` and `${!prefix@}` list the names sharing a prefix.
            if text[0] == b'!' && matches!(text.get(index), Some(b'*' | b'@')) {
                index += 1;
            }
            return (text.get(index) == Some(&b'}')).then_some(index + 1);
        }
        if text.get(index) == Some(&b'}') {
            return Some(index + 1);
        }
        self.shell = true;
        let &(operator, operand) = EXPANSION_OPERATORS
            .iter()
            .find(|(operator, _)| text[index..].starts_with(operator))?;
        // `${item?.name}` is optional chaining in a template hole, not an error message that
        // opens on a dot.
        if depth >= MAX_REFERENCE_DEPTH || text[index..].starts_with(b"?.") {
            return None;
        }
        index += operator.len();
        let rest = &text[index..];
        index += match operand {
            Operand::Text => self.nested_length(rest, depth, b'}')?,
            Operand::Pattern => self.pattern_length(rest, depth, b"}")?,
            Operand::Substitution => {
                let pattern = self.pattern_length(rest, depth, b"/}")?;
                if rest.get(pattern) == Some(&b'/') {
                    pattern + 1 + self.nested_length(&rest[pattern + 1..], depth, b'}')?
                } else {
                    pattern
                }
            }
            Operand::Arithmetic => self.arithmetic_length(rest, depth, b'}')?,
        };
        (text.get(index) == Some(&b'}')).then_some(index + 1)
    }

    /// reads the text of a default, an alternative, a message, a replacement or a command one
    /// level deeper, up to its `closing` byte, adding its words to this value's.
    fn nested_length(&mut self, text: &[u8], depth: usize, closing: u8) -> Option<usize> {
        if depth >= MAX_REFERENCE_DEPTH {
            return None;
        }
        let mut nested = ReferenceReader {
            tally: self.tally,
            operand: true,
            ..ReferenceReader::default()
        };
        let length = nested.read(text, depth + 1, Some(closing))?;
        self.tally = nested.tally;
        self.members |= nested.members;
        Some(length)
    }

    /// the length of a glob pattern before the first of its `terminators`: word pieces in uniform
    /// case (`is_uniform_case`), the glob bytes, punctuation, bracket expressions, backslash escapes,
    /// quotes and nested references. an escaped letter reads as a one-letter piece.
    fn pattern_length(&mut self, text: &[u8], depth: usize, terminators: &[u8]) -> Option<usize> {
        let mut index = 0;
        while index < text.len() {
            let byte = text[index];
            if terminators.contains(&byte) {
                return Some(index);
            }
            if byte.is_ascii_alphanumeric() {
                let end = text[index..]
                    .iter()
                    .position(|byte| !byte.is_ascii_alphanumeric())
                    .map_or(text.len(), |offset| index + offset);
                let piece = &text[index..end];
                if !self.tally.piece(piece) || !is_uniform_case(piece) {
                    return None;
                }
                index = end;
                continue;
            }
            index += match byte {
                b'\\' => self.escape(*text.get(index + 1)?, false)?,
                b'[' => 1 + self.bracket_length(&text[index + 1..])?,
                b'$' if text.get(index + 1) == Some(&b'\'') => {
                    1 + self.quoted_length(&text[index + 1..], true)?
                }
                b'$' => {
                    if depth >= MAX_REFERENCE_DEPTH {
                        return None;
                    }
                    self.reference_length(&text[index..], depth + 1)?
                }
                b'"' | b'\'' | b'/' | b'.' | b'-' | b'_' | b':' | b'|' | b'~' | b'@' | b'+'
                | b',' | b'=' | b'!' | b'*' | b'?' | b'^' | b'%' | b'#' => 1,
                _ => return None,
            };
        }
        None
    }

    /// the length of an arithmetic expression, a subscript or an offset before its unbalanced
    /// `closing` byte: names, numbers, references, operators and balanced parentheses.
    fn arithmetic_length(&mut self, text: &[u8], depth: usize, closing: u8) -> Option<usize> {
        let mut index = 0;
        let mut open = 0_usize;
        while index < text.len() {
            let byte = text[index];
            if byte == closing && open == 0 {
                return Some(index);
            }
            if byte.is_ascii_alphabetic() || byte == b'_' {
                // a counter or an index is named in uniform case (`cursor`, `history_idx`).
                let length = self.name_length(&text[index..], false)?;
                if !text[index..index + length]
                    .split(|&byte| byte == b'_')
                    .all(is_uniform_case)
                {
                    return None;
                }
                index += length;
            } else if byte.is_ascii_digit() {
                // a number ends where its word does: `99abc` is no number and no name.
                let end = text[index..]
                    .iter()
                    .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                    .map_or(text.len(), |offset| index + offset);
                let number = &text[index..end];
                if !number.iter().all(u8::is_ascii_digit) || !self.tally.piece(number) {
                    return None;
                }
                index = end;
            } else if byte == b'$' {
                if depth >= MAX_REFERENCE_DEPTH {
                    return None;
                }
                index += self.reference_length(&text[index..], depth + 1)?;
            } else {
                match byte {
                    b'(' => open += 1,
                    b')' => open = open.checked_sub(1)?,
                    b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'=' | b'!' | b'&' | b'|'
                    | b'^' | b'?' | b':' | b',' | b'~' => {}
                    _ => return None,
                }
                index += 1;
            }
        }
        None
    }

    /// the two bytes of a backslash escape whose escaped byte is `escaped`. an escaped letter or
    /// digit is a byte of the text, not syntax (`\a` reads `a`), so it counts as a piece of its own
    /// (`Tally::piece`), as an unescaped one-letter piece would; inside ansi-c quoting (`ansi`) a
    /// control escape (`CONTROL_ESCAPES`, `\n`) names a control byte and counts neither way. an
    /// escaped punctuation byte (`\]`, `\-`, `\$`) is punctuation.
    fn escape(&mut self, escaped: u8, ansi: bool) -> Option<usize> {
        let control = ansi && CONTROL_ESCAPES.contains(&escaped);
        (!escaped.is_ascii_alphanumeric() || control || self.tally.piece(&[escaped])).then_some(2)
    }

    /// the length of a bracket expression after its `[`, closing bracket included: an optional
    /// `!` or `^`, then POSIX classes (`[:space:]`), ranges (`a-z`), backslash escapes
    /// (`escape`), quoted strings (`'\n'`, `$'\n\t'`) and punctuation. a letter or digit stands
    /// only as the end of a range, and a range runs up within one class (`a-z`, `A-F`, `0-9`); at
    /// most `MAX_BRACKET_RANGES` of them in the whole value, so their endpoints, which count
    /// neither way, never carry a token. every escaped letter or digit is a piece of the value.
    fn bracket_length(&mut self, text: &[u8]) -> Option<usize> {
        let start = usize::from(matches!(text.first(), Some(b'!' | b'^')));
        let mut index = start;
        while index < text.len() {
            let byte = text[index];
            if byte == b']' && index > start {
                return Some(index + 1);
            }
            index += if byte == b'[' && text.get(index + 1) == Some(&b':') {
                let name = &text[index + 2..];
                let end = name.windows(2).position(|pair| pair == b":]")?;
                if !POSIX_CLASSES.contains(&&name[..end]) {
                    return None;
                }
                end + 4
            } else if byte == b'\\' {
                self.escape(*text.get(index + 1)?, false)?
            } else if byte == b'$' && text.get(index + 1) == Some(&b'\'') {
                1 + self.quoted_length(&text[index + 1..], true)?
            } else if byte == b'\'' {
                self.quoted_length(&text[index..], false)?
            } else if byte.is_ascii_alphanumeric() {
                let last = *text.get(index + 2)?;
                let class = |endpoint: u8| {
                    (
                        endpoint.is_ascii_lowercase(),
                        endpoint.is_ascii_uppercase(),
                        endpoint.is_ascii_digit(),
                    )
                };
                self.tally.ranges += 1;
                if text[index + 1] != b'-'
                    || class(byte) != class(last)
                    || byte >= last
                    || self.tally.ranges > MAX_BRACKET_RANGES
                {
                    return None;
                }
                3
            } else if byte.is_ascii_graphic() {
                1
            } else {
                return None;
            };
        }
        None
    }

    /// the length of a single-quoted string opening `text` (`'\n'`), closing quote included: its
    /// body holds backslash escapes (`escape`, `ansi` for `$'…'`) and punctuation only.
    fn quoted_length(&mut self, text: &[u8], ansi: bool) -> Option<usize> {
        let mut index = 1;
        while index < text.len() {
            index += match text[index] {
                b'\'' => return Some(index + 1),
                b'\\' => self.escape(*text.get(index + 1)?, ansi)?,
                byte if byte.is_ascii_graphic() && !byte.is_ascii_alphanumeric() => 1,
                _ => return None,
            };
        }
        None
    }
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'\\' | b'.' | b'-' | b'_' | b'~' | b':' | b'@' | b'+' | b'%' | b','
        )
}

fn has_wordy_path_leaf(value: &[u8], pointer: bool) -> bool {
    let mut end = value.len();
    while end > 0 && matches!(value[end - 1], b'/' | b'\\') {
        end -= 1;
    }
    let value = &value[..end];
    let mut segments = value
        .split(|&byte| matches!(byte, b'/' | b'\\'))
        .filter(|segment| !segment.is_empty())
        .peekable();

    while let Some(segment) = segments.next() {
        let is_leaf = segments.peek().is_none();
        // a json schema keyword such as `$defs` opens its pointer segment with `$`.
        let segment = if pointer {
            segment.strip_prefix(b"$").unwrap_or(segment)
        } else {
            segment
        };
        // this documented heuristic is not proof a value is non-secret: any separator-free
        // run of min_entropy_length bytes rejects the exemption, except a word-structured one in a
        // json pointer (`#/definitions/PaymentMethodDescriptorConfig`); only leaf words may exempt it.
        if segment
            .split(|&byte| matches!(byte, b'-' | b'_' | b'.'))
            .any(|part| {
                part.len() >= MIN_ENTROPY_LENGTH
                    && !(pointer && crate::scanner::wordshape::is_word_structured(part))
            })
        {
            return false;
        }

        if is_leaf {
            return is_wordy_leaf(segment, b"-_");
        }
    }

    false
}

/// whether a leaf segment carries a word of its own once its extensions are set aside. trailing dot
/// parts that are short alphanumeric (`.gz`, `.a7B2q`) or all alphabetic of any length are popped
/// while more than one part remains, so `.credentials`, `.keystore` or `.production` after an opaque
/// stem supplies no wordiness while `secrets.production` and `README.markdown` stay wordy through
/// their stem. a remaining part is wordy with a piece of three or more letters between the
/// `piece_separators`, or as a run of short lowercase words (`oh-my-pi`).
fn is_wordy_leaf(leaf: &[u8], piece_separators: &[u8]) -> bool {
    let mut parts: Vec<_> = leaf
        .split(|&byte| byte == b'.')
        .filter(|part| !part.is_empty())
        .collect();

    while parts.len() > 1
        && parts.last().is_some_and(|part| {
            ((1..=5).contains(&part.len()) && part.iter().all(u8::is_ascii_alphanumeric))
                || part.iter().all(u8::is_ascii_alphabetic)
        })
    {
        parts.pop();
    }

    parts.iter().any(|part| {
        part.split(|byte| piece_separators.contains(byte))
            .any(|piece| piece.len() >= 3 && piece.iter().all(u8::is_ascii_alphabetic))
            || is_short_word_run(part, piece_separators)
    })
}

/// two to `MAX_SHORT_RUN` short lowercase words joined by the `piece_separators`, each carrying a
/// vowel (including y), as in `oh-my-pi`: no piece reaches three letters, yet none is an opaque
/// chunk. the bound keeps such a leaf under the 20 bytes an opaque value needs, so two-letter chunks
/// of a random value never make it wordy.
fn is_short_word_run(part: &[u8], piece_separators: &[u8]) -> bool {
    const MAX_SHORT_RUN: usize = 4;

    let mut pieces = 0;
    part.split(|byte| piece_separators.contains(byte))
        .all(|piece| {
            pieces += 1;
            !piece.is_empty()
                && piece.iter().all(u8::is_ascii_lowercase)
                && piece
                    .iter()
                    .any(|byte| matches!(byte, b'a' | b'e' | b'i' | b'o' | b'u' | b'y'))
        })
        && (2..=MAX_SHORT_RUN).contains(&pieces)
}

/// calculate entropy only over hex charset [0-9a-fA-F]
/// returns None if the string contains non-hex characters
#[allow(dead_code)]
pub fn hex_entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return Some(0.0);
    }
    // verify all chars are hex
    if !data.iter().all(|&b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(charset_entropy(data, 16))
}

/// calculate entropy only over base64 charset [A-Za-z0-9+/=]
/// returns None if the string contains non-base64 characters
#[allow(dead_code)]
pub fn base64_entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return Some(0.0);
    }
    if !data.iter().all(|&b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    }) {
        return None;
    }
    Some(charset_entropy(data, 64))
}

/// calculate entropy only over alphanumeric charset [A-Za-z0-9]
/// returns None if the string contains non-alphanumeric characters
#[allow(dead_code)]
pub fn alphanumeric_entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return Some(0.0);
    }
    if !data.iter().all(|&b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(charset_entropy(data, 62))
}

/// calculate entropy relative to a given charset size.
/// this uses the observed frequency distribution (shannon entropy)
/// but the result is meaningful in the context of the expected charset.
#[allow(dead_code)]
fn charset_entropy(data: &[u8], _charset_size: usize) -> f64 {
    // use standard shannon entropy - the charset_size parameter is kept
    // for potential future normalization but standard entropy is what
    // tools like gitleaks and trufflehog use
    shannon_entropy(data)
}

/// check if a byte slice passes the entropy threshold for scanning.
/// returns true if the data has sufficient entropy (is suspicious).
/// secrets shorter than MIN_ENTROPY_LENGTH skip the entropy check
/// (they pass through) since the regex+keyword match already provides
/// confidence and short strings have inherently lower entropy.
pub fn passes_entropy_check(data: &[u8], threshold: f64) -> bool {
    if data.len() < MIN_ENTROPY_LENGTH {
        return true;
    }
    shannon_entropy(data) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn entropy_two_chars_equal() {
        // "abababab" - exactly 2 chars, equal frequency -> entropy = 1.0
        let e = shannon_entropy(b"abababab");
        assert!((e - 1.0).abs() < 0.001);
    }

    #[test]
    fn entropy_high_randomness() {
        // a string with many distinct characters should have high entropy
        let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
        let e = shannon_entropy(data);
        assert!(e > 3.5, "expected high entropy, got {}", e);
    }

    #[test]
    fn entropy_low_repetition() {
        let data = b"aaaaaaaabbbbbbbb";
        let e = shannon_entropy(data);
        assert!(e < 1.5, "expected low entropy, got {}", e);
    }

    #[test]
    fn hex_entropy_valid() {
        let data = b"a1b2c3d4e5f6a7b8c9d0";
        let e = hex_entropy(data);
        assert!(e.is_some());
        assert!(e.unwrap() > 2.0);
    }

    #[test]
    fn hex_entropy_invalid_chars() {
        let data = b"not-hex-string!!";
        assert!(hex_entropy(data).is_none());
    }

    #[test]
    fn base64_entropy_valid() {
        let data = b"SGVsbG8gV29ybGQhIFRoaXM=";
        let e = base64_entropy(data);
        assert!(e.is_some());
        assert!(e.unwrap() > 2.0);
    }

    #[test]
    fn base64_entropy_with_url_safe() {
        // base64url uses - and _ instead of + and /
        let data = b"SGVsbG8tV29ybGRf";
        let e = base64_entropy(data);
        assert!(e.is_some());
    }

    #[test]
    fn alphanumeric_entropy_valid() {
        let data = b"aB3dEf7hIj1kLmN0pQrS";
        let e = alphanumeric_entropy(data);
        assert!(e.is_some());
        assert!(e.unwrap() > 3.0);
    }

    #[test]
    fn alphanumeric_entropy_invalid() {
        let data = b"has-dashes-and_underscores";
        assert!(alphanumeric_entropy(data).is_none());
    }

    #[test]
    fn passes_entropy_check_short_strings_pass_through() {
        // short strings skip entropy check (pass through)
        assert!(passes_entropy_check(b"short", 3.0));
    }

    #[test]
    fn passes_entropy_check_below_threshold() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaa";
        assert!(!passes_entropy_check(data, 3.0));
    }

    #[test]
    fn passes_entropy_check_above_threshold() {
        let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
        assert!(passes_entropy_check(data, 3.0));
    }

    #[test]
    fn path_shape_contract() {
        fn opaque_stem(len: usize) -> Vec<u8> {
            (0..len)
                .map(|index| {
                    if index % 3 == 0 {
                        b'0' + ((index * 7 + 3) % 10) as u8
                    } else {
                        let letter = ((index * 11 + 5) % 26) as u8;
                        if index % 2 == 0 {
                            b'A' + letter
                        } else {
                            b'a' + letter
                        }
                    }
                })
                .collect()
        }

        fn hex_stem(len: usize) -> Vec<u8> {
            let mut stem = Vec::with_capacity(len);
            let mut counter = 0u8;

            while stem.len() < len {
                stem.extend(format!("{counter:x}").bytes());
                counter = counter.wrapping_add(1);
            }

            stem.truncate(len);
            stem
        }

        fn path_with_stem(prefix: &[u8], stem: &[u8], suffix: &[u8]) -> Vec<u8> {
            let mut path = Vec::with_capacity(prefix.len() + stem.len() + suffix.len());
            path.extend_from_slice(prefix);
            path.extend_from_slice(stem);
            path.extend_from_slice(suffix);
            path
        }

        let task_path = b"/Users/example/work/rust/sekretbarilo/.claude/backlog/tasks/2026-09-08-redact-claude-masks-plain-absolute-files-9zVZK8LgjmLKdXZG.md";
        let cases: &[(&[u8], bool)] = &[
            (task_path, true),
            (b"~/work/some-project/target/release/build-output.log", true),
            (b"./a/b/config-file.toml", true),
            (b"../x/y/data-2026.csv", true),
            (br"C:\Users\example\some-tool\cache-index.db", true),
            (br"C:\Users\example\some-tool\cache-index.db\", true),
            (br"C:\\Users\\example\\some-tool\\cache-index.db", true),
            (b"/Users/example/work/rust/sekretbarilo/.claude/backlog/tasks/2026-09-08-redact-claude-masks-plain-absolute-files-9zVZK8LgjmLKdXZG.md/", true),
            (b"/opt/ABCDEFGHIJKLMNOPQRSTUVWXYZ", false),
            (b"/x/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", false),
            (b"/data/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef.md", false),
            (b"/data/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef/", false),
            (b"/mnt/secrets/aB3dEf7hIj1kLmN0pQrStUvWxYz5A/token.txt", false),
            (b"/tmp/cache/sess_aB3dEf7hIj1kLmN0pQrStUvWxYz5A6bC", false),
            (b"/mnt/secrets/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef/token.txt", false),
            (b"/tmp/cache/sess-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
            (b"/data/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef.tar.gz", false),
            // "internationalization" is exactly min_entropy_length bytes; this is an accepted heuristic cost.
            (b"/srv/internationalization/notes.txt", false),
            (b"abc/DEF+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
            (b"some/dir/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
            (b"//user:aB3dEf7hIj1kLmN0pQrStUvWxYz5A6bC@host/path", false),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
        ];

        for &(value, expected) in cases {
            assert_eq!(is_path_shaped(value), expected, "{value:?}");
        }

        let opaque_19 = opaque_stem(19);
        let opaque_20 = opaque_stem(20);
        let opaque_25 = opaque_stem(25);
        let generated_cases = [
            (path_with_stem(b"/var/lib/", &opaque_19, b".key"), false),
            (path_with_stem(b"/var/lib/", &opaque_20, b".key"), false),
            (
                path_with_stem(b"/var/cache/nginx/", &hex_stem(18), b".tmp"),
                false,
            ),
            (
                path_with_stem(b"/opt/tools/", &opaque_19, b".tar.gz"),
                false,
            ),
            (
                path_with_stem(b"/opt/tools/", &opaque_19, b".spec.d.ts"),
                false,
            ),
            (path_with_stem(b"/x/", &opaque_20, b"/"), false),
            (path_with_stem(b"/a/b/", &opaque_19, b".txt"), false),
            (path_with_stem(b"/a/b/", &opaque_20, b".txt"), false),
            // the raw 20-byte stem is disqualified before extension stripping.
            (b"/a/b/internationalization.txt".to_vec(), false),
            (path_with_stem(b"#/definitions/", &opaque_25, b""), false),
            (b"/home/user/notes.txt".to_vec(), true),
            (b"/etc/app/.env.local".to_vec(), true),
            (b"/var/log/nginx/my-app.log".to_vec(), true),
            (b"/srv/data/archive-2026.tar.gz".to_vec(), true),
            (b"/a/b/some.long.name.here.txt".to_vec(), true),
            (b"/etc/nginx/conf.d/".to_vec(), true),
            (b"/a/b/README".to_vec(), true),
            (b"/a/b/name.".to_vec(), true),
            (
                b"#/definitions/PaymentMethod/properties/identifier".to_vec(),
                true,
            ),
            (b"#/components/schemas/AddressValidation".to_vec(), true),
            (b"#/x".to_vec(), false),
            (b"abc#/definitions/foo/bar".to_vec(), false),
            (b"##/definitions/foo/bar".to_vec(), false),
            // a word-structured pointer segment of 20+ bytes is a word; a two-letter leaf is not.
            (
                b"#/definitions/PaymentMethodDescriptorConfig/properties/identifier".to_vec(),
                true,
            ),
            (
                b"#/definitions/PaymentMethodDescriptorConfig/properties/id".to_vec(),
                false,
            ),
            // a 20+ byte pointer segment below four camel words keeps the veto.
            (b"#/$defs/WebhookPayloadEnvelope".to_vec(), false),
            (b"#/definitions/internationalization/name".to_vec(), false),
            // a json schema keyword opens a pointer segment; `$` elsewhere is not a path byte.
            (b"#/$defs/retry_policy".to_vec(), true),
            (b"#/$defs/WebhookRetryPayloadEnvelope".to_vec(), true),
            (b"#/components/$defs/AddressCheck".to_vec(), true),
            (path_with_stem(b"#/$defs/", &opaque_25, b""), false),
            (path_with_stem(b"#/$defs/", &opaque_19, b""), false),
            (b"#/de$fs/retry_policy".to_vec(), false),
            (b"#/$$defs/retry_policy".to_vec(), false),
            (b"/etc/$defs/retry_policy".to_vec(), false),
            // an opaque short ancestor remains exempt because only leaves use the wordy check.
            (path_with_stem(b"/data/", &opaque_19, b"/token.txt"), true),
            (
                path_with_stem(b"https://user:", &opaque_stem(32), b"@host.example/path"),
                false,
            ),
            // an all-alphabetic extension of any length supplies no wordiness to an opaque stem.
            (
                path_with_stem(b"/var/lib/", &opaque_19, b".credentials"),
                false,
            ),
            (
                path_with_stem(b"/var/lib/", &opaque_19, b".keystore"),
                false,
            ),
            (
                path_with_stem(b"/srv/app/", &opaque_19, b".production"),
                false,
            ),
            (
                path_with_stem(b"/srv/app/", &opaque_19, b".credentials.production"),
                false,
            ),
            (
                path_with_stem(b"/srv/app/", &hex_stem(19), b".Keystore"),
                false,
            ),
            (b"/etc/app/secrets.production".to_vec(), true),
            (b"/srv/docs/README.markdown".to_vec(), true),
            (b"/etc/app/.env.production".to_vec(), true),
            (b"/etc/app/database.credentials.json".to_vec(), true),
            // a leaf of short lowercase words, each with a vowel, is wordy.
            (b"/srv/build/Q4/workspace/oh-my-pi".to_vec(), true),
            (b"/opt/vendor/toolkit/go/is-it-up".to_vec(), true),
            (path_with_stem(b"/data/", &opaque_19, b"/ab-cd"), false),
            (path_with_stem(b"/data/", &opaque_19, b"/OH-MY"), false),
            (path_with_stem(b"/data/", &opaque_19, b"/oh"), false),
        ];

        for (value, expected) in generated_cases {
            assert_eq!(is_path_shaped(&value), expected, "{value:?}");
        }
    }

    /// a generated opaque run: alternating case with a digit every third byte, no word structure.
    fn opaque(len: usize, seed: usize) -> String {
        (0..len)
            .map(|index| {
                let byte = if index % 3 == 0 {
                    b'0' + ((index * 7 + seed) % 10) as u8
                } else {
                    let letter = ((index * 11 + seed) % 26) as u8;
                    if index % 2 == 0 {
                        b'A' + letter
                    } else {
                        b'a' + letter
                    }
                };
                char::from(byte)
            })
            .collect()
    }

    /// a generated single-case letter run with five-consonant stretches, no word structure.
    fn consonant_run(len: usize, seed: usize) -> String {
        (0..len)
            .map(|index| char::from(b'a' + ((index * 11 + seed) % 26) as u8))
            .collect()
    }

    #[test]
    fn reference_rooted_contract() {
        for (index, value) in [
            "$HOME/.cache/example-tool",
            "$HOME/Library/Caches/example-tool",
            "${WORKSPACE}/target/release/build-output.log",
            "${ARCHIVE%.*}.extraction.log",
            "${ARCHIVE##*/}.backup.log",
            "${XDG_CONFIG_HOME:-$HOME/.config}/example/settings.toml",
            "${TMPDIR:-/tmp}/example-2026/run-logs",
            "$(BUILD_ROOT)/objects/release-universal",
            "{project_root}/logs/{run_name}.jsonl",
            "{self.root}/reports/summary.html",
            "%APPDATA%\\ExampleTool\\user-settings.json",
            "/Library/Preferences/$bundle_id.plist",
            "~/.local/share/$tool_name/state.json",
            "$HOME/Library/HTTPStorages/example.binarycookies",
            "$STATE_DIR/2026/diagnostic.log",
            "$STATE_DIR/v-2/diagnostic.log",
            "$CARGO_HOME/bin/example-cli-v2",
            "${ctx.workspace}/${ctx.name}.lock",
            // a name and its default are words of the path, and a vocabulary word such as `com`
            // is a word, not a short group.
            "${XDG_CACHE_HOME:-$HOME/.cache}/example",
            "${LOG_DIR}/deploy-${HOSTNAME}-${RUN_ID}.log",
            "$HOME/Library/Preferences/com.apple.dock.plist",
            "$HOME/Library/WebKit/com.apple.WebKit.WebContent/$bundle_id",
            // the parameter expansion grammar: substitutions, subscripts, lengths, messages,
            // nested defaults, command and arithmetic substitution, special parameters.
            "${expanded_path/#\\~/$HOME}",
            "${display_config/#$HOME/~}",
            "${bundle_display_name//[$'\\n\\r\\t']/}",
            "${bundle_display_name//|/-}",
            "${cleaned_selection//[[:space:]]/}",
            "${cleanup_protected_patterns[@]}",
            "${#cleanup_protected_patterns[*]}",
            "${history_stack[$history_idx]}",
            "${menu_options[cursor]:--1}",
            "${bundle_identifier%.appextension}",
            "${EDITOR:-${VISUAL:-vim}}",
            "${list[@]}/example.log",
            "${STATE_DIR:?missing}/diagnostic.log",
            "${archive_name:0:12}/extracted.log",
            "$(basename)/release-notes.md",
            "$((${#history_stack[@]}-1))/snapshot.json",
            "${TMPDIR:-/tmp}/spinner_stop_$$_$session.flag",
            "\\$HOME/.config/example-tool/settings.json",
            "\\\"$HOME/.claude/hooks/account-swap-hook.sh\\\"",
            // globs and `|` or `:` lists between wordy pieces.
            "$HOME/Library/Caches/*.log",
            "$HOME/Library/Caches/com.example.helper*",
            "$HOME/.cache/example/*",
            "$HOME/Library/Caches|backups|com.example.*:org.example.*",
            "$HOME/.cargo/bin:$PATH",
            "/usr/libexec/bin:/usr/local/bin:$PATH",
            "cache|$HOME/.cache|user_backups",
        ]
        .iter()
        .enumerate()
        {
            assert!(is_reference_rooted(value.as_bytes()), "accepted[{index}]");
        }

        // short random chunks joined by `_` outnumber the words of the path in a component, a
        // default and a name; pronounceable groups of five letters read as chunked.
        let short: Vec<String> = consonant_run(36, 7)
            .as_bytes()
            .chunks(3)
            .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
            .collect();
        let short = short.join("_");
        let groups: Vec<String> = (0..5)
            .map(|group| {
                (0..5)
                    .map(|index| {
                        let seed = group * 5 + index;
                        char::from(if index % 2 == 0 {
                            b"bcdfghjklmnpqrstvwxz"[(seed * 7 + 3) % 20]
                        } else {
                            b"aeiou"[(seed * 3 + 1) % 5]
                        })
                    })
                    .collect()
            })
            .collect();
        let groups = groups.join("-");
        for value in [
            format!("$VAR/{short}"),
            format!("${{VAR:-{short}}}/settings.log"),
            format!("${{{short}}}/settings.log"),
            format!("$VAR/{groups}"),
            format!("${{VAR:-{groups}}}/settings.log"),
            format!("$HOME/settings.{}", groups.replace('-', ".")),
        ] {
            assert!(!is_reference_rooted(value.as_bytes()), "{value}");
        }

        // a bare backslash separates windows directories only in a path of plain references; in an
        // operand, a pattern, a command, a glob, a list or an escaped value it is an escape, and
        // the short groups on both sides of it stay one run.
        let escaped = groups.replace('-', "\\");
        for value in [
            format!("${{STATE_DIR:?{escaped}}}/diagnostic.log"),
            format!("${{STATE_DIR:-{escaped}}}/diagnostic.log"),
            format!("${{STATE_DIR:+{escaped}}}/diagnostic.log"),
            format!("${{expanded_path/#\\~/{escaped}}}"),
            format!("${{ARCHIVE%{escaped}}}.log"),
            format!("$({escaped})/objects/release"),
            format!("$HOME/Library/{escaped}/*.log"),
            format!("$HOME/.cargo/bin:{escaped}"),
            format!("{escaped}:$HOME/.local/bin"),
            format!("\\$HOME/{escaped}/settings.json"),
            format!("\\\"$HOME/.config/{escaped}\\\""),
            format!("${{STATE_DIR:?missing}}\\{escaped}\\diagnostic.log"),
        ] {
            assert!(!is_reference_rooted(value.as_bytes()), "{value}");
        }
        for value in [
            "%APPDATA%\\ExampleTool\\user-settings.json",
            "${LOCALAPPDATA}\\ExampleTool\\cache\\settings.json",
            "$(BUILD_ROOT)\\objects\\release\\example.log",
        ] {
            assert!(is_reference_rooted(value.as_bytes()), "{value}");
        }

        let long = opaque(32, 3);
        let short = opaque(19, 5);
        let left = opaque(16, 7);
        let right = opaque(15, 9);
        let letters = consonant_run(32, 3);
        let rejected = [
            format!("$STATE_DIR/{long}"),
            format!("$STATE_DIR/{long}.log"),
            format!("$STATE_DIR/{short}"),
            format!("$STATE_DIR/{short}/diagnostic.log"),
            format!("$STATE_DIR/{left}_{right}/diagnostic.log"),
            format!("$STATE_DIR/diagnostic-{left}.{right}.log"),
            format!(
                "$STATE_DIR/{}_{}/diagnostic.log",
                &letters[..16],
                &letters[16..]
            ),
            // a name opens on a letter, so each opaque name below does too.
            format!("${{x{long}}}/diagnostic.log"),
            format!("${{STATE_DIR:-{long}}}/diagnostic.log"),
            format!("${{STATE_DIR:-/tmp/{short}}}/diagnostic.log"),
            format!("${{STATE_DIR%{short}}}/diagnostic.log"),
            format!("${{x{left}_{right}}}/diagnostic.log"),
            format!("$x{short}/diagnostic.log"),
            format!("$(x{short})/diagnostic.log"),
            format!("{{x{short}}}/diagnostic.log"),
            format!("%x{short}%\\Tool\\settings.json"),
            format!("${{ctx.x{short}}}/diagnostic.log"),
            format!("/Library/Caches/{short}/$bundle_id.plist"),
            format!("{short}/$HOME/diagnostic.log"),
            "$STATE_DIR/KpZrTwXyQm/diagnostic.log".to_owned(),
            // one vowel-less four-letter word passes, as `html` does; a second one does not.
            "$STATE_DIR/xlsx/report.html".to_owned(),
            "${STATE_DIR:-/tmp/xlsx}/report.html".to_owned(),
            "/usr/local/share/example/tool.conf".to_owned(),
            "$HOME".to_owned(),
            "${HOME}${USER}".to_owned(),
            "https://$HOST/example/path".to_owned(),
            // known gap: references alone whose words are all chunk-sized carry no word a cut
            // value could not.
            "${path/#\\~/$HOME}".to_owned(),
            "$(command arg)/example.log".to_owned(),
            "$2y$10$example/path.log".to_owned(),
            "$2y/example/path.log".to_owned(),
            // a member chain alone is a template hole, optional chaining and a command opening on
            // a member are never references.
            "${settings.workspace.location}".to_owned(),
            "{settings.workspace}{session.location}".to_owned(),
            "${WORKSPACE:-${settings.location}}".to_owned(),
            "${settings?.workspace}/diagnostic.log".to_owned(),
            "$(settings.workspace)/diagnostic.log".to_owned(),
            "$(settings?.workspace)".to_owned(),
            "{}/logs/output.log".to_owned(),
            "${A:-${B:-${C:-${D:-${E:-/tmp}}}}}/x.log".to_owned(),
            // an expansion cut short by the capture is not read to its end.
            "${#history_stack[@".to_owned(),
            "$((${#history_stack[@".to_owned(),
            "$(truncate_display_width".to_owned(),
            "${HOME}/${history_stack[@]})".to_owned(),
            // an opaque piece in every new position.
            format!("${{path/#{short}/$HOME}}"),
            format!("${{display_name//{short}/}}"),
            format!("${{config_path/#\\~/{short}}}"),
            format!("${{history_stack[{short}]}}"),
            format!("${{#x{short}[@]}}"),
            format!("${{STATE_DIR:?{short}}}/run.log"),
            format!("$HOME/Library/{short}*"),
            format!("$HOME/Library/Caches|{short}|backups"),
            format!("$HOME/.cargo/bin:{short}"),
            format!("{short}:$PATH"),
            format!("$({short})/run.log"),
            format!("$((x{short}+1))/run.log"),
            format!("$[{short}]/run.log"),
            format!("\\\"$HOME/{long}\\\""),
            format!("\\$HOME/{long}"),
            format!("${{TMPDIR:-/tmp}}/{short}_$$.log"),
            // a bracket expression holds no word.
            "${display_name//[example]/}".to_owned(),
            // chunks that each set digits beside short letters.
            "$HOME/cache/abe12-fix3-rum7/settings.log".to_owned(),
        ];
        for (index, value) in rejected.iter().enumerate() {
            assert!(!is_reference_rooted(value.as_bytes()), "rejected[{index}]");
        }
    }

    #[test]
    fn random_base64_values_are_never_keyed_relative_paths() {
        const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32
        };
        let mut accepted = 0;
        for sample in 0..20_000 {
            let length = 20 + (next() % 45) as usize;
            let mut value: Vec<u8> = (0..length)
                .map(|_| BASE64[(next() % 64) as usize])
                .collect();
            // every other sample is cut into short chunks by extra slashes, as a path is.
            if sample % 2 == 0 {
                for _ in 0..length / 5 {
                    let at = next() as usize % length;
                    value[at] = b'/';
                }
            }
            accepted += usize::from(is_keyed_relative_path(&value));
        }
        assert_eq!(accepted, 0);
    }

    #[test]
    fn keyed_relative_path_contract() {
        for value in [
            "provider/abc-5-large:medium",
            ".agent/tasks/ab-12345-run7-migration/02-summary",
            "docs/plans/hud-refresh-flow.md",
            "Sources/AppKit/WindowStore+Layout.swift:restoreFrame",
            "build/dist/widget-1.4.2/lib/widget.core.esm.production.min.js",
            "backlog/2026/12345678/review-notes.md",
            "agentCoreTests/SessionStoreTests",
            "tools/Python3/runtime-notes.md",
        ] {
            assert!(is_keyed_relative_path(value.as_bytes()), "{value}");
        }

        let id = opaque(16, 4);
        let long = opaque(32, 6);
        let letters = consonant_run(24, 3);
        let rejected = [
            format!("task/{id}/integrator/lead"),
            format!("task/{}/integrator/lead", &id[..9]),
            format!("docs/{long}/notes.md"),
            format!("docs/notes.md:{long}"),
            format!("docs/{}/notes.md", &letters[..20]),
            // two vowel-less four-letter chunks; one alone would pass, as `html` does.
            format!(
                "task/{}-{}-{}-{}-{}/lead",
                &letters[..4],
                &letters[4..8],
                &letters[8..12],
                &letters[12..16],
                &letters[16..20]
            ),
            "run7/ab12/notes".to_owned(),
            // a mixed part holds one digit run between letter runs of one case each.
            "docs/v1beta1/release-notes.md".to_owned(),
            "docs/a9bCde/release-notes.md".to_owned(),
            "docs/123456789/notes.md".to_owned(),
            "docs/plans/x9".to_owned(),
            "./hitlr-request.a7B2q9".to_owned(),
            "../docs/plans/notes.md".to_owned(),
            "/docs/plans/notes.md".to_owned(),
            "~/docs/plans/notes.md".to_owned(),
            "docs//plans/notes.md".to_owned(),
            "docs/plans/".to_owned(),
            "hud-refresh-flow.md".to_owned(),
            "https://host/docs/notes.md".to_owned(),
            "docs/plans/notes@2x.png".to_owned(),
        ];
        for value in rejected {
            assert!(!is_keyed_relative_path(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn keyed_path_words_and_dated_names_contract() {
        for value in [
            "Tests/<ExampleClass>/<method_name>/fixtures.json",
            "docs/<workspace>/<task-id>/manifest.md",
            ":!docs/drafts/release-planning-notes.md",
            ":^docs/drafts/release-planning-notes.md",
            "rules/example-peer-protocol.md's",
            "2026-09-10-docs-site-redesign.md",
            "docs/plans/2026-09-10-docs-site-redesign.md",
        ] {
            assert!(is_keyed_relative_path(value.as_bytes()), "{value}");
        }
        for value in [
            "2026-09-10-docs-site-redesign.md",
            "2026-07-04-release-planning-notes.md",
            "2026-09-26-python3-migration-notes.md",
        ] {
            assert!(is_relative_id_path(value.as_bytes()), "{value}");
        }

        let long = opaque(32, 6);
        let short = opaque(16, 2);
        let letters = consonant_run(16, 5);
        let rejected = [
            // a placeholder is words shorter than a credential, paired, and apart from its
            // neighbours.
            format!("docs/<{long}>/notes.md"),
            format!("docs/<{short}>/notes.md"),
            "docs/<Class/notes.md".to_owned(),
            "docs/x<Class>/notes.md".to_owned(),
            "docs/<>/notes.md".to_owned(),
            "docs/<example.class>/notes.md".to_owned(),
            format!(":!docs/{long}.md"),
            format!("docs/{long}.md's"),
            // a date before an opaque tail, several mixed parts, short chunks or a digit inside
            // a word.
            format!("2026-09-10-{long}.md"),
            format!("2026-09-10-{short}.md"),
            "2026-09-10-abc12-def34-ghi56.md".to_owned(),
            format!(
                "2026-09-10-{}-{}-{}-{}.md",
                &letters[..4],
                &letters[4..8],
                &letters[8..12],
                &letters[12..]
            ),
            "2026-09-10-docs9site-redesign.md".to_owned(),
            "2026-13-10-docs-site-redesign.md".to_owned(),
        ];
        for (index, value) in rejected.iter().enumerate() {
            assert!(
                !is_keyed_relative_path(value.as_bytes()) && !is_relative_id_path(value.as_bytes()),
                "rejected[{index}]"
            );
        }
    }

    #[test]
    fn host_path_contract() {
        for value in [
            "github.com/charmbracelet/x/ansi",
            "golang.org/x/sys/unix",
            "gopkg.in/yaml.v3",
            "k8s.io/client-go/kubernetes",
            "sigs.k8s.io/controller-runtime/pkg/client",
            "github.com/example/widget-toolkit/v2/renderer",
            "github.com/example/widget-service/internal/transport/http2",
        ] {
            assert!(is_path_shaped(value.as_bytes()), "{value}");
        }

        let long = opaque(32, 6);
        let short = opaque(16, 2);
        let groups: Vec<String> = (0..5).map(|group| consonant_run(4, group * 5)).collect();
        let rejected = [
            format!("github.com/example/{long}"),
            format!("github.com/{short}/widget"),
            format!("github.com/example/{}", groups.join("-")),
            format!("github.com/{}", groups.join("/")),
            "github.com/example/abc12-def34-tool".to_owned(),
            "github.com/example/release9notes-final-xq-build".to_owned(),
            "github.com/example/Widget-toolKiT".to_owned(),
        ];
        for (index, value) in rejected.iter().enumerate() {
            assert!(!is_path_shaped(value.as_bytes()), "rejected[{index}]");
        }
    }

    #[test]
    fn scheme_less_url_contract() {
        for value in [
            "//www.example.com/DTDs/PropertyList-1.0.dtd",
            "//doc.rust-lang.org/std/collections/struct.HashMap.html",
            "//cdn.example.com/assets/widget-toolkit/widget.bundle.min.js",
            "//stackoverflow.com/questions/12345678/how-to-read-a-file",
        ] {
            assert!(is_path_shaped(value.as_bytes()), "{value}");
        }

        // the twins of the shapes above with an opaque token, a base64url-like value or a random
        // value of the path alphabet under the host; and userinfo in the authority.
        let long = opaque(32, 6);
        let rejected = [
            format!("//cdn.example.com/{long}"),
            format!("//cdn.example.com/assets/{long}/app.js"),
            format!(
                "//cdn.example.com/{}-{}_{}",
                &long[..9],
                &long[9..19],
                &long[19..]
            ),
            format!(
                "//cdn.example.com/assets/{}-{}/app.js",
                &long[..9],
                &long[9..18]
            ),
            "//cdn.example.com/assets/kqvx9brtz-plmn7wdfg-release/app.js".to_owned(),
            "//user:example@host.example.com/docs/notes.html".to_owned(),
            "///srv/opaque/notes.html".to_owned(),
        ];
        for (index, value) in rejected.iter().enumerate() {
            let expected = index == rejected.len() - 1;
            assert_eq!(
                is_path_shaped(value.as_bytes()),
                expected,
                "rejected[{index}]"
            );
        }
    }

    #[test]
    fn long_runs_read_as_file_names_or_identifiers() {
        for run in [
            "account-swap-hook.sh",
            "x86_64-unknown-linux-gnu",
            "python3.11-site-packages",
            "2026-09-10-release-notes.md",
            "com.apple.WebKit.WebContent",
            "Cookies.binarycookies",
            "com.apple.UIKitSystemHelper",
            "CLAUDE_CODE_MAX_CONCURRENT",
            "HTTPStorages-cache-index",
        ] {
            assert!(run_reads_as_words(run.as_bytes()), "{run}");
        }
        let long = opaque(24, 1);
        for (index, run) in [
            long.as_str(),
            "release9notes-final-xq-build",
            "release--notes-xq-generator.md",
            "SessionStoreHTTP-xq-release-notes",
            "AbCdEfGhIjKl-release-notes",
            "Release.Notes.KpZrTwXyQm-final",
        ]
        .iter()
        .enumerate()
        {
            assert!(!run_reads_as_words(run.as_bytes()), "rejected[{index}]");
        }
    }

    #[test]
    fn case_and_mixed_piece_contract() {
        for piece in ["appextension", "Caches", "HOME", "run7", "x86"] {
            assert!(is_uniform_case(piece.as_bytes()), "{piece}");
            assert!(is_coherent(piece.as_bytes()), "{piece}");
        }
        for piece in [
            "JetBrains",
            "SafariTechnologyPreview",
            "HTTPStorages",
            "appExtension",
        ] {
            assert!(!is_uniform_case(piece.as_bytes()), "{piece}");
            assert!(is_coherent(piece.as_bytes()), "{piece}");
        }
        for piece in ["KpZrTw", "aBcd", "iCloud"] {
            assert!(!is_coherent(piece.as_bytes()), "{piece}");
        }
        // an operand is written in uniform case, a glob leaf may be camel case.
        assert!(!is_reference_rooted(b"${bundle_identifier%.appExtension}"));
        assert!(is_reference_rooted(b"$HOME/Library/Caches/JetBrains*"));
        // a mixed piece counts once whatever its case; two distinct ones do not pass.
        assert!(is_reference_rooted(
            b"$HOME/Library/Audio/Plug-Ins/VST3/$bundle_name.vst3"
        ));
        assert!(!is_reference_rooted(
            b"$HOME/Library/Audio/VST3/$bundle_name.au2"
        ));
    }
}
