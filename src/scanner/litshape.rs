// literal-shape recognition (symbol tables, format templates) for exemption-layer filtering

use super::entropy::MIN_ENTROPY_LENGTH;
use super::wordshape::{
    PieceWords, has_wordlike_vowels, identifier_words, is_chunked_with_digits, is_leading_acronym,
    is_short_word, is_word_structured, wordlike_piece,
};

/// recognizes a lookup set of punctuation, such as a delimiter table tested with `contains`.
/// a backslash escape is one element and every other byte is one element. the value qualifies
/// when no element repeats, no two unescaped alphanumeric elements are adjacent, and at most one
/// element in eight is an unescaped alphanumeric. every credential alphabet draws at least 62 of
/// its at most 94 graphic bytes from [A-Za-z0-9], so a random 20-byte token holds two or fewer
/// alphanumerics with probability below 4e-7, and longer tokens less often still.
pub fn is_symbol_table(value: &[u8]) -> bool {
    let mut seen = [false; 512];
    let mut elements = 0_usize;
    let mut alphanumerics = 0_usize;
    let mut previous_alphanumeric = false;
    let mut index = 0;
    while index < value.len() {
        let (slot, alphanumeric, width) = if value[index] == b'\\' {
            let Some(&escaped) = value.get(index + 1) else {
                return false;
            };
            (256 + usize::from(escaped), false, 2)
        } else {
            (
                usize::from(value[index]),
                value[index].is_ascii_alphanumeric(),
                1,
            )
        };
        if seen[slot] || (alphanumeric && previous_alphanumeric) {
            return false;
        }
        seen[slot] = true;
        elements += 1;
        alphanumerics += usize::from(alphanumeric);
        previous_alphanumeric = alphanumeric;
        index += width;
    }
    elements > 0 && alphanumerics * 8 <= elements
}

/// recognizes a format template with at least one placeholder: brace fields (`{}`, `{0}`,
/// `{name:>8}`, `{:?}`), printf conversions (`%s`, `%-10s`, `%(name)s`, `%v`, and `$%(price).2f`
/// with a currency sign), `${name}` substitutions and interpolation holes (`template_hole_end`),
/// with `{{`, `}}` and `%%` as escapes. every literal segment between them must carry no opaque
/// payload: it is word structured, or it reads as words, short numbers, escapes and separators. a
/// value may open with the `spec}` tail of a named field, which an assignment capture hands over
/// when it takes `name:` of `{name:spec}` as its key; that tail alone does not make the value a
/// template. a string body with no placeholder whose escapes are its only structure is judged by
/// `is_escaped_text`. the literal text of either form, read with every placeholder, hole and
/// escape as a separator, holds no run of four or more short letter groups
/// (`wordshape::is_chunked_with_digits`): a random token cut into chunks and joined by placeholders
/// or escapes reads as such a run. a value that holds a token the base grammar did not read, a hole
/// or a currency conversion (`Token::fresh`), was no template before those tokens existed, so the
/// same guard also reads the whole value, every name and hole expression in place: a token cut into
/// members, arguments or names reads as such a run too. a value made of the base placeholders
/// alone keeps their names out of the guard, as before, so `{user}@{host}:{port}/{db}` stays a
/// template.
pub fn is_format_template(value: &[u8]) -> bool {
    is_placeholder_template(value) || is_escaped_text(value)
}

fn is_placeholder_template(value: &[u8]) -> bool {
    let mut placeholders = 0_usize;
    let mut fresh = false;
    let mut segment_start = spec_end(value, 0)
        .filter(|&end| end > 0 && value.get(end) == Some(&b'}'))
        .map_or(0, |end| end + 1);
    // the literal text, one separator standing for each token and escape.
    let mut text = Vec::with_capacity(value.len());
    // the whole value, each token in place between separators and each escape a separator.
    let mut whole = Vec::with_capacity(value.len() + 8);
    whole.extend_from_slice(&value[..segment_start]);
    whole.push(b' ');
    let mut index = segment_start;
    while index < value.len() {
        // an escaped backslash is segment text; it never opens a `\(` hole.
        if value[index] == b'\\' && value.get(index + 1) == Some(&b'\\') {
            index += 2;
            continue;
        }
        let Some(token) = format_token(value, index) else {
            index += 1;
            continue;
        };
        let segment = &value[segment_start..index];
        if !is_plain_segment(segment) {
            return false;
        }
        push_unescaped(segment, &mut text);
        text.push(b' ');
        push_unescaped(segment, &mut whole);
        whole.push(b' ');
        whole.extend_from_slice(&value[index..token.end]);
        whole.push(b' ');
        placeholders += usize::from(token.placeholder);
        fresh |= token.fresh;
        segment_start = token.end;
        index = token.end;
    }
    let segment = &value[segment_start..];
    push_unescaped(segment, &mut text);
    push_unescaped(segment, &mut whole);
    placeholders > 0
        && is_plain_segment(segment)
        && !is_chunked_with_digits(&text, b"")
        && !(fresh && is_chunked_with_digits(&whole, b""))
}

/// appends a segment with each backslash escape read as a separator, so the letter of `\n` never
/// joins the word after it.
fn push_unescaped(segment: &[u8], text: &mut Vec<u8>) {
    let mut index = 0;
    while index < segment.len() {
        if segment[index] == b'\\' {
            text.push(b' ');
            index += 2;
        } else {
            text.push(segment[index]);
            index += 1;
        }
    }
}

/// a format token of a template.
struct Token {
    end: usize,
    /// a placeholder rather than an escape (`{{`, `}}`, `%%`).
    placeholder: bool,
    /// a token the base grammar did not read, a hole or a currency conversion: `\(`, `#`, `(` and
    /// `$` are no bytes of a plain segment, so a value holding one was no template before.
    fresh: bool,
}

/// returns the format token at `start`.
fn format_token(value: &[u8], start: usize) -> Option<Token> {
    let token = |end: usize, placeholder: bool, fresh: bool| Token {
        end,
        placeholder,
        fresh,
    };
    match (value[start], value.get(start + 1)) {
        (b'{', Some(b'{')) | (b'}', Some(b'}')) | (b'%', Some(b'%')) => {
            Some(token(start + 2, false, false))
        }
        (b'{', _) => brace_field_end(value, start + 1).map(|end| token(end, true, false)),
        (b'%', _) => conversion_end(value, start + 1).map(|end| token(end, true, false)),
        // a currency sign before a conversion is literal text of the template.
        (b'$', Some(b'%')) => conversion_end(value, start + 2).map(|end| token(end, true, true)),
        (b'$', Some(b'{')) => name_end(value, start + 2)
            .filter(|&end| value.get(end) == Some(&b'}'))
            .map(|end| token(end + 1, true, false))
            .or_else(|| template_hole_end(value, start).map(|end| token(end, true, true))),
        (b'\\' | b'#' | b'(', _) => {
            template_hole_end(value, start).map(|end| token(end, true, true))
        }
        _ => None,
    }
}

/// the deepest call nesting an interpolation hole may hold.
const MAX_HOLE_DEPTH: usize = 4;

/// the most opaque short words one hole expression may hold (`opaque_short_words`), the bound the
/// syntax step puts on a member chain: word-shaped members and at most one short opaque name, as
/// `\(rect.origin.x)` or `${format(x)}`.
const MAX_OPAQUE_SHORT_WORDS: usize = 1;

/// end of an interpolation hole opened at `start`: swift `\(expr)` and raw `\#(expr)`, ruby and
/// crystal `#{expr}`, javascript and kotlin `${expr}`, and nushell `($name.field)`. the hole holds
/// one expression (`hole_expression_end`); a nushell hole opens with a `$` variable, so a
/// parenthesized word in prose is no hole. its identifiers read as words, and at most
/// `MAX_OPAQUE_SHORT_WORDS` of their words are short and outside the vocabulary: a random token
/// cut into members or arguments of one to three letters (`\(qz.vk.rt…)`) leaves one per member.
/// the expression is no literal text, but the chunk guard of a template reads it
/// (`is_placeholder_template`).
fn template_hole_end(value: &[u8], start: usize) -> Option<usize> {
    let (open, close) = match (value[start], value.get(start + 1)) {
        (b'\\', Some(b'(')) => (start + 2, b')'),
        (b'\\', Some(b'#')) => {
            let hashes = value[start + 1..]
                .iter()
                .take_while(|&&byte| byte == b'#')
                .count();
            if value.get(start + 1 + hashes) != Some(&b'(') {
                return None;
            }
            (start + 2 + hashes, b')')
        }
        (b'#' | b'$', Some(b'{')) => (start + 2, b'}'),
        (b'(', Some(b'$')) => (start + 1, b')'),
        _ => return None,
    };
    let end = hole_expression_end(value, open, 0)?;
    (value.get(end) == Some(&close)
        && opaque_short_words(&value[open..end]) <= MAX_OPAQUE_SHORT_WORDS)
        .then_some(end + 1)
}

/// counts the words of one to three letters outside the short-word vocabulary among the
/// identifiers of an expression, read at `_`, camel humps and digits (`wordshape::identifier_words`):
/// `x`, `qz` and the `ab` of `ab12`, but not `id`, `URL` or `tab`.
fn opaque_short_words(expression: &[u8]) -> usize {
    expression
        .split(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        .filter_map(identifier_words)
        .flatten()
        .filter(|word| word[0].is_ascii_alphabetic() && word.len() < 4 && !is_short_word(word))
        .count()
}

/// end of an expression inside a hole: an operand (an identifier, `$name` or `$0`, or a number of
/// at most four digits) followed by any number of member accesses (`.name`, `?.name`, `!.name`),
/// calls with balanced parentheses whose arguments are expressions, optionally labelled
/// (`prefix(8)`, `join(separator: sep)`), and forced unwraps (`!`). single spaces may pad the
/// operand. every identifier reads as words (`identifier_end`).
fn hole_expression_end(value: &[u8], start: usize, depth: usize) -> Option<usize> {
    if depth > MAX_HOLE_DEPTH {
        return None;
    }
    let mut index = skip_space(value, start);
    if value.get(index) == Some(&b'$') {
        index = digits_end(value, index + 1, 2).or_else(|| identifier_end(value, index + 1))?;
    } else if let Some(end) = digits_end(value, index, 4) {
        index = end;
    } else {
        index = identifier_end(value, index)?;
    }
    loop {
        match (value.get(index), value.get(index + 1)) {
            (Some(b'('), _) => index = call_end(value, index + 1, depth + 1)?,
            // a member name, or a tuple element (`pair.0`).
            (Some(b'.'), _) => {
                index =
                    identifier_end(value, index + 1).or_else(|| digits_end(value, index + 1, 2))?;
            }
            (Some(b'?' | b'!'), Some(b'.')) => index = identifier_end(value, index + 2)?,
            (Some(b'!'), _) => index += 1,
            _ => break,
        }
    }
    Some(skip_space(value, index))
}

/// end of a call's argument list, entered after `(`: zero or more expressions, each optionally
/// labelled `name:`, separated by `,`, closed by `)`.
fn call_end(value: &[u8], start: usize, depth: usize) -> Option<usize> {
    let mut index = skip_space(value, start);
    if value.get(index) == Some(&b')') {
        return Some(index + 1);
    }
    loop {
        index = skip_space(value, index);
        if let Some(end) = identifier_end(value, index)
            && value.get(end) == Some(&b':')
            && value.get(end + 1) != Some(&b':')
        {
            index = end + 1;
        }
        index = hole_expression_end(value, index, depth)?;
        match value.get(index) {
            Some(b',') => index += 1,
            Some(b')') => return Some(index + 1),
            _ => return None,
        }
    }
}

fn skip_space(value: &[u8], start: usize) -> usize {
    start + usize::from(value.get(start) == Some(&b' '))
}

/// end of one identifier of a hole: a letter or `_`, then letters, digits and `_`, shorter than
/// MIN_ENTROPY_LENGTH, each `_`-separated part a word unit (camel case allowed) or at most four digits.
fn identifier_end(value: &[u8], start: usize) -> Option<usize> {
    let tail = value.get(start..)?;
    if !tail
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let length = tail
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    (length < MIN_ENTROPY_LENGTH
        && tail[..length]
            .split(|&byte| byte == b'_')
            .all(|part| part.is_empty() || is_word_unit(part, true)))
    .then_some(start + length)
}

/// the escapes a string body carries: a quote, a control character or a backslash.
fn is_body_escape(byte: u8) -> bool {
    matches!(byte, b'"' | b'\'' | b'n' | b't' | b'r' | b'\\')
}

/// recognizes a string body whose only structure is its escapes, such as a line of a config
/// snippet embedded in a string (`\"feature-flag-rollout\"\nenabled`) or `\n`-separated records
/// (`name=value\nstate=running`): judged after unescaping, it is words joined by separators, `=`
/// and `,`. there is at least one escape of a quote or a control character, every other byte is a
/// letter, a digit, a separator or a join, no `://` or `@` appears, and the alphanumeric pieces
/// read as words or short numbers (`wordshape::wordlike_piece`, or a word-structured piece of
/// MIN_ENTROPY_LENGTH or more), at least three of them words of four or more letters, that
/// outweigh the short pieces among them (`PieceWords::outweigh_short_pieces`). every word of one
/// to three letters belongs to the short-word vocabulary, as in an identifier: random letters cut
/// by escapes and separators leave short pieces outside it. a line of the body, the text between
/// two escapes, of `MIN_ENTROPY_LENGTH` bytes or more is word structured as it stands
/// (`is_word_structured`), so a token that fills a line is exempted no more often than alone.
fn is_escaped_text(value: &[u8]) -> bool {
    let mut escapes = 0;
    let mut text = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte == b'\\' {
            let Some(&escaped) = value.get(index + 1) else {
                return false;
            };
            if !is_body_escape(escaped) {
                return false;
            }
            escapes += usize::from(escaped != b'\\');
            // an escape separates the words around it.
            text.push(b' ');
            index += 2;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'-' | b'_' | b'/' | b':' | b'=' | b','))
        {
            return false;
        }
        text.push(byte);
        index += 1;
    }
    if escapes == 0
        || text.windows(3).any(|window| window == b"://")
        || is_chunked_with_digits(&text, b"")
    {
        return false;
    }
    if text
        .split(|&byte| byte == b' ')
        .any(|line| line.len() >= MIN_ENTROPY_LENGTH && !is_word_structured(line))
    {
        return false;
    }
    let mut words = PieceWords::default();
    for piece in text
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
    words.long >= 3 && words.short == words.known && words.outweigh_short_pieces()
}

/// `{` [position | name] [`!` conversion] [`:` spec] `}`, entered after the opening brace.
fn brace_field_end(value: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    if value.get(index).is_some_and(u8::is_ascii_digit) {
        index = digits_end(value, index, 3)?;
    } else if let Some(end) = name_end(value, index) {
        index = end;
    }
    if value.get(index) == Some(&b'!') && matches!(value.get(index + 1), Some(b'r' | b's' | b'a')) {
        index += 2;
    }
    if value.get(index) == Some(&b':') {
        index = spec_end(value, index + 1)?;
    }
    (value.get(index) == Some(&b'}')).then_some(index + 1)
}

/// [[fill] align] [sign] [`#`] [`0`] [width] [grouping] [`.` precision] [type], where width
/// and precision are counts, `name$` or `N$`, and precision may also be `*`.
fn spec_end(value: &[u8], start: usize) -> Option<usize> {
    let is_align = |byte: Option<&u8>| matches!(byte, Some(b'<' | b'^' | b'>' | b'='));
    let mut index = start;
    if value
        .get(index)
        .is_some_and(|&byte| byte != b'{' && byte != b'}')
        && is_align(value.get(index + 1))
    {
        index += 2;
    } else if is_align(value.get(index)) {
        index += 1;
    }
    for flag in [b"+-".as_slice(), b"#", b"0"] {
        if value.get(index).is_some_and(|byte| flag.contains(byte)) {
            index += 1;
        }
    }
    index = count_end(value, index).unwrap_or(index);
    if matches!(value.get(index), Some(b',' | b'_')) {
        index += 1;
    }
    if value.get(index) == Some(&b'.') {
        index += 1;
        index = if value.get(index) == Some(&b'*') {
            index + 1
        } else {
            count_end(value, index)?
        };
    }
    if matches!(value.get(index), Some(b'x' | b'X')) && value.get(index + 1) == Some(&b'?') {
        index += 2;
    } else if value
        .get(index)
        .is_some_and(|byte| b"?bcdeEfFgGnosxXp%".contains(byte))
    {
        index += 1;
    }
    Some(index)
}

/// a count is a number of at most four digits or a name, either optionally followed by `$`;
/// a name needs the `$`.
fn count_end(value: &[u8], start: usize) -> Option<usize> {
    if let Some(end) = digits_end(value, start, 4) {
        return Some(end + usize::from(value.get(end) == Some(&b'$')));
    }
    let end = name_end(value, start)?;
    (value.get(end) == Some(&b'$')).then_some(end + 1)
}

/// `%` [`(` name `)`] [flags] [width] [`.` precision] [length] conversion, entered after `%`.
fn conversion_end(value: &[u8], start: usize) -> Option<usize> {
    const CONVERSIONS: &[u8] = b"diouxXeEfFgGcspvTtqUbwr";
    const LENGTHS: [&[u8]; 9] = [b"hh", b"ll", b"h", b"l", b"L", b"q", b"j", b"z", b"t"];
    let mut index = start;
    if value.get(index) == Some(&b'(') {
        index = name_end(value, index + 1)?;
        if value.get(index) != Some(&b')') {
            return None;
        }
        index += 1;
    }
    while value
        .get(index)
        .is_some_and(|byte| matches!(byte, b'-' | b'+' | b'#' | b'0'))
    {
        index += 1;
    }
    if value.get(index) == Some(&b'*') {
        index += 1;
    } else if let Some(end) = digits_end(value, index, 3) {
        index = end;
    }
    if value.get(index) == Some(&b'.') {
        index += 1;
        if value.get(index) == Some(&b'*') {
            index += 1;
        } else if let Some(end) = digits_end(value, index, 3) {
            index = end;
        }
    }
    if value
        .get(index)
        .is_some_and(|byte| CONVERSIONS.contains(byte))
    {
        return Some(index + 1);
    }
    let length = LENGTHS
        .iter()
        .find(|length| value[index..].starts_with(length))?;
    let index = index + length.len();
    value
        .get(index)
        .is_some_and(|byte| CONVERSIONS.contains(byte))
        .then_some(index + 1)
}

/// end of a run of one to `limit` ascii digits.
fn digits_end(value: &[u8], start: usize, limit: usize) -> Option<usize> {
    let count = value
        .get(start..)?
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    (1..=limit).contains(&count).then_some(start + count)
}

/// end of a dotted identifier whose parts read as words and whose length stays below
/// MIN_ENTROPY_LENGTH, so an opaque token cannot pass as a placeholder name.
fn name_end(value: &[u8], start: usize) -> Option<usize> {
    let tail = value.get(start..)?;
    if !tail
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let length = tail
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        .count();
    let name = &tail[..length];
    (length < MIN_ENTROPY_LENGTH
        && name
            .split(|byte| matches!(byte, b'_' | b'.'))
            .all(|part| part.is_empty() || is_word_unit(part, true)))
    .then_some(start + length)
}

/// a segment is word structured, or a sequence of word units, escapes and separators in which
/// adjacent separators repeat one byte or join a path with `.` and `/`. word structure is judged
/// without the separators that join the segment to its placeholders, so that the template adds no
/// separator the standalone wordshape step would not see. the path predicates of the entropy
/// module are not consulted: they admit a rooted base64 token with inner slashes.
fn is_plain_segment(segment: &[u8]) -> bool {
    let joint = |byte: &u8| matches!(byte, b'.' | b'-' | b'_' | b'/' | b':');
    let start = segment
        .iter()
        .position(|byte| !joint(byte))
        .unwrap_or(segment.len());
    let end = segment
        .iter()
        .rposition(|byte| !joint(byte))
        .map_or(start, |last| last + 1);
    // a `|` segment goes through the unit grammar below: wordshape's alternation rule admits
    // short id-shaped items, which a template would splice out of a random printable value
    let trimmed = &segment[start..end];
    if !trimmed.contains(&b'|') && is_word_structured(trimmed) {
        return true;
    }
    let mut previous_separator = None;
    let mut index = 0;
    while index < segment.len() {
        let byte = segment[index];
        if byte.is_ascii_alphanumeric() {
            let length = segment[index..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric())
                .count();
            if !is_word_unit(&segment[index..index + length], false) {
                return false;
            }
            previous_separator = None;
            index += length;
        } else if byte == b'\\' {
            if !matches!(
                segment.get(index + 1),
                Some(b'n' | b't' | b'r' | b'0' | b'\\' | b'"' | b'\'')
            ) {
                return false;
            }
            previous_separator = None;
            index += 2;
        } else if matches!(
            byte,
            b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b',' | b'|' | b'@' | b'?' | b'&'
        ) {
            if previous_separator.is_some_and(|previous| {
                previous != byte && !(b"./".contains(&previous) && b"./".contains(&byte))
            }) {
                return false;
            }
            previous_separator = Some(byte);
            index += 1;
        } else {
            return false;
        }
    }
    true
}

/// an alphanumeric run below MIN_ENTROPY_LENGTH bytes reads as a word: a number of at most four
/// digits, a lowercase word optionally followed by such a number, an uppercase acronym, or a
/// capitalized word; `camel` also admits camel-case words, whose acronym parts are words of the
/// short-word vocabulary (`windowID`) or a framework prefix opening the name (`NSUserName`,
/// `wordshape::is_leading_acronym`). a lowercase or uppercase word of four or more bytes, and every
/// capitalized or camel-case part, needs a vowel and at most four consecutive consonants, except
/// that uppercase acronyms of two to five bytes need none.
fn is_word_unit(run: &[u8], camel: bool) -> bool {
    if run.len() >= MIN_ENTROPY_LENGTH {
        return false;
    }
    let letters = run
        .iter()
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    let (word, number) = run.split_at(letters);
    if number.len() > 4 || !number.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if word.iter().all(u8::is_ascii_lowercase) {
        return word.len() < 4 || has_wordlike_vowels(word);
    }
    if !number.is_empty() {
        return false;
    }
    if word.iter().all(u8::is_ascii_uppercase) {
        return (2..=5).contains(&word.len()) || has_wordlike_vowels(word);
    }
    let Some(parts) = identifier_words(word) else {
        return false;
    };
    if parts.len() > 1 && !camel {
        return false;
    }
    parts.iter().enumerate().all(|(index, part)| {
        if part.len() >= 2 && part.iter().all(u8::is_ascii_uppercase) {
            // an acronym of the short-word vocabulary (`windowID`, `requestURL`), or one that opens
            // the name from the closed framework-prefix list (`CGRectGetWidth`), as the camel rule
            // of wordshape reads it: any run of capitals there would be a payload position.
            if index == 0 {
                is_leading_acronym(part)
            } else {
                is_short_word(part)
            }
        } else {
            part.len() >= 2
                && part[1..].iter().all(u8::is_ascii_lowercase)
                && has_wordlike_vowels(part)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{is_format_template, is_symbol_table};

    const SAMPLES: usize = 20_000;
    const LENGTHS: [usize; 5] = [20, 24, 32, 40, 64];

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

        fn string(&mut self, alphabet: &[u8], length: usize) -> Vec<u8> {
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

    fn base62_with(extra: &[u8]) -> Vec<u8> {
        base62().into_iter().chain(extra.iter().copied()).collect()
    }

    fn punctuation() -> Vec<u8> {
        (b'!'..=b'~')
            .filter(|byte| !byte.is_ascii_alphanumeric())
            .collect()
    }

    /// the encodings of the rule's recall contract and two password alphabets: letters, digits
    /// and the shifted-digit symbols, and the whole graphic range a generator with every symbol
    /// class draws from.
    fn credential_alphabets() -> [(&'static str, Vec<u8>); 10] {
        [
            ("hex-lower", b"0123456789abcdef".to_vec()),
            ("hex-upper", b"0123456789ABCDEF".to_vec()),
            ("base32", (b'A'..=b'Z').chain(b'2'..=b'7').collect()),
            ("base36-lower", (b'0'..=b'9').chain(b'a'..=b'z').collect()),
            (
                "base58",
                base62()
                    .into_iter()
                    .filter(|byte| !b"0OIl".contains(byte))
                    .collect(),
            ),
            ("base62", base62()),
            ("base64", base62_with(b"+/")),
            ("base64url", base62_with(b"-_")),
            ("strong-password", base62_with(b"!@#$%^&*")),
            ("printable", (b'!'..=b'~').collect()),
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

    #[test]
    fn delimiter_tables_are_symbol_tables() {
        let punctuation = punctuation();
        for table in [
            br#"()[]{}<>,;:?!&*=\\'\"`|."#.as_slice(),
            b"(,=:[!&|?{};+-*%<>~^",
            &punctuation,
            br#"\t\n\r\0\\\"'()[]{}<>|;&"#,
        ] {
            assert!(is_symbol_table(table), "{}", skeleton(table));
        }
    }

    #[test]
    fn symbol_tables_are_sets_with_sparse_single_alphanumerics() {
        // sixteen elements carry two alphanumerics at most, fifteen carry one.
        assert!(is_symbol_table(b"()[]{}<>,;:?!a&b"));
        assert!(!is_symbol_table(b"()[]{}<>,;:?a&b"));
        assert!(!is_symbol_table(b"()[]{}<>,;:?!&*=|ab"));
        assert!(!is_symbol_table(b"()[]{}<>,;:?!&*=|.("));
        assert!(!is_symbol_table(br"()[]{}<>,;:?!&*=|.\"));
        assert!(!is_symbol_table(br"\x41\x42\x43\x44\x45"));
        assert!(!is_symbol_table(b""));
    }

    #[test]
    fn format_templates_across_languages_are_recognized() {
        for template in [
            // the fuzz-target directory name observed in this repository
            "sekretbarilo-fuzz-config-{}-{id}",
            // rust and python brace fields with specs, conversions and escapes
            "{name:>8}|{value:<12.3}|{unit:^6}|{flags:#06x}",
            "{0}_{1:?}_{2:08.3f}_{3:-^20}.csv",
            "{name!r}.{value!s}:{items}:{:>width$}",
            // the tail an assignment capture hands over after `{name:`
            ">8}|{value:<12.3}|{unit:^6}",
            r#"{{\"id\":{},\"name\":\"{}\"}}"#,
            // c, go and python printf conversions
            r"%-10s|%08.3f|%+5d|%#x\n",
            "%s@%s:%d/%s?sslmode=%s",
            "%v:%d/%s-%T.%lu.%zu",
            "%(asctime)s|%(levelname)-8s|%(name)s:%(lineno)d",
            "100%%-%d/%s",
            // shell and javascript substitutions
            "${LOG_DIR}/deploy-${HOSTNAME}-${RUN_ID}.log",
            "${baseUrl}/api/v${version}/users/${userId}",
            "${HOME}/.config/{}/settings.toml",
        ] {
            assert!(is_format_template(template.as_bytes()), "{template}");
        }
    }

    #[test]
    fn format_templates_need_a_placeholder_and_word_segments() {
        for value in [
            // escapes alone are not placeholders
            "{{name}}-{{value}}-{{unit}}",
            "plain-words-and-numbers-2026",
            // documented gaps: strftime directives, brackets, bare shell variables, lone braces
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "[%s]:%d/%s(%v)",
            "$HOME/.config/%s/%s.toml",
            "{}}-{name}-{value}",
            // a name of twenty letters is opaque, so its braces are literal text
            "{internationalization}-{}",
            // mixed separator runs and unknown bytes
            "{}?-&{}",
            "{}~{}",
            // a field tail alone is no placeholder
            ">8}-plain-words-and-numbers",
        ] {
            assert!(!is_format_template(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn interpolation_holes_and_escaped_bodies_are_templates() {
        for template in [
            // swift and raw swift holes; the expression is code, whatever its words
            r"window-detail-\(UUID().uuidString)",
            r"\(session.id.uuidString)-zoom-\(tabIndex)",
            r"session-\(UUID().uuidString.prefix(8))",
            r"session-type-\(makeIdentifier(for: kind, index: 2))",
            r"\(windowID.uuidString):\(surfaceID.uuidString):\(pane.tabIndex)",
            r"cursor:\#(surfaceId):state",
            r"\(NSUserName())-session-\(requestURL.host)",
            r"\(rect.origin.x)-offset-\(frame.height)",
            // ruby and crystal, javascript, nushell
            "#{user.first_name}-#{account.display_name}.profile",
            r"\n${formatToolResult(result)}",
            "${format(x)}/reports/quarterly-summary",
            "${config.baseUrl}/api/v1/${resolveTenant(tenant)}",
            "($name)&status=active&per_page=5",
            // a currency sign before a conversion, with a unit tail
            "$%(default).2f/gb/month",
            // escaped string bodies, judged unescaped
            r"\(socket)\nwidth=9\nheight=9\nscroll=9",
            r#"\"quarterly-budget-review\"\tauthor=jimmy\nversion=2"#,
            r#"\"release-notes-summary\"\tpublished\nupdated"#,
        ] {
            assert!(is_format_template(template.as_bytes()), "{template}");
        }
        for value in [
            // a hole the capture cut open, and an escaped backslash before a parenthesis
            r"\(controller.handleRequest(for:",
            r"foo\\(bar.baz)-something-long-here",
            // a nushell hole opens with a variable, so a parenthesized word is prose
            "(name)&status=active&per_page=5",
            // an escaped record with a short piece outside the vocabulary, and a url
            r"qzx-list\nname=running\nsession=workspaces",
            r#"\"https://example.com/release-notes\"\nsummary"#,
            // escapes that are no string escapes
            r"release\xnotes\ysummary\zupdated",
            // two short names outside the vocabulary in one hole, as a token cut into members
            // leaves them
            r"\(p.x)-\(rect.size.width)-detail",
            "${f(x)}/reports/quarterly-summary",
            // four short words in a row across holes and literal text read as a token cut into
            // chunks; the words of a hole count once a hole makes the value a template
            r"\(NSUserName())-agent-\(requestURL.host)",
            "#{user.first_name}-#{user.last_name}.profile",
            // a camel name opened by capitals that are no framework prefix
            "{QZXWindowName}-{RTVBufferSize}.log",
        ] {
            assert!(!is_format_template(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_alphabets_are_never_recognized() {
        let mut prng = XorShift64Star(0x9e37_79b9_7f4a_7c15);
        let punctuation = punctuation();
        let base62 = base62();
        let mut failures = Vec::new();
        for (name, alphabet) in credential_alphabets() {
            for length in LENGTHS {
                let (mut symbols, mut templates) = (0, 0);
                for _ in 0..SAMPLES {
                    let value = prng.string(&alphabet, length);
                    symbols += usize::from(is_symbol_table(&value));
                    templates += usize::from(is_format_template(&value));
                }
                eprintln!("{name} length {length}: symbols={symbols} template={templates}");
                if symbols + templates > 0 {
                    failures.push(format!("{name} length {length}"));
                }
            }
        }
        // a stress generator drawing a symbol for every other byte on average, denser in
        // symbols than any password generator's alphabet.
        for length in LENGTHS {
            let (mut symbols, mut templates) = (0, 0);
            for _ in 0..SAMPLES {
                let value: Vec<u8> = (0..length)
                    .map(|_| {
                        if prng.next().is_multiple_of(2) {
                            punctuation[prng.below(punctuation.len())]
                        } else {
                            base62[prng.below(base62.len())]
                        }
                    })
                    .collect();
                symbols += usize::from(is_symbol_table(&value));
                templates += usize::from(is_format_template(&value));
            }
            eprintln!("half-symbols length {length}: symbols={symbols} template={templates}");
            if symbols + templates > 0 {
                failures.push(format!("half-symbols length {length}"));
            }
        }
        assert!(failures.is_empty(), "recognized samples: {failures:?}");
    }

    /// a whole token of any alphabet is an opaque segment. a token cut by placeholders into
    /// pieces below MIN_ENTROPY_LENGTH, or used as a placeholder name, is checked for the
    /// alphabets whose pieces mix character classes: a single-case piece of hex, base32 or base36
    /// that happens to hold no digit reads as a word by design, and is below the rule's minimum
    /// length on its own.
    #[test]
    fn opaque_payloads_in_templates_are_not_recognized() {
        let mut prng = XorShift64Star(0x2545_f491_4f6c_dd1d);
        let mut recognized = Vec::new();
        for (name, alphabet) in credential_alphabets() {
            let mixed = !matches!(name, "hex-lower" | "hex-upper" | "base32" | "base36-lower");
            for _ in 0..SAMPLES / 10 {
                let length = 20 + prng.below(21);
                let token = prng.string(&alphabet, length);
                let (head, tail) = token.split_at(length / 2);
                let mut forms: Vec<Vec<u8>> = [
                    ("{}-", ""),
                    ("%s", ""),
                    ("", "{}"),
                    ("${name}/", ""),
                    ("{name:>8}|", ""),
                    ("%s/", ".json"),
                    ("", "/{}"),
                    ("{", "}"),
                    (r"\(session.id)-", ""),
                    ("", r"-\(tab.index)"),
                    (r"\#(surface.id):", ""),
                    ("#{user.name}-", ""),
                    ("$%(price).2f/", ""),
                    ("($name)&token=", ""),
                    ("${config.baseUrl}/", ""),
                    (r#"\"release-notes-summary\"\n"#, ""),
                    ("", r"\nstatus=running"),
                ]
                .iter()
                .map(|(prefix, suffix)| [prefix.as_bytes(), &token, suffix.as_bytes()].concat())
                .collect();
                if mixed {
                    forms.push([head, b"{}", tail].concat());
                    forms.push([head, b"%s", tail].concat());
                    forms.push([b"${".as_slice(), &token[..19], b"}-%s"].concat());
                    forms.push([head, br"\(session.id)", tail].concat());
                    forms.push([head, b"#{user.name}", tail].concat());
                    forms.push([head, br"\n", tail].concat());
                    // the token as the expression of a hole
                    forms.push([br"\(".as_slice(), &token, b")-detail"].concat());
                    forms.push([b"#{".as_slice(), &token[..19], b"}-detail"].concat());
                }
                for form in forms {
                    if is_format_template(&form) || is_symbol_table(&form) {
                        recognized.push(format!("{name}: {}", skeleton(&form)));
                    }
                }
            }
        }
        assert!(recognized.is_empty(), "recognized: {recognized:?}");
    }

    /// a placeholder spliced into a random password is the hardest case for the segment grammar,
    /// since every literal segment is short and random. over 2,000,000 samples per cell, 20-byte
    /// passwords from either alphabet were recognized about twice per million and 24- and 32-byte
    /// ones never. the 20-byte bound, 1 in 20,000, keeps a margin of more than twenty.
    #[test]
    fn passwords_with_a_spliced_placeholder_stay_rare() {
        const SPLICED: usize = 50_000;
        let placeholders: [&[u8]; 13] = [
            b"{}",
            b"{0}",
            b"{name}",
            b"%s",
            b"%d",
            b"%-10s",
            b"%v",
            b"${name}",
            br"\(value)",
            b"#{value}",
            b"($value)",
            b"$%(value).2f",
            b"${f(value)}",
        ];
        let mut prng = XorShift64Star(0x5851_f42d_4c95_7f2d);
        let mut failures = Vec::new();
        for (name, alphabet) in credential_alphabets()
            .into_iter()
            .filter(|(name, _)| matches!(*name, "strong-password" | "printable"))
        {
            for length in [20, 24, 32] {
                let mut recognized = 0;
                for _ in 0..SPLICED {
                    let mut value = prng.string(&alphabet, length);
                    let placeholder = placeholders[prng.below(placeholders.len())];
                    let at = prng.below(length + 1);
                    value.splice(at..at, placeholder.iter().copied());
                    recognized += usize::from(is_format_template(&value));
                }
                let allowed = if length == 20 { SPLICED / 20_000 } else { 0 };
                eprintln!("{name} length {length} spliced: recognized={recognized}/{SPLICED}");
                if recognized > allowed {
                    failures.push(format!("{name} length {length}: {recognized} > {allowed}"));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }
}
