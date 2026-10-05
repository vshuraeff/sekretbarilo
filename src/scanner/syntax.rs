// source expression recognition for exemption-layer filtering

use crate::scanner::entropy::MIN_ENTROPY_LENGTH;
use crate::scanner::wordshape;

/// the longest identifier segment of a member chain that may lack word structure. a chain carries
/// at most one such segment, so an opaque payload split by a dot keeps a long opaque half.
const MAX_OPAQUE_SEGMENT: usize = 8;

/// the most identifier segments a member chain records; a longer chain is not a member chain.
const MAX_SEGMENTS: usize = 16;

/// the length from which an identifier made of one word alone is not taken for a word.
const MAX_SINGLE_WORD: usize = 12;

/// the longest identifier segment a widened reading passes without reading it as words: too short
/// to carry a token, as `std`, `buf` or `x`.
const MAX_FREE_SEGMENT: usize = 3;

/// the bytes that end a run of short groups in a widened reading: whitespace and list separators
/// part the items of a list (`Debug, Clone, Copy, Hash, Eq`), while `.`, `::`, `->`, `?` and `!`
/// join the pieces of one term.
const REGION_RUN_BREAKS: &[u8] = b" \t,;";

#[allow(dead_code)]
/// recognizes a complete source expression, bounded to the current line and `max_scan` bytes, starting at `start`.
/// a line may also end inside the open argument list of a call whose callee is an identifier or
/// member chain, the opener of a multi-line call.
/// when the value run starting at `start` closes groups it did not open, the expression is read from
/// the callee of the enclosing opener to its left instead, so the span may start before `start`.
/// a span only a widened reading recognizes (see `forward_span`), and the part of an enclosing
/// span the value itself holds, must also read as words (`reads_as_words`): these readings claim
/// values the plain grammar reported, so an opaque, chunked or word-cut payload in them keeps it
/// reported.
/// `Some(range)` means the bytes are syntactic source scaffolding with no eligible secret token.
pub fn expression_span(
    line: &[u8],
    start: usize,
    max_scan: usize,
) -> Option<std::ops::Range<usize>> {
    let unmatched = unmatched_closers(line, start, max_scan);
    if unmatched > 0
        && let Some(head) = enclosing_head(line, start, unmatched, max_scan)
        && let Some((span, _)) = forward_span(line, head, max_scan)
        && span.end > start
        && reads_as_words(&line[start..span.end])
    {
        return Some(span);
    }
    let (span, widened) = forward_span(line, start, max_scan)?;
    (!widened || numeric_rust_attribute(&line[span.clone()]) || reads_as_words(&line[span.clone()]))
        .then_some(span)
}

fn numeric_rust_attribute(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"#[") || !bytes.ends_with(b")]") {
        return false;
    }
    let Some(name_end) = identifier_end(bytes, 2) else {
        return false;
    };
    if bytes.get(name_end) != Some(&b'(') {
        return false;
    }
    let args = bytes[name_end + 1..bytes.len() - 2].trim_ascii();
    let args = args.strip_suffix(b",").unwrap_or(args);
    !args.contains(&b',') && numeric_literal(args)
}

fn numeric_literal(bytes: &[u8]) -> bool {
    let bytes = bytes.trim_ascii();
    let bytes = bytes.strip_prefix(b"-").unwrap_or(bytes);
    let (digits, hex, limit) = if let Some(digits) = bytes.strip_prefix(b"0x") {
        (digits, true, 16)
    } else {
        (bytes, false, 20)
    };
    let count = digits.iter().filter(|&&byte| byte != b'_').count();
    count > 0
        && count <= limit
        && digits.first() != Some(&b'_')
        && digits.last() != Some(&b'_')
        && !digits.windows(2).any(|pair| pair == b"__")
        && digits.iter().all(|byte| {
            *byte == b'_'
                || if hex {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
        })
}

/// the number of groups the unquoted run starting at `start` closes without opening them. the run
/// ends where an unquoted or bare capture ends: at whitespace, a quote or the line end.
fn unmatched_closers(line: &[u8], start: usize, max_scan: usize) -> usize {
    let Some(rest) = line.get(start..) else {
        return 0;
    };
    let mut depth = 0_isize;
    let mut lowest = 0_isize;
    for &byte in rest.iter().take(max_scan) {
        if ascii_whitespace(byte) || matches!(byte, b'\'' | b'"' | b'`') {
            break;
        }
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                lowest = lowest.min(depth);
            }
            _ => {}
        }
    }
    lowest.unsigned_abs()
}

/// the start of the callee chain of the `unmatched`-th group left open before `start` on its line,
/// read by one quote-aware pass from the line start. a quote still open at `start` begins a fresh
/// line, the way a markdown code span or a string interpolation holds code of its own.
fn enclosing_head(line: &[u8], start: usize, unmatched: usize, max_scan: usize) -> Option<usize> {
    let line_start = line
        .get(..start)?
        .iter()
        .rposition(|byte| matches!(byte, b'\n' | b'\r'))
        .map_or(0, |index| index + 1);
    if start - line_start > max_scan {
        return None;
    }
    let prefix = &line[..start];
    // each open group with the start of the term that names it.
    let mut open: Vec<(u8, usize)> = Vec::new();
    let mut term: Option<usize> = None;
    let mut cursor = line_start;
    while cursor < start {
        let byte = prefix[cursor];
        if matches!(byte, b'\'' | b'"' | b'`') {
            if let Some(end) = quote_end(prefix, cursor) {
                term.get_or_insert(cursor);
                cursor = end;
            } else {
                open.clear();
                term = None;
                cursor += 1;
            }
            continue;
        }
        match byte {
            b'(' | b'[' | b'{' => {
                if open.len() == 32 {
                    return None;
                }
                open.push((byte, term.unwrap_or(cursor)));
                term = None;
            }
            b')' | b']' | b'}' => {
                let (opener, head) = open.pop()?;
                if closer_for(opener) != byte {
                    return None;
                }
                term = Some(head);
            }
            b'.' | b'?' | b'!' | b'#' | b'@' | b'$' => {
                term.get_or_insert(cursor);
            }
            b':' if prefix.get(cursor + 1) == Some(&b':')
                || (cursor > line_start && prefix[cursor - 1] == b':') =>
            {
                term.get_or_insert(cursor);
            }
            b'-' if prefix.get(cursor + 1) == Some(&b'>') => {
                term.get_or_insert(cursor);
                cursor += 1;
            }
            _ if byte.is_ascii_alphanumeric() || byte == b'_' => {
                term.get_or_insert(cursor);
            }
            _ => term = None,
        }
        cursor += 1;
    }
    let index = open.len().checked_sub(unmatched)?;
    Some(open[index].1)
}

fn closer_for(opener: u8) -> u8 {
    match opener {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => b'>',
    }
}

/// the forward reading of `expression_span` from `start` alone, and whether it is widened: whether
/// the span needed a reading the plain call, index and member grammar does not have. those are a
/// `#name`, `@Name`, `#[` or `$N` head, a go slice, array or map type head, a `.0` tuple field, a
/// `.(T)` type assertion, a quote ending a complete expression, a member chain or a type name
/// without a group, and a call left open whose callee is only a callee after `>` or `!`.
fn forward_span(
    line: &[u8],
    start: usize,
    max_scan: usize,
) -> Option<(std::ops::Range<usize>, bool)> {
    let remaining = line.get(start..)?;
    let limit = remaining.len().min(max_scan);
    let bytes = &remaining[..limit];
    let bytes = &bytes[..bytes
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .unwrap_or(bytes.len())];
    // a window cut short by `max_scan` is not a line end, so it never ends an open call.
    let line_end = remaining
        .get(bytes.len())
        .is_none_or(|byte| matches!(byte, b'\n' | b'\r'));
    let mut cursor = 0;
    if bytes.starts_with(b"?.") {
        cursor = 2;
    } else if matches!(bytes.first(), Some(b',' | b'&' | b'*' | b'!' | b'.')) {
        cursor = 1;
    }

    let mut stack = [0; 32];
    let mut depth = 0;
    let mut had_group = false;
    let mut after_ident = false;
    // the latest group opened at depth zero, and whether an identifier directly precedes it.
    let mut outer_open = 0;
    let mut callee = false;
    let mut generic_callee = false;
    // identifier segments read at depth zero, for the member-chain and type readings. a `$N`
    // closure parameter is recorded as an empty segment, which counts as a word.
    let mut segments = [(0, 0); MAX_SEGMENTS];
    let mut segment_count = 0;
    // whether the depth-zero bytes still read as a member chain, and whether they end in `?`/`!`.
    let mut chain = true;
    let mut postfix = false;
    // a `#` or `@` head names a macro or an attribute, which applies to a group.
    let mut sigil = false;
    let mut widened = false;
    if let Some(end) = go_type_head_end(bytes, cursor) {
        // a go slice, array or map type heads a composite literal or a conversion.
        cursor = end;
        after_ident = true;
        had_group = true;
        chain = false;
        widened = true;
    } else {
        match bytes.get(cursor)? {
            b'(' | b'[' => {
                stack[depth] = bytes[cursor];
                depth += 1;
                cursor += 1;
            }
            b'#' if bytes.get(cursor + 1) == Some(&b'[')
                || bytes[cursor + 1..].starts_with(b"![") =>
            {
                sigil = true;
                widened = true;
                cursor += if bytes[cursor + 1] == b'[' { 1 } else { 2 };
                stack[depth] = b'[';
                depth += 1;
                cursor += 1;
            }
            b'#' | b'@' => {
                sigil = true;
                widened = true;
                cursor = identifier_end(bytes, cursor + 1)?;
                after_ident = true;
            }
            b'$' => {
                widened = true;
                cursor = parameter_end(bytes, cursor)?;
                after_ident = true;
                segments[0] = (cursor, cursor);
                segment_count = 1;
            }
            _ => {
                let begin = cursor;
                cursor = identifier_end(bytes, cursor)?;
                after_ident = true;
                segments[0] = (begin, cursor);
                segment_count = 1;
            }
        }
    }

    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if depth > 0 {
            if matches!(byte, b'\'' | b'"' | b'`') {
                cursor = quote_end(bytes, cursor)?;
                after_ident = false;
                continue;
            }
            if matches!(byte, b')' | b']' | b'}') || (byte == b'>' && stack[depth - 1] == b'<') {
                let expected = match stack[depth - 1] {
                    b'(' => b')',
                    b'[' => b']',
                    b'{' => b'}',
                    b'<' => b'>',
                    _ => unreachable!(),
                };
                if byte != expected {
                    return None;
                }
                depth -= 1;
                had_group = true;
                cursor += 1;
                // generic arguments leave their type the callee of a group that follows.
                after_ident = byte == b'>';
                continue;
            }
            if let Some(end) = identifier_end(bytes, cursor) {
                cursor = end;
                after_ident = true;
                continue;
            }
            if bytes[cursor..].starts_with(b"::") {
                cursor += 2;
                after_ident = true;
                continue;
            }
            if !matches!(byte, b'(' | b'[' | b'{') && !(byte == b'<' && after_ident) {
                cursor += 1;
                after_ident = false;
                continue;
            }
        } else {
            // a quote after a complete expression begins other text: an unquoted capture ends at
            // its first quote, and markdown closes a code span with one.
            if matches!(byte, b'"' | b'\'' | b'`') {
                widened = true;
                break;
            }
            if ascii_whitespace(byte)
                || matches!(byte, b';' | b',' | b')' | b']' | b'}' | b'>')
                || (byte == b'<' && !after_ident)
            {
                break;
            }
            let suffix = &bytes[cursor..];
            let connector_len = if suffix.starts_with(b"?.")
                || suffix.starts_with(b"->")
                || suffix.starts_with(b"::")
            {
                2
            } else if byte == b'.' {
                1
            } else {
                0
            };
            if connector_len > 0 {
                cursor += connector_len;
                postfix = false;
                if suffix.starts_with(b"::") && bytes.get(cursor) == Some(&b'<') {
                    after_ident = true;
                    continue;
                }
                // a tuple field such as `.0` is a member without a name.
                if connector_len == 1
                    && let Some(end) = tuple_index_end(bytes, cursor)
                {
                    cursor = end;
                    after_ident = true;
                    widened = true;
                    continue;
                }
                // a go type assertion `.(T)` is a group after the dot.
                if connector_len == 1 && bytes.get(cursor) == Some(&b'(') {
                    after_ident = false;
                    widened = true;
                    continue;
                }
                let begin = cursor;
                cursor = identifier_end(bytes, cursor)?;
                after_ident = true;
                if segment_count < MAX_SEGMENTS {
                    segments[segment_count] = (begin, cursor);
                    segment_count += 1;
                } else {
                    chain = false;
                }
                continue;
            }
            if suffix.starts_with(b"=>") {
                chain = false;
                cursor += 2;
                if let Some(end) = identifier_end(bytes, cursor) {
                    cursor = end;
                    after_ident = true;
                } else if matches!(bytes.get(cursor), Some(b'(' | b'[' | b'{')) {
                    after_ident = false;
                } else {
                    return None;
                }
                continue;
            }
            if matches!(byte, b'!' | b'?') {
                // a macro bang keeps its identifier the callee of the group that follows.
                after_ident = byte == b'!' && after_ident;
                postfix = true;
                cursor += 1;
                continue;
            }
            if !matches!(byte, b'(' | b'[' | b'{') && !(byte == b'<' && after_ident) {
                return None;
            }
        }
        if depth == stack.len() {
            return None;
        }
        if depth == 0 {
            outer_open = cursor;
            callee = after_ident;
            // generic arguments and a macro bang name a callee only in the widened grammar.
            generic_callee = after_ident && cursor > 0 && matches!(bytes[cursor - 1], b'>' | b'!');
        }
        stack[depth] = byte;
        depth += 1;
        cursor += 1;
        after_ident = false;
    }

    // without a group, a member chain or a type name marked optional is complete when its
    // identifiers read as words and it ends at a terminator or the line end, never at a window
    // cut short by `max_scan`.
    let chain_complete = depth == 0
        && (cursor < bytes.len() || line_end)
        && !had_group
        && !sigil
        && chain
        && is_member_chain(bytes, &segments[..segment_count], postfix);
    let complete = depth == 0 && (had_group || chain_complete);
    // an open call reaches the line end inside call, index or block groups only, its outermost
    // group follows an identifier, and its open tail is printable ascii source text that breaks
    // after an opener, a separator or a closed argument, never inside a bare argument token.
    let tail = &bytes[outer_open..cursor];
    let open_call = depth > 0
        && line_end
        && callee
        && stack[..depth]
            .iter()
            .all(|open| matches!(open, b'(' | b'[' | b'{'))
        && tail
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t'))
        && matches!(
            tail.trim_ascii_end().last(),
            Some(b'(' | b'[' | b'{' | b')' | b']' | b'}' | b',')
        );
    if (!complete && !open_call)
        || bytes[..cursor].windows(3).any(|window| window == b"://")
        || contains_secret_token(&bytes[..cursor])
    {
        return None;
    }
    let widened = widened || chain_complete || (!complete && generic_callee);
    Some((start..start + cursor, widened))
}

fn identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !first.is_ascii_alphabetic() && first != b'_' {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    Some(end)
}

/// a closure parameter such as swift `$0`: a `$` and one or two digits.
fn parameter_end(bytes: &[u8], start: usize) -> Option<usize> {
    let digits = bytes
        .get(start + 1..)?
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let end = start + 1 + digits;
    ((1..=2).contains(&digits) && !bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte)))
        .then_some(end)
}

/// a tuple field index such as `.0`: one to three digits not running into an identifier.
fn tuple_index_end(bytes: &[u8], start: usize) -> Option<usize> {
    let digits = bytes
        .get(start..)?
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let end = start + digits;
    ((1..=3).contains(&digits) && !bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte)))
        .then_some(end)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// the end of a go slice, array or map type (`[]T`, `[4]*T`, `map[K][]pkg.T`) at `start`, the head
/// of a composite literal or a conversion.
fn go_type_head_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !(bytes[start..].starts_with(b"[]")
        || bytes[start..].starts_with(b"map[")
        || (bytes.get(start) == Some(&b'[')
            && bytes.get(start + 1).is_some_and(u8::is_ascii_digit)))
    {
        return None;
    }
    go_type_end(bytes, start, 8)
}

fn go_type_end(bytes: &[u8], mut cursor: usize, budget: usize) -> Option<usize> {
    let budget = budget.checked_sub(1)?;
    while bytes.get(cursor) == Some(&b'*') {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'[') {
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b']') {
            return None;
        }
        return go_type_end(bytes, cursor + 1, budget);
    }
    if bytes[cursor..].starts_with(b"map[") {
        let key_end = go_type_end(bytes, cursor + 4, budget)?;
        if bytes.get(key_end) != Some(&b']') {
            return None;
        }
        return go_type_end(bytes, key_end + 1, budget);
    }
    let mut end = identifier_end(bytes, cursor)?;
    if bytes.get(end) == Some(&b'.') {
        end = identifier_end(bytes, end + 1)?;
    }
    Some(end)
}

/// a member chain of two or more identifier segments whose segments read as words, one of them
/// allowed to be a short opaque name; or a single word-structured type name ending in `?` or `!`.
fn is_member_chain(bytes: &[u8], segments: &[(usize, usize)], postfix: bool) -> bool {
    if let [(start, end)] = segments {
        return postfix && start < end && is_wordy_segment(&bytes[*start..*end]);
    }
    if segments.len() < 2 {
        return false;
    }
    let mut opaque = 0;
    for &(start, end) in segments {
        let segment = &bytes[start..end];
        if segment.is_empty() || is_wordy_segment(segment) {
            continue;
        }
        if segment.len() > MAX_OPAQUE_SEGMENT {
            return false;
        }
        opaque += 1;
    }
    opaque <= 1
}

/// an identifier made of words: every camel, snake or digit piece is a known short word, a
/// pronounceable word of three to nineteen letters or a run of at most four digits, there are at
/// most two digit runs, and there are at most two words shorter than four letters per longer word
/// unless only one short word is present. an all-capitals word counts only in a constant
/// name, underscores and no lowercase letter, or as a known short word, since a capital run
/// beside lowercase letters is as often a random stretch of a token. a segment with neither an
/// underscore nor an inner capital is a single word, digits included shorter than twelve bytes.
fn is_wordy_segment(segment: &[u8]) -> bool {
    if segment.len() >= MIN_ENTROPY_LENGTH && wordshape::is_word_structured(segment) {
        return true;
    }
    if !segment
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        || !segment.iter().all(|byte| is_identifier_byte(*byte))
    {
        return false;
    }
    let Some(words) = wordshape::identifier_words(segment) else {
        return false;
    };
    // a single long word cannot be told from a random letter run without a dictionary.
    if let [word] = words.as_slice()
        && word.len() >= MAX_SINGLE_WORD
    {
        return false;
    }
    // without an underscore or an inner capital, a segment is one short word, perhaps with digits:
    // letter runs split by digits alone are as often a random run of lowercase letters and digits.
    let structured = segment.contains(&b'_') || segment[1..].iter().any(u8::is_ascii_uppercase);
    let letter_words = words
        .iter()
        .filter(|word| !word[0].is_ascii_digit())
        .count();
    if !structured && (segment.len() >= MAX_SINGLE_WORD || letter_words != 1) {
        return false;
    }
    let constant = segment.contains(&b'_') && !segment.iter().any(u8::is_ascii_lowercase);
    let mut digit_runs = 0;
    let mut long_words = 0;
    let mut short_words = 0;
    for word in words {
        if word[0].is_ascii_digit() {
            digit_runs += 1;
            if word.len() > 4 || digit_runs > 2 {
                return false;
            }
            continue;
        }
        if word.len() >= 4 {
            long_words += 1;
        } else {
            short_words += 1;
        }
        if !wordshape::is_short_word(word) {
            let cased = word.iter().all(u8::is_ascii_lowercase)
                || (word[0].is_ascii_uppercase() && word[1..].iter().all(u8::is_ascii_lowercase))
                || (constant && word.len() >= 4 && word.iter().all(u8::is_ascii_uppercase));
            if word.len() < 3
                || word.len() >= MIN_ENTROPY_LENGTH
                || !cased
                || !wordshape::has_wordlike_vowels(word)
            {
                return false;
            }
        }
    }
    short_words <= 1 || long_words * 2 >= short_words
}

/// whether the value a widened reading claims reads as words throughout (`expression_span`). no run
/// of short groups crosses the region between whitespace and list separators
/// (`wordshape::is_chunked_with_digits`), so a token cut into pieces keeps the value reported
/// whatever joins the pieces, holes and quotes included. the region is then cut into terms,
/// identifier segments joined by `.`, `::` or `->` with any `?` and `!` marks before the joint,
/// each of which reads as words (`term_words`); quoted text is left to the token veto. in a region
/// long enough to be a value of its own, `MIN_ENTROPY_LENGTH` bytes, the words of all the terms
/// outweigh their short pieces (`wordshape::PieceWords::outweigh_short_pieces`, numbers aside), so
/// a short token cut by operators into pieces too short to judge on their own keeps the value
/// reported too. numbers are set aside only while the region's opaque content is shorter than a
/// value: its numbers and its one opaque segment, each with the byte that joins it to the next,
/// and the digit runs of its words span at most `MIN_ENTROPY_LENGTH` bytes together
/// (`term_words`), so a list of numeric literals, whose `,` and `;` end the chunk run, keeps a
/// value of 20 bytes or more reported.
fn reads_as_words(region: &[u8]) -> bool {
    if wordshape::is_chunked_with_digits(region, REGION_RUN_BREAKS) {
        return false;
    }
    let mut opaque = 0;
    let mut content = 0;
    let mut words = wordshape::PieceWords::default();
    let mut cursor = 0;
    while cursor < region.len() {
        let byte = region[cursor];
        if matches!(byte, b'\'' | b'"' | b'`') {
            let Some(end) = quote_end(region, cursor) else {
                return false;
            };
            cursor = end;
            continue;
        }
        if !is_identifier_byte(byte) {
            cursor += 1;
            continue;
        }
        let term_start = cursor;
        let mut segments = Vec::new();
        loop {
            let segment_start = cursor;
            while region
                .get(cursor)
                .is_some_and(|byte| is_identifier_byte(*byte))
            {
                cursor += 1;
            }
            segments.push(&region[segment_start..cursor]);
            let joint = term_joint_len(&region[cursor..]);
            if joint == 0
                || !region
                    .get(cursor + joint)
                    .is_some_and(|byte| is_identifier_byte(*byte))
            {
                break;
            }
            cursor += joint;
        }
        let Some(term) = term_words(
            &region[term_start..cursor],
            &segments,
            &mut opaque,
            &mut content,
        ) else {
            return false;
        };
        words.add(term);
    }
    words.numbers = 0;
    region.len() < MIN_ENTROPY_LENGTH || words.outweigh_short_pieces()
}

/// the length of the joint between two segments of a term at the start of `bytes`: any `?` and `!`
/// marks, then `.`, `::` or `->`; zero when there is none.
fn term_joint_len(bytes: &[u8]) -> usize {
    let marks = bytes
        .iter()
        .take_while(|byte| matches!(byte, b'?' | b'!'))
        .count();
    let rest = &bytes[marks..];
    if rest.starts_with(b"::") || rest.starts_with(b"->") {
        marks + 2
    } else if rest.first() == Some(&b'.') {
        marks + 1
    } else {
        0
    }
}

/// the words of one term of `reads_as_words`, or none when the term does not read as words. every
/// segment is a number of at most 16 digits, reads as words (`is_wordy_segment`) or holds at most
/// `MAX_FREE_SEGMENT` bytes, and the region carries at most one other segment, of at most
/// `MAX_OPAQUE_SEGMENT` bytes, counted in `opaque`. a long member made of one pronounceable word
/// (`configuration`) reads as a word beside a member with a word structure of its own
/// (`sessionCount`). a term of two or more named segments and at least `MIN_ENTROPY_LENGTH` bytes
/// also has words that outweigh its short pieces and at least one such structured member: random
/// letters cut at dots read as one-word members as often as a member chain does, and without a
/// dictionary only the word-structure step can judge them. each number and the opaque segment,
/// with one byte for the joint after it, and each digit run of a word add their bytes to the
/// region's opaque `content`, which stays within `MIN_ENTROPY_LENGTH` bytes: numbers and an
/// opaque piece that together span a value of that length are a payload, not an argument list.
fn term_words(
    term: &[u8],
    segments: &[&[u8]],
    opaque: &mut usize,
    content: &mut usize,
) -> Option<wordshape::PieceWords> {
    let one_word = |segment: &[u8]| {
        segment.iter().all(u8::is_ascii_alphabetic)
            && wordshape::identifier_words(segment).is_some_and(|pieces| pieces.len() == 1)
    };
    let named = segments
        .iter()
        .filter(|segment| !is_number(segment))
        .count();
    let structured = segments
        .iter()
        .any(|segment| !is_number(segment) && !one_word(segment) && is_wordy_segment(segment));
    let mut words = wordshape::PieceWords::default();
    for &segment in segments {
        if is_number(segment) {
            *content += segment.len() + 1;
            if *content > MIN_ENTROPY_LENGTH {
                return None;
            }
            words.numbers += 1;
            continue;
        }
        let long_member = structured
            && one_word(segment)
            && segment.len() < MIN_ENTROPY_LENGTH
            && segment[1..].iter().all(u8::is_ascii_lowercase)
            && wordshape::has_wordlike_vowels(segment);
        if is_wordy_segment(segment) || long_member {
            for piece in wordshape::identifier_words(segment).unwrap_or_default() {
                if piece[0].is_ascii_digit() {
                    words.numbers += 1;
                    *content += piece.len();
                    if *content > MIN_ENTROPY_LENGTH {
                        return None;
                    }
                } else if piece.len() >= 4 {
                    words.long += 1;
                } else {
                    words.short += 1;
                    words.known += usize::from(wordshape::is_short_word(piece));
                }
            }
            continue;
        }
        if segment.len() > MAX_OPAQUE_SEGMENT {
            return None;
        }
        words.short += 1;
        if segment.len() > MAX_FREE_SEGMENT {
            *opaque += 1;
            *content += segment.len() + 1;
            if *opaque > 1 || *content > MIN_ENTROPY_LENGTH {
                return None;
            }
        }
    }
    (named < 2 || term.len() < MIN_ENTROPY_LENGTH || (structured && words.outweigh_short_pieces()))
        .then_some(words)
}

/// a numeric literal of at most 16 digits, the width of a 64-bit integer: decimal digits, or hex
/// digits after `0x`, with optional `_` digit groups.
fn is_number(segment: &[u8]) -> bool {
    let (digits, hex) = match segment
        .strip_prefix(b"0x")
        .or_else(|| segment.strip_prefix(b"0X"))
    {
        Some(rest) => (rest, true),
        None => (segment, false),
    };
    let count = digits.iter().filter(|byte| **byte != b'_').count();
    (1..=16).contains(&count)
        && segment.first().is_some_and(u8::is_ascii_digit)
        && digits.iter().all(|byte| {
            *byte == b'_'
                || if hex {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
        })
}

fn quote_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == quote {
            return Some(cursor + 1);
        }
        cursor += if bytes[cursor] == b'\\' { 2 } else { 1 };
    }
    None
}

/// splits unquoted inner-veto tokens, including on `.`; these are not grammar terminators.
fn token_delimiter(byte: u8) -> bool {
    ascii_whitespace(byte) || b"()[]{}<>,;:?!&*=\\'\"`|.".contains(&byte)
}

fn ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | b' ')
}

/// returns whether an opaque token vetoes expression recognition by entropy or exact hex length.
/// a leading macro, attribute or parameter sigil is not part of the token's shape, but it still
/// counts toward its length and entropy, so a sigil in front of a 19-byte payload keeps the veto the
/// whole 20-byte token had. an identifier whose every piece reads as a word and that is not cut into
/// short groups (`wordshape::is_chunked_with_digits`), and a grouped numeric literal, do not veto by
/// entropy.
fn secret_token(token: &[u8]) -> bool {
    token_vetoes(token, true)
}

/// `secret_token`, with the entropy gate on or off: without it, every opaque token of
/// `MIN_ENTROPY_LENGTH` bytes vetoes.
fn token_vetoes(token: &[u8], entropy_gate: bool) -> bool {
    if token.len() < MIN_ENTROPY_LENGTH {
        return false;
    }
    let bare = match token.first() {
        Some(b'#' | b'@' | b'$') => &token[1..],
        _ => token,
    };
    if wordshape::is_word_structured(bare) {
        return false;
    }

    let hex = bare.strip_prefix(b"0x").unwrap_or(bare);
    if matches!(hex.len(), 32 | 40 | 64) && hex.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }

    (!entropy_gate || crate::scanner::entropy::shannon_entropy(token) >= 4.0)
        && !(is_wordy_segment(bare) && !wordshape::is_chunked_with_digits(bare, b""))
        && !is_grouped_number(bare)
}

/// a numeric literal written with `_` digit-group separators, such as `0x9e37_79b9_7f4a_7c15`: at
/// most 16 hex digits, the width of a 64-bit integer, so a longer grouped value is judged like any
/// other token.
fn is_grouped_number(token: &[u8]) -> bool {
    let digits = token
        .strip_prefix(b"0x")
        .or_else(|| token.strip_prefix(b"0X"))
        .unwrap_or(token);
    digits.contains(&b'_')
        && !digits.starts_with(b"_")
        && !digits.ends_with(b"_")
        && !digits.windows(2).any(|pair| pair == b"__")
        && digits
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() || *byte == b'_')
        && (digits.len() != token.len() || digits.iter().all(|byte| !byte.is_ascii_alphabetic()))
        && digits.iter().filter(|byte| **byte != b'_').count() <= 16
}

/// a quoted body vetoes as a whole, except that string interpolation holes (`\(...)`, `${...}`,
/// `#{...}`) are code and whitespace separates the words of a phrase: then each word of the text
/// around the holes vetoes on its own, with and without the punctuation that joins it to a hole or
/// a neighbour, and each hole by its own tokens. a body with holes also vetoes when the text around
/// its holes, joined, holds an opaque token of `MIN_ENTROPY_LENGTH` bytes at any entropy (the whole
/// body, whose entropy the token's own may fall short of, vetoed at the gate before the holes were
/// read), or when the whole body, holes included, is cut into short groups
/// (`wordshape::is_chunked_with_digits`): holes placed between the pieces of a token do not part it.
fn quoted_body_is_secret(body: &[u8]) -> bool {
    let mut pieces = Vec::new();
    let mut holes = Vec::new();
    let mut piece_start = 0;
    let mut cursor = 0;
    while cursor < body.len() {
        let opener = match &body[cursor..] {
            [b'\\', b'(', ..] => Some((b'(', b')')),
            [b'$' | b'#', b'{', ..] => Some((b'{', b'}')),
            [b'\\', ..] => {
                cursor += 2;
                continue;
            }
            _ => None,
        };
        let Some((open, close)) = opener else {
            cursor += 1;
            continue;
        };
        let Some(hole_end) = balanced_end(body, cursor + 1, open, close) else {
            break;
        };
        pieces.push(&body[piece_start..cursor]);
        holes.push(&body[cursor + 2..hole_end]);
        cursor = hole_end + 1;
        piece_start = cursor;
    }
    if holes.is_empty() && !body.iter().any(|byte| ascii_whitespace(*byte)) {
        return secret_token(body);
    }
    pieces.push(&body[piece_start.min(body.len())..]);
    if !holes.is_empty()
        && (wordshape::is_chunked_with_digits(body, b"")
            || pieces
                .concat()
                .split(|byte| ascii_whitespace(*byte))
                .any(|word| {
                    token_vetoes(word, false) || token_vetoes(trim_joints(word, true, true), false)
                }))
    {
        return true;
    }
    let last = pieces.len() - 1;
    pieces.into_iter().enumerate().any(|(index, piece)| {
        let words: Vec<&[u8]> = piece.split(|byte| ascii_whitespace(*byte)).collect();
        let last_word = words.len() - 1;
        words.iter().enumerate().any(|(position, word)| {
            secret_token(word)
                || secret_token(trim_joints(
                    word,
                    index > 0 && position == 0,
                    index < last && position == last_word,
                ))
                || secret_token(trim_joints(word, true, true))
        })
    }) || holes.into_iter().any(contains_secret_token)
}

/// a text piece without the punctuation joining it to the hole after it and the hole before it.
fn trim_joints(piece: &[u8], after_hole: bool, before_hole: bool) -> &[u8] {
    let start = if after_hole {
        piece
            .iter()
            .position(u8::is_ascii_alphanumeric)
            .unwrap_or(piece.len())
    } else {
        0
    };
    let end = if before_hole {
        piece
            .iter()
            .rposition(u8::is_ascii_alphanumeric)
            .map_or(start, |index| index + 1)
    } else {
        piece.len()
    };
    &piece[start..end.max(start)]
}

/// the index of the byte closing the group opened at `open_at`, counting nested groups.
fn balanced_end(bytes: &[u8], open_at: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    for (index, &byte) in bytes.iter().enumerate().skip(open_at) {
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn contains_secret_token(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            let Some(end) = quote_end(bytes, cursor) else {
                return true;
            };
            if quoted_body_is_secret(&bytes[cursor + 1..end - 1]) {
                return true;
            }
            cursor = end;
        } else if token_delimiter(bytes[cursor]) {
            cursor += 1;
        } else {
            let start = cursor;
            while cursor < bytes.len() && !token_delimiter(bytes[cursor]) {
                cursor += 1;
            }
            if secret_token(&bytes[start..cursor]) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::expression_span;

    fn secret_fixture() -> Vec<u8> {
        secret_fixture_with_offset(0)
    }

    fn secret_fixture_with_offset(offset: u8) -> Vec<u8> {
        (0..32)
            .map(|index| {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + (index + offset % 26) % 26
            })
            .collect()
    }

    fn alphabetic_fixture() -> Vec<u8> {
        (0..40_u16)
            .map(|index| b'a' + ((index * 7) % 26) as u8)
            .collect()
    }

    fn alphanumeric_fixture() -> Vec<u8> {
        (0..40_u16)
            .map(|index| {
                if index % 3 == 0 {
                    b'0' + (index % 10) as u8
                } else {
                    b'a' + ((index * 7) % 26) as u8
                }
            })
            .collect()
    }

    fn hex_fixture(length: usize) -> Vec<u8> {
        const HEX: &[u8] = b"0123456789abcdef";
        (0..length)
            .map(|index| HEX[(index * 11 + index / 3) % HEX.len()])
            .collect()
    }

    fn base32_fixture(length: usize) -> Vec<u8> {
        const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        (0..length)
            .map(|index| BASE32[(index * 5 + index / 2) % BASE32.len()])
            .collect()
    }

    fn inject(prefix: &[u8], token: &[u8], suffix: &[u8]) -> Vec<u8> {
        [prefix, token, suffix].concat()
    }

    #[test]
    fn syntax_safe_expressions() {
        let cases: &[(&[u8], usize)] = &[
            (br##"Regex::new(r"[a-z]+")"##, 0),
            (
                b"CompiledAllowlist::from_config(&config, &rules).unwrap()",
                0,
            ),
            (
                br##"container.querySelector<HTMLElement>(".wui-kanban__card")"##,
                0,
            ),
            (b"String.fromCodePoint(0x2588)", 0),
            (b"S(0x1234567890abcdef,0xfedcba0987654321)", 0),
            (b"sum(rate(node_tcp_connections[5m]))", 0),
            (b"pthread_mutex_unlock(&spawn_lock);", 1),
            (b"[]Entry{Entry{Value: otherValue}}", 0),
            (b"resolverObject?.acceptLeaderSnapshotNow(items)", 0),
            (b".deletingLastPathComponent()", 0),
            (b"refreshGateway.noteLifecycleChangeHappened();", 1),
            (br##"runtime.environment["ENVVAR"],"##, 1),
            (b"foo.bar(baz);", 1),
            (
                br##"assert!(is_hex_policy_candidate(Some(b"value"), &bytes))"##,
                0,
            ),
        ];
        for &(input, trailing) in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                Some(0..input.len() - trailing),
                "{input:?}"
            );
        }
        assert_eq!(expression_span(b"foo.bar(baz);", 0, 100), Some(0..12));
    }

    #[test]
    fn syntax_secret_veto() {
        let secret = secret_fixture();
        let cases = [
            inject(br##"Regex::new(r""##, &secret, br##"")"##),
            inject(b"CompiledAllowlist::from_config(", &secret, b").unwrap()"),
            inject(br##"runtime.environment[""##, &secret, br##""]"##),
            inject(b"callee(", &secret, b")"),
            inject(b"foo(", &alphabetic_fixture(), b")"),
            inject(b"foo(", &alphanumeric_fixture(), b")"),
            inject(b"foo('", &secret, b"')"),
            inject(b"foo(`", &secret, b"`)"),
        ];
        for input in cases {
            assert_eq!(expression_span(&input, 0, usize::MAX), None);
        }
        assert_eq!(expression_span(&secret, 0, usize::MAX), None);
    }

    #[test]
    fn syntax_opaque_inner_tokens_veto_expressions_without_an_entropy_gate() {
        let hex40 = hex_fixture(40);
        let hex32 = hex_fixture(32);
        let base32 = base32_fixture(24);
        let alphanumeric = alphanumeric_fixture();
        let cases = [
            inject(b"foo(", &hex40, b")"),
            inject(b"foo(", &hex32, b")"),
            inject(b"handler.process(", &base32, b")"),
            inject(b"Type::func(", &alphanumeric[..20], b")"),
        ];
        for input in cases {
            assert_eq!(expression_span(&input, 0, usize::MAX), None, "{input:?}");
        }
    }

    #[test]
    fn syntax_word_structured_calls_remain_expressions() {
        let cases: &[(&[u8], usize)] = &[
            (b"refreshGateway.noteLifecycleChangeHappened();", 1),
            (b"pthread_mutex_unlock(&spawn_lock);", 1),
            (b"lv.font_montserrat_compressed.init(x)", 0),
        ];
        for &(input, trailing) in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                Some(0..input.len() - trailing),
                "{input:?}"
            );
        }
    }

    #[test]
    fn syntax_dotted_secret_veto() {
        let first = secret_fixture();
        let second = secret_fixture_with_offset(9);
        assert_ne!(first, second);
        for token in [&first, &second] {
            assert!(super::secret_token(token));
        }
        let dotted = inject(&first, b".", &second);
        let cases = [
            inject(b"foo(", &dotted, b")"),
            inject(b"foo(x.", &first, b")"),
            inject(
                br##"foo(""##,
                &inject(&first[..16], b".", &first[16..]),
                br##"")"##,
            ),
        ];
        for input in cases {
            assert_eq!(expression_span(&input, 0, usize::MAX), None);
        }
    }

    #[test]
    fn syntax_invalid_expressions() {
        let cases: &[&[u8]] = &[
            b"foo(bar)baz",
            // `foo(` left this list on purpose: a line ending in an open call is a multi-line call.
            br##"foo("unterminated"##,
            b"mongodb://user:pass@[::1]:27017/db",
            b"where: relative/path/File.swift",
            b"key = value(x)",
            b"a => b",
            b"foo()=value(x)",
            b"foo(])",
            b"foo([)]",
            b"foo().",
            b"foo()?.",
            b"foo()::",
            b"foo()->",
            b"foo()=>",
            b"foo()+bar",
            br##"foo("https://example.test")"##,
            b"foo(a://b)",
            b"!!foo()",
            b"{value}",
        ];
        for input in cases {
            assert_eq!(expression_span(input, 0, usize::MAX), None, "{input:?}");
        }
    }

    #[test]
    fn syntax_open_calls() {
        let cases: &[&[u8]] = &[
            b"foo(",
            b"window.history.replaceState(",
            b"hashlib.sha256(x.encode()",
            b"store.dispatch(setUserProfile({",
            b"CompiledAllowlist::from_config(",
            b"ctx->handlers->on_connect(",
            b"self.navigationController?.pushViewController(",
            b"json.NewDecoder(r.Body).Decode(",
            b"dev->netdev_ops->ndo_start_xmit(skb, ",
            b"[]string{",
            b".replaceState(",
            b"foo(bar, [",
            b"foo(\tbar,",
        ];
        for input in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                Some(0..input.len()),
                "{input:?}"
            );
        }
        for eol in [&b"\n"[..], b"\r\n", b"\r"] {
            let input = inject(b"window.history.replaceState(", eol, b"state)");
            assert_eq!(expression_span(&input, 0, usize::MAX), Some(0..28));
        }
        let assignment = b"let config = CompiledAllowlist::from_config(";
        assert_eq!(
            expression_span(assignment, 13, usize::MAX),
            Some(13..assignment.len())
        );
        // a window that ends exactly at the line end still sees the whole line.
        assert_eq!(expression_span(b"foo.bar(\nbaz)", 0, 8), Some(0..8));
    }

    #[test]
    fn syntax_invalid_open_calls() {
        let cases: &[&[u8]] = &[
            // unbalanced closers
            b"foo(]",
            b"foo([)",
            b"foo({]",
            b"foo(bar(baz]",
            // garbage after the opener
            b"foo(\x00",
            b"foo(bar\x7f",
            b"foo(\xc3\xa9",
            b"foo(a\x0cb",
            b"foo(bar)baz(",
            br##"foo("unterminated"##,
            b"foo('",
            b"foo(`",
            b"foo(a://b",
            b"foo(https://example.test/path",
            // the outermost open group has no identifier callee
            b"(",
            b"(foo",
            b"[foo",
            b"(foo)(",
            b"foo()(",
            b"items[0](",
            b"foo=>(",
            b"foo=>{bar",
            // an open comparison or generic argument list
            b"Vec<String",
            b"foo(a<b",
            b"foo::<Bar",
            // the line breaks inside an argument rather than after an opener, separator or group
            b"foo(bar",
            b"foo(bar, baz  ",
            br##"foo("abc""##,
            b"foo(a +",
            b"window.history.replaceState(state",
        ];
        for input in cases {
            assert_eq!(expression_span(input, 0, usize::MAX), None, "{input:?}");
        }
        assert_eq!(expression_span(b"foo.bar(baz)", 0, 8), None);
        assert_eq!(expression_span(b"foo.bar(baz", 0, 10), None);
    }

    #[test]
    fn syntax_open_call_secret_veto() {
        let secret = secret_fixture();
        let alphanumeric = alphanumeric_fixture();
        let cases = [
            inject(b"foo(", &secret, b""),
            inject(b"foo.bar(", &secret, b""),
            inject(b"foo(x, ", &secret, b""),
            inject(b"foo(x.", &secret, b""),
            inject(b"foo(bar(", &secret, b""),
            inject(br##"foo(""##, &secret, br##"","##),
            inject(b"foo(", &hex_fixture(40), b""),
            inject(b"foo(", &hex_fixture(32), b""),
            inject(b"handler.process(", &base32_fixture(24), b""),
            inject(b"Type::func(", &alphanumeric[..20], b""),
            inject(b"foo.", &secret, b"("),
            inject(&secret, b"(", b""),
        ];
        for input in cases {
            assert_eq!(expression_span(&input, 0, usize::MAX), None, "{input:?}");
        }
    }

    #[test]
    fn syntax_open_call_depth_limit() {
        for depth in [32, 33] {
            let input = inject(b"foo", &b"(".repeat(depth), b"");
            let expected = (depth == 32).then_some(0..input.len());
            assert_eq!(expression_span(&input, 0, usize::MAX), expected);
        }
    }

    #[test]
    fn syntax_connectors_groups_and_quotes() {
        let cases: &[&[u8]] = &[
            b",foo()",
            b"&foo()",
            b"*foo()",
            b"!foo()",
            b"?.foo()",
            b"foo::<Bar>()",
            b"Foo<Bar<Baz>>()",
            b"foo()->bar::baz()!?",
            b"foo=>bar()",
            b"foo=>{bar}",
            b"foo=>(bar)",
            b"foo=>[bar]",
            b"(foo)[bar]{baz}",
            b"foo(a < b, a > b)",
            b"foo(a<b>)",
            br##"foo("escaped\"quote", 'escaped\'quote', `escaped\`quote`)"##,
            br##"foo("\\")"##,
        ];
        for input in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                Some(0..input.len()),
                "{input:?}"
            );
        }
    }

    #[test]
    fn syntax_depth_limit() {
        for depth in [32, 33] {
            let mut input = Vec::new();
            for index in 0..depth * 2 + 1 {
                input.push(if index < depth {
                    b'('
                } else if index == depth {
                    b'x'
                } else {
                    b')'
                });
            }
            let expected = (depth == 32).then_some(0..input.len());
            assert_eq!(expression_span(&input, 0, usize::MAX), expected);
        }
    }

    #[test]
    fn syntax_scan_bounds_and_terminators() {
        let safe = b"foo.bar(baz)";
        for terminator in b"\n\r \t\x0b\x0c;,)]}><" {
            let mut input = safe.to_vec();
            input.push(*terminator);
            input.extend(secret_fixture());
            assert_eq!(expression_span(&input, 0, usize::MAX), Some(0..safe.len()));
            assert_eq!(
                expression_span(&input, 0, usize::MAX),
                expression_span(safe, 0, usize::MAX)
            );
        }
        for max_scan in 0..safe.len() {
            assert_eq!(expression_span(safe, 0, max_scan), None);
        }
        assert_eq!(expression_span(safe, 0, safe.len()), Some(0..safe.len()));
        assert_eq!(expression_span(safe, safe.len(), 100), None);
        assert_eq!(expression_span(safe, safe.len() + 1, 100), None);
        assert_eq!(expression_span(safe, usize::MAX, 100), None);
        assert_eq!(expression_span(b"", 0, 100), None);
        let offset = inject(b"skip ", safe, b";rest");
        assert_eq!(
            expression_span(&offset, 5, usize::MAX),
            Some(5..5 + safe.len())
        );
        assert_eq!(expression_span(&offset, 5, safe.len() - 1), None);
        // a group still open at the line end is an open call bounded by that line.
        assert_eq!(expression_span(b"foo(\n)", 0, 100), Some(0..4));
        assert_eq!(expression_span(b"foo(\r)", 0, 100), Some(0..4));
        assert_eq!(expression_span(br##"foo("abc\"##, 0, 100), None);
    }

    fn assert_whole(cases: &[(&[u8], usize)]) {
        for &(input, trailing) in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                Some(0..input.len() - trailing),
                "{}",
                String::from_utf8_lossy(input)
            );
        }
    }

    fn assert_vetoed(cases: &[Vec<u8>]) {
        for input in cases {
            assert_eq!(
                expression_span(input, 0, usize::MAX),
                None,
                "{}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn syntax_macro_and_attribute_heads() {
        assert_whole(&[
            (b"#expect(settings.workspaceIdentifier)", 0),
            (
                b"#require(store.workspaces.first?.selectedSessionIdentifier)",
                0,
            ),
            (b"#selector(WorkspaceController.handleSelection(_:))", 0),
            (b"@AppStorage(PreferenceKeys.preferredColorScheme)", 0),
            (b"#[serial(environment_lock)]", 0),
            (b"#![allow(dead_code)]", 0),
            (b"vec![first_entry, second_entry];", 1),
        ]);
        // a head applies to a group, so a bare `#name` or `@Name` is not an expression.
        for input in [
            &b"#expectation"[..],
            b"@MainActor",
            b"#(value)",
            b"@(value)",
        ] {
            assert_eq!(expression_span(input, 0, usize::MAX), None, "{input:?}");
        }
        let secret = secret_fixture();
        assert_vetoed(&[
            inject(b"#expect(", &secret, b")"),
            inject(b"#expect(settings.", &secret, b")"),
            inject(b"@AppStorage(", &secret, b")"),
            inject(b"#[serial(", &secret, b")]"),
            inject(b"#", &secret, b"(value)"),
            inject(b"@", &secret, b"(value)"),
            inject(b"", &secret, b"!(value)"),
        ]);
    }

    #[test]
    fn rust_numeric_attributes_are_expressions_without_hiding_payloads() {
        let input = b"#[test_case(0x9e37_79b9_7f4a_7c15)]";
        assert_eq!(expression_span(input, 0, usize::MAX), Some(0..input.len()));
        let secret = secret_fixture();
        assert_vetoed(&[
            inject(b"#[test_case(\"", &secret, b"\")]"),
            inject(b"#[test_case(", &secret, b")]"),
        ]);
    }

    #[test]
    fn syntax_member_chains() {
        assert_whole(&[
            (b"workspaceStore?.activeWindowController.hostWindow", 0),
            (b"NSApp.keyWindow?.firstResponder", 0),
            (b"policy.DefaultActionTimeoutSec}", 1),
            (b"AppActions.toggleSidebarVisibility,", 1),
            (b"$0.workspaceSessions.isEmpty", 0),
            (b"self.0.pendingTransitions", 0),
            // a type name alone is complete when it is marked optional or unwrapped.
            (b"TerminalAccessoryHostView?", 0),
            (b"NSTitlebarAccessoryViewController!", 0),
        ]);
        // one identifier without a group or a postfix mark is a name, not an expression.
        assert_eq!(expression_span(b"workspaceIdentifier", 0, usize::MAX), None);
        // a chain cut short by the scan window is not complete.
        let chain = b"settings.workspaceIdentifier";
        assert_eq!(expression_span(chain, 0, chain.len() - 1), None);
        assert_eq!(expression_span(chain, 0, chain.len()), Some(0..chain.len()));

        let secret = secret_fixture();
        let other = secret_fixture_with_offset(9);
        assert_vetoed(&[
            inject(b"settings.", &secret, b""),
            inject(b"", &secret, b".configuration"),
            inject(b"self.", &inject(&secret, b".", &other), b""),
            inject(b"$0.", &secret, b""),
            inject(b"", &secret, b"?"),
            inject(b"", &secret, b"!"),
            // a segment above eight bytes that does not read as words is opaque.
            inject(b"settings.", &secret[..12], b".configuration"),
            // two short opaque segments are one more than a chain may carry.
            inject(
                b"settings.",
                &inject(&secret[..8], b".", &other[..8]),
                b".configuration",
            ),
            // a value split by a dot reads as two opaque segments.
            inject(&secret[..14], b".", &secret[14..]),
        ]);
    }

    #[test]
    fn syntax_enclosing_group_is_read_from_its_opener() {
        let line = b"store.update(workspace: activeWorkspace)?.refreshSessions()";
        let start = line.len() - "activeWorkspace)?.refreshSessions()".len();
        assert_eq!(
            expression_span(line, start, usize::MAX),
            Some(0..line.len())
        );

        let line = b"var isEnabled: Bool { preferences.value(forKey: configurationKey).boolValue }";
        let head = line.len() - "preferences.value(forKey: configurationKey).boolValue }".len();
        let start = line.len() - "configurationKey).boolValue }".len();
        assert_eq!(
            expression_span(line, start, usize::MAX),
            Some(head..line.len() - 2)
        );

        let secret = secret_fixture();
        let line = inject(
            b"update(",
            &secret,
            b", workspace: activeWorkspace).refresh()",
        );
        let start = line.len() - "activeWorkspace).refresh()".len();
        assert_eq!(expression_span(&line, start, usize::MAX), None);
        // a closer that does not match the opener on its left ends nothing.
        let line = b"update[workspace: activeWorkspace).refresh()";
        let start = line.len() - "activeWorkspace).refresh()".len();
        assert_eq!(expression_span(line, start, usize::MAX), None);
        // the opener is looked for on the capture's own line only.
        let line = b"update(\nworkspace: activeWorkspace).refresh()";
        let start = line.len() - "activeWorkspace).refresh()".len();
        assert_eq!(expression_span(line, start, usize::MAX), None);
        // an opener inside a string does not open a group, so the closer belongs to `log(`.
        let line = br##"log("update(" workspace: activeWorkspace).refresh()"##;
        let start = line.len() - "activeWorkspace).refresh()".len();
        assert_eq!(
            expression_span(line, start, usize::MAX),
            Some(0..line.len())
        );
        let line = br##""update(" workspace: activeWorkspace).refresh()"##;
        let start = line.len() - "activeWorkspace).refresh()".len();
        assert_eq!(expression_span(line, start, usize::MAX), None);
    }

    #[test]
    fn syntax_go_types_assertions_and_generic_callees() {
        assert_whole(&[
            (b"[]layout.SessionDescriptor{first, second}", 0),
            (br##"map[string]widget.Descriptor{"alpha": first},"##, 1),
            (b"value.(*widgetState).Transition(expectedState)", 0),
            (b"fields.Items[0].Entries[1].(form.SelectOption).Label,", 1),
            (b"std::make_unique<KeyStream>(std::string(buffer), mode)", 0),
        ]);
        let secret = secret_fixture();
        assert_vetoed(&[
            inject(b"[]", &secret, b"{first}"),
            inject(b"map[string]", &secret, b"{first}"),
            inject(b"value.(", &secret, b").Transition(state)"),
            inject(b"std::make_unique<", &secret, b">(buffer)"),
        ]);
    }

    #[test]
    fn syntax_quoted_prose_and_numeric_literals() {
        assert_whole(&[
            (
                br##"String(localized: "Close the selected workspace and its sessions.")"##,
                0,
            ),
            (
                br##"build("restored \(count) sessions in \(windows) windows")"##,
                0,
            ),
            (b"Wrapping(0x2545_f491_4f6c_dd1d);", 1),
            (b"registerURLSchemeHandlerForApplication()", 0),
        ]);
        let secret = secret_fixture();
        assert_vetoed(&[
            inject(
                br##"String(localized: "Close the "##,
                &secret,
                br##" workspace.")"##,
            ),
            inject(br##"build("prefix-\(value)-"##, &secret, br##"")"##),
            inject(br##"build("${value}"##, &secret, br##"")"##),
            inject(br##"build("\("##, &secret, br##")")"##),
            inject(b"Wrapping(0x", &hex_fixture(32), b")"),
            inject(b"register", &secret, b"()"),
        ]);
    }

    /// eight consonant-vowel groups of `width` letters joined by `joint`: a value cut into short
    /// groups, or into long one-word members.
    fn chunked_fixture(width: usize, joint: &str) -> Vec<u8> {
        const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
        const VOWELS: &[u8] = b"aeiou";
        let groups: Vec<String> = (0..8)
            .map(|group| {
                (0..width)
                    .map(|index| {
                        let seed = group * 7 + index * 3;
                        char::from(if index % 2 == 0 {
                            CONSONANTS[seed % CONSONANTS.len()]
                        } else {
                            VOWELS[seed % VOWELS.len()]
                        })
                    })
                    .collect()
            })
            .collect();
        groups.join(joint).into_bytes()
    }

    #[test]
    fn syntax_widened_readings_read_their_value_as_words() {
        assert_whole(&[
            (b"#expect(result.configuration.sessionCount)", 0),
            (b"#[derive(Debug, Clone, Copy, Hash, Eq)]", 0),
            (
                b"std::make_unique<std::string>(std::string(buf), mode, cipher,",
                0,
            ),
        ]);
        let short_name = &secret_fixture()[..19];
        let chunks = chunked_fixture(4, ".");
        let long_members = chunked_fixture(9, ".");
        assert_vetoed(&[
            // a macro or attribute name below the token length is judged as a word.
            inject(b"#", short_name, b"(value)"),
            inject(b"@", short_name, b"(value)"),
            // short groups joined by member joints, whatever the position.
            chunks.clone(),
            inject(b"#expect(", &chunks, b")"),
            inject(b"#expect(", &chunked_fixture(4, "!."), b")"),
            inject(b"$0.", &chunks, b""),
            inject(b"value.(", &chunks, b").Transition(state)"),
            inject(b"foo(", &chunks, b")\"rest\""),
            // one-word members only, however pronounceable.
            long_members.clone(),
            inject(b"#expect(", &long_members, b")"),
            inject(b"settings.", &long_members, b""),
        ]);
        // an argument read from its enclosing call is judged as words too.
        for argument in [&chunks, &long_members] {
            let line = inject(b"make(for: ", argument, b")");
            assert_eq!(expression_span(&line, 10, usize::MAX), None);
        }
        // holes placed between the pieces of a value do not part it.
        let line = inject(br##"build("${a}"##, &chunked_fixture(3, "${b}"), br##"")"##);
        assert_eq!(expression_span(&line, 0, usize::MAX), None);
    }
}
