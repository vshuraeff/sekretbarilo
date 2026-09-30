// URL-shape recognition for exemption-layer filtering

use super::entropy::MIN_ENTROPY_LENGTH;
use super::wordshape::{is_chunked, is_chunked_with_digits, is_short_word};

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a URL-shaped value has no credential-bearing component. a markdown link chain
/// split by the value grammar (`label](url)](target`) is credential free when one of its targets is
/// an absolute url and every target is free, and a value without a scheme is accepted only as an
/// email address or `user@host` of words.
///
/// the git-position exception is a semantic exception to the general opaque-run cap.
/// a capability URL carrying a hex bearer token in a git-position path slot is not
/// detected by this rule. it is intended only for the generic-high-entropy-value
/// rule; callers decide which rules this result gates.
pub fn is_credential_free_url(value: &[u8]) -> bool {
    let value = trim_prose_delimiters(value);
    if let Some(free) = link_chain_free(value) {
        return free;
    }
    if !is_url_shaped(value) {
        return is_email_address(value);
    }
    url_free(value)
}

/// the check of one url with a scheme or a network-path prefix.
fn url_free(value: &[u8]) -> bool {
    let rest = if let Some(rest) = value.strip_prefix(b"//") {
        rest
    } else {
        let Some(scheme_end) = scheme_end(value) else {
            return false;
        };
        let Some(rest) = value.get(scheme_end + 3..) else {
            return false;
        };
        rest
    };

    let authority_end = rest
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains(&b'@') || !host_labels_allowed(authority) {
        return false;
    }
    reference_free(&rest[authority_end..])
}

/// the check of the path, query and fragment of a url.
fn reference_free(path_and_more: &[u8]) -> bool {
    let question = path_and_more.iter().position(|byte| *byte == b'?');
    let fragment = path_and_more.iter().position(|byte| *byte == b'#');
    let path_end = match (question, fragment) {
        (Some(question), Some(fragment)) => question.min(fragment),
        (Some(question), None) => question,
        (None, Some(fragment)) => fragment,
        (None, None) => path_and_more.len(),
    };

    if !path_segments_allowed(&path_and_more[..path_end]) {
        return false;
    }

    if let Some(question) = question.filter(|question| {
        fragment
            .map(|fragment| *question < fragment)
            .unwrap_or(true)
    }) {
        let query_end = fragment.unwrap_or(path_and_more.len());
        if !query_allowed(&path_and_more[question + 1..query_end]) {
            return false;
        }
    }

    if let Some(fragment) = fragment {
        let fragment = &path_and_more[fragment + 1..];
        return component_allowed(fragment) || is_slug(&percent_decode(fragment));
    }

    true
}

/// a markdown link chain that the value grammar split inside a label or a badge:
/// `tail](target)](target` or `target)](target`. none when the value holds no `](`. at least one
/// target must be an absolute url, every target must be a credential-free url or relative file
/// reference, and a label tail, which is never evaluated on its own, must be a name shorter than
/// the tier-3 minimum that is not cut into short groups (`is_chunked_with_digits`). the label tail
/// and the relative targets are read together too: a token cut into letter groups across them is
/// chunked (`is_chunked`), whichever of them holds each group. a token whose groups carry digits
/// cannot pass that way, as the leaf of a relative target must hold a word that outweighs its
/// short pieces and digit runs, so the letter form of the guard is the one read across the parts,
/// and a numbered file name after a short tail (`MIT](...)](../adr/0002-tier3-layer.md`) stays a
/// name.
fn link_chain_free(value: &[u8]) -> Option<bool> {
    let parts = split_on(value, b"](");
    if parts.len() < 2 {
        return None;
    }
    let last = parts.len() - 1;
    let mut absolute_targets = 0;
    let mut names = Vec::new();
    for (index, part) in parts.into_iter().enumerate() {
        let target = if index < last {
            match part.strip_suffix(b")") {
                Some(target) => target,
                None if index == 0 => {
                    let label = part
                        .strip_prefix(b"![")
                        .or_else(|| part.strip_prefix(b"["))
                        .unwrap_or(part);
                    if label.len() >= MIN_ENTROPY_LENGTH
                        || !is_name_segment(label)
                        || is_chunked_with_digits(label, b"")
                    {
                        return Some(false);
                    }
                    names.extend_from_slice(label);
                    names.push(b'/');
                    continue;
                }
                None => return Some(false),
            }
        } else if count(part, b')') > count(part, b'(') {
            part.strip_suffix(b")").unwrap_or(part)
        } else {
            part
        };
        // only the first part can be a url the value grammar cut after its scheme.
        let absolute = scheme_end(target).is_some() || (index == 0 && target.starts_with(b"//"));
        absolute_targets += usize::from(absolute);
        if target.is_empty()
            || target
                .iter()
                .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'<' | b'>' | b'[' | b']'))
            || !(if absolute {
                url_free(target)
            } else {
                relative_target_free(target)
            })
        {
            return Some(false);
        }
        if !absolute {
            names.extend_from_slice(target);
            names.push(b'/');
        }
    }
    Some(absolute_targets > 0 && !is_chunked(&names, b""))
}

/// a relative link target such as `LICENSE` or `../adr/0002-layer.md#usage`: a path of file and
/// directory names, no query, and at most a slug fragment. the leaf is judged on its own, so a
/// word in a directory above it (`docs/`) never vouches for it: the leaf holds a word of four or
/// more letters, and its words outweigh its short pieces. the whole path, directories included,
/// must hold words that outweigh its short pieces and must not be cut into short groups.
fn relative_target_free(target: &[u8]) -> bool {
    let (path, fragment) = match target.iter().position(|byte| *byte == b'#') {
        Some(hash) => (&target[..hash], Some(&target[hash + 1..])),
        None => (target, None),
    };
    let segments = path
        .split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty());
    let leaf = segments
        .clone()
        .rfind(|segment| !matches!(*segment, b"." | b".."));
    fragment.is_none_or(is_slug)
        && segments.clone().all(is_name_segment)
        && leaf.is_some_and(|leaf| {
            leaf.split(|byte| matches!(byte, b'.' | b'-' | b'_'))
                .any(|piece| piece.len() >= 4 && is_word_field(piece))
                && words_outweigh_short_pieces(leaf)
        })
        && is_worded_name(path)
}

/// whether a name made of name segments (`is_name_segment`) reads as names as a whole: its words
/// outweigh its short pieces (`words_outweigh_short_pieces`) and it is not cut into short groups
/// (`is_chunked_with_digits`, read across `/` too, so a token spread over several directories or
/// over an owner and a repository is one run). each segment on its own may hold up to five opaque
/// bytes per piece, so only the whole name tells a path of words from a token cut into pieces.
fn is_worded_name(name: &[u8]) -> bool {
    words_outweigh_short_pieces(name) && !is_chunked_with_digits(name, b"")
}

/// whether the words of a name outweigh its other pieces, as a slug's do. a piece is a run of
/// letters or of digits between non-alphanumeric bytes and letter-digit boundaries; a long word is
/// a word of four or more letters (`is_word_field`) or a camel-cased pair or triple of them
/// (`is_camel_field`), and a short piece is any other letter run outside the short-word vocabulary
/// (`x`, `gh`, `abc`), with every digit run after the first counted as one too. the long words
/// must be at least half as many as the short pieces: `pypa/gh-action-pypi-publish` and
/// `0002-tier3-exemption-layer.md` pass, while a token cut into short pieces is all short pieces
/// and digit runs.
fn words_outweigh_short_pieces(value: &[u8]) -> bool {
    let (mut long, mut short, mut numbers) = (0usize, 0usize, 0usize);
    for field in value
        .split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|field| !field.is_empty())
    {
        let mut start = 0;
        while start < field.len() {
            let digits = field[start].is_ascii_digit();
            let end = field[start..]
                .iter()
                .position(|byte| byte.is_ascii_digit() != digits)
                .map_or(field.len(), |offset| start + offset);
            let piece = &field[start..end];
            if digits {
                numbers += 1;
            } else if (piece.len() >= 4 && is_word_field(piece)) || is_camel_field(piece) {
                long += 1;
            } else if !is_short_word(piece) {
                short += 1;
            }
            start = end;
        }
    }
    long * 2 >= short + numbers.saturating_sub(1)
}

/// `.`, `..`, or a name whose pieces between `.`, `-` and `_` are words (camel humps included),
/// numbers of up to ten digits, or lowercase alphanumerics of up to five bytes (`tier3`, `x86`).
fn is_name_segment(segment: &[u8]) -> bool {
    matches!(segment, b"." | b"..")
        || (segment.iter().any(u8::is_ascii_alphanumeric)
            && segment
                .split(|byte| matches!(byte, b'.' | b'-' | b'_'))
                .all(|piece| {
                    piece.is_empty()
                        || is_word_field(piece)
                        || is_camel_field(piece)
                        || (piece.len() <= 10 && piece.iter().all(u8::is_ascii_digit))
                        || (piece.len() <= 5
                            && piece
                                .iter()
                                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
                }))
}

fn split_on<'a>(value: &'a [u8], separator: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index + separator.len() <= value.len() {
        if &value[index..index + separator.len()] == separator {
            parts.push(&value[start..index]);
            index += separator.len();
            start = index;
        } else {
            index += 1;
        }
    }
    parts.push(&value[start..]);
    parts
}

fn count(value: &[u8], target: u8) -> usize {
    value.iter().filter(|byte| **byte == target).count()
}

/// an email address or an ssh-style `user@host` destination whose local part and host labels are
/// words: pieces joined by `. - _ +` in the local part and by `-` inside each host label, at least
/// two host labels, and an alphabetic last label. every piece is a letter word on its own, so the
/// whole address is read as well: its words outweigh its short pieces and are not a run of short
/// groups (`is_chunked`; the pieces hold no digits), as a token cut into words of two to five
/// letters across the local part or the host labels would be.
fn is_email_address(value: &[u8]) -> bool {
    let mut halves = value.split(|byte| *byte == b'@');
    let (Some(local), Some(domain), None) = (halves.next(), halves.next(), halves.next()) else {
        return false;
    };
    let labels: Vec<&[u8]> = domain.split(|byte| *byte == b'.').collect();
    labels.len() >= 2
        && labels
            .last()
            .is_some_and(|label| label.len() >= 2 && label.iter().all(u8::is_ascii_alphabetic))
        && local
            .split(|byte| matches!(byte, b'.' | b'-' | b'_' | b'+'))
            .all(is_word_field)
        && labels
            .iter()
            .all(|label| label.split(|byte| *byte == b'-').all(is_word_field))
        && words_outweigh_short_pieces(value)
        && !is_chunked(value, b"")
}

/// a slug: words and short numbers joined by `-`, `_` or `.`, as titles, anchors and file names
/// are written in urls. at least half of the alphabetic pieces are words of four or more letters,
/// a number has at most ten digits and all numbers together at most twelve, and the words are not
/// a run of short groups (`is_chunked`): a token cut every two to five letters is all words of up
/// to five letters. digits cannot carry such a token here, as they stand only in whole pieces of
/// at most twelve digits in all, so the letter form of the chunk guard is the one that applies and
/// a dated name such as `2026-09-10-docs-site-redesign` stays a slug.
fn is_slug(value: &[u8]) -> bool {
    let mut pieces = 0;
    let mut letter_pieces = 0;
    let mut long_words = 0;
    let mut digits = 0;
    for piece in value.split(|byte| matches!(byte, b'-' | b'_' | b'.')) {
        pieces += 1;
        if !piece.is_empty() && piece.iter().all(u8::is_ascii_digit) {
            if piece.len() > 10 {
                return false;
            }
            digits += piece.len();
        } else if is_word_field(piece) {
            letter_pieces += 1;
            if piece.len() >= 4 {
                long_words += 1;
            }
        } else {
            return false;
        }
    }
    pieces >= 2
        && digits <= 12
        && long_words >= 1
        && long_words * 2 >= letter_pieces
        && !is_chunked(value, b"")
}

/// one word: a lowercase, capitalized or uppercase letter run under 20 letters with at most four
/// consonants in a row (y counts as a vowel).
fn is_word_field(field: &[u8]) -> bool {
    !field.is_empty()
        && field.len() < 20
        && field.iter().all(u8::is_ascii_alphabetic)
        && (field[1..].iter().all(u8::is_ascii_lowercase)
            || field.iter().all(u8::is_ascii_uppercase))
        && field
            .split(|byte| is_vowel(*byte))
            .all(|consonants| consonants.len() <= 4)
}

fn is_vowel(byte: u8) -> bool {
    matches!(
        byte.to_ascii_lowercase(),
        b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
    )
}

/// returns whether a value has a url scheme or network-path prefix.
pub fn is_url_shaped(value: &[u8]) -> bool {
    value.starts_with(b"//") || scheme_end(value).is_some()
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// locates the value a markdown link, an autolink, a markup element or a one-item flow sequence
/// of a url wraps, so the caller evaluates only that text. the returned range never drops a byte
/// that could hold a credential: wrapping syntax is dropped, and any other text run it leaves out
/// is shorter than the tier-3 minimum.
pub fn unwrap_markdown_target(value: &[u8]) -> Option<std::ops::Range<usize>> {
    // an autolink carries its own closer, so it is read before prose punctuation is trimmed: a
    // trailing `.` or `?` of a cut autolink may be the last byte of its target.
    if let Some(target) = unwrap_autolink(value) {
        return Some(target);
    }
    let value = trim_prose_delimiters(value);
    if let Some(text) = unwrap_markup(value) {
        return Some(text);
    }
    if let Some(target) = unwrap_autolink(value) {
        return Some(target);
    }
    if let Some(item) = unwrap_flow_item(value) {
        return Some(item);
    }

    let label_start = match value.first() {
        Some(b'[') => 1,
        Some(b'!') if value.get(1) == Some(&b'[') => 2,
        _ => return None,
    };
    let label_end = value[label_start..]
        .iter()
        .position(|byte| *byte == b']')
        .map(|offset| label_start + offset)?;
    let target_start = label_end + 2;
    if value.get(label_end + 1) != Some(&b'(')
        || value.last() != Some(&b')')
        || target_start > value.len() - 1
    {
        return None;
    }

    let label = &value[label_start..label_end];
    let target = &value[target_start..value.len() - 1];
    if has_opaque_run(label) || contains_ascii_whitespace(target) {
        return None;
    }

    Some(target_start..value.len() - 1)
}

/// an autolink `<scheme://...>`, whose closing `>` the value grammar may have consumed as a
/// trailing delimiter; its target holds no whitespace, `<` or `>`.
fn unwrap_autolink(value: &[u8]) -> Option<std::ops::Range<usize>> {
    let target = value.strip_prefix(b"<")?;
    let target = target.strip_suffix(b">").unwrap_or(target);
    (scheme_end(target).is_some()
        && !target
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'<' | b'>')))
    .then_some(1..1 + target.len())
}

/// a markup element on one line, or the part of one the line holds, anchored at both ends: the
/// text of `<name>text</name>` after one or more open tags, of `>text</name` after an open tag
/// closed on the line before, or a url the value grammar cut out of its element,
/// `https://host/path</name>...`. the first text run is returned for evaluation and the close tag
/// after it must match the innermost open tag the value holds. every dropped byte is syntax or a
/// short run: tag names are lowercase names shorter than the tier-3 minimum, later text runs are
/// enclosed by an element of their own and shorter than it all together, and together with the
/// returned text too when that text is short enough to be dropped for its length, and only a close
/// tag at the end of the value may lack its `>`. the value as a whole, tag names and texts, must
/// not be cut into short groups (`is_chunked_with_digits`): a token spread over several names or
/// texts, or cut into short groups inside the text, is evaluated whole instead.
fn unwrap_markup(value: &[u8]) -> Option<std::ops::Range<usize>> {
    let text = unwrap_markup_parts(value)?;
    (!is_chunked_with_digits(value, b"")).then_some(text)
}

fn unwrap_markup_parts(value: &[u8]) -> Option<std::ops::Range<usize>> {
    let residue = value.first() == Some(&b'>');
    let mut index = usize::from(residue);
    let mut open: Vec<&[u8]> = Vec::new();
    while !residue && value.get(index) == Some(&b'<') {
        let tag = read_tag(value, index)?;
        if !matches!(tag.kind, TagKind::Open) {
            return None;
        }
        open.push(tag.name);
        index = tag.end;
    }
    let text_start = index;
    let text_end = value[index..]
        .iter()
        .position(|byte| matches!(byte, b'<' | b'>'))
        .map_or(value.len(), |offset| index + offset);
    if text_end == text_start || value.get(text_end) != Some(&b'<') {
        return None;
    }
    let close = read_tag(value, text_end)?;
    if !matches!(close.kind, TagKind::Close) {
        return None;
    }
    match open.pop() {
        Some(name) if name != close.name => return None,
        // with no open tag and no residue only a url with its scheme may stand before the close,
        // which must then carry its `>`. a `//` value is not enough: returned alone it would read
        // as a path.
        None if !residue
            && (scheme_end(&value[text_start..text_end]).is_none() || !close.complete) =>
        {
            return None;
        }
        _ => {}
    }
    index = close.end;
    // the rest is tags, and short texts each enclosed by an element of its own. the dropped texts
    // are shorter than the tier-3 minimum together, and so are they with the returned text when
    // the caller drops that text for its length.
    let mut dropped = if text_end - text_start < MIN_ENTROPY_LENGTH {
        text_end - text_start
    } else {
        0
    };
    let mut after_open = false;
    let mut after_text = false;
    while index < value.len() {
        if value[index] != b'<' {
            let end = value[index..]
                .iter()
                .position(|byte| *byte == b'<')
                .map_or(value.len(), |offset| index + offset);
            dropped += end - index;
            if !after_open || dropped >= MIN_ENTROPY_LENGTH || value[index..end].contains(&b'>') {
                return None;
            }
            after_open = false;
            after_text = true;
            index = end;
            continue;
        }
        let tag = read_tag(value, index)?;
        match tag.kind {
            TagKind::Open if !after_text => open.push(tag.name),
            TagKind::Close => {
                if open.pop().is_some_and(|name| name != tag.name) {
                    return None;
                }
            }
            TagKind::Empty if !after_text => {}
            _ => return None,
        }
        after_open = matches!(tag.kind, TagKind::Open);
        after_text = false;
        index = tag.end;
    }
    Some(text_start..text_end)
}

enum TagKind {
    Open,
    Close,
    Empty,
}

struct Tag<'a> {
    kind: TagKind,
    name: &'a [u8],
    end: usize,
    complete: bool,
}

/// reads `<name>`, `</name>` or `<name/>` at `start`, with a lowercase name shorter than the
/// tier-3 minimum whose `:`-separated parts are each a name (`is_name_segment`: words, numbers
/// and lowercase alphanumerics of up to five bytes, as `xs:element` or `h1`). only a close tag may
/// be cut by the end of the value, and it is read as if closed there.
fn read_tag(value: &[u8], start: usize) -> Option<Tag<'_>> {
    let close = value.get(start + 1) == Some(&b'/');
    let name_start = start + 1 + usize::from(close);
    if !value.get(name_start).is_some_and(u8::is_ascii_lowercase) {
        return None;
    }
    let name_end = value[name_start..]
        .iter()
        .position(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-'))
        })
        .map_or(value.len(), |offset| name_start + offset);
    let name = &value[name_start..name_end];
    if name.len() >= MIN_ENTROPY_LENGTH
        || !name
            .split(|byte| *byte == b':')
            .all(|part| is_name_segment(part) && !matches!(part, b"." | b".."))
    {
        return None;
    }
    let kind = if close { TagKind::Close } else { TagKind::Open };
    let (kind, end, complete) = match &value[name_end..] {
        [] if close => (kind, name_end, false),
        [b'>', ..] => (kind, name_end + 1, true),
        [b'/', b'>', ..] if !close => (TagKind::Empty, name_end + 2, true),
        _ => return None,
    };
    Some(Tag {
        kind,
        name,
        end,
        complete,
    })
}

/// a flow sequence of one quoted url, `['https://...']` or `["https://..."]`, whose closing `]`
/// the value grammar may have consumed as a trailing delimiter.
fn unwrap_flow_item(value: &[u8]) -> Option<std::ops::Range<usize>> {
    let quote = *value.strip_prefix(b"[")?.first()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let close = 2 + value[2..].iter().position(|byte| *byte == quote)?;
    let item = &value[2..close];
    (scheme_end(item).is_some()
        && !contains_ascii_whitespace(item)
        && matches!(&value[close + 1..], [] | [b']']))
    .then_some(2..close)
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a key/value pair is a pinned action reference: `owner/repo[/path]` at a
/// 40-hex commit digest, a docker image at a sha-256 digest, or an action at a version tag
/// `vN[.N[.N]]` (optionally on a `word/` release branch) whose owner, repository and path
/// segments are each a name of words, short numbers and short lowercase alphanumerics, and whose
/// reference and branch word read as names together (`is_worded_name`).
pub fn is_pinned_action_ref(key: Option<&[u8]>, value: &[u8]) -> bool {
    let Some(key) = key else {
        return false;
    };
    let key = strip_matching_quotes(key);
    if key != b"uses" {
        return false;
    }

    let Some(at) = value.iter().rposition(|byte| *byte == b'@') else {
        return false;
    };
    let reference = &value[..at];
    let digest = &value[at + 1..];

    if let Some(image) = reference.strip_prefix(b"docker://") {
        return !image.is_empty()
            && !contains_ascii_whitespace(image)
            && digest
                .strip_prefix(b"sha256:")
                .is_some_and(|hex| is_hex_run(hex, 64, 64));
    }

    let is_reference = !reference.is_empty()
        && reference.contains(&b'/')
        && reference
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-'));
    if !is_reference {
        return false;
    }
    if is_hex_run(digest, 40, 40) {
        return true;
    }
    // a tag is not a credential, but the reference then carries the value's bytes, so each of its
    // segments must read as a name, and so must the reference and the branch word as a whole: a
    // token cut into short pieces passes every segment check one piece at a time.
    if !is_version_tag(digest) || !reference.split(|byte| *byte == b'/').all(is_name_segment) {
        return false;
    }
    let mut names = reference.to_vec();
    if let Some(slash) = digest.iter().position(|byte| *byte == b'/') {
        names.push(b'/');
        names.extend_from_slice(&digest[..slash]);
    }
    is_worded_name(&names)
}

/// `vN`, `vN.N` or `vN.N.N` with numbers of up to four digits, optionally after one lowercase
/// branch word and `/`, as in `release/v1`.
fn is_version_tag(value: &[u8]) -> bool {
    let tag = match value.iter().position(|byte| *byte == b'/') {
        Some(slash)
            if is_word_field(&value[..slash])
                && value[..slash].iter().all(u8::is_ascii_lowercase) =>
        {
            &value[slash + 1..]
        }
        Some(_) => return false,
        None => value,
    };
    let Some(numbers) = tag.strip_prefix(b"v") else {
        return false;
    };
    let parts: Vec<&[u8]> = numbers.split(|byte| *byte == b'.').collect();
    parts.len() <= 3
        && parts
            .iter()
            .all(|part| (1..=4).contains(&part.len()) && part.iter().all(u8::is_ascii_digit))
}

fn scheme_end(value: &[u8]) -> Option<usize> {
    if !value.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }

    let mut end = 1;
    while value
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
    {
        end += 1;
    }

    value
        .get(end..end + 3)
        .filter(|prefix| *prefix == b"://")
        .map(|_| end)
}

fn contains_ascii_whitespace(value: &[u8]) -> bool {
    value.iter().any(u8::is_ascii_whitespace)
}

/// drops the prose that closes a sentence around a url or link (rfc 3986 appendix c, gfm
/// autolinks): trailing `. , ; : ! ?`, and a closing `) ] } >` that has no opener in the value.
fn trim_prose_delimiters(value: &[u8]) -> &[u8] {
    const PAIRS: [(u8, u8); 4] = [(b'(', b')'), (b'[', b']'), (b'{', b'}'), (b'<', b'>')];
    let count = |target: u8| value.iter().filter(|byte| **byte == target).count();
    let mut unmatched = PAIRS.map(|(open, close)| count(close).saturating_sub(count(open)));
    let mut end = value.len();
    while let Some(&last) = value[..end].last() {
        if matches!(last, b'.' | b',' | b';' | b':' | b'!' | b'?') {
            end -= 1;
        } else if let Some(index) = PAIRS.iter().position(|(_, close)| *close == last)
            && unmatched[index] > 0
        {
            unmatched[index] -= 1;
            end -= 1;
        } else {
            break;
        }
    }
    &value[..end]
}

fn has_opaque_run(value: &[u8]) -> bool {
    let mut run_length = 0;
    for byte in value {
        if byte.is_ascii_whitespace() {
            run_length = 0;
        } else {
            run_length += 1;
            if run_length >= 20 {
                return true;
            }
        }
    }
    false
}

fn host_labels_allowed(authority: &[u8]) -> bool {
    let Some(last_dot) = authority.iter().rposition(|byte| *byte == b'.') else {
        return component_allowed(
            authority
                .split(|byte| *byte == b':')
                .next()
                .unwrap_or_default(),
        );
    };

    if !authority[..last_dot]
        .split(|byte| *byte == b'.')
        .all(component_allowed)
    {
        return false;
    }

    let final_label = authority[last_dot + 1..]
        .split(|byte| *byte == b':')
        .next()
        .unwrap_or_default();
    component_allowed(final_label)
}

fn path_segments_allowed(path: &[u8]) -> bool {
    let mut previous = None;
    for segment in path
        .split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty())
    {
        let decoded = percent_decode(segment);
        if decoded.len() >= 20
            && !crate::scanner::wordshape::is_word_structured(&decoded)
            && !is_slug(&decoded)
            && !is_git_position(&decoded, previous)
        {
            return false;
        }
        previous = Some(segment);
    }
    true
}

fn query_allowed(query: &[u8]) -> bool {
    for pair in query.split(|byte| *byte == b'&') {
        let (key, value) = match pair.iter().position(|byte| *byte == b'=') {
            Some(equal) => (&pair[..equal], &pair[equal + 1..]),
            None => {
                if !component_allowed(pair) {
                    return false;
                }
                (pair, &[][..])
            }
        };
        if is_veto_key(&percent_decode(key))
            || !component_allowed(key)
            || !(component_allowed(value) || is_form_list(value))
        {
            return false;
        }
    }
    true
}

/// recognizes a form-encoded list of words and short numbers, such as a font family with its axis
/// tuples. after percent-decoding, `+` and space join words and `, ; : @ | . - _` delimit list
/// items; every field is empty, at most four digits, one lowercase, uppercase or capitalized word
/// under 20 letters with at most four consonants in a row (y counts as a vowel, so axis tags such
/// as `wght` pass), two or three such capitalized words run together (`JetBrains`), or one letter
/// and digit mix of at most three bytes (`2P`), and at least one field is a word. any other field,
/// such as a longer letter and digit mix, a second short mix, a case change inside a hump, or a run
/// of five consonants, rejects the value, as the pieces of a random or sequential token do: a
/// token cut into mixes of up to three bytes is all mixes.
fn is_form_list(value: &[u8]) -> bool {
    let decoded = percent_decode(value);
    let mut has_word = false;
    let mut mixes = 0;
    for field in decoded.split(|byte| {
        matches!(
            byte,
            b'+' | b' ' | b',' | b';' | b':' | b'@' | b'|' | b'.' | b'-' | b'_'
        )
    }) {
        if field.iter().all(u8::is_ascii_digit) {
            if field.len() > 4 {
                return false;
            }
        } else if is_word_field(field) || is_camel_field(field) {
            has_word = true;
        } else if field.len() <= 3 && field.iter().all(u8::is_ascii_alphanumeric) {
            mixes += 1;
            if mixes > 1 {
                return false;
            }
        } else {
            return false;
        }
    }
    has_word
}

/// two or three capitalized words run together, each of two or more letters with a vowel, and
/// under 20 letters in all.
fn is_camel_field(field: &[u8]) -> bool {
    if field.len() >= 20 || !field.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let mut starts: Vec<usize> = field
        .iter()
        .enumerate()
        .filter(|(_, byte)| byte.is_ascii_uppercase())
        .map(|(index, _)| index)
        .collect();
    starts.push(field.len());
    (3..=4).contains(&starts.len())
        && starts.windows(2).all(|bounds| {
            let hump = &field[bounds[0]..bounds[1]];
            hump.len() >= 2 && is_word_field(hump) && hump.iter().any(|byte| is_vowel(*byte))
        })
}

fn is_veto_key(key: &[u8]) -> bool {
    const VETO_KEYS: &[&[u8]] = &[
        b"token",
        b"access_token",
        b"accesstoken",
        b"key",
        b"api_key",
        b"apikey",
        b"secret",
        b"sig",
        b"signature",
        b"password",
        b"passwd",
        b"pass",
        b"pwd",
        b"auth",
        b"authorization",
        b"x-amz-signature",
        b"x-amz-credential",
        b"x-amz-security-token",
        b"sv",
        b"st",
        b"se",
        b"sr",
        b"sp",
        b"sas",
        b"sas_token",
        b"private_token",
        b"client_secret",
        b"code",
    ];

    VETO_KEYS.iter().any(|candidate| {
        key.len() == candidate.len()
            && key
                .iter()
                .zip(*candidate)
                .all(|(byte, candidate)| byte.to_ascii_lowercase() == *candidate)
    })
}

fn component_allowed(value: &[u8]) -> bool {
    let decoded = percent_decode(value);
    decoded.len() < 20 || crate::scanner::wordshape::is_word_structured(&decoded)
}

fn is_git_position(segment: &[u8], previous: Option<&[u8]>) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    const GIT_POSITIONS: &[&[u8]] = &[
        b"compare", b"commit", b"commits", b"tree", b"blob", b"blame", b"raw",
    ];

    if GIT_POSITIONS.contains(&previous) && is_hex_run(segment, 7, 64) {
        return true;
    }
    if previous != b"compare" {
        return false;
    }

    split_hex_range(segment, b"...") || split_hex_range(segment, b"..")
}

fn split_hex_range(segment: &[u8], separator: &[u8]) -> bool {
    let Some(start) = segment
        .windows(separator.len())
        .position(|window| window == separator)
    else {
        return false;
    };
    let end = start + separator.len();
    is_hex_run(&segment[..start], 7, 64) && is_hex_run(&segment[end..], 7, 64)
}

fn is_hex_run(value: &[u8], min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.iter().all(u8::is_ascii_hexdigit)
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%'
            && let Some(byte) = value
                .get(index + 1..index + 3)
                .and_then(|digits| hex_byte(digits[0], digits[1]))
        {
            decoded.push(byte);
            index += 3;
            continue;
        }
        decoded.push(value[index]);
        index += 1;
    }
    decoded
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn strip_matching_quotes(value: &[u8]) -> &[u8] {
    if value.len() >= 2 && matches!(value[0], b'\'' | b'"') && value[0] == value[value.len() - 1] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Build = fn(&str) -> String;
    type Predicate = fn(&[u8]) -> bool;

    fn distinct_token(len: usize) -> String {
        (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .cycle()
            .take(len)
            .map(char::from)
            .collect()
    }

    fn hex_token(len: usize) -> String {
        (0..len)
            .map(|index| char::from_digit((index % 16) as u32, 16).unwrap())
            .collect()
    }

    const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /// xorshift64 over `alphabet`, so opaque values are generated rather than stored.
    fn random_token(alphabet: &[u8], len: usize, state: &mut u64) -> String {
        (0..len)
            .map(|_| {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                char::from(alphabet[(*state % alphabet.len() as u64) as usize])
            })
            .collect()
    }

    fn mixed_token(len: usize, seed: u64) -> String {
        random_token(BASE62, len, &mut (seed ^ 0x9e37_79b9_7f4a_7c15))
    }

    #[test]
    fn credential_free_urls_accept_expected_shapes() {
        let hex = hex_token(40);

        for value in [
            "https://github.com/owner/repo/compare/v1.0.0...v1.1.0".to_owned(),
            format!("//github.com/owner/repo/compare/{hex}...{hex}"),
            "https://www.apache.org/licenses/LICENSE-2.0".to_owned(),
            "https://img.shields.io/badge/license-MIT.svg".to_owned(),
            "https://github.com/owner/repo/archive/refs/tags/v2026.09.zip".to_owned(),
            "https://vector.example.internal:9598/metrics?format=prometheus".to_owned(),
            format!("https://host/commit/{hex}"),
            format!("https://host/blob/{hex}/README.md"),
            "https://host/path?format=short".to_owned(),
            "https://host/path#about".to_owned(),
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_reject_credentials_and_opaque_parts() {
        let opaque = distinct_token(24);
        let non_hex = distinct_token(40);
        let hex = hex_token(40);

        for value in [
            format!("https://user:{opaque}@host/"),
            format!("https://host/download/{opaque}"),
            format!("https://host/?token={opaque}"),
            format!("https://host/?x={opaque}"),
            "https://host/?key=abc123".to_owned(),
            format!("https://host/?%74oken={opaque}"),
            format!("https://host/#{opaque}"),
            format!("//host/{opaque}"),
            format!("https://{opaque}.ngrok.io/"),
            format!("https://host/blob/{non_hex}"),
            format!("https://host/x/{hex}"),
            format!("ftp://host/{opaque}"),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_reject_key_only_opaque_query_values() {
        let opaque = distinct_token(32);
        assert!(!is_credential_free_url(
            format!("https://host/?{opaque}").as_bytes()
        ));
        assert!(is_credential_free_url(b"https://host/?v=sample"));
        assert!(is_credential_free_url(b"https://host/?debug"));
    }

    #[test]
    fn credential_free_urls_reject_opaque_query_keys_with_values() {
        let opaque = distinct_token(32);
        let encoded = opaque
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        for key in [&opaque, &encoded] {
            assert!(!is_credential_free_url(
                format!("https://host/?{key}=1").as_bytes()
            ));
        }
    }

    #[test]
    fn credential_free_urls_preserve_query_key_and_value_policy() {
        let opaque = distinct_token(32);
        for key in ["page", "utm_source", "v", "redirect_uri"] {
            assert!(is_credential_free_url(
                format!("https://host/?{key}=sample").as_bytes()
            ));
            assert!(!is_credential_free_url(
                format!("https://host/?{key}={opaque}").as_bytes()
            ));
        }
        assert!(!is_credential_free_url(
            format!("https://host/path?token={opaque}").as_bytes()
        ));
    }

    #[test]
    fn unwraps_markdown_targets() {
        let link = b"[text](docs/plans/x.md)";
        let range = unwrap_markdown_target(link).unwrap();
        assert_eq!(&link[range], b"docs/plans/x.md");

        let image = b"![alt](/images/a.png)";
        let range = unwrap_markdown_target(image).unwrap();
        assert_eq!(&image[range], b"/images/a.png");

        let autolink = b"<https://example.com/a>";
        let range = unwrap_markdown_target(autolink).unwrap();
        assert_eq!(&autolink[range], b"https://example.com/a");
    }

    #[test]
    fn refuses_malformed_or_opaque_markdown_targets() {
        let opaque = distinct_token(20);
        let opaque_label = format!("[{opaque}](notes)");

        for value in [
            opaque_label.as_bytes(),
            b"[a](b) c",
            b"[a]",
            b"text](x)",
            b"[a](has space)",
            b"<not-a-url>",
        ] {
            assert!(unwrap_markdown_target(value).is_none());
        }
    }

    #[test]
    fn unwraps_markdown_targets_before_closing_prose() {
        for (value, target) in [
            (
                &b"[ADR-0002](../adr/0002-tier3-exemption-layer.md)."[..],
                &b"../adr/0002-tier3-exemption-layer.md"[..],
            ),
            (b"![alt](/images/a.png)!", b"/images/a.png"),
            (b"<https://example.com/a>:", b"https://example.com/a"),
            (b"[a](b)).", b"b"),
        ] {
            let range = unwrap_markdown_target(value).unwrap();
            assert_eq!(&value[range], target);
        }
        for value in [&b"[a](b)x."[..], b"[a](b) c.", b"[a](b.", b"<not-a-url>."] {
            assert!(unwrap_markdown_target(value).is_none());
        }
    }

    #[test]
    fn trims_only_unmatched_closers_and_sentence_punctuation() {
        for (value, trimmed) in [
            (&b"https://host/a.md)."[..], &b"https://host/a.md"[..]),
            (
                b"https://host/wiki/Word_(x)).",
                b"https://host/wiki/Word_(x)",
            ),
            (b"https://host/a]>}):;!?,.", b"https://host/a"),
            (b"https://host/a_(b)", b"https://host/a_(b)"),
            (b"<https://host/a>", b"<https://host/a>"),
            (b"https://host/a/", b"https://host/a/"),
        ] {
            assert_eq!(trim_prose_delimiters(value), trimmed);
        }
    }

    #[test]
    fn credential_free_urls_ignore_closing_prose() {
        for value in [
            "//github.com/acme/widget/blob/master/docs/adr/0002-tier3-exemption-layer.md).",
            "//github.com/acme/widget/blob/master/docs/adr/0002-tier3-exemption-layer.md):",
            "https://github.com/acme/widget/tree/master/docs/adr/0001-entropy-baseline-8-char-password.md)?",
            "https://github.com/acme/widget/blob/master/docs/adr/0002-tier3-exemption-layer.md>.",
            "https://github.com/acme/widget/blob/master/docs/adr/0002-tier3-exemption-layer.md].",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }

        let opaque = mixed_token(24, 1);
        for value in [
            format!("//host/download/{opaque})."),
            format!("https://host/blob/master/{opaque}.md)."),
            format!("https://user:{opaque}@host)."),
            format!("https://user:{opaque}@host/docs/readme.md):"),
            format!("https://host/?token={opaque})."),
            format!("https://host/#{opaque})!"),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_read_userinfo_only_in_the_authority() {
        for value in [
            "https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap",
            "//fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap",
            "https://fonts.googleapis.com?family=Roboto+Mono:wght@400;700",
            "https://host?next=Roboto+Mono:wght@400",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }

        let opaque = mixed_token(32, 2);
        for value in [
            format!("https://user:{opaque}@host/path"),
            format!("https://user:{opaque}@host?family=Roboto+Mono:wght@400;700"),
            format!(
                "https://user:{opaque}@fonts.example.internal/css2?family=Roboto+Mono:wght@400"
            ),
            format!("redis://:{opaque}@host:6379/0"),
            format!("//:{opaque}@host/"),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_accept_form_encoded_lists() {
        for value in [
            "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap",
            "https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,700;1,400&display=swap",
            "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200",
            "https://fonts.googleapis.com/css2?family=Noto%20Sans%20Display:wdth,wght@62.5..100,100..900",
            "https://fonts.googleapis.com/css?family=Open+Sans:400,700|Roboto+Slab:300,400&subset=latin,latin-ext,cyrillic",
            "https://search.example.internal/?q=rotation+schedule+for+deploy+keys",
            "https://host/?x=Alpha+Beta+GammaDelta+Epsilon",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_reject_opaque_fields_in_form_lists() {
        let opaque = mixed_token(24, 3);
        let short = mixed_token(12, 4);
        let mut state = 0x2545_f491_4f6c_dd1d;
        let base64 = random_token(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            44,
            &mut state,
        );
        let plus_split = format!("{}+{}+{}", &base64[..14], &base64[14..28], &base64[28..]);
        for value in [
            format!("https://fonts.googleapis.com/css2?family=Roboto+Mono:{opaque}@400"),
            format!("https://host/css2?family=Roboto+Mono:wght@{opaque}"),
            format!("https://host/?family=Roboto+Mono:wght@400;700&x={opaque}"),
            format!("https://host/?x=Roboto+Mono+{short}+Sans"),
            format!("https://host/?x={short}+{short}"),
            format!("https://host/?x={base64}"),
            format!("https://host/?x={plus_split}"),
            "https://host/?x=Alpha+Beta+Gamma+Bcdfgh+Sans".to_owned(),
            "https://host/?token=Roboto+Mono:wght@400;700".to_owned(),
            "https://host/?x=Alpha+Beta+Gamma+123456".to_owned(),
            "https://host/?x=1234-5678-9012-3456-7890".to_owned(),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn random_tokens_are_not_form_lists() {
        let alphabets: [&[u8]; 4] = [
            BASE62,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            b"0123456789abcdef",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15;
        for alphabet in alphabets {
            for len in [20, 24, 32, 44, 64] {
                for _ in 0..2_000 {
                    let token = random_token(alphabet, len, &mut state);
                    assert!(!is_form_list(token.as_bytes()), "{token}");
                    for url in [
                        format!("https://host/?x={token}"),
                        format!("https://host/css2?family=Roboto+Mono:{token}@400"),
                    ] {
                        assert!(!is_credential_free_url(url.as_bytes()), "{url}");
                    }
                }
            }
        }
    }

    #[test]
    fn sequential_alphabet_windows_are_not_form_lists() {
        let alphabets: [&[u8]; 3] = [
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
            b"0123456789abcdef",
        ];
        for alphabet in alphabets {
            for offset in 0..alphabet.len() {
                for len in 20..65 {
                    let window: String = (0..len)
                        .map(|index| char::from(alphabet[(offset + index) % alphabet.len()]))
                        .collect();
                    let url = format!("https://host/?t={window}");
                    assert!(!is_credential_free_url(url.as_bytes()), "{url}");
                }
            }
        }
    }

    #[test]
    fn recognizes_pinned_action_references() {
        let sha1 = hex_token(40);
        let action = format!("actions/checkout@{sha1}");
        let sha256 = hex_token(64);
        let image = format!("docker://ghcr.io/org/img@sha256:{sha256}");

        assert!(is_pinned_action_ref(Some(b"uses"), action.as_bytes()));
        assert!(is_pinned_action_ref(Some(b"\"uses\""), action.as_bytes()));
        assert!(is_pinned_action_ref(Some(b"uses"), image.as_bytes()));
    }

    #[test]
    fn recognizes_tag_pinned_action_references() {
        for value in [
            "actions/checkout@v4",
            "actions/setup-python@v5.1",
            "github/codeql-action/upload-sarif@v3.28.10",
            "acme-labs-internal/widget-release-publisher@v1",
            "pypa/gh-action-pypi-publish@release/v1",
        ] {
            assert!(
                is_pinned_action_ref(Some(b"uses"), value.as_bytes()),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_unpinned_or_wrong_action_references() {
        let opaque = distinct_token(24);
        let sha1 = hex_token(40);

        for value in [
            "actions/checkout@main".to_owned(),
            "actions/checkout@v4-beta".to_owned(),
            "actions/checkout@v12345".to_owned(),
            "actions/checkout@v1.2.3.4".to_owned(),
            "actions/checkout@Release/v1".to_owned(),
            "actions/checkout@a/b/v1".to_owned(),
            "actions/checkout@qzxwvkrtplmnbhgfdsjc/v1".to_owned(),
            "actions/checkout@releasereleaserelease/v1".to_owned(),
            "checkout@v4".to_owned(),
            "actions//checkout@v4".to_owned(),
            format!("{opaque}/checkout@v4"),
            format!("actions/{opaque}@v4"),
            format!("actions/checkout/{opaque}@v4"),
            format!("actions/checkout@release/{opaque}"),
        ] {
            assert!(
                !is_pinned_action_ref(Some(b"uses"), value.as_bytes()),
                "{value}"
            );
        }
        assert!(!is_pinned_action_ref(Some(b"use"), b"actions/checkout@v4"));
        assert!(!is_pinned_action_ref(
            Some(b"uses"),
            format!("actions/checkout@{opaque}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"use"),
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"uses_ref"),
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            None,
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"uses"),
            format!("checkout@{sha1}").as_bytes()
        ));
    }

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

    const ALPHABETS: [(&str, &[u8]); 6] = [
        ("base62", BASE62),
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
        ("printable", &PRINTABLE),
    ];

    /// samples per alphabet in the random-token cells below, so every position sees 1e5 tokens
    /// from the five encoding alphabets and 1e5 more from the printable one.
    const PER_ALPHABET: usize = 20_000;

    /// samples per cell of the word-shaped alphabet rates, and of printable tokens per position.
    const SAMPLES: usize = 100_000;

    /// feeds random tokens of 20 to 64 bytes from every alphabet to `exempted` and returns the
    /// count per alphabet it exempted.
    fn random_exemptions(seed: u64, exempted: impl Fn(&str) -> bool) -> Vec<(&'static str, usize)> {
        random_exemptions_in(&ALPHABETS, seed, exempted)
    }

    fn random_exemptions_in(
        alphabets: &[(&'static str, &[u8])],
        seed: u64,
        exempted: impl Fn(&str) -> bool,
    ) -> Vec<(&'static str, usize)> {
        let mut state = seed;
        alphabets
            .iter()
            .map(|(name, alphabet)| {
                let samples = if *name == "printable" {
                    SAMPLES
                } else {
                    PER_ALPHABET
                };
                let hits = (0..samples)
                    .filter(|index| {
                        let token = random_token(alphabet, 20 + index % 45, &mut state);
                        exempted(&token)
                    })
                    .count();
                (*name, hits)
            })
            .collect()
    }

    fn range_text(value: &str) -> Option<&str> {
        unwrap_markdown_target(value.as_bytes()).map(|range| &value[range])
    }

    #[test]
    fn unwraps_markup_elements_and_their_residue() {
        for (value, text) in [
            (
                "<key>NSCameraUsageDescription</key>",
                "NSCameraUsageDescription",
            ),
            (
                "<string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>",
                "$(PRODUCT_BUNDLE_IDENTIFIER)",
            ),
            (
                "<string>com.example.widget.helper</string>.",
                "com.example.widget.helper",
            ),
            (">{ctx_session_name}</code", "{ctx_session_name}"),
            (
                ">~/.config/widget/settings.toml</code>",
                "~/.config/widget/settings.toml",
            ),
            (
                "https://widget.example.org/guide</loc><lastmod>2026-09-01</lastmod><priority>0.8</priority></url",
                "https://widget.example.org/guide",
            ),
            ("<string>widget</string><key>next</key>", "widget"),
            (
                "<xs:element>widget-helper-name</xs:element>",
                "widget-helper-name",
            ),
            (
                "https://widget.example.org/guide</loc>",
                "https://widget.example.org/guide",
            ),
            ("<dict><key>widget-helper</key>", "widget-helper"),
        ] {
            assert_eq!(range_text(value), Some(text), "{value}");
        }
    }

    #[test]
    fn refuses_mismatched_malformed_or_opaque_markup() {
        let opaque = mixed_token(32, 11);
        for value in [
            "<string>widget</key>".to_owned(),
            "<key></key>".to_owned(),
            "<key>".to_owned(),
            ">widget-helper-name".to_owned(),
            "widget>helper</code>".to_owned(),
            "<1key>widget</1key>".to_owned(),
            "<key attr>widget</key>".to_owned(),
            format!("<string>widget</string><string>{opaque}</string>"),
            format!("<a>x</a>{opaque}"),
            // a text before a close tag with no open tag or residue is anchored only by a url.
            "super+shift+x=goto_split:right</code>".to_owned(),
            "https://widget.example.org/guide</loc".to_owned(),
            "//widget.example.org/guide</loc>".to_owned(),
            // open tags are never cut, and the names of dropped tags are short and lowercase.
            "ABCDEFG<HIJKLMNOPQRSTUVWX".to_owned(),
            "<string>widget</string><key".to_owned(),
            "<Key>widget</Key>".to_owned(),
            format!(">widget</{}", "a".repeat(20)),
            // a later text run needs an element of its own.
            "<string>widget</string>next".to_owned(),
            "<string>widget</string></dict>next".to_owned(),
            "<a>widget</a><b>x<c>y</c></b>".to_owned(),
            "<string>widget</string><key>next<key>".to_owned(),
        ] {
            assert_eq!(range_text(&value), None, "{value}");
        }
    }

    #[test]
    fn unwraps_cut_autolinks_and_single_item_flow_sequences() {
        for (value, text) in [
            (
                "<https://github.com/acme/widget/issues/new",
                "https://github.com/acme/widget/issues/new",
            ),
            (
                "['https://www.example.org/sponsor.html?user=acme'",
                "https://www.example.org/sponsor.html?user=acme",
            ),
            (
                "[\"https://docs.example.org/guide\"]",
                "https://docs.example.org/guide",
            ),
        ] {
            assert_eq!(range_text(value), Some(text), "{value}");
        }
        for value in [
            "[\"docs/guide.md\"]",
            "<not-a-url",
            "<https://host/a<b",
            "['a','b']",
            "['']",
            "['widget'x",
            "[widget]",
        ] {
            assert_eq!(range_text(value), None, "{value}");
        }
    }

    #[test]
    fn credential_free_link_chains_need_every_target_free() {
        for value in [
            "//img.shields.io/badge/ci-passing-green.svg)](https://github.com/acme/widget/actions",
            "MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE",
            "https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.example.org/widget/)",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
        // a chain needs an absolute url, and a label tail must be a name.
        for value in [
            "[guide](docs/guide.md#getting-started)",
            "MIT](LICENSE",
            "https://host/guide](https://host/widget",
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
        let opaque = mixed_token(32, 12);
        for value in [
            format!("//img.shields.io/badge/ci.svg)](https://host/{opaque}"),
            format!("//img.shields.io/badge/{opaque}.svg)](https://host/actions"),
            format!("{opaque}](https://img.shields.io/badge/ci.svg)](LICENSE"),
            format!("MIT](https://img.shields.io/badge/ci.svg)]({opaque}"),
            format!("MIT](https://img.shields.io/badge/ci.svg)](https://user:{opaque}@host/"),
            "MIT](https://img.shields.io/badge/ci.svg)](a b".to_owned(),
            "MIT](https://img.shields.io/badge/ci.svg)](".to_owned(),
            "MIT](https://img.shields.io/badge/ci.svg)x](LICENSE".to_owned(),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn email_addresses_of_words_are_credential_free() {
        for value in [
            "jane.appleseed@example.com",
            "build-bot+ci@ci.example-labs.org",
            "deploy@build-host-west.internal.example.com",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
        let opaque = mixed_token(24, 13);
        for value in [
            format!("{opaque}@example.com"),
            format!("jane@{opaque}.example.com"),
            format!("jane.{opaque}@example.com"),
            "jane.appleseed@localhost".to_owned(),
            "jane.appleseed@example.c0m".to_owned(),
            "jane.appleseed2@example.com".to_owned(),
            "jane@appleseed@example.com".to_owned(),
            "@appleseed.example.com".to_owned(),
            "jane.appleseed@".to_owned(),
            "jane.appleseed@.example.com".to_owned(),
            "jane..appleseed@example.com".to_owned(),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn slug_path_segments_and_fragments_are_credential_free() {
        for value in [
            "https://github.com/acme/widget/blob/master/docs/guide.md#using-sessions-in-the-terminal-view",
            "https://github.com/acme/widget/pull/42#pullrequestreview-12345678",
            "https://en.example.org/wiki/List_of_the_largest_widget_factories.html",
            "https://docs.example.org/blog/2026-09-10-docs-site-redesign.md",
            "https://docs.example.org/documentation/observation/migrating-from-the-observable-object-protocol",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
        let opaque = mixed_token(24, 14);
        let short = mixed_token(8, 15);
        for value in [
            format!("https://host/docs/guide.md#using-{opaque}"),
            format!("https://host/docs/using-{short}-in-the-terminal-view"),
            "https://host/docs/guide.md#pullrequestreview-12345678901".to_owned(),
            "https://host/docs/guide.md#ab-cd-ef-gh-ij-kl-mn-op".to_owned(),
            "https://host/docs/guide.md#Using-SessionS-in-the-terminal-view".to_owned(),
            "https://host/docs/guide.md#usingsessionsintheterminalview-now".to_owned(),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn form_lists_accept_camel_family_names_and_short_letter_digit_words() {
        for value in [
            "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap",
            "https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap",
            "https://fonts.googleapis.com/css2?family=SourceCodePro:wght@400&display=swap",
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
        let opaque = mixed_token(24, 16);
        for value in [
            "https://host/?x=JetBrainsMonoSansSerif".to_owned(),
            "https://host/?x=JeTBrains+Mono+Sans+Serif".to_owned(),
            "https://host/?x=JtBrns+Mono+Sans+Serif".to_owned(),
            "https://host/?x=Press+Start+2P3X+Sans+Serif".to_owned(),
            format!("https://host/?x={opaque}+Mono"),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    fn exempted_after_unwrapping(value: &str) -> bool {
        match unwrap_markdown_target(value.as_bytes()) {
            Some(range) => is_credential_free_url(&value.as_bytes()[range]),
            None => is_credential_free_url(value.as_bytes()),
        }
    }

    #[test]
    fn random_tokens_are_never_exempted_by_the_new_url_positions() {
        for (alphabet, hits) in
            random_exemptions(0x9e37_79b9_7f4a_7c14, |token| is_slug(token.as_bytes()))
        {
            assert_eq!(hits, 0, "slug, {alphabet}");
        }
        let positions: [(&str, Build); 5] = [
            ("email local part", |token| format!("{token}@example.com")),
            ("email host label", |token| {
                format!("jane@{token}.example.com")
            }),
            ("chain relative target", |token| {
                format!("MIT](https://img.example.org/badge.svg)]({token}")
            }),
            ("chain label tail", |token| {
                format!("{token}](https://img.example.org/badge.svg)](LICENSE")
            }),
            ("form list field", |token| {
                format!("https://host/css2?family={token}+Mono")
            }),
        ];
        for (index, (position, build)) in positions.iter().enumerate() {
            // a printable query value can end the query early with `#` or `&`, where the fragment
            // and field checks that predate these positions accept its short pieces; that
            // accepted cost is the url step's own, recorded in adr 0002.
            let alphabets = if *position == "form list field" {
                &ALPHABETS[..5]
            } else {
                &ALPHABETS[..]
            };
            for (alphabet, hits) in
                random_exemptions_in(alphabets, 0x9e37_79b9_7f4a_7c15 ^ index as u64, |token| {
                    // a token opening the value with a scheme or `//` makes the value a url of its
                    // own, judged by the url checks that predate these positions.
                    let value = build(token);
                    !(value.starts_with(token) && is_url_shaped(token.as_bytes()))
                        && exempted_after_unwrapping(&value)
                })
            {
                assert_eq!(hits, 0, "{position}, {alphabet}");
            }
        }
        // a token alone with no scheme or `//` could be freed only by the email and chain readings.
        for (alphabet, hits) in random_exemptions(0x9e37_79b9_7f4a_7c17, |token| {
            !is_url_shaped(token.as_bytes()) && is_credential_free_url(token.as_bytes())
        }) {
            assert_eq!(hits, 0, "token alone, {alphabet}");
        }
        // a chain or a cut autolink around a url must admit nothing the plain url does not: a path
        // segment or query value under 20 bytes, or one the word-structure step accepts.
        for (alphabet, hits) in random_exemptions(0x9e37_79b9_7f4a_7c16, |token| {
            [format!("/{token}"), format!("/?v={token}")]
                .iter()
                .any(|reference| {
                    let plain =
                        is_credential_free_url(format!("https://host{reference}").as_bytes());
                    let wrapped = [
                        format!("//img.example.org/badge.svg)](https://host{reference}"),
                        format!("<https://host{reference}"),
                    ];
                    !plain && wrapped.iter().any(|value| exempted_after_unwrapping(value))
                })
        }) {
            assert_eq!(hits, 0, "wrapped url, {alphabet}");
        }
    }

    #[test]
    fn random_tokens_are_never_dropped_by_markup_or_flow_unwrapping() {
        // the text around the token is returned whole, so the caller evaluates every token byte. a
        // token carrying markup, quote or link bytes may make the wrapper unreadable, and a token
        // cut into short groups makes the element chunked; the value is then evaluated whole. a
        // narrower text is never returned.
        let returned: [(&str, Build, Build); 5] = [
            (
                "element text",
                |token| format!("<string>{token}</string>"),
                |token| token.to_owned(),
            ),
            (
                "open tags and element text",
                |token| format!("<dict><key>{token}</key>"),
                |token| token.to_owned(),
            ),
            (
                "element residue",
                |token| format!(">{token}</code"),
                |token| token.to_owned(),
            ),
            (
                "url before a close tag",
                |token| format!("https://host/{token}</loc><lastmod>2026-09-01</lastmod></url"),
                |token| format!("https://host/{token}"),
            ),
            (
                "flow item",
                |token| format!("['https://host/{token}']"),
                |token| format!("https://host/{token}"),
            ),
        ];
        for (index, (position, build, text)) in returned.iter().enumerate() {
            for (alphabet, hits) in
                random_exemptions(0x2545_f491_4f6c_dd1d ^ index as u64, |token| {
                    let value = build(token);
                    let structural = token.bytes().any(|byte| {
                        !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'-' | b'_')
                    });
                    match range_text(&value) {
                        Some(returned) => returned != text(token),
                        None => !structural && !is_chunked_with_digits(value.as_bytes(), b""),
                    }
                })
            {
                assert_eq!(hits, 0, "{position}, {alphabet}");
            }
        }
        // a token alone is never read as markup or a flow item and narrowed.
        for (alphabet, hits) in random_exemptions(0x2545_f491_4f6c_dd1e, |token| {
            range_text(token).is_some_and(|returned| returned.len() < token.len())
        }) {
            assert_eq!(hits, 0, "token alone, {alphabet}");
        }
        // a later text run is never dropped: the value is refused and evaluated whole.
        for (alphabet, hits) in random_exemptions(0x5bd1_e995_5bd1_e995, |token| {
            let value = format!("<string>widget</string><string>{token}</string>");
            unwrap_markdown_target(value.as_bytes()).is_some()
        }) {
            assert_eq!(hits, 0, "later element text, {alphabet}");
        }
    }

    #[test]
    fn random_tokens_are_never_tag_pinned_action_references() {
        let positions: [(&str, Build); 6] = [
            ("owner", |token| format!("{token}/widget@v4")),
            ("repository", |token| format!("acme/{token}@v4")),
            ("path", |token| format!("acme/widget/{token}@v4.1")),
            ("tag", |token| format!("acme/widget@{token}")),
            ("branch tag", |token| format!("acme/widget@release/{token}")),
            ("branch word", |token| format!("acme/widget@{token}/v1")),
        ];
        for (index, (position, build)) in positions.iter().enumerate() {
            for (alphabet, hits) in
                random_exemptions(0x6c07_8965_6c07_8965 ^ index as u64, |token| {
                    // a 40-hex ref is the commit-digest pin, which predates the tag form.
                    !is_hex_run(token.as_bytes(), 40, 40)
                        && is_pinned_action_ref(Some(b"uses"), build(token).as_bytes())
                })
            {
                assert_eq!(hits, 0, "{position}, {alphabet}");
            }
        }
    }

    /// ten groups of lowercase letter, digit, letter, digit (`a9a9`), or letter groups of two to
    /// five, joined by `separator`.
    fn chunked_value(letter_digit: bool, separator: &str, state: &mut u64) -> String {
        let mut groups = Vec::new();
        let mut carried = 0;
        while (letter_digit && groups.len() < 10) || (!letter_digit && carried < 32) {
            let group = if letter_digit {
                (0..4)
                    .map(|index| {
                        let alphabet: &[u8] = if index % 2 == 0 {
                            b"abcdefghijklmnopqrstuvwxyz"
                        } else {
                            b"0123456789"
                        };
                        random_token(alphabet, 1, state)
                    })
                    .collect::<String>()
            } else {
                let len = 2 + (random_token(b"0123", 1, state).as_bytes()[0] - b'0') as usize;
                random_token(b"abcdefghijklmnopqrstuvwxyz", len, state)
            };
            carried += group.len();
            groups.push(group);
        }
        groups.join(separator)
    }

    /// a token cut into short groups passes every per-piece name check, so the readers judge the
    /// whole name: the owner, repository, path and branch word of an action, a badge's label tail
    /// and relative target (a benign `docs/` in front of the leaf does not vouch for it), a slug,
    /// an email address and a markup element all refuse it, while the names they were written for
    /// still pass.
    #[test]
    fn names_cut_into_short_groups_are_judged_as_a_whole() {
        let mut state = 0x517c_c1b7_2722_0a95;
        let mut refused = 0;
        for separator in ["_", "-", "."] {
            for letter_digit in [true, false] {
                for _ in 0..500 {
                    let value = chunked_value(letter_digit, separator, &mut state);
                    for reference in [
                        format!("acme/{value}@v1"),
                        format!("{value}/widget@v4"),
                        format!("acme/widget/{value}@v3.2.1"),
                        format!("acme/{value}@release/v1"),
                    ] {
                        assert!(
                            !is_pinned_action_ref(Some(b"uses"), reference.as_bytes()),
                            "{reference}"
                        );
                    }
                    let tail = &value[..19];
                    for chain in [
                        format!("MIT](https://img.example.org/badge.svg)](docs/{value}"),
                        format!("MIT](https://img.example.org/badge.svg)](docs/guide.md#{value}"),
                        format!("{tail}](https://img.example.org/badge.svg)](docs/{value}"),
                        format!("https://img.example.org/badge.svg)](https://host/docs/{value}"),
                        format!("{value}@example.com"),
                        format!("jane.{value}@example.com"),
                        format!("jane@{value}.example.com"),
                        format!("https://host/blog/{value}"),
                        format!("https://host/guide.md#{value}"),
                    ] {
                        assert!(!is_credential_free_url(chain.as_bytes()), "{chain}");
                    }
                    // a label tail of letter-digit groups, with the rest of the token in a segment
                    // of an absolute target short enough for the url to accept on its own.
                    if letter_digit {
                        let chain = format!(
                            "{tail}](https://img.example.org/badge.svg)](https://host/docs/{}",
                            &value[19..38]
                        );
                        assert!(!is_credential_free_url(chain.as_bytes()), "{chain}");
                    }
                    // the whole value in tag names of at most nineteen bytes, opened in turn.
                    let names: Vec<&str> = (0..value.len())
                        .step_by(19)
                        .map(|start| &value[start..value.len().min(start + 19)])
                        .collect();
                    let opened: String = names.iter().map(|name| format!("<{name}>")).collect();
                    let closed: String = names
                        .iter()
                        .rev()
                        .map(|name| format!("</{name}>"))
                        .collect();
                    for element in [
                        format!("<string>{value}</string>"),
                        format!("{opened}widget{closed}"),
                    ] {
                        assert_eq!(range_text(&element), None, "{element}");
                    }
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 3_000);

        for reference in [
            "actions/setup-python@v5",
            "github/codeql-action/upload-sarif@v3.28.10",
            "pypa/gh-action-pypi-publish@release/v1",
            "r-lib/actions/setup-r@v2",
            "ad-m/github-push-action@v0.6.0",
            "EmbarkStudios/cargo-deny-action@v1",
            "aws-actions/configure-aws-credentials@v4",
        ] {
            assert!(
                is_pinned_action_ref(Some(b"uses"), reference.as_bytes()),
                "{reference}"
            );
        }
        for chain in [
            "MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE",
            "MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../adr/0002-tier3-exemption-layer.md#layer-usage",
            "Covenant](https://img.shields.io/badge/covenant-2.1-purple.svg)](CODE_OF_CONDUCT.md",
            "https://img.shields.io/badge/docs-latest-blue.svg)](docs/",
            "jane.appleseed@example.com",
            "build-bot+ci@ci.example-labs.org",
            "https://docs.example.org/blog/2026-09-10-docs-site-redesign.md",
            "https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap",
        ] {
            assert!(is_credential_free_url(chain.as_bytes()), "{chain}");
        }
        // a relative target's word must stand in its leaf, not in a directory above it.
        for chain in [
            "MIT](https://img.shields.io/badge/ci.svg)](docs/x9",
            "MIT](https://img.shields.io/badge/ci.svg)](docs/a1b2c3",
            "https://host/?x=Mono+a1b+c2d+e3f+g4h",
        ] {
            assert!(!is_credential_free_url(chain.as_bytes()), "{chain}");
        }
        // later element texts are dropped only while they, and a short returned text with them,
        // stay below the tier-3 minimum.
        assert_eq!(
            range_text("<key>CFBundleName</key><string>Widget</string>"),
            Some("CFBundleName")
        );
        assert_eq!(
            range_text("<a>abcdefghijklmnop</a><b>qrstuvwxyzabcdef</b>"),
            None
        );
        assert_eq!(
            range_text(
                "https://widget.example.org/guide</loc><lastmod>2026-09-26</lastmod><changefreq>weekly</changefreq></url>"
            ),
            Some("https://widget.example.org/guide")
        );
        // a tag name is a name: a lowercase letter-digit run of eighteen bytes is not one.
        let name = format!(
            "h{}",
            random_token(b"abcdefghijklmnopqrstuvwxyz0123456789", 17, &mut state)
        );
        assert_eq!(range_text(&format!("<{name}>widget</{name}>")), None);
    }

    /// the rate at which random strings over the alphabet the recognizers accept pass them: none
    /// over the full alphabet. words are what these recognizers look for, so a lowercase-only
    /// alphabet chunked by separators passes at a measurable rate (about 1.9% slug and 0.5% email,
    /// against 0.7% for the word-structure step on the same strings); the bounds catch drift and
    /// the figures are recorded in ADR 0002.
    #[test]
    fn word_shaped_alphabet_pass_rates_stay_bounded() {
        let cells: [(&str, &[u8], Predicate, f64); 5] = [
            (
                "slug, full alphabet",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-",
                is_slug,
                0.001,
            ),
            (
                "email, full alphabet",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+@",
                is_email_address,
                0.001,
            ),
            (
                "form list, full alphabet",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+",
                is_form_list,
                0.001,
            ),
            (
                "slug, lowercase and dash",
                b"abcdefghijklmnopqrstuvwxyz-",
                is_slug,
                0.025,
            ),
            (
                "email, lowercase, dot and at",
                b"abcdefghijklmnopqrstuvwxyz.@",
                is_email_address,
                0.01,
            ),
        ];
        let mut state = 0x94d0_49bb_1331_11eb;
        for (name, alphabet, recognizer, bound) in cells {
            let hits = (0..SAMPLES)
                .filter(|index| {
                    recognizer(random_token(alphabet, 20 + index % 45, &mut state).as_bytes())
                })
                .count();
            let rate = hits as f64 / SAMPLES as f64;
            eprintln!("{name}: {hits}/{SAMPLES} = {rate:.5}");
            assert!(rate < bound, "{name}: {rate}");
        }
    }
}
