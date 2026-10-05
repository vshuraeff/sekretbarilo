//! complete-source parsers report proven literal bodies and their kinds.
//! callers use generic full posture when a parse, line, or body kind is unknown.

use std::ops::{ControlFlow, Range};
use tree_sitter::{Node, ParseOptions, Parser};

use super::literals::LineLiterals;

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const PARSE_CALLBACK_BUDGET: usize = 32_768;

/// a complete parse carries body kinds for the engine's candidate routing.
/// `None` at either level means the engine must use generic full posture.
#[allow(dead_code)]
pub(crate) struct ParsedLine {
    pub(crate) literals: LineLiterals,
    regex_bodies: Vec<Range<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BodyKind {
    String,
    Regex,
    Generic,
}

impl ParsedLine {
    /// a body crossing a regex boundary has no proven single kind.
    #[allow(dead_code)]
    pub(crate) fn body_kind(&self, body: &Range<usize>) -> BodyKind {
        if body.start >= body.end
            || !self
                .literals
                .bodies
                .iter()
                .any(|literal| literal.start <= body.start && body.end <= literal.end)
        {
            return BodyKind::Generic;
        }
        if self
            .regex_bodies
            .iter()
            .any(|regex| regex.start <= body.start && body.end <= regex.end)
        {
            BodyKind::Regex
        } else if self
            .regex_bodies
            .iter()
            .any(|regex| regex.start < body.end && body.start < regex.end)
        {
            BodyKind::Generic
        } else {
            BodyKind::String
        }
    }
}

#[cfg(test)]
thread_local! {
    static PARSER_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug)]
enum Dialect {
    C,
    Cpp,
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Swift,
    Header,
}

fn dialect(path: &str) -> Option<Dialect> {
    let extension = path.rsplit_once('.')?.1;
    if extension == "C" {
        return Some(Dialect::Cpp);
    }
    let extension = extension.to_ascii_lowercase();
    match extension.as_str() {
        "c" => Some(Dialect::C),
        "h" => Some(Dialect::Header),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some(Dialect::Cpp),
        "py" | "pyi" => Some(Dialect::Python),
        "js" | "jsx" | "mjs" | "cjs" => Some(Dialect::JavaScript),
        "ts" | "mts" | "cts" => Some(Dialect::TypeScript),
        "tsx" => Some(Dialect::Tsx),
        "swift" => Some(Dialect::Swift),
        _ => None,
    }
}

pub(crate) fn supports_path(path: &str) -> bool {
    dialect(path).is_some()
}

/// only a fully validated complete blob can establish code outside literal bodies.
#[cfg(test)]
pub(crate) fn analyze(path: &str, source: &[u8]) -> Option<Vec<Option<LineLiterals>>> {
    analyze_with_kinds(path, source).map(|lines| {
        lines
            .into_iter()
            .map(|line| line.map(|parsed| parsed.literals))
            .collect()
    })
}

pub(crate) fn analyze_with_kinds(path: &str, source: &[u8]) -> Option<Vec<Option<ParsedLine>>> {
    let dialect = dialect(path)?;
    if matches!(dialect, Dialect::Header) {
        analyze_bounded_with_kinds(Dialect::Cpp, source, PARSE_CALLBACK_BUDGET)
            .or_else(|| analyze_bounded_with_kinds(Dialect::C, source, PARSE_CALLBACK_BUDGET))
    } else {
        analyze_bounded_with_kinds(dialect, source, PARSE_CALLBACK_BUDGET)
    }
}

#[cfg(test)]
fn analyze_bounded(
    dialect: Dialect,
    source: &[u8],
    budget: usize,
) -> Option<Vec<Option<LineLiterals>>> {
    analyze_bounded_with_kinds(dialect, source, budget).map(|lines| {
        lines
            .into_iter()
            .map(|line| line.map(|parsed| parsed.literals))
            .collect()
    })
}

fn analyze_bounded_with_kinds(
    dialect: Dialect,
    source: &[u8],
    budget: usize,
) -> Option<Vec<Option<ParsedLine>>> {
    if source.len() > MAX_BYTES
        || std::str::from_utf8(source).is_err()
        || source.contains(&0)
        || source
            .iter()
            .enumerate()
            .any(|(i, &b)| b == b'\r' && source.get(i + 1) != Some(&b'\n'))
        || (matches!(dialect, Dialect::C) && source.windows(2).any(|bytes| bytes == b"R\""))
        || (matches!(dialect, Dialect::C | Dialect::Cpp)
            && (source.windows(2).any(|bytes| bytes == b"??")
                || source.split(|&b| b == b'\n').any(|line| {
                    line.iter()
                        .rfind(|&&b| !matches!(b, b' ' | b'\t' | b'\r' | 0x0b | 0x0c))
                        == Some(&b'\\')
                })))
        || (matches!(dialect, Dialect::Python) && !python_utf8(source))
        || budget == 0
    {
        return None;
    }
    let language = match dialect {
        Dialect::C => tree_sitter_c::LANGUAGE.into(),
        Dialect::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Dialect::Python => tree_sitter_python::LANGUAGE.into(),
        Dialect::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Dialect::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Dialect::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Dialect::Swift => tree_sitter_swift::LANGUAGE.into(),
        Dialect::Header => return None,
    };
    #[cfg(test)]
    PARSER_BUILDS.with(|count| count.set(count.get() + 1));
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let mut callback_count = 0;
    let mut progress = |_: &tree_sitter::ParseState| {
        callback_count += 1;
        if callback_count > budget {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let tree = parser.parse_with_options(
        &mut |offset, _| source.get(offset..).unwrap_or_default(),
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    )?;
    // tree-sitter-swift can recover through a zero-width ordinary leaf that carries the error
    // cost, so neither an error nor a missing node reaches the walk below.
    if tree.root_node().has_error() {
        return None;
    }
    let mut spans = Vec::new();
    let mut regex_spans = Vec::new();
    let mut opaque = Vec::new();
    let mut cursor = tree.walk();
    let mut count = 0;
    loop {
        let node = cursor.node();
        count += 1;
        if count > MAX_NODES
            || node.is_error()
            || node.is_missing()
            || node.end_byte() > source.len()
        {
            return None;
        }
        match node.kind() {
            // swift kinds never reach the arms of the other families.
            _ if matches!(dialect, Dialect::Swift) => {
                swift_node(node, source, &mut spans)?;
            }
            "string" if matches!(dialect, Dialect::Python) => {
                python_string(node, source, &mut spans)?;
            }
            "format_specifier" if matches!(dialect, Dialect::Python) => {
                if source.get(node.start_byte()) != Some(&b':') {
                    return None;
                }
                segmented_body(
                    node,
                    node.start_byte() + 1..node.end_byte(),
                    "format_expression",
                    &mut spans,
                )?;
            }
            "string" if node.is_named() => {
                spans.push(quoted_body(node, source)?);
            }
            "template_string" | "template_literal_type" => {
                if source.get(node.start_byte()) != Some(&b'`')
                    || source.get(node.end_byte().checked_sub(1)?) != Some(&b'`')
                {
                    return None;
                }
                let hole = if node.kind() == "template_literal_type" {
                    "template_type"
                } else {
                    "template_substitution"
                };
                segmented_body(
                    node,
                    node.start_byte() + 1..node.end_byte() - 1,
                    hole,
                    &mut spans,
                )?;
            }
            "regex_pattern" => {
                spans.push(node.byte_range());
                regex_spans.push(node.byte_range());
            }
            "jsx_text" => {
                spans.push(node.byte_range());
            }
            "html_character_reference"
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "jsx_element") =>
            {
                spans.push(node.byte_range());
            }
            "string_literal" | "char_literal" => {
                spans.push(quoted_body(node, source)?);
            }
            "raw_string_literal" => {
                let mut children = node.walk();
                if let Some(body) = node
                    .children(&mut children)
                    .find(|n| n.kind() == "raw_string_content")
                {
                    spans.push(body.byte_range());
                } else if !node.utf8_text(source).ok()?.contains("()") {
                    return None;
                }
            }
            "preproc_arg" | "system_lib_string" => {
                // without splices these opaque tokens cannot affect the next physical line.
                if node.start_position().row != node.end_position().row {
                    return None;
                }
                if node.kind() == "preproc_arg"
                    && source[node.byte_range()]
                        .windows(2)
                        .any(|pair| matches!(pair, b"R\"" | b"/*"))
                {
                    return None;
                }
                opaque.push(node.start_position().row);
            }
            _ => {}
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return project(source, spans, regex_spans, opaque);
            }
        }
    }
}

fn python_utf8(source: &[u8]) -> bool {
    for line in source.split(|&b| b == b'\n').take(2) {
        let line = line.trim_ascii_start();
        if !line.starts_with(b"#") {
            continue;
        }
        for start in 0..line.len().saturating_sub(6) {
            if !line[start..].starts_with(b"coding:") && !line[start..].starts_with(b"coding=") {
                continue;
            }
            let name = line[start + 7..].trim_ascii_start();
            let end = name
                .iter()
                .position(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'.'))
                .unwrap_or(name.len());
            let normalized: Vec<_> = name[..end]
                .iter()
                .filter(|&&b| !matches!(b, b'-' | b'_'))
                .map(u8::to_ascii_lowercase)
                .collect();
            if normalized != b"utf8" {
                return false;
            }
        }
    }
    true
}

fn python_string(node: Node<'_>, source: &[u8], spans: &mut Vec<Range<usize>>) -> Option<()> {
    let start = node.child(0)?;
    let end = node.child(node.child_count().checked_sub(1)?)?;
    if start.kind() != "string_start" || end.kind() != "string_end" {
        return None;
    }
    let opener = source.get(start.byte_range())?;
    let quote = opener.iter().position(|&b| matches!(b, b'\'' | b'"'))?;
    let prefix = opener[..quote].to_ascii_lowercase();
    if !matches!(
        prefix.as_slice(),
        b"" | b"r" | b"u" | b"b" | b"br" | b"rb" | b"f" | b"fr" | b"rf" | b"t" | b"tr" | b"rt"
    ) || !matches!(&opener[quote..], b"\"" | b"'" | b"\"\"\"" | b"'''")
        || source.get(end.byte_range())? != &opener[quote..]
    {
        return None;
    }
    let mut children = node.walk();
    if node.named_children(&mut children).any(|child| {
        !matches!(
            child.kind(),
            "string_start" | "string_end" | "string_content" | "interpolation"
        )
    }) {
        return None;
    }
    segmented_body(
        node,
        start.end_byte()..end.start_byte(),
        "interpolation",
        spans,
    )
}

fn segmented_body(
    node: Node<'_>,
    body: Range<usize>,
    hole: &str,
    spans: &mut Vec<Range<usize>>,
) -> Option<()> {
    let mut start = body.start;
    let mut cursor = node.walk();
    for child in node
        .children(&mut cursor)
        .filter(|child| child.kind() == hole)
    {
        if child.start_byte() < start || child.end_byte() > body.end {
            return None;
        }
        if start < child.start_byte() {
            spans.push(start..child.start_byte());
        }
        start = child.end_byte();
    }
    if start < body.end {
        spans.push(start..body.end);
    }
    Some(())
}

fn quoted_body(node: Node<'_>, source: &[u8]) -> Option<Range<usize>> {
    let bytes = source.get(node.byte_range())?;
    let quote = bytes.iter().position(|&b| matches!(b, b'\'' | b'"'))?;
    if !matches!(&bytes[..quote], b"" | b"u8" | b"u" | b"U" | b"L")
        || bytes.last() != bytes.get(quote)
        || bytes.len() < quote + 2
    {
        return None;
    }
    Some(node.start_byte() + quote + 1..node.end_byte() - 1)
}

/// swift literal bodies. the grammar accepts some text the compiler lexes differently, so every
/// such shape rejects the whole file: a comment inside a literal, a regex literal, a slash the
/// compiler may lex as a bare regex, a single-line literal over several rows and a misplaced
/// multi-line delimiter.
fn swift_node(node: Node<'_>, source: &[u8], spans: &mut Vec<Range<usize>>) -> Option<()> {
    match node.kind() {
        "line_string_literal" | "multi_line_string_literal" => swift_string(node, source, spans),
        "raw_string_literal" => swift_raw_string(node, source, spans),
        "regex_literal" => None,
        "#" if !node.is_named() && source.get(node.end_byte()) == Some(&b'/') => None,
        // swiftc re-lexes a prefix operator holding a slash as a bare regex opener, and an
        // operator is prefix when it is not left-bound but is right-bound.
        "/" | "/=" | "custom_operator" if source.get(node.byte_range())?.contains(&b'/') => {
            let start = node.start_byte();
            let before = |back: usize| start.checked_sub(back).and_then(|i| source.get(i));
            let left_bound = match before(1) {
                None => false,
                Some(&b)
                    if swift_space(b) || matches!(b, b'(' | b'[' | b'{' | b',' | b';' | b':') =>
                {
                    false
                }
                Some(b'/') => before(2) != Some(&b'*'),
                Some(0xa0) => before(2) != Some(&0xc2),
                Some(_) => true,
            };
            let right_bound = source
                .get(node.end_byte())
                .is_some_and(|&b| !swift_space(b));
            (left_bound || !right_bound).then_some(())
        }
        // `#warning`, `#error` and `#sourceLocation` swallow their line as one token: the whole
        // line after `#` is kept as a body, and a multi-line literal there could leave the line.
        "diagnostic" => {
            let text = source.get(node.byte_range())?;
            if node.start_position().row != node.end_position().row
                || text.first() != Some(&b'#')
                || text.windows(3).any(|window| window == b"\"\"\"")
            {
                return None;
            }
            spans.push(node.start_byte() + 1..node.end_byte());
            Some(())
        }
        _ => Some(()),
    }
}

fn swift_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// a gap between two tokens of one literal can only be skipped whitespace.
fn swift_gap(source: &[u8], gap: Range<usize>) -> Option<()> {
    source
        .get(gap)?
        .iter()
        .all(|&b| swift_space(b))
        .then_some(())
}

/// swiftc requires a multi-line opener to end its line and the closer to start its own line.
fn swift_multi_line(source: &[u8], body: Range<usize>) -> Option<()> {
    let body = source.get(body)?;
    let first = body.iter().position(|&b| b == b'\n')?;
    let last = body.iter().rposition(|&b| b == b'\n')?;
    let opener = body[..first].strip_suffix(b"\r").unwrap_or(&body[..first]);
    (opener.iter().all(|&b| matches!(b, b' ' | b'\t'))
        && body[last + 1..].iter().all(|&b| matches!(b, b' ' | b'\t')))
    .then_some(())
}

fn swift_string(node: Node<'_>, source: &[u8], spans: &mut Vec<Range<usize>>) -> Option<()> {
    let multi = node.kind() == "multi_line_string_literal";
    let delimiter = if multi { "\"\"\"" } else { "\"" };
    let count = usize::try_from(node.child_count()).ok()?;
    let first = node.child(0)?;
    let last = node.child(count.checked_sub(1)?.try_into().ok()?)?;
    if count < 2
        || [first, last]
            .iter()
            .any(|edge| edge.is_named() || edge.kind() != delimiter)
        || first.byte_range() != (node.start_byte()..node.start_byte() + delimiter.len())
        || last.byte_range() != (node.end_byte().checked_sub(delimiter.len())?..node.end_byte())
        || first.end_byte() > last.start_byte()
    {
        return None;
    }
    let body = first.end_byte()..last.start_byte();
    if multi {
        swift_multi_line(source, body.clone())?;
    } else if node.start_position().row != node.end_position().row {
        return None;
    }
    // `\(` opens an interpolation and its own `)` closes it; the tokens are siblings.
    let mut holes = Vec::new();
    let mut hole = None;
    let mut previous = body.start;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor).skip(1).take(count - 2) {
        swift_gap(source, previous..child.start_byte())?;
        match (child.kind(), child.is_named(), hole) {
            ("\\(", false, None) => hole = Some(child.start_byte()),
            ("interpolated_expression", true, Some(_)) | (",", false, Some(_)) => {}
            (")", false, Some(start)) => {
                holes.push(start..child.end_byte());
                hole = None;
            }
            ("str_escaped_char", true, None) => {}
            ("line_str_text", true, None) if !multi => {}
            ("multi_line_str_text", true, None) | ("\"", false, None) if multi => {}
            _ => return None,
        }
        previous = child.end_byte();
    }
    if hole.is_some() {
        return None;
    }
    swift_gap(source, previous..body.end)?;
    let mut start = body.start;
    for hole in holes {
        if start < hole.start {
            spans.push(start..hole.start);
        }
        start = hole.end;
    }
    if start < body.end {
        spans.push(start..body.end);
    }
    Some(())
}

/// raw strings are external-scanner tokens that carry their own `#` delimiters.
fn swift_raw_string(node: Node<'_>, source: &[u8], spans: &mut Vec<Range<usize>>) -> Option<()> {
    let text = source.get(node.byte_range())?;
    let hashes = text.iter().take_while(|&&b| b == b'#').count();
    // swiftc reads a raw string closed on its opening row as single-line, even after `#"""`.
    let multi = node.start_position().row != node.end_position().row;
    let quotes = if multi { 3 } else { 1 };
    let open = hashes + quotes;
    let mut closer = vec![b'"'; quotes];
    closer.extend(std::iter::repeat_n(b'#', hashes));
    let mut escape = vec![b'\\'];
    escape.extend(std::iter::repeat_n(b'#', hashes));
    let close = text.len().checked_sub(closer.len())?;
    if hashes == 0
        || close < open
        || !text[hashes..open].iter().all(|&b| b == b'"')
        || text[close..] != closer[..]
        // swiftc reads `\#"` as an escaped quote, while the scanner closes the string on it.
        || text[..close].ends_with(&escape)
    {
        return None;
    }
    let body = node.start_byte() + open..node.start_byte() + close;
    if multi {
        swift_multi_line(source, body.clone())?;
    }
    let mut interpolation = escape;
    interpolation.push(b'(');
    let count = usize::try_from(node.child_count()).ok()?;
    let mut previous = node.start_byte();
    let mut cursor = node.walk();
    for (index, child) in node.children(&mut cursor).enumerate() {
        swift_gap(source, previous..child.start_byte())?;
        match child.kind() {
            "raw_str_end_part" if index + 1 == count => {}
            "raw_str_part" | "raw_str_continuing_indicator" if index + 1 < count => {}
            "raw_str_interpolation" if index + 1 < count => {
                let start = child.child(0)?;
                let end = child.child(child.child_count().checked_sub(1)?)?;
                if start.kind() != "raw_str_interpolation_start"
                    || start.start_byte() != child.start_byte()
                    || source.get(start.byte_range())? != interpolation.as_slice()
                    || end.kind() != ")"
                    || end.is_named()
                    || end.end_byte() != child.end_byte()
                {
                    return None;
                }
            }
            _ => return None,
        }
        previous = child.end_byte();
    }
    if previous != node.end_byte() {
        return None;
    }
    segmented_body(node, body, "raw_str_interpolation", spans)
}

fn project(
    source: &[u8],
    mut spans: Vec<Range<usize>>,
    mut regex_spans: Vec<Range<usize>>,
    opaque: Vec<usize>,
) -> Option<Vec<Option<ParsedLine>>> {
    spans.sort_by_key(|span| (span.start, span.end));
    regex_spans.sort_by_key(|span| (span.start, span.end));
    if spans
        .iter()
        .any(|span| span.start > span.end || span.end > source.len())
        || spans.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return None;
    }
    let mut joined: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = joined.last_mut()
            && previous.end == span.start
        {
            previous.end = span.end;
        } else {
            joined.push(span);
        }
    }
    let spans = joined;
    let mut result = Vec::new();
    let mut offset = 0;
    let mut first = 0;
    let mut first_regex = 0;
    for line in source.split(|&b| b == b'\n') {
        let end = offset + line.strip_suffix(b"\r").unwrap_or(line).len();
        while first < spans.len() && spans[first].end <= offset {
            first += 1;
        }
        let bodies = spans[first..]
            .iter()
            .take_while(|span| span.start <= end)
            .filter_map(|span| {
                let start = span.start.max(offset);
                let stop = span.end.min(end);
                (start < stop).then_some(start - offset..stop - offset)
            })
            .collect();
        while first_regex < regex_spans.len() && regex_spans[first_regex].end <= offset {
            first_regex += 1;
        }
        let regex_bodies = regex_spans[first_regex..]
            .iter()
            .take_while(|span| span.start <= end)
            .filter_map(|span| {
                let start = span.start.max(offset);
                let stop = span.end.min(end);
                (start < stop).then_some(start - offset..stop - offset)
            })
            .collect();
        result.push(Some(ParsedLine {
            literals: LineLiterals {
                bodies,
                known: true,
                test_span: None,
            },
            regex_bodies,
        }));
        offset += line.len() + 1;
    }
    for row in opaque {
        *result.get_mut(row)? = None;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_kind_requires_proven_containment_and_preserves_regex_subranges() {
        let source = b"const value = /alpha[0-9]+/; const text = \"plain\";";
        let lines = analyze_with_kinds("src/value.js", source).unwrap();
        let line = lines[0].as_ref().unwrap();
        let regex = line.regex_bodies[0].clone();
        let string = line
            .literals
            .bodies
            .iter()
            .find(|body| source[(*body).clone()] == *b"plain")
            .unwrap();
        assert_eq!(line.body_kind(&regex), BodyKind::Regex);
        assert_eq!(
            line.body_kind(&(regex.start + 1..regex.end - 1)),
            BodyKind::Regex
        );
        assert_eq!(line.body_kind(string), BodyKind::String);
        assert_eq!(line.body_kind(&(0..5)), BodyKind::Generic);
        assert_eq!(
            line.body_kind(&(regex.start..string.end)),
            BodyKind::Generic
        );
        assert_eq!(
            line.body_kind(&(source.len()..source.len())),
            BodyKind::Generic
        );
    }

    #[test]
    fn headers_accept_clean_cpp_and_c() {
        let cpp = b"namespace demo { const char *key = \"cpp body\"; }";
        let c = b"void take(int values[static 10]) { const char *key = \"c body\"; }";
        assert!(analyze("src/value.h", cpp).is_some());
        assert!(analyze_bounded(Dialect::C, c, PARSE_CALLBACK_BUDGET).is_some());
        assert!(analyze("src/value.h", c).is_some());
        assert!(analyze("src/value.c", b"const char *key = R\"(raw)\";").is_none());
    }

    #[test]
    fn parser_error_falls_back_for_every_dialect() {
        for (path, source) in [
            ("src/value.c", &b"int value = ;"[..]),
            ("src/value.cpp", &b"int value = ;"[..]),
            ("src/value.py", &b"value = ("[..]),
            ("src/value.js", &b"const value = ;"[..]),
            ("src/value.ts", &b"const value: string = ;"[..]),
            ("src/value.tsx", &b"const value = <div>"[..]),
            ("src/value.swift", &b"let value ="[..]),
        ] {
            assert!(analyze(path, source).is_none(), "{path}");
        }
    }

    #[test]
    fn callback_budget_exhaustion_is_repeatable() {
        let source = "const value = 1;\n".repeat(10_000);
        for _ in 0..3 {
            assert!(analyze_bounded(Dialect::JavaScript, source.as_bytes(), 1).is_none());
        }
        assert!(
            analyze_bounded(
                Dialect::JavaScript,
                source.as_bytes(),
                PARSE_CALLBACK_BUDGET
            )
            .is_some()
        );
    }

    fn append_body(source: &mut String, expected: &mut Vec<Range<usize>>, body: &str) {
        let start = source.len();
        source.push_str(body);
        expected.push(start..source.len());
    }

    fn assert_oracle(path: &str, source: &str, expected: &[Range<usize>]) {
        let lines = analyze(path, source.as_bytes()).unwrap_or_else(|| {
            panic!("generated supported source must be known: {path}: {source}")
        });
        assert_eq!(lines.len(), source.split('\n').count());
        let mut offset = 0;
        let mut observed = Vec::new();
        let mut physical_expected = Vec::new();
        for (line, text) in lines.iter().zip(source.split('\n')) {
            let end = offset + text.strip_suffix('\r').unwrap_or(text).len();
            for span in expected {
                let start = span.start.max(offset);
                let stop = span.end.min(end);
                if start < stop {
                    physical_expected.push(start..stop);
                }
            }
            for span in &line
                .as_ref()
                .expect("ordinary generated line must be known")
                .bodies
            {
                observed.push(offset + span.start..offset + span.end);
            }
            offset += text.len() + 1;
        }
        physical_expected.sort_by_key(|span| span.start);
        assert_eq!(observed, physical_expected, "{path}: {source}");
    }

    #[test]
    fn python_generated_body_oracle() {
        for seed in 0..100 {
            let body = format!("generated{seed}\\nbody");
            for prefix in [
                "", "r", "R", "u", "b", "br", "rb", "f", "fr", "rf", "t", "tr", "rt",
            ] {
                for quotes in ["\"", "'", "\"\"\"", "'''"] {
                    let mut source = format!("ordinary = 1\nvalue = {prefix}{quotes}");
                    let mut spans = Vec::new();
                    append_body(&mut source, &mut spans, &body);
                    source.push_str(quotes);
                    source.push_str("\n# ordinary comment\n");
                    assert_oracle("src/value.py", &source, &spans);
                }
            }
        }
    }

    #[test]
    fn python_interpolation_oracle() {
        for prefix in ["f", "F", "fr", "rf", "t", "T", "tr", "rt"] {
            let mut source = format!("value = {prefix}\"\"\"");
            let mut spans = Vec::new();
            append_body(&mut source, &mut spans, "first\\nline\nsecond");
            source.push_str("{call(\"");
            append_body(&mut source, &mut spans, "nested\\tvalue");
            source.push_str("\"):");
            append_body(&mut source, &mut spans, "format");
            source.push_str("{call('");
            append_body(&mut source, &mut spans, "width");
            source.push_str("')}");
            append_body(&mut source, &mut spans, "spec");
            source.push('}');
            append_body(&mut source, &mut spans, "last");
            source.push_str("\"\"\"\nordinary = 1\n");
            assert_oracle("src/value.py", &source, &spans);
        }
        assert_oracle(
            "src/value.py",
            "value = f\"{call(\"nested\")}\"",
            std::slice::from_ref(&(17..23)),
        );
    }

    #[test]
    fn python_encoding_and_malformed_prefixes_fall_back() {
        for source in [
            "# coding: latin-1\nvalue = 'body'",
            "# encoding=utf-16\nvalue = 'body'",
            "value = tf'body'",
            "value = f'{unclosed'",
            "value = t'{unclosed'",
        ] {
            assert!(
                analyze("src/value.py", source.as_bytes()).is_none(),
                "{source}"
            );
        }
        assert!(analyze("src/value.py", b"# coding: utf-8\nvalue = 'body'").is_some());
    }

    #[test]
    fn javascript_generated_body_oracle() {
        for seed in 0..100 {
            for path in [
                "src/value.js",
                "src/value.jsx",
                "src/value.mjs",
                "src/value.cjs",
                "src/value.tsx",
            ] {
                let mut source = String::from("let ordinary = 1;\nconst value = `");
                let mut spans = Vec::new();
                append_body(&mut source, &mut spans, &format!("text{seed}\\n\nline"));
                source.push_str("${call(\"");
                append_body(&mut source, &mut spans, &format!("nested{seed}\\t"));
                source.push_str("\", `");
                append_body(&mut source, &mut spans, "inner");
                source.push_str("${ordinary}");
                append_body(&mut source, &mut spans, "tail");
                source.push_str("`)}");
                append_body(&mut source, &mut spans, "after");
                source.push_str("`;\nconst element = <div label=\"");
                append_body(&mut source, &mut spans, "attribute&amp;value");
                source.push_str("\">");
                append_body(&mut source, &mut spans, "jsx&amp;text\nsecond");
                source.push_str("{call('");
                append_body(&mut source, &mut spans, "nested attribute");
                source.push_str("')}</div>;\nconst regex = /");
                append_body(&mut source, &mut spans, "[abc]\\/[xyz]");
                source.push_str("/gi;\nordinary++;\nordinary / other;\n");
                assert_oracle(path, &source, &spans);
            }
        }
    }

    #[test]
    fn javascript_line_separators_preserve_original_offsets() {
        for separator in ["\n", "\r\n", "\u{2028}", "\u{2029}"] {
            let mut source = format!("// comment{separator}const value = `");
            let mut spans = Vec::new();
            append_body(&mut source, &mut spans, &format!("first{separator}last"));
            source.push_str("`;\n");
            assert_oracle("src/value.js", &source, &spans);
        }
        assert!(analyze("src/value.js", b"const value = `body\rline`;").is_none());
    }

    #[test]
    fn typescript_generated_body_oracle() {
        for seed in 0..100 {
            for path in [
                "src/value.ts",
                "src/value.mts",
                "src/value.cts",
                "src/value.tsx",
            ] {
                let mut source = String::from("type Value = `");
                let mut spans = Vec::new();
                append_body(&mut source, &mut spans, &format!("prefix{seed}"));
                source.push_str("${\"");
                append_body(&mut source, &mut spans, "nested");
                source.push_str("\" | number}");
                append_body(&mut source, &mut spans, "suffix");
                source.push_str("`;\nconst value: string = `");
                append_body(&mut source, &mut spans, "template");
                source.push_str("${call('");
                append_body(&mut source, &mut spans, "nested value");
                source.push_str("')}`;\nconst ordinary: number = 1;\n");
                assert_oracle(path, &source, &spans);
            }
        }
    }

    #[test]
    fn swift_generated_body_oracle() {
        for seed in 0..100 {
            let mut source = String::from("let ordinary = 1\nlet value = \"");
            let mut spans = Vec::new();
            append_body(
                &mut source,
                &mut spans,
                &format!("line{seed} \\\"quoted\\\" \\u{{1F600}}\\\\"),
            );
            source.push_str("\\(call(\"");
            append_body(&mut source, &mut spans, &format!("nested{seed}\\t"));
            source.push_str("\", #\"");
            append_body(&mut source, &mut spans, "raw \\(kept) \"inner\"");
            source.push_str("\"#))");
            append_body(&mut source, &mut spans, " middle ");
            source.push_str("\\(ordinary, format: .hex)\\(ordinary)");
            append_body(&mut source, &mut spans, "tail");
            source.push_str("\"\nlet empty = \"\" + #\"\"#\nlet multi = \"\"\"");
            append_body(
                &mut source,
                &mut spans,
                &format!("\n    first \"quoted\" \"\" line{seed}\n    second "),
            );
            source.push_str("\\(call(\"");
            append_body(&mut source, &mut spans, "inner");
            source.push_str("\"))");
            append_body(&mut source, &mut spans, " third\\\n    fourth\n    ");
            source.push_str("\"\"\"\n");
            for hashes in 1..=3 {
                let delimiter = "#".repeat(hashes);
                let fewer = "#".repeat(hashes - 1);
                source.push_str(&format!("let raw{hashes} = {delimiter}\""));
                append_body(
                    &mut source,
                    &mut spans,
                    &format!("raw{seed} \"{fewer} \\(not) \\{fewer}(not) \\{delimiter}n "),
                );
                source.push_str(&format!("\\{delimiter}(call(\""));
                append_body(&mut source, &mut spans, &format!("hole{hashes}"));
                source.push_str("\"))");
                append_body(&mut source, &mut spans, " end");
                source.push_str(&format!("\"{delimiter}\n"));
            }
            source.push_str("let rawMulti = ##\"\"\"");
            append_body(
                &mut source,
                &mut spans,
                &format!("\n    raw multi{seed} \"\"\"# \\#(not)\n    "),
            );
            source.push_str("\\##(ordinary)");
            append_body(&mut source, &mut spans, "\n    ");
            // closed on its opening row, `#"""` opens a single-line raw string.
            source.push_str("\"\"\"##\nlet single = #\"");
            append_body(&mut source, &mut spans, "\"\"\"\"one row\"\"");
            // a diagnostic line is one token, kept whole as a body.
            source.push_str("\"#\n#");
            append_body(&mut source, &mut spans, "warning(\"diagnostic\")");
            source.push_str("\nlet ratio = total / count\n// ordinary comment\n");
            assert_oracle("src/value.swift", &source, &spans);
            assert_oracle("src/Value.SWIFT", &source, &spans);
        }
    }

    #[test]
    fn swift_crlf_preserves_original_offsets() {
        let mut source = String::from("let value = \"");
        let mut spans = Vec::new();
        append_body(&mut source, &mut spans, "single");
        source.push_str("\"\r\nlet multi = \"\"\"");
        append_body(&mut source, &mut spans, " \r\n    body\r\n    ");
        source.push_str("\"\"\"\r\nlet raw = #\"\"\"");
        append_body(&mut source, &mut spans, "\r\n    raw\r\n");
        source.push_str("\"\"\"#\r\n");
        assert_oracle("src/value.swift", &source, &spans);
    }

    fn swift_parses_cleanly(source: &str) -> bool {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
            .unwrap();
        !parser.parse(source, None).unwrap().root_node().has_error()
    }

    #[test]
    fn swift_rejects_grammar_mislabels_and_uncertain_sources() {
        // each of these parses without an error node, so only the adapter can reject it.
        for source in [
            "let value = \"/* note */\"",
            "let value = \"\"\"\n    /* note */ text\n    \"\"\"",
            "let pattern = /[a-z]+/",
            "let pattern = #/[a-z]+ /#",
            "call()\n/b/.wholeMatch(text)",
            "let q = a /b/ c",
            "let value = \"first\nsecond\"",
            "let value = \"\"\"abc\"\"\"",
            "let value = \"\"\"\"\"\"",
            "let value = \"\"\"\n    abc\"\"\"",
            "let value = #\"\"\"abc\n    \"\"\"#",
            "let value = #\"abc\\#\"#",
        ] {
            assert!(swift_parses_cleanly(source), "grammar error: {source}");
            assert!(
                analyze("src/value.swift", source.as_bytes()).is_none(),
                "{source}"
            );
        }
        // a recovered parse that shows no error or missing node to a tree walk.
        let recovered = "let version = info?[\"key\"] as? String ?? \"unknown\"";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(recovered, None).unwrap();
        assert!(tree.root_node().has_error());
        let mut cursor = tree.walk();
        let mut hidden = true;
        loop {
            hidden &= !cursor.node().is_error() && !cursor.node().is_missing();
            if cursor.goto_first_child() || cursor.goto_next_sibling() {
                continue;
            }
            while cursor.goto_parent() && !cursor.goto_next_sibling() {}
            if cursor.node() == tree.root_node() {
                break;
            }
        }
        assert!(hidden, "the recovery shape now shows an error node");
        assert!(analyze("src/value.swift", recovered.as_bytes()).is_none());
        for source in [
            &b"let value = ("[..],
            b"let value = \"unterminated\n",
            b"let value = 1\r",
            b"let value = \"\0\"",
            b"let value = \"\xff\"",
            b"#warning(\"\"\"\nbody\n\"\"\")\n",
        ] {
            assert!(analyze("src/value.swift", source).is_none(), "{source:?}");
        }
        // balanced or bound slashes are division, and a regex-like string is a string.
        for source in [
            "let ratio = total / count\nlet other = total/count\nlet path = \"a /b/ c\"",
            "let value = (total) / count\nvalue /= 2",
        ] {
            assert!(swift_parses_cleanly(source), "grammar error: {source}");
            assert!(
                analyze("src/value.swift", source.as_bytes()).is_some(),
                "{source}"
            );
        }
    }

    #[test]
    fn pathless_and_shell_scanning_construct_no_parser() {
        use crate::config::allowlist::CompiledAllowlist;
        use crate::diff::parser::{AddedLine, DiffFile};
        use crate::scanner::engine::{redact_text, scan, scan_text};
        use crate::scanner::rules::{compile_rules, load_default_rules};
        assert!(analyze("src/value.c", b"int value;").is_some());
        assert!(PARSER_BUILDS.with(|count| count.get()) > 0);
        PARSER_BUILDS.with(|count| count.set(0));
        assert!(analyze("src/value.swift", b"let value = 1").is_some());
        assert_eq!(PARSER_BUILDS.with(|count| count.get()), 1);
        PARSER_BUILDS.with(|count| count.set(0));
        let scanner = compile_rules(&load_default_rules().unwrap()).unwrap();
        let al = CompiledAllowlist::default_allowlist().unwrap();
        scan_text("const value = 'ordinary';", &scanner, &al);
        redact_text("const value = 'ordinary';", &scanner, &al);
        scan_text("let value = #\"ordinary \\#(name)\"#", &scanner, &al);
        redact_text("let value = \"ordinary \\(name)\"", &scanner, &al);
        for path in ["", "command.sh"] {
            let input = DiffFile {
                path: path.into(),
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                context: Some(b"echo ordinary".to_vec()),
                added_lines: vec![AddedLine {
                    line_number: 1,
                    content: b"echo ordinary".to_vec(),
                }],
            };
            scan(&[input], &scanner, &al);
        }
        assert_eq!(PARSER_BUILDS.with(|count| count.get()), 0);
    }

    #[test]
    fn c_generated_body_oracle() {
        for dialect in [Dialect::C, Dialect::Cpp] {
            for seed in 0..256 {
                let value: String = (0..32)
                    .map(|i| char::from(b'a' + ((i * 7 + seed) % 26) as u8))
                    .collect();
                let source = format!(
                    "int ordinary = 1;\nconst char *value = \"{value}\\n{value}\";\n// {value}\n"
                );
                let lines =
                    analyze_bounded(dialect, source.as_bytes(), PARSE_CALLBACK_BUDGET).unwrap();
                assert!(lines[0].as_ref().unwrap().bodies.is_empty());
                assert!(lines[2].as_ref().unwrap().bodies.is_empty());
                let start = "const char *value = \"".len();
                assert_eq!(
                    lines[1].as_ref().unwrap().bodies,
                    vec![start..start + value.len() * 2 + 2]
                );
            }
        }
    }

    #[test]
    fn c_raw_and_opaque_regions() {
        let source =
            b"#define VALUE opaque_value\nconst auto value = u8R\"tag(first\nsecond)tag\";\n";
        let lines = analyze("src/value.cpp", source).unwrap();
        assert!(lines[0].is_none());
        let start = "const auto value = u8R\"tag(".len();
        assert_eq!(lines[1].as_ref().unwrap().bodies, vec![start..start + 5]);
        assert_eq!(lines[2].as_ref().unwrap().bodies, vec![0..6]);
        assert_eq!(analyze("src/value.C", source), Some(lines));
    }

    #[test]
    fn c_rejects_uncertain_and_exhausted_sources() {
        for source in [
            &b"int x = ;"[..],
            b"int x",
            b"/\\\n* comment */",
            b"// note \\\x0b\n/*\nconst char *k = \"opaque\";\n// */\n",
            b"// note \\\x0c\n/*\nconst char *k = \"opaque\";\n// */\n",
            b"R\\ \r\n\"(body)\"",
            b"??/\n",
            b"int x;\r",
            b"\xff",
            b"#define VALUE R\"(\nbody\n)\"\n",
        ] {
            assert!(analyze("src/value.cpp", source).is_none(), "{source:?}");
        }
        for prefix in ["R", "LR", "uR", "UR", "u8R"] {
            let source = format!("int ordinary;\nconst char *k = {prefix}\"(opaque)\";\n");
            assert!(
                analyze("src/value.c", source.as_bytes()).is_none(),
                "{prefix}"
            );
        }
        assert!(analyze_bounded(Dialect::C, b"int x;", 0).is_none());
        assert!(analyze("src/value.c", &vec![b' '; MAX_BYTES + 1]).is_none());
        assert!(analyze("src/value.c", b"").is_some());
        assert_oracle(
            "src/value.c",
            "#define VALUE /* comment\nbody */\nint ordinary;\n",
            &[],
        );
    }

    #[test]
    fn every_grammar_obeys_tiny_oversized_and_callback_budget_controls() {
        let oversized = vec![b' '; MAX_BYTES + 1];
        for dialect in [
            Dialect::C,
            Dialect::Cpp,
            Dialect::Python,
            Dialect::JavaScript,
            Dialect::TypeScript,
            Dialect::Tsx,
            Dialect::Swift,
        ] {
            assert!(analyze_bounded(dialect, b"", PARSE_CALLBACK_BUDGET).is_some());
            assert!(analyze_bounded(dialect, b"", 0).is_none());
            assert!(analyze_bounded(dialect, &oversized, PARSE_CALLBACK_BUDGET).is_none());
        }
    }
}
