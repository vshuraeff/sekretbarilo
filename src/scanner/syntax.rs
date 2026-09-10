// source expression recognition for exemption-layer filtering

#[allow(dead_code)]
/// recognizes a complete source expression, bounded to the current line and `max_scan` bytes, starting at `start`.
/// `Some(range)` means the bytes are syntactic source scaffolding with no eligible secret token.
pub fn expression_span(
    line: &[u8],
    start: usize,
    max_scan: usize,
) -> Option<std::ops::Range<usize>> {
    let remaining = line.get(start..)?;
    let limit = remaining.len().min(max_scan);
    let bytes = &remaining[..limit];
    let bytes = &bytes[..bytes
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .unwrap_or(bytes.len())];
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
    // an initial empty bracket pair can introduce a go slice type.
    let slice_head_end = bytes[cursor..].starts_with(b"[]").then_some(cursor + 2);
    match bytes.get(cursor)? {
        b'(' | b'[' => {
            stack[depth] = bytes[cursor];
            depth += 1;
            cursor += 1;
        }
        _ => {
            cursor = identifier_end(bytes, cursor)?;
            after_ident = true;
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
                after_ident = false;
                if depth == 0
                    && slice_head_end == Some(cursor)
                    && let Some(end) = identifier_end(bytes, cursor)
                {
                    cursor = end;
                    after_ident = true;
                }
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
                if suffix.starts_with(b"::") && bytes.get(cursor) == Some(&b'<') {
                    after_ident = true;
                    continue;
                }
                cursor = identifier_end(bytes, cursor)?;
                after_ident = true;
                continue;
            }
            if suffix.starts_with(b"=>") {
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
                cursor += 1;
                after_ident = false;
                continue;
            }
            if !matches!(byte, b'(' | b'[' | b'{') && !(byte == b'<' && after_ident) {
                return None;
            }
        }
        if depth == stack.len() {
            return None;
        }
        stack[depth] = byte;
        depth += 1;
        cursor += 1;
        after_ident = false;
    }

    if depth != 0
        || !had_group
        || bytes[..cursor].windows(3).any(|window| window == b"://")
        || contains_secret_token(&bytes[..cursor])
    {
        return None;
    }
    Some(start..start + cursor)
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
fn secret_token(token: &[u8]) -> bool {
    if token.len() < crate::scanner::entropy::MIN_ENTROPY_LENGTH
        || crate::scanner::wordshape::is_word_structured(token)
    {
        return false;
    }

    if crate::scanner::entropy::shannon_entropy(token) >= 4.0 {
        return true;
    }

    let hex = token.strip_prefix(b"0x").unwrap_or(token);
    matches!(hex.len(), 32 | 40 | 64) && hex.iter().all(u8::is_ascii_hexdigit)
}

fn contains_secret_token(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            let Some(end) = quote_end(bytes, cursor) else {
                return true;
            };
            if secret_token(&bytes[cursor + 1..end - 1]) {
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
            b"foo(",
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
        assert_eq!(expression_span(b"foo(\n)", 0, 100), None);
        assert_eq!(expression_span(b"foo(\r)", 0, 100), None);
        assert_eq!(expression_span(br##"foo("abc\"##, 0, 100), None);
    }
}
