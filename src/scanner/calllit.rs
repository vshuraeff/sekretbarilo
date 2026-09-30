use std::ops::Range;

/// an open call carries argument context into the next line only while its outermost `(`
/// lies within this many bytes, the bound the engine gives syntax::expression_span.
const MAX_CALL_SPAN: usize = 4096;

/// deeper nesting at a line break is treated as unbalanced input rather than carried.
const MAX_CALL_DEPTH: usize = 16;

/// enumerate argument bodies in source order, without decoding escapes.
/// ordinary quotes and rust raw/byte delimiters are supported; python-specific
/// raw/byte forms and go backtick strings are out of scope. paren depth and a pending
/// argument position cross line breaks within the span and depth bounds above; a literal
/// never does, and one left open at a line end resets the call state, since the lexical
/// state after it is unknown. input without line breaks is collected as a single line.
/// each byte is visited a bounded number of times, including raw delimiter hashes.
pub(super) fn collect(input: &[u8], mut emit: impl FnMut(Range<usize>)) {
    let mut index = 0;
    let mut depth = 0usize;
    let mut call_start = 0;
    let mut argument_start = false;
    while index < input.len() {
        if matches!(input[index], b'\r' | b'\n') {
            if depth > MAX_CALL_DEPTH || (depth > 0 && index - call_start > MAX_CALL_SPAN) {
                depth = 0;
                argument_start = false;
            }
            index += 1;
            continue;
        }
        let mut quote = index;
        let mut raw = false;
        let mut hashes = 0;
        if input[index] == b'b' && input.get(index + 1) == Some(&b'"') {
            quote += 1;
        } else {
            let prefix = if input[index] == b'r' {
                Some(index + 1)
            } else if input[index] == b'b' && input.get(index + 1) == Some(&b'r') {
                Some(index + 2)
            } else {
                None
            };
            if let Some(mut cursor) = prefix {
                while input.get(cursor) == Some(&b'#') {
                    hashes += 1;
                    cursor += 1;
                }
                if input.get(cursor) == Some(&b'"') {
                    quote = cursor;
                    raw = true;
                }
            }
        }
        if matches!(input[quote], b'\'' | b'"') {
            let delimiter = input[quote];
            let start = quote + 1;
            let mut cursor = start;
            let mut closed = false;
            while cursor < input.len() && !matches!(input[cursor], b'\r' | b'\n') {
                if !raw && input[cursor] == b'\\' {
                    // a backslash never escapes a line break: the break leaves the literal open.
                    cursor += 1;
                    if input
                        .get(cursor)
                        .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
                    {
                        cursor += 1;
                    }
                } else if input[cursor] == delimiter {
                    let body_end = cursor;
                    cursor += 1;
                    if raw {
                        let mut matched = 0;
                        while matched < hashes && input.get(cursor) == Some(&b'#') {
                            matched += 1;
                            cursor += 1;
                        }
                        if matched != hashes {
                            continue;
                        }
                    }
                    if argument_start {
                        emit(start..body_end);
                    }
                    closed = true;
                    break;
                } else {
                    cursor += 1;
                }
            }
            if !closed {
                depth = 0;
            }
            index = cursor;
            argument_start = false;
            continue;
        }
        match input[index] {
            b'(' => {
                if depth == 0 {
                    call_start = index;
                }
                depth += 1;
                argument_start = true;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                argument_start = false;
            }
            b',' => argument_start = depth > 0,
            b' ' | b'\t' => {}
            _ => argument_start = false,
        }
        index += 1;
    }
}
