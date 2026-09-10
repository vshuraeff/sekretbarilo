use std::ops::Range;

/// enumerate same-line argument bodies in source order, without decoding escapes.
/// ordinary quotes and rust raw/byte delimiters are supported; python-specific
/// raw/byte forms and go backtick strings are out of scope. no state crosses lines.
/// each byte is visited a bounded number of times, including raw delimiter hashes.
pub(super) fn collect(input: &[u8], mut emit: impl FnMut(Range<usize>)) {
    let end = input
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(input.len());
    let line = &input[..end];
    let mut index = 0;
    let mut depth = 0usize;
    let mut argument_start = false;
    while index < line.len() {
        let mut quote = index;
        let mut raw = false;
        let mut hashes = 0;
        if line[index] == b'b' && line.get(index + 1) == Some(&b'"') {
            quote += 1;
        } else {
            let prefix = if line[index] == b'r' {
                Some(index + 1)
            } else if line[index] == b'b' && line.get(index + 1) == Some(&b'r') {
                Some(index + 2)
            } else {
                None
            };
            if let Some(mut cursor) = prefix {
                while line.get(cursor) == Some(&b'#') {
                    hashes += 1;
                    cursor += 1;
                }
                if line.get(cursor) == Some(&b'"') {
                    quote = cursor;
                    raw = true;
                }
            }
        }
        if matches!(line[quote], b'\'' | b'"') {
            let delimiter = line[quote];
            let start = quote + 1;
            let mut cursor = start;
            let mut closed = false;
            while cursor < line.len() {
                if !raw && line[cursor] == b'\\' {
                    cursor = (cursor + 2).min(line.len());
                } else if line[cursor] == delimiter {
                    let body_end = cursor;
                    cursor += 1;
                    if raw {
                        let mut matched = 0;
                        while matched < hashes && line.get(cursor) == Some(&b'#') {
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
                return;
            }
            index = cursor;
            argument_start = false;
            continue;
        }
        match line[index] {
            b'(' => {
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
