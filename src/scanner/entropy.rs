// shannon entropy calculation

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
/// this is a documented lexical heuristic, not proof the value is non-secret.
pub fn is_path_shaped(value: &[u8]) -> bool {
    if !is_rooted_path(value)
        || value.windows(3).any(|window| window == b"://")
        || value.iter().any(|&byte| !is_path_byte(byte))
        || value
            .iter()
            .filter(|&&byte| matches!(byte, b'/' | b'\\'))
            .count()
            < 2
    {
        return false;
    }

    has_wordy_path_leaf(value)
}

fn is_rooted_path(value: &[u8]) -> bool {
    value.starts_with(b"/")
        || value.starts_with(b"~/")
        || value.starts_with(b"./")
        || value.starts_with(b"../")
        || (value.len() >= 3
            && value[0].is_ascii_alphabetic()
            && value[1] == b':'
            && matches!(value[2], b'/' | b'\\'))
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'\\' | b'.' | b'-' | b'_' | b'~' | b':' | b'@' | b'+' | b'%' | b','
        )
}

fn has_wordy_path_leaf(value: &[u8]) -> bool {
    let mut end = value.len();
    while end > 0 && matches!(value[end - 1], b'/' | b'\\') {
        end -= 1;
    }
    let value = &value[..end];
    let Some(mut leaf) = value
        .rsplit(|&byte| matches!(byte, b'/' | b'\\'))
        .find(|segment| !segment.is_empty())
    else {
        return false;
    };

    if let Some(extension_start) = leaf.iter().rposition(|&byte| byte == b'.') {
        let extension = &leaf[extension_start + 1..];
        if (1..=5).contains(&extension.len()) && extension.iter().all(u8::is_ascii_alphanumeric) {
            leaf = &leaf[..extension_start];
        }
    }

    let has_leaf_separator = leaf.iter().any(|&byte| matches!(byte, b'-' | b'_' | b'.'));
    if !has_leaf_separator && leaf.len() >= MIN_ENTROPY_LENGTH {
        return false;
    }

    leaf.split(|&byte| matches!(byte, b'-' | b'_' | b'.'))
        .any(|part| part.len() >= 3 && part.iter().all(u8::is_ascii_alphabetic))
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
            (b"abc/DEF+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
            (b"some/dir/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
            (b"https://user:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef@host.example/path", false),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", false),
        ];

        for &(value, expected) in cases {
            assert_eq!(is_path_shaped(value), expected, "{value:?}");
        }
    }
}
