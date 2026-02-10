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

/// calculate entropy only over hex charset [0-9a-fA-F]
/// returns None if the string contains non-hex characters
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
fn charset_entropy(data: &[u8], _charset_size: usize) -> f64 {
    // use standard shannon entropy - the charset_size parameter is kept
    // for potential future normalization but standard entropy is what
    // tools like gitleaks and trufflehog use
    shannon_entropy(data)
}

/// check if a byte slice passes the entropy threshold for scanning.
/// returns true if the data has sufficient entropy (is suspicious).
/// returns false (not suspicious) if data is too short or below threshold.
pub fn passes_entropy_check(data: &[u8], threshold: f64) -> bool {
    if data.len() < MIN_ENTROPY_LENGTH {
        return false;
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
    fn passes_entropy_check_too_short() {
        assert!(!passes_entropy_check(b"short", 3.0));
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
}
