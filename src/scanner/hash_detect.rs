// hash detection (false positive avoidance)
// SHA-1, SHA-256, MD5, and git commit hashes must NOT be treated as secrets

/// check if a value looks like a hash, considering the surrounding line context.
/// full-length hashes (32/40/64 hex chars) and abbreviated git hashes (7-12 hex)
/// require hash/git context keywords on the line to avoid false negatives on
/// hex-based API keys that happen to match hash lengths.
pub fn is_hash_in_context(data: &[u8], line: &[u8]) -> bool {
    if !is_hex_string(data) {
        return false;
    }
    let len = data.len();
    let has_context = is_git_context(line);
    // full-length hashes: MD5 (32), SHA-1 (40), SHA-256 (64)
    if (len == 32 || len == 40 || len == 64) && has_context {
        return true;
    }
    // abbreviated git hashes (7-12 hex chars) with context
    if (7..=12).contains(&len) && has_context {
        return true;
    }
    false
}

/// check if all bytes are hex digits [0-9a-fA-F]
fn is_hex_string(data: &[u8]) -> bool {
    !data.is_empty() && data.iter().all(|&b| b.is_ascii_hexdigit())
}

/// check if the line contains git-related context keywords at word boundaries.
/// word boundary = the byte before/after the keyword is not alphanumeric.
/// this prevents "sha" from matching inside "shadow" or "hash" inside "HashMap".
/// uses case-insensitive comparison without allocating a lowered copy.
fn is_git_context(line: &[u8]) -> bool {
    let keywords = [
        &b"commit"[..],
        b"merge",
        b"cherry-pick",
        b"revert",
        b"sha",
        b"sha1",
        b"sha256",
        b"md5",
        b"digest",
        b"checksum",
        b"hash",
        b"integrity",
    ];
    keywords.iter().any(|kw| {
        line.windows(kw.len()).enumerate().any(|(pos, w)| {
            if !w.eq_ignore_ascii_case(kw) {
                return false;
            }
            let before_ok =
                pos == 0 || !line[pos - 1].is_ascii_alphanumeric();
            let after_pos = pos + kw.len();
            let after_ok =
                after_pos >= line.len() || !line[after_pos].is_ascii_alphanumeric();
            before_ok && after_ok
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_md5_with_context() {
        let hash = b"d41d8cd98f00b204e9800998ecf8427e";
        let line = b"md5: d41d8cd98f00b204e9800998ecf8427e";
        assert!(is_hash_in_context(hash, line));
    }

    #[test]
    fn md5_length_hex_without_context_not_hash() {
        // 32 hex chars but no hash context - could be an API key
        let hash = b"d41d8cd98f00b204e9800998ecf8427e";
        let line = b"api_key = d41d8cd98f00b204e9800998ecf8427e";
        assert!(!is_hash_in_context(hash, line));
    }

    #[test]
    fn detect_sha1_with_context() {
        let hash = b"da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let line = b"commit da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(is_hash_in_context(hash, line));
    }

    #[test]
    fn sha1_length_hex_without_context_not_hash() {
        let hash = b"da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let line = b"token = da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(!is_hash_in_context(hash, line));
    }

    #[test]
    fn detect_sha256_with_context() {
        let hash =
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let line =
            b"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(is_hash_in_context(hash, line));
    }

    #[test]
    fn not_a_hash_wrong_length() {
        // 20 hex chars - not a standard hash length
        let hash = b"abcdef1234567890abcd";
        let line = b"checksum: abcdef1234567890abcd";
        assert!(!is_hash_in_context(hash, line));
    }

    #[test]
    fn not_a_hash_non_hex() {
        let data = b"this-is-not-a-hash-at-all-really";
        let line = b"commit this-is-not-a-hash-at-all-really";
        assert!(!is_hash_in_context(data, line));
    }

    #[test]
    fn git_commit_hash_in_context() {
        let hash = b"da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let line = b"# commit da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(is_hash_in_context(hash, line));
    }

    #[test]
    fn abbreviated_git_hash_in_context() {
        let hash = b"da39a3e";
        let line = b"merge commit da39a3e into main";
        assert!(is_hash_in_context(hash, line));
    }

    #[test]
    fn hex_string_without_context_not_hash() {
        // 10 hex chars but no git context - not detected as hash
        let hash = b"abcdef1234";
        let line = b"api_key = abcdef1234";
        assert!(!is_hash_in_context(hash, line));
    }

    #[test]
    fn sha256_in_checksum_context() {
        let hash =
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let line =
            b"checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(is_hash_in_context(hash, line));
    }
}
