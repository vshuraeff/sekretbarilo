// hash detection (false positive avoidance)
// SHA-1, SHA-256, MD5, and git commit hashes must NOT be treated as secrets

/// check if a byte slice looks like a known hash format.
/// returns true if the value appears to be a hash (and should be skipped).
pub fn is_hash(data: &[u8]) -> bool {
    is_md5(data) || is_sha1(data) || is_sha256(data)
}

/// check if a value looks like a hash, considering the surrounding line context.
/// git commit hashes may appear with context keywords.
pub fn is_hash_in_context(data: &[u8], line: &[u8]) -> bool {
    if is_hash(data) {
        return true;
    }
    // check for git commit hash patterns (40 hex chars or abbreviated 7-12 hex)
    if is_hex_string(data) && is_git_context(line) {
        let len = data.len();
        // full sha1 (40), abbreviated (7-12), or sha256 (64)
        if len == 40 || (7..=12).contains(&len) || len == 64 {
            return true;
        }
    }
    false
}

/// detect MD5 hashes (exactly 32 hex chars)
fn is_md5(data: &[u8]) -> bool {
    data.len() == 32 && is_hex_string(data)
}

/// detect SHA-1 hashes (exactly 40 hex chars)
fn is_sha1(data: &[u8]) -> bool {
    data.len() == 40 && is_hex_string(data)
}

/// detect SHA-256 hashes (exactly 64 hex chars)
fn is_sha256(data: &[u8]) -> bool {
    data.len() == 64 && is_hex_string(data)
}

/// check if all bytes are hex digits [0-9a-fA-F]
fn is_hex_string(data: &[u8]) -> bool {
    !data.is_empty() && data.iter().all(|&b| b.is_ascii_hexdigit())
}

/// check if the line contains git-related context keywords
fn is_git_context(line: &[u8]) -> bool {
    let lower: Vec<u8> = line.iter().map(|&b| b.to_ascii_lowercase()).collect();
    let keywords = [
        &b"commit"[..],
        b"merge",
        b"cherry-pick",
        b"revert",
        b"hash",
        b"sha",
        b"sha1",
        b"sha256",
        b"md5",
        b"digest",
        b"checksum",
    ];
    keywords
        .iter()
        .any(|kw| lower.windows(kw.len()).any(|w| w == *kw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_md5() {
        assert!(is_hash(b"d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn detect_sha1() {
        assert!(is_hash(b"da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    #[test]
    fn detect_sha256() {
        assert!(is_hash(
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn not_a_hash_wrong_length() {
        // 20 hex chars - not a standard hash length
        assert!(!is_hash(b"abcdef1234567890abcd"));
    }

    #[test]
    fn not_a_hash_non_hex() {
        assert!(!is_hash(b"this-is-not-a-hash-at-all-really"));
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
