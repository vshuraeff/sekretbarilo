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
            let before_ok = pos == 0 || !line[pos - 1].is_ascii_alphanumeric();
            let after_pos = pos + kw.len();
            let after_ok = after_pos >= line.len() || !line[after_pos].is_ascii_alphanumeric();
            before_ok && after_ok
        })
    })
}

#[allow(dead_code)]
/// determines whether an assignment value is eligible for the deterministic exact-length hex policy.
/// unprefixed and `0x`/`0X`-prefixed values admit exactly 32, 40, or 64 hex digits.
/// this is a deterministic exact-length policy, not a secret classifier.
/// key-token exclusions are name-based recall limits: a hex credential stored under a `*_id`,
/// `*_hash`, or `address`-shaped key is not caught by this path.
/// a value matching this predicate is emitted by the engine under the
/// `generic-high-entropy-value` rule; this function only decides candidacy and does not emit
/// findings itself.
pub fn is_hex_policy_candidate(key: Option<&[u8]>, value: &[u8]) -> bool {
    let Some(key) = key else {
        return false;
    };

    let value = if value.starts_with(b"0x") || value.starts_with(b"0X") {
        let remainder = &value[2..];
        if !matches!(remainder.len(), 32 | 40 | 64) || !is_hex_string(remainder) {
            return false;
        }
        remainder
    } else {
        if !matches!(value.len(), 32 | 40 | 64) || !is_hex_string(value) {
            return false;
        }
        value
    };

    debug_assert!(is_hex_string(value));

    let key = strip_matching_key_quotes(key);
    !has_hex_policy_exclusion(key)
}

fn strip_matching_key_quotes(key: &[u8]) -> &[u8] {
    if key.len() >= 2 && matches!(key[0], b'\'' | b'\"' | b'`') && key[0] == key[key.len() - 1] {
        &key[1..key.len() - 1]
    } else {
        key
    }
}

fn has_hex_policy_exclusion(key: &[u8]) -> bool {
    if is_hex_policy_exclusion_token(key) {
        return true;
    }

    let mut token_start = 0;
    for index in 0..key.len() {
        if is_key_token_separator(key[index]) {
            if is_hex_policy_exclusion_token(&key[token_start..index]) {
                return true;
            }
            token_start = index + 1;
            continue;
        }

        let camel_case_split = index > token_start
            && ((key[index - 1].is_ascii_lowercase() && key[index].is_ascii_uppercase())
                || (index >= token_start + 2
                    && key[index - 2].is_ascii_uppercase()
                    && key[index - 1].is_ascii_uppercase()
                    && key[index].is_ascii_lowercase()));
        if camel_case_split {
            let split_at = if key[index - 1].is_ascii_uppercase() && key[index].is_ascii_lowercase()
            {
                index - 1
            } else {
                index
            };
            if is_hex_policy_exclusion_token(&key[token_start..split_at]) {
                return true;
            }
            token_start = split_at;
        }
    }

    is_hex_policy_exclusion_token(&key[token_start..])
}

fn is_key_token_separator(byte: u8) -> bool {
    matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
}

fn is_hex_policy_exclusion_token(token: &[u8]) -> bool {
    const EXCLUSIONS: &[&[u8]] = &[
        b"md5",
        b"sha",
        b"sha1",
        b"sha224",
        b"sha256",
        b"sha384",
        b"sha512",
        b"digest",
        b"checksum",
        b"hash",
        b"hashes",
        b"integrity",
        b"etag",
        b"commit",
        b"commits",
        b"rev",
        b"revision",
        b"ref",
        b"refs",
        b"id",
        b"ids",
        b"uuid",
        b"guid",
        b"oid",
        b"blob",
        b"tree",
        b"cksum",
        b"crc",
        b"address",
        b"addr",
        b"wallet",
        b"contract",
        b"txid",
        b"txhash",
    ];

    EXCLUSIONS
        .iter()
        .any(|&exclusion| token.eq_ignore_ascii_case(exclusion))
        || is_numbered_hash_token(token)
}

fn is_numbered_hash_token(token: &[u8]) -> bool {
    let suffix = if token.len() >= 3 && token[..3].eq_ignore_ascii_case(b"sha") {
        &token[3..]
    } else if token.len() >= 2 && token[..2].eq_ignore_ascii_case(b"md") {
        &token[2..]
    } else {
        return false;
    };

    let digits = if suffix.len() >= 3 && suffix[suffix.len() - 3..].eq_ignore_ascii_case(b"sum") {
        &suffix[..suffix.len() - 3]
    } else {
        suffix
    };

    !digits.is_empty() && digits.iter().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_hex(seed: u64, length: usize) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                HEX[(state >> 60) as usize]
            })
            .collect()
    }

    fn prefixed_generated_hex(seed: u64, length: usize) -> Vec<u8> {
        let mut value = b"0x".to_vec();
        value.extend(generated_hex(seed, length));
        value
    }

    #[test]
    fn hex_policy_accepts_allowed_assignment_values() {
        assert!(is_hex_policy_candidate(
            Some(b"API_KEY"),
            &generated_hex(1, 32)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"api-key"),
            &generated_hex(2, 40)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"token"),
            &generated_hex(3, 64)
        ));
        assert!(is_hex_policy_candidate(Some(b"x"), &generated_hex(4, 32)));
        assert!(is_hex_policy_candidate(
            Some(b"TxnSignature"),
            &generated_hex(5, 40)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"\"quoted_key\""),
            &generated_hex(6, 32)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"PRIVATE_KEY"),
            &prefixed_generated_hex(7, 32)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"PRIVATE_KEY"),
            &prefixed_generated_hex(8, 40)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"PRIVATE_KEY"),
            &prefixed_generated_hex(9, 64)
        ));

        let mut uppercase_prefix_32 = prefixed_generated_hex(10, 32);
        uppercase_prefix_32[..2].make_ascii_uppercase();
        assert!(is_hex_policy_candidate(
            Some(b"PRIVATE_KEY"),
            &uppercase_prefix_32
        ));

        let mut uppercase_prefix_40 = prefixed_generated_hex(11, 40);
        uppercase_prefix_40[..2].make_ascii_uppercase();
        assert!(is_hex_policy_candidate(
            Some(b"PRIVATE_KEY"),
            &uppercase_prefix_40
        ));

        assert!(is_hex_policy_candidate(
            Some(b"session"),
            &generated_hex(8, 32)
        ));
        assert!(is_hex_policy_candidate(
            Some(b"salt"),
            &generated_hex(9, 40)
        ));
        assert!(is_hex_policy_candidate(Some(b"iv"), &generated_hex(10, 32)));

        let mut uppercase = generated_hex(11, 40);
        uppercase.make_ascii_uppercase();
        assert!(is_hex_policy_candidate(Some(b"token"), &uppercase));

        let mut mixed_case = generated_hex(12, 64);
        for (index, byte) in mixed_case.iter_mut().enumerate() {
            if index % 2 == 0 {
                *byte = byte.to_ascii_uppercase();
            }
        }
        assert!(is_hex_policy_candidate(Some(b"token"), &mixed_case));
    }

    #[test]
    fn hex_policy_rejects_excluded_key_tokens() {
        let cases: &[(&[u8], usize, u64)] = &[
            (b"secret_id", 32, 21),
            (b"commit", 40, 22),
            (b"sha256", 64, 23),
            (b"md5sum", 32, 24),
            (b"sha256sum", 64, 25),
            (b"image_digest", 32, 26),
            (b"git_rev", 40, 27),
            (b"uuid", 32, 28),
            (b"trace_id", 32, 29),
            (b"ETag", 40, 30),
            (b"content-hash", 64, 31),
            (b"blobId", 40, 32),
            (b"address", 40, 33),
            (b"wallet_addr", 32, 34),
            (b"contract", 40, 35),
        ];

        for &(key, length, seed) in cases {
            assert!(!is_hex_policy_candidate(
                Some(key),
                &generated_hex(seed, length)
            ));
        }

        for (key, seed) in [(b"commit" as &[u8], 35), (b"sha256", 36)] {
            assert!(!is_hex_policy_candidate(
                Some(key),
                &prefixed_generated_hex(seed, 32)
            ));
        }
    }

    #[test]
    fn hex_policy_rejects_invalid_values_and_missing_keys() {
        for (length, seed) in [(31, 43), (33, 44), (39, 45), (41, 46), (63, 47), (65, 48)] {
            assert!(!is_hex_policy_candidate(
                Some(b"API_KEY"),
                &generated_hex(seed, length)
            ));
        }

        for (length, seed) in [(31, 51), (33, 52), (39, 53), (41, 54), (63, 55)] {
            assert!(!is_hex_policy_candidate(
                Some(b"API_KEY"),
                &prefixed_generated_hex(seed, length)
            ));
        }

        let mut non_hex = generated_hex(49, 32);
        non_hex[16] = b'g';
        assert!(!is_hex_policy_candidate(Some(b"API_KEY"), &non_hex));
        assert!(!is_hex_policy_candidate(None, &generated_hex(50, 32)));
    }

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
        let hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let line = b"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
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
        let hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let line = b"checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(is_hash_in_context(hash, line));
    }
}
