// secret value masking

/// mask a secret value for display
/// shows first 2 and last 2 chars: "sk****rd"
/// for short secrets (< 6 chars): replaces all with "x"
pub fn mask_secret(secret: &[u8]) -> String {
    if secret.is_empty() {
        return String::new();
    }
    let s = String::from_utf8_lossy(secret);
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 6 {
        "x".repeat(chars.len())
    } else {
        let first: String = chars[..2].iter().collect();
        let last: String = chars[chars.len() - 2..].iter().collect();
        let middle = "*".repeat(chars.len() - 4);
        format!("{first}{middle}{last}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_empty_secret() {
        assert_eq!(mask_secret(b""), "");
    }

    #[test]
    fn mask_short_secret_1_char() {
        assert_eq!(mask_secret(b"a"), "x");
    }

    #[test]
    fn mask_short_secret_3_chars() {
        assert_eq!(mask_secret(b"abc"), "xxx");
    }

    #[test]
    fn mask_short_secret_5_chars() {
        assert_eq!(mask_secret(b"abcde"), "xxxxx");
    }

    #[test]
    fn mask_exact_threshold_6_chars() {
        // 6 chars: show first 2 and last 2, 2 stars in middle
        assert_eq!(mask_secret(b"abcdef"), "ab**ef");
    }

    #[test]
    fn mask_long_secret() {
        // "sk_live_abc123" -> "sk**********23"
        assert_eq!(mask_secret(b"sk_live_abc123"), "sk**********23");
    }

    #[test]
    fn mask_aws_key() {
        let key = b"AKIAIOSFODNN7ABCDEFG";
        let masked = mask_secret(key);
        assert!(masked.starts_with("AK"));
        assert!(masked.ends_with("FG"));
        assert!(masked.contains("*"));
        // never exposes raw value
        assert_ne!(masked, "AKIAIOSFODNN7ABCDEFG");
    }

    #[test]
    fn mask_never_exposes_full_secret() {
        let secrets: &[&[u8]] = &[
            b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            b"sk-ant-api03-something-very-long",
            b"xoxb-token-value",
            b"password123",
        ];
        for secret in secrets {
            let masked = mask_secret(secret);
            let original = String::from_utf8_lossy(secret);
            assert_ne!(masked, original.as_ref());
        }
    }
}
