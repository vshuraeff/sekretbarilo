// password strength heuristic
// goal: block strong/complex passwords, allow simple/placeholder ones

use crate::scanner::entropy;

/// minimum score to consider a password "strong" (and thus a real secret)
const STRONG_PASSWORD_THRESHOLD: f64 = 6.0;

/// common placeholder/weak passwords that should not be flagged
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "master",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "letmein",
    "football",
    "shadow",
    "michael",
    "login",
    "admin",
    "welcome",
    "passw0rd",
    "1234567890",
    "000000",
    "access",
];

/// result of password strength analysis
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PasswordStrength {
    pub score: f64,
    pub has_uppercase: bool,
    pub has_lowercase: bool,
    pub has_digits: bool,
    pub has_special: bool,
    pub char_class_count: usize,
    pub is_dictionary_word: bool,
    pub entropy: f64,
}

/// analyze password strength to determine if it's a real secret.
/// returns true if the password appears to be a strong/real password
/// (and should be blocked), false if it's weak/placeholder (safe to allow).
pub fn is_strong_password(data: &[u8]) -> bool {
    let strength = analyze_strength(data);
    strength.score >= STRONG_PASSWORD_THRESHOLD
}

/// perform detailed password strength analysis
pub fn analyze_strength(data: &[u8]) -> PasswordStrength {
    let s = String::from_utf8_lossy(data);

    let has_uppercase = data.iter().any(|&b| b.is_ascii_uppercase());
    let has_lowercase = data.iter().any(|&b| b.is_ascii_lowercase());
    let has_digits = data.iter().any(|&b| b.is_ascii_digit());
    let has_special = data.iter().any(|&b| b.is_ascii_punctuation());

    let char_class_count = has_uppercase as usize
        + has_lowercase as usize
        + has_digits as usize
        + has_special as usize;

    let is_dictionary_word = COMMON_PASSWORDS
        .iter()
        .any(|&pw| s.eq_ignore_ascii_case(pw));

    let ent = entropy::shannon_entropy(data);

    // scoring:
    // - entropy contributes directly (typically 0-5 for passwords)
    // - character class diversity adds bonus (0-2)
    // - length bonus for longer passwords (0-2)
    // - dictionary words get a heavy penalty
    let mut score = ent;

    // character class bonus
    if char_class_count >= 3 {
        score += 1.0;
    }
    if char_class_count >= 4 {
        score += 1.0;
    }

    // length bonus
    let len = data.len();
    if len >= 12 {
        score += 0.5;
    }
    if len >= 20 {
        score += 0.5;
    }

    // dictionary penalty
    if is_dictionary_word {
        score -= 4.0;
    }

    // very short passwords are weak
    if len < 6 {
        score -= 2.0;
    }

    if score < 0.0 {
        score = 0.0;
    }

    PasswordStrength {
        score,
        has_uppercase,
        has_lowercase,
        has_digits,
        has_special,
        char_class_count,
        is_dictionary_word,
        entropy: ent,
    }
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a value is a placeholder password embedded in a URL.
///
/// `secret` and `passphrase` are deliberately not placeholders because
/// `https://user:secret@host/` is the reference fixture of the bug this repairs.
pub fn is_url_password_placeholder(value: &[u8]) -> bool {
    const PLACEHOLDERS: &[&[u8]] = &[
        b"password",
        b"pass",
        b"passwd",
        b"pwd",
        b"changeme",
        b"change_me",
        b"change-me",
        b"example",
        b"sample",
        b"placeholder",
        b"dummy",
        b"fake",
        b"mock",
        b"test",
        b"todo",
        b"lorem",
        b"replace_me",
        b"replace-me",
        b"insert_here",
        b"insert-here",
        b"redacted",
        b"hidden",
        b"none",
        b"null",
        b"empty",
    ];
    const PASSWORD_WORDS: &[&[u8]] = &[b"password", b"pass", b"passwd", b"pwd"];

    if PLACEHOLDERS
        .iter()
        .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
    {
        return true;
    }

    for prefix in [b"your".as_slice(), b"my".as_slice()] {
        if value.len() > prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix) {
            let suffix = &value[prefix.len()..];
            let suffix = suffix
                .strip_prefix(b"-")
                .or_else(|| suffix.strip_prefix(b"_"))
                .unwrap_or(suffix);

            if PASSWORD_WORDS
                .iter()
                .any(|word| suffix.eq_ignore_ascii_case(word))
            {
                return true;
            }
        }
    }

    if value.len() >= 3
        && (value.iter().all(|&byte| byte.eq_ignore_ascii_case(&b'x'))
            || value.iter().all(|&byte| byte == b'*')
            || value.iter().all(|&byte| byte == b'.'))
    {
        return true;
    }

    value.len() >= 3
        && value[0] == b'<'
        && value[value.len() - 1] == b'>'
        && value[1..value.len() - 1]
            .iter()
            .all(|byte| !byte.is_ascii_whitespace())
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a value is solely a variable or other pure reference.
///
/// `<PASSWORD>` intentionally overlaps with `is_url_password_placeholder`.
pub fn is_pure_reference(value: &[u8]) -> bool {
    let is_name = |name: &[u8]| {
        matches!(name.first(), Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_')
            && name[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.'))
    };
    let has_unquoted_template_content =
        |content: &[u8]| !content.iter().any(|byte| matches!(*byte, b'\'' | b'\"'));

    if value.len() >= 5
        && value.starts_with(b"${{")
        && value.ends_with(b"}}")
        && has_unquoted_template_content(&value[3..value.len() - 2])
    {
        return true;
    }

    if value.len() >= 4
        && value.starts_with(b"{{")
        && value.ends_with(b"}}")
        && has_unquoted_template_content(&value[2..value.len() - 2])
    {
        return true;
    }

    (value.len() > 1 && value[0] == b'$' && is_name(&value[1..]))
        || (value.len() >= 4
            && value.starts_with(b"${")
            && value.ends_with(b"}")
            && is_name(&value[2..value.len() - 1]))
        || (value.len() >= 3
            && value[0] == b'%'
            && value[value.len() - 1] == b'%'
            && is_name(&value[1..value.len() - 1]))
        || (value.len() >= 3
            && value.len() <= 30
            && value[0] == b'{'
            && value[value.len() - 1] == b'}'
            && is_name(&value[1..value.len() - 1]))
        || (value.len() >= 3
            && value[0] == b'<'
            && value[value.len() - 1] == b'>'
            && is_name(&value[1..value.len() - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct_token(len: usize) -> String {
        (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .take(len)
            .map(char::from)
            .collect()
    }

    #[test]
    fn weak_password_common_word() {
        assert!(!is_strong_password(b"password"));
        assert!(!is_strong_password(b"admin"));
        assert!(!is_strong_password(b"123456"));
    }

    #[test]
    fn weak_password_simple() {
        assert!(!is_strong_password(b"changeme"));
        assert!(!is_strong_password(b"test"));
        assert!(!is_strong_password(b"abc"));
    }

    #[test]
    fn strong_password_complex() {
        // a realistic complex password
        assert!(is_strong_password(b"Kj8#mP2!xQ9vL4nR"));
    }

    #[test]
    fn strong_password_long_mixed() {
        assert!(is_strong_password(b"aB3dEf7hIj1kLmN0pQrS"));
    }

    #[test]
    fn password_all_same_char() {
        assert!(!is_strong_password(b"aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn password_character_classes() {
        let s = analyze_strength(b"Abc123!@");
        assert!(s.has_uppercase);
        assert!(s.has_lowercase);
        assert!(s.has_digits);
        assert!(s.has_special);
        assert_eq!(s.char_class_count, 4);
    }

    #[test]
    fn dictionary_word_detected() {
        let s = analyze_strength(b"password");
        assert!(s.is_dictionary_word);
    }

    #[test]
    fn url_password_placeholders() {
        let cases: &[(&[u8], bool)] = &[
            (b"password", true),
            (b"pass", true),
            (b"passwd", true),
            (b"pwd", true),
            (b"changeme", true),
            (b"change_me", true),
            (b"change-me", true),
            (b"example", true),
            (b"sample", true),
            (b"placeholder", true),
            (b"dummy", true),
            (b"fake", true),
            (b"mock", true),
            (b"test", true),
            (b"todo", true),
            (b"lorem", true),
            (b"replace_me", true),
            (b"replace-me", true),
            (b"insert_here", true),
            (b"insert-here", true),
            (b"redacted", true),
            (b"hidden", true),
            (b"none", true),
            (b"null", true),
            (b"empty", true),
            (b"PASSWORD", true),
            (b"ChangeMe", true),
            (b"xxx", true),
            (b"xXx", true),
            (b"***", true),
            (b"...", true),
            (b"<x>", true),
            (b"<PASSWORD>", true),
            (b"secret", false),
            (b"passphrase", false),
            (b"admin", false),
            (b"1234", false),
            (b"a", false),
            (b"aaaaaaaa", false),
            (b"{anything}", false),
            (b"[anything]", false),
            (b"${X}", false),
            (b"xx", false),
            (b"**", false),
            (b"..", false),
            (b"x*X", false),
            (b"<>", false),
            (b"<a b>", false),
            (b"<\t>", false),
            (b"${NAME:-x}", false),
            (b"${NAME:=x}", false),
            (b"${NAME}suffix", false),
            (b"prefix$NAME", false),
            (b"$NAME/suffix", false),
            (b"{{ 'literal' }}", false),
            (b"", false),
        ];

        for &(value, expected) in cases {
            assert_eq!(is_url_password_placeholder(value), expected, "{value:?}");
        }

        for prefix in ["your", "my"] {
            for separator in ["", "-", "_"] {
                for word in ["password", "pass", "passwd", "pwd"] {
                    let value = format!("{prefix}{separator}{word}");
                    assert!(is_url_password_placeholder(value.as_bytes()), "{value}");
                }
            }
        }

        let password_with_digits = format!("{}{}", "password", 123);
        let changeme_with_digit = format!("{}{}", "changeme", 2);
        let hunter_with_digit = format!("{}{}", "hunter", 2);
        assert!(!is_url_password_placeholder(
            password_with_digits.as_bytes()
        ));
        assert!(!is_url_password_placeholder(changeme_with_digit.as_bytes()));
        assert!(!is_url_password_placeholder(hunter_with_digit.as_bytes()));
    }

    #[test]
    fn pure_references() {
        let cases: &[(&[u8], bool)] = &[
            (b"$NAME", true),
            (b"$my_var.2", true),
            (b"${NAME}", true),
            (b"%NAME%", true),
            (b"{{}}", true),
            (b"{{ value }}", true),
            (b"${{}}", true),
            (b"${{ value }}", true),
            (b"{NAME}", true),
            (b"<NAME>", true),
            (b"<PASSWORD>", true),
            (b"${NAME:-x}", false),
            (b"${NAME:=x}", false),
            (b"${NAME}suffix", false),
            (b"prefix$NAME", false),
            (b"$NAME/suffix", false),
            (b"{{ 'literal' }}", false),
            (b"{{ \"literal\" }}", false),
            (b"", false),
            (b"$1NAME", false),
            (b"${1NAME}", false),
            (b"%NAME-1%", false),
        ];

        for &(value, expected) in cases {
            assert_eq!(is_pure_reference(value), expected, "{value:?}");
        }

        let long_braced_name = format!("{{{}}}", distinct_token(29));
        assert!(!is_pure_reference(long_braced_name.as_bytes()));
    }

    #[test]
    fn opaque_tokens_are_not_exemptions() {
        for len in [8, 16, 32] {
            let token = distinct_token(len);
            assert!(!is_url_password_placeholder(token.as_bytes()));
            assert!(!is_pure_reference(token.as_bytes()));
        }

        let url_password_shaped = format!("user:{}@host", distinct_token(16));
        assert!(!is_url_password_placeholder(url_password_shaped.as_bytes()));
        assert!(!is_pure_reference(url_password_shaped.as_bytes()));
    }

    #[test]
    fn non_dictionary_word() {
        let s = analyze_strength(b"xK9mP2qR");
        assert!(!s.is_dictionary_word);
    }
}
