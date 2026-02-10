// password strength heuristic
// goal: block strong/complex passwords, allow simple/placeholder ones

use crate::scanner::entropy;

/// minimum score to consider a password "strong" (and thus a real secret)
const STRONG_PASSWORD_THRESHOLD: f64 = 6.0;

/// common placeholder/weak passwords that should not be flagged
const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "football", "shadow", "michael", "login", "admin",
    "welcome", "passw0rd", "1234567890", "000000", "access",
];

/// result of password strength analysis
#[derive(Debug, Clone)]
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
    let has_special = data.iter().any(|&b| {
        b.is_ascii_punctuation() || (b.is_ascii_graphic() && !b.is_ascii_alphanumeric())
    });

    let char_class_count =
        has_uppercase as usize + has_lowercase as usize + has_digits as usize + has_special as usize;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn non_dictionary_word() {
        let s = analyze_strength(b"xK9mP2qR");
        assert!(!s.is_dictionary_word);
    }
}
