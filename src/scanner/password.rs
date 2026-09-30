// password strength heuristic
// goal: block strong/complex passwords, allow simple/placeholder ones

use crate::scanner::{entropy, wordshape};

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

/// placeholder words the scanner already treats as non-secrets (the default stopwords and the url
/// placeholders). a digit or `!` suffix defeats the stopword word boundary, so the assignment gate
/// compares stems against these as well.
const PLACEHOLDER_STEMS: &[&str] = &[
    "changeme",
    "example",
    "sample",
    "placeholder",
    "dummy",
    "fake",
    "mock",
    "test",
    "todo",
    "fixme",
    "lorem",
    "default",
    "redacted",
    "hidden",
    "none",
    "null",
    "empty",
];

/// the key's credential words. `pass` covers password and passwd, so the two cover every key the
/// generic-password-assignment rule accepts.
const CREDENTIAL_WORDS: &[&[u8]] = &[b"pass", b"pwd"];

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

/// folds common leet substitutions onto one letter each, so `P@ssw0rd` and `password` compare
/// equal. `1`, `!` and `l` share the class of `i` because `1` stands for either letter.
fn leet_fold(byte: u8) -> u8 {
    match byte.to_ascii_lowercase() {
        b'0' => b'o',
        b'1' | b'!' | b'l' => b'i',
        b'3' => b'e',
        b'4' | b'@' => b'a',
        b'5' | b'$' => b's',
        b'7' => b't',
        other => other,
    }
}

fn leet_eq(value: &[u8], word: &[u8]) -> bool {
    value.len() == word.len()
        && value
            .iter()
            .zip(word)
            .all(|(&left, &right)| leet_fold(left) == leet_fold(right))
}

/// whether the value is a dictionary or placeholder word followed only by digits and `!?.*#`,
/// compared after leet folding on both sides. every split point inside that trailing run is
/// tried, so a word that itself ends in a digit (`trustno1`) still matches with more digits
/// appended, and a whole-value match needs no separate check.
fn is_dictionary_stem(data: &[u8]) -> bool {
    let mut stem_end = data.len();
    while stem_end > 0
        && matches!(
            data[stem_end - 1],
            b'0'..=b'9' | b'!' | b'?' | b'.' | b'*' | b'#'
        )
    {
        stem_end -= 1;
    }
    (stem_end.max(1)..=data.len()).any(|end| {
        COMMON_PASSWORDS
            .iter()
            .chain(PLACEHOLDER_STEMS)
            .any(|word| leet_eq(&data[..end], word.as_bytes()))
    })
}

/// a value naming the key's own credential word (`passwordFieldLabel1`, `MyPass123`, `p@ss_hint`)
/// is a label or placeholder, not the credential.
fn contains_credential_word(data: &[u8]) -> bool {
    CREDENTIAL_WORDS
        .iter()
        .any(|word| data.windows(word.len()).any(|window| leet_eq(window, word)))
}

/// a value made only of identifier words (camel, snake, dotted, short digit runs), two or more of
/// them meaningful, is a field label such as `DatabaseHostName3`. a meaningful word is a wordlike
/// run of four or more letters; a common short word may sit between them. an all-caps run counts
/// only in a separated constant (`SERVICE_HOST_NAME`): inside a camel value it is an acronym or,
/// far more often, a random stretch of capitals. any other chunk keeps the value opaque, so a
/// generated value is not rejected merely for having an uppercase boundary: its single letters and
/// consonant clusters break the word structure.
fn is_identifier_label(data: &[u8]) -> bool {
    let Some(words) = wordshape::identifier_words(data) else {
        return false;
    };
    let separated = data
        .iter()
        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b',' | b';'));
    let mut meaningful = 0;
    for word in words {
        if word[0].is_ascii_digit() {
            if word.len() > 4 {
                return false;
            }
        } else if word.len() >= 4 && wordshape::has_wordlike_vowels(word) {
            if separated || !word.iter().all(u8::is_ascii_uppercase) {
                meaningful += 1;
            }
        } else if !wordshape::is_short_word(word) {
            return false;
        }
    }
    meaningful >= 2
}

/// whitespace-separated natural-language words (a sentence quoted after a `password:` label) are
/// prose, not a credential. a passphrase of ordinary words is therefore missed as well, the blind
/// spot the word-structure exemption already documents.
fn is_prose(data: &[u8]) -> bool {
    if !data.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    let mut tokens = 0;
    let mut words = 0;
    for token in data
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
    {
        tokens += 1;
        let start = token
            .iter()
            .position(|byte| !byte.is_ascii_punctuation())
            .unwrap_or(token.len());
        let end = token
            .iter()
            .rposition(|byte| !byte.is_ascii_punctuation())
            .map_or(start, |index| index + 1);
        let core = &token[start..end];
        let case_consistent = core.iter().all(u8::is_ascii_lowercase)
            || core.iter().all(u8::is_ascii_uppercase)
            || core.split_first().is_some_and(|(first, rest)| {
                first.is_ascii_uppercase() && rest.iter().all(u8::is_ascii_lowercase)
            });
        if !core.is_empty()
            && case_consistent
            && (core.len() <= 3 || wordshape::has_wordlike_vowels(core))
        {
            words += 1;
        }
    }
    words >= 3 && words * 4 >= tokens * 3
}

/// minimum number of distinct bytes the interleaved lowercase+digit branch requires, so a
/// short-period alternation of a handful of symbols does not qualify as a generated password.
const MIN_INTERLEAVED_DISTINCT_BYTES: usize = 6;

/// the longest repeating period treated as "short": a value that is its own first `k` bytes
/// repeated (and truncated) for some `k` up to this bound reads as a pattern, not a generated
/// secret.
const MAX_SHORT_PERIOD: usize = 4;

/// whether `data`'s shortest repeating period is at most `max_period` bytes: `data` equals its
/// first `k` bytes repeated (and truncated to length) for some `k` in `1..=max_period`.
fn has_short_period(data: &[u8], max_period: usize) -> bool {
    (1..=max_period.min(data.len())).any(|period| {
        data.iter()
            .enumerate()
            .all(|(index, &byte)| byte == data[index % period])
    })
}

/// count of distinct bytes appearing anywhere in `data`.
fn distinct_byte_count(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    data.iter()
        .filter(|&&byte| {
            let is_new = !seen[byte as usize];
            seen[byte as usize] = true;
            is_new
        })
        .count()
}

/// 12+ bytes of only lowercase letters and digits, with at least two runs of each, where no run of
/// four or more letters is wordlike, at least `MIN_INTERLEAVED_DISTINCT_BYTES` distinct bytes
/// appear, and the value is not a short-period repetition (period at most `MAX_SHORT_PERIOD`
/// bytes): the shape of a generated lowercase alphanumeric password rather than an alternation.
fn is_interleaved_lowercase_digits(data: &[u8]) -> bool {
    if data.len() < 12
        || !data
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return false;
    }
    let mut letter_runs = 0;
    let mut digit_runs = 0;
    for run in data.chunk_by(|left, right| left.is_ascii_digit() == right.is_ascii_digit()) {
        if run[0].is_ascii_digit() {
            digit_runs += 1;
        } else {
            letter_runs += 1;
            if run.len() >= 4 && wordshape::has_wordlike_vowels(run) {
                return false;
            }
        }
    }
    letter_runs >= 2
        && digit_runs >= 2
        && distinct_byte_count(data) >= MIN_INTERLEAVED_DISTINCT_BYTES
        && !has_short_period(data, MAX_SHORT_PERIOD)
}

/// acceptance check for password-assignment values (used only at the generic-password-assignment
/// gate). `concrete_literal` says the right-hand side is written as a literal: a quoted value, a
/// shell assignment word, or a plain value in a yaml, ini-style, toml or dotenv file, never an
/// unquoted source identifier or expression.
///
/// posture:
/// - prose (three or more whitespace-separated words) is never a password.
/// - a value scoring at least STRONG_PASSWORD_THRESHOLD is reported.
/// - below that threshold, labels and placeholders are dropped first: a dictionary or placeholder
///   stem followed only by digits and `!?.*#` (leet-folded), a value containing the key's
///   credential word, or an identifier made of two or more meaningful words.
/// - what remains is reported when it is 12+ bytes mixing lowercase, uppercase and digits (any
///   right-hand side), or, for a concrete literal without whitespace only, when it is 8-11 bytes
///   with four character classes or three including a special byte and no repeating period of
///   four bytes or fewer, or 12+ bytes of interleaved lowercase letters and digits whose
///   4+-letter runs are not wordlike, with at least six distinct bytes and no repeating period of
///   four bytes or fewer.
///
/// gaps by design: word-based lowercase passwords (`hunter2hunter2`), word-built identifiers and
/// passphrases, one- or two-class values under the threshold, 12+-byte values without uppercase
/// that mix in punctuation, and any low-strength value written as an unquoted source expression.
pub fn is_strong_assignment_password(data: &[u8], concrete_literal: bool) -> bool {
    if is_prose(data) {
        return false;
    }
    if is_strong_password(data) {
        return true;
    }
    if is_dictionary_stem(data) || contains_credential_word(data) || is_identifier_label(data) {
        return false;
    }
    let strength = analyze_strength(data);
    if data.len() >= 12 && strength.has_lowercase && strength.has_uppercase && strength.has_digits {
        return true;
    }
    if !concrete_literal || data.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    let classes = strength.char_class_count;
    ((8..=11).contains(&data.len())
        && (classes == 4 || (classes == 3 && strength.has_special))
        && !has_short_period(data, MAX_SHORT_PERIOD))
        || is_interleaved_lowercase_digits(data)
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
/// a url whose password is `secret` is the reference fixture of the bug this repairs.
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
    fn strong_assignment_password_accepts_long_mixed_alphanumeric_values() {
        let value = [
            'q', '2', 'r', 'Q', 't', '2', 'w', 'r', 'R', 'q', 'y', '2', 't', 'u', 'q', '5', 'i',
            'r', 'o', 'q', 'p', 'q',
        ]
        .into_iter()
        .collect::<String>()
        .into_bytes();

        assert!(!is_strong_password(&value));
        for literal in [true, false] {
            assert!(is_strong_assignment_password(&value, literal));
        }
    }

    #[test]
    fn strong_assignment_password_rejects_dictionary_word_with_trailing_digits() {
        let dictionary_word = COMMON_PASSWORDS
            .iter()
            .copied()
            .find(|word| *word == "password")
            .unwrap();
        let mut chars = dictionary_word.chars();
        let capitalized = chars
            .next()
            .unwrap()
            .to_uppercase()
            .chain(chars)
            .collect::<String>();
        let suffix: String = (0..4).map(|index| char::from(b'1' + index as u8)).collect();
        let value = format!("{capitalized}{suffix}");

        for literal in [true, false] {
            assert!(!is_strong_assignment_password(value.as_bytes(), literal));
        }

        let incident_shape = [
            'q', '2', 'r', 'Q', 't', '2', 'w', 'r', 'R', 'q', 'y', '2', 't', 'u', 'q', '5', 'i',
            'r', 'o', 'q', 'p', 'q',
        ]
        .into_iter()
        .collect::<String>();
        for literal in [true, false] {
            assert!(is_strong_assignment_password(
                incident_shape.as_bytes(),
                literal
            ));
        }
    }

    #[test]
    fn strong_assignment_password_keeps_length_and_class_requirements() {
        let short: Vec<u8> = (0..11)
            .map(|index| match index % 3 {
                0 => b'q',
                1 => b'2',
                _ => b'R',
            })
            .collect();
        let missing_digit: Vec<u8> = (0..20)
            .map(|index| if index % 2 == 0 { b'q' } else { b'R' })
            .collect();

        for literal in [true, false] {
            assert!(!is_strong_assignment_password(&short, literal));
            assert!(!is_strong_assignment_password(&missing_digit, literal));
        }
    }

    fn capitalized(word: &str) -> String {
        let mut chars = word.chars();
        chars
            .next()
            .map(|first| first.to_uppercase().chain(chars).collect())
            .unwrap_or_default()
    }

    #[test]
    fn dictionary_stem_tries_every_split_point_of_the_trailing_run() {
        let ends_in_digit = COMMON_PASSWORDS
            .iter()
            .copied()
            .find(|word| {
                word.bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_digit())
                    && word.bytes().any(|byte| byte.is_ascii_alphabetic())
            })
            .unwrap();
        for suffix in ["", "2345", "0", "99!", "7#?", "!*."] {
            let value = format!("{}{suffix}", capitalized(ends_in_digit));
            assert!(is_dictionary_stem(value.as_bytes()), "{value}");
        }
        // leet folding on both sides: `1` stands for `i` or `l`, `@` for `a`, `0` for `o`
        let folded = |word: &str| -> String {
            word.chars()
                .map(|character| match character {
                    'a' => '@',
                    'o' => '0',
                    'i' | 'l' => '1',
                    'e' => '3',
                    's' => '5',
                    't' => '7',
                    other => other,
                })
                .collect()
        };
        for word in COMMON_PASSWORDS.iter().chain(PLACEHOLDER_STEMS) {
            for suffix in ["", "1", "2024!", "#"] {
                let value = format!("{}{suffix}", capitalized(&folded(word)));
                assert!(is_dictionary_stem(value.as_bytes()), "{value}");
            }
        }
        // a stem needs the whole word: a longer or interrupted stem is not a dictionary word
        for value in ["admins1", "adm_in1", "xadmin1", "admin1x"] {
            assert!(!is_dictionary_stem(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_words_and_identifier_labels_are_recognized() {
        for value in [
            ["password", "Field", "Label", "1"].concat(),
            ["confirm", "_", "pwd"].concat(),
            ["P@", "55", "hint"].concat(),
        ] {
            assert!(contains_credential_word(value.as_bytes()), "{value}");
        }
        for value in [
            ["Database", "Host", "Name", "3"].concat(),
            ["db", ".", "connection", ".", "timeout"].concat(),
            ["SERVICE", "_", "HOST", "_", "URL", "_", "2"].concat(),
            ["Secure", "Router", "123"].concat(),
        ] {
            assert!(is_identifier_label(value.as_bytes()), "{value}");
        }
        for value in [
            // one meaningful word, an all-caps run inside a camel value, a single-letter chunk, a
            // consonant cluster, a long digit run, or a byte outside identifiers keeps a value
            // opaque
            ["Router", "123"].concat(),
            ["Web", "Router", "123"].concat(),
            ["ROUTE", "Name", "1"].concat(),
            ["q2r", "Q", "t2wr"].concat(),
            ["Xkcd", "Mnbv", "7"].concat(),
            ["Secure", "Router", "12345"].concat(),
            ["Secure", "!", "Router"].concat(),
        ] {
            assert!(!is_identifier_label(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn prose_and_interleaving_shapes() {
        assert!(is_prose(
            b"Keyring: stores the value in the OS keychain; never written to disk."
        ));
        assert!(!is_prose(b"two words"));
        assert!(!is_prose(["aB9!", "wX2#", "rT7pL4"].join(" ").as_bytes()));
        assert!(!is_prose(b"NoSpacesAtAll"));

        // generated: consonant, digit, consonant, digit, ...
        let consonants = b"bcdfghjkmnpqrstvwxz";
        let interleaved = |length: usize| -> Vec<u8> {
            (0..length)
                .map(|index| {
                    if index % 2 == 0 {
                        consonants[(index * 7) % consonants.len()]
                    } else {
                        b'0' + (index * 3 % 10) as u8
                    }
                })
                .collect()
        };
        assert!(is_interleaved_lowercase_digits(&interleaved(12)));
        // a run of four consonants has no vowel, so it is not wordlike
        let consonant_run = [&consonants[..4], &interleaved(9)[1..]].concat();
        assert_eq!(consonant_run.len(), 12);
        assert!(is_interleaved_lowercase_digits(&consonant_run));
        // a wordlike run of four or more letters, a single digit run, another class, or length
        assert!(!is_interleaved_lowercase_digits(
            ["hunter", "2", "hunter", "2"].concat().as_bytes()
        ));
        assert!(!is_interleaved_lowercase_digits(
            &[&consonants[..10], b"42".as_slice()].concat()
        ));
        assert!(!is_interleaved_lowercase_digits(
            &[interleaved(11).as_slice(), b"A".as_slice()].concat()
        ));
        assert!(!is_interleaved_lowercase_digits(&interleaved(11)));
    }

    /// xorshift64*
    fn next(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    #[test]
    fn random_values_are_never_placeholders_and_rarely_labels() {
        const SAMPLES: usize = 5_000;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut credential_words = 0;
        for length in 8..=22 {
            let mut labels = 0;
            let mut stems = 0;
            for _ in 0..SAMPLES {
                let value: Vec<u8> = (0..length)
                    .map(|_| alphabet[(next(&mut state) >> 33) as usize % alphabet.len()])
                    .collect();
                labels += usize::from(is_identifier_label(&value));
                stems += usize::from(is_dictionary_stem(&value));
                credential_words += usize::from(contains_credential_word(&value));
            }
            eprintln!("base62 length {length}: labels {labels}/{SAMPLES}, stems {stems}");
            assert_eq!(stems, 0, "length {length}");
            // two random runs of four letters with a vowel can read as two camel words: a
            // documented residual of at most 2 in 1000, none from 20 bytes up
            assert!(labels * 500 <= SAMPLES, "length {length}: {labels}");
            if length >= 20 {
                assert_eq!(labels, 0, "length {length}");
            }
        }
        // a random value spells pass or pwd less than once per 1000 samples
        eprintln!("credential words in random base62: {credential_words}");
        assert!(credential_words * 1000 < SAMPLES * 15, "{credential_words}");

        // an 8-11 byte candidate reaches the veto with a special byte only when that byte is a
        // separator, so this is the population whose recall the veto can cost
        let separated = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
        for length in 8..=11 {
            let mut labels = 0;
            let mut drawn = 0;
            while drawn < SAMPLES {
                let value: Vec<u8> = (0..length)
                    .map(|_| separated[(next(&mut state) >> 33) as usize % separated.len()])
                    .collect();
                if !value.iter().any(|byte| matches!(byte, b'.' | b'_' | b'-')) {
                    continue;
                }
                drawn += 1;
                labels += usize::from(is_identifier_label(&value));
            }
            eprintln!("separated length {length}: labels {labels}/{SAMPLES}");
            assert!(labels * 500 <= SAMPLES, "length {length}: {labels}");
        }
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
