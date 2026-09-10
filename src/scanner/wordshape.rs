// word-structure recognition for exemption-layer filtering

use super::entropy::MIN_ENTROPY_LENGTH;

// com is the common domain abbreviation; wui abbreviates web user interface.
const SHORT_WORDS: &str = "id ids db io os ui ux ip by to of in at is on or if no go do up as an it my we api url uri get set add del new key val var str int num max min sum avg len idx src dst dir cfg env tmp log err msg cmd arg obj ptr ref res req ctx mod lib bin dev app web css js ts py rs md sh txt xml yml row col tab div img btn nav pos end run map fn mut pub use let for and not all any one two out off low top fs tcp udp dns tls ssl ssh git npm pip cli gui sql orm jwt uid gid pid sec ms ns kb mb gb hz ok com wui";

struct Word<'a> {
    bytes: &'a [u8],
    start: usize,
}

fn checked_value(value: &[u8]) -> Option<&[u8]> {
    let value = match value.last() {
        Some(b',' | b';') => &value[..value.len() - 1],
        _ => value,
    };
    if value
        .iter()
        .any(|&byte| !byte.is_ascii_alphanumeric() && !is_separator(byte))
        || value.windows(3).any(|bytes| bytes == b"://")
    {
        return None;
    }
    Some(value)
}

fn is_separator(byte: u8) -> bool {
    matches!(byte, b'.' | b'-' | b'_' | b'/' | b':')
}

fn is_lowercase_word(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_lowercase)
}

fn is_capitalized_word(bytes: &[u8]) -> bool {
    bytes[0].is_ascii_uppercase() && bytes[1..].iter().all(u8::is_ascii_lowercase)
}

fn words(value: &[u8]) -> Vec<Word<'_>> {
    let mut words = Vec::new();
    let mut start = 0;
    for i in 0..value.len() {
        if is_separator(value[i]) {
            if start < i {
                words.push(Word {
                    bytes: &value[start..i],
                    start,
                });
            }
            start = i + 1;
        } else if i > start {
            let previous = value[i - 1];
            let current = value[i];
            let boundary = previous.is_ascii_digit() != current.is_ascii_digit()
                || (previous.is_ascii_lowercase() && current.is_ascii_uppercase())
                || (previous.is_ascii_uppercase()
                    && current.is_ascii_uppercase()
                    && value.get(i + 1).is_some_and(u8::is_ascii_lowercase));
            if boundary {
                words.push(Word {
                    bytes: &value[start..i],
                    start,
                });
                start = i;
            }
        }
    }
    if start < value.len() {
        words.push(Word {
            bytes: &value[start..],
            start,
        });
    }
    words
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// summarizes the byte-level word structure of a candidate value.
pub struct WordStructure {
    pub words: usize,
    pub short_words: usize,
    pub longest_word: usize,
    pub digit_bytes: usize,
    pub rejected_byte: bool,
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// analyzes the byte-level word structure of a candidate value.
pub fn analyze(value: &[u8]) -> WordStructure {
    let mut report = WordStructure {
        words: 0,
        short_words: 0,
        longest_word: 0,
        digit_bytes: 0,
        rejected_byte: true,
    };
    let Some(value) = checked_value(value) else {
        return report;
    };
    report.rejected_byte = false;
    for word in words(value) {
        report.words += 1;
        report.longest_word = report.longest_word.max(word.bytes.len());
        if word.bytes[0].is_ascii_digit() {
            report.digit_bytes += word.bytes.len();
        } else if word.bytes.len() < 4 {
            report.short_words += 1;
        }
    }
    report
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// recognizes identifier structure; human-style passphrases are a documented blind spot.
pub fn is_word_structured(value: &[u8]) -> bool {
    let Some(value) = checked_value(value) else {
        return false;
    };
    if value.len() < MIN_ENTROPY_LENGTH {
        return false;
    }
    let words = words(value);
    if words.iter().any(|word| word.bytes.len() >= 20) {
        return false;
    }
    let digit_bytes: usize = words
        .iter()
        .filter(|word| word.bytes[0].is_ascii_digit())
        .map(|word| word.bytes.len())
        .sum();
    if digit_bytes > 8 {
        return false;
    }
    let mut numeric_words = 0;
    let mut alphabetic_words = 0;
    let mut long_words = 0;
    let separator_count = value.iter().filter(|&&byte| is_separator(byte)).count();
    let has_separator = separator_count > 0;
    let mut i = 0;
    while i < words.len() {
        let word = &words[i];
        let bytes = word.bytes;
        if bytes[0].is_ascii_digit() {
            numeric_words += 1;
            if numeric_words > 2 || bytes.len() > 4 {
                return false;
            }
        } else {
            if bytes.len() == 1 {
                if words.get(i + 1).is_some_and(|next| {
                    next.start == word.start + 1
                        && next.bytes[0].is_ascii_digit()
                        && next.bytes.len() <= 4
                }) {
                    i += 2;
                    continue;
                }
                return false;
            }
            if !(is_lowercase_word(bytes)
                || bytes.iter().all(u8::is_ascii_uppercase)
                || is_capitalized_word(bytes))
            {
                return false;
            }
            alphabetic_words += 1;
            if bytes.len() >= 4 {
                long_words += 1;
            } else if !SHORT_WORDS
                .split_ascii_whitespace()
                .any(|allowed| bytes.eq_ignore_ascii_case(allowed.as_bytes()))
            {
                return false;
            }
        }
        i += 1;
    }
    let camel_only = !has_separator
        && words.iter().enumerate().all(|(index, word)| {
            (index == 0 && is_lowercase_word(word.bytes)) || is_capitalized_word(word.bytes)
        });
    if separator_count < 2 && !camel_only {
        return false;
    }
    if camel_only && long_words < 4 {
        return false;
    }
    // multiplication implements a ceiling for half of an odd alphabetic count.
    long_words >= 3 && long_words * 2 >= alphabetic_words && (long_words >= 4 || has_separator)
}

#[cfg(test)]
mod tests {
    use super::{analyze, is_word_structured};
    use crate::scanner::entropy::shannon_entropy;

    const SAMPLES: usize = 5_000;

    struct XorShift64Star(u64);

    impl XorShift64Star {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u32 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
        }

        fn byte_from(&mut self, alphabet: &[u8]) -> u8 {
            alphabet[(self.next() as usize) % alphabet.len()]
        }
    }

    fn random_string(prng: &mut XorShift64Star, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(prng.byte_from(alphabet)))
            .collect()
    }

    fn uuid_v4(prng: &mut XorShift64Star, dashed: bool) -> String {
        let mut value = String::with_capacity(if dashed { 36 } else { 32 });
        for (group, length) in [8, 4, 4, 4, 12].into_iter().enumerate() {
            for position in 0..length {
                let byte = if group == 2 && position == 0 {
                    b'4'
                } else if group == 3 && position == 0 {
                    prng.byte_from(b"89ab")
                } else {
                    prng.byte_from(b"0123456789abcdef")
                };
                value.push(char::from(byte));
            }
            if dashed && group < 4 {
                value.push('-');
            }
        }
        value
    }

    #[test]
    fn analyze_reports_raw_word_structure() {
        let report = analyze(b"XMLParser/v2");
        assert_eq!(report.words, 4);
        assert_eq!(report.short_words, 2);
        assert_eq!(report.longest_word, 6);
        assert_eq!(report.digit_bytes, 1);
        assert!(!report.rejected_byte);
        assert!(analyze(b"invalid+byte").rejected_byte);
    }

    #[test]
    fn benign_identifier_table_meets_threshold() {
        let benign = [
            "hummingbot.strategy.strategy_v2_base.ExecutorOrchestrator",
            "noteLifecycleChangeHappened",
            "CloseType.STOP_LOSS_TRIGGERED_EVENT",
            ".wui-candlestick-chart__something",
            "lv.font_montserrat_compressed",
            "some/dir/config-file.toml",
            "getUserAccessTokenFromCache",
            "unittest.mock.patch.object",
            "CompiledAllowlist::from_config",
            "github.com/owner/repo/internal/scan",
            "rbac.authorization.k8s.io/v1beta1",
            "docs/plans/redact-claude-masks.md",
            "strategy_v2_base.ExecutorOrchestrator",
            "node_modules/.bin/eslint-config-next",
            "internal/scan/libsecp256k1/src/precomputed",
        ];
        let passed = benign
            .iter()
            .filter(|value| is_word_structured(value.as_bytes()))
            .count();
        for value in benign {
            eprintln!("benign {value}: {}", is_word_structured(value.as_bytes()));
        }
        eprintln!("benign pass rate: {passed}/{}", benign.len());
        assert!(
            passed >= 13,
            "benign pass rate was {passed}/{}",
            benign.len()
        );
        assert!(!is_word_structured(b"application/vnd.api+json"));
    }

    #[test]
    fn opaque_and_credential_shaped_values_are_not_exempted() {
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);
        let uppercase_then_lowercase: String =
            (b'A'..=b'Z').chain(b'a'..=b'f').map(char::from).collect();
        let lowercase: String = (b'a'..=b'z').map(char::from).collect();
        let alternating: String = (0..26)
            .map(|index| {
                let byte = b'a' + index as u8;
                char::from(if index % 2 == 0 {
                    byte.to_ascii_uppercase()
                } else {
                    byte
                })
            })
            .collect();
        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let lower_hex = b"0123456789abcdef";
        let random_identifier = random_string(&mut prng, base62, 16);
        let jwt_header = random_string(&mut prng, base62, 10);
        let jwt_payload = random_string(&mut prng, base62, 12);
        let jwt_signature = random_string(&mut prng, base62, 15);
        let values = vec![
            uppercase_then_lowercase,
            lowercase,
            alternating,
            random_string(&mut prng, base62, 32),
            random_string(&mut prng, lower_hex, 32),
            uuid_v4(&mut prng, true),
            uuid_v4(&mut prng, false),
            format!("task/{random_identifier}/main/unit/detector"),
            format!("{jwt_header}.{jwt_payload}.{jwt_signature}"),
            "https://x".to_owned(),
            "foo(bar)".to_owned(),
            "a+b".to_owned(),
            "x=y".to_owned(),
            "name@host".to_owned(),
            "rate%value".to_owned(),
            "internationalization".to_owned(),
            "2026-09-08-1234-5678".to_owned(),
        ];
        for value in values {
            assert!(
                !is_word_structured(value.as_bytes()),
                "unexpected exemption: {value}"
            );
        }
    }

    #[test]
    fn random_credentials_are_never_exempted() {
        let alphabets: [(&str, &[u8]); 8] = [
            ("hex-lower", b"0123456789abcdef"),
            ("hex-upper", b"0123456789ABCDEF"),
            ("base32", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            ("base36-lower", b"0123456789abcdefghijklmnopqrstuvwxyz"),
            (
                "base58",
                b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            ),
            (
                "base62",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            ),
            (
                "base64url",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            ),
            (
                "mixed-alpha",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            ),
        ];
        let lengths = [20, 24, 32, 40, 64];
        let mut prng = XorShift64Star::new(0x9e37_79b9_7f4a_7c15);

        for (name, alphabet) in alphabets {
            for length in lengths {
                let exempted = (0..SAMPLES)
                    .filter(|_| {
                        is_word_structured(random_string(&mut prng, alphabet, length).as_bytes())
                    })
                    .count();
                eprintln!("{name}\t{length}\t{SAMPLES}\t{exempted}");
                assert_eq!(exempted, 0, "{name} length {length}");
            }
        }

        for dashed in [true, false] {
            let name = if dashed {
                "uuid-v4-dashed"
            } else {
                "uuid-v4-dashless"
            };
            let exempted = (0..SAMPLES)
                .filter(|_| is_word_structured(uuid_v4(&mut prng, dashed).as_bytes()))
                .count();
            let length = if dashed { 36 } else { 32 };
            eprintln!("{name}\t{length}\t{SAMPLES}\t{exempted}");
            assert_eq!(exempted, 0, "{name}");
        }

        let base62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let separators = b".-_";
        let exempted = (0..SAMPLES)
            .filter(|_| {
                let length = 24 + (prng.next() as usize % 17);
                let mut value = random_string(&mut prng, base62, length);
                let position = prng.next() as usize % (value.len() + 1);
                value.insert(position, char::from(prng.byte_from(separators)));
                is_word_structured(value.as_bytes())
            })
            .count();
        eprintln!("base62-separated\t24-40\t{SAMPLES}\t{exempted}");
        assert_eq!(exempted, 0, "base62 with one separator");
    }

    #[test]
    fn human_passphrases_are_exempted_documented_cost() {
        let passphrases = [
            "MyVeryLongPassphraseForProduction",
            "correct-horse-battery-staple",
            "SuperSecretAdminPassword",
            "winter_meadow_sunrise_memory",
            "ReliableBackupRotationSchedule",
            "MountainRiverCedarForest",
            "orchard-lantern-morning-walk",
            "GentleNotebookCoffeeBreak",
            "archive_index_cleanup_plan",
            "secure-vault-rotation-checklist",
            "ProductReleaseValidationNotes",
            "telescope-garden-midnight-rain",
            "HelpfulAssistantDocumentReview",
            "network_backup_storage_policy",
            "CalendarMeetingReminderWorkflow",
            "copper-bridge-evening-window",
            "DocumentedMigrationSafetySteps",
            "morning_coffee_reading_journal",
            "PrivacyFocusedAccessControl",
            "library-catalog-search-index",
            "ServiceHealthMonitoringDashboard",
            "orange-violet-silver-garden",
            "ProjectPlanningSessionNotes",
            "friendly-neighbor-weekend-market",
        ];
        for value in passphrases {
            assert!(
                is_word_structured(value.as_bytes()),
                "expected exemption: {value}"
            );
        }
        let high_entropy = passphrases
            .iter()
            .filter(|value| shannon_entropy(value.as_bytes()) >= 4.0)
            .count();
        eprintln!(
            "human passphrases at entropy >= 4.0: {high_entropy}/{}",
            passphrases.len()
        );
    }
}
