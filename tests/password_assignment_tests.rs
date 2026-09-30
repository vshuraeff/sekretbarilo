use sekretbarilo::config::{self, ProjectConfig, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use sekretbarilo::scanner::{entropy, password};
use std::collections::HashSet;
use std::sync::LazyLock;

const PASSWORD: &str = "h9L!q2N#v7T@r4W$";
const RULE: &str = "generic-password-assignment";

fn setup() -> (CompiledScanner, CompiledAllowlist) {
    let rules = load_default_rules().unwrap();
    (
        compile_rules(&rules).unwrap(),
        config::build_allowlist(&ProjectConfig::default(), &rules).unwrap(),
    )
}

#[test]
fn quoted_and_plain_assignments_share_the_existing_rule_and_exact_capture() {
    let (scanner, allowlist) = setup();
    for (path, text) in [
        ("config.ini", format!("password = {PASSWORD}")),
        (
            "config.properties",
            format!("spring.datasource.password={PASSWORD}"),
        ),
        ("deploy.sh", format!("export DB_PASSWORD={PASSWORD}")),
        ("config.yaml", format!("password: {PASSWORD}")),
        ("config.toml", format!("password = \"{PASSWORD}\"")),
        (
            "config.json",
            format!("{{\"password\":\"{PASSWORD}\",\"port\":5432}}"),
        ),
        ("config.py", format!("{{'passwd': '{PASSWORD}'}}")),
        ("config.go", format!("password = `{PASSWORD}`")),
        ("config.js", format!("const pwd = `{PASSWORD}`;")),
        ("config.php", format!("$config['password'] = '{PASSWORD}';")),
    ] {
        let file = DiffFile {
            path: path.into(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            context: None,
            added_lines: vec![AddedLine {
                line_number: 7,
                content: text.as_bytes().to_vec(),
            }],
        };
        let findings = scan(&[file], &scanner, &allowlist);
        let password_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == RULE).collect();
        assert_eq!(password_findings.len(), 1, "{path}: {findings:?}");
        assert_eq!(
            password_findings[0].matched_value,
            PASSWORD.as_bytes(),
            "{path}"
        );
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            text.replace(PASSWORD, "[REDACTED]"),
            "{path}"
        );
    }
}

#[test]
fn matching_quote_pairs_preserve_internal_quotes_escapes_and_spaces() {
    let (scanner, allowlist) = setup();
    for (quote, password) in [
        ('"', "aB9!w'xQ2#rT7pL4"),
        ('\'', "aB9!w\"xQ2#rT7pL4"),
        ('`', "aB9!w'\"xQ2#rT7pL4"),
        ('"', r#"aB9!w\"xQ2#rT7pL4"#),
        ('\'', r"aB9!w\'xQ2#rT7pL4"),
        ('`', r"aB9!w\`xQ2#rT7pL4"),
        ('"', "aB9! wX2# rT7pL4秘密"),
        ('\'', r"aB9!wX2#rT7pL4\"),
        ('`', r"aB9!wX2#rT7pL4\"),
        ('\'', "aB9!w''X2#rT7pL4"),
    ] {
        let text = format!("password = {quote}{password}{quote}; port=5432");
        let matches = scan_text(&text, &scanner, &allowlist);
        assert_eq!(matches.len(), 1, "{text}: {matches:?}");
        assert_eq!(&text[matches[0].range.clone()], password);
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            format!("password = {quote}[REDACTED]{quote}; port=5432")
        );
    }
}

#[test]
fn plain_values_stop_at_separators_and_leave_adjacent_fields_and_comments() {
    let (scanner, allowlist) = setup();
    for text in [
        format!("password={PASSWORD} port=5432"),
        format!("password={PASSWORD};port=5432"),
        format!("{{password: {PASSWORD}, port: 5432}}"),
        format!("connect(password={PASSWORD})"),
        format!("password={PASSWORD}\t# keep this comment"),
        format!("password={PASSWORD} ; keep this comment"),
        format!("host=localhost\r\npassword={PASSWORD}\r\nport=5432\r\n"),
        format!("password={PASSWORD}\npwd={PASSWORD}\n"),
    ] {
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            text.replace(PASSWORD, "[REDACTED]")
        );
    }
    let value = "aB9!xQ2#rT7@pL4$/+=:秘密";
    assert_eq!(
        redact_text(&format!("password={value}"), &scanner, &allowlist),
        "password=[REDACTED]"
    );
    for value in [
        r"aB9!qX2\;rT7pL4",
        r"aB9!qX2\ rT7pL4",
        r"aB9!qX2\,rT7pL4",
        r"aB9!qX2\'rT7pL4",
    ] {
        assert_eq!(
            redact_text(
                &format!("password={value}; port=5432"),
                &scanner,
                &allowlist
            ),
            "password=[REDACTED]; port=5432"
        );
    }
    for ending in ["", "\r\n"] {
        assert_eq!(
            redact_text(
                &format!("password={PASSWORD}\\{ending}"),
                &scanner,
                &allowlist
            ),
            format!("password=[REDACTED]{ending}")
        );
    }
}

#[test]
fn ambiguous_raw_or_escaped_closing_quotes_mask_the_longer_interpretation() {
    let (scanner, allowlist) = setup();
    for quote in ['\'', '`'] {
        let text = format!("password={quote}{PASSWORD}\\{quote}; label={quote}visible{quote}");
        // the same text can contain a raw literal or an escaped quote inside a
        // longer password. keep the conservative interpretation without a parser.
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            format!("password={quote}[REDACTED]{quote}visible{quote}")
        );
    }
}

#[test]
fn placeholders_references_weak_values_and_unassigned_lines_stay_clean() {
    let (scanner, allowlist) = setup();
    for text in [
        "password=password",
        "password=changeme",
        "password=aaaaaaaaaaaaaaaaaaaa",
        "password=$DATABASE_PASSWORD",
        "password=${DATABASE_PASSWORD}",
        "password=${var.database_password}",
        "password=${DATABASE_PASSWORD:-fallback}",
        "password=%DATABASE_PASSWORD%",
        "password={{ vault_password }}",
        "password=process.env.DATABASE_PASSWORD",
        "password=os.getenv(\"DATABASE_PASSWORD\")",
        "password=System.getenv(\"DATABASE_PASSWORD\")",
        "password=std::env::var(\"DATABASE_PASSWORD\")",
        "password = #aB9!xQ2rT7pL4 comment",
        "password = ;aB9!xQ2rT7pL4 comment",
        "password =\nh9L!q2N#v7T@r4W$",
        "password_validation_minimum_length = 12",
    ] {
        assert!(scan_text(text, &scanner, &allowlist).is_empty(), "{text}");
    }
}

#[test]
fn existing_value_allowlists_cover_every_quoting_form() {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::new(
        &[],
        &[],
        None,
        &[(
            RULE.into(),
            vec![format!("^{}$", regex::escape(PASSWORD))],
            vec![],
        )],
        false,
    )
    .unwrap();
    for quote in ["", "\"", "'", "`"] {
        assert!(
            scan_text(
                &format!("password={quote}{PASSWORD}{quote}"),
                &scanner,
                &allowlist
            )
            .is_empty()
        );
    }
}

#[test]
fn custom_override_of_existing_rule_keeps_its_capture_semantics() {
    let mut rules = load_default_rules().unwrap();
    let rule = rules.iter_mut().find(|r| r.id == RULE).unwrap();
    rule.regex_pattern = "PASSWORD=([A-Za-z0-9!]+)".into();
    rule.secret_group = 1;
    rule.secret_groups.clear();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    assert!(scan_text(&format!("password={PASSWORD}"), &scanner, &allowlist).is_empty());
    let value = "Q7m4V9!z2N8k5!p3R6";
    assert_eq!(
        redact_text(&format!("PASSWORD={value}"), &scanner, &allowlist),
        "PASSWORD=[REDACTED]"
    );
}

#[test]
fn old_custom_rules_keep_whole_match_fallback_without_opted_in_groups() {
    let config: ProjectConfig = toml::from_str(
        r#"
[[rules]]
id = "generic-password-assignment"
description = "custom optional group"
regex = 'PASSWORD=(DISABLED)?(?P<password_unquoted>Q7m4V9!z2N8k5!p3R6)'
secret_group = 1
keywords = ["password"]
"#,
    )
    .unwrap();
    assert!(config.rules[0].secret_groups.is_empty());
    let rules = config::load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&config, &rules).unwrap();
    assert_eq!(
        redact_text("PASSWORD=Q7m4V9!z2N8k5!p3R6", &scanner, &allowlist),
        "[REDACTED]"
    );
}

fn core_repro_value() -> String {
    [
        'q', '2', 'r', 'Q', 't', '2', 'w', 'r', 'R', 'q', 'y', '2', 't', 'u', 'q', '5', 'i', 'r',
        'o', 'q', 'p', 'q',
    ]
    .into_iter()
    .collect()
}

fn weak_mixed_value(len: usize) -> String {
    (0..len)
        .map(|index| match index % 3 {
            0 => 'q',
            1 => '2',
            _ => 'R',
        })
        .collect()
}

fn two_class_value(len: usize, first: char, second: char) -> String {
    (0..len)
        .map(|index| if index % 2 == 0 { first } else { second })
        .collect()
}

fn connection_password_value() -> String {
    [
        'q', '2', 'R', 'w', '5', 'T', 'y', '7', 'U', 'i', '2', 'R', 'o', '5', 'T', 'p', '9', 'V',
    ]
    .into_iter()
    .collect()
}

#[test]
fn long_mixed_alphanumeric_assignment_is_detected() {
    let (scanner, allowlist) = setup();
    let value = core_repro_value();
    let distinct: HashSet<_> = value.bytes().collect();
    let strength = password::analyze_strength(value.as_bytes());

    assert_eq!(value.len(), 22);
    assert_eq!(distinct.len(), 13);
    assert!(strength.has_lowercase);
    assert!(strength.has_uppercase);
    assert!(strength.has_digits);
    assert!(!password::is_strong_password(value.as_bytes()));
    assert!((entropy::shannon_entropy(value.as_bytes()) - 3.4085).abs() < 0.01);

    let text = format!("password: \"{value}\"");
    let file = DiffFile {
        path: "settings.yaml".into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: text.as_bytes().to_vec(),
        }],
    };
    let findings = scan(&[file], &scanner, &allowlist);
    let password_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == RULE).collect();

    assert_eq!(password_findings.len(), 1);
    assert_eq!(password_findings[0].matched_value, value.as_bytes());
}

#[test]
fn dictionary_word_with_trailing_digits_stays_clean_in_assignment_scan() {
    let (scanner, allowlist) = setup();
    let dictionary_word = ["pass", "word"].concat();
    let mut chars = dictionary_word.chars();
    let capitalized = chars
        .next()
        .unwrap()
        .to_uppercase()
        .chain(chars)
        .collect::<String>();
    let suffix: String = (0..4).map(|index| char::from(b'1' + index as u8)).collect();
    let value = format!("{capitalized}{suffix}");
    let text = format!("x_password: \"{value}\"");

    assert!(
        scan_text(&text, &scanner, &allowlist)
            .iter()
            .all(|finding| finding.rule_id != RULE)
    );

    let file = DiffFile {
        path: "settings.yaml".into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: text.as_bytes().to_vec(),
        }],
    };
    let findings = scan(&[file], &scanner, &allowlist);
    assert!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == RULE)
            .count()
            == 0,
        "{findings:?}"
    );
}

#[test]
fn mixed_alphanumeric_yaml_quoting_forms_are_detected_and_redacted() {
    let (scanner, allowlist) = setup();
    let double_quoted = weak_mixed_value(12);
    let single_quoted = weak_mixed_value(13);
    let unquoted = weak_mixed_value(14);

    for (text, value, expected_redaction) in [
        (
            format!("x_password: \"{double_quoted}\""),
            double_quoted,
            "x_password: \"[REDACTED]\"".to_owned(),
        ),
        (
            format!("x_password: '{single_quoted}'"),
            single_quoted,
            "x_password: '[REDACTED]'".to_owned(),
        ),
        (
            format!("x_password: {unquoted}"),
            unquoted,
            "x_password: [REDACTED]".to_owned(),
        ),
    ] {
        assert!(!password::is_strong_password(value.as_bytes()));

        let file = DiffFile {
            path: "settings.yaml".into(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            context: None,
            added_lines: vec![AddedLine {
                line_number: 1,
                content: text.as_bytes().to_vec(),
            }],
        };
        let findings = scan(&[file], &scanner, &allowlist);
        let password_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == RULE).collect();
        assert_eq!(password_findings.len(), 1);
        assert_eq!(password_findings[0].matched_value, value.as_bytes());

        assert_eq!(scan_text(&text, &scanner, &allowlist).len(), 1);
        assert_eq!(redact_text(&text, &scanner, &allowlist), expected_redaction);
    }
}

#[test]
fn assignment_mixed_alphanumeric_length_and_class_boundaries_are_preserved() {
    let (scanner, allowlist) = setup();
    let scan_line = |text: &str| {
        scan(
            &[DiffFile {
                path: "settings.yaml".into(),
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                context: None,
                added_lines: vec![AddedLine {
                    line_number: 1,
                    content: text.as_bytes().to_vec(),
                }],
            }],
            &scanner,
            &allowlist,
        )
    };

    for len in [11, 12, 15, 16, 19, 20] {
        let value = weak_mixed_value(len);
        assert!(password::analyze_strength(value.as_bytes()).score < 6.0);
        assert!(!password::is_strong_password(value.as_bytes()));

        let findings = scan_line(&format!("password: {value}"));
        let password_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == RULE).collect();
        if len == 11 {
            assert!(password_findings.is_empty());
        } else {
            assert_eq!(password_findings.len(), 1);
            assert_eq!(password_findings[0].matched_value, value.as_bytes());
        }
    }

    for value in [two_class_value(22, 'R', '2'), two_class_value(22, 'q', 'R')] {
        assert!(password::analyze_strength(value.as_bytes()).score < 6.0);
        assert!(!password::is_strong_password(value.as_bytes()));
        assert!(
            scan_line(&format!("password: {value}"))
                .iter()
                .all(|finding| finding.rule_id != RULE)
        );
    }

    // a lowercase and digit alternation is a short-period repetition (period 2), so the diversity
    // floor keeps it clean everywhere, config literal or not
    let alternation = two_class_value(22, 'q', '2');
    let alternation_line = format!("password: {alternation}");
    assert!(
        scan_line(&alternation_line)
            .iter()
            .all(|finding| finding.rule_id != RULE)
    );
    assert!(
        scan_text(&alternation_line, &scanner, &allowlist)
            .iter()
            .all(|finding| finding.rule_id != RULE)
    );

    let control = PASSWORD;
    let control_strength = password::analyze_strength(control.as_bytes());
    assert!(control_strength.score >= 6.0);
    assert!(control_strength.has_special);
    assert!(password::is_strong_password(control.as_bytes()));
    assert_eq!(
        scan_line(&format!("password: {control}"))
            .iter()
            .filter(|finding| finding.rule_id == RULE)
            .count(),
        1
    );
}

#[test]
fn assignment_password_clean_controls_remain_clean() {
    let (scanner, allowlist) = setup();
    let scan_line = |text: &str| {
        scan(
            &[DiffFile {
                path: "settings.yaml".into(),
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                context: None,
                added_lines: vec![AddedLine {
                    line_number: 1,
                    content: text.as_bytes().to_vec(),
                }],
            }],
            &scanner,
            &allowlist,
        )
    };

    for value in [["pass", "word"].concat(), ["pass", "w0rd"].concat()] {
        assert!(password::analyze_strength(value.as_bytes()).is_dictionary_word);
        assert!(
            scan_line(&format!("password: {value}"))
                .iter()
                .all(|finding| finding.rule_id != RULE)
        );
    }

    let repeated: String = (0..20).map(|_| 'q').collect();
    assert!(
        scan_line(&format!("password: {repeated}"))
            .iter()
            .all(|finding| finding.rule_id != RULE)
    );

    for text in [
        "DB_PASSWORD_FILE=/run/keys/db_password",
        "password: db.connection.timeout_seconds",
        "password: service_auth_name_value",
    ] {
        let value = text
            .split_once('=')
            .or_else(|| text.split_once(':'))
            .unwrap()
            .1
            .trim();
        assert!(password::analyze_strength(value.as_bytes()).score < 6.0);
        assert!(
            scan_line(text)
                .iter()
                .all(|finding| finding.rule_id != RULE)
        );
    }
}

#[test]
fn assignment_labels_and_connection_string_keep_their_scoped_behavior() {
    let (scanner, allowlist) = setup();
    let scan_line = |text: &str| {
        scan(
            &[DiffFile {
                path: "settings.yaml".into(),
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                context: None,
                added_lines: vec![AddedLine {
                    line_number: 1,
                    content: text.as_bytes().to_vec(),
                }],
            }],
            &scanner,
            &allowlist,
        )
    };

    for value in [
        ["pass", "word", "Field", "Label", "1"].concat(),
        ["Pass", "word", "Input", "2"].concat(),
    ] {
        assert!(value.len() >= 12);
        assert!(!password::is_strong_password(value.as_bytes()));
        // 0.8.1 reported these mixed-case labels; the identifier veto drops them in every form.
        for text in [
            format!("password: {value}"),
            format!("password: \"{value}\""),
            format!("PASSWORD={value}"),
        ] {
            assert_eq!(
                scan_line(&text)
                    .iter()
                    .filter(|finding| finding.rule_id == RULE)
                    .count(),
                0,
                "{text}"
            );
        }
        assert!(scan_text(&format!("# {value}"), &scanner, &allowlist).is_empty());
    }
}

#[test]
fn connection_string_strength_gate_remains_unchanged() {
    let (scanner, allowlist) = setup();
    let value = connection_password_value();
    assert!(entropy::shannon_entropy(value.as_bytes()) > 3.5);
    assert!(!password::is_strong_password(value.as_bytes()));

    let file = DiffFile {
        path: "settings.yaml".into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: format!("postgres://user:{value}@host/db").into_bytes(),
        }],
    };
    assert_eq!(
        scan(&[file], &scanner, &allowlist)
            .iter()
            .filter(|finding| finding.rule_id == "password-in-url")
            .count(),
        1
    );
}

// generated values for the widened gate. no opaque literal is stored: every value below comes from
// this deterministic generator.

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!#%&*+=?@^~";
const CONSONANTS: &[u8] = b"bcdfghjkmnpqrstvwxz";

/// xorshift64*
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn pick(&mut self, alphabet: &[u8]) -> char {
        char::from(alphabet[(self.next() >> 33) as usize % alphabet.len()])
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() >> 33) as usize % bound
    }
}

/// one random byte per position, cycling through the given classes, so every class is present and
/// no run of letters can spell a word.
fn cycled(prng: &mut Prng, classes: &[&[u8]], len: usize) -> String {
    (0..len)
        .map(|index| prng.pick(classes[index % classes.len()]))
        .collect()
}

/// alternating runs of one to three lowercase letters and one to three digits, starting with a
/// letter, optionally with one run of four consonants that no vowel makes wordlike.
fn interleaved(prng: &mut Prng, len: usize, consonant_run: bool) -> String {
    let mut value = String::new();
    if consonant_run {
        (0..4).for_each(|_| value.push(prng.pick(CONSONANTS)));
    }
    let mut letters = !consonant_run;
    while value.len() < len {
        let run = 1 + prng.below(3);
        let alphabet = if letters { LOWER } else { DIGITS };
        (0..run).for_each(|_| value.push(prng.pick(alphabet)));
        letters = !letters;
    }
    value.truncate(len);
    value
}

/// a value whose first `period` bytes repeat (and truncate) to reach `len`: alternating one
/// lowercase letter and one digit per block position, so the block itself is not a single class.
fn periodic_value(prng: &mut Prng, period: usize, len: usize) -> String {
    let block: Vec<char> = (0..period)
        .map(|index| {
            if index % 2 == 0 {
                prng.pick(LOWER)
            } else {
                prng.pick(DIGITS)
            }
        })
        .collect();
    (0..len).map(|index| block[index % period]).collect()
}

/// a value whose first `period` bytes repeat (and truncate) to reach `len`, cycling through all
/// four character classes so the block alone can carry four-class diversity.
fn periodic_class_value(prng: &mut Prng, period: usize, len: usize) -> String {
    let classes = [UPPER, LOWER, DIGITS, SPECIAL];
    let block: Vec<char> = (0..period)
        .map(|index| prng.pick(classes[index % classes.len()]))
        .collect();
    (0..len).map(|index| block[index % period]).collect()
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// one compiled scanner for the generated-value tests, which scan thousands of lines.
static SHARED: LazyLock<(CompiledScanner, CompiledAllowlist)> = LazyLock::new(setup);

fn diff_values(path: &str, text: &str) -> Vec<Vec<u8>> {
    let (scanner, allowlist) = &*SHARED;
    let file = DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: text.as_bytes().to_vec(),
        }],
    };
    scan(&[file], scanner, allowlist)
        .into_iter()
        .filter(|finding| finding.rule_id == RULE)
        .map(|finding| finding.matched_value)
        .collect()
}

fn text_hits(text: &str) -> usize {
    let (scanner, allowlist) = &*SHARED;
    scan_text(text, scanner, allowlist)
        .iter()
        .filter(|matched| matched.rule_id == RULE)
        .count()
}

/// every concrete-literal form of the widened branches: quoted values, a json string, and shell
/// assignment words.
fn literal_forms(value: &str) -> Vec<(&'static str, String)> {
    vec![
        ("config.json", format!("{{\"password\": \"{value}\"}}")),
        ("config.yaml", format!("db_password: '{value}'")),
        ("settings.py", format!("DB_PASSWORD = \"{value}\"")),
        ("app.js", format!("const pwd = `{value}`;")),
        ("deploy.sh", format!("export DB_PASSWORD={value}")),
        ("deploy.sh", format!("ADMIN_PASSWORD={value}")),
    ]
}

/// unquoted right-hand sides in source files that are not shell assignment words: a mapping-shaped
/// or object-literal plain value, a spaced source assignment, and an assignment that does not
/// start the line.
fn non_literal_forms(value: &str) -> Vec<(&'static str, String)> {
    vec![
        ("settings.py", format!("password: {value}")),
        ("app.js", format!("  password: {value},")),
        ("settings.py", format!("password = {value}")),
        ("run.sh", format!("docker run -e DB_PASSWORD={value} image")),
    ]
}

/// unquoted values that are concrete literals only because the file is a configuration file: yaml
/// plain scalars (optionally in a list item and before a comment), ini-style, toml and dotenv
/// entries. the same lines in source files and on the pathless text surface are not literals.
fn config_forms(value: &str) -> Vec<(&'static str, String)> {
    vec![
        ("config.yaml", format!("db_password: {value}")),
        (
            "deploy/values.yml",
            format!("  - admin_password: {value}  # rotated"),
        ),
        ("compose.yaml", format!("    \"db_password\": {value}")),
        ("app.ini", format!("password = {value}")),
        ("app.ini", format!("password = {value} ; rotated")),
        ("settings.cfg", format!("db_password: {value}")),
        ("server.properties", format!("db.password = {value}")),
        ("config.toml", format!("password = {value}")),
        (".env.example", format!("DB_PASSWORD = {value}")),
    ]
}

#[test]
fn short_three_and_four_class_literals_are_reported_in_every_literal_form() {
    let (scanner, allowlist) = &*SHARED;
    let mut prng = Prng(0x9E37_79B9_7F4A_7C15);
    for len in 8..=11 {
        for classes in [
            [UPPER, LOWER, DIGITS, SPECIAL].as_slice(),
            [LOWER, DIGITS, SPECIAL].as_slice(),
            [UPPER, LOWER, SPECIAL].as_slice(),
            [UPPER, DIGITS, SPECIAL].as_slice(),
        ] {
            let value = cycled(&mut prng, classes, len);
            // below the general threshold, so only the widened branch can report it
            assert!(password::analyze_strength(value.as_bytes()).score < 6.0);
            for (path, text) in literal_forms(&value) {
                assert_eq!(
                    diff_values(path, &text),
                    vec![value.as_bytes().to_vec()],
                    "{path}: {text}"
                );
                // concern codex-cl-password-001: a bare backtick pair on the pathless surface
                // cannot be told apart from shell command substitution, so it is never a literal
                // there (decision 3); app.js's own path still reports it since backtick keeps its
                // JS-template meaning on a known non-shell surface.
                if path == "app.js" {
                    assert_eq!(text_hits(&text), 0, "{text}");
                    assert_eq!(redact_text(&text, scanner, allowlist), text, "{text}");
                } else {
                    assert_eq!(text_hits(&text), 1, "{text}");
                    assert_eq!(
                        redact_text(&text, scanner, allowlist),
                        text.replace(&value, "[REDACTED]"),
                        "{text}"
                    );
                }
            }
            for (path, text) in non_literal_forms(&value) {
                assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
                assert_eq!(text_hits(&text), 0, "{text}");
            }
        }
    }
}

#[test]
fn short_values_below_the_class_floor_stay_clean() {
    let mut prng = Prng(0x2545_F491_4F6C_DD1D);
    for len in 8..=11 {
        for classes in [
            // three classes without a special byte, and two classes with one
            [UPPER, LOWER, DIGITS].as_slice(),
            [LOWER, SPECIAL].as_slice(),
            [UPPER, DIGITS].as_slice(),
        ] {
            let value = cycled(&mut prng, classes, len);
            for (path, text) in literal_forms(&value)
                .into_iter()
                .chain(config_forms(&value))
            {
                assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
            }
        }
    }
}

#[test]
fn interleaved_lowercase_digit_literals_are_reported_and_wordlike_ones_are_not() {
    let mut prng = Prng(0x5DEE_CE66_D1CE_4E5B);
    for len in [12, 13, 16, 20, 24] {
        for consonant_run in [false, true] {
            let value = interleaved(&mut prng, len, consonant_run);
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            );
            for (path, text) in literal_forms(&value)
                .into_iter()
                .chain(config_forms(&value))
            {
                assert_eq!(
                    diff_values(path, &text),
                    vec![value.as_bytes().to_vec()],
                    "{path}: {text}"
                );
            }
            for (path, text) in non_literal_forms(&value) {
                assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
            }
        }
        // one digit run is not interleaving
        let letters = cycled(&mut prng, &[CONSONANTS], len - 3);
        let digits = cycled(&mut prng, &[DIGITS], 3);
        let single_digit_run = format!("{letters}{digits}");
        for (path, text) in literal_forms(&single_digit_run)
            .into_iter()
            .chain(config_forms(&single_digit_run))
        {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        }
    }

    // word-based lowercase passwords are the documented gap of the lowercase branch
    for value in [
        ["hunter", "2", "hunter", "2"].concat(),
        ["summer", "2024", "winter", "99"].concat(),
        ["orange", "7", "violet", "42"].concat(),
    ] {
        for (path, text) in literal_forms(&value) {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        }
    }
}

#[test]
fn leet_and_dictionary_placeholders_stay_clean() {
    let leet = |word: &str| -> String {
        word.chars()
            .map(|character| match character {
                'a' => '@',
                'o' => '0',
                'e' => '3',
                'i' => '1',
                's' => '$',
                other => other,
            })
            .collect()
    };
    let trust = ["trust", "no1"].concat();
    let pass = ["pass", "word"].concat();
    let values = [
        // a dictionary word that ends in a digit, with more digits appended
        format!("{}2345", capitalize(&trust)),
        format!("{}0!", capitalize(&trust)),
        format!("{}!", capitalize(&leet(&pass))),
        format!("{}2024#", capitalize(&leet("admin"))),
        format!("{}1!", capitalize("welcome")),
        format!("{}9?", capitalize(&leet("letmein"))),
        format!("{}99#", capitalize("changeme")),
        format!("{}1!", capitalize("example")),
        format!("{}12.", leet("dragon").to_uppercase()),
    ];
    for value in values {
        assert!(
            password::analyze_strength(value.as_bytes()).score < 6.0,
            "{value}"
        );
        for (path, text) in literal_forms(&value)
            .into_iter()
            .chain(config_forms(&value))
        {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
            assert_eq!(text_hits(&text), 0, "{text}");
        }
    }
}

#[test]
fn identifier_labels_and_credential_words_stay_clean_while_opaque_values_are_reported() {
    let labels = [
        ["user", "Field", "Label", "1"].concat(),
        ["Database", "Host", "Name", "3"].concat(),
        // a compound of ordinary words with a trailing digit run, the documentation placeholder
        // shape the 0.8.1 widening reported
        ["Secure", "Router", "123"].concat(),
        ["Mountain", "View", "2024"].concat(),
        // four classes at 8-11 bytes, so only the identifier veto keeps these clean
        ["Host", "_", "Name", "1"].concat(),
        ["User", ".", "Panel", "2"].concat(),
        // the key's credential word, plain or leet
        ["My", "Pass", "12", "!"].concat(),
        ["p@ss", "_", "hint", "9"].concat(),
        ["new", "Pwd", "Value", "1"].concat(),
    ];
    for value in &labels {
        assert!(
            password::analyze_strength(value.as_bytes()).score < 6.0,
            "{value}"
        );
        for (path, text) in literal_forms(value)
            .into_iter()
            .chain(non_literal_forms(value))
            .chain(config_forms(value))
        {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        }
    }

    // a generated mixed-case value keeps the 0.8.1 detection even though it has uppercase
    // boundaries the word splitter cuts at
    let base62 = [UPPER, LOWER, DIGITS].concat();
    let mut prng = Prng(0x0123_4567_89AB_CDEF);
    let mut checked = 0;
    while checked < 200 {
        let len = 12 + prng.below(11);
        let value = cycled(&mut prng, &[&base62], len);
        let strength = password::analyze_strength(value.as_bytes());
        // the placeholder filter drops a run of three x's before the strength gate
        if !(strength.has_uppercase && strength.has_lowercase && strength.has_digits)
            || value.to_ascii_lowercase().contains("xxx")
        {
            continue;
        }
        checked += 1;
        for text in [
            format!("password: \"{value}\""),
            format!("password: {value}"),
        ] {
            assert_eq!(
                diff_values("settings.yaml", &text),
                vec![value.as_bytes().to_vec()],
                "{text}"
            );
        }
    }
}

#[test]
fn unquoted_source_expressions_do_not_reach_the_widened_branches() {
    for (path, text) in [
        ("app.js", "  password: form.pw1_x,"),
        ("app.ts", "const password = cfg.pw9#x;"),
        ("settings.py", "password = pw_x9!q"),
        ("settings.py", "DB_PASSWORD = os_pw1!x"),
        ("deploy.sh", "DB_PASSWORD=abc$X9!q"),
        ("deploy.sh", "DB_PASSWORD=\"${U}9!aB\""),
        ("app.js", "const pwd = `${a}9!xQ`;"),
    ] {
        assert!(diff_values(path, text).is_empty(), "{path}: {text}");
        assert_eq!(text_hits(text), 0, "{text}");
    }
}

#[test]
fn plain_configuration_values_are_literals_only_in_configuration_files() {
    let (scanner, allowlist) = &*SHARED;
    let mut prng = Prng(0xD6E8_FEB8_6659_FD93);
    let mut values = Vec::new();
    for len in 8..=11 {
        for classes in [
            [UPPER, LOWER, DIGITS, SPECIAL].as_slice(),
            [LOWER, DIGITS, SPECIAL].as_slice(),
        ] {
            values.push(cycled(&mut prng, classes, len));
        }
    }
    values.push(interleaved(&mut prng, 14, true));
    for value in values {
        // below the general threshold, so only the widened branches can report it
        assert!(!password::is_strong_password(value.as_bytes()), "{value}");
        for (path, text) in config_forms(&value) {
            assert_eq!(
                diff_values(path, &text),
                vec![value.as_bytes().to_vec()],
                "{path}: {text}"
            );
            assert_eq!(
                redact_text(&text, scanner, allowlist),
                text,
                "the pathless text surface keeps the source rule: {text}"
            );
            for source in ["settings.py", "app.js", "src/config.rs"] {
                assert!(diff_values(source, &text).is_empty(), "{source}: {text}");
            }
        }
    }
}

#[test]
fn configuration_references_templates_and_partial_values_are_not_literals() {
    let mut prng = Prng(0xA076_1D64_78BD_642F);
    let value = cycled(&mut prng, &[UPPER, LOWER, DIGITS, SPECIAL], 9);
    let (head, tail) = value.split_at(4);
    // the bare value is reported, so the shape around it is what keeps each line below clean
    for (path, text) in [
        ("config.yaml", format!("password: {value}")),
        ("config.yaml", format!("password: {value} # rotated")),
        ("app.ini", format!("password = @{value}")),
    ] {
        assert_eq!(diff_values(path, &text).len(), 1, "{path}: {text}");
    }
    for text in [
        "password: {{ vault_pw }}".to_owned(),
        "password: ${PW}".to_owned(),
        "password: !vault |".to_owned(),
        // aliases, anchors, tags and reserved indicators
        format!("password: *{value}"),
        format!("password: &{value}"),
        format!("password: !{value}"),
        format!("password: @{value}"),
        format!("password: %{value}"),
        // expansion inside the value
        format!("password: {head}${tail}"),
        // a value the capture cut short or that continues past whitespace
        format!("password: {value} and more"),
        format!("password: {value},{value}"),
        // not a mapping entry: no space after the colon, a nested key, a flag, a subscript
        format!("password:{value}"),
        format!("note: password: {value}"),
        format!("command: mysql --password={value}"),
        format!("data[password]: {value}"),
    ] {
        assert!(diff_values("config.yaml", &text).is_empty(), "{text}");
    }
    for text in [
        format!("password = *{value}"),
        format!("password = {value};{value}"),
        format!("password = {value} trailing words"),
        format!("  export password = ${value}"),
        format!("[db] password = {value}"),
    ] {
        assert!(diff_values("app.ini", &text).is_empty(), "{text}");
    }
    // the yaml separator does not apply to a toml or dotenv file, and `=` does not apply to yaml
    assert!(diff_values("config.toml", &format!("password: {value}")).is_empty());
    assert!(diff_values(".env.local", &format!("PASSWORD: {value}")).is_empty());
    assert!(diff_values("config.yaml", &format!("password = {value}")).is_empty());
}

#[test]
fn prose_after_a_password_label_is_not_a_password() {
    let sentences = [
        "Keyring: stores the value in the OS keychain; it is never written to disk.",
        "Use the value from the team vault (see section 4, not the README).",
        "Rotate this every 90 days and keep it out of shell history!",
    ];
    // the prose check precedes the strength score, which would otherwise report these
    assert!(
        sentences
            .iter()
            .any(|sentence| password::is_strong_password(sentence.as_bytes()))
    );
    for sentence in sentences {
        for (path, text) in [
            ("docs/contract.md", format!("- password: `{sentence}`")),
            ("config.yaml", format!("password: \"{sentence}\"")),
            ("config.json", format!("{{\"password\": \"{sentence}\"}}")),
        ] {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
            assert_eq!(text_hits(&text), 0, "{text}");
        }
    }

    // short messages with whitespace never take the widened branches
    for message in ["Too short.", "Retry now!", "Try again?"] {
        for (path, text) in literal_forms(message) {
            assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        }
    }
}

/// whether `value`'s shortest repeating period is at most `max_period` bytes, checked
/// independently of the production code as a precondition on the generated fixtures below.
fn shortest_period_at_most(value: &str, max_period: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=max_period.min(bytes.len())).any(|period| {
        bytes
            .iter()
            .enumerate()
            .all(|(index, &byte)| byte == bytes[index % period])
    })
}

/// concern codex-cl-password-001: an unquoted `KEY=value` shell word is a concrete literal only
/// on a shell/env/config surface or the pathless one, and a dotted identifier chain (`cfg.pw1_x`)
/// is never a literal on any surface, even one that otherwise qualifies.
#[test]
fn unquoted_key_equals_value_literal_status_is_gated_by_file_type_and_expression_shape() {
    let mut prng = Prng(0x1F83_D9AB_FB41_BD6B);

    // reviewer case 1: a dotted identifier reference, no spaces around `=`. python and js are not
    // shell-word surfaces, so this was already clean by the surface gate alone.
    for (path, text) in [
        ("settings.py", "password=cfg.pw1_x".to_owned()),
        ("app.js", "password=cfg.pw1_x;".to_owned()),
    ] {
        assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        assert_eq!(text_hits(&text), 0, "{text}");
    }

    // the same dotted value on a surface that otherwise qualifies as a shell word (deploy.sh, and
    // pathless) is still not a literal: the expression-shape veto applies on any surface. "cfg" and
    // "pw1_x" are too short/mixed to trip the identifier-label veto, so this exercises the new
    // dotted-chain check specifically, not a different one.
    for (path, text) in [
        ("deploy.sh", "password=cfg.pw1_x".to_owned()),
        ("app.env", "password=cfg.pw1_x".to_owned()),
    ] {
        assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
    }

    // reviewer case: a lowercase+digit generated identifier is clean in python (surface gate) but
    // reported on a shell script, a dotenv file and the pathless surface when it is strong enough
    // (12+ interleaved bytes, the lowercase-branch shape).
    let value = interleaved(&mut prng, 14, false);
    let text = format!("password={value}");
    assert!(diff_values("settings.py", &text).is_empty(), "{text}");
    for path in ["deploy.sh", "app.env"] {
        assert_eq!(
            diff_values(path, &text),
            vec![value.as_bytes().to_vec()],
            "{path}: {text}"
        );
    }
    assert_eq!(text_hits(&text), 1, "pathless surface: {text}");

    // a value the capture had to stop before a call/index/statement-end token is an expression,
    // even though it would otherwise satisfy the short 4-class literal branch.
    let short_four_class = cycled(&mut prng, &[UPPER, LOWER, DIGITS, SPECIAL], 8);
    for suffix in ["(", ")", "[", "]"] {
        let text = format!("password={short_four_class}{suffix}");
        assert!(diff_values("deploy.sh", &text).is_empty(), "{text}");
    }
    // on a shell-evaluated surface `;` separates commands, so the word before it stays a literal
    let text = format!("password={short_four_class};cmd");
    for path in ["deploy.sh", "app.env"] {
        assert_eq!(
            diff_values(path, &text),
            vec![short_four_class.as_bytes().to_vec()],
            "{path}: {text}"
        );
    }
    assert_eq!(text_hits(&text), 1, "pathless surface: {text}");
    // the same value with nothing following it is a literal on a qualifying surface
    assert_eq!(
        diff_values("deploy.sh", &format!("password={short_four_class}")),
        vec![short_four_class.as_bytes().to_vec()]
    );
}

/// concern codex-cl-password-001, finding 2: a double-quoted shell value containing an unescaped
/// `$` or a backtick requires shell evaluation and is never a literal on a shell/env surface or
/// the pathless one; a backtick pair is command substitution (or a template) and is never a
/// literal at all. python keeps today's behavior: `$` inside a double-quoted string is literal
/// text there, so the same shape is still reported.
#[test]
fn shell_evaluated_double_quote_and_backtick_forms_are_not_literals() {
    for (path, text) in [
        ("deploy.sh", r#"DB_PASSWORD="pre$CFG9_x""#.to_owned()),
        ("deploy.sh", "DB_PASSWORD=`cat</pw1`".to_owned()),
    ] {
        assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
        assert_eq!(text_hits(&text), 0, "{text}");
    }

    // control: the same shape but single-quoted stays literal in shell files, since single quotes
    // block all shell expansion.
    let mut prng = Prng(0x9E96_9C40_7B4A_20E1);
    let ten_byte_four_class = cycled(&mut prng, &[UPPER, LOWER, DIGITS, SPECIAL], 10);
    assert_eq!(
        diff_values("deploy.sh", &format!("DB_PASSWORD='{ten_byte_four_class}'")),
        vec![ten_byte_four_class.as_bytes().to_vec()]
    );

    // documented today's behavior: python does not expand `$` inside a double-quoted string, so
    // the shell-surface rejection above does not apply there and the value is still reported.
    let py_value = format!("{}$", cycled(&mut prng, &[UPPER, LOWER, DIGITS], 7));
    assert_eq!(
        diff_values("settings.py", &format!("password = \"{py_value}\"")),
        vec![py_value.as_bytes().to_vec()]
    );

    // decision 3 scopes the double-quote `$`/backtick rejection to a *shell-evaluated* surface
    // (shell scripts, dotenv, Dockerfile, Makefile, pathless), narrower than decision 1's
    // shell-word surface: YAML, INI and TOML are declarative formats no shell ever parses, so a
    // double-quoted value there keeps today's quote handling even though the same file admits the
    // unquoted `KEY=value` case.
    let config_value = format!("{}$", cycled(&mut prng, &[UPPER, LOWER, DIGITS], 7));
    for (path, text) in [
        ("config.yaml", format!("password: \"{config_value}\"")),
        ("config.toml", format!("password = \"{config_value}\"")),
        ("app.ini", format!("password = \"{config_value}\"")),
    ] {
        assert_eq!(
            diff_values(path, &text),
            vec![config_value.as_bytes().to_vec()],
            "{path}: {text}"
        );
    }
    // the identical shape on an actual shell-evaluated surface, or pathless, is still not a
    // literal.
    for (path, text) in [
        ("deploy.sh", format!("password=\"{config_value}\"")),
        (".env", format!("password=\"{config_value}\"")),
    ] {
        assert!(diff_values(path, &text).is_empty(), "{path}: {text}");
    }
    assert_eq!(
        text_hits(&format!("password=\"{config_value}\"")),
        0,
        "{config_value}"
    );
}

#[test]
fn short_period_repetitions_stay_clean_and_diverse_interleaving_is_still_reported() {
    let mut prng = Prng(0x1234_5678_9ABC_DEF0);

    // 12-24 byte values whose shortest period is 1-4 bytes are short-period repetitions, not
    // generated passwords, whatever their length.
    for period in 1..=4 {
        for len in [12, 13, 16, 20, 24] {
            let value = periodic_value(&mut prng, period, len);
            assert!(
                shortest_period_at_most(&value, 4),
                "period {period} len {len}: {value}"
            );
            for (path, text) in literal_forms(&value)
                .into_iter()
                .chain(config_forms(&value))
            {
                assert!(
                    diff_values(path, &text).is_empty(),
                    "period {period} len {len} {path}: {text}"
                );
            }
        }
    }

    // 8-11 byte values whose block alone spans all four character classes: without the period
    // guard the four-class branch would report these on class diversity alone.
    for period in 1..=4 {
        for len in 8..=11 {
            let value = periodic_class_value(&mut prng, period, len);
            assert!(
                shortest_period_at_most(&value, 4),
                "period {period} len {len}: {value}"
            );
            for (path, text) in literal_forms(&value)
                .into_iter()
                .chain(config_forms(&value))
            {
                assert!(
                    diff_values(path, &text).is_empty(),
                    "period {period} len {len} {path}: {text}"
                );
            }
        }
    }

    // control: a generated 12+ byte interleaved value with at least six distinct bytes and no
    // short period is still reported, so the new floor does not blanket-suppress the branch.
    let control = interleaved(&mut prng, 20, false);
    let distinct: HashSet<_> = control.bytes().collect();
    assert!(distinct.len() >= 6, "{control}");
    assert!(!shortest_period_at_most(&control, 4), "{control}");
    for (path, text) in literal_forms(&control)
        .into_iter()
        .chain(config_forms(&control))
    {
        assert_eq!(
            diff_values(path, &text),
            vec![control.as_bytes().to_vec()],
            "{path}: {text}"
        );
    }
}
