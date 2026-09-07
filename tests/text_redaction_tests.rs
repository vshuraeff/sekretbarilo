use sekretbarilo::config::{self, ProjectConfig, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, Rule, RuleAllowlist, compile_rules};

const AWS_KEY: &str = "AKIAIOSFODNN7ABCDEFG";
const PASSWORD: &str = "Kj8#mP2!xQ9vL4nR";

fn defaults(public: bool) -> (CompiledScanner, CompiledAllowlist) {
    let rules = sekretbarilo::scanner::rules::load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let mut allowlist = config::build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    allowlist.detect_public_keys = public;
    (scanner, allowlist)
}

fn rule(id: &str, regex: &str, keyword: &str, entropy: Option<f64>) -> Rule {
    Rule {
        id: id.into(),
        description: id.into(),
        regex_pattern: regex.into(),
        secret_group: 1,
        secret_groups: Vec::new(),
        keywords: vec![keyword.into()],
        entropy_threshold: entropy,
        allowlist: RuleAllowlist::default(),
    }
}

fn custom(rules: Vec<Rule>) -> (CompiledScanner, CompiledAllowlist) {
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    (scanner, allowlist)
}

#[test]
fn clean_text_and_line_endings_are_identical() {
    let (scanner, allowlist) = defaults(false);
    for text in [
        "",
        "host = localhost\nport = 5432\n",
        "текст\r\nκόσμος\rfin",
    ] {
        assert!(scan_text(text, &scanner, &allowlist).is_empty());
        assert_eq!(redact_text(text, &scanner, &allowlist), text);
    }
}

#[test]
fn repeated_values_have_distinct_exact_ranges() {
    let (scanner, allowlist) = defaults(false);
    let text = format!("first={AWS_KEY}; second={AWS_KEY}");
    let matches = scan_text(&text, &scanner, &allowlist);
    assert_eq!(matches.len(), 2);
    assert_eq!(&text[matches[0].range.clone()], AWS_KEY);
    assert_eq!(&text[matches[1].range.clone()], AWS_KEY);
    assert!(matches[0].range.end < matches[1].range.start);
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "first=[REDACTED]; second=[REDACTED]"
    );
}

#[test]
fn several_secrets_preserve_surrounding_unicode_and_crlf() {
    let (scanner, allowlist) = defaults(false);
    let text = format!("ключ={AWS_KEY}\r\npassword = '{PASSWORD}'\r\nконец\n");
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "ключ=[REDACTED]\r\npassword = '[REDACTED]'\r\nконец\n"
    );
}

#[test]
fn captures_are_used_instead_of_matching_surrounding_text() {
    let (scanner, allowlist) = custom(vec![rule(
        "capture",
        r"credential=([A-Z0-9]+);",
        "credential",
        None,
    )]);
    assert_eq!(
        redact_text("before credential=ABCDE12345; after", &scanner, &allowlist),
        "before credential=[REDACTED]; after"
    );
}

#[test]
fn overlapping_rules_are_merged_and_adjacent_values_remain_distinct() {
    let (scanner, allowlist) = custom(vec![
        rule("first", r"(ABCDEF)", "abc", None),
        rule("second", r"(DEFGHI)", "def", None),
        rule("third", r"(KLM)", "klm", None),
        rule("fourth", r"(NOP)", "nop", None),
    ]);
    assert_eq!(scan_text("ABCDEFGHI KLMNOP", &scanner, &allowlist).len(), 4);
    assert_eq!(
        redact_text("ABCDEFGHI KLMNOP", &scanner, &allowlist),
        "[REDACTED] [REDACTED][REDACTED]"
    );
}

#[test]
fn multiline_custom_capture_retains_every_cr_and_lf() {
    let (scanner, allowlist) = custom(vec![rule("multiline", r"(?s)blob=\[(.+?)\]", "blob", None)]);
    let text = "начало blob=[秘密\r\nαβγ\nκλειδί\rfin] τέλος";
    let matches = scan_text(text, &scanner, &allowlist);
    assert_eq!(&text[matches[0].range.clone()], "秘密\r\nαβγ\nκλειδί\rfin");
    assert_eq!(
        redact_text(text, &scanner, &allowlist),
        "начало blob=[[REDACTED]\r\n\n\r] τέλος"
    );
}

#[test]
fn anchored_custom_rules_match_each_later_line_with_lf_and_crlf() {
    for pattern in [r"^TOKEN=([A-Z0-9]+)$", r"\ATOKEN=([A-Z0-9]+)\z"] {
        let (scanner, allowlist) = custom(vec![rule("anchored", pattern, "token", None)]);
        for ending in ["\n", "\r\n", "\r"] {
            let text = format!("before{ending}TOKEN=AB12CD34{ending}TOKEN=EF56GH78{ending}after");
            let matches = scan_text(&text, &scanner, &allowlist);
            assert_eq!(matches.len(), 2, "{pattern:?} with {ending:?}");
            assert_eq!(&text[matches[0].range.clone()], "AB12CD34");
            assert_eq!(&text[matches[1].range.clone()], "EF56GH78");
            assert_eq!(
                redact_text(&text, &scanner, &allowlist),
                format!("before{ending}TOKEN=[REDACTED]{ending}TOKEN=[REDACTED]{ending}after")
            );
        }
    }
}

#[test]
fn anchored_lines_and_multiline_custom_captures_are_both_detected() {
    let (scanner, allowlist) = custom(vec![
        rule("anchored", r"^TOKEN=([A-Z0-9]+)$", "token", None),
        rule("multiline", r"(?s)blob=\[(.+?)\]", "blob", None),
        rule(
            "cross-line-prefix",
            r"credential=\s*([A-Z0-9]+)",
            "credential",
            None,
        ),
    ]);
    let text =
        "before\r\nTOKEN=AB12CD34\r\nblob=[秘密\r\nκλειδί]\r\ncredential=\r\nEF56GH78\r\nafter";
    assert_eq!(scan_text(text, &scanner, &allowlist).len(), 3);
    assert_eq!(
        redact_text(text, &scanner, &allowlist),
        "before\r\nTOKEN=[REDACTED]\r\nblob=[[REDACTED]\r\n]\r\ncredential=\r\n[REDACTED]\r\nafter"
    );
}

#[test]
fn matches_found_in_both_line_and_field_scans_are_returned_once() {
    let (scanner, allowlist) = custom(vec![rule("token", r"TOKEN=([A-Z0-9]+)", "token", None)]);
    assert_eq!(
        scan_text("before\nTOKEN=AB12CD34\nafter", &scanner, &allowlist).len(),
        1
    );
}

#[test]
fn key_headers_inside_broader_custom_captures_expand_to_the_footer() {
    for (label, public) in [("RSA PRIVATE KEY", false), ("PGP PUBLIC KEY BLOCK", true)] {
        for suffix in ["", " annotation"] {
            let pattern = format!("(prefix -----BEGIN {label}-----{suffix})");
            let (scanner, mut allowlist) =
                custom(vec![rule("broad-header", &pattern, "prefix", None)]);
            allowlist.detect_public_keys = public;
            let text = format!(
                "before prefix -----BEGIN {label}-----{suffix}\r\nbody\r\n-----END {label}----- after"
            );
            assert_eq!(
                redact_text(&text, &scanner, &allowlist),
                "before [REDACTED]\r\n\r\n after"
            );
            let truncated = format!("before prefix -----BEGIN {label}-----{suffix}\r\nbody");
            assert_eq!(
                redact_text(&truncated, &scanner, &allowlist),
                "before [REDACTED]\r\n"
            );
        }
    }
}

#[test]
fn byte_regex_captures_expand_to_whole_utf8_characters() {
    let (scanner, allowlist) = custom(vec![rule("byte", r"(?-u:(\xA9))", "é", None)]);
    let text = "préfixe";
    assert_eq!(scan_text(text, &scanner, &allowlist)[0].range, 2..4);
    assert_eq!(redact_text(text, &scanner, &allowlist), "pr[REDACTED]fixe");
}

#[test]
fn value_allowlists_apply_but_global_and_rule_paths_do_not() {
    let mut detector = rule("value", r"token=([A-Z0-9]+)", "token", None);
    detector.allowlist.regexes = vec!["^ALLOWED123$".into()];
    detector.allowlist.paths = vec![".*".into()];
    let rules = vec![detector];
    let scanner = compile_rules(&rules).unwrap();
    let mut config = ProjectConfig::default();
    config.allowlist.paths = vec![".*".into()];
    let allowlist = config::build_allowlist(&config, &rules).unwrap();
    assert_eq!(
        redact_text("token=ALLOWED123 token=ABCDE12345", &scanner, &allowlist),
        "token=ALLOWED123 token=[REDACTED]"
    );
}

#[test]
fn text_mode_has_no_documentation_entropy_bonus() {
    let (scanner, allowlist) = custom(vec![rule(
        "entropy",
        r"token=([A-Z0-9]+)",
        "token",
        Some(3.5),
    )]);
    let text = "token=AB12CD34EF56GH78IJ90";
    let file = DiffFile {
        path: "README.md".into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: text.as_bytes().to_vec(),
        }],
    };
    assert!(scan(&[file], &scanner, &allowlist).is_empty());
    assert_eq!(redact_text(text, &scanner, &allowlist), "token=[REDACTED]");
}

#[test]
fn entropy_threshold_and_global_floor_remain_effective() {
    let (scanner, mut allowlist) = custom(vec![rule(
        "entropy",
        r"token=([A-Z0-9]+)",
        "token",
        Some(3.5),
    )]);
    let text = "token=AAAAAAAAAAAAAAAAAAAA token=AB12CD34EF56GH78IJ90";
    assert_eq!(
        redact_text(text, &scanner, &allowlist),
        "token=AAAAAAAAAAAAAAAAAAAA token=[REDACTED]"
    );
    allowlist.entropy_threshold_override = Some(5.0);
    assert_eq!(redact_text(text, &scanner, &allowlist), text);
}

#[test]
fn password_heuristic_and_variable_exclusions_remain_effective() {
    let (scanner, allowlist) = defaults(false);
    let text =
        format!("password = 'password'\npassword = '${{PASSWORD}}'\npassword = '{PASSWORD}'");
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "password = 'password'\npassword = '${PASSWORD}'\npassword = '[REDACTED]'"
    );
}

#[test]
fn context_filters_are_limited_to_each_matching_line() {
    let (scanner, allowlist) = defaults(false);
    let text = format!(
        "{{{{ template }}}}\npassword = '{PASSWORD}'\nchecksum\napi_key = '0123456789abcdef0123456789abcdef'"
    );
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "{{ template }}\npassword = '[REDACTED]'\nchecksum\napi_key = '[REDACTED]'"
    );
}

#[test]
fn unicode_stopwords_do_not_panic_after_a_nonboundary_match() {
    let (scanner, _) = custom(vec![rule("unicode", r"value=(.+)", "value", Some(0.0))]);
    let allowlist = CompiledAllowlist::new(&[], &["é".into()], None, &[], false).unwrap();
    assert!(!allowlist.contains_stopword("aébA1cD2fG3hJ4kL5".as_bytes()));
    assert!(allowlist.contains_stopword("aéb é".as_bytes()));
    assert_eq!(
        redact_text("value=aébA1cD2fG3hJ4kL5", &scanner, &allowlist),
        "value=[REDACTED]"
    );
    assert_eq!(
        redact_text("value=aéb éA1cD2fG3hJ4kL5 é", &scanner, &allowlist),
        "value=aéb éA1cD2fG3hJ4kL5 é"
    );
}

#[test]
fn complete_private_blocks_are_hidden_through_the_corresponding_footer() {
    let (scanner, allowlist) = defaults(false);
    for label in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let text = format!("prefix -----BEGIN {label}-----\r\nbody\n-----END {label}----- suffix");
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            "prefix [REDACTED]\r\n\n suffix",
            "{label}"
        );
    }
}

#[test]
fn unrelated_key_footer_does_not_end_redaction() {
    let (scanner, allowlist) = defaults(false);
    let text = "-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END EC PRIVATE KEY-----\nmore\n-----END RSA PRIVATE KEY-----\nafter";
    assert_eq!(
        redact_text(text, &scanner, &allowlist),
        "[REDACTED]\n\n\n\n\nafter"
    );
}

#[test]
fn unterminated_private_block_hides_the_rest_of_the_field() {
    let (scanner, allowlist) = defaults(false);
    for label in ["RSA PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
        let text = format!("before\n-----BEGIN {label}-----\nbody\r\nremaining output");
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            "before\n[REDACTED]\n\r\n"
        );
    }
}

#[test]
fn repeated_key_headers_and_overlapping_embedded_secrets_are_merged() {
    let (scanner, allowlist) = defaults(false);
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n{AWS_KEY}\n-----END PRIVATE KEY-----\nafter"
    );
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "[REDACTED]\n\n\n\nafter"
    );
}

#[test]
fn public_blocks_are_optional_but_unterminated_blocks_never_suppress_later_secrets() {
    for label in ["PUBLIC KEY", "RSA PUBLIC KEY", "PGP PUBLIC KEY BLOCK"] {
        let (scanner, allowlist) = defaults(false);
        let closed = format!("-----BEGIN {label}-----\n{AWS_KEY}\n-----END {label}-----\nafter");
        assert_eq!(redact_text(&closed, &scanner, &allowlist), closed);
        let unclosed = format!("-----BEGIN {label}-----\n{AWS_KEY}\nafter");
        assert_eq!(
            redact_text(&unclosed, &scanner, &allowlist),
            format!("-----BEGIN {label}-----\n[REDACTED]\nafter")
        );
        let (scanner, allowlist) = defaults(true);
        assert_eq!(
            redact_text(&closed, &scanner, &allowlist),
            "[REDACTED]\n\n\nafter"
        );
        assert_eq!(
            redact_text(&unclosed, &scanner, &allowlist),
            "[REDACTED]\n\n"
        );
    }
}

#[test]
fn openssh_detection_does_not_suppress_the_following_line() {
    let (scanner, allowlist) = defaults(false);
    let public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABCDEFGH12345678abcdefgh owner@host";
    let text = format!("{public}\n{AWS_KEY}");
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        format!("{public}\n[REDACTED]")
    );
    let (scanner, allowlist) = defaults(true);
    assert_eq!(
        redact_text(&text, &scanner, &allowlist),
        "[REDACTED] owner@host\n[REDACTED]"
    );
}
