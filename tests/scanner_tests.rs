// comprehensive unit tests for the scanner module (phase 8.2)
//
// covers:
//   - all tier-1 prefix-based rules
//   - tier-2 context-dependent rules
//   - tier-3 generic catch-all rule
//   - entropy calculation accuracy
//   - subthreshold hash controls and strict entropy detection

mod common;

use sekretbarilo::config;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, scan};
use sekretbarilo::scanner::entropy;
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

// -- helpers --

fn default_scanner_and_allowlist() -> (
    sekretbarilo::scanner::rules::CompiledScanner,
    sekretbarilo::config::allowlist::CompiledAllowlist,
) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();
    (scanner, al)
}

fn make_file(path: &str, lines: Vec<(usize, &[u8])>) -> DiffFile {
    DiffFile {
        path: path.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: lines
            .into_iter()
            .map(|(num, content)| AddedLine {
                line_number: num,
                content: content.to_vec(),
            })
            .collect(),
    }
}

fn scan_line(path: &str, line: &[u8]) -> Vec<Finding> {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(path, vec![(1, line)]);
    scan(&[file], &scanner, &al)
}

fn assert_detected(path: &str, line: &[u8], expected_rule: &str) {
    let findings = scan_line(path, line);
    assert!(
        findings.iter().any(|f| f.rule_id == expected_rule),
        "expected rule '{}' to trigger on line {:?}, got findings: {:?}",
        expected_rule,
        String::from_utf8_lossy(line),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

fn assert_not_detected(path: &str, line: &[u8]) {
    let findings = scan_line(path, line);
    assert!(
        findings.is_empty(),
        "expected no findings for line {:?}, got: {:?}",
        String::from_utf8_lossy(line),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

mod high_entropy_values {
    use super::*;
    use sekretbarilo::config::allowlist::CompiledAllowlist;
    use sekretbarilo::scanner::engine::{redact_text, scan_text};
    use sekretbarilo::scanner::rules::CompiledScanner;

    const RULE: &str = "generic-high-entropy-value";

    fn distinct_token(len: usize) -> String {
        (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .take(len)
            .map(char::from)
            .collect()
    }

    fn balanced_hex() -> String {
        (0..32)
            .map(|i| char::from_digit(i % 16, 16).unwrap())
            .collect()
    }

    fn scanner_and_key_allowlist(keys: &[&str]) -> (CompiledScanner, CompiledAllowlist) {
        let rules = load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let config = config::ProjectConfig {
            allowlist: config::AllowlistConfig {
                rules: vec![config::AllowlistRuleOverride {
                    id: RULE.to_string(),
                    regexes: vec![],
                    paths: vec![],
                    keys: keys.iter().map(|key| (*key).to_string()).collect(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let allowlist = config::build_allowlist(&config, &rules).unwrap();
        (scanner, allowlist)
    }

    fn assert_values(
        path: &str,
        input: &str,
        expected: &[&str],
        scanner: &CompiledScanner,
        al: &CompiledAllowlist,
    ) {
        let file = make_file(
            path,
            input
                .lines()
                .enumerate()
                .map(|(i, line)| (i + 1, line.as_bytes()))
                .collect(),
        );
        let findings = scan(&[file], scanner, al);
        let values: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == RULE)
            .map(|finding| finding.matched_value.as_slice())
            .collect();
        let expected_bytes: Vec<_> = expected.iter().map(|value| value.as_bytes()).collect();
        assert_eq!(values, expected_bytes, "diff input: {input:?}");

        let matches = scan_text(input, scanner, al);
        let ranges: Vec<_> = matches
            .iter()
            .filter(|found| found.rule_id == RULE)
            .map(|found| found.range.clone())
            .collect();
        let mut offset = 0;
        let expected_ranges: Vec<_> = expected
            .iter()
            .map(|value| {
                let start = offset + input[offset..].find(value).unwrap();
                offset = start + value.len();
                start..offset
            })
            .collect();
        assert_eq!(ranges, expected_ranges, "text input: {input:?}");
    }

    #[test]
    fn assignments_and_bare_tokens_have_exact_complete_captures() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = distinct_token(32);
        assert_eq!(entropy::shannon_entropy(value.as_bytes()), 5.0);
        for input in [
            format!("ALPHA={value}"),
            format!("export ALPHA={value}"),
            format!("\tALPHA : {value}\r\n"),
            format!("name = \"{value}\";"),
            format!("name = '{value}'"),
            format!("{{\"name\": \"{value}\"}}"),
            format!("{{\"arbitrary mapping key\":\"{value}\",\"other\":\"short\"}}"),
            format!("'{value}'"),
            format!("\t\"{value}\" \r\n"),
            format!(" \t{value}\t "),
            format!("before\n{value}\nafter"),
        ] {
            assert_values("config.txt", &input, &[&value], &scanner, &al);
        }
        for value in [
            format!("{value}+/=="),
            format!("{value}-_="),
            format!("{value}/+="),
        ] {
            for input in [
                value.clone(),
                format!("'{value}'"),
                format!("ALPHA={value}"),
            ] {
                assert_values("config.txt", &input, &[&value], &scanner, &al);
            }
        }
    }

    #[test]
    fn entropy_key_capture_indices_match_configured_value_groups() {
        let (scanner, _) = default_scanner_and_allowlist();
        let rule = scanner.rules.iter().find(|rule| rule.id == RULE).unwrap();
        let captures: Vec<_> = rule
            .regex
            .capture_names()
            .enumerate()
            .filter_map(|(index, name)| name.map(|name| (name, index)))
            .collect();
        assert_eq!(
            captures,
            vec![
                ("entropy_reference", 1),
                ("entropy_bare_double", 2),
                ("entropy_bare_single", 3),
                ("entropy_url", 4),
                ("entropy_key", 5),
                ("entropy_double", 6),
                ("entropy_single", 7),
                ("entropy_bracket", 8),
                ("entropy_unquoted", 9),
                ("entropy_bare", 10),
            ]
        );

        let value_indices: Vec<_> = captures
            .iter()
            .filter(|(name, _)| *name != "entropy_key")
            .map(|(_, index)| *index)
            .collect();
        let configured_groups: Vec<_> = std::iter::once(rule.secret_group)
            .chain(rule.secret_groups.iter().copied())
            .collect();
        assert_eq!(configured_groups, value_indices);
    }

    #[test]
    fn key_allowlist_suppresses_only_matching_assignment_keys() {
        let (scanner, al) = scanner_and_key_allowlist(&["TMPDIR"]);
        let allowed = distinct_token(32);
        let disallowed: String = allowed.chars().rev().collect();

        for input in [
            format!("TMPDIR={allowed}"),
            format!("export TMPDIR={allowed}"),
            format!("TMPDIR:{allowed}"),
            format!("\"TMPDIR\":{allowed}"),
            format!("'TMPDIR':{allowed}"),
            format!("\t TMPDIR = {allowed}\r\n"),
        ] {
            assert_values("config.txt", &input, &[], &scanner, &al);
        }

        for (input, expected) in [
            (
                format!("TMPDIR={allowed},DISALLOWED={disallowed}"),
                disallowed.as_str(),
            ),
            (
                format!("DISALLOWED={disallowed},TMPDIR={allowed}"),
                disallowed.as_str(),
            ),
        ] {
            assert_values("config.txt", &input, &[expected], &scanner, &al);
        }
    }

    #[test]
    fn key_allowlist_does_not_affect_values_without_a_matching_assignment_key() {
        let (scanner, mut al) = scanner_and_key_allowlist(&["TMPDIR"]);
        let token = distinct_token(24);
        let inside_value = format!("{}TMPDIR{}", &token[..12], &token[12..]);
        assert!(entropy::shannon_entropy(inside_value.as_bytes()) >= 4.0);
        assert_values(
            "config.txt",
            &format!("OTHER={inside_value}"),
            &[&inside_value],
            &scanner,
            &al,
        );

        let url = format!("https://{}", distinct_token(13));
        assert!(entropy::shannon_entropy(url.as_bytes()) >= 4.0);
        assert_values("config.txt", &token, &[&token], &scanner, &al);
        // q1: the 0.7.0 exemption layer exempts this credential-free url.
        assert_values("config.txt", &url, &[], &scanner, &al);
        assert_values("config.txt", &format!("TMPDIR={url}"), &[], &scanner, &al);
        al.exemption_layer = false;
        assert_values("config.txt", &url, &[&url], &scanner, &al);
        assert_values("config.txt", &format!("TMPDIR={url}"), &[], &scanner, &al);
    }

    #[test]
    fn key_allowlist_never_suppresses_named_secret_rules() {
        let (scanner, al) = scanner_and_key_allowlist(&["TMPDIR"]);
        let input = b"TMPDIR=AKIAIOSFODNN7REALKEY";
        let findings = scan(&[make_file("config.txt", vec![(1, input)])], &scanner, &al);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "aws-access-key-id"),
            "named AWS rule was unexpectedly suppressed: {findings:?}"
        );
    }

    #[test]
    fn adjacent_fields_escaped_quotes_and_syntax_are_preserved() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = distinct_token(32);
        let double = format!("{value}\\\"suffix");
        let single = format!("{value}\\'suffix");
        let doubled = format!("{value}''suffix");
        let unquoted = format!("{value}\\;suffix");
        for (input, expected) in [
            (
                format!("{{\"key\\\"with space\":\"{double}\",\"next\":\"{value}\"}}\r\n"),
                vec![double.as_str(), value.as_str()],
            ),
            (
                format!("'key with space' = '{single}'; next='{doubled}'"),
                vec![single.as_str(), doubled.as_str()],
            ),
            (
                format!("ALPHA={unquoted};BRAVO={value},CHARLIE={value}"),
                vec![unquoted.as_str(), value.as_str(), value.as_str()],
            ),
        ] {
            assert_values("config.txt", &input, &expected, &scanner, &al);
        }
    }

    #[test]
    fn punctuated_unquoted_assignments_capture_complete_values() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(24);
        for punctuation in
            (b'!'..=b'~').filter(|byte| byte.is_ascii_punctuation() && !b"\"'`".contains(byte))
        {
            let value = format!("{}{}{}", &token[..7], char::from(punctuation), &token[7..]);
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            assert_values(
                "config.txt",
                &format!("SESSION_SECRET={value}"),
                &[&value],
                &scanner,
                &al,
            );
        }
        for delimiter in [",", ";", ")", "]", "}", ">", ")};"] {
            assert_values(
                "config.txt",
                &format!("ALPHA={token}{delimiter}\r\n"),
                &[&token],
                &scanner,
                &al,
            );
        }
        let raw_crlf = format!("ALPHA={token}\r");
        let file = make_file("config.txt", vec![(1, raw_crlf.as_bytes())]);
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE);
        assert_eq!(findings[0].matched_value, token.as_bytes());
    }

    #[test]
    fn punctuated_bare_lines_capture_complete_values() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(24);
        for punctuation in
            (b'!'..=b'~').filter(|byte| byte.is_ascii_punctuation() && !b"\"'`=".contains(byte))
        {
            let value = format!("{}{}{}", &token[..7], char::from(punctuation), &token[7..]);
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            for input in [
                value.clone(),
                format!("\t'{value}' \r\n"),
                format!("\"{value}\""),
            ] {
                let expected = if punctuation == b':' && input == value {
                    vec![]
                } else {
                    vec![value.as_str()]
                };
                assert_values("config.txt", &input, &expected, &scanner, &al);
            }
        }
    }

    #[test]
    fn bare_url_and_colon_boundary_preserve_complete_values() {
        let (scanner, mut al) = default_scanner_and_allowlist();
        let url = format!("https://{}", distinct_token(13));
        assert_eq!(url.len(), 21);
        assert!(entropy::shannon_entropy(url.as_bytes()) >= 4.0);
        let opaque = distinct_token(url.len());
        assert_values("config.txt", &opaque, &[&opaque], &scanner, &al);
        // q1: the 0.7.0 exemption layer exempts this credential-free url.
        assert_values("config.txt", &url, &[], &scanner, &al);
        al.exemption_layer = false;
        assert_values("config.txt", &url, &[&url], &scanner, &al);
        al.exemption_layer = true;
        let value = distinct_token(24);
        let assignment = format!("ALPHA:{value}");
        assert_values("config.txt", &assignment, &[&value], &scanner, &al);
        assert_values(
            "config.txt",
            &format!("ALPHA: {value}"),
            &[&value],
            &scanner,
            &al,
        );
        let assignment_with_comma = format!("ALPHA:{value},");
        assert_values(
            "config.txt",
            &assignment_with_comma,
            &[&value],
            &scanner,
            &al,
        );
        assert_values(
            "config.txt",
            &format!("\"ALPHA\":\"{value}\""),
            &[&value],
            &scanner,
            &al,
        );
        assert_values("config.txt", &format!("{value}=short"), &[], &scanner, &al);
    }

    mod structural_precedence {
        use super::*;

        fn hash_line() -> String {
            let hash = ["a94a8fe5ccb19ba61", "c4c0873d391e987982fbbd3"].concat();
            assert!(entropy::shannon_entropy(hash.as_bytes()) < 4.0);
            let line = format!("commit:{hash}");
            assert!(entropy::shannon_entropy(line.as_bytes()) >= 4.0);
            line
        }

        #[test]
        fn whole_line_urls_preserve_complete_spans_and_assignment_keys() {
            let (scanner, al) = default_scanner_and_allowlist();
            let (_, mut layer_off) = default_scanner_and_allowlist();
            layer_off.exemption_layer = false;
            let url = format!("https://{}", distinct_token(13));
            assert_eq!(url.len(), 21);
            assert!(entropy::shannon_entropy(url.as_bytes()) >= 4.0);
            for url in [
                url,
                format!("git+ssh.2://{}", distinct_token(13)),
                format!("https://{}?q=x", distinct_token(13)),
            ] {
                let opaque = distinct_token(url.len());
                for (input, expected) in [
                    (url.clone(), "[REDACTED]".to_string()),
                    (format!("\t {url} \r\n"), "\t [REDACTED] \r\n".into()),
                    (format!("\"{url}\""), "\"[REDACTED]\"".into()),
                    (format!("\t'{url}'\r\n"), "\t'[REDACTED]'\r\n".into()),
                    (format!("ALPHA={url}"), "ALPHA=[REDACTED]".into()),
                    (
                        format!("LEFT=short,ALPHA={url}"),
                        "LEFT=short,ALPHA=[REDACTED]".into(),
                    ),
                ] {
                    // q1: the 0.7.0 exemption layer exempts each credential-free url form.
                    assert_values("config.txt", &input, &[], &scanner, &al);
                    assert_eq!(redact_text(&input, &scanner, &al), input);
                    assert_values("config.txt", &input, &[&url], &scanner, &layer_off);
                    assert_eq!(redact_text(&input, &scanner, &layer_off), expected);

                    let opaque_input = input.replace(&url, &opaque);
                    assert_values("config.txt", &opaque_input, &[&opaque], &scanner, &al);
                    assert_eq!(redact_text(&opaque_input, &scanner, &al), expected);
                }
            }
        }

        #[test]
        fn colon_assignments_exclude_keys_and_preserve_complete_output() {
            let (scanner, al) = default_scanner_and_allowlist();
            let value = distinct_token(24);
            for (input, expected) in [
                (format!("ALPHA:{value}"), "ALPHA:[REDACTED]"),
                (format!("ALPHA: {value}"), "ALPHA: [REDACTED]"),
                (format!("\tALPHA:{value}\r\n"), "\tALPHA:[REDACTED]\r\n"),
                (format!("\"ALPHA\":\"{value}\""), "\"ALPHA\":\"[REDACTED]\""),
                (format!("ALPHA:{value},"), "ALPHA:[REDACTED],"),
            ] {
                assert_values("config.txt", &input, &[&value], &scanner, &al);
                assert_eq!(redact_text(&input, &scanner, &al), expected);
            }
        }

        #[test]
        fn keys_do_not_contribute_to_length_or_entropy() {
            let (scanner, al) = default_scanner_and_allowlist();
            let short = distinct_token(19);
            assert!(entropy::shannon_entropy(short.as_bytes()) >= 4.0);
            for input in [format!("long_variable_name:{short}"), "ALPHA:short".into()] {
                assert_values("config.txt", &input, &[], &scanner, &al);
                assert_eq!(redact_text(&input, &scanner, &al), input);
            }
        }

        #[test]
        fn commit_key_does_not_raise_hash_entropy() {
            let (scanner, al) = default_scanner_and_allowlist();
            let input = hash_line();
            assert_values("config.txt", &input, &[], &scanner, &al);
            assert_eq!(redact_text(&input, &scanner, &al), input);
        }

        #[test]
        fn check_file_accepts_subthreshold_hash_after_colon_key() {
            let environment = common::IsolatedEnv::new();
            let file = environment.root().join("config.txt");
            std::fs::write(&file, hash_line()).unwrap();
            let output = environment
                .command()
                .arg("check-file")
                .arg(&file)
                .current_dir(environment.root())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        fn configured_stopwords_do_not_match_assignment_keys() {
            let (scanner, _) = default_scanner_and_allowlist();
            let al = CompiledAllowlist::new(&[], &["test".into()], None, &[], false).unwrap();
            let value = distinct_token(28);
            assert!(!value.to_lowercase().contains("test"));
            let input = format!("test_api_key:{value}");
            assert_values("config.txt", &input, &[&value], &scanner, &al);
            assert_eq!(
                redact_text(&input, &scanner, &al),
                "test_api_key:[REDACTED]"
            );
        }

        #[test]
        fn audit_stopword_in_key_keeps_exactly_one_entropy_finding() {
            let environment = common::IsolatedEnv::new();
            let repo = environment.git_repo();
            let value = distinct_token(28);
            assert!(!value.to_lowercase().contains("test"));
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            std::fs::write(repo.join("config.txt"), format!("test_api_key:{value}")).unwrap();
            let staged = std::process::Command::new("git")
                .args(["add", "config.txt"])
                .env("GIT_CONFIG_GLOBAL", environment.git_config_global())
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(staged.status.success());
            let output = environment
                .command()
                .args(["audit", "--stopword", "test"])
                .current_dir(&repo)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.trim_start().starts_with("rule:"))
                    .collect::<Vec<_>>(),
                ["  rule: generic-high-entropy-value"]
            );
            assert!(stderr.contains("1 secret(s) in 1 file(s)"), "{stderr}");
        }

        #[test]
        fn mixed_case_stopwords_inside_values_remain_suppressed() {
            let (scanner, _) = default_scanner_and_allowlist();
            let al = CompiledAllowlist::new(&[], &["test".into()], None, &[], false).unwrap();
            let token = distinct_token(28);
            let value = format!("{}TeSt{}", &token[..8], &token[8..]);
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            for delimiter in ["=", ":"] {
                let input = format!("ALPHA{delimiter}{value}");
                assert_values("config.txt", &input, &[], &scanner, &al);
                assert_eq!(redact_text(&input, &scanner, &al), input);
            }
        }

        #[test]
        fn anchored_value_allowlist_applies_to_both_assignment_delimiters() {
            let (scanner, _) = default_scanner_and_allowlist();
            let allowed = distinct_token(24);
            let other = distinct_token(28);
            let al = CompiledAllowlist::new(
                &[],
                &[],
                None,
                &[(RULE.into(), vec![format!("^{allowed}$")], vec![])],
                false,
            )
            .unwrap();
            for delimiter in ["=", ":"] {
                let input = format!("ALPHA{delimiter}{allowed}");
                assert_values("config.txt", &input, &[], &scanner, &al);
                assert_eq!(redact_text(&input, &scanner, &al), input);
                let input = format!("ALPHA{delimiter}{other}");
                assert_values("config.txt", &input, &[&other], &scanner, &al);
                assert_eq!(
                    redact_text(&input, &scanner, &al),
                    format!("ALPHA{delimiter}[REDACTED]")
                );
            }
        }

        #[test]
        fn bracket_wrappers_are_symmetric_and_quoted_brackets_are_value_bytes() {
            let (scanner, al) = default_scanner_and_allowlist();
            let value = distinct_token(24);
            let input = format!("ALPHA=[{value}]");
            assert_values("config.txt", &input, &[&value], &scanner, &al);
            assert_eq!(redact_text(&input, &scanner, &al), "ALPHA=[[REDACTED]]");
            let quoted_value = format!("[{value}]");
            let input = format!("ALPHA=\"{quoted_value}\"");
            assert_values("config.txt", &input, &[&quoted_value], &scanner, &al);
            assert_eq!(redact_text(&input, &scanner, &al), "ALPHA=\"[REDACTED]\"");
        }

        #[test]
        fn quoting_distinguishes_standalone_colons_from_assignments() {
            let (scanner, al) = default_scanner_and_allowlist();
            let value = distinct_token(24);
            let rhs = format!("bar{value}");
            let input = format!("foo:{rhs}");
            assert_values("config.txt", &input, &[&rhs], &scanner, &al);
            assert_eq!(redact_text(&input, &scanner, &al), "foo:[REDACTED]");
            let quoted = format!("\"{input}\"");
            assert_values("config.txt", &quoted, &[&input], &scanner, &al);
            assert_eq!(redact_text(&quoted, &scanner, &al), "\"[REDACTED]\"");
            let rhs = format!("prefix:{value}");
            let input = format!("ALPHA={rhs}");
            assert_values("config.txt", &input, &[&rhs], &scanner, &al);
            assert_eq!(redact_text(&input, &scanner, &al), "ALPHA=[REDACTED]");
        }

        #[test]
        fn adjacent_assignments_keep_both_keys_and_ranges() {
            let (scanner, al) = default_scanner_and_allowlist();
            let first = distinct_token(24);
            let second = distinct_token(28);
            let input = format!("A={first},B={second}");
            assert_values("config.txt", &input, &[&first, &second], &scanner, &al);
            assert_eq!(
                redact_text(&input, &scanner, &al),
                "A=[REDACTED],B=[REDACTED]"
            );
        }
    }

    #[test]
    fn length_and_raw_entropy_boundaries_use_complete_values() {
        let (scanner, al) = default_scanner_and_allowlist();
        let short = distinct_token(19);
        let minimum = distinct_token(20);
        let boundary = balanced_hex();
        let below = format!("{}0", &boundary[..31]);
        assert!((entropy::shannon_entropy(short.as_bytes()) - 19_f64.log2()).abs() < 1e-12);
        assert!((entropy::shannon_entropy(minimum.as_bytes()) - 20_f64.log2()).abs() < 1e-12);
        assert_eq!(entropy::shannon_entropy(boundary.as_bytes()), 4.0);
        assert!(entropy::shannon_entropy(below.as_bytes()) < 4.0);
        assert!(entropy::shannon_entropy(below.as_bytes()) >= 2.0);
        for value in [&short, &minimum, &boundary, &below] {
            for input in [
                format!("ALPHA={value}"),
                format!("ALPHA='{value}'"),
                value.clone(),
            ] {
                // q3: the 0.7.0 exemption layer admits eligible hex assignments below 4.0 bits.
                let expected: Vec<_> = if value == &minimum
                    || value == &boundary
                    || (value == &below && input != *value)
                {
                    vec![value.as_str()]
                } else {
                    vec![]
                };
                assert_values("config.txt", &input, &expected, &scanner, &al);
            }
        }
        let diluted = format!("{minimum}{}", "a".repeat(300));
        assert!(entropy::shannon_entropy(diluted.as_bytes()) < 4.0);
        let digits: String = (0..40)
            .map(|index| char::from(b'0' + ((index + 1) % 10) as u8))
            .collect();
        for value in [diluted, digits.clone(), "a".repeat(64)] {
            for input in [
                format!("ALPHA={value}"),
                format!("ALPHA=\"{value}\""),
                value.clone(),
            ] {
                // q3: the 0.7.0 exemption layer also admits this 40-digit hex assignment.
                let expected = if value == digits && input != value {
                    vec![value.as_str()]
                } else {
                    vec![]
                };
                assert_values("config.txt", &input, &expected, &scanner, &al);
            }
        }
        let lower_override = CompiledAllowlist::new(&[], &[], Some(3.0), &[], false).unwrap();
        // q3: the 0.7.0 exemption layer bypass applies independently of the ordinary threshold.
        assert_values(
            "config.txt",
            &format!("ALPHA={below}"),
            &[&below],
            &scanner,
            &lower_override,
        );
        let higher_override = CompiledAllowlist::new(&[], &[], Some(4.5), &[], false).unwrap();
        assert_values(
            "config.txt",
            &format!("ALPHA={minimum}"),
            &[],
            &scanner,
            &higher_override,
        );
        let value = distinct_token(32);
        assert_values(
            "config.txt",
            &format!("ALPHA={value}"),
            &[&value],
            &scanner,
            &higher_override,
        );
    }

    #[test]
    fn names_shapes_and_templates_do_not_exempt_opaque_literals() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = balanced_hex();
        for name in [
            "ALPHA",
            "DB_TOKEN",
            "PATH",
            "MANPATH",
            "LS_COLORS",
            "TERM_SESSION_ID",
            "commit_token",
            "hash",
            "checksum",
        ] {
            for path in ["config.txt", "docs/guide.md"] {
                let input = format!("{name}={value}");
                assert_values(path, &input, &[&value], &scanner, &al);
            }
        }
        for input in [
            format!("{{\"arbitrary mapping key\":\"{value}\",\"checksum\":\"short\"}}"),
            format!("ALPHA={value} # hash checksum"),
            format!("{{{{ reference }}}} ALPHA=\"{value}\""),
            format!("{{\"ref\":\"{{{{ reference }}}}\",\"literal\":\"{value}\"}}"),
            format!("<%= reference %> ALPHA='{value}'"),
            format!("{{{{ 'ALPHA={value}' }}}}"),
            format!("{{{{\"ALPHA\":\"{value}\"}}}}"),
        ] {
            assert_values("docs/guide.md", &input, &[&value], &scanner, &al);
        }
        let alphabetic = distinct_token(32);
        // q4: mixed letters and digits in every segment preserve the opaque-literal pin.
        let token: String = alphabetic
            .bytes()
            .enumerate()
            .map(|(index, byte)| {
                char::from(if index % 4 == 1 {
                    b'0' + (index % 10) as u8
                } else {
                    byte
                })
            })
            .collect();
        for value in [
            format!("/{token}"),
            format!("~/{token}"),
            format!("https://{token}"),
            format!("one:two:three:four:{token}"),
            format!("example_{token}"),
            format!("XXX_{token}"),
            format!(
                "{}-{}-{}-{}-{}",
                &token[..8],
                &token[8..12],
                &token[12..16],
                &token[16..20],
                &token[20..]
            ),
        ] {
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            assert_values(
                "config.txt",
                &format!("PATH={value}"),
                &[&value],
                &scanner,
                &al,
            );
        }
        let word_structured = format!(
            "{}-{}-{}-{}-{}",
            &alphabetic[..8],
            &alphabetic[8..12],
            &alphabetic[12..16],
            &alphabetic[16..20],
            &alphabetic[20..]
        );
        // q4: the 0.7.0 exemption layer exempts the original alphabetic word-structured variant.
        assert_values(
            "config.txt",
            &format!("PATH={word_structured}"),
            &[],
            &scanner,
            &al,
        );
    }

    #[test]
    fn references_whitespace_non_ascii_and_prose_are_outside_eligibility() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        for value in [
            format!("${token}"),
            format!("${{{token}}}"),
            format!("%{token}%"),
            format!("{{{{{token}}}}}"),
            format!("${{var.{token}}}"),
            format!("process.env.{token}"),
            format!("${{LONG_NAME:-{token}}}"),
            format!("{{{{lookup('ALPHA={token}')}}}}"),
            format!("{token} prose"),
            format!("{token}\tmore"),
            format!("{token}é"),
            format!("{token}\\ more"),
            format!("{token}\nmore"),
        ] {
            assert_values(
                "config.txt",
                &format!("ALPHA=\"{value}\""),
                &[],
                &scanner,
                &al,
            );
        }
        for input in [
            format!("{token}=short"),
            format!("ALPHA=${{LONG_NAME:-{token}}}"),
            format!("ALPHA={token}é"),
            format!("ALPHA={token}\\ more"),
            format!("ALPHA=`{token}`"),
            format!("here is {token} in prose"),
            format!("\"{token} with spaces\""),
            "WORD=configuration".into(),
            "GREETING=hello world".into(),
            "NUMBER=12345".into(),
            "PATHLIKE=/usr/local/bin/tooling".into(),
        ] {
            assert_values("config.txt", &input, &[], &scanner, &al);
        }
        // reclassified per g1: opaque call-argument literals are tier-3 candidates (s19b).
        let call_body = format!("BRAVO={token}");
        for input in [
            format!("ALPHA={{{{lookup('{call_body}')}}}}"),
            format!("ALPHA=<%=lookup('{call_body}')%>"),
            format!("{{{{lookup('{call_body}')}}}}"),
        ] {
            assert_values("config.txt", &input, &[&call_body], &scanner, &al);
        }
    }

    #[test]
    fn explicit_stopwords_and_value_allowlists_still_apply() {
        let (scanner, _) = default_scanner_and_allowlist();
        let value = format!("example_{}", distinct_token(32));
        let input = format!("ALPHA={value}");
        let stopword = CompiledAllowlist::new(&[], &["EXAMPLE".into()], None, &[], false).unwrap();
        assert_values("config.txt", &input, &[], &scanner, &stopword);
        let allowed = CompiledAllowlist::new(
            &[],
            &[],
            None,
            &[(RULE.into(), vec![format!("^{value}$")], vec![])],
            false,
        )
        .unwrap();
        assert_values("config.txt", &input, &[], &scanner, &allowed);
        let other: String = distinct_token(32).chars().rev().collect();
        assert_values(
            "config.txt",
            &format!("ALPHA={value};BRAVO={other}"),
            &[&other],
            &scanner,
            &allowed,
        );
    }

    #[test]
    fn cli_and_config_stopwords_suppress_embedded_text_but_defaults_do_not() {
        let environment = common::IsolatedEnv::new();
        let repo = environment.git_repo();
        let token = distinct_token(16);
        let value = format!("example_{token}mystopword{}", token.to_lowercase());
        assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
        let config_path = repo.join(".sekretbarilo.toml");
        std::fs::write(&config_path, "[allowlist]\nstopwords = [\"unrelated\"]\n").unwrap();
        std::fs::write(repo.join("config.py"), format!("ALPHA = '{value}'\n")).unwrap();
        let staged = std::process::Command::new("git")
            .args(["add", "config.py"])
            .env("GIT_CONFIG_GLOBAL", environment.git_config_global())
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(staged.status.success());

        let baseline = environment
            .command()
            .arg("audit")
            .current_dir(&repo)
            .output()
            .unwrap();
        assert_eq!(baseline.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&baseline.stderr).contains(RULE));

        let from_cli = environment
            .command()
            .args(["audit", "--stopword", "MyStopWord"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert_eq!(from_cli.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&from_cli.stderr).contains("0 secret(s) found"));

        std::fs::write(&config_path, "[allowlist]\nstopwords = [\"MyStopWord\"]\n").unwrap();
        let from_config = environment
            .command()
            .arg("audit")
            .current_dir(&repo)
            .output()
            .unwrap();
        assert_eq!(from_config.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&from_config.stderr).contains("0 secret(s) found"));
    }

    #[test]
    fn global_and_rule_paths_and_public_key_suppression_are_preserved() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = distinct_token(32);
        let input = format!("ALPHA={value}");
        let custom = CompiledAllowlist::new(
            &["ignored/".into()],
            &[],
            None,
            &[(RULE.into(), vec![], vec!["safe/".into()])],
            false,
        )
        .unwrap();
        for (path, al) in [
            ("Cargo.lock", &al),
            ("ignored/config.txt", &custom),
            ("safe/config.txt", &custom),
        ] {
            let file = make_file(path, vec![(1, input.as_bytes())]);
            assert!(scan(&[file], &scanner, al).is_empty());
            assert!(
                scan_text(&input, &scanner, al)
                    .iter()
                    .any(|found| found.rule_id == RULE)
            );
        }
        let public = format!("-----BEGIN PUBLIC KEY-----\n{value}\n-----END PUBLIC KEY-----");
        assert_values("key.pem", &public, &[], &scanner, &al);
        let enabled = CompiledAllowlist::new(&[], &[], None, &[], true).unwrap();
        assert_values("key.pem", &public, &[&value], &scanner, &enabled);
    }

    #[test]
    fn unquoted_quote_and_backtick_bytes_keep_complete_value_ranges() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let cases = [
            format!("{}\"{}", &token[..2], &token[2..]),
            format!("{}'{}", &token[..30], &token[30..]),
            format!("{}{}{}", &token[..12], '`', &token[12..]),
            format!("{}\\\"{}", &token[..9], &token[9..]),
        ];

        for value in &cases {
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
            assert_values(
                "config.txt",
                &format!("SESSION={value}"),
                &[value],
                &scanner,
                &al,
            );
        }
    }

    #[test]
    fn export_unquoted_quote_byte_keeps_complete_value_range() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let value = format!("{}\"{}", &token[..5], &token[5..]);
        assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
        assert_values(
            "config.txt",
            &format!("export NAME={value}"),
            &[&value],
            &scanner,
            &al,
        );
    }

    #[test]
    fn indented_export_unquoted_quote_byte_keeps_complete_value_range() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let value = format!("{}'{}", &token[..5], &token[5..]);
        assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0);
        assert_values(
            "config.txt",
            &format!("    export NAME={value}"),
            &[&value],
            &scanner,
            &al,
        );
    }

    #[test]
    fn non_env_style_prefix_keeps_legacy_quote_boundary() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let legacy = token[..24].to_string();
        let value = format!("{legacy}\"{}", &token[24..]);
        let input = format!("let NAME={value}");
        let rule = scanner.rules.iter().find(|rule| rule.id == RULE).unwrap();
        let captures = rule.regex.captures(input.as_bytes()).unwrap();
        assert_eq!(
            captures.name("entropy_unquoted").unwrap().as_bytes(),
            value.as_bytes()
        );
        assert_values("config.txt", &input, &[&legacy], &scanner, &al);
    }

    #[test]
    fn parenthesized_env_assignment_keeps_legacy_quote_boundary() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let legacy = format!("{}(", &token[..24]);
        let value = format!("{legacy}\"{}", &token[24..]);
        let input = format!("NAME={value}");
        assert!(entropy::shannon_entropy(legacy.as_bytes()) >= 4.0);
        assert_values("config.txt", &input, &[&legacy], &scanner, &al);
    }

    #[test]
    fn rust_source_shapes_keep_the_generic_entropy_rule_clean() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let regex_source = format!("let re = Regex::new(r\"{token}\").unwrap();");
        let rule = scanner.rules.iter().find(|rule| rule.id == RULE).unwrap();
        let captures = rule.regex.captures(regex_source.as_bytes()).unwrap();
        assert_eq!(
            captures.name("entropy_unquoted").unwrap().as_bytes(),
            format!("Regex::new(r\"{token}\").unwrap(").as_bytes()
        );
        // reclassified per g1: dense regex literals in calls are an accepted, allowlistable cost.
        assert_values("src/validator.rs", &regex_source, &[&token], &scanner, &al);

        let assertion_source = format!("assert_eq!(x, \"{token}\");");
        // reclassified per g1: opaque call-argument literals are tier-3 candidates (s19b).
        assert_values(
            "tests/scanner_test.rs",
            &assertion_source,
            &[&token],
            &scanner,
            &al,
        );
    }

    #[test]
    fn unquoted_quote_value_keeps_adjacent_assignments_and_redaction_syntax() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let first = format!("{}\"{}", &token[..8], &token[8..]);
        let second: String = token.chars().rev().collect();
        let input = format!("ALPHA={first};BRAVO={second}");

        assert_values("config.txt", &input, &[&first, &second], &scanner, &al);
        assert_eq!(
            redact_text(&input, &scanner, &al),
            "ALPHA=[REDACTED];BRAVO=[REDACTED]"
        );
    }

    #[test]
    fn quoted_value_still_uses_quoted_group_and_unmatched_opening_quote_is_ignored() {
        let (scanner, al) = default_scanner_and_allowlist();
        let token = distinct_token(32);
        let rule = scanner.rules.iter().find(|rule| rule.id == RULE).unwrap();
        let input = format!("NAME=\"{token}\"");
        let captures = rule.regex.captures(input.as_bytes()).unwrap();
        assert_eq!(
            captures.name("entropy_double").unwrap().as_bytes(),
            token.as_bytes()
        );
        assert!(captures.name("entropy_unquoted").is_none());
        assert_values("config.txt", &format!("NAME=\"{token}"), &[], &scanner, &al);
    }

    #[test]
    fn rooted_path_shaped_values_are_exempt_but_opaque_and_unrooted_values_remain_flagged() {
        let (scanner, al) = default_scanner_and_allowlist();
        let task_path = "/Users/example/work/rust/sekretbarilo/.claude/backlog/tasks/2026-09-08-redact-claude-masks-plain-absolute-files-9zVZK8LgjmLKdXZG.md";
        let exempt = [
            task_path,
            "~/work/some-project/target/release/build-output.log",
            "./a/b/config-file.toml",
            "../x/y/data-2026.csv",
            r"C:\Users\example\some-tool\cache-index.db",
            r"C:\Users\example\some-tool\cache-index.db\",
            r"C:\\Users\\example\\some-tool\\cache-index.db",
            "/Users/example/work/rust/sekretbarilo/.claude/backlog/tasks/2026-09-08-redact-claude-masks-plain-absolute-files-9zVZK8LgjmLKdXZG.md/",
        ];
        for value in exempt {
            assert_values("config.txt", &format!("PATH={value}"), &[], &scanner, &al);
        }
        assert_values(
            "config.json",
            &format!(r#"{{"path":"{task_path}"}}"#),
            &[],
            &scanner,
            &al,
        );
        assert_values(
            "config.json",
            r#"{"path":"C:\\Users\\example\\some-tool\\cache-index.db"}"#,
            &[],
            &scanner,
            &al,
        );

        let token24 = distinct_token(24);
        let token32 = distinct_token(32);
        let token40 = format!("{}ABCDEFGH", token32);
        let opaque = "aB3dEf7hIj1kLmN0pQrStUvWxYz5A6bC";
        let url = format!("https://user:{token32}@host.example/path");
        let still_flagged = [
            format!("/opt/{token24}"),
            format!("/x/{token40}"),
            format!("/data/{token32}.md"),
            format!("/data/{token32}/"),
            format!("/mnt/secrets/{}/token.txt", &opaque[..29]),
            format!("/tmp/cache/sess_{opaque}"),
            format!("/mnt/secrets/{token32}/token.txt"),
            format!("/tmp/cache/sess-{token32}"),
            format!("/data/{token32}.tar.gz"),
            format!("abc/DEF+{token32}"),
            format!("some/dir/{token32}"),
            url,
            format!("//user:{opaque}@host/path"),
            token32.clone(),
        ];
        for value in &still_flagged {
            assert!(entropy::shannon_entropy(value.as_bytes()) >= 4.0, "{value}");
            assert_values(
                "config.txt",
                &format!("VALUE={value}"),
                &[value],
                &scanner,
                &al,
            );
        }
    }

    #[test]
    fn path_exemption_resumes_for_the_next_assignment_and_preserves_tier_one_rules() {
        let (scanner, al) = default_scanner_and_allowlist();
        let path = "/Users/example/work/rust/sekretbarilo/.claude/backlog/tasks/2026-09-08-redact-claude-masks-plain-absolute-files-9zVZK8LgjmLKdXZG.md";
        let token = distinct_token(32);
        let input = format!("PATH={path},TOKEN={token}");
        assert_values("config.txt", &input, &[&token], &scanner, &al);
        assert_eq!(
            redact_text(&input, &scanner, &al),
            format!("PATH={path},TOKEN=[REDACTED]")
        );

        let aws_path = "/Users/example/work/AKIAIOSFODNN7ABCDEFG/cache-index.db";
        let findings = scan(
            &[make_file("config.txt", vec![(1, aws_path.as_bytes())])],
            &scanner,
            &al,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "aws-access-key-id"),
            "tier-1 AWS rule did not see an exempt path-shaped value: {findings:?}"
        );
    }

    #[test]
    fn generic_password_assignment_keeps_its_quote_termination_contract() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = format!("ab\"cd{}", distinct_token(28));
        let findings = scan(
            &[make_file(
                "config.txt",
                vec![(1, format!("password={value}").as_bytes())],
            )],
            &scanner,
            &al,
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "generic-password-assignment"),
            "generic-password-assignment changed its rule-specific quote handling: {findings:?}"
        );
    }

    #[test]
    fn bare_backlog_filename_remains_the_entropy_bare_alternative() {
        let (scanner, al) = default_scanner_and_allowlist();
        let value = "2026-09-05-doctor-e2e-tests-fail-on-macos-due-to-tm-9zQsedOXccoyIHP8.md";
        let rule = scanner.rules.iter().find(|rule| rule.id == RULE).unwrap();
        let captures = rule.regex.captures(value.as_bytes()).unwrap();
        assert_eq!(
            captures.name("entropy_bare").unwrap().as_bytes(),
            value.as_bytes()
        );
        assert!(captures.name("entropy_unquoted").is_none());
        assert_values("config.txt", value, &[value], &scanner, &al);
    }
}

// ============================================================================
// tier 1: prefix-based rules (very low false positives)
// ============================================================================

#[test]
fn tier1_aws_access_key_id() {
    assert_detected(
        "config.py",
        b"AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"",
        "aws-access-key-id",
    );
}

#[test]
fn tier1_aws_access_key_id_inline() {
    // key directly in code without quotes
    assert_detected(
        "deploy.sh",
        b"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7XYZWTUV",
        "aws-access-key-id",
    );
}

#[test]
fn tier1_github_personal_access_token() {
    assert_detected(
        "config.yml",
        b"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-personal-access-token",
    );
}

#[test]
fn tier1_github_oauth_token() {
    assert_detected(
        "config.yml",
        b"token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-oauth-token",
    );
}

#[test]
fn tier1_github_app_token() {
    assert_detected(
        "config.yml",
        b"token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-app-token",
    );
}

#[test]
fn tier1_github_refresh_token() {
    assert_detected(
        "config.yml",
        b"token: ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-refresh-token",
    );
}

#[test]
fn tier1_github_fine_grained_pat() {
    // github_pat_ tokens are 82+ chars after the prefix
    let token = format!("github_pat_{}", "A".repeat(82));
    let line = format!("token: {}", token);
    assert_detected("config.yml", line.as_bytes(), "github-fine-grained-pat");
}

#[test]
fn tier1_gitlab_personal_access_token() {
    assert_detected(
        "config.yml",
        b"token: glpat-ABCDEFGHIJKLMNOPQRSTU",
        "gitlab-personal-access-token",
    );
}

#[test]
fn tier1_slack_bot_token() {
    assert_detected(
        "config.js",
        b"const token = \"xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-bot-token",
    );
}

#[test]
fn tier1_slack_user_token() {
    assert_detected(
        "config.js",
        b"const token = \"xoxp-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-user-token",
    );
}

#[test]
fn tier1_slack_app_token() {
    assert_detected(
        "config.js",
        b"const token = \"xapp-1-ABCDEFGHIJ-1234567890-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-app-token",
    );
}

#[test]
fn tier1_stripe_secret_key_live() {
    assert_detected(
        "config.rb",
        b"Stripe.api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-secret-key-live",
    );
}

#[test]
fn tier1_stripe_secret_key_test_detected() {
    // tier 1 rules skip stopword filtering (high confidence prefix-based
    // rules should not be suppressed by stopwords embedded in the token).
    assert_detected(
        "config.rb",
        b"Stripe.api_key = \"sk_test_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-secret-key-test",
    );
}

#[test]
fn tier1_stripe_secret_key_test_regex_matches() {
    // verify the regex pattern itself matches sk_test_ tokens
    let rules = load_default_rules().unwrap();
    let rule = rules
        .iter()
        .find(|r| r.id == "stripe-secret-key-test")
        .unwrap();
    let re = regex::bytes::Regex::new(&rule.regex_pattern).unwrap();
    assert!(re.is_match(b"sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
}

#[test]
fn tier1_stripe_publishable_key_live() {
    assert_detected(
        "config.rb",
        b"pk = \"pk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-publishable-key-live",
    );
}

#[test]
fn tier1_sendgrid_api_key() {
    assert_detected(
        "email.py",
        b"sg_key = \"SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQR\"",
        "sendgrid-api-key",
    );
}

#[test]
fn tier1_pem_private_key() {
    assert_detected(
        "key.pem",
        b"-----BEGIN RSA PRIVATE KEY-----",
        "pem-private-key",
    );
}

#[test]
fn tier1_pem_ec_private_key() {
    assert_detected(
        "key.pem",
        b"-----BEGIN EC PRIVATE KEY-----",
        "pem-private-key",
    );
}

#[test]
fn tier1_pem_generic_private_key() {
    assert_detected("key.pem", b"-----BEGIN PRIVATE KEY-----", "pem-private-key");
}

#[test]
fn tier1_jwt_token() {
    // a realistic JWT: header.payload.signature
    assert_detected(
        "auth.js",
        b"token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\"",
        "jwt-token",
    );
}

#[test]
fn tier1_digitalocean_personal_access_token() {
    let token = format!("dop_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected(
        "config.yml",
        line.as_bytes(),
        "digitalocean-personal-access-token",
    );
}

#[test]
fn tier1_digitalocean_oauth_token() {
    let token = format!("doo_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected("config.yml", line.as_bytes(), "digitalocean-oauth-token");
}

#[test]
fn tier1_digitalocean_refresh_token() {
    let token = format!("dor_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected("config.yml", line.as_bytes(), "digitalocean-refresh-token");
}

#[test]
fn tier1_npm_access_token() {
    assert_detected(
        ".npmrc",
        b"//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "npm-access-token",
    );
}

#[test]
fn tier1_pypi_api_token() {
    assert_detected(
        "config.cfg",
        b"password = pypi-AgEIcHlwaS5vcmcCJGQwNmE4ZjNhLTRhO",
        "pypi-api-token",
    );
}

#[test]
fn tier1_docker_hub_pat() {
    assert_detected(
        "docker.env",
        b"DOCKER_TOKEN=dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWx",
        "docker-hub-pat",
    );
}

#[test]
fn tier1_new_relic_api_key() {
    assert_detected(
        "monitoring.yml",
        b"api_key: NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
        "new-relic-api-key",
    );
}

#[test]
fn tier1_terraform_cloud_token() {
    let token = format!("abcdefghijklmn.atlasv1.{}", "A".repeat(60));
    let line = format!("token = \"{}\"", token);
    assert_detected("terraform.tf", line.as_bytes(), "terraform-cloud-token");
}

#[test]
fn tier1_anthropic_api_key() {
    assert_detected(
        "config.py",
        b"ANTHROPIC_KEY = \"sk-ant-api03-abcdefghijklmnopqrst\"",
        "anthropic-api-key",
    );
}

#[test]
fn tier1_openai_api_key() {
    assert_detected(
        "config.py",
        b"OPENAI_KEY = \"sk-abcdefghijklmnopqrstT3BlbkFJuvwxyz0123456789abcd\"",
        "openai-api-key-legacy",
    );
}

#[test]
fn tier1_openai_api_key_project_format() {
    assert_detected(
        "config.py",
        b"OPENAI_KEY = \"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\"",
        "openai-api-key",
    );
}

// ============================================================================
// tier 2: context-needed rules (medium false positives)
// ============================================================================

#[test]
fn tier2_aws_secret_access_key() {
    // high entropy base64-like value with AWS context keyword
    // avoid "EXAMPLE" in value since it's a stopword
    assert_detected(
        "config.py",
        b"aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzR9gB4kN+a'",
        "aws-secret-access-key",
    );
}

#[test]
fn tier2_aws_secret_low_entropy_not_flagged() {
    // low entropy value should not be flagged (entropy threshold 3.5)
    assert_not_detected(
        "config.py",
        b"aws_secret_access_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    );
}

#[test]
fn tier2_postgres_connection_string() {
    assert_detected(
        "config.rs",
        b"let url = \"postgres://admin:Xk9#mQ2!vR7$nP4w@db.prod-host.com:5432/mydb\"",
        "database-connection-string-postgres",
    );
}

#[test]
fn tier2_postgresql_connection_string() {
    assert_detected(
        "config.rs",
        b"let url = \"postgresql://admin:Xk9#mQ2!vR7$nP4w@db.prod-host.com:5432/mydb\"",
        "database-connection-string-postgres",
    );
}

#[test]
fn tier2_mysql_connection_string() {
    assert_detected(
        "config.py",
        b"db_url = \"mysql://root:Xk9#mQ2!vR7$nP4w@db.prod-host.com:3306/app\"",
        "database-connection-string-mysql",
    );
}

#[test]
fn tier2_mongodb_connection_string() {
    assert_detected(
        "config.py",
        b"mongo_url = \"mongodb://admin:Xk9#mQ2!vR7$nP4w@mongo.prod-host.com:27017/app\"",
        "database-connection-string-mongodb",
    );
}

#[test]
fn tier2_mongodb_srv_connection_string() {
    assert_detected(
        "config.py",
        b"mongo_url = \"mongodb+srv://admin:Xk9#mQ2!vR7$nP4w@cluster.prod-host.com/app\"",
        "database-connection-string-mongodb",
    );
}

#[test]
fn tier2_redis_connection_string() {
    assert_detected(
        "config.py",
        b"redis_url = \"redis://:Xk9#mQ2!vR7$nP4w@redis.prod-host.com:6379\"",
        "redis-connection-string",
    );
}

#[test]
fn tier2_generic_password_assignment_high_entropy() {
    // strong password with high entropy - should be detected
    assert_detected(
        "config.py",
        b"password = \"Kj8mP2xQ9vL4nR5tB7wY\"",
        "generic-password-assignment",
    );
}

#[test]
fn tier2_generic_password_low_entropy_not_flagged() {
    // low entropy value should not pass the entropy threshold
    assert_not_detected("config.py", b"password = \"aaaaaaaaaaaaaaaaaaaaaa\"");
}

#[test]
fn tier2_generic_secret_assignment() {
    assert_detected(
        "config.py",
        b"secret = \"aB3dEf7hIj1kLmN0pQrStUvW\"",
        "generic-secret-assignment",
    );
}

#[test]
fn tier2_generic_secret_assignment_low_entropy_not_flagged() {
    assert_not_detected("config.py", b"secret = \"aaaaaaaaaaaaaaaaaaaaaa\"");
}

#[test]
fn tier2_password_in_url() {
    // password must be 8+ chars and >= 20 chars for entropy check (MIN_ENTROPY_LENGTH=20)
    // use a long, high-entropy password and avoid "example" domain (stopword)
    assert_detected(
        "config.yml",
        b"url: https://admin:Kj8mP2xQ9vL4nR5tB7wY@prod-host.com/api",
        "password-in-url",
    );
}

#[test]
fn tier2_http_bearer_token() {
    // high entropy bearer token
    assert_detected(
        "api.py",
        b"Authorization: Bearer aB3dEf7hIj1kLmN0pQrStUvW",
        "http-bearer-token",
    );
}

#[test]
fn tier2_http_basic_auth() {
    // base64 encoded credentials
    assert_detected(
        "api.py",
        b"Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NQ==",
        "http-basic-auth",
    );
}

#[test]
fn tier2_webhook_url_slack() {
    // avoid "xxx" or repetitive chars in the token (stopword "xxx")
    assert_detected(
        "notify.py",
        b"webhook = \"https://hooks.slack.com/services/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\"",
        "webhook-url-with-token",
    );
}

#[test]
fn tier2_azure_storage_account_key() {
    // azure keys are 86 base64 chars + ==
    let key = format!("{}==", "A".repeat(86));
    let line = format!("AccountKey={}", key);
    assert_detected("config.cs", line.as_bytes(), "azure-storage-account-key");
}

#[test]
fn tier2_cloudflare_api_key() {
    // 37 hex chars with cloudflare context and high entropy (threshold 3.0)
    let key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a";
    assert_eq!(key.len(), 37);
    let line = format!("cloudflare_api_key = '{}'", key);
    assert_detected("config.py", line.as_bytes(), "cloudflare-api-key");
}

#[test]
fn tier2_datadog_api_key() {
    // 32 hex chars should now be detected when there is no hash context.
    // hash detection requires context keywords (md5, sha, checksum, etc.)
    // to avoid false negatives on hex-based API keys.
    let key = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
    let line = format!("datadog_api_key = '{}'", key);
    assert_detected("config.py", line.as_bytes(), "datadog-api-key");
}

#[test]
fn tier2_datadog_api_key_mixed_case() {
    // datadog keys with mixed case won't trigger MD5 hash detection
    // since is_hex_string checks ascii_hexdigit (accepts A-F too)
    // but mixed with uppercase makes it clearly not a hash
    // use a value with uppercase hex chars that still matches [0-9a-f]{32}
    // actually the regex only allows lowercase [0-9a-f] so we use lowercase
    // and accept that pure-lowercase 32-hex = hash detection filters it.
    // instead, verify the rule regex pattern directly
    let rules = load_default_rules().unwrap();
    let rule = rules.iter().find(|r| r.id == "datadog-api-key").unwrap();
    let re = regex::bytes::Regex::new(&rule.regex_pattern).unwrap();
    let line = b"datadog_api_key = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8'";
    assert!(re.is_match(line), "datadog-api-key regex should match");
}

#[test]
fn tier2_heroku_api_key() {
    // 36-char uuid-like with heroku context
    let key = "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6";
    let line = format!("heroku_api_key = '{}'", key);
    assert_detected("config.py", line.as_bytes(), "heroku-api-key");
}

// ============================================================================
// tier 3: catch-all rules
// ============================================================================

#[test]
fn tier3_generic_api_key_high_entropy() {
    // generic api key with high entropy (threshold 4.0)
    assert_detected(
        "config.py",
        b"api_key = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

#[test]
fn tier3_generic_api_key_low_entropy_not_flagged() {
    // low entropy value should not trigger
    assert_not_detected("config.py", b"api_key = \"aaaaaaaaaaaaaaaaaaaaaa\"");
}

#[test]
fn tier3_generic_api_token() {
    assert_detected(
        "config.py",
        b"api_token = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

#[test]
fn tier3_generic_apikey_no_separator() {
    assert_detected(
        "config.py",
        b"apikey = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

// ============================================================================
// entropy calculation accuracy
// ============================================================================

#[test]
fn entropy_zero_for_empty() {
    assert_eq!(entropy::shannon_entropy(b""), 0.0);
}

#[test]
fn entropy_zero_for_uniform() {
    // all same character = zero entropy
    assert_eq!(entropy::shannon_entropy(b"aaaaaaaaaa"), 0.0);
}

#[test]
fn entropy_one_for_two_equal_symbols() {
    // exactly 2 symbols with equal frequency -> entropy = 1.0
    let e = entropy::shannon_entropy(b"abababab");
    assert!((e - 1.0).abs() < 0.001, "expected ~1.0, got {}", e);
}

#[test]
fn entropy_two_for_four_equal_symbols() {
    // 4 symbols with equal frequency -> entropy = 2.0
    let e = entropy::shannon_entropy(b"abcdabcdabcdabcd");
    assert!((e - 2.0).abs() < 0.001, "expected ~2.0, got {}", e);
}

#[test]
fn entropy_increases_with_more_symbols() {
    let e1 = entropy::shannon_entropy(b"aabb");
    let e2 = entropy::shannon_entropy(b"aabbccdd");
    let e3 = entropy::shannon_entropy(b"aabbccddeeffgghh");
    assert!(e1 < e2, "e1={} should be < e2={}", e1, e2);
    assert!(e2 < e3, "e2={} should be < e3={}", e2, e3);
}

#[test]
fn entropy_realistic_api_key() {
    // a realistic high-entropy API key
    let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
    let e = entropy::shannon_entropy(data);
    assert!(e > 3.5, "expected high entropy for API key, got {}", e);
}

#[test]
fn entropy_realistic_low_entropy_password() {
    // a low entropy "password"
    let data = b"aaaaaaaaaaaaaaaaaaaaaa";
    let e = entropy::shannon_entropy(data);
    assert!(e < 0.5, "expected near-zero entropy, got {}", e);
}

#[test]
fn entropy_hex_valid_returns_some() {
    let e = entropy::hex_entropy(b"a1b2c3d4e5f6a7b8c9d0");
    assert!(e.is_some());
    assert!(e.unwrap() > 2.0);
}

#[test]
fn entropy_hex_invalid_returns_none() {
    assert!(entropy::hex_entropy(b"not-hex-at-all!!").is_none());
}

#[test]
fn entropy_base64_valid_returns_some() {
    let e = entropy::base64_entropy(b"SGVsbG8gV29ybGQhIFRoaXM=");
    assert!(e.is_some());
    assert!(e.unwrap() > 2.0);
}

#[test]
fn entropy_base64_url_safe_valid() {
    let e = entropy::base64_entropy(b"SGVsbG8tV29ybGRf");
    assert!(e.is_some());
}

#[test]
fn entropy_base64_invalid_returns_none() {
    assert!(entropy::base64_entropy(b"has spaces and !@#").is_none());
}

#[test]
fn entropy_alphanumeric_valid_returns_some() {
    let e = entropy::alphanumeric_entropy(b"aB3dEf7hIj1kLmN0pQrS");
    assert!(e.is_some());
    assert!(e.unwrap() > 3.0);
}

#[test]
fn entropy_alphanumeric_invalid_returns_none() {
    assert!(entropy::alphanumeric_entropy(b"has-dashes!").is_none());
}

#[test]
fn entropy_passes_check_short_strings_pass_through() {
    // short strings skip entropy check (pass through) since regex+keyword
    // match already provides confidence
    assert!(entropy::passes_entropy_check(b"aB3dEf7h", 1.0));
    assert!(entropy::passes_entropy_check(b"short", 0.0));
}

#[test]
fn entropy_passes_check_below_threshold() {
    // long string but low entropy
    let data = b"aaaaaaaaaaaaaaaaaaaaaa";
    assert!(!entropy::passes_entropy_check(data, 3.0));
}

#[test]
fn entropy_passes_check_above_threshold() {
    let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
    assert!(entropy::passes_entropy_check(data, 3.0));
}

#[test]
fn entropy_min_length_constant() {
    assert_eq!(entropy::MIN_ENTROPY_LENGTH, 20);
}

// ============================================================================
// hash detection (should NOT flag as secrets)
// ============================================================================

#[test]
fn hash_md5_not_flagged_as_secret() {
    // MD5 hash (32 hex chars) with context keyword should be skipped
    assert_not_detected(
        "checksums.txt",
        b"md5 secret = \"d41d8cd98f00b204e9800998ecf8427e\"",
    );
}

#[test]
fn hash_sha1_not_flagged_as_secret() {
    // SHA-1 hash (40 hex chars) with context keyword should be skipped
    assert_not_detected(
        "config.py",
        b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
    );
}

#[test]
fn hash_sha256_not_flagged_as_secret() {
    // SHA-256 hash (64 hex chars) with context keyword should be skipped
    assert_not_detected(
        "config.py",
        b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

#[test]
fn hash_git_commit_sha_in_context() {
    // 40-char hex with "commit" context - should NOT flag
    assert_not_detected(
        "changelog.py",
        b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
    );
}

#[test]
fn hash_abbreviated_git_in_merge_context() {
    // abbreviated commit hash in merge context
    // note: the scanner only detects this as hash if the captured value
    // itself is hex and line has git context keywords
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file("git.log", vec![(1, b"merge commit da39a3e into main")]);
    let findings = scan(&[file], &scanner, &al);
    // should not flag anything - no rule keywords match in this line
    assert!(
        findings.is_empty(),
        "git merge line should not be flagged, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn hash_sha256_checksum_context() {
    // hash with "checksum" context word
    assert_not_detected(
        "verify.py",
        b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

#[test]
fn hash_sha256_digest_context() {
    assert_not_detected(
        "verify.py",
        b"digest secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

// ============================================================================
// additional coverage: scanner behavior with default rules
// ============================================================================

#[test]
fn stopword_changeme_not_flagged() {
    // "changeme" is a stopword - should not flag
    assert_not_detected("config.py", b"password = \"changeme_please_update\"");
}

#[test]
fn stopword_example_not_flagged() {
    assert_not_detected(
        "config.py",
        b"api_key = \"example_api_key_for_documentation\"",
    );
}

#[test]
fn variable_reference_env_not_flagged() {
    assert_not_detected("config.py", b"secret = \"${SECRET_KEY}\"");
}

#[test]
fn variable_reference_process_env_not_flagged() {
    assert_not_detected("config.js", b"secret = \"process.env.SECRET_KEY\"");
}

#[test]
fn aws_example_key_allowlisted() {
    // AKIAIOSFODNN7EXAMPLE is the well-known AWS example key
    // it's skipped because "EXAMPLE" matches the "example" stopword
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();

    let file = make_file("config.py", vec![(5, b"key = \"AKIAIOSFODNN7EXAMPLE\"")]);
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "AWS example key should be allowlisted, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn multiple_secrets_in_one_file() {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        "leaked.py",
        vec![
            (1, b"aws_key = \"AKIAIOSFODNN7ABCDEFG\""),
            (5, b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\""),
            (10, b"-----BEGIN RSA PRIVATE KEY-----"),
        ],
    );
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.len() >= 3,
        "expected at least 3 findings, got {}: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn clean_code_no_findings() {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        "clean.rs",
        vec![
            (1, b"fn main() {"),
            (2, b"    let x = 42;"),
            (3, b"    println!(\"hello world\");"),
            (4, b"    let config = load_config();"),
            (5, b"}"),
        ],
    );
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "clean code should have no findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// tier 1: additional prefix-based rules
// ============================================================================

#[test]
fn tier1_gcp_api_key() {
    assert_detected(
        "src/config.rs",
        b"let key = \"AIzaSyA1234567890abcdefghijklmnopqrstuvwx\";",
        "gcp-api-key",
    );
}

#[test]
fn tier1_gcp_oauth_client_secret() {
    assert_detected(
        "src/config.rs",
        b"client_secret = \"GOCSPX-abcdefghijklmnopqrstuvwxyzAB\";",
        "gcp-oauth-client-secret",
    );
}

#[test]
fn tier1_alibaba_access_key_id() {
    assert_detected(
        "src/config.rs",
        b"key = \"LTAI5t1234567890abcde\";",
        "alibaba-access-key-id",
    );
}

#[test]
fn tier1_gitlab_pipeline_trigger_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"glptt-abcdefghijklmnopqrstuv\";",
        "gitlab-pipeline-trigger-token",
    );
}

#[test]
fn tier1_huggingface_access_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\";",
        "huggingface-access-token",
    );
}

#[test]
fn tier1_replicate_api_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\";",
        "replicate-api-token",
    );
}

#[test]
fn tier1_discord_webhook_url() {
    assert_detected(
        "src/config.rs",
        b"url = \"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz123456\";",
        "discord-webhook-url",
    );
}

#[test]
fn tier1_stripe_restricted_key_live() {
    assert_detected(
        "src/config.rs",
        b"key = \"rk_live_abcdefghijklmnopqrstuvwxyz\";",
        "stripe-restricted-key-live",
    );
}

#[test]
fn tier1_square_access_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"sq0atp-abcdefghijklmnopqrstuv\";",
        "square-access-token",
    );
}

#[test]
fn tier1_planetscale_password() {
    assert_detected(
        "src/config.rs",
        b"pw = \"pscale_pw_abcdefghijklmnopqrstuvwxyz123456\";",
        "planetscale-password",
    );
}

#[test]
fn tier1_sendinblue_api_key() {
    assert_detected(
        "src/config.rs",
        b"key = \"xkeysib-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789-abcdefghijklmnop\";",
        "sendinblue-api-key",
    );
}

#[test]
fn tier1_sentry_auth_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"sntrys_eyJpYXQiOjE2OTQwMTY1NzQuNzMsInVybCI6I\";",
        "sentry-auth-token",
    );
}

#[test]
fn tier1_grafana_service_account_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"glsa_abcdefghijklmnopqrstuvwxyz123456\";",
        "grafana-service-account-token",
    );
}

#[test]
fn tier1_age_secret_key() {
    assert_detected(
        "src/config.rs",
        b"key = \"AGE-SECRET-KEY-1abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv\";",
        "age-secret-key",
    );
}

#[test]
fn tier1_pgp_private_key_block() {
    assert_detected(
        "src/config.rs",
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "pgp-private-key-block",
    );
}

#[test]
fn tier1_fly_io_api_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"fo1_abcdefghijklmnopqrstuvwxyz01234567891234\";",
        "fly-io-api-token",
    );
}

#[test]
fn tier1_linear_api_key() {
    assert_detected(
        "src/config.rs",
        b"key = \"lin_api_abcdefghijklmnopqrstuvwxyz01234567890123\";",
        "linear-api-key",
    );
}

#[test]
fn tier1_shopify_admin_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"shpat_abcdef0123456789abcdef0123456789\";",
        "shopify-access-token-admin",
    );
}

#[test]
fn tier1_hashicorp_vault_service_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"hvs.abcdefghijklmnopqrstuvwx\";",
        "hashicorp-vault-service-token",
    );
}

#[test]
fn tier1_sourcegraph_access_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"sgp_abcdef0123456789abcdef0123456789abcdef01\";",
        "sourcegraph-access-token",
    );
}

#[test]
fn tier1_notion_api_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"ntn_abcdefghijklmnopqrstuvwxyz01234567890123\";",
        "notion-api-token",
    );
}

#[test]
fn tier1_databricks_api_token() {
    assert_detected(
        "src/config.rs",
        b"token = \"dapi0123456789abcdef0123456789abcdef\";",
        "databricks-api-token",
    );
}

#[test]
fn tier1_sentry_dsn() {
    assert_detected(
        "src/config.rs",
        b"dsn = \"https://abcdef0123456789abcdef0123456789@o123456.ingest.sentry.io/1234567\";",
        "sentry-dsn",
    );
}

#[test]
fn tier1_mapbox_api_token() {
    // pk.<60+ chars>.<20+ chars>
    let part1 = "eyJ1IjoibXl1c2VybmFtZSIsImEiOiJjazFhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MGFi";
    let part2 = "abcdefghijklmnopqrstu";
    let token = format!("pk.{}.{}", part1, part2);
    let line = format!("token = \"{}\";", token);
    assert_detected("src/config.rs", line.as_bytes(), "mapbox-api-token");
}

// ============================================================================
// tier 2: additional context-based rules
// ============================================================================

#[test]
fn tier2_mssql_connection_string() {
    assert_detected(
        "src/config.rs",
        b"conn = \"Data Source=myserver;Initial Catalog=mydb;User Id=sa;Password=Str0ng!P@ss#2024\";",
        "mssql-connection-string",
    );
}

#[test]
fn tier2_azure_ad_client_secret() {
    // regex: (?i)(?:azure|client_secret|client[-_]?secret)\s*[=:]\s*['"]?([0-9a-zA-Z~._-]{34,})['"]?
    // needs azure/client_secret context, 34+ chars, entropy >= 3.5
    assert_detected(
        "src/config.rs",
        b"azure_client_secret = \"abcD.efgH~ijkL-mnop_qrst.uvwx~yz0123\"",
        "azure-ad-client-secret",
    );
}

#[test]
fn tier2_okta_api_token() {
    // regex: (?i)(?:okta)[-_]?(?:api)?[-_]?(?:key|token)\s*[=:]\s*['"]?([0-9a-zA-Z_-]{30,})['"]?
    // needs "okta" keyword, 30+ alphanumeric chars, entropy >= 3.0
    assert_detected(
        "src/config.rs",
        b"okta_api_token = \"00aBcDeFgHiJkLmNoPqRsTuVwXyZ1234\"",
        "okta-api-token",
    );
}

#[test]
fn tier2_cohere_api_key() {
    // regex: (?i)(?:cohere)[-_]?(?:api)?[-_]?(?:key|token)\s*[=:]\s*['"]?([0-9a-zA-Z]{40})['"]?
    // needs "cohere" keyword, exactly 40 alphanumeric chars, entropy >= 3.5
    assert_detected(
        "src/config.rs",
        b"cohere_api_key = \"aBcDeFgH0123456789iJkLmNoPqRsTuVwXyZ0123\"",
        "cohere-api-key",
    );
}

// ============================================================================
// credential rule password strength filtering
// ============================================================================

#[test]
fn credential_rule_skips_common_password_but_entropy_flags_complete_url() {
    let findings = scan_line(
        "config.rs",
        b"let url = \"postgres://admin:password@db.host.com:5432/mydb\"",
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "generic-high-entropy-value");
    assert_eq!(
        findings[0].matched_value,
        b"postgres://admin:password@db.host.com:5432/mydb"
    );
}

#[test]
fn credential_rule_detects_strong_password() {
    // strong password should still be detected
    assert_detected(
        "config.rs",
        b"let url = \"postgres://admin:Xk9#mQ2!vR7$nP4w@db.host.com:5432/mydb\"",
        "database-connection-string-postgres",
    );
}
