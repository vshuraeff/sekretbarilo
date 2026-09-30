use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{scan, scan_text};
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

fn body(length: usize, state: &mut u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    (0..length)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            ALPHABET[(*state >> 58) as usize] as char
        })
        .collect()
}

#[test]
fn openai_project_placeholder_bodies_do_not_gain_entropy_from_the_prefix() {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    for pattern in ["-", "_", "a_", "ab-", "a_-", "abc_-", "123_-", "abAB_-"] {
        let token = format!("sk-proj-{}", pattern.repeat(40));
        let input = format!("OPENAI_API_KEY=\"{token}\"");
        assert!(
            !scan_text(&input, &scanner, &allowlist)
                .iter()
                .any(|finding| finding.rule_id == "openai-api-key"),
            "placeholder pattern {pattern:?} matched"
        );
    }
}

#[test]
fn openai_project_generated_bodies_keep_recall_at_short_and_long_lengths() {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    // renaming this otherwise identical rule bypasses only the provider-specific payload guard.
    let mut reference_rule = rules
        .iter()
        .find(|rule| rule.id == "openai-api-key")
        .unwrap()
        .clone();
    reference_rule.id = "openai-reference".into();
    let reference = compile_rules(&[reference_rule]).unwrap();
    let mut state = 0x529a_38b4_2091_d732;
    for length in [20, 24, 40, 156] {
        let mut baseline_detected = 0;
        for case in 0..256 {
            let token = format!("sk-proj-{}", body(length, &mut state));
            let input = format!("OPENAI_API_KEY=\"{token}\"");
            let expected = !scan_text(&input, &reference, &allowlist).is_empty();
            baseline_detected += usize::from(expected);
            assert_eq!(
                scan_text(&input, &scanner, &allowlist)
                    .iter()
                    .any(|finding| {
                        finding.rule_id == "openai-api-key"
                            && &input.as_bytes()[finding.range.clone()] == token.as_bytes()
                    }),
                expected,
                "agent surface lost length {length} case {case}"
            );
            let file = DiffFile {
                path: "docs/example.md".into(),
                is_new: true,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                context: None,
                added_lines: vec![AddedLine {
                    line_number: 1,
                    content: input.into_bytes(),
                }],
            };
            let expected = !scan(std::slice::from_ref(&file), &reference, &allowlist).is_empty();
            assert_eq!(
                scan(&[file], &scanner, &allowlist)
                    .iter()
                    .any(|finding| finding.rule_id == "openai-api-key"),
                expected,
                "documentation surface lost length {length} case {case}"
            );
        }
        assert!(
            baseline_detected >= 250,
            "length {length}: {baseline_detected}"
        );
    }
}
