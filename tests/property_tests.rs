use std::io::Write;
use std::ops::Range;
use std::sync::OnceLock;

use proptest::prelude::*;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{
    self, ProjectConfig, load_project_config_from_paths, load_single_config,
};
use sekretbarilo::diff::parser::{AddedLine, DiffFile, parse_diff};
use sekretbarilo::scanner::{
    engine::{TextMatch, redact_text, scan, scan_text},
    entropy::is_path_shaped,
    hash_detect::{is_hash_in_context, is_hex_policy_candidate},
    password::{is_pure_reference, is_strong_password, is_url_password_placeholder},
    rules::{CompiledScanner, compile_rules, load_default_rules},
    syntax::expression_span,
    urlshape::{is_credential_free_url, is_pinned_action_ref, unwrap_markdown_target},
    wordshape::is_word_structured,
};

const MARKER: &str = "[REDACTED]";

static DEFAULTS: OnceLock<(CompiledScanner, config::allowlist::CompiledAllowlist)> =
    OnceLock::new();
static D2_DEFAULTS: OnceLock<(CompiledScanner, CompiledAllowlist, CompiledAllowlist)> =
    OnceLock::new();

fn defaults() -> &'static (CompiledScanner, config::allowlist::CompiledAllowlist) {
    DEFAULTS.get_or_init(|| {
        let rules = load_default_rules().expect("default rules compile");
        let scanner = compile_rules(&rules).expect("scanner compiles");
        let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules)
            .expect("default allowlist compiles");
        (scanner, allowlist)
    })
}

fn d2_defaults() -> &'static (CompiledScanner, CompiledAllowlist, CompiledAllowlist) {
    D2_DEFAULTS.get_or_init(|| {
        let rules = load_default_rules().expect("default rules compile");
        let scanner = compile_rules(&rules).expect("scanner compiles");
        let layer_on = config::build_allowlist(&ProjectConfig::default(), &rules)
            .expect("default allowlist compiles");
        let mut layer_off = config::build_allowlist(&ProjectConfig::default(), &rules)
            .expect("default allowlist compiles");
        layer_off.exemption_layer = false;
        (scanner, layer_on, layer_off)
    })
}

fn merge_ranges(matches: &[TextMatch]) -> Vec<Range<usize>> {
    let mut ranges: Vec<_> = matches.iter().map(|found| found.range.clone()).collect();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start < previous.end
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn expected_redaction(text: &str, ranges: &[Range<usize>]) -> String {
    let mut expected = String::new();
    let mut cursor = 0;
    for range in ranges {
        expected.push_str(&text[cursor..range.start]);
        expected.push_str(MARKER);
        for byte in text.as_bytes()[range.clone()].iter().copied() {
            if matches!(byte, b'\r' | b'\n') {
                expected.push(char::from(byte));
            }
        }
        cursor = range.end;
    }
    expected.push_str(&text[cursor..]);
    expected
}

fn high_entropy_token(family: u8, length: usize, offset: usize) -> String {
    let alphabet: Vec<u8> = match family {
        0 => (b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .chain(b'0'..=b'9')
            .collect(),
        1 => (b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .chain(b'0'..=b'9')
            .chain(*b"-_")
            .collect(),
        _ => (b'0'..=b'9').chain(b'a'..=b'f').collect(),
    };
    (0..length)
        .map(|index| char::from(alphabet[(offset + index) % alphabet.len()]))
        .collect()
}

fn token_cases() -> impl Strategy<Value = (u8, String)> {
    (0u8..3, 20usize..65, any::<u8>()).prop_map(|(family, length, offset)| {
        let length = if family == 2 {
            [32, 40, 64][length % 3]
        } else {
            length
        };
        (
            family,
            high_entropy_token(family, length, usize::from(offset)),
        )
    })
}

fn has_opaque_run(value: &[u8]) -> bool {
    let mut run = 0;
    for byte in value {
        if byte.is_ascii_whitespace() {
            run = 0;
        } else {
            run += 1;
            if run >= 20 {
                return true;
            }
        }
    }
    false
}

proptest! {
    #[test]
    fn structured_call_literals_preserve_ranges_and_surroundings(
        offset in 0usize..62,
        hashes in 0usize..96,
        nesting in 0usize..16,
        padding in 0usize..256,
        copies in 1usize..5,
        raw in any::<bool>(),
        byte_literal in any::<bool>(),
        close_outer in any::<bool>(),
        single_quote in any::<bool>(),
    ) {
        let (scanner, on, _) = d2_defaults();
        let body = high_entropy_token(0, 32, offset);
        prop_assert!(!is_word_structured(body.as_bytes()));
        let delimiter = "#".repeat(hashes);
        let prefix = if byte_literal { "b" } else { "" };
        let literal = if raw {
            format!("{prefix}r{delimiter}\"{body}\"{delimiter}")
        } else if single_quote && !byte_literal {
            format!("'{body}'")
        } else {
            format!("{prefix}\"{body}\"")
        };
        let mut text = format!("λ wrapper({}", r#""safe,(", "escaped\")", "#.repeat(padding));
        text.push_str(&"nested(".repeat(nesting));
        for index in 0..copies {
            if index > 0 {
                text.push_str(r##", r#"safe"#, "safe,(", "##);
            }
            text.push_str(&literal);
        }
        if close_outer {
            text.push_str(&")".repeat(nesting + 1));
        }
        text.push_str(" // Ω");
        let matches = scan_text(&text, scanner, on);
        prop_assert_eq!(&matches, &scan_text(&text, scanner, on));
        prop_assert_eq!(matches.len(), copies);
        let expected: Vec<_> = text.match_indices(&body).map(|(start, value)| start..start + value.len()).collect();
        let mut identities = std::collections::HashSet::new();
        for (found, wanted) in matches.iter().zip(&expected) {
            prop_assert_eq!(&found.rule_id, "generic-high-entropy-value");
            prop_assert_eq!(&found.range, wanted);
            prop_assert!(found.range.start < found.range.end);
            prop_assert!(found.range.end <= text.len());
            prop_assert!(text.is_char_boundary(found.range.start));
            prop_assert!(text.is_char_boundary(found.range.end));
            prop_assert!(identities.insert((&found.rule_id, found.range.start, found.range.end)));
        }
        for pair in matches.windows(2) {
            prop_assert!(pair[0].range.end <= pair[1].range.start);
        }
        prop_assert_eq!(
            redact_text(&text, scanner, on),
            expected_redaction(&text, &merge_ranges(&matches))
        );
    }

    #[test]
    fn text_scan_and_redaction_invariants(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let text = String::from_utf8_lossy(&data);
        let (scanner, allowlist) = defaults();
        let matches = scan_text(&text, scanner, allowlist);
        prop_assert_eq!(matches.clone(), scan_text(&text, scanner, allowlist));
        for found in &matches {
            prop_assert!(found.range.start < found.range.end);
            prop_assert!(found.range.end <= text.len());
            prop_assert!(text.is_char_boundary(found.range.start));
            prop_assert!(text.is_char_boundary(found.range.end));
        }

        let ranges = merge_ranges(&matches);
        let redacted = redact_text(&text, scanner, allowlist);
        prop_assert_eq!(redacted.clone(), expected_redaction(&text, &ranges));
        let replaced_len: usize = ranges
            .iter()
            .map(|range| {
                text.as_bytes()[range.clone()]
                    .iter()
                    .filter(|byte| !matches!(**byte, b'\r' | b'\n'))
                    .count()
            })
            .sum();
        prop_assert_eq!(
            redacted.len(),
            text.len() - replaced_len + ranges.len() * MARKER.len()
        );
        prop_assert_eq!(redact_text(&redacted, scanner, allowlist), redacted);
    }

    #[test]
    fn diff_parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_diff(&data);
    }

    #[test]
    fn line_scan_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let (scanner, allowlist) = defaults();
        let file = DiffFile {
            path: "input.txt".to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: vec![AddedLine {
                line_number: 1,
                content: data,
            }],
        };
        let findings = scan(&[file], scanner, allowlist);
        prop_assert!(findings.iter().all(|finding| !finding.matched_value.is_empty()));
    }

    #[test]
    fn config_load_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut file = tempfile::NamedTempFile::new().expect("temporary config file");
        file.write_all(&data).expect("write temporary config");
        let path = file.path().to_path_buf();
        let _ = load_single_config(&path);
        let _ = load_project_config_from_paths(&[path]);
    }

    #[test]
    fn predicates_are_bounded(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = is_path_shaped(&data);
        let _ = is_pinned_action_ref(Some(b"uses"), &data);
        let _ = is_hash_in_context(&data, &data);
        let _ = is_url_password_placeholder(&data);
        let _ = is_pure_reference(&data);
        let _ = is_strong_password(&data);

        if has_opaque_run(&data) {
            prop_assert!(!is_word_structured(&data));
            prop_assert!(!is_credential_free_url(&data));
        }
        if let Some(range) = unwrap_markdown_target(&data) {
            let target = &data[range];
            if has_opaque_run(target) {
                prop_assert!(!is_word_structured(target));
                prop_assert!(!is_credential_free_url(target));
            }
        }
        if let Some(range) = expression_span(&data, 0, data.len()) {
            let newline = data
                .iter()
                .position(|byte| matches!(*byte, b'\r' | b'\n'))
                .unwrap_or(data.len());
            prop_assert!(range.start < range.end);
            prop_assert!(range.end <= newline);
            prop_assert!(range.end <= data.len());
            prop_assert!(!has_opaque_run(&data[range]));
        }
        if is_hex_policy_candidate(Some(b"key"), &data) {
            let remainder = data
                .strip_prefix(b"0x")
                .or_else(|| data.strip_prefix(b"0X"))
                .unwrap_or(&data);
            prop_assert!(matches!(remainder.len(), 32 | 40 | 64));
            prop_assert!(remainder.iter().all(u8::is_ascii_hexdigit));
            prop_assert!(
                (!data.starts_with(b"0x") && !data.starts_with(b"0X")) || remainder.len() == 64
            );
        }
    }

    #[test]
    fn d2_exemption_layer_preserves_base_detections((family, token) in token_cases()) {
        let (scanner, layer_on, layer_off) = d2_defaults();
        let assignment = format!("KEY={token}");
        let call = format!("foo({token})");
        let url = format!("https://host/?t={token}");
        let markdown = format!("[x](https://host/{token})");

        prop_assert!(!is_word_structured(token.as_bytes()));
        prop_assert!(!is_credential_free_url(url.as_bytes()));
        let target = unwrap_markdown_target(markdown.as_bytes()).expect("markdown target");
        let target = &markdown.as_bytes()[target];
        prop_assert!(!is_word_structured(target));
        prop_assert!(!is_credential_free_url(target));
        let expression = expression_span(call.as_bytes(), 0, call.len());
        prop_assert!(expression.is_none());

        let mut tally = [0usize; 4];
        for form in [&assignment, &call, &url, &markdown] {
            let token_start = form.find(&token).expect("generated token is present");
            let token_end = token_start + token.len();
            let layer_off_covered = scan_text(form, scanner, layer_off).iter().any(|found| {
                found.range.start <= token_start && found.range.end >= token_end
            });
            let layer_on_covered = scan_text(form, scanner, layer_on).iter().any(|found| {
                found.range.start <= token_start && found.range.end >= token_end
            });
            let tally_index = match (layer_off_covered, layer_on_covered) {
                (false, false) => 0,
                (false, true) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            tally[tally_index] += 1;
            prop_assert!(
                !layer_off_covered || layer_on_covered,
                "exemption layer removed a base detection: family={family}, form={form:?}"
            );
        }
        eprintln!(
            "d2 coverage tally: off=false,on=false={}; off=false,on=true={}; off=true,on=false={}; off=true,on=true={}",
            tally[0], tally[1], tally[2], tally[3]
        );
    }
}
