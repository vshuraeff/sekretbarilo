#![no_main]

use std::ops::Range;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sekretbarilo::config::{self, ProjectConfig};
use sekretbarilo::scanner::engine::{TextMatch, redact_text, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};

static DEFAULTS: OnceLock<(CompiledScanner, config::allowlist::CompiledAllowlist)> = OnceLock::new();

fn defaults() -> &'static (CompiledScanner, config::allowlist::CompiledAllowlist) {
    DEFAULTS.get_or_init(|| {
        let rules = load_default_rules().expect("default rules compile");
        let scanner = compile_rules(&rules).expect("scanner compiles");
        let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules)
            .expect("default allowlist compiles");
        (scanner, allowlist)
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
        expected.push_str("[REDACTED]");
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

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (scanner, allowlist) = defaults();
    let matches = scan_text(&text, scanner, allowlist);
    assert_eq!(matches, scan_text(&text, scanner, allowlist));
    for found in &matches {
        assert!(found.range.start < found.range.end);
        assert!(found.range.end <= text.len());
        assert!(text.is_char_boundary(found.range.start));
        assert!(text.is_char_boundary(found.range.end));
    }

    let ranges = merge_ranges(&matches);
    let redacted = redact_text(&text, scanner, allowlist);
    assert_eq!(redacted, expected_redaction(&text, &ranges));
    let replaced_len: usize = ranges
        .iter()
        .map(|range| {
            text.as_bytes()[range.clone()]
                .iter()
                .filter(|byte| !matches!(**byte, b'\r' | b'\n'))
                .count()
        })
        .sum();
    assert_eq!(
        redacted.len(),
        text.len() - replaced_len + ranges.len() * "[REDACTED]".len()
    );
    assert_eq!(redact_text(&redacted, scanner, allowlist), redacted);
});
