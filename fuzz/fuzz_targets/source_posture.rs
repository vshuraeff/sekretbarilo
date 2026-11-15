#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sekretbarilo::config::{SourcePosture, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, scan};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};

static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
static SETTINGS: OnceLock<(CompiledAllowlist, CompiledAllowlist)> = OnceLock::new();

fn scanner() -> &'static CompiledScanner {
    SCANNER.get_or_init(|| {
        compile_rules(&load_default_rules().expect("default rules")).expect("scanner")
    })
}

fn settings() -> &'static (CompiledAllowlist, CompiledAllowlist) {
    SETTINGS.get_or_init(|| {
        let mut all = CompiledAllowlist::default_allowlist().expect("allowlist");
        all.source_posture = Some(SourcePosture::All);
        let mut literals = CompiledAllowlist::default_allowlist().expect("allowlist");
        literals.source_posture = Some(SourcePosture::Literals);
        (all, literals)
    })
}

fn identities(findings: &[Finding]) -> BTreeMap<(String, usize, Vec<u8>), usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts
            .entry((
                finding.rule_id.clone(),
                finding.line,
                finding.matched_value.clone(),
            ))
            .or_insert(0) += 1;
    }
    counts
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    // the selector counts from b'0' so the committed seeds keep their grammar.
    let path = [
        "src/input.c",
        "src/input.cpp",
        "src/input.py",
        "src/input.js",
        "src/input.ts",
        "src/input.tsx",
        "src/input.swift",
    ][usize::from(data[0].wrapping_sub(b'0')) % 7];
    let source = &data[1..];
    let lines: Vec<&[u8]> = source.split(|&byte| byte == b'\n').collect();
    let file = DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: Some(source.to_vec()),
        added_lines: lines
            .iter()
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.to_vec(),
            })
            .collect(),
    };
    let (all_settings, literals_settings) = settings();
    let all = scan(std::slice::from_ref(&file), scanner(), all_settings);
    let narrowed = scan(&[file], scanner(), literals_settings);

    for finding in all.iter().chain(narrowed.iter()) {
        assert_eq!(finding.file, path);
        assert!((1..=lines.len()).contains(&finding.line));
        assert!(!finding.matched_value.is_empty());
        assert!(
            lines[finding.line - 1]
                .windows(finding.matched_value.len())
                .any(|window| window == finding.matched_value)
        );
    }
    // the literal posture only narrows: the parser clip (adr 0003, amendment 2026-09-26) may
    // report the in-body segments of a straddling tier-3 finding, so a retained value is a
    // full-posture finding of that rule on that line or a contiguous part of one. one finding can
    // yield several equal segments, so counts are not compared.
    for finding in narrowed
        .iter()
        .filter(|finding| finding.rule_id == "generic-high-entropy-value")
    {
        assert!(all.iter().any(|base| {
            base.rule_id == finding.rule_id
                && base.line == finding.line
                && base
                    .matched_value
                    .windows(finding.matched_value.len())
                    .any(|window| window == finding.matched_value)
        }));
    }
    let non_tier3 = |findings: &[Finding]| {
        identities(
            &findings
                .iter()
                .filter(|finding| finding.rule_id != "generic-high-entropy-value")
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(non_tier3(&all), non_tier3(&narrowed));
});
