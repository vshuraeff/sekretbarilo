#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sekretbarilo::config::{self, ProjectConfig};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::scan;
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

fuzz_target!(|data: &[u8]| {
    let (scanner, allowlist) = defaults();
    let file = DiffFile {
        path: "input.txt".to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: data.to_vec(),
        }],
    };
    let findings = scan(&[file], scanner, allowlist);
    assert!(findings.iter().all(|finding| !finding.matched_value.is_empty()));
});
