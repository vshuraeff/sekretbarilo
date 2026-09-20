#![no_main]

use libfuzzer_sys::fuzz_target;
use sekretbarilo::scanner::literals::{Language, LiteralTracker};

fuzz_target!(|data: &[u8]| {
    for language in [
        Language::Rust,
        Language::Go,
        Language::Python,
        Language::JavaScript,
        Language::C,
    ] {
        let mut tracker = LiteralTracker::new(language);
        for (index, line) in data.split(|&byte| byte == b'\n').enumerate() {
            let literals = tracker.feed(line, index + 1);
            if let Some(range) = literals.test_span {
                assert!(literals.known);
                assert!(range.start <= range.end && range.end <= line.len());
            }
            let mut previous_end = 0;
            for range in literals.bodies {
                assert!(range.start <= range.end && range.end <= line.len());
                assert!(previous_end <= range.start);
                previous_end = range.end;
            }
        }
    }
});
