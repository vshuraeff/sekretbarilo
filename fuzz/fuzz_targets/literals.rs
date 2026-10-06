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
            let mut previous_start = 0;
            let mut furthest_end = 0;
            for range in literals.bodies {
                assert!(range.start <= range.end && range.end <= line.len());
                assert!(previous_start <= range.start);
                if range.start < furthest_end {
                    // go struct tags expose both the full value and its component items.
                    assert!(matches!(language, Language::Go));
                    assert!(range.end <= furthest_end);
                } else {
                    furthest_end = range.end;
                }
                previous_start = range.start;
            }
        }
    }
});
