#![no_main]

use libfuzzer_sys::fuzz_target;
use sekretbarilo::diff::parser::parse_diff;

fuzz_target!(|data: &[u8]| {
    let _ = parse_diff(data);
});
