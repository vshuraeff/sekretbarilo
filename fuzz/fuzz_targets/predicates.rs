#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use sekretbarilo::scanner::{
    entropy::is_path_shaped,
    hash_detect::{is_hash_in_context, is_hex_policy_candidate},
    password::{is_pure_reference, is_strong_password, is_url_password_placeholder},
    syntax::expression_span,
    urlshape::{is_credential_free_url, is_pinned_action_ref, unwrap_markdown_target},
    wordshape::is_word_structured,
};

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

pub(crate) fn check_predicates(data: &[u8]) {
    let _ = is_path_shaped(data);
    let _ = is_credential_free_url(data);
    let _ = is_pinned_action_ref(Some(b"uses"), data);
    let _ = is_hash_in_context(data, data);
    let _ = is_url_password_placeholder(data);
    let _ = is_pure_reference(data);
    let _ = is_strong_password(data);

    if let Some(range) = unwrap_markdown_target(data) {
        let target = &data[range];
        let _ = is_credential_free_url(target);
        if has_opaque_run(target) {
            assert!(!is_word_structured(target));
        }
    }
    if let Some(range) = expression_span(data, 0, data.len()) {
        let newline = data
            .iter()
            .position(|byte| matches!(*byte, b'\r' | b'\n'))
            .unwrap_or(data.len());
        assert!(range.start < range.end);
        assert!(range.end <= newline);
        assert!(range.end <= data.len());
        assert!(!has_opaque_run(&data[range]));
    }
    if is_hex_policy_candidate(Some(b"key"), data) {
        let remainder = data
            .strip_prefix(b"0x")
            .or_else(|| data.strip_prefix(b"0X"))
            .unwrap_or(data);
        assert!(matches!(remainder.len(), 32 | 40 | 64));
        assert!(remainder.iter().all(u8::is_ascii_hexdigit));
    }
}

#[cfg(not(test))]
fuzz_target!(|data: &[u8]| {
    check_predicates(data);
});
