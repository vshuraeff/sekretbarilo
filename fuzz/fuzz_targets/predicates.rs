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

fn check_expression_bounds(data: &[u8], start: usize, max_scan: usize) {
    if let Some(range) = expression_span(data, start, max_scan) {
        let remaining = data.get(start..).expect("span starts inside input");
        let line_end = start
            + remaining
                .iter()
                .position(|byte| matches!(*byte, b'\r' | b'\n'))
                .unwrap_or(remaining.len());
        let line_start = data[..start]
            .iter()
            .rposition(|byte| matches!(*byte, b'\r' | b'\n'))
            .map_or(0, |index| index + 1);
        // enclosing expressions may start to the left, but must cover the requested byte.
        assert!(line_start <= range.start);
        assert!(range.start <= start);
        assert!(start < range.end);
        assert!(range.end <= line_end);
        // the span itself is capped by the scan budget, measured from where it starts.
        assert!(range.len() <= max_scan);
    }
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
        assert!(range.start <= range.end);
        assert!(range.end <= data.len());
        let target = &data[range];
        let _ = is_credential_free_url(target);
        // word structure is valid even in a long whitespace-free markdown target.
        let _ = is_word_structured(target);
    }
    // token eligibility depends on private delimiter, entropy and shape rules, not run length.
    // exercise the public range contract at both full and input-derived scan windows.
    check_expression_bounds(data, 0, data.len());
    let start = data.first().map_or(0, |byte| usize::from(*byte)) % (data.len() + 1);
    let budget = data.get(1).map_or(0, |byte| usize::from(*byte));
    check_expression_bounds(data, start, budget);
    assert!(expression_span(data, data.len() + 1, budget).is_none());
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

#[cfg(test)]
mod tests {
    use super::{check_expression_bounds, check_predicates};

    #[test]
    fn weekly_control_byte_crash_is_valid_input() {
        check_predicates(b"[//hox](https\x1d\0\0\0ost/sample)\n");
    }

    #[test]
    fn expression_windows_include_enclosing_calls_and_line_edges() {
        let data = b"previous\ncall(value)\r\nnext";
        // starting at the argument's closer widens back to the enclosing callee.
        assert_eq!(super::expression_span(data, 19, data.len()), Some(9..20));
        for start in 0..=data.len() + 1 {
            for budget in [0, 1, 5, data.len(), usize::MAX] {
                check_expression_bounds(data, start, budget);
            }
        }
    }
}
