// accepted recall cost: one opaque segment shorter than 20 bytes inside an otherwise wordy
// keyless relative path is no longer reported, the same class of cost as the existing ./-prefixed
// rooted-path exemption already accepts today.

use proptest::prelude::*;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{scan, scan_text};
use sekretbarilo::scanner::rules::{
    CompiledScanner, Rule, RuleAllowlist, compile_rules, load_default_rules,
};
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
const DIFF_PATH: &str = "notes/output.txt";

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

fn allowlist() -> CompiledAllowlist {
    let rules = load_default_rules().unwrap();
    build_allowlist(&ProjectConfig::default(), &rules).unwrap()
}

fn file(line: &str) -> DiffFile {
    DiffFile {
        path: DIFF_PATH.to_owned(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.as_bytes().to_vec(),
        }],
    }
}

fn assert_exempt(line: &str, allowlist: &CompiledAllowlist) {
    assert!(
        scan(&[file(line)], &SCANNER, allowlist).is_empty(),
        "{line}"
    );
    assert!(scan_text(line, &SCANNER, allowlist).is_empty(), "{line}");
}

fn assert_detected(line: &str, allowlist: &CompiledAllowlist) {
    assert_detected_with(&SCANNER, line, allowlist);
}

fn assert_detected_with(scanner: &CompiledScanner, line: &str, allowlist: &CompiledAllowlist) {
    assert!(
        scan(&[file(line)], scanner, allowlist)
            .iter()
            .any(|finding| finding.rule_id == ENTROPY),
        "diff scan missed {line}"
    );
    assert!(
        scan_text(line, scanner, allowlist)
            .iter()
            .any(|finding| finding.rule_id == ENTROPY),
        "text scan missed {line}"
    );
}

fn fragment_scanner() -> CompiledScanner {
    compile_rules(&[Rule {
        id: ENTROPY.to_owned(),
        description: "test-only bare fragment".to_owned(),
        regex_pattern: r"(?P<entropy_bare>[^\s]+)".to_owned(),
        secret_group: 1,
        secret_groups: Vec::new(),
        keywords: Vec::new(),
        entropy_threshold: Some(4.0),
        payload_group: None,
        min_payload_entropy: None,
        reject_hex_payload: false,
        allowlist: RuleAllowlist::default(),
        class: None,
    }])
    .unwrap()
}

struct XorShift64Star(u64);

impl XorShift64Star {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0 = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        self.0
    }
}

fn opaque_id(length: usize, seed: u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut random = XorShift64Star(seed);
    let mut id: Vec<_> = (0..length)
        .map(|_| ALPHABET[(random.next() as usize) % ALPHABET.len()])
        .collect();
    id[0] = b'A';
    id[1] = b'a';
    id[2] = b'7';
    String::from_utf8(id).unwrap()
}

fn relative_path(id: &str) -> String {
    format!("task/{id}/integrator/lead")
}

fn chunked_lowercase(seed: u64) -> String {
    const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
    let mut random = XorShift64Star(seed);
    (0..6)
        .map(|_| {
            (0..4)
                .map(|_| char::from(CONSONANTS[(random.next() as usize) % CONSONANTS.len()]))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[test]
fn relative_paths_with_one_short_id_are_exempt_on_both_surfaces() {
    let al = allowlist();
    for line in [
        "task/9zjEfcywkWlJ5QOj/integrator/lead",
        "task/9zjEfcywkWlJ5QOj/main/unit/t3-engine",
    ] {
        assert_exempt(line, &al);
    }

    let mut traced = allowlist();
    traced.trace_exemptions = true;
    assert!(
        scan_text("task/9zjEfcywkWlJ5QOj/integrator/lead", &SCANNER, &traced)
            .iter()
            .any(|finding| finding.rule_id == "exempt:relpath")
    );
}

#[test]
fn relative_path_controls_remain_detected() {
    let al = allowlist();
    let id = opaque_id(19, 0x5a17_2026);
    let value = relative_path(&id);
    let long_id = opaque_id(20, 0x5a17_2027);
    let second_id = opaque_id(19, 0x5a17_2028);
    let opaque_leaf = opaque_id(19, 0x5a17_2029);
    let chunks = chunked_lowercase(0x5a17_2030);

    for line in [
        relative_path(&long_id),
        format!("task/{id}/bucket/{second_id}/lead"),
        format!("token = {value}"),
        format!("task/{id}/integrator/{opaque_leaf}"),
        format!("task/{id}/lead"),
        format!("task://user:{id}@integrator/lead"),
        format!("task/{id}/{chunks}/lead"),
    ] {
        assert_detected(&line, &al);
    }

    // the production bare-line regex cannot capture a path fragment with same-line text.
    let fragment_scanner = fragment_scanner();
    assert_detected_with(&fragment_scanner, &format!("{value} trailing"), &al);

    let mut layer_off = allowlist();
    layer_off.exemption_layer = false;
    assert_detected(&value, &layer_off);
}

proptest! {
    #[test]
    fn short_mixed_or_digit_ids_are_exempt(id in prop::collection::vec(0usize..62, 8..20)) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut id: Vec<_> = id.into_iter().map(|index| ALPHABET[index]).collect();
        id[0] = b'A';
        id[1] = b'7';
        let id = String::from_utf8(id).unwrap();
        let value = relative_path(&id);
        let al = allowlist();

        prop_assert!(scan(&[file(&value)], &SCANNER, &al).is_empty());
        prop_assert!(scan_text(&value, &SCANNER, &al).is_empty());
    }
}
