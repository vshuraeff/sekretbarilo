//! open calls on the engine surfaces: a line that ends inside the argument list of a call is
//! claimed by the syntax exemption, while an opaque value inside that open group or naming its
//! callee is still reported by the diff scan, the text scan and redaction.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";

/// a path in full source posture, so the syntax step rather than the literal tracker decides.
const SOURCE_PATH: &str = "web/app.js";

/// call openers that the tier-3 rule reports without the exemption layer.
const OPENERS: &[&str] = &[
    "window.history.replaceState(",
    "    window.history.replaceState(",
    "hashlib.sha256(x.encode()",
    "log.Fatal(http.ListenAndServe(",
    "http.HandleFunc(mux.NewRouter().PathPrefix(",
    "let config = CompiledAllowlist::from_config(",
    "self.navigationController?.pushViewController(",
    "dev->netdev_ops->ndo_start_xmit(skb,",
];

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    compile_rules(&load_default_rules().expect("default rules load"))
        .expect("default rules compile")
});

fn allowlist() -> CompiledAllowlist {
    let rules = load_default_rules().expect("default rules load");
    build_allowlist(&ProjectConfig::default(), &rules).expect("default allowlist")
}

/// alternating case with a digit at every fifth index: no word structure, entropy above the gate.
fn opaque(seed: usize) -> String {
    (0..32)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + ((index + seed) % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7 + seed) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

fn diff_file(line: &str) -> DiffFile {
    DiffFile {
        path: SOURCE_PATH.to_owned(),
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

fn entropy_rules(text: &str, allowlist: &CompiledAllowlist) -> Vec<String> {
    scan_text(text, &SCANNER, allowlist)
        .into_iter()
        .map(|matched| matched.rule_id)
        .collect()
}

#[test]
fn open_call_openers_are_exempt_on_every_surface() {
    let al = allowlist();
    let mut off = allowlist();
    off.exemption_layer = false;
    let mut traced = allowlist();
    traced.trace_exemptions = true;
    for opener in OPENERS {
        assert_eq!(
            entropy_rules(opener, &off),
            [ENTROPY],
            "the opener must reach the rule without the layer: {opener}"
        );
        assert!(
            scan(&[diff_file(opener)], &SCANNER, &al).is_empty(),
            "diff scan: {opener}"
        );
        assert_eq!(
            entropy_rules(opener, &traced),
            ["exempt:syntax"],
            "{opener}"
        );
        for eol in ["", "\n", "\r\n"] {
            let text = format!("{opener}{eol}  state,{eol}  title,{eol}){eol}");
            assert!(entropy_rules(&text, &al).is_empty(), "text scan: {text:?}");
            assert_eq!(
                redact_text(&text, &SCANNER, &al),
                text,
                "redaction: {text:?}"
            );
        }
    }
}

#[test]
fn open_call_opaque_values_are_still_reported() {
    let al = allowlist();
    for (seed, (prefix, suffix)) in [
        ("foo(", ""),
        ("foo.bar(", ""),
        ("hashlib.sha256(", ""),
        ("window.history.replaceState(", ","),
        ("digest = foo.bar(", ""),
        ("store.dispatch(setUserProfile({", ""),
        ("", "("),
        ("window.", "("),
    ]
    .into_iter()
    .enumerate()
    {
        let secret = opaque(seed);
        let line = format!("{prefix}{secret}{suffix}");
        let start = line.find(&secret).expect("generated value is present");
        let end = start + secret.len();
        for eol in ["", "\n", "\r\n"] {
            let text = format!("{line}{eol}");
            let covered = scan_text(&text, &SCANNER, &al).iter().any(|matched| {
                matched.rule_id == ENTROPY
                    && matched.range.start <= start
                    && matched.range.end >= end
            });
            assert!(covered, "text scan must cover the value: {text:?}");
            assert!(
                !redact_text(&text, &SCANNER, &al).contains(&secret),
                "redaction must mask the value: {text:?}"
            );
        }
        let findings = scan(&[diff_file(&line)], &SCANNER, &al);
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == ENTROPY
                    && finding
                        .matched_value
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes())
            }),
            "diff scan must carry the value: {line}"
        );
    }
}

/// an opaque value with one opener inside reads like `name(argument`. neither piece is long enough
/// for the token veto, so only the rule that an open call breaks after an opener, a separator or a
/// closed group keeps it reported.
#[test]
fn opaque_values_split_by_an_opener_are_still_reported() {
    let al = allowlist();
    for (seed, opener) in ["(", "[", "{"].into_iter().enumerate() {
        let token = opaque(seed);
        let value = format!("{}{opener}{}", &token[1..8], &token[8..25]);
        for line in [value.clone(), format!("SESSION_SECRET={value}")] {
            let start = line.find(&value).expect("generated value is present");
            let exact = scan_text(&line, &SCANNER, &al).iter().any(|matched| {
                matched.rule_id == ENTROPY && matched.range == (start..start + value.len())
            });
            assert!(exact, "text scan must report the value: {line}");
            let findings = scan(&[diff_file(&line)], &SCANNER, &al);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == ENTROPY && finding.matched_value == value.as_bytes()
                }),
                "diff scan must report the value: {line}"
            );
        }
    }
}
