//! url shapes at the engine: userinfo is read only in the authority, a form-encoded query list is
//! not a credential, sentence punctuation after a link closes the prose rather than the url, and
//! every credential-bearing url is still reported on the diff and text surfaces.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::sync::LazyLock;

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

static PASSWORD_SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let rules: Vec<_> = load_default_rules()
        .unwrap()
        .into_iter()
        .filter(|rule| rule.id == "password-in-url")
        .collect();
    compile_rules(&rules).unwrap()
});

static ALLOWLIST: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    build_allowlist(&ProjectConfig::default(), &load_default_rules().unwrap()).unwrap()
});

/// data files of the kinds the shapes come from; none selects the rust/go literal posture.
const PATHS: &[&str] = &[
    "docs/_layouts/default.html",
    "docs/assets/css/site.css",
    "docs/_pages/how-detection-works.md",
    "notes/shapes.txt",
];

const FONT_LINK: &str = r#"<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">"#;
const FONT_IMPORT_QUOTED: &str = "@import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');";
const FONT_IMPORT_BARE: &str = "@import url(https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,700;1,400&display=swap);";
const ADR_LINK_END: &str = "The layer is described in [ADR 0002](https://github.com/acme/widget/blob/master/docs/adr/0002-tier3-exemption-layer.md).";
const ADR_LINK_COLON: &str = "See [ADR 0001](https://github.com/acme/widget/blob/master/docs/adr/0001-entropy-baseline-8-char-password.md): it explains the baseline.";
const ADR_LINK_MID: &str = "[ADR 0001](https://github.com/acme/widget/blob/master/docs/adr/0001-entropy-baseline-8-char-password.md) explains the baseline.";
const ADR_RELATIVE_END: &str = "[ADR-0002](../adr/0002-tier3-exemption-layer.md).";

/// base62 bytes from xorshift64, so the suite stores no opaque value.
fn opaque(len: usize, seed: u64) -> String {
    const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(BASE62[(state % BASE62.len() as u64) as usize])
        })
        .collect()
}

fn file(path: &str, line: &str) -> DiffFile {
    DiffFile {
        path: path.to_owned(),
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

fn assert_clean(line: &str) {
    for path in PATHS {
        let findings = scan(&[file(path, line)], &SCANNER, &ALLOWLIST);
        let rules: Vec<_> = findings.iter().map(|found| &found.rule_id).collect();
        assert!(rules.is_empty(), "{path}: {rules:?} :: {line}");
    }
    let matches = scan_text(line, &SCANNER, &ALLOWLIST);
    assert!(matches.is_empty(), "text scan: {matches:?} :: {line}");
    assert_eq!(redact_text(line, &SCANNER, &ALLOWLIST), line);
}

fn assert_reported(line: &str, value: &str) {
    for path in PATHS {
        let findings = scan(&[file(path, line)], &SCANNER, &ALLOWLIST);
        assert!(
            findings.iter().any(|found| found
                .matched_value
                .windows(value.len())
                .any(|window| window == value.as_bytes())),
            "{path}: no finding carries the value :: {line}"
        );
    }
    let start = line.find(value).unwrap();
    let end = start + value.len();
    let matches = scan_text(line, &SCANNER, &ALLOWLIST);
    assert!(
        matches
            .iter()
            .any(|found| found.range.start <= start && found.range.end >= end),
        "text scan: no match covers the value, got {matches:?} :: {line}"
    );
    assert!(!redact_text(line, &SCANNER, &ALLOWLIST).contains(value));
}

fn traced_rules(line: &str) -> Vec<String> {
    let mut traced =
        build_allowlist(&ProjectConfig::default(), &load_default_rules().unwrap()).unwrap();
    traced.trace_exemptions = true;
    let mut rules: Vec<_> = scan_text(line, &SCANNER, &traced)
        .into_iter()
        .map(|found| found.rule_id)
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

#[test]
fn font_stylesheet_urls_are_not_credentials() {
    for line in [
        FONT_LINK,
        FONT_IMPORT_QUOTED,
        FONT_IMPORT_BARE,
        "https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap",
        r#"fonts = "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200""#,
    ] {
        assert_clean(line);
        assert_eq!(traced_rules(line), ["exempt:url"], "{line}");
    }
}

#[test]
fn links_closing_a_sentence_are_not_credentials() {
    for line in [ADR_LINK_END, ADR_LINK_COLON] {
        assert_clean(line);
        assert_eq!(traced_rules(line), ["exempt:url"], "{line}");
    }
    assert_clean(ADR_LINK_MID);
    assert_clean(ADR_RELATIVE_END);
    assert_eq!(traced_rules(ADR_RELATIVE_END), ["exempt:path"]);
}

#[test]
fn userinfo_in_the_authority_is_still_reported() {
    let secret = opaque(32, 1);
    for line in [
        format!("remote = \"https://deploy:{secret}@git.example.internal/acme/widget.git\""),
        format!("https://deploy:{secret}@git.example.internal/acme/widget/blob/master/README.md"),
        format!("REDIS_URL=redis://:{secret}@cache.example.internal:6379/0"),
        format!(
            "fonts = \"https://deploy:{secret}@fonts.example.internal/css2?family=Roboto+Mono:wght@400;700\""
        ),
        format!(
            "Clone [the mirror](https://deploy:{secret}@git.example.internal/acme/widget.git)."
        ),
    ] {
        assert_reported(&line, &secret);
    }
}

fn assert_password_rule(value: &str, expected: bool) {
    let line = format!("let endpoint = \"https://deploy:{value}@git.example.internal/repo\";");
    for path in PATHS
        .iter()
        .copied()
        .chain(["src/main.swift", "scripts/connect.sh"])
    {
        let findings = scan(&[file(path, &line)], &PASSWORD_SCANNER, &ALLOWLIST);
        assert_eq!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "password-in-url"),
            expected,
            "{path}: wrong password rule result"
        );
    }
    let findings = scan_text(&line, &PASSWORD_SCANNER, &ALLOWLIST);
    assert_eq!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "password-in-url"),
        expected,
        "text: wrong password rule result"
    );
    let redacted = redact_text(&line, &PASSWORD_SCANNER, &ALLOWLIST);
    if expected {
        assert!(
            !redacted.contains(&format!("deploy:{value}@")),
            "password was left unmasked"
        );
    } else {
        assert!(redacted == line, "reference was redacted");
    }
}

#[test]
fn a_shell_parameter_must_fill_the_password_component() {
    for reference in [
        "${NAME}",
        "${NAME:-}",
        "${NAME-}",
        "${NAME:=}",
        "${NAME:-$OTHER}",
        "${CI_TOKEN:-${CI_JOB_TOKEN}}",
        "${NAME:-changeme}",
        "${NAME:?x}",
        "${NAME:?unset}",
    ] {
        assert_password_rule(reference, false);
        for value in [
            format!("{reference}literal"),
            format!("literal{reference}"),
            format!("{reference}${{OTHER}}"),
            format!("{reference}literal${{OTHER}}"),
        ] {
            assert_password_rule(&value, true);
        }
    }
    // a `-`/`=` default is the password while the variable is unset, so it is judged as a bare
    // password: a literal word is as much a finding there as in the url itself.
    let secret = opaque(32, 21);
    for operator in [":-", "-", ":?", ":="] {
        assert_password_rule(&format!("${{NAME{operator}{secret}}}"), true);
    }
    for operator in [":-", "-", ":=", "="] {
        for default in ["x", "secret", "realpass", "Passw0rd"] {
            assert_password_rule(&format!("${{NAME{operator}{default}}}"), true);
            assert_password_rule(default, true);
        }
        assert_password_rule(&format!("${{NAME{operator}${{OTHER:-{secret}}}}}"), true);
    }
    assert_password_rule("${NAME:+x}", true);
    assert_password_rule("${NAME!x}", true);
    assert_password_rule("${NAME:-x", true);
    assert_password_rule(&secret, true);
}

#[test]
fn nested_defaults_are_bounded_and_still_judged() {
    let nest = |depth: usize, inner: &str| {
        format!("{}{inner}{}", "${A:-".repeat(depth), "}".repeat(depth))
    };
    // five expansions are the deepest reference: four defaults wrapping one more
    assert_password_rule(&nest(4, "${B}"), false);
    assert_password_rule(&nest(5, "${B}"), true);
    assert_password_rule(&nest(8, "${B}"), true);
    assert_password_rule(&nest(3, "realpass"), true);
    // a crafted nesting deep enough to exhaust the stack of an unbounded reader
    let line = format!(
        "https://deploy:{}@git.example.internal/repo",
        nest(100_000, "realpass")
    );
    assert!(
        scan_text(&line, &PASSWORD_SCANNER, &ALLOWLIST)
            .iter()
            .any(|finding| finding.rule_id == "password-in-url")
    );
    assert_ne!(redact_text(&line, &PASSWORD_SCANNER, &ALLOWLIST), line);
}

#[test]
fn one_reference_alternative_never_spans_two_url_parts() {
    for line in [
        "url = http://localhost:${PORT}?to=${USER}@${DOMAIN}",
        "url = http://localhost:${PORT}#to=${USER}@${DOMAIN}",
        r#"let url = "http://localhost:\(port)?to=\(user)@\(domain)""#,
        r#"let url = "http://localhost:\(port)#to=\(user)@\(domain)""#,
    ] {
        assert!(
            scan_text(line, &PASSWORD_SCANNER, &ALLOWLIST).is_empty(),
            "{line}"
        );
        assert_eq!(redact_text(line, &PASSWORD_SCANNER, &ALLOWLIST), line);
    }
}

#[test]
fn every_url_of_an_unseparated_run_is_reported() {
    // a host part running to the next whitespace once swallowed every url after the first
    let secret = opaque(16, 32);
    let count = 2_000;
    let line = format!(
        "x{}",
        format!("https://user:{secret}@host.example/").repeat(count)
    );
    assert_eq!(scan_text(&line, &PASSWORD_SCANNER, &ALLOWLIST).len(), count);
    assert!(!redact_text(&line, &PASSWORD_SCANNER, &ALLOWLIST).contains(&secret));
}

#[test]
fn a_skipped_reference_never_hides_the_next_url_of_a_list() {
    let secret = opaque(24, 31);
    for reference in ["${PG_PASS:?}", "${PG_PASS}", "${PG_PASS:-}", r"\(cfg?.pw)"] {
        for separator in [",", " ", "/"] {
            let line = format!(
                "URLS=postgres://app:{reference}@db:5432/app{separator}redis://default:{secret}@cache:6379"
            );
            let findings = scan_text(&line, &PASSWORD_SCANNER, &ALLOWLIST);
            assert_eq!(findings.len(), 1, "{reference}{separator}");
            let start = line.rfind(&secret).unwrap();
            assert_eq!(findings[0].range, start..start + secret.len());
            let redacted = redact_text(&line, &PASSWORD_SCANNER, &ALLOWLIST);
            assert!(!redacted.contains(&secret));
            assert!(redacted.contains(reference));
            let findings = scan(
                &[file("deploy/env.sh", &line)],
                &PASSWORD_SCANNER,
                &ALLOWLIST,
            );
            assert_eq!(findings.len(), 1, "diff {reference}{separator}");
        }
    }
}

#[test]
fn a_swift_interpolation_must_fill_the_password_component() {
    for reference in [
        r"\(value)",
        r"\#(value)",
        r"\##(value)",
        r"\(config.password)",
        r"\#(config?.password)",
        r"\(value.prefix(8))",
    ] {
        assert_password_rule(reference, false);
        for value in [
            format!("{reference}abc"),
            format!("abc{reference}"),
            format!("{reference}{}", r"\(other)"),
            format!("{reference}literal{}", r"\(other)"),
        ] {
            assert_password_rule(&value, true);
        }
    }
    let secret = opaque(32, 22);
    for value in [
        format!(r"\({secret})"),
        format!(r"\#({secret})"),
        format!(r"\(value({secret}))"),
        format!(r"\(value){secret}"),
        format!(r"{secret}\#(value)"),
        r"\\(value)".to_owned(),
        r"\(value".to_owned(),
    ] {
        assert_password_rule(&value, true);
    }
}

#[test]
fn inline_markdown_code_preserves_secret_assignment_detection() {
    let rules = load_rules_with_config(&ProjectConfig::default()).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let secret = opaque(64, 23);
    let line = format!("The setting is `{{\"secret\":\"{secret}\"}}` in the example.");
    for path in ["notes/review.md", "notes/review.txt"] {
        let findings = scan(&[file(path, &line)], &scanner, &ALLOWLIST);
        let ids: Vec<_> = findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert!(
            ids.contains(&"generic-secret-assignment"),
            "{path}: {ids:?}"
        );
    }
    assert!(
        scan_text(&line, &scanner, &ALLOWLIST)
            .iter()
            .any(|finding| finding.rule_id == "generic-secret-assignment")
    );
    assert!(!redact_text(&line, &scanner, &ALLOWLIST).contains(&secret));
}

#[test]
fn opaque_query_values_and_list_fields_are_still_reported() {
    let secret = opaque(32, 2);
    for line in [
        format!(
            "<link rel=\"stylesheet\" href=\"https://fonts.example.internal/css2?family=Roboto+Mono:{secret}@400&display=swap\">"
        ),
        format!(
            "@import url(https://fonts.example.internal/css2?family=Roboto+Mono:wght@400;700&key={secret});"
        ),
        format!("endpoint = \"https://api.example.internal/v1/export?token={secret}\""),
        format!("endpoint = \"https://api.example.internal/v1/export?x={secret}&format=csv\""),
        format!("endpoint = \"https://api.example.internal/v1/export?q=Roboto+Mono+{secret}\""),
    ] {
        assert_reported(&line, &secret);
    }
}

#[test]
fn opaque_path_segments_are_still_reported_after_closing_prose() {
    let secret = opaque(32, 3);
    for line in [
        format!("endpoint = \"https://files.example.internal/download/{secret}\""),
        format!("Fetch [the export](https://files.example.internal/download/{secret})."),
        format!("[export](https://files.example.internal/download/{secret})"),
        format!("Fetch [the export](https://files.example.internal/download/{secret}):"),
        format!("The export lives at <https://files.example.internal/download/{secret}>."),
        format!("[export](https://files.example.internal/blob/master/{secret}.md)?"),
    ] {
        assert_reported(&line, &secret);
    }
}
