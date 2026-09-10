mod common;

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
const URL_PASSWORD: &str = "password-in-url";
const ASSIGNMENT_PASSWORD: &str = "generic-password-assignment";
const HUMMINGBOT: &str = "hummingbot.strategy.strategy_v2_base.ExecutorOrchestrator";
const COMPARE_URL: &str = "https://github.com/owner/repo/compare/v1.0.0...v1.1.0";

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

fn allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().unwrap()
}

fn token(seed: usize) -> String {
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

fn interleaved_token(seed: usize) -> String {
    (0..32)
        .map(|index| {
            let byte = if index % 3 == 1 {
                b'0' + ((index * 3 + seed) % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'a' } else { b'A' };
                base + ((index * 11 + seed) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

fn uppercase_token(seed: usize) -> String {
    (0..24)
        .map(|index| char::from(b'A' + ((index * 7 + seed) % 26) as u8))
        .collect()
}

fn base64url_token(seed: usize) -> String {
    (0..24)
        .map(|index| match (index * 11 + seed) % 64 {
            value @ 0..=25 => char::from(b'A' + value as u8),
            value @ 26..=51 => char::from(b'a' + (value - 26) as u8),
            value @ 52..=61 => char::from(b'0' + (value - 52) as u8),
            62 => '-',
            _ => '_',
        })
        .collect()
}

fn hex(length: usize, seed: u64) -> String {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            char::from_digit((state >> 60) as u32, 16).unwrap()
        })
        .collect()
}

fn hex_symbol_entropy(value: &[u8]) -> f64 {
    let payload = value
        .strip_prefix(b"0x")
        .or_else(|| value.strip_prefix(b"0X"))
        .unwrap_or(value);
    let mut counts = [0_u32; 16];
    for byte in payload {
        let symbol = match byte.to_ascii_lowercase() {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte.to_ascii_lowercase() - b'a' + 10,
            _ => panic!("expected a hex fixture"),
        };
        counts[usize::from(symbol)] += 1;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = f64::from(count) / payload.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn distributed_hex(counts: &[usize]) -> String {
    let mut remaining = counts.to_vec();
    let mut value = String::new();
    while remaining.iter().any(|&count| count > 0) {
        for (symbol, count) in remaining.iter_mut().enumerate() {
            if *count > 0 {
                value.push(char::from_digit(symbol as u32, 16).unwrap());
                *count -= 1;
            }
        }
    }
    value
}

fn make_file(path: &str, line: &str) -> DiffFile {
    DiffFile {
        path: path.to_owned(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.as_bytes().to_vec(),
        }],
    }
}

fn check_scan(path: &str, line: &str, expected: &[(&str, &str)], al: &CompiledAllowlist) {
    let findings = scan(&[make_file(path, line)], &SCANNER, al);
    let mut actual: Vec<_> = findings
        .iter()
        .map(|finding| {
            assert_eq!(finding.file, path);
            assert_eq!(finding.line, 1);
            (finding.rule_id.as_str(), finding.matched_value.as_slice())
        })
        .collect();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(id, value)| (*id, value.as_bytes()))
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected, "diff scan: {line}");
}

fn check(line: &str, expected: &[(&str, &str)], al: &CompiledAllowlist) {
    check_scan("src/x.rs", line, expected, al);
    let matches = scan_text(line, &SCANNER, al);
    let mut actual: Vec<_> = matches
        .iter()
        .map(|matched| {
            (
                matched.rule_id.as_str(),
                matched.range.start,
                matched.range.end,
            )
        })
        .collect();
    let mut wanted: Vec<_> = expected
        .iter()
        .map(|(id, value)| {
            let start = line.rfind(value).expect("expected span occurs in input");
            (*id, start, start + value.len())
        })
        .collect();
    actual.sort();
    wanted.sort();
    assert_eq!(actual, wanted, "text scan: {line}");

    let mut ranges: Vec<_> = wanted
        .iter()
        .map(|(_, start, end)| (*start, *end))
        .collect();
    ranges.sort();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start < last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    let mut masked = line.to_owned();
    for (start, end) in merged.into_iter().rev() {
        masked.replace_range(start..end, "[REDACTED]");
    }
    assert_eq!(redact_text(line, &SCANNER, al), masked, "redaction: {line}");
}

// q15: literal extraction inside urls is deferred; broader entropy findings are allowed.
// still require the specified rule/span and agreement on every finding and masked span.
fn check_rule(
    line: &str,
    rule_id: &str,
    value: Option<&str>,
    allow_covering: bool,
    al: &CompiledAllowlist,
) {
    let matches = scan_text(line, &SCANNER, al);
    let selected: Vec<_> = matches
        .iter()
        .filter(|matched| matched.rule_id == rule_id)
        .collect();
    if let Some(value) = value {
        let start = line.rfind(value).unwrap();
        let end = start + value.len();
        assert!(
            selected.iter().any(|matched| {
                if allow_covering {
                    matched.range.start <= start && matched.range.end >= end
                } else {
                    matched.range == (start..end)
                }
            }),
            "missing {rule_id} span for {line}"
        );
        if rule_id == URL_PASSWORD {
            assert_eq!(
                selected.len(),
                1,
                "only the literal password should be flagged: {line}"
            );
        }
    } else {
        assert!(
            selected.is_empty(),
            "unexpected {rule_id} finding for {line}"
        );
    }
    let expected: Vec<_> = matches
        .iter()
        .map(|matched| (matched.rule_id.as_str(), &line[matched.range.clone()]))
        .collect();
    check(line, &expected, al);
}

fn safe_forms() -> Vec<String> {
    vec![
        r##"Regex::new(r"[a-z]+")"##.into(),
        "CompiledAllowlist::from_config(&config, &rules).unwrap()".into(),
        r##"container.querySelector<HTMLElement>(".wui-kanban__card")"##.into(),
        "String.fromCodePoint(0x2588)".into(),
        format!(
            "S(0x{},0x{})",
            (0..16)
                .map(|i| char::from_digit(i, 16).unwrap())
                .collect::<String>(),
            (0..16)
                .rev()
                .map(|i| char::from_digit(i, 16).unwrap())
                .collect::<String>()
        ),
        "sum(rate(node_tcp_connections[5m]))".into(),
        "pthread_mutex_unlock(&spawn_lock);".into(),
        "[]Entry{Entry{Value: otherValue}}".into(),
        "resolverObject?.acceptLeaderSnapshotNow(items)".into(),
        ".deletingLastPathComponent()".into(),
        "refreshGateway.noteLifecycleChangeHappened();".into(),
        r##"runtime.environment["ENVVAR"],"##.into(),
        "foo.bar(baz);".into(),
        r##"assert!(is_hex_policy_candidate(Some(b"value"), &bytes))"##.into(),
    ]
}

#[test]
fn syntax_forms_and_adjacent_secrets() {
    let al = allowlist();
    let forms = safe_forms();
    assert_eq!(forms.len(), 14);
    for (index, form) in forms.iter().enumerate() {
        check(form, &[], &al);
        check(&format!("value = {form}"), &[], &al);
        let secret = token(index);
        check(
            &format!("{form} ;TOKEN={secret}"),
            &[(ENTROPY, &secret)],
            &al,
        );
        check(
            &format!("let token = \"{secret}\";"),
            &[(ENTROPY, &secret)],
            &al,
        );
    }
}

#[test]
fn urls_keep_credential_spans() {
    let al = allowlist();
    check(&format!("Full diff: {COMPARE_URL}"), &[], &al);
    let secret = interleaved_token(21);
    let query = format!("https://host/?token={secret}");
    check_rule(&query, ENTROPY, Some(&secret), true, &al);
    let url = format!("https://user:{secret}@host/");
    check_rule(&url, URL_PASSWORD, Some(&secret), false, &al);
}

#[test]
fn pinned_action_references() {
    let al = allowlist();
    check(&format!("uses: actions/checkout@{}", hex(40, 31)), &[], &al);
    let value = format!("actions/checkout@{}", token(32));
    check(&format!("uses: {value}"), &[(ENTROPY, &value)], &al);
}

#[test]
fn path_scoped_exemptions_preserve_prefix_rules() {
    let al = allowlist();
    let secret = token(41);
    check_scan(".gitignore", &secret, &[], &al);
    let suffix: String = (0..16)
        .map(|i| char::from(b'A' + ((i * 7 + 3) % 26) as u8))
        .collect();
    let key = format!("AKIA{suffix}");
    check_scan(
        ".gitignore",
        &format!("{secret} {key}"),
        &[("aws-access-key-id", &key)],
        &al,
    );
    assert!(al.is_path_skipped("bun.lock"));
    check_scan("bun.lock", &secret, &[], &al);
}

#[test]
fn imports_and_similarly_named_assignments() {
    let al = allowlist();
    let secret = interleaved_token(51);
    check(&format!("use crate::{secret};"), &[], &al);
    check(&format!("import_key={secret}"), &[(ENTROPY, &secret)], &al);
}

#[test]
fn markdown_targets() {
    let al = allowlist();
    check("[docs](https://host/path/{key}/stamp.md)", &[], &al);
    let secret = token(61);
    check_rule(
        &format!("[x](https://host/?t={secret})"),
        ENTROPY,
        Some(&secret),
        true,
        &al,
    );
}

#[test]
fn exact_length_hex_assignments() {
    let al = allowlist();
    let contextual = hex(40, 126);
    check(&format!("checksum secret = \"{contextual}\""), &[], &al);
    check(
        &format!("secret = \"{contextual}\""),
        &[
            (ENTROPY, &contextual),
            ("generic-secret-assignment", &contextual),
        ],
        &al,
    );
    for (key, length, seed, quote, prefix) in [
        ("API_KEY=", 32, 71, "", ""),
        ("api_key: ", 40, 72, "\"", ""),
        ("PRIVATE_KEY=", 32, 73, "", "0x"),
        ("PRIVATE_KEY=", 40, 74, "", "0x"),
        ("PRIVATE_KEY=", 64, 75, "", "0x"),
    ] {
        let value = format!("{prefix}{}", hex(length, seed));
        if prefix == "0x" && matches!(length, 32 | 40) {
            assert!(hex_symbol_entropy(value.as_bytes()) < 4.0);
        }
        check(
            &format!("{key}{quote}{value}{quote}"),
            &[(ENTROPY, &value)],
            &al,
        );
    }
    let upper = hex(32, 76).to_ascii_uppercase();
    check(&format!("API_KEY={upper}"), &[(ENTROPY, &upper)], &al);
    for (key, length, seed, quote) in [
        ("commit = ", 40, 77, "\""),
        ("sha256: ", 64, 78, ""),
        ("etag: ", 32, 79, "\""),
        ("", 32, 80, ""),
        ("x = ", 31, 81, "\""),
        ("x = ", 20, 82, "\""),
    ] {
        check(
            &format!("{key}{quote}{}{quote}", hex(length, seed)),
            &[],
            &al,
        );
    }
    check(&format!("commit = 0x{}", hex(40, 83)), &[], &al);
}

#[test]
fn hex_floor_boundaries_and_capture_kinds() {
    let al = allowlist();
    let repeated = ["a".repeat(16), "b".repeat(16)].concat();
    assert_eq!(hex_symbol_entropy(repeated.as_bytes()), 1.0);
    check(&format!("SESSION={repeated}"), &[], &al);

    // four equally frequent symbols give exactly 2.0 bits; one transferred byte is below it.
    let boundary = distributed_hex(&[8, 8, 8, 8]);
    let below = distributed_hex(&[9, 8, 8, 7]);
    assert_eq!(hex_symbol_entropy(boundary.as_bytes()), 2.0);
    assert!(hex_symbol_entropy(below.as_bytes()) < 2.0);
    check(&format!("SESSION={boundary}"), &[(ENTROPY, &boundary)], &al);
    check(&format!("SESSION={below}"), &[], &al);

    // probabilities 1/2, 1/8, 1/8, 1/8, 1/16, 1/16 give exactly 2.125 bits.
    let skewed = distributed_hex(&[16, 4, 4, 4, 2, 2]);
    assert_eq!(hex_symbol_entropy(skewed.as_bytes()), 2.125);
    check(&format!("SESSION='{skewed}'"), &[(ENTROPY, &skewed)], &al);

    // four counts of four and eight counts of two give exactly 3.5 bits in 32 bytes.
    let diverse = distributed_hex(&[4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2]);
    assert_eq!(hex_symbol_entropy(diverse.as_bytes()), 3.5);
    check(
        &format!("SESSION=\"{diverse}\""),
        &[(ENTROPY, &diverse)],
        &al,
    );

    for (length, seed, open, close, prefix) in [
        (32, 121, "", "", ""),
        (40, 122, "'", "'", ""),
        (64, 123, "[", "]", ""),
        (64, 124, "\"", "\"", "0x"),
        (64, 125, "", "", "0X"),
    ] {
        let lower = hex(length, seed);
        let mixed: String = lower
            .bytes()
            .enumerate()
            .map(|(index, byte)| {
                char::from(if index % 2 == 0 {
                    byte.to_ascii_uppercase()
                } else {
                    byte
                })
            })
            .collect();
        for payload in [&lower, &lower.to_ascii_uppercase(), &mixed] {
            let value = format!("{prefix}{payload}");
            assert!(hex_symbol_entropy(value.as_bytes()) >= 2.0);
            check(
                &format!("SESSION={open}{value}{close}"),
                &[(ENTROPY, &value)],
                &al,
            );
        }
    }

    // case folding keeps four byte spellings of two hex symbols at 1.0 bit.
    let mixed_low: String = (0..32)
        .map(|index| char::from(b"aAbB"[index % 4]))
        .collect();
    assert_eq!(hex_symbol_entropy(mixed_low.as_bytes()), 1.0);
    check(&format!("SESSION={mixed_low}"), &[], &al);
    for prefix in ["0x", "0X"] {
        let value = format!("{prefix}{}", distributed_hex(&[18, 16, 16, 14]));
        assert!(hex_symbol_entropy(value.as_bytes()) < 2.0);
        check(&format!("SESSION={value}"), &[], &al);
    }

    let prefixed_low = format!("0x{}", distributed_hex(&[9, 8, 8, 7]));
    assert!(hex_symbol_entropy(prefixed_low.as_bytes()) < 2.0);
    check(&format!("PRIVATE_KEY={prefixed_low}"), &[], &al);

    let mut traced = allowlist();
    traced.trace_exemptions = true;
    check(&format!("SESSION={repeated}"), &[], &traced);
    let mut disabled = allowlist();
    disabled.exemption_layer = false;
    check(&format!("SESSION={boundary}"), &[], &disabled);
}

#[test]
#[ignore]
fn hex_floor_calibration() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for length in [32, 40, 64] {
        let mut minimum = f64::INFINITY;
        for _ in 0..1_000_000 {
            let mut value = [0_u8; 64];
            for byte in &mut value[..length] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let symbol = (state >> 60) as u8;
                *byte = if symbol < 10 {
                    b'0' + symbol
                } else {
                    b'a' + symbol - 10
                };
            }
            minimum = minimum.min(hex_symbol_entropy(&value[..length]));
        }
        eprintln!("hex_floor_calibration length={length} samples=1000000 minimum={minimum:.12}");
        assert!(
            minimum >= 2.0,
            "{length}-hex sample below the floor: {minimum}"
        );
    }
}

#[test]
fn word_structured_targets() {
    let al = allowlist();
    check(&format!("target = {HUMMINGBOT}"), &[], &al);
    let secret = interleaved_token(81);
    check(&format!("target = {secret}"), &[(ENTROPY, &secret)], &al);
    check(
        r##"label: runtime.environment["CONFIG_ENVIRONMENT_NAME"],"##,
        &[],
        &al,
    );
}

#[test]
fn url_password_literals_and_references() {
    let al = allowlist();
    for (user, password) in [
        ("user", "secret"),
        ("user", "a"),
        ("user", "1234"),
        ("user", "changeme2"),
        ("admin", "admin"),
        ("user", "aaaaaaaa"),
        ("user", "p%40ss"),
        ("user", "${PASSWORD:-realpass}"),
    ] {
        let url = format!("https://{user}:{password}@host/");
        check_rule(&url, URL_PASSWORD, Some(password), false, &al);
    }
    for password in [
        "password",
        "${PASSWORD}",
        "$PASSWORD",
        "<PASSWORD>",
        "xxxxxxxx",
    ] {
        let url = format!("https://user:{password}@host/");
        check_rule(&url, URL_PASSWORD, None, false, &al);
    }
    check("https://host/", &[], &al);
    let reference = "${PASSWORD}";
    let literal = "secret";
    check_rule(
        &format!("https://user:{reference}@host/ https://user:{literal}@host/"),
        URL_PASSWORD,
        Some(literal),
        false,
        &al,
    );
}

#[test]
fn pwd_exception_is_case_sensitive_and_rule_scoped() {
    let al = allowlist();
    check("PWD=/Users/example/work/project", &[], &al);
    check("OLDPWD=/Users/example/work", &[], &al);
    for (index, key) in ["pwd", "DB_PWD", "foo.PWD", "PASSWORD"].iter().enumerate() {
        let password = format!("{}!", &interleaved_token(91 + index)[..16]);
        check(
            &format!("{key}={password}"),
            &[(ASSIGNMENT_PASSWORD, &password)],
            &al,
        );
    }
    let secret = token(96);
    check(&format!("PWD={secret}"), &[(ENTROPY, &secret)], &al);
    for key in ["PWD", "OLDPWD"] {
        for quote in ["", "\"", "'", "`"] {
            let expected = if quote == "`" {
                vec![]
            } else {
                vec![(ENTROPY, secret.as_str())]
            };
            check(&format!("{quote}{key}{quote}={secret}"), &expected, &al);
        }
    }
}

#[test]
fn facebook_prefix_rejects_hex_only_suffixes() {
    let al = allowlist();
    let value = format!("EAA{}", hex(29, 101));
    check(&value, &[], &al);
    let value = format!("EAA{}", &interleaved_token(102)[..29]);
    // a non-hex facebook token can also satisfy the generic entropy rule.
    check_rule(&value, "facebook-access-token", Some(&value), false, &al);
}

#[test]
fn exemption_switch_restores_plain_entropy_gate() {
    let mut al = allowlist();
    al.exemption_layer = false;
    let form = "sum(rate(node_tcp_connections[5m]))";
    check(form, &[(ENTROPY, form)], &al);
    check(
        &format!("Full diff: {COMPARE_URL}"),
        &[(ENTROPY, COMPARE_URL)],
        &al,
    );
    check(
        &format!("target = {HUMMINGBOT}"),
        &[(ENTROPY, HUMMINGBOT)],
        &al,
    );
    check(&format!("commit = \"{}\"", hex(40, 111)), &[], &al);
}

#[test]
fn trace_url_exemption_is_opt_in() {
    let mut al = allowlist();
    let line = format!("Full diff: {COMPARE_URL}");
    check(&line, &[], &al);
    al.trace_exemptions = true;
    check(&line, &[("exempt:url", COMPARE_URL)], &al);
    al.trace_exemptions = false;
    check(&line, &[], &al);
}

#[test]
fn url_shaped_values_skip_non_url_exemptions() {
    let al = allowlist();
    let uppercase = uppercase_token(9);
    let url = format!("https://host/{uppercase}");
    let captured_url = &url["https:".len()..];
    let markdown = format!("[link]({url})");
    check(&markdown, &[(ENTROPY, captured_url)], &al);

    let mut traced = allowlist();
    traced.trace_exemptions = true;
    check(&markdown, &[(ENTROPY, captured_url)], &traced);

    check(&url, &[(ENTROPY, &url)], &al);
    check(&format!("url = \"{url}\""), &[(ENTROPY, &url)], &al);
    check(
        "[docs](https://example.com/getting-started/installation)",
        &[],
        &al,
    );

    let base64url = base64url_token(19);
    let base64url = format!("https://host/{base64url}");
    let captured_base64url = &base64url["https:".len()..];
    check(
        &format!("[link]({base64url})"),
        &[(ENTROPY, captured_base64url)],
        &al,
    );
    check("some-random-words-here-ok", &[], &al);
}

#[test]
fn opaque_hex_call_matches_the_base_rule_with_or_without_the_exemption_layer() {
    let value = distributed_hex(&[3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2]);
    assert_eq!(value.len(), 40);
    assert!(hex_symbol_entropy(value.as_bytes()) < 4.0);

    for line in [format!("foo({value})"), format!("let d = foo({value});")] {
        let on = allowlist();
        let mut off = allowlist();
        off.exemption_layer = false;

        let on_text = scan_text(&line, &SCANNER, &on);
        let off_text = scan_text(&line, &SCANNER, &off);
        assert_eq!(on_text, off_text, "text scan changed for {line}");

        let hex_start = line.rfind(&value).unwrap();
        assert!(on_text.iter().any(|matched| {
            matched.rule_id == ENTROPY
                && matched.range.start <= hex_start
                && matched.range.end >= hex_start + value.len()
        }));

        let on_findings: Vec<_> = scan(&[make_file("src/x.rs", &line)], &SCANNER, &on)
            .into_iter()
            .map(|finding| (finding.rule_id, finding.matched_value))
            .collect();
        let off_findings: Vec<_> = scan(&[make_file("src/x.rs", &line)], &SCANNER, &off)
            .into_iter()
            .map(|finding| (finding.rule_id, finding.matched_value))
            .collect();
        assert_eq!(on_findings, off_findings, "diff scan changed for {line}");
        assert!(on_findings.iter().any(|(rule_id, matched_value)| {
            rule_id == ENTROPY
                && matched_value
                    .windows(value.len())
                    .any(|window| window == value.as_bytes())
        }));
    }
}

#[test]
fn opaque_hex_veto_preserves_the_existing_safe_forms() {
    let al = allowlist();
    let forms = safe_forms();
    assert_eq!(forms.len(), 14);
    for form in forms {
        check(&form, &[], &al);
    }
}

fn check_call_bodies(line: &str, bodies: &[&str], al: &CompiledAllowlist) {
    let mut ranges: Vec<_> = bodies
        .iter()
        .flat_map(|body| {
            line.match_indices(body)
                .map(|(start, value)| start..start + value.len())
        })
        .collect();
    ranges.sort_by_key(|range| (range.start, range.end));
    let matches = scan_text(line, &SCANNER, al);
    assert_eq!(matches.len(), ranges.len(), "finding count for {line}");
    for (found, range) in matches.iter().zip(&ranges) {
        assert_eq!(found.rule_id, ENTROPY);
        assert_eq!(&found.range, range, "exact body for {line}");
    }
    let expected: Vec<_> = ranges
        .iter()
        .map(|range| (ENTROPY, &line[range.clone()]))
        .collect();
    check_scan("src/x.rs", line, &expected, al);
    let mut masked = line.to_owned();
    for range in ranges.into_iter().rev() {
        masked.replace_range(range, "[REDACTED]");
    }
    assert_eq!(redact_text(line, &SCANNER, al), masked);
}

#[test]
fn call_literals_have_exact_independent_ranges() {
    let s = token(3);
    let t = token(8);
    let al = allowlist();
    for shape in [
        r#"handler.process("{S}")"#,
        r#"let x = build("{S}");"#,
        r#"outer(build("{S}"))"#,
        r#"handler.process("safe", "{S}", "{T}")"#,
        r#"let x = build("{S}"); TOKEN={T}"#,
        r#"build("safe", "{S}"); build("{T}")"#,
        r#"TOKEN={T}; build("{S}")"#,
        r#"require("{S}")"#,
        r#"re.compile("{S}")"#,
        r##"Regex::new(r#"{S}"#)"##,
        r###"build(br##"{S}"##, b"{T}")"###,
        r#"build(r"{S}", br"{T}")"#,
        r#"build('{S}', '{T}')"#,
        r#"build("{S}", "{S}")"#,
        r#"build(   "{S}",	"{T}")"#,
        r#"outer(build("{S}""#,
        r#"build("{S}")suffix"#,
        r#"build("{S}", "safe,)")"#,
    ] {
        let line = shape.replace("{S}", &s).replace("{T}", &t);
        let bodies: Vec<_> = [&s, &t]
            .into_iter()
            .filter(|value| line.contains(value.as_str()))
            .map(String::as_str)
            .collect();
        check_call_bodies(&line, &bodies, &al);
    }
}

#[test]
fn call_literal_escapes_and_raw_boundaries_preserve_source_bytes() {
    let s = token(4);
    let al = allowlist();
    for body in [
        format!("{s}\\\"end"),
        format!("{s}\\\\end"),
        format!("{s}\\'end"),
    ] {
        let quote = if body.ends_with("\\'end") { '\'' } else { '"' };
        let line = format!("build({quote}{body}{quote}, \"safe\")");
        check_call_bodies(&line, &[&body], &al);
    }
    let body = format!("{s}\"#tail\\");
    let line = format!("build(r###\"{body}\"###, \"safe\")");
    check_call_bodies(&line, &[&body], &al);
    let line = format!("build(r#\"{s}\"##)");
    check_call_bodies(&line, &[&s], &al);
}

#[test]
fn call_literal_collection_rejects_non_arguments_and_unclosed_strings() {
    let s = token(5);
    let al = allowlist();
    for line in [
        format!("build(\"{s}"),
        format!("build(r##\"{s}\"#)"),
        format!("build(\"{s}\\\""),
        format!("[\"safe\", \"{s}\"]"),
        format!("{{\"safe\", \"{s}\"}}"),
        format!("\"safe\", \"{s}\""),
        format!("build(\"safe\"), \"{s}\""),
        format!("note = \"safe, \\\"{s}\\\"\";"),
        format!("build(\"safe, \\\"{s}\\\"\")"),
        format!("build(r#\"safe, \"{s}\"\"#)"),
        "runtime.environment[\"ACME_WIDGET_SERVICE_ACCOUNT\"]".to_owned(),
    ] {
        check(&line, &[], &al);
    }
}

#[test]
fn call_literal_policy_is_body_scoped_and_switchable() {
    let s = token(6);
    let al = allowlist();
    let mut off = allowlist();
    off.exemption_layer = false;
    for shape in [
        r#"build("{S}")"#,
        r#"let x = build("{S}");"#,
        r#"require("{S}")"#,
        r#"re.compile("{S}")"#,
        r##"Regex::new(r#"{S}"#)"##,
        r#"build(b"{S}", br"{S}")"#,
    ] {
        let line = shape.replace("{S}", &s);
        check_call_bodies(&line, &[&s], &al);
        check(&line, &[], &off);
    }
    let markdown = format!("[{s}](https://host/docs)");
    check_call_bodies(&format!("build(\"{markdown}\")"), &[&markdown], &al);
    // url and wordshape allowances deliberately retain their body-level recall costs.
    for (body, predicate) in [
        ("https://example.org/manual/reference", "url"),
        ("reliable-backup-rotation-schedule", "wordshape"),
    ] {
        let line = format!("build(\"{body}\")");
        check(&line, &[], &al);
        let mut traced = allowlist();
        traced.trace_exemptions = true;
        check(
            &line,
            &[(format!("exempt:{predicate}").as_str(), body)],
            &traced,
        );
    }
    // no key means no hex bypass: this 40-byte body remains below the shannon gate.
    let value = hex(40, 7);
    assert!(sekretbarilo::scanner::entropy::shannon_entropy(value.as_bytes()) < 4.0);
    check(&format!("build(\"{value}\")"), &[], &al);
    for body in [
        &s[..19],
        "low-diversity-repeat-repeat",
        "words with spaces inside",
        "/usr/local/share/tooling/config",
    ] {
        check(&format!("build(\"{body}\")"), &[], &al);
    }
    // dense regexes cannot inherit the enclosing callee's syntax exemption.
    for body in [r"^[A-Za-z0-9+/]{43}=$", r"(?i)\b[0-9a-f]{7,40}\b"] {
        check_call_bodies(&format!("Regex::new(r#\"{body}\"#)"), &[body], &al);
    }
    // this dense regex stays below the unchanged 4.0-bit entropy gate.
    let body = r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$";
    assert!(sekretbarilo::scanner::entropy::shannon_entropy(body.as_bytes()) < 4.0);
    check(&format!("Regex::new(r#\"{body}\"#)"), &[], &al);
}

#[test]
fn call_literal_user_allowlists_keep_values_and_keys_separate() {
    let s = token(9);
    let line = format!("let ignored_key = build(\"{s}\");");
    let keyed = CompiledAllowlist::new_with_keys(
        &[],
        &[],
        None,
        &[(
            ENTROPY.to_owned(),
            vec![],
            vec![],
            vec!["ignored_key".to_owned()],
        )],
        false,
    )
    .unwrap();
    check_call_bodies(&line, &[&s], &keyed);
    let valued = CompiledAllowlist::new_with_keys(
        &[],
        &[],
        None,
        &[(
            ENTROPY.to_owned(),
            vec![format!("^{}$", regex::escape(&s))],
            vec![],
            vec![],
        )],
        false,
    )
    .unwrap();
    check(&line, &[], &valued);
}

#[test]
fn multiline_call_literals_run_once_with_exact_offsets() {
    let s = token(11);
    let t = token(17);
    let input = format!("// unicode: λ\r\nbuild(\"{s}\");\rwrap(br#\"{t}\"#\n");
    let matches = scan_text(&input, &SCANNER, &allowlist());
    assert_eq!(matches.len(), 2);
    for (found, body) in matches.iter().zip([&s, &t]) {
        let start = input.find(body).unwrap();
        assert_eq!(found.rule_id, ENTROPY);
        assert_eq!(found.range, start..start + body.len());
    }
    assert_eq!(
        redact_text(&input, &SCANNER, &allowlist()),
        "// unicode: λ\r\nbuild(\"[REDACTED]\");\rwrap(br#\"[REDACTED]\"#\n"
    );
    // neither a comma nor an unclosed literal inherits state from the previous line.
    let input = format!("build(\n, \"{s}\")\nbuild(\"{t}\n\")");
    assert!(scan_text(&input, &SCANNER, &allowlist()).is_empty());
}

#[test]
fn hex_hash_context_veto_handles_optional_prefixes() {
    let al = allowlist();
    for prefix in ["", "0x", "0X"] {
        let value = format!("{prefix}{}", hex(64, 211));
        check(&format!("token = \"{value}\" # sha256"), &[], &al);
        check(&format!("token = \"{value}\""), &[(ENTROPY, &value)], &al);
    }
}

#[test]
fn key_only_opaque_query_values_are_not_credential_free() {
    let al = allowlist();
    let opaque = token(211);
    check_rule(
        &format!("https://host/?{opaque}"),
        ENTROPY,
        Some(&opaque),
        true,
        &al,
    );
    check("https://host/?v=sample", &[], &al);
    check("https://host/?debug", &[], &al);
}

#[path = "../fuzz/fuzz_targets/predicates.rs"]
mod fuzz_predicates;

#[test]
fn credential_free_seed_satisfies_fuzz_invariants() {
    fuzz_predicates::check_predicates(b"https://host/?v=sample");
}

#[test]
fn markdown_credential_free_seed_satisfies_fuzz_invariants() {
    let input = b"[x](https://host/samplee)";
    let range = sekretbarilo::scanner::urlshape::unwrap_markdown_target(input).unwrap();
    assert!(sekretbarilo::scanner::urlshape::is_credential_free_url(
        &input[range]
    ));
    fuzz_predicates::check_predicates(input);
}

#[test]
fn autolink_credential_free_seed_satisfies_fuzz_invariants() {
    let input = b"<https://example.com/docs/intro>";
    let range = sekretbarilo::scanner::urlshape::unwrap_markdown_target(input).unwrap();
    assert!(sekretbarilo::scanner::urlshape::is_credential_free_url(
        &input[range]
    ));
    fuzz_predicates::check_predicates(input);
}

#[test]
fn opaque_markdown_target_satisfies_fuzz_invariants() {
    let input = format!("[x](https://host/{})", token(211));
    let range = sekretbarilo::scanner::urlshape::unwrap_markdown_target(input.as_bytes()).unwrap();
    assert!(!sekretbarilo::scanner::urlshape::is_credential_free_url(
        &input.as_bytes()[range]
    ));
    fuzz_predicates::check_predicates(input.as_bytes());
}

#[test]
fn hex_policy_lengths_satisfy_fuzz_invariants() {
    for length in [32, 40, 64] {
        for prefix in ["", "0x", "0X"] {
            let value = format!("{prefix}{}", hex(length, 211));
            assert!(sekretbarilo::scanner::hash_detect::is_hex_policy_candidate(
                Some(b"key"),
                value.as_bytes()
            ));
            fuzz_predicates::check_predicates(value.as_bytes());
        }
    }
}

#[test]
fn opaque_query_keys_with_values_are_not_exempted() {
    let al = allowlist();
    let opaque = token(211);
    check_rule(
        &format!("https://host/?{opaque}=1"),
        ENTROPY,
        Some(&opaque),
        true,
        &al,
    );
}

#[test]
fn credential_bearing_query_values_remain_detected() {
    let al = allowlist();
    let opaque = token(211);
    check_rule(
        &format!("https://host/path?token={opaque}"),
        ENTROPY,
        Some(&opaque),
        true,
        &al,
    );
}
