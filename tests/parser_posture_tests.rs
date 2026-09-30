use sekretbarilo::config::{SourcePosture, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{Finding, scan};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::ops::Range;
use std::slice::from_ref;
use std::sync::LazyLock;

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());
const RULE: &str = "generic-high-entropy-value";

fn token(seed: u64) -> String {
    let mut state = seed + 1;
    (0..40)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            char::from(
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    [(state >> 32) as usize % 62],
            )
        })
        .collect()
}

fn file(path: &str, source: &str) -> DiffFile {
    DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: Some(source.as_bytes().to_vec()),
        added_lines: source
            .split('\n')
            .enumerate()
            .map(|(i, line)| AddedLine {
                line_number: i + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    }
}

fn identities(findings: Vec<Finding>) -> Vec<(String, usize, Vec<u8>)> {
    let mut result: Vec<_> = findings
        .into_iter()
        .map(|f| (f.rule_id, f.line, f.matched_value))
        .collect();
    result.sort();
    result
}

fn settings(posture: SourcePosture) -> CompiledAllowlist {
    let mut al = CompiledAllowlist::default_allowlist().unwrap();
    al.source_posture = Some(posture);
    al
}

#[test]
fn go_struct_tags_keep_generated_opaque_keys_whole_values_and_items() {
    let all_settings = settings(SourcePosture::All);
    let literal_settings = settings(SourcePosture::Literals);
    let mut eligible = 0;
    for seed in 0..256 {
        let opaque = token(90_001 + seed);
        let split = opaque
            .as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        for (form, tag) in [
            format!("json:\"{opaque}\""),
            format!("json:\"name,{opaque}\""),
            format!("json:\"left\\\"quote,{opaque}\""),
            format!("json:\"{split}\""),
            format!("k={opaque}:\"x\" json:\"y\""),
        ]
        .into_iter()
        .enumerate()
        {
            let source = format!("type Record struct {{ Field string `{tag}` }}");
            let baseline = scan(&[file("pkg/record.go", &source)], &SCANNER, &all_settings);
            let narrowed = scan(
                &[file("pkg/record.go", &source)],
                &SCANNER,
                &literal_settings,
            );
            assert!(
                baseline.iter().any(|finding| finding.rule_id == RULE),
                "seed {seed}, form {form}"
            );
            eligible += 1;
            assert!(
                narrowed.iter().any(|finding| finding.rule_id == RULE),
                "seed {seed}, form {form}"
            );
        }
    }
    assert_eq!(eligible, 1280);
}

#[test]
fn go_raw_tag_assignment_keys_remain_candidates() {
    let literal_settings = settings(SourcePosture::Literals);
    for seed in 0..256 {
        let opaque = token(91_001 + seed);
        for tag in [
            format!("{opaque}:\"x\""),
            format!("k={opaque}:\"x\" json:\"y\""),
            format!("{opaque}:\"\""),
        ] {
            let source = format!("v := `{tag}`");
            let found = scan(&[file("pkg/x.go", &source)], &SCANNER, &literal_settings);
            assert!(
                found.iter().any(|finding| {
                    finding.rule_id == RULE
                        && finding
                            .matched_value
                            .windows(opaque.len())
                            .any(|part| part == opaque.as_bytes())
                }),
                "opaque key lost at seed {seed}"
            );
        }
    }
}

#[test]
fn generated_engine_parity_and_exact_dropped_traces() {
    let all_settings = settings(SourcePosture::All);
    let literals_settings = settings(SourcePosture::Literals);
    let mut traced = settings(SourcePosture::Literals);
    traced.trace_exemptions = true;
    for path in [
        "src/value.c",
        "src/value.cpp",
        "src/value.cc",
        "src/value.cxx",
        "src/value.hpp",
        "src/value.hxx",
        "src/value.py",
        "src/value.pyi",
        "src/value.js",
        "src/value.jsx",
        "src/value.mjs",
        "src/value.cjs",
        "src/value.ts",
        "src/value.mts",
        "src/value.cts",
        "src/value.tsx",
        "src/value.swift",
    ] {
        for seed in 0..100 {
            let body = token(seed);
            let code = format!("x{}", token(seed + 1000));
            let source = if path.ends_with(".py") || path.ends_with(".pyi") {
                format!("value = \"{body}\"\nother = {code}\n")
            } else if path.ends_with(".swift") {
                format!("let value = \"{body}\"\nlet other = {code}\n")
            } else if path.ends_with("js")
                || path.ends_with("jsx")
                || path.ends_with("ts")
                || path.ends_with("tsx")
            {
                format!("const value = \"{body}\";\nconst other = {code};\n")
            } else {
                format!("const char *value = \"{body}\";\nint other = {code};\n")
            };
            let input = file(path, &source);
            let all = identities(scan(from_ref(&input), &SCANNER, &all_settings));
            assert!(all.iter().any(|(rule, line, value)| rule == RULE
                && *line == 1
                && *value == body.as_bytes()));
            assert!(all.iter().any(|(rule, line, value)| rule == RULE
                && *line == 2
                && *value == code.as_bytes()));
            let c_raw_fallback = path.ends_with(".c") && source.contains("R\"");
            let expected: Vec<_> = all
                .iter()
                .filter(|(rule, line, _)| c_raw_fallback || rule != RULE || *line == 1)
                .cloned()
                .collect();
            assert_eq!(
                identities(scan(from_ref(&input), &SCANNER, &literals_settings)),
                expected,
                "{path}, seed {seed}"
            );
            let dropped: Vec<_> = identities(scan(&[input], &SCANNER, &traced))
                .into_iter()
                .filter(|(rule, _, _)| rule == "exempt:code")
                .collect();
            let expected_dropped = if c_raw_fallback {
                Vec::new()
            } else {
                vec![("exempt:code".into(), 2, code.into_bytes())]
            };
            assert_eq!(dropped, expected_dropped);
        }
    }
}

/// the clip contract: a full-posture tier-3 finding disjoint from every body is dropped and traced
/// `exempt:code`; one inside a single body stands; one that straddles bodies and code is traced
/// `exempt:clip` and replaced by its body segments, each evaluated again as a literal body. the
/// generated bodies are opaque tokens, so each segment of 20 bytes or more that passes the entropy
/// gate is reported on its own.
fn assert_filtered_baseline(path: &str, source: &str, bodies: &[Range<usize>]) {
    let input = file(path, source);
    let all = settings(SourcePosture::All);
    let literals = settings(SourcePosture::Literals);
    let baseline = scan(from_ref(&input), &SCANNER, &all);
    let lines: Vec<_> = source.split('\n').collect();
    let mut starts = vec![0];
    for line in &lines {
        starts.push(starts.last().unwrap() + line.len() + 1);
    }
    let mut expected = Vec::new();
    let mut dropped = Vec::new();
    let mut clipped = Vec::new();
    let mut segments = std::collections::BTreeSet::new();
    for finding in baseline {
        let line = lines[finding.line - 1].as_bytes();
        let positions: Vec<_> = line
            .windows(finding.matched_value.len())
            .enumerate()
            .filter_map(|(start, bytes)| {
                (bytes == finding.matched_value).then_some(starts[finding.line - 1] + start)
            })
            .collect();
        assert!(!positions.is_empty());
        let touched = |start: usize| -> Vec<Range<usize>> {
            let end = start + finding.matched_value.len();
            bodies
                .iter()
                .filter(|body| start < body.end && body.start < end)
                .map(|body| start.max(body.start)..end.min(body.end))
                .collect()
        };
        assert!(
            positions
                .iter()
                .all(|position| touched(*position).len() == touched(positions[0]).len()),
            "ambiguous generated placement"
        );
        let start = positions[0];
        let range = start..start + finding.matched_value.len();
        let touched = touched(start);
        if finding.rule_id != RULE {
            expected.push(finding);
        } else if touched.is_empty() {
            dropped.push((
                "exempt:code".to_owned(),
                finding.line,
                finding.matched_value,
            ));
        } else if touched.len() == 1 && touched[0] == range {
            expected.push(finding);
        } else {
            clipped.push((
                "exempt:clip".to_owned(),
                finding.line,
                finding.matched_value.clone(),
            ));
            for segment in touched {
                let value = &source.as_bytes()[segment.clone()];
                if value.len() >= 20
                    && sekretbarilo::scanner::entropy::shannon_entropy(value) >= 4.0
                {
                    segments.insert((finding.line, segment.start, segment.end));
                }
            }
        }
    }
    let mut expected = identities(expected);
    for (line, start, end) in segments {
        let identity = (
            RULE.to_owned(),
            line,
            source.as_bytes()[start..end].to_vec(),
        );
        if !expected.contains(&identity) {
            expected.push(identity);
        }
    }
    expected.sort();
    let found = scan(from_ref(&input), &SCANNER, &literals);
    assert_eq!(identities(found), expected, "{path}: {source}");
    let mut traced = settings(SourcePosture::Literals);
    traced.trace_exemptions = true;
    let result = scan(from_ref(&input), &SCANNER, &traced);
    let label = |label: &str| -> Vec<_> {
        identities(
            result
                .iter()
                .filter(|finding| finding.rule_id == label)
                .cloned()
                .collect(),
        )
    };
    dropped.sort();
    clipped.sort();
    assert_eq!(
        label("exempt:code"),
        dropped,
        "{path}: exact dropped identities"
    );
    assert_eq!(
        label("exempt:clip"),
        clipped,
        "{path}: exact clipped identities"
    );
    let mut all_traced = settings(SourcePosture::All);
    all_traced.trace_exemptions = true;
    let other_traces = |findings: Vec<Finding>| {
        identities(
            findings
                .into_iter()
                .filter(|finding| {
                    finding.rule_id.starts_with("exempt:")
                        && !matches!(finding.rule_id.as_str(), "exempt:code" | "exempt:clip")
                })
                .collect(),
        )
    };
    assert_eq!(
        other_traces(result),
        other_traces(scan(&[input], &SCANNER, &all_traced)),
        "{path}: other trace decisions"
    );
}

#[test]
fn parsed_nested_literal_values_filter_the_full_scanner_candidates() {
    let literal = token(12000);
    let positive = token(12001);
    for (path, source) in [
        (
            "src/value.py",
            format!(
                "def value():\n    return ['{literal}', f'{{call(\"{literal}\")}}', t'{{call(\"{literal}\")}}']\n"
            ),
        ),
        (
            "src/value.js",
            format!("function value() {{ return ['{literal}', `${{call(\"{literal}\")}}`]; }}\n"),
        ),
        (
            "src/value.jsx",
            format!("const value = <div label='{literal}'>{literal}{{call('{literal}')}}</div>;\n"),
        ),
        (
            "src/value.cpp",
            format!("const char *value() {{ return R\"tag({literal})tag\"; }}\n"),
        ),
        (
            "src/value.ts",
            format!("type T = `${{\"{literal}\" | number}}`;\n"),
        ),
        (
            "src/value.swift",
            format!(
                "func value() -> [String] {{\n    return [\"{literal}\", \"\\(call(\"{literal}\"))\", ##\"{literal}\\##(call(#\"{literal}\"#))\"##]\n}}\nlet multi = \"\"\"\n    {literal}\\(call(\"{literal}\"))\n    \"\"\"\n"
            ),
        ),
    ] {
        let source = format!(
            "{source}{}\n",
            if path.ends_with(".py") {
                format!("positive = \"{positive}\"")
            } else if path.ends_with(".swift") {
                format!("let positive = \"{positive}\"")
            } else if path.ends_with(".cpp") {
                format!("const char *positive = \"{positive}\";")
            } else {
                format!("const positive = \"{positive}\";")
            }
        );
        let bodies: Vec<_> = [&literal, &positive]
            .into_iter()
            .flat_map(|body| {
                source
                    .match_indices(body)
                    .map(|(start, _)| start..start + body.len())
            })
            .collect();
        assert!(
            scan(
                &[file(path, &source)],
                &SCANNER,
                &settings(SourcePosture::All)
            )
            .iter()
            .any(|finding| finding.rule_id == RULE && finding.matched_value == positive.as_bytes())
        );
        assert_filtered_baseline(path, &source, &bodies);
    }
}

#[test]
fn parser_corpus_skeletons_do_not_add_candidates() {
    let opaque = token(40000);
    let positive = token(40001);
    let pattern = format!("{opaque}|[a-z]+\\d{{4}}");
    let import = format!("@scope/{opaque}");
    for (path, prefix, body) in [
        (
            "src/value.ts",
            format!("import type {{ Name }} from \"{import}\";\n"),
            import.as_str(),
        ),
        (
            "src/value.ts",
            format!("const pattern = /{pattern}/;\n"),
            pattern.as_str(),
        ),
        (
            "src/value.py",
            format!("pattern = r\"{pattern}\"\n"),
            pattern.as_str(),
        ),
        (
            "src/value.py",
            format!("\"\"\"{opaque}\nmodule documentation\n\"\"\"\n"),
            opaque.as_str(),
        ),
        (
            "src/value.py",
            format!("values = [\"{opaque}\"]\n"),
            opaque.as_str(),
        ),
        (
            "src/value.cc",
            format!("static const char alphabet[] = \"{opaque}\";\n"),
            opaque.as_str(),
        ),
        (
            "src/value.swift",
            format!("let pattern = #\"{pattern}\"#\n"),
            pattern.as_str(),
        ),
        (
            "src/value.swift",
            format!("let documentation = \"\"\"\n{opaque}\nmodule documentation\n\"\"\"\n"),
            opaque.as_str(),
        ),
        (
            "src/value.swift",
            format!("let values = [\"{opaque}\"]\n"),
            opaque.as_str(),
        ),
    ] {
        let suffix = if path.ends_with(".py") {
            format!("positive = \"{positive}\"\n")
        } else if path.ends_with(".swift") {
            format!("let positive = \"{positive}\"\n")
        } else if path.ends_with(".cc") {
            format!("const char *positive = \"{positive}\";\n")
        } else {
            format!("const positive = \"{positive}\";\n")
        };
        let source = prefix + &suffix;
        let bodies: Vec<_> = [body, positive.as_str()]
            .into_iter()
            .flat_map(|body| {
                source
                    .match_indices(body)
                    .map(|(start, _)| start..start + body.len())
            })
            .collect();
        assert!(
            scan(
                &[file(path, &source)],
                &SCANNER,
                &settings(SourcePosture::All)
            )
            .iter()
            .any(|finding| finding.rule_id == RULE && finding.matched_value == positive.as_bytes())
        );
        assert_filtered_baseline(path, &source, &bodies);
    }
}

#[test]
fn parser_posture_filters_call_candidates_in_comments_and_expressions() {
    let positive = token(50000);
    let comment = token(50001);
    let code = token(50002);
    for (path, source) in [
        (
            "src/value.py",
            format!(
                "# call(\"{comment}\")\nvalue = f'{{call(\"{positive}\")}}'\nother = f'{{x{code}}}'\n"
            ),
        ),
        (
            "src/value.js",
            format!(
                "// call(\"{comment}\")\nconst value = `${{call(\"{positive}\")}}`;\nconst other = `${{x{code}}}`;\n"
            ),
        ),
        (
            "src/value.cpp",
            format!("// call(\"{comment}\")\nvoid value() {{ call(\"{positive}\"); }}\n"),
        ),
        (
            "src/value.swift",
            format!(
                "// call(\"{comment}\")\nlet value = \"\\(call(\"{positive}\"))\"\nlet other = \"\\(x{code})\"\n"
            ),
        ),
    ] {
        let bodies: Vec<_> = source
            .match_indices(&positive)
            .map(|(start, _)| start..start + positive.len())
            .collect();
        let all = scan(
            &[file(path, &source)],
            &SCANNER,
            &settings(SourcePosture::All),
        );
        assert!(
            all.iter()
                .any(|finding| finding.rule_id == RULE
                    && finding.matched_value == comment.as_bytes()),
            "baseline call control: {path}"
        );
        assert_filtered_baseline(path, &source, &bodies);
    }
}

#[test]
fn parser_language_monte_carlo_has_zero_literal_recall_loss() {
    let all = settings(SourcePosture::All);
    let literals = settings(SourcePosture::Literals);
    let mut state = 918_273_645_u64;
    for path in [
        "src/value.c",
        "src/value.cpp",
        "src/value.py",
        "src/value.js",
        "src/value.ts",
        "src/value.tsx",
        "src/value.swift",
    ] {
        let mut total = 0;
        for alphabet in [
            b"0123456789abcdef".as_slice(),
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        ] {
            for length in [20, 32, 40, 64] {
                let mut positives = 0;
                for sample in 0..100 {
                    let body: String = (0..length)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            char::from(alphabet[state as usize % alphabet.len()])
                        })
                        .collect();
                    let source = if path.ends_with(".py") {
                        format!("value = \"{body}\"\n")
                    } else if path.ends_with(".swift") {
                        // plain, raw and multi-line bodies share the swift cell.
                        match sample % 3 {
                            0 => format!("let value = \"{body}\"\n"),
                            1 => format!("let value = #\"{body}\"#\n"),
                            _ => format!("let value = \"\"\"\n    token=\"{body}\"\n    \"\"\"\n"),
                        }
                    } else if path.ends_with(".c") || path.ends_with(".cpp") {
                        format!("const char *value = \"{body}\";\n")
                    } else {
                        format!("const value = \"{body}\";\n")
                    };
                    let input = file(path, &source);
                    let baseline = identities(scan(from_ref(&input), &SCANNER, &all));
                    let narrowed = identities(scan(&[input], &SCANNER, &literals));
                    positives += baseline.iter().filter(|(rule, _, _)| rule == RULE).count();
                    for finding in baseline {
                        assert!(
                            narrowed.contains(&finding),
                            "lost literal in {path}, length {length}"
                        );
                    }
                }
                total += positives;
            }
        }
        assert!(total >= 800, "vacuous baseline for {path}: {total}");
    }
}

#[test]
fn generated_straddling_literal_bodies_retain_exact_baseline_findings() {
    let all = settings(SourcePosture::All);
    let literals = settings(SourcePosture::Literals);
    let mut traced = settings(SourcePosture::Literals);
    traced.trace_exemptions = true;
    let mut positive_counts = std::collections::BTreeMap::new();
    // every branch of the clip contract is exercised, not only the total.
    let mut branch_counts = std::collections::BTreeMap::new();
    let mut state = 70_000_u64;
    for alphabet in [
        b"0123456789abcdef".as_slice(),
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ] {
        for length in [20, 32, 40, 64] {
            for sample in 0..20 {
                let body: String = (0..length)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        char::from(alphabet[state as usize % alphabet.len()])
                    })
                    .collect();
                let code = format!("x{}", token(80_000 + sample));
                let mut cases = Vec::new();
                for prefix in ["b", "r", "u", "f", "rb"] {
                    for quote in ['\"', '\''] {
                        for indented in [false, true] {
                            let start = if indented { "def value():\n    " } else { "" };
                            let name = format!("python {prefix}{quote} indented={indented}");
                            let source = format!(
                                "{start}SECRET_KEY = {prefix}{quote}{body}{quote}\nother = {code}\n"
                            );
                            cases.push((name, "src/value.py", source));
                        }
                    }
                }
                for prefix in ["L", "u8"] {
                    let name = format!("c++ {prefix}\"");
                    let source = format!(
                        "void value() {{\n    key = {prefix}\"{body}\";\n    other = {code};\n}}\n"
                    );
                    cases.push((name, "src/value.cpp", source));
                }
                for (shape, line) in [
                    ("key=#\"", format!("key=#\"{body}\"#")),
                    ("key=##\"", format!("key=##\"{body}\"##")),
                    ("interpolated prefix", format!("let k = \"\\(a){body}\"")),
                    (
                        "multi-line interpolated prefix",
                        format!("let k = \"\"\"\n    token=\\(a){body}\n    \"\"\""),
                    ),
                ] {
                    for indented in [false, true] {
                        let name = format!("swift {shape} indented={indented}");
                        let source = if indented {
                            let line = line.replace('\n', "\n    ");
                            format!("func value() {{\n    {line}\n    let other = {code}\n}}\n")
                        } else {
                            format!("{line}\nlet other = {code}\n")
                        };
                        cases.push((name, "src/value.swift", source));
                    }
                }
                cases.push((
                    "swift dictionary ??\"".to_owned(),
                    "src/value.swift",
                    format!("let config = [\n    \"apiKey\": env.x??\"{body}\",\n]\nlet other = {code}\n"),
                ));
                for path in ["src/value.js", "src/value.ts"] {
                    for quote in ['\"', '\''] {
                        let name = format!("{path} {quote}");
                        let source = format!(
                            "const value = {{\n  apiKey: env.X??{quote}{body}{quote},\n}};\nconst other = {code};\n"
                        );
                        cases.push((name, path, source));
                    }
                }
                // the clip contract keeps exactly the literal body: every body a full-posture
                // finding carries is reported as the body itself whenever the body alone passes
                // the length and entropy gates a plain literal body faces.
                let body_reportable =
                    sekretbarilo::scanner::entropy::shannon_entropy(body.as_bytes()) >= 4.0;
                for (name, path, source) in cases {
                    positive_counts.entry(name.clone()).or_insert(0);
                    let input = file(path, &source);
                    let baseline = identities(scan(from_ref(&input), &SCANNER, &all));
                    let retained = identities(scan(from_ref(&input), &SCANNER, &literals));
                    let body_findings: Vec<_> = baseline
                        .iter()
                        .filter(|(rule, _, value)| {
                            rule == RULE
                                && value
                                    .windows(body.len())
                                    .any(|part| part == body.as_bytes())
                        })
                        .collect();
                    for (_, line, value) in body_findings {
                        // a finding that is exactly the body stands as evaluated, key included.
                        let exact = value == body.as_bytes();
                        let expected = exact || body_reportable;
                        *positive_counts.get_mut(&name).unwrap() += usize::from(expected);
                        let branch = match (exact, body_reportable) {
                            (true, _) => "retained exact",
                            (false, true) => "clipped and reported",
                            (false, false) => "clipped and dropped",
                        };
                        *branch_counts.entry(branch).or_insert(0_usize) += 1;
                        let clipped = (RULE.to_owned(), *line, body.as_bytes().to_vec());
                        assert_eq!(
                            retained.contains(&clipped),
                            expected,
                            "lost body: {name}, length {length}"
                        );
                    }
                    let code_findings: Vec<_> = baseline
                        .iter()
                        .filter(|(rule, _, value)| rule == RULE && value == code.as_bytes())
                        .collect();
                    assert!(
                        !code_findings.is_empty(),
                        "vacuous code control: {name}, length {length}"
                    );
                    *branch_counts.entry("code").or_insert(0) += code_findings.len();
                    for finding in code_findings {
                        assert!(
                            !retained.contains(finding),
                            "kept disjoint code: {name}, length {length}"
                        );
                    }
                    // a retained finding is a full-posture finding, or exactly the generated body
                    // clipped out of a full-posture finding on its line; nothing else may appear.
                    assert!(
                        retained.iter().all(|finding| baseline.contains(finding)
                            || (finding.0 == RULE
                                && finding.2 == body.as_bytes()
                                && baseline.iter().any(|(rule, line, value)| rule == RULE
                                    && *line == finding.1
                                    && value
                                        .windows(body.len())
                                        .any(|part| part == body.as_bytes())))),
                        "parser introduced a finding: {name}, length {length}"
                    );
                    let traces = identities(scan(&[input], &SCANNER, &traced));
                    let trace = |label: &str| -> Vec<_> {
                        traces
                            .iter()
                            .filter(|(rule, _, _)| rule == label)
                            .cloned()
                            .collect()
                    };
                    let mut dropped: Vec<_> = baseline
                        .iter()
                        .filter(|finding| {
                            finding.0 == RULE
                                && !retained.contains(finding)
                                && !finding
                                    .2
                                    .windows(body.len())
                                    .any(|part| part == body.as_bytes())
                        })
                        .map(|(_, line, value)| ("exempt:code".to_owned(), *line, value.clone()))
                        .collect();
                    dropped.sort();
                    assert_eq!(
                        trace("exempt:code"),
                        dropped,
                        "exact code traces: {name}, length {length}"
                    );
                    let mut clipped: Vec<_> = baseline
                        .iter()
                        .filter(|finding| {
                            finding.0 == RULE
                                && finding.2 != body.as_bytes()
                                && finding
                                    .2
                                    .windows(body.len())
                                    .any(|part| part == body.as_bytes())
                        })
                        .map(|(_, line, value)| ("exempt:clip".to_owned(), *line, value.clone()))
                        .collect();
                    clipped.sort();
                    assert_eq!(
                        trace("exempt:clip"),
                        clipped,
                        "exact clip traces: {name}, length {length}"
                    );
                }
            }
        }
    }
    for (name, positives) in positive_counts {
        assert!(
            positives >= 40,
            "vacuous shape: {name}, positives {positives}"
        );
    }
    for branch in [
        "retained exact",
        "clipped and reported",
        "clipped and dropped",
        "code",
    ] {
        let count = branch_counts.get(branch).copied().unwrap_or(0);
        assert!(count >= 100, "vacuous clip branch: {branch}, {count}");
    }
}

#[test]
fn unsupported_parser_forms_keep_full_file_baseline() {
    let body = token(60000);
    let all = settings(SourcePosture::All);
    let literals = settings(SourcePosture::Literals);
    for (path, source) in [
        (
            "src/value.py",
            format!("before = x{body}\nvalue = tf'{body}'\nafter = x{body}\n"),
        ),
        (
            "src/value.py",
            format!("# coding: latin-1\nbefore = x{body}\nvalue = '{body}'\nafter = x{body}\n"),
        ),
        (
            "src/value.js",
            format!("const before = x{body};\nconst value = `unclosed;\nconst after = x{body};\n"),
        ),
        (
            "src/value.ts",
            format!(
                "const before = x{body};\ntype T = `${{\"{body}\" | number`;\nconst after = x{body};\n"
            ),
        ),
        ("src/value.h", format!("const before = x{body};\n")),
    ]
    .into_iter()
    .chain(
        [
            // a block comment inside a string literal is a grammar mislabel.
            "let value = \"/* note */\"",
            "let value = \"\"\"\n    /* note */ text\n    \"\"\"",
            // regex literals are not mapped, and a prefix-shaped slash may be one.
            "let pattern = /[a-z]+/",
            "let pattern = #/[a-z]+/#",
            "call()\n/b/.wholeMatch(text)",
            "let q = a /b/ c",
            // forms the compiler rejects but the grammar accepts.
            "let value = \"first\nsecond\"",
            "let value = \"\"\"abc\"\"\"",
            "let value = \"\"\"\n    abc\"\"\"",
            "let value = #\"\"\"abc\n    \"\"\"#",
            "let value = (",
        ]
        .map(|construct| {
            (
                "src/value.swift",
                format!("let before = x{body}\n{construct}\nlet after = x{body}\n"),
            )
        }),
    ) {
        let input = file(path, &source);
        let baseline = identities(scan(from_ref(&input), &SCANNER, &all));
        assert!(!baseline.is_empty());
        assert_eq!(
            identities(scan(&[input], &SCANNER, &literals)),
            baseline,
            "{path}"
        );
    }
}

#[test]
fn c_uncertain_context_keeps_explicit_all_identities() {
    let body = token(421);
    for whitespace in ['\x0b', '\x0c'] {
        for path in ["src/value.c", "src/value.cpp"] {
            let source =
                format!("// note \\{whitespace}\n/*\nconst char *k = \"{body}\";\n// */\n");
            let input = file(path, &source);
            let all = identities(scan(
                from_ref(&input),
                &SCANNER,
                &settings(SourcePosture::All),
            ));
            assert!(
                all.iter()
                    .any(|(rule, _, value)| rule == RULE && value == body.as_bytes()),
                "vacuous splice baseline: {path}, {whitespace:?}"
            );
            assert_eq!(
                identities(scan(&[input], &SCANNER, &settings(SourcePosture::Literals))),
                all,
                "full fallback: {path}, {whitespace:?}"
            );
        }
    }
    for construct in [
        "/\\\n* comment */",
        "#define VALUE \\\r\n next",
        "R\\ \n\"(body)\"",
        "??/\n",
        "int invalid = ;",
        "int x;\r",
    ] {
        let source = format!(
            "const char *before = \"{body}\";\n{construct}\nconst char *after = \"{body}\";\n"
        );
        let input = file("src/value.cpp", &source);
        let all = identities(scan(
            from_ref(&input),
            &SCANNER,
            &settings(SourcePosture::All),
        ));
        assert!(!all.is_empty());
        assert_eq!(
            identities(scan(&[input], &SCANNER, &settings(SourcePosture::Literals))),
            all
        );
    }
    for prefix in ["R", "LR", "uR", "UR", "u8R"] {
        let source = format!(
            "const char *before = x{body};\nvoid send(void) {{ send({prefix}\"({{\"token\": \"{body}\"}})\"); }}\nconst char *after = x{body};\n"
        );
        let input = file("src/value.c", &source);
        let all = identities(scan(
            from_ref(&input),
            &SCANNER,
            &settings(SourcePosture::All),
        ));
        assert!(
            all.iter().any(|(rule, line, value)| rule == RULE
                && *line == 2
                && value
                    .windows(body.len())
                    .any(|part| part == body.as_bytes())),
            "vacuous raw C baseline: {prefix}"
        );
        assert_eq!(
            identities(scan(&[input], &SCANNER, &settings(SourcePosture::Literals))),
            all,
            "raw C fallback: {prefix}"
        );
    }
    let mut input = file("src/value.c", &format!("int value = x{body};\n"));
    for state in 0..4 {
        match state {
            0 => input.context = None,
            1 => input.context = Some(b"int unrelated;\n".to_vec()),
            2 => {
                input.context = Some(format!("int value = x{body};\n").into_bytes());
                input.added_lines.push(input.added_lines[0].clone());
            }
            _ => input.added_lines[0].line_number = 99,
        }
        assert_eq!(
            identities(scan(
                from_ref(&input),
                &SCANNER,
                &settings(SourcePosture::Literals)
            )),
            identities(scan(
                from_ref(&input),
                &SCANNER,
                &settings(SourcePosture::All)
            ))
        );
    }
}
