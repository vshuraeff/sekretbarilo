use sekretbarilo::config::{self, SourcePosture, allowlist::CompiledAllowlist};
use sekretbarilo::diff::{
    attach_staged_context,
    parser::{AddedLine, DiffFile, parse_diff},
};
use sekretbarilo::scanner::engine::{Finding, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::process::Command;
use std::sync::LazyLock;

const ENTROPY: &str = "generic-high-entropy-value";
static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

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

fn allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().unwrap()
}

fn file(path: &str, lines: &[(usize, &str)]) -> DiffFile {
    DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: lines
            .iter()
            .map(|&(line_number, content)| AddedLine {
                line_number,
                content: content.as_bytes().to_vec(),
            })
            .collect(),
    }
}

fn findings(file: DiffFile, al: &CompiledAllowlist) -> Vec<Finding> {
    scan(&[file], &SCANNER, al)
        .into_iter()
        .filter(|f| f.rule_id == ENTROPY)
        .collect()
}

fn source_input(path: &str, lines: &[String], eol: &str, with_context: bool) -> DiffFile {
    let line_suffix = eol.strip_suffix('\n').unwrap_or(eol);
    DiffFile {
        path: path.into(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: with_context.then(|| format!("{}{eol}", lines.join(eol)).into_bytes()),
        added_lines: lines
            .iter()
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: format!("{line}{line_suffix}").into_bytes(),
            })
            .collect(),
    }
}

fn finding_identities(
    input: DiffFile,
    al: &CompiledAllowlist,
) -> Vec<(String, String, usize, Vec<u8>)> {
    let mut identities: Vec<_> = scan(&[input], &SCANNER, al)
        .into_iter()
        .map(|finding| {
            (
                finding.rule_id,
                finding.file,
                finding.line,
                finding.matched_value,
            )
        })
        .collect();
    identities.sort();
    identities
}

fn assert_deferred_postures(label: &str, input: DiffFile) {
    let baseline = finding_identities(input.clone(), &allowlist());
    assert!(!baseline.is_empty(), "{label}: default baseline is empty");
    for (name, posture) in [
        ("literals", SourcePosture::Literals),
        ("all", SourcePosture::All),
    ] {
        let mut al = allowlist();
        al.source_posture = Some(posture);
        assert_eq!(
            finding_identities(input.clone(), &al),
            baseline,
            "{label}: source_posture={name} changed the finding set"
        );
    }
}

fn assert_deferred_source_scenario(
    label: &str,
    path: &str,
    lines: &[String],
    expected: &[(usize, String)],
) {
    for (ending, eol) in [("lf", "\n"), ("crlf", "\r\n")] {
        for (input_kind, with_context) in [("added-only", false), ("full-context", true)] {
            let input = source_input(path, lines, eol, with_context);
            let baseline = finding_identities(input.clone(), &allowlist());
            assert!(
                !baseline.is_empty(),
                "{label}/{ending}/{input_kind}: empty baseline"
            );
            for (line, value) in expected {
                assert!(
                    baseline.iter().any(|(rule, _, found_line, matched)| {
                        rule == ENTROPY && found_line == line && matched == value.as_bytes()
                    }),
                    "{label}/{ending}/{input_kind}: missing payload at line {line}"
                );
            }
            assert_deferred_postures(&format!("{label}/{ending}/{input_kind}"), input);
        }
    }
}

#[test]
fn deferred_source_postures_keep_full_findings_for_review_shapes() {
    let c_before = token(30);
    let c_on = token(31);
    let c_after = token(32);
    assert_deferred_source_scenario(
        "c-spliced-comment",
        "src/example.c",
        &[
            format!("const char *before = \"{c_before}\";"),
            format!("// comment k = {c_on} \\"),
            "/* still comment".into(),
            format!("const char *after = \"{c_after}\";"),
        ],
        &[(1, c_before), (2, c_on), (4, c_after)],
    );

    for (shape, division) in [
        ("js-postfix-spaced", "/ count"),
        ("js-postfix-tight", "/count"),
    ] {
        let before = token(33);
        let on = token(34);
        let after = token(35);
        assert_deferred_source_scenario(
            shape,
            "src/example.js",
            &[
                format!("const before = \"{before}\";"),
                format!("total! {division}; const on = \"{on}\";"),
                format!("const after = \"{after}\";"),
            ],
            &[(1, before), (2, on), (3, after)],
        );
    }

    let regex_before = token(36);
    let regex_on = token(37);
    let regex_after = token(38);
    assert_deferred_source_scenario(
        "js-regex-after-bang",
        "src/example.js",
        &[
            format!("const before = \"{regex_before}\";"),
            format!("if (ready) !/re/.test(x); const on = \"{regex_on}\";"),
            format!("const positive = \"{regex_after}\";"),
        ],
        &[(1, regex_before), (2, regex_on), (3, regex_after)],
    );

    let macro_before = token(39);
    let macro_on = token(40);
    let macro_after = token(41);
    assert_deferred_source_scenario(
        "c-multiline-macro",
        "src/example.c",
        &[
            format!("const char *before = \"{macro_before}\";"),
            format!("#define WRAP(value) k = \"{macro_on}\" \\"),
            "    value".into(),
            format!("const char *after = \"{macro_after}\";"),
        ],
        &[(1, macro_before), (2, macro_on), (4, macro_after)],
    );

    let python_before = token(42);
    let python_on = token(43);
    let python_after = token(44);
    assert_deferred_source_scenario(
        "python-fstring-replacement",
        "src/example.py",
        &[
            format!("before = \"{python_before}\""),
            format!("message = f\"value={{item}}\"; on = \"{python_on}\""),
            format!("after = \"{python_after}\""),
        ],
        &[(1, python_before), (2, python_on), (3, python_after)],
    );
}

#[test]
fn crlf_c_macro_diffs_keep_full_findings_through_the_parser() {
    let before = token(45);
    let on = token(46);
    let after = token(47);
    let lines = [
        format!("const char *before = \"{before}\";"),
        format!("#define WRAP(value) k = \"{on}\" \\"),
        "    value".into(),
        format!("const char *after = \"{after}\";"),
    ];
    let additions = lines
        .iter()
        .map(|line| format!("+{line}\r\n"))
        .collect::<String>();
    for (label, header, is_new, first_line) in [
        (
            "new-file",
            "new file mode 100644\r\n--- /dev/null\r\n+++ b/src/example.c\r\n@@ -0,0 +1,4 @@\r\n",
            true,
            1,
        ),
        (
            "gapped-hunk",
            "--- a/src/example.c\r\n+++ b/src/example.c\r\n@@ -8,0 +9,4 @@\r\n",
            false,
            9,
        ),
    ] {
        let diff = format!("diff --git a/src/example.c b/src/example.c\r\n{header}{additions}");
        let files = parse_diff(diff.as_bytes());
        assert_eq!(files.len(), 1, "{label}");
        assert_eq!(files[0].is_new, is_new, "{label}");
        assert_eq!(files[0].added_lines[0].line_number, first_line, "{label}");
        assert_deferred_postures(
            &format!("c-multiline-macro/parser/{label}"),
            files[0].clone(),
        );
    }
}

#[test]
fn known_source_scans_literals_and_excludes_code_and_comments() {
    let value = token(3);
    for (line, expected) in [
        (format!("let k = \"{value}\";"), 1),
        (format!("foo::bar({value})"), 0),
        (format!("// {value}"), 0),
        (format!("return \"{value}\";"), 1),
        (value.clone(), 0),
    ] {
        let found = findings(file("src/x.rs", &[(1, &line)]), &allowlist());
        assert_eq!(found.len(), expected);
        assert!(found.iter().all(|f| f.matched_value == value.as_bytes()));
    }
}

#[test]
fn regex_owned_key_allowlist_does_not_suppress_a_different_body() {
    let config: config::ProjectConfig = toml::from_str(
        r#"
        [[allowlist.rules]]
        id = "generic-high-entropy-value"
        keys = ["ignored_key"]
    "#,
    )
    .unwrap();
    let al = config::build_allowlist(&config, &load_default_rules().unwrap()).unwrap();
    let value = token(4);
    let assignment = format!("let ignored_key = \"{value}\";");
    let body = format!("return \"{value}\";");
    let found = findings(file("src/x.rs", &[(1, &assignment), (2, &body)]), &al);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 2);
    assert!(found[0].matched_value == value.as_bytes());
}

#[test]
fn regex_owned_hex_assignment_keeps_its_bypass() {
    let value = hex(40, 7);
    assert!(shannon_entropy(value.as_bytes()) < 4.0);
    let assignment = format!("let k = \"{value}\";");
    assert_eq!(
        findings(file("src/x.rs", &[(1, &assignment)]), &allowlist()).len(),
        1
    );
    // bodies are always capturekind::call, excluded by the hex bypass kind guard.
    // this body's ordinary measured entropy is below the unchanged 4.0-bit gate.
    let body = format!("build(\"{value}\")");
    assert!(findings(file("src/x.rs", &[(1, &body)]), &allowlist()).is_empty());
}

#[test]
fn repeated_values_at_different_offsets_remain_distinct() {
    let value = token(5);
    for line in [
        format!("build(\"{value}\", \"{value}\")"),
        format!("let k = \"{value}\"; build(\"{value}\");"),
    ] {
        let found = findings(file("src/x.rs", &[(1, &line)]), &allowlist());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.matched_value == value.as_bytes()));
    }
}

#[test]
fn strict_subrange_regex_does_not_own_the_enclosing_body() {
    let value = token(6);
    let body = format!("k={value}");
    let line = format!("return \"{body}\";");
    let found = findings(file("src/x.rs", &[(1, &line)]), &allowlist());
    assert_eq!(found.len(), 2);
    assert!(found.iter().any(|f| f.matched_value == value.as_bytes()));
    assert!(found.iter().any(|f| f.matched_value == body.as_bytes()));
}

#[test]
fn language_less_paths_retain_the_pathless_candidate_set() {
    let value = token(3);
    let al = allowlist();
    for line in [
        value.clone(),
        format!("let k = \"{value}\";"),
        format!("foo::bar({value})"),
        format!("// {value}"),
        format!("return \"{value}\";"),
        format!("build(\"{value}\")"),
        format!("// k={value}"),
    ] {
        let found = findings(file("src/x.conf", &[(1, &line)]), &al);
        let pathless = scan_text(&line, &SCANNER, &al);
        let expected: Vec<_> = pathless
            .iter()
            .filter(|f| f.rule_id == ENTROPY)
            .map(|f| &line.as_bytes()[f.range.clone()])
            .collect();
        assert_eq!(found.len(), expected.len());
        assert!(
            found
                .iter()
                .zip(expected)
                .all(|(f, value)| f.matched_value == value)
        );
    }
    for line in [
        value.clone(),
        format!("// k={value}"),
        format!("build(\"{value}\")"),
    ] {
        assert_eq!(findings(file("src/x.conf", &[(1, &line)]), &al).len(), 1);
    }
}

#[test]
fn explicit_posture_and_layer_switch_table() {
    let value = token(3);
    for (posture, layer, expected) in [
        (None, true, [1, 0, 1]),
        (None, false, [1, 1, 0]),
        (Some(SourcePosture::Literals), true, [1, 0, 1]),
        (Some(SourcePosture::Literals), false, [1, 0, 1]),
        (Some(SourcePosture::All), true, [1, 1, 1]),
        (Some(SourcePosture::All), false, [1, 1, 0]),
    ] {
        let mut al = allowlist();
        al.source_posture = posture;
        al.exemption_layer = layer;
        for (index, line) in [
            format!("let k = \"{value}\";"),
            value.clone(),
            format!("build(\"{value}\")"),
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                findings(file("src/x.rs", &[(1, line)]), &al).len(),
                expected[index],
                "{posture:?}, layer={layer}, shape={index}"
            );
        }
    }
}

#[test]
fn testpath_skip_is_labelled_and_only_applies_to_tier3_with_layer_on() {
    let value = token(3);
    let line = format!("let k = \"{value}\";");
    let mut al = allowlist();
    assert!(findings(file("tests/x.rs", &[(1, &line)]), &al).is_empty());
    al.trace_exemptions = true;
    let traced = scan(&[file("tests/x.rs", &[(1, &line)])], &SCANNER, &al);
    assert_eq!(traced.len(), 1);
    assert_eq!(traced[0].rule_id, "exempt:testpath");
    let provider = format!(
        "AKIA{}",
        (0..16)
            .map(|index| char::from(b'A' + ((index * 7 + 3) % 26) as u8))
            .collect::<String>()
    );
    assert!(
        scan(&[file("tests/x.rs", &[(1, &provider)])], &SCANNER, &al)
            .iter()
            .any(|f| f.rule_id == "aws-access-key-id")
    );
    al.trace_exemptions = false;
    al.tier3_skip_test_paths = false;
    assert_eq!(findings(file("tests/x.rs", &[(1, &line)]), &al).len(), 1);
    al.tier3_skip_test_paths = true;
    al.exemption_layer = false;
    // the pre-existing skip decision is inside the layer guard.
    assert_eq!(findings(file("tests/x.rs", &[(1, &line)]), &al).len(), 1);
}

/// without context line five uses the bare regex; complete context exposes a body.
/// an equal-range bare regex owns that body, preserving one finding on either path.
#[test]
fn multiline_context_and_gaps_never_lose_the_value() {
    let value = token(3);
    let mut partial = file("src/x.py", &[(1, "\"\"\""), (5, &value)]);
    assert_eq!(findings(partial.clone(), &allowlist()).len(), 1);
    partial.context = Some(format!("\"\"\"\n\n\n\n{value}").into_bytes());
    assert_eq!(findings(partial, &allowlist()).len(), 1);
    let gapped = file("src/x.rs", &[(1, "let n = 1;"), (5, &value), (6, &value)]);
    assert_eq!(findings(gapped, &allowlist()).len(), 2);
    let mut known = file("src/x.rs", &[(1, "let n = 1;"), (2, &value)]);
    known.context = Some(format!("let n = 1;\n{value}").into_bytes());
    assert!(findings(known, &allowlist()).is_empty());
}

#[test]
fn missing_mismatched_or_unknown_context_keeps_full_posture() {
    let value = token(3);
    for context in [b"let n = 1;".to_vec(), b"let n = 1;\n\"short\"".to_vec()] {
        let mut input = file("src/x.rs", &[(2, &value)]);
        input.context = Some(context);
        assert_eq!(findings(input, &allowlist()).len(), 1);
    }
    let input = file(
        "src/x.js",
        &[(1, "'unterminated"), (2, &value), (3, &value)],
    );
    assert_eq!(findings(input, &allowlist()).len(), 2);
    let mut unordered = file("src/x.rs", &[(2, &value), (1, "let n = 1;")]);
    assert!(findings(unordered.clone(), &allowlist()).is_empty());
    unordered.context = Some(format!("let n = 1;\r\n{value}\r\n").into_bytes());
    assert!(findings(unordered, &allowlist()).is_empty());
}

#[test]
fn pathless_text_is_unchanged_by_source_posture_and_testpath_settings() {
    let value = token(3);
    for posture in [
        None,
        Some(SourcePosture::Literals),
        Some(SourcePosture::All),
    ] {
        let mut al = allowlist();
        al.source_posture = posture;
        let found = scan_text(&value, &SCANNER, &al);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range, 0..value.len());
        assert_eq!(found[0].rule_id, ENTROPY);
    }
}

#[test]
fn audit_retains_context_across_empty_lines() {
    let dir = tempfile::tempdir().unwrap();
    let value = token(3);
    let content = format!("let n = 1;\n\n{value}\nreturn \"{value}\";");
    std::fs::write(dir.path().join("x.rs"), &content).unwrap();
    let input = sekretbarilo::audit::read_file_to_diff("x.rs", dir.path(), None).unwrap();
    assert!(input.context.as_deref() == Some(content.as_bytes()));
    assert_eq!(input.added_lines.len(), 3);
    let found = findings(input, &allowlist());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 4);
}

#[test]
fn multiline_crlf_context_uses_the_scanned_byte_boundaries() {
    let value = token(3);
    let dir = tempfile::tempdir().unwrap();
    let content = format!("let k = \"\r\n{value}\r\n\";\r\n");
    std::fs::write(dir.path().join("x.rs"), &content).unwrap();
    let input = sekretbarilo::audit::read_file_to_diff("x.rs", dir.path(), None).unwrap();
    let found = findings(input, &allowlist());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 2);
    assert!(found[0].matched_value == value.as_bytes());
}

#[test]
fn duplicate_line_numbers_cannot_borrow_another_lines_body_ranges() {
    let value = token(3);
    let line = format!("return \"{value}\";");
    let mut input = file("src/x.rs", &[(1, &line), (1, "x")]);
    input.context = Some(line.as_bytes().to_vec());
    assert!(findings(input, &allowlist()).is_empty());
}

#[test]
fn mismatched_context_cannot_narrow_following_matching_lines() {
    let value = token(3);
    let mut input = file("src/x.rs", &[(1, "let k = \""), (2, &value)]);
    input.context = Some(format!("let k = 1;\n{value}").into_bytes());
    let found = findings(input, &allowlist());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 2);
}

#[test]
fn staged_context_is_bounded_and_comes_from_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(output.status.success());
    };
    git(&["init", "-b", "master"]);
    std::fs::write(dir.path().join("small.rs"), "let staged = 1;\n").unwrap();
    std::fs::write(dir.path().join("limit.rs"), vec![b' '; 4 * 1024 * 1024]).unwrap();
    std::fs::write(dir.path().join("large.rs"), vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    git(&["add", "."]);
    std::fs::write(dir.path().join("small.rs"), "let working = 2;\n").unwrap();
    // run the helper in a child test process so cwd changes cannot race other tests.
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "staged_context_child", "--nocapture"])
        .env("SEKRETBARILO_CONTEXT_CHILD", "1")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn staged_context_child() {
    if std::env::var_os("SEKRETBARILO_CONTEXT_CHILD").is_none() {
        return;
    }
    let mut files: Vec<_> = [
        "small.rs",
        "limit.rs",
        "large.rs",
        "missing.rs",
        "small.conf",
        "small.rs",
        "small.rs",
    ]
    .iter()
    .map(|path| file(path, &[]))
    .collect();
    files[5].is_renamed = true;
    files[6].is_deleted = true;
    for input in &mut files {
        input.context = Some(b"stale".to_vec());
    }
    attach_staged_context(&mut files);
    assert_eq!(
        files[0].context.as_deref(),
        Some(b"let staged = 1;\n".as_slice())
    );
    assert_eq!(files[1].context.as_ref().unwrap().len(), 4 * 1024 * 1024);
    assert!(files[2..].iter().all(|f| f.context.is_none()));
}

#[test]
fn rust_cfg_test_region_suppresses_entropy_with_exact_testpath_trace() {
    let value = token(3);
    for source in [
        format!("#[cfg(test)] mod t {{ let k = \"{value}\"; }}"),
        format!("#[cfg(test)]\n#[allow(dead_code)]\npub(crate) mod t {{\nlet k = \"{value}\";\n}}"),
    ] {
        let lines: Vec<_> = source
            .lines()
            .enumerate()
            .map(|(i, line)| (i + 1, line))
            .collect();
        let input = file("src/x.rs", &lines);
        let mut al = allowlist();
        assert!(scan(std::slice::from_ref(&input), &SCANNER, &al).is_empty());
        al.trace_exemptions = true;
        let traced: Vec<_> = scan(&[input], &SCANNER, &al)
            .into_iter()
            .filter(|finding| finding.matched_value == value.as_bytes())
            .collect();
        assert_eq!(traced.len(), 1);
        assert_eq!(traced[0].rule_id, "exempt:testpath");
        assert_eq!(traced[0].matched_value, value.as_bytes());
    }
}

#[test]
fn rust_cfg_test_region_from_full_context_exempts_only_the_added_literal() {
    let value = token(3);
    let line = format!("let k = \"{value}\";");
    let mut input = file("src/x.rs", &[(3, &line)]);
    input.context = Some(format!("#[cfg(test)]\nmod t {{\n{line}\n}}").into_bytes());
    let mut al = allowlist();
    assert!(scan(std::slice::from_ref(&input), &SCANNER, &al).is_empty());
    al.trace_exemptions = true;
    let traced = scan(&[input], &SCANNER, &al);
    assert_eq!(traced.len(), 1);
    assert_eq!(traced[0].rule_id, "exempt:testpath");
    assert_eq!(traced[0].matched_value, value.as_bytes());
}

#[test]
fn rust_cfg_test_region_leaves_production_literals_before_and_after_its_braces() {
    let value = token(3);
    let literal = format!("let k = \"{value}\";");
    for source in [
        format!("#[cfg(test)] mod t {{}}\n{literal}"),
        format!("#[cfg(test)] mod t {{}} {literal}"),
        format!("{literal} #[cfg(test)] mod t {{}}"),
        format!("#[cfg(test)] mod t {{ {literal} }} {literal}"),
        format!("#[cfg(test)] mod t {{\n}} {literal}"),
    ] {
        let lines: Vec<_> = source
            .lines()
            .enumerate()
            .map(|(i, line)| (i + 1, line))
            .collect();
        let found = findings(file("src/x.rs", &lines), &allowlist());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched_value, value.as_bytes());
    }
}

#[test]
fn rust_cfg_test_region_requires_testpath_setting_and_exemption_layer() {
    let value = token(3);
    let line = format!("#[cfg(test)] mod t {{ let k = \"{value}\"; }}");
    for (skip, layer, posture) in [
        (false, true, None),
        (true, false, None),
        (true, false, Some(SourcePosture::Literals)),
    ] {
        let mut al = allowlist();
        al.tier3_skip_test_paths = skip;
        al.exemption_layer = layer;
        al.source_posture = posture;
        assert_eq!(findings(file("src/x.rs", &[(1, &line)]), &al).len(), 1);
    }
}

#[test]
fn rust_cfg_test_region_is_inert_under_source_posture_all() {
    let value = token(3);
    let line = format!("#[cfg(test)] mod t {{ let k = \"{value}\"; }}");
    let mut al = allowlist();
    al.source_posture = Some(SourcePosture::All);
    assert_eq!(findings(file("src/x.rs", &[(1, &line)]), &al).len(), 1);
}

#[test]
fn rust_cfg_test_region_never_exempts_unknown_or_gapped_diff_lines() {
    let value = token(3);
    let line = format!("let k = \"{value}\";");
    let same_line = format!("#[cfg(test)] mod t {{ {line} }}");
    for input in [
        file("src/x.rs", &[(5, &same_line)]),
        file("src/x.rs", &[(5, "#[cfg(test)] mod t {"), (6, &line)]),
        file("src/x.rs", &[(1, "#[cfg(test)] mod t {"), (5, &line)]),
    ] {
        assert!(input.context.is_none());
        assert_eq!(findings(input, &allowlist()).len(), 1);
    }
}

#[test]
fn rust_cfg_test_region_keeps_tier1_provider_detection() {
    let provider = format!(
        "AKIA{}",
        (0..16)
            .map(|index| char::from(b'A' + ((index * 7 + 3) % 26) as u8))
            .collect::<String>()
    );
    let line = format!("#[cfg(test)] mod t {{ let k = \"{provider}\"; }}");
    let found = scan(&[file("src/x.rs", &[(1, &line)])], &SCANNER, &allowlist());
    assert!(found.iter().any(|f| f.rule_id == "aws-access-key-id"));
}
