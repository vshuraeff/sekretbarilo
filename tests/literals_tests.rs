use sekretbarilo::scanner::literals::{Language, LineLiterals, LiteralTracker, language_for_path};

fn assert_bodies(tracker: &mut LiteralTracker, number: usize, line: &[u8], expected: &[&[u8]]) {
    let result = tracker.feed(line, number);
    assert!(result.known, "line {number}: {line:?}: {result:?}");
    assert!(tracker.is_known(), "line {number}: {line:?}");
    let mut previous_end = 0;
    for range in &result.bodies {
        assert!(previous_end <= range.start && range.start <= range.end && range.end <= line.len());
        previous_end = range.end;
    }
    let bodies: Vec<_> = result
        .bodies
        .iter()
        .map(|range| &line[range.clone()])
        .collect();
    assert_eq!(bodies, expected, "line {number}: {line:?}");
}

#[test]
fn source_extension_selection_matrix_is_rust_and_go_only() {
    for (extension, expected) in [
        ("rs", Some(Language::Rust)),
        ("go", Some(Language::Go)),
        ("py", None),
        ("pyi", None),
        ("js", None),
        ("jsx", None),
        ("mjs", None),
        ("cjs", None),
        ("ts", None),
        ("tsx", None),
        ("mts", None),
        ("cts", None),
        ("c", None),
        ("h", None),
        ("cc", None),
        ("cpp", None),
        ("cxx", None),
        ("hpp", None),
        ("hxx", None),
    ] {
        let mixed: String = extension
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index % 2 == 0 {
                    character.to_ascii_uppercase()
                } else {
                    character
                }
            })
            .collect();
        for extension in [extension.to_owned(), extension.to_ascii_uppercase(), mixed] {
            let path = format!("src/sample.{extension}");
            assert_eq!(language_for_path(&path), expected, "{path}");
        }
    }
    for path in [
        "src/sample.d.ts",
        "data/sample.txt",
        "scripts/sample.sh",
        "README.md",
        "Makefile",
    ] {
        assert_eq!(language_for_path(path), None, "{path}");
    }
}

#[test]
fn path_selected_trackers_return_byte_ranges_to_consumers() {
    for language in [Language::Rust, Language::Go] {
        let mut tracker = LiteralTracker::new(language);
        let line = "  \"é\\\"ok\"".as_bytes();
        let result = tracker.feed(line, 1);
        assert_eq!(
            result,
            LineLiterals {
                bodies: std::iter::once(3..9).collect(),
                known: true,
                test_span: None,
            }
        );
        assert_eq!(&line[result.bodies[0].clone()], "é\\\"ok".as_bytes());
        assert_bodies(&mut tracker, 2, b"plain_identifier", &[]);
    }
}

#[test]
fn rust_stream_carries_raw_hash_counts_between_comments_and_byte_strings() {
    for count in [1, 3] {
        let hashes = "#".repeat(count);
        let mut tracker = LiteralTracker::new(Language::Rust);
        assert_bodies(&mut tracker, 1, b"/* an open comment", &[]);
        let opening = format!("*/ let value = r{hashes}\"first");
        assert_bodies(&mut tracker, 2, opening.as_bytes(), &[b"first"]);
        let short_closer = format!("middle\"{} // still literal", "#".repeat(count - 1));
        assert_bodies(
            &mut tracker,
            3,
            short_closer.as_bytes(),
            &[short_closer.as_bytes()],
        );
        let closing = format!("last\"{hashes}; let bytes = b\"escaped\\\"quote\"; /*");
        assert_bodies(
            &mut tracker,
            4,
            closing.as_bytes(),
            &[b"last", br#"escaped\"quote"#],
        );
        assert_bodies(
            &mut tracker,
            5,
            b"\"hidden\" */ let done = \"visible\";",
            &[b"visible"],
        );
    }
}

#[test]
fn go_stream_moves_between_raw_strings_comments_and_interpreted_strings() {
    let mut tracker = LiteralTracker::new(Language::Go);
    assert_bodies(&mut tracker, 1, b"value := `first", &[b"first"]);
    assert_bodies(
        &mut tracker,
        2,
        br#"/* "quoted" \n */"#,
        &[br#"/* "quoted" \n */"#],
    );
    assert_bodies(
        &mut tracker,
        3,
        br#"last`; next := "a\"b"; /*"#,
        &[b"last", br#"a\"b"#],
    );
    assert_bodies(&mut tracker, 4, br#"`ignored` "ignored""#, &[]);
    assert_bodies(
        &mut tracker,
        5,
        br#"*/ r := '\''; value = "after" // "hidden""#,
        &[b"after"],
    );
}

#[test]
fn go_struct_tags_keep_keys_whole_values_and_comma_items() {
    let cases: &[(&str, &[&str])] = &[
        (
            r#"json:"name,omitempty""#,
            &["json", "name,omitempty", "name", "omitempty"],
        ),
        (
            r#"json:"left\"quote,opaque" yaml:"other""#,
            &[
                "json",
                r#"left\"quote,opaque"#,
                r#"left\"quote"#,
                "opaque",
                "yaml",
                "other",
            ],
        ),
        (
            r#"json:"first\x2csecond,third""#,
            &[
                "json",
                r#"first\x2csecond,third"#,
                r#"first\x2csecond"#,
                "third",
            ],
        ),
        (
            r#"json:"a,b,c,d""#,
            &["json", "a,b,c,d", "a", "b", "c", "d"],
        ),
        (r#"unusual=key:"x" json:"""#, &["unusual=key", "x", "json"]),
    ];
    for (tag, expected) in cases {
        let line = format!("type T struct {{ Field string `{tag}` }}");
        let mut tracker = LiteralTracker::new(Language::Go);
        let result = tracker.feed(line.as_bytes(), 1);
        assert!(result.known);
        let bodies: Vec<_> = result
            .bodies
            .iter()
            .map(|range| &line[range.clone()])
            .collect();
        assert_eq!(bodies, *expected, "{tag}");
    }
}

#[test]
fn go_struct_tag_crash_seed_keeps_contained_item_ranges() {
    let line = include_bytes!("../fuzz/corpus/literals/overlapping-go-tag");
    let result = LiteralTracker::new(Language::Go).feed(line, 1);
    assert!(result.known);
    assert_eq!(result.bodies, vec![16..20, 22..38, 22..25, 26..38]);
    for range in result.bodies {
        assert!(range.start <= range.end && range.end <= line.len());
    }
}

#[test]
fn go_malformed_tag_keeps_the_raw_body() {
    for tag in [
        r#"json:"broken" extra"#,
        r#"json:"unterminated"#,
        r#"json:"bad\q""#,
        r#"json:"bad\777""#,
        r#"json:"bad\uD800""#,
        "bad\x7fkey:\"value\"",
    ] {
        let line = format!("type T struct {{ Field string `{tag}` }}");
        let mut tracker = LiteralTracker::new(Language::Go);
        let result = tracker.feed(line.as_bytes(), 1);
        assert!(result.known);
        assert_eq!(result.bodies.len(), 1);
        assert_eq!(&line[result.bodies[0].clone()], tag);
    }
}

#[test]
fn python_stream_preserves_triple_quoted_bodies_and_resumes_prefixed_strings() {
    let mut tracker = LiteralTracker::new(Language::Python);
    assert_bodies(&mut tracker, 1, b"value = r'''first", &[b"first"]);
    assert_bodies(
        &mut tracker,
        2,
        br#"# "still a body" \'quote"#,
        &[br#"# "still a body" \'quote"#],
    );
    assert_bodies(
        &mut tracker,
        3,
        br#"last'''; other = b"a\"b" # "hidden""#,
        &[b"last", br#"a\"b"#],
    );
    assert_bodies(&mut tracker, 4, b"value = f\"\"\"next", &[b"next"]);
    assert_bodies(
        &mut tracker,
        5,
        b"end\"\"\"; other = u'plain'",
        &[b"end", b"plain"],
    );
    assert_bodies(&mut tracker, 6, b"# ''' no open string", &[]);
    assert_bodies(&mut tracker, 7, b"bare_code", &[]);
}

#[test]
fn javascript_stream_returns_only_template_text_and_interpolation_literals() {
    let mut tracker = LiteralTracker::new(Language::JavaScript);
    assert_bodies(&mut tracker, 1, b"const text = `first ${", &[b"first "]);
    assert_bodies(
        &mut tracker,
        2,
        br#"call("a\"b") /* an open comment"#,
        &[br#"a\"b"#],
    );
    assert_bodies(&mut tracker, 3, b"`ignored` } */", &[]);
    assert_bodies(&mut tracker, 4, br"} tail\`still", &[br" tail\`still"]);
    assert_bodies(
        &mut tracker,
        5,
        br#"last`; const other = 'plain'; // `hidden`"#,
        &[b"last", b"plain"],
    );
    assert_bodies(&mut tracker, 6, b"bare_code", &[]);
}

#[test]
fn c_stream_handles_continuation_adjacent_strings_and_comments() {
    let mut tracker = LiteralTracker::new(Language::C);
    assert_bodies(
        &mut tracker,
        1,
        b"const char *value = \"first\\",
        &[b"first"],
    );
    assert_bodies(
        &mut tracker,
        2,
        br#"last" "a\"b"; char quote = '\''; /*"#,
        &[b"last", br#"a\"b"#],
    );
    assert_bodies(&mut tracker, 3, b"\"hidden\"", &[]);
    assert_bodies(
        &mut tracker,
        4,
        br#"*/ auto raw = R"end(first"#,
        &[b"first"],
    );
    assert_bodies(
        &mut tracker,
        5,
        br#"/* literal */ )other""#,
        &[br#"/* literal */ )other""#],
    );
    assert_bodies(
        &mut tracker,
        6,
        br#"last)end"; value = "after";"#,
        &[b"last", b"after"],
    );
}

#[test]
fn unknown_lines_discard_partial_bodies_until_contiguous_recovery() {
    let mut tracker = LiteralTracker::new(Language::JavaScript);
    assert_bodies(&mut tracker, 1, b"const value = `open", &[b"open"]);
    for number in [10, 11] {
        let result = tracker.feed(br#""visible"; /unterminated"#, number);
        assert_eq!(
            result,
            LineLiterals {
                bodies: vec![],
                known: false,
                test_span: None,
            }
        );
        assert!(!tracker.is_known());
    }
    let result = tracker.feed(b"const value = `recovery", 12);
    assert!(!result.known);
    assert!(result.bodies.is_empty());
    assert!(tracker.is_known());
    assert_bodies(&mut tracker, 13, b"body`", &[b"body"]);
    assert_bodies(&mut tracker, 14, b"outside", &[]);
}

#[test]
fn reset_reuses_a_tracker_for_a_new_document_without_leaking_open_state() {
    for (language, opener, fresh) in [
        (Language::Rust, "r###\"old", "b\"new\""),
        (Language::Go, "`old", "\"new\""),
        (Language::Python, "'''old", "r'new'"),
        (Language::JavaScript, "`old ${", "'new'"),
        (Language::C, "/* old", "\"new\""),
    ] {
        let mut tracker = LiteralTracker::new(language);
        assert!(tracker.feed(opener.as_bytes(), 1).known);
        tracker.reset();
        assert!(tracker.is_known());
        assert_bodies(&mut tracker, 1, fresh.as_bytes(), &[b"new"]);
        assert_bodies(&mut tracker, 2, b"plain_code", &[]);
    }
    let mut tracker = LiteralTracker::new(Language::JavaScript);
    assert!(!tracker.feed(b"/unterminated", 20).known);
    assert!(!tracker.is_known());
    tracker.reset();
    assert!(tracker.is_known());
    assert_bodies(&mut tracker, 1, b"'new'", &[b"new"]);
}

#[test]
fn rust_test_regions_match_exact_tokens_and_allowed_item_prefixes() {
    for source in [
        "#[cfg(test)] mod t { body } after",
        "#[cfg(test)]\nmod t { body } after",
        "# \t[\ncfg \n( test\n) ]\nmod\nt\n{ body } after",
        "#[cfg(test)] #[allow(dead_code)] mod t { body } after",
        "#[cfg(test)] #[attr([nested], text = \"[ ]\")] mod t { body } after",
        "#[cfg(test)] pub(crate) mod t { body } after",
        "#[cfg(test)] pub mod t { body } after",
        "#[cfg(test)] pub(in crate::parent) mod t { body } after",
        "#[cfg(test)] // comment\n/* nested /* comment */ */ mod /* c */ t { body } after",
    ] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        for (index, line) in source.lines().enumerate() {
            let result = tracker.feed(line.as_bytes(), index + 1);
            assert!(result.known, "{source}");
            let expected = line
                .find('{')
                .map(|start| start + 1..line.rfind('}').unwrap());
            assert_eq!(result.test_span, expected, "{source}: {line}");
        }
    }
}

#[test]
fn rust_test_regions_reject_noncode_attributes_and_other_items() {
    for source in [
        "\"#[cfg(test)] mod t {\"",
        "r##\"#[cfg(test)] mod t {\"##",
        "// #[cfg(test)] mod t {",
        "/* #[cfg(test)] mod t { */",
        "#[cfg(test)] const X: u8 = 1;",
        "#[cfg(test)] mod t;",
        "#[cfg(test)] ; mod t {",
        "#[cfg(any(test, unix))] mod t {",
        "#[cfg(not(test))] mod t {",
        "#[cfg_attr(test, allow(dead_code))] mod t {",
        "#[cfg(testing)] mod t {",
        "#[cfg(test)] module t {",
        "#[cfg(test)] mod 123 {",
        "#[cfg(test)] mod t extra {",
        "#[cfg(test)] \"ignored\" mod t {",
    ] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        assert_eq!(
            tracker.feed(source.as_bytes(), 1).test_span,
            None,
            "{source}"
        );
        assert_eq!(tracker.feed(b"fn f() {", 2).test_span, None, "{source}");
        assert_eq!(tracker.feed(b"body", 3).test_span, None, "{source}");
    }
    for opener in ["\"", "r#\"", "/*"] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        tracker.feed(opener.as_bytes(), 1);
        assert_eq!(tracker.feed(b"#[cfg(test)] mod t {", 2).test_span, None);
    }
}

#[test]
fn rust_cfg_implication_and_body_items() {
    for predicate in [
        "test",
        "all(test, unix)",
        "all(unix, any(test, all(test, feature = \"fast\")))",
        "all(test, not(unix))",
        "any(test, all(test, unix))",
        "any(all(test, unix), all(test, feature = \"fast\"))",
    ] {
        for item in [
            "mod t",
            "fn f()",
            "fn f() -> Thing",
            "const fn f() -> Vec<Thing>",
            "extern \"C\" fn f()",
            "pub(crate) async fn f()",
            "impl Thing",
        ] {
            let source = format!("#[cfg({predicate})] {item} {{ body }} after");
            let mut tracker = LiteralTracker::new(Language::Rust);
            let start = source.find('{').unwrap() + 1;
            let end = source.rfind('}').unwrap();
            assert_eq!(
                tracker.feed(source.as_bytes(), 1).test_span,
                Some(start..end),
                "{source}"
            );
            assert_eq!(tracker.feed(b"production", 2).test_span, None, "{source}");
        }
    }
    let mut tracker = LiteralTracker::new(Language::Rust);
    let source = "#[cfg(/* comment */ test)] mod t { body }";
    let start = source.find('{').unwrap() + 1;
    let end = source.rfind('}').unwrap();
    assert_eq!(
        tracker.feed(source.as_bytes(), 1).test_span,
        Some(start..end)
    );
    for predicate in [
        "any(test, unix)",
        "any(test, not(test))",
        "not(test)",
        "all(unix, feature = \"fast\")",
        "all()",
        "any()",
        "all(test,)",
        "all(test, mystery(test))",
        "all(test, not(test, unix))",
        "all(test, not())",
    ] {
        let source = format!("#[cfg({predicate})] fn f() {{ body }}");
        let mut tracker = LiteralTracker::new(Language::Rust);
        let expected = predicate == "all(test,)";
        assert_eq!(
            tracker.feed(source.as_bytes(), 1).test_span.is_some(),
            expected,
            "{source}"
        );
    }
}

#[test]
fn rust_inner_cfg_applies_only_to_fresh_eligible_scope() {
    for source in [
        "#![cfg(test)]\nfn f() { body }",
        "mod m {\n#![cfg(test)]\nfn f() { body }\n}",
        "fn f() {\n#![cfg(test)]\nlet x = 1;\n}",
        "impl Thing {\n#![cfg(test)]\nfn f() { body }\n}",
    ] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        let lines: Vec<_> = source.lines().collect();
        let marked: Vec<_> = lines
            .iter()
            .enumerate()
            .map(|(i, line)| tracker.feed(line.as_bytes(), i + 1).test_span)
            .collect();
        assert!(marked.iter().any(Option::is_some), "{source}");
        if !source.starts_with("#!") {
            assert_eq!(
                tracker.feed(b"production", lines.len() + 1).test_span,
                None,
                "{source}"
            );
        }
    }
    for source in [
        "mod m {\nlet x = 1;\n#![cfg(test)]\nfn f() { body }\n}",
        "macro_rules! m {\n#![cfg(test)]\nfn f() { body }\n}",
        "#[cfg(test)] use a::{b,c};\nfn f() { body }",
        "#[cfg(test)] mod other;\nfn f() { body }",
        "#[cfg(test)] fn f() -> [u8; { 1 }] { body }",
        "emit! {\n; fn apparent() {\n#![cfg(test)]\nproduction_marker\n}\n}",
        "emit!(; #[cfg(test)] fn apparent() {\nproduction_marker\n});",
        "emit![; #[cfg(test)] fn apparent() {\nproduction_marker\n}];",
    ] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        for (i, line) in source.lines().enumerate() {
            assert_eq!(
                tracker.feed(line.as_bytes(), i + 1).test_span,
                None,
                "{source}: {line}"
            );
        }
    }
    let mut tracker = LiteralTracker::new(Language::Rust);
    assert_eq!(tracker.feed(b"mod m {", 1).test_span, None);
    assert!(
        tracker
            .feed(b"#[cfg(test)] fn f() {}", 2)
            .test_span
            .is_some()
    );
    assert_eq!(tracker.feed(b"#![cfg(test)]", 3).test_span, None);
    assert_eq!(tracker.feed(b"fn prod() { body }", 4).test_span, None);
}

#[test]
fn rust_inner_cfg_does_not_extend_an_earlier_same_line_region() {
    for first in ["#[cfg(test)] fn t() {}", "#[cfg(test)] mod t {\n}"] {
        for later in ["fn p()", "mod p", "impl Thing"] {
            let source =
                format!("{first} const K: &str = \"production\"; {later} {{ #![cfg(test)] }}");
            let mut tracker = LiteralTracker::new(Language::Rust);
            for (index, line) in source.lines().enumerate() {
                let result = tracker.feed(line.as_bytes(), index + 1);
                if line.contains("production") {
                    let production = line.find("production").unwrap();
                    assert!(result.known, "{source}");
                    assert!(
                        result
                            .test_span
                            .as_ref()
                            .is_none_or(|span| !span.contains(&production)),
                        "{source}: {result:?}"
                    );
                }
            }
            assert_eq!(
                tracker
                    .feed(b"production", source.lines().count() + 1)
                    .test_span,
                None
            );
        }
    }
}

#[test]
fn rust_attribute_braces_do_not_change_item_scope_depth() {
    for attribute in ["#[note { a }]", "#[note({ a })]", "#[note([{ a }])]"] {
        let source = format!("{attribute} fn x() {{}} #[cfg(test)] mod t {{ body }}");
        let mut tracker = LiteralTracker::new(Language::Rust);
        let result = tracker.feed(source.as_bytes(), 1);
        let body = source.find("body").unwrap();
        assert!(result.known, "{source}");
        assert!(
            result.test_span.is_some_and(|span| span.contains(&body)),
            "{source}"
        );
        assert_eq!(tracker.feed(b"production", 2).test_span, None, "{source}");
    }
}

#[test]
fn rust_inner_cfg_after_a_boundary_is_not_a_fresh_scope() {
    for earlier in [
        ";",
        "#[cfg(test)] ;",
        "{ let a = 1; }",
        "#[allow(dead_code)] { let a = 1; }",
    ] {
        let source = format!("fn f() {{ {earlier} #![cfg(test)] let k = \"production\"; }}");
        let mut tracker = LiteralTracker::new(Language::Rust);
        let result = tracker.feed(source.as_bytes(), 1);
        assert!(result.known, "{source}");
        assert_eq!(result.test_span, None, "{source}");
    }
}

#[test]
fn rust_attribute_buffer_limit_keeps_later_lines_unknown() {
    let mut tracker = LiteralTracker::new(Language::Rust);
    let nested = format!("#[cfg(test)] #[allow({})] fn f() {{}}", "[".repeat(600));
    let first = tracker.feed(nested.as_bytes(), 1);
    assert!(!first.known);
    assert_eq!(first.test_span, None);
    let later = tracker.feed(b"#[cfg(test)] fn f() { body }", 2);
    assert!(!later.known);
    assert_eq!(later.test_span, None);
}

#[test]
fn rust_test_region_depth_ignores_literals_comments_and_nested_attributes() {
    let mut tracker = LiteralTracker::new(Language::Rust);
    assert_eq!(tracker.feed(b"mod outer {", 1).test_span, None);
    let opening = b"#[cfg(test)] mod t {";
    assert_eq!(
        tracker.feed(opening, 2).test_span,
        Some(opening.len()..opening.len())
    );
    for (index, line) in [
        "fn f() { let c = '{'; let s = \"}\";",
        "let raw = r#\"} {\"#; /* } */ }",
        "#[cfg(test)] mod nested { }",
        "body",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            tracker.feed(line.as_bytes(), index + 3).test_span,
            Some(0..line.len())
        );
    }
    assert_eq!(tracker.feed(b"  } production", 7).test_span, Some(0..2));
    assert_eq!(tracker.feed(b"let production = 1; }", 8).test_span, None);
    assert_eq!(tracker.feed(b"}}}", 9).test_span, None);
    assert_eq!(
        tracker.feed(b"#[cfg(test)] mod next {}", 10).test_span,
        None
    );
}

#[test]
fn rust_test_region_closing_wins_over_another_opening_on_the_same_line() {
    for prefix in ["", "#[cfg(test)] mod first {\n"] {
        let source = format!(
            "{prefix}{}",
            if prefix.is_empty() {
                "#[cfg(test)] mod first {} #[cfg(test)] mod second {"
            } else {
                "} #[cfg(test)] mod second {"
            }
        );
        let mut tracker = LiteralTracker::new(Language::Rust);
        let mut count = 0;
        for (index, line) in source.lines().enumerate() {
            count = index + 1;
            let result = tracker.feed(line.as_bytes(), count);
            if let Some(end) = line.find('}') {
                let start = if prefix.is_empty() {
                    line.find('{').unwrap() + 1
                } else {
                    0
                };
                assert_eq!(result.test_span, Some(start..end));
            }
        }
        assert_eq!(tracker.feed(b"body", count + 1).test_span, None);
    }
    let mut tracker = LiteralTracker::new(Language::Rust);
    tracker.feed(b"#[cfg(test)] mod first {", 1);
    assert_eq!(tracker.feed(b"} #[cfg(test)]", 2).test_span, Some(0..0));
    assert_eq!(tracker.feed(b"mod second {", 3).test_span, Some(12..12));
    assert_eq!(tracker.feed(b"body", 4).test_span, Some(0..4));
}

#[test]
fn rust_unclosed_test_regions_reach_eof_including_line_terminators() {
    let mut tracker = LiteralTracker::new(Language::Rust);
    tracker.feed(b"#[cfg(test)] mod t {", 1);
    for (index, line) in [b"body\r\n".as_slice(), b"", b"last"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(tracker.feed(line, index + 2).test_span, Some(0..line.len()));
    }
}

#[test]
fn rust_unknown_lines_and_reset_forget_pending_and_open_test_regions() {
    for first in [
        b"#[cfg(test)] mod t {".as_slice(),
        b"#[cfg(test)]",
        b"#[cfg(",
    ] {
        let mut tracker = LiteralTracker::new(Language::Rust);
        tracker.feed(first, 1);
        let unknown = tracker.feed(b"#[cfg(test)] mod lost {", 5);
        assert!(!unknown.known);
        assert_eq!(unknown.test_span, None);
        assert_eq!(tracker.feed(b"body", 6).test_span, None);
        tracker.reset();
        assert_eq!(tracker.feed(b"mod fresh {", 1).test_span, None);
    }
    let mut tracker = LiteralTracker::new(Language::Rust);
    tracker.feed(b"#[cfg(test)] mod t {", 1);
    let broken = tracker.feed(b"'\\", 2);
    assert!(!broken.known);
    assert_eq!(broken.test_span, None);
    assert_eq!(tracker.feed(b"body", 3).test_span, None);
    let mut tracker = LiteralTracker::new(Language::Rust);
    assert!(!tracker.feed(b"#[cfg(test)]", 5).known);
    assert_eq!(tracker.feed(b"mod lost {", 6).test_span, None);
}

#[test]
fn non_rust_trackers_never_set_test_spans() {
    for language in [
        Language::Go,
        Language::Python,
        Language::JavaScript,
        Language::C,
    ] {
        let mut tracker = LiteralTracker::new(language);
        for (index, line) in ["#[cfg(test)] mod t {", "body", "}"].iter().enumerate() {
            assert_eq!(tracker.feed(line.as_bytes(), index + 1).test_span, None);
        }
    }
}
