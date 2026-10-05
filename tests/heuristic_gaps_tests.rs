use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan};
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

const RULE: &str = "generic-high-entropy-value";

fn opaque() -> String {
    (0..32)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + (index % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

fn findings(line: &str, path: &str) -> Vec<sekretbarilo::scanner::engine::Finding> {
    let scanner = compile_rules(&load_default_rules().unwrap()).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    let file = DiffFile {
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
    };
    scan(&[file], &scanner, &allowlist)
}

#[test]
fn shell_default_operators_report_only_the_operand() {
    let value = opaque();
    for operator in [":-", ":="] {
        for line in [
            format!("${{VAR{operator}{value}}}"),
            format!("VALUE=${{VAR{operator}{value}}}"),
            format!("VALUE=\"${{VAR{operator}{value}}}\""),
            format!("\"${{VAR{operator}{value}}}\""),
        ] {
            let matches: Vec<_> = findings(&line, "config/shapes.txt")
                .into_iter()
                .filter(|finding| finding.rule_id == RULE)
                .collect();
            assert_eq!(matches.len(), 1, "{line}");
            assert_eq!(matches[0].matched_value, value.as_bytes(), "{line}");
        }
    }
    for line in ["${TMPDIR:-/tmp}", "${EDITOR:=vim}"] {
        assert!(findings(line, "config/shapes.txt").is_empty(), "{line}");
    }
}

#[test]
fn trailing_comma_reports_only_quoted_body_on_text_and_source_paths() {
    let value = opaque();
    let scanner = compile_rules(&load_default_rules().unwrap()).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    for path in ["data/list.json", "scripts/list.py", "notes/list.txt"] {
        for quote in ['"', '\''] {
            let line = format!("    {quote}{value}{quote},");
            let matches: Vec<_> = findings(&line, path)
                .into_iter()
                .filter(|finding| finding.rule_id == RULE)
                .collect();
            assert_eq!(matches.len(), 1, "{path}: {line}");
            assert_eq!(matches[0].matched_value, value.as_bytes(), "{path}: {line}");
            assert_eq!(
                redact_text(&line, &scanner, &allowlist),
                line.replace(&value, "[REDACTED]")
            );
        }
    }
}
