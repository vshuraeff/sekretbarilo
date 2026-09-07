use sekretbarilo::config::{self, ProjectConfig, allowlist::CompiledAllowlist};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};

const PASSWORD: &str = "h9L!q2N#v7T@r4W$";
const RULE: &str = "generic-password-assignment";

fn setup() -> (CompiledScanner, CompiledAllowlist) {
    let rules = load_default_rules().unwrap();
    (
        compile_rules(&rules).unwrap(),
        config::build_allowlist(&ProjectConfig::default(), &rules).unwrap(),
    )
}

#[test]
fn quoted_and_plain_assignments_share_the_existing_rule_and_exact_capture() {
    let (scanner, allowlist) = setup();
    for (path, text) in [
        ("config.ini", format!("password = {PASSWORD}")),
        (
            "config.properties",
            format!("spring.datasource.password={PASSWORD}"),
        ),
        ("deploy.sh", format!("export DB_PASSWORD={PASSWORD}")),
        ("config.yaml", format!("password: {PASSWORD}")),
        ("config.toml", format!("password = \"{PASSWORD}\"")),
        (
            "config.json",
            format!("{{\"password\":\"{PASSWORD}\",\"port\":5432}}"),
        ),
        ("config.py", format!("{{'passwd': '{PASSWORD}'}}")),
        ("config.go", format!("password = `{PASSWORD}`")),
        ("config.js", format!("const pwd = `{PASSWORD}`;")),
        ("config.php", format!("$config['password'] = '{PASSWORD}';")),
    ] {
        let file = DiffFile {
            path: path.into(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: vec![AddedLine {
                line_number: 7,
                content: text.as_bytes().to_vec(),
            }],
        };
        let findings = scan(&[file], &scanner, &allowlist);
        let password_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == RULE).collect();
        assert_eq!(password_findings.len(), 1, "{path}: {findings:?}");
        assert_eq!(
            password_findings[0].matched_value,
            PASSWORD.as_bytes(),
            "{path}"
        );
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            text.replace(PASSWORD, "[REDACTED]"),
            "{path}"
        );
    }
}

#[test]
fn matching_quote_pairs_preserve_internal_quotes_escapes_and_spaces() {
    let (scanner, allowlist) = setup();
    for (quote, password) in [
        ('"', "aB9!w'xQ2#rT7pL4"),
        ('\'', "aB9!w\"xQ2#rT7pL4"),
        ('`', "aB9!w'\"xQ2#rT7pL4"),
        ('"', r#"aB9!w\"xQ2#rT7pL4"#),
        ('\'', r"aB9!w\'xQ2#rT7pL4"),
        ('`', r"aB9!w\`xQ2#rT7pL4"),
        ('"', "aB9! wX2# rT7pL4秘密"),
        ('\'', r"aB9!wX2#rT7pL4\"),
        ('`', r"aB9!wX2#rT7pL4\"),
        ('\'', "aB9!w''X2#rT7pL4"),
    ] {
        let text = format!("password = {quote}{password}{quote}; port=5432");
        let matches = scan_text(&text, &scanner, &allowlist);
        assert_eq!(matches.len(), 1, "{text}: {matches:?}");
        assert_eq!(&text[matches[0].range.clone()], password);
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            format!("password = {quote}[REDACTED]{quote}; port=5432")
        );
    }
}

#[test]
fn plain_values_stop_at_separators_and_leave_adjacent_fields_and_comments() {
    let (scanner, allowlist) = setup();
    for text in [
        format!("password={PASSWORD} port=5432"),
        format!("password={PASSWORD};port=5432"),
        format!("{{password: {PASSWORD}, port: 5432}}"),
        format!("connect(password={PASSWORD})"),
        format!("password={PASSWORD}\t# keep this comment"),
        format!("password={PASSWORD} ; keep this comment"),
        format!("host=localhost\r\npassword={PASSWORD}\r\nport=5432\r\n"),
        format!("password={PASSWORD}\npwd={PASSWORD}\n"),
    ] {
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            text.replace(PASSWORD, "[REDACTED]")
        );
    }
    let value = "aB9!xQ2#rT7@pL4$/+=:秘密";
    assert_eq!(
        redact_text(&format!("password={value}"), &scanner, &allowlist),
        "password=[REDACTED]"
    );
    for value in [
        r"aB9!qX2\;rT7pL4",
        r"aB9!qX2\ rT7pL4",
        r"aB9!qX2\,rT7pL4",
        r"aB9!qX2\'rT7pL4",
    ] {
        assert_eq!(
            redact_text(
                &format!("password={value}; port=5432"),
                &scanner,
                &allowlist
            ),
            "password=[REDACTED]; port=5432"
        );
    }
    for ending in ["", "\r\n"] {
        assert_eq!(
            redact_text(
                &format!("password={PASSWORD}\\{ending}"),
                &scanner,
                &allowlist
            ),
            format!("password=[REDACTED]{ending}")
        );
    }
}

#[test]
fn ambiguous_raw_or_escaped_closing_quotes_mask_the_longer_interpretation() {
    let (scanner, allowlist) = setup();
    for quote in ['\'', '`'] {
        let text = format!("password={quote}{PASSWORD}\\{quote}; label={quote}visible{quote}");
        // the same text can contain a raw literal or an escaped quote inside a
        // longer password. keep the conservative interpretation without a parser.
        assert_eq!(
            redact_text(&text, &scanner, &allowlist),
            format!("password={quote}[REDACTED]{quote}visible{quote}")
        );
    }
}

#[test]
fn placeholders_references_weak_values_and_unassigned_lines_stay_clean() {
    let (scanner, allowlist) = setup();
    for text in [
        "password=password",
        "password=changeme",
        "password=aaaaaaaaaaaaaaaaaaaa",
        "password=$DATABASE_PASSWORD",
        "password=${DATABASE_PASSWORD}",
        "password=${var.database_password}",
        "password=${DATABASE_PASSWORD:-fallback}",
        "password=%DATABASE_PASSWORD%",
        "password={{ vault_password }}",
        "password=process.env.DATABASE_PASSWORD",
        "password=os.getenv(\"DATABASE_PASSWORD\")",
        "password=System.getenv(\"DATABASE_PASSWORD\")",
        "password=std::env::var(\"DATABASE_PASSWORD\")",
        "password = #aB9!xQ2rT7pL4 comment",
        "password = ;aB9!xQ2rT7pL4 comment",
        "password =\nh9L!q2N#v7T@r4W$",
        "password_validation_minimum_length = 12",
    ] {
        assert!(scan_text(text, &scanner, &allowlist).is_empty(), "{text}");
    }
}

#[test]
fn existing_value_allowlists_cover_every_quoting_form() {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::new(
        &[],
        &[],
        None,
        &[(
            RULE.into(),
            vec![format!("^{}$", regex::escape(PASSWORD))],
            vec![],
        )],
        false,
    )
    .unwrap();
    for quote in ["", "\"", "'", "`"] {
        assert!(
            scan_text(
                &format!("password={quote}{PASSWORD}{quote}"),
                &scanner,
                &allowlist
            )
            .is_empty()
        );
    }
}

#[test]
fn custom_override_of_existing_rule_keeps_its_capture_semantics() {
    let mut rules = load_default_rules().unwrap();
    let rule = rules.iter_mut().find(|r| r.id == RULE).unwrap();
    rule.regex_pattern = "PASSWORD=([A-Za-z0-9!]+)".into();
    rule.secret_group = 1;
    rule.secret_groups.clear();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    assert!(scan_text(&format!("password={PASSWORD}"), &scanner, &allowlist).is_empty());
    let value = "Q7m4V9!z2N8k5!p3R6";
    assert_eq!(
        redact_text(&format!("PASSWORD={value}"), &scanner, &allowlist),
        "PASSWORD=[REDACTED]"
    );
}

#[test]
fn old_custom_rules_keep_whole_match_fallback_without_opted_in_groups() {
    let config: ProjectConfig = toml::from_str(
        r#"
[[rules]]
id = "generic-password-assignment"
description = "custom optional group"
regex = 'PASSWORD=(DISABLED)?(?P<password_unquoted>Q7m4V9!z2N8k5!p3R6)'
secret_group = 1
keywords = ["password"]
"#,
    )
    .unwrap();
    assert!(config.rules[0].secret_groups.is_empty());
    let rules = config::load_rules_with_config(&config).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = config::build_allowlist(&config, &rules).unwrap();
    assert_eq!(
        redact_text("PASSWORD=Q7m4V9!z2N8k5!p3R6", &scanner, &allowlist),
        "[REDACTED]"
    );
}
