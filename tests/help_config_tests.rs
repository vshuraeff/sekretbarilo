mod common;
use common::IsolatedEnv;

#[test]
fn embedded_reference_examples_parse_and_cover_sections() {
    let env = IsolatedEnv::new();
    let out = run(&env, &["help", "config"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for snippet in text.split("```toml\n").skip(1) {
        let config = snippet.split("```").next().unwrap();
        toml::from_str::<sekretbarilo::config::ProjectConfig>(config).unwrap();
    }
    for term in [
        "[settings]",
        "[settings.rules]",
        "[settings.rule_classes]",
        "[allowlist]",
        "[[allowlist.rules]]",
        "[[rules]]",
        "[audit]",
        "tier3_skip_test_paths",
        "secret_groups",
        "XDG_CONFIG_HOME",
    ] {
        assert!(text.contains(term), "missing {term}");
    }
}

fn run(env: &IsolatedEnv, args: &[&str]) -> std::process::Output {
    env.command()
        .args(args)
        .current_dir(env.home())
        .output()
        .unwrap()
}

#[test]
fn static_help_and_defaults_survive_invalid_config() {
    let env = IsolatedEnv::new();
    std::fs::write(
        env.home().join(".sekretbarilo.toml"),
        "[settings.rule_classes]\nheuristic='PRIVATE_MARKER'\n",
    )
    .unwrap();
    for args in [
        vec!["help"],
        vec!["help", "config"],
        vec!["help", "rules", "--defaults"],
    ] {
        let out = run(&env, &args);
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
        assert!(!out.stdout.is_empty());
    }
    let out = run(&env, &["help", "rules"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("see: sekretbarilo help config"));
    assert!(!err.contains("PRIVATE_MARKER"));
}

#[test]
fn inventory_reports_defaults_overrides_custom_rules_and_public_key_gate() {
    let env = IsolatedEnv::new();
    let out = run(&env, &["help", "rules", "--defaults"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().skip(2).count(), 113);
    assert!(text.contains("generic-high-entropy-value\theuristic\tdisabled\tdefault"));
    assert!(text.contains("pem-public-key\tsignature\tdisabled\tdetect_public_keys gate"));
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\tenabled\t"))
            .count(),
        109
    );
    let ids: Vec<_> = text
        .lines()
        .skip(2)
        .map(|line| line.split('\t').next().unwrap())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    std::fs::write(
        env.home().join(".sekretbarilo.toml"),
        r#"
[settings.rule_classes]
signature = false
[settings.rules]
generic-high-entropy-value = true
pem-public-key = true
[[rules]]
id = "custom-help-rule"
description = "synthetic"
regex = '(CUSTOM_[A-Z]{10})'
secret_group = 1
keywords = ['custom_']
"#,
    )
    .unwrap();
    let out = run(&env, &["help", "rules"]);
    assert!(out.status.success(), "{:?}", out);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("custom-help-rule\tcontextual\tenabled\tdefault"));
    assert!(text.contains("generic-high-entropy-value\theuristic\tenabled\trule override"));
    assert!(text.contains("aws-access-key-id\tsignature\tdisabled\tclass"));
    assert!(text.contains("pem-public-key\tsignature\tdisabled\tdetect_public_keys gate"));
}

#[test]
fn help_rejects_bad_topics_flags_and_unknown_switches() {
    let env = IsolatedEnv::new();
    for args in [
        vec!["help", "wat"],
        vec!["help", "config", "--defaults"],
        vec!["help", "rules", "--no-defaults"],
        vec!["help", "rules", "--defaults", "extra"],
    ] {
        let out = run(&env, &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
    std::fs::write(
        env.home().join(".sekretbarilo.toml"),
        "[settings.rules]\nunknown-rule=false\n",
    )
    .unwrap();
    assert_eq!(run(&env, &["help", "rules"]).status.code(), Some(2));
    let old = run(&env, &["--help"]);
    assert!(old.status.success());
    assert!(old.stdout.is_empty());
    assert!(String::from_utf8_lossy(&old.stderr).contains("help <topic>"));
}
