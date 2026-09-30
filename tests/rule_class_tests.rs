// rule classes and the [settings.rule_classes] / [settings.rules] switches

mod common;

use common::IsolatedEnv;
use sekretbarilo::config::merge::merge_all;
use sekretbarilo::config::{
    ProjectConfig, RuleSwitchReason, load_all_rules_with_config, load_custom_rules_with_config,
    load_rules_with_config, rule_switch,
};
use sekretbarilo::scanner::rules::RuleClass;

/// run `scan` in a fresh repo whose discovered project layer is `config`.
fn scan_with_project_config(config: &str, args: &[&str]) -> std::process::Output {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    std::fs::write(repo.join(".sekretbarilo.toml"), config).unwrap();
    // stage a clean file so the run reaches the scan itself, not only config validation
    std::fs::write(repo.join("notes.txt"), "hello\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "notes.txt"])
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .current_dir(&repo)
        .output()
        .unwrap();
    env.command()
        .arg("scan")
        .args(args)
        .current_dir(&repo)
        .output()
        .unwrap()
}

#[test]
fn misspelt_class_in_a_discovered_layer_fails_the_scan() {
    let out = scan_with_project_config("[settings.rule_classes]\nheurisitic = true\n", &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(".sekretbarilo.toml"), "{stderr}");
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(
        stderr.contains("invalid TOML syntax or configuration type"),
        "{stderr}"
    );
}

#[test]
fn config_parse_errors_never_echo_values_or_comments() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let path = repo.join(".sekretbarilo.toml");
    std::fs::write(repo.join("notes.txt"), "ordinary text\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["add", "notes.txt"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    for content in [
        "[settings.rule_classes]\nheuristic = 'SYNTHETIC_PRIVATE_VALUE' # SYNTHETIC_PRIVATE_COMMENT\n",
        "[settings.rule_classes]\n'SYNTHETIC_PRIVATE_VALUE' = true # SYNTHETIC_PRIVATE_COMMENT\n",
        "[settings]\nentropy_threshold = 'SYNTHETIC_PRIVATE_VALUE' # SYNTHETIC_PRIVATE_COMMENT\n",
        "[settings]\nentropy_threshold = [ # SYNTHETIC_PRIVATE_COMMENT\n'SYNTHETIC_PRIVATE_VALUE'\n",
    ] {
        std::fs::write(&path, content).unwrap();
        for explicit in [false, true] {
            let mut command = env.command();
            command.arg("scan").current_dir(&repo);
            if explicit {
                command.arg("--config").arg(&path);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(".sekretbarilo.toml"), "{stderr}");
            assert!(
                stderr.contains("line ") && stderr.contains("column "),
                "{stderr}"
            );
            assert!(!stderr.contains("SYNTHETIC_PRIVATE"), "{stderr}");
        }
    }
}

#[test]
fn both_skip_spellings_in_a_discovered_layer_fail_the_scan() {
    let out = scan_with_project_config(
        "[settings]\ntier3_skip_test_paths = false\nheuristic_skip_test_paths = true\n",
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_rule_switch_fails_with_and_without_no_defaults() {
    let config = "[settings.rules]\n\"no-such-rule\" = false\n";
    for args in [&[][..], &["--no-defaults"][..]] {
        let out = scan_with_project_config(config, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("no-such-rule"), "{args:?}: {stderr}");
    }
}

#[test]
fn no_defaults_accepts_switches_for_embedded_rules() {
    let out = scan_with_project_config(
        "[settings.rules]\n\"aws-access-key-id\" = false\n\n[[rules]]\nid = \"custom-token\"\ndescription = \"c\"\nregex = \"(CUSTOM_[A-Z]{10})\"\nsecret_group = 1\nkeywords = [\"custom_\"]\n",
        &["--no-defaults"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_defaults_same_id_custom_rule_inherits_the_embedded_class() {
    let custom = "[[rules]]\nid = \"generic-high-entropy-value\"\ndescription = \"c\"\nregex = \"(MARK_[A-Z]{10})\"\nsecret_group = 1\nkeywords = [\"mark_\"]\n";
    let off = load_custom_rules_with_config(&parse(custom)).unwrap();
    assert!(
        off.is_empty(),
        "inherited heuristic class is off by default"
    );
    let on = load_custom_rules_with_config(&parse(&format!(
        "[settings.rules]\n\"generic-high-entropy-value\" = true\n\n{custom}"
    )))
    .unwrap();
    assert_eq!(on.len(), 1);
    assert_eq!(on[0].class, Some(RuleClass::Heuristic));
}

const HEURISTIC: &str = "generic-high-entropy-value";

fn parse(toml: &str) -> ProjectConfig {
    toml::from_str(toml).expect("config parses")
}

fn enabled_ids(config: &ProjectConfig) -> Vec<String> {
    load_rules_with_config(config)
        .expect("rules load")
        .into_iter()
        .map(|r| r.id)
        .collect()
}

#[test]
fn heuristic_rule_is_off_by_default_and_the_rest_on() {
    let config = ProjectConfig::default();
    let all = load_all_rules_with_config(&config).unwrap();
    let enabled = enabled_ids(&config);
    assert!(!enabled.iter().any(|id| id == HEURISTIC));
    assert_eq!(enabled.len(), all.len() - 1);
    assert!(enabled.iter().any(|id| id == "generic-api-key"));
    assert!(enabled.iter().any(|id| id == "generic-token-assignment"));
}

#[test]
fn class_switch_enables_heuristic_and_disables_a_class() {
    let config = parse("[settings.rule_classes]\nheuristic = true\ncontextual = false\n");
    let all = load_all_rules_with_config(&config).unwrap();
    for rule in load_rules_with_config(&config).unwrap() {
        assert_ne!(rule.resolved_class(), RuleClass::Contextual, "{}", rule.id);
    }
    let heuristic = all.iter().find(|r| r.id == HEURISTIC).unwrap();
    assert_eq!(
        rule_switch(&config.settings, heuristic),
        (true, RuleSwitchReason::Class)
    );
}

#[test]
fn rule_switch_beats_class_switch() {
    let config = parse(
        "[settings.rule_classes]\nsignature = false\n\n[settings.rules]\n\"aws-access-key-id\" = true\n",
    );
    let enabled = enabled_ids(&config);
    assert!(enabled.iter().any(|id| id == "aws-access-key-id"));
    assert!(
        !enabled
            .iter()
            .any(|id| id == "github-personal-access-token")
    );
}

#[test]
fn nearer_layer_overrides_same_key_and_keeps_other_keys() {
    let user = parse(
        "[settings.rule_classes]\nheuristic = true\n\n[settings.rules]\n\"aws-access-key-id\" = false\n",
    );
    let project = parse("[settings.rules]\n\"aws-access-key-id\" = true\n");
    let merged = merge_all(vec![user, project]);
    assert_eq!(
        merged.settings.rule_classes.get(&RuleClass::Heuristic),
        Some(&true)
    );
    assert_eq!(merged.settings.rules.get("aws-access-key-id"), Some(&true));
    let enabled = enabled_ids(&merged);
    assert!(enabled.iter().any(|id| id == HEURISTIC));
    assert!(enabled.iter().any(|id| id == "aws-access-key-id"));
}

#[test]
fn project_layer_can_turn_heuristic_back_off() {
    let user = parse("[settings.rules]\n\"generic-high-entropy-value\" = true\n");
    let project = parse("[settings.rules]\n\"generic-high-entropy-value\" = false\n");
    let merged = merge_all(vec![user, project]);
    assert!(!enabled_ids(&merged).iter().any(|id| id == HEURISTIC));
}

#[test]
fn unknown_class_is_a_parse_error() {
    let err = toml::from_str::<ProjectConfig>("[settings.rule_classes]\ntier3 = false\n")
        .expect_err("unknown class rejected");
    assert!(err.to_string().contains("tier3"), "{err}");
}

#[test]
fn unknown_rule_id_is_an_error() {
    let config = parse("[settings.rules]\n\"no-such-rule\" = false\n");
    let err = load_rules_with_config(&config).expect_err("unknown id rejected");
    assert!(err.contains("no-such-rule"), "{err}");
}

#[test]
fn custom_rule_id_is_a_known_switch_target() {
    let config = parse(
        "[settings.rules]\n\"custom-token\" = false\n\n[[rules]]\nid = \"custom-token\"\ndescription = \"c\"\nregex = \"(CUSTOM_[A-Z]{10})\"\nsecret_group = 1\nkeywords = [\"custom_\"]\n",
    );
    assert!(!enabled_ids(&config).iter().any(|id| id == "custom-token"));
}

#[test]
fn deprecated_tier3_alias_is_accepted() {
    let config = parse("[settings]\ntier3_skip_test_paths = false\n");
    assert_eq!(config.settings.heuristic_skip_test_paths, Some(false));
}

#[test]
fn both_skip_test_path_spellings_in_one_file_are_rejected() {
    let result = toml::from_str::<ProjectConfig>(
        "[settings]\ntier3_skip_test_paths = false\nheuristic_skip_test_paths = true\n",
    );
    assert!(result.is_err());
}

#[test]
fn check_file_ignores_prefixless_random_value_by_default_and_flags_it_when_enabled() {
    // a 40-byte mixed-alphabet value with no prefix or credential key
    let value: String = (0..40u32)
        .map(|i| {
            let alphabet = b"AbCdEfGhJkMnPqRsTuVwXyZ23456789aBcDeFgHj";
            alphabet[((i * 7 + 3) % 40) as usize] as char
        })
        .collect();
    let run = |env: &IsolatedEnv| {
        let dir = env.home().join("workspace");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("env-dump");
        std::fs::write(&file, format!("ALPHA={value}\n")).unwrap();
        env.command()
            .args(["check-file", file.to_str().unwrap()])
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    let off = run(&IsolatedEnv::new());
    assert_eq!(
        off.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&off.stderr)
    );
    let on = run(&IsolatedEnv::with_heuristic());
    assert_eq!(
        on.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&on.stderr)
    );
}
