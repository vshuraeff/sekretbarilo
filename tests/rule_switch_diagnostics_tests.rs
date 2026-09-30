// doctor and --trace-exemptions reporting of the rule-class switches

mod common;

use common::IsolatedEnv;
use std::path::PathBuf;
use std::process::{Command, Output};

/// a repo with one staged clean file and the given project config.
fn repo_with_config(env: &IsolatedEnv, config: &str) -> PathBuf {
    let repo = env.git_repo();
    if !config.is_empty() {
        std::fs::write(repo.join(".sekretbarilo.toml"), config).unwrap();
    }
    std::fs::write(repo.join("notes.txt"), "hello\n").unwrap();
    Command::new("git")
        .args(["add", "notes.txt"])
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .current_dir(&repo)
        .output()
        .unwrap();
    repo
}

fn run(env: &IsolatedEnv, repo: &PathBuf, args: &[&str]) -> (Output, String) {
    let out = env.command().args(args).current_dir(repo).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stderr)
}

#[test]
fn doctor_reports_default_class_states_and_counts() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, "");
    let (_, stderr) = run(&env, &repo, &["doctor"]);
    assert!(
        stderr.contains("[INFO] rule class signature: enabled (default)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("[INFO] rule class contextual: enabled (default)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("[INFO] rule class heuristic: disabled (default)"),
        "{stderr}"
    );
    assert!(stderr.contains("[INFO] rules enabled: 109/113"), "{stderr}");
    assert!(
        stderr.contains("public-key rules held back by detect_public_keys = false"),
        "{stderr}"
    );
    assert!(!stderr.contains("no effect on detection"), "{stderr}");
}

#[test]
fn doctor_reports_configured_class_rule_override_and_ineffective_settings() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(
        &env,
        "[settings]\nexemption_layer = false\n\n[settings.rule_classes]\ncontextual = false\n\n[settings.rules]\n\"generic-api-key\" = true\n",
    );
    let (_, stderr) = run(&env, &repo, &["doctor"]);
    assert!(
        stderr.contains("rule class contextual: disabled (configured)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("rule generic-api-key: enabled (rule override)"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "exemption_layer set, but no effect on detection while generic-high-entropy-value is disabled"
        ),
        "{stderr}"
    );
}

#[test]
fn doctor_counts_the_heuristic_rule_once_enabled() {
    let env = IsolatedEnv::with_heuristic();
    let repo = repo_with_config(&env, "[settings]\nexemption_layer = true\n");
    let (_, stderr) = run(&env, &repo, &["doctor"]);
    assert!(stderr.contains("rules enabled: 110/113"), "{stderr}");
    assert!(!stderr.contains("no effect on detection"), "{stderr}");
}

#[test]
fn doctor_fails_on_broken_config_with_help_hint() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, "[settings.rule_classes]\nheurisitic = true\n");
    let (out, stderr) = run(&env, &repo, &["doctor"]);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("[ERROR] failed to load config"), "{stderr}");
    assert!(stderr.contains("see: sekretbarilo help config"), "{stderr}");
}

#[test]
fn scan_config_error_carries_help_hint() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, "[settings.rules]\n\"no-such-rule\" = false\n");
    let (out, stderr) = run(&env, &repo, &["scan"]);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("see: sekretbarilo help config"), "{stderr}");
}

#[test]
fn trace_lists_disabled_and_gated_rules_once_without_changing_exit_status() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, "[settings.rules]\n\"aws-access-key-id\" = false\n");
    let (out, stderr) = run(&env, &repo, &["scan", "--trace-exemptions"]);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr
            .matches(
                "[TRACE] rule:disabled generic-high-entropy-value class=heuristic reason=default"
            )
            .count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "[TRACE] rule:disabled aws-access-key-id class=signature reason=rule override"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "[TRACE] rule:gated pem-public-key class=signature reason=detect_public_keys"
        ),
        "{stderr}"
    );
}

#[test]
fn no_trace_lines_without_the_flag() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, "");
    let (_, stderr) = run(&env, &repo, &["scan"]);
    assert!(!stderr.contains("rule:disabled"), "{stderr}");
}

const MARKER: &str = "SYNTHETIC_PATTERN_MARKER";

#[test]
fn invalid_allowlist_fails_scan_and_doctor_with_hint_and_no_pattern_echo() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(&env, &format!("[allowlist]\npaths = ['[{MARKER}']\n"));
    for args in [&["scan"][..], &["doctor"][..]] {
        let (out, stderr) = run(&env, &repo, args);
        assert_ne!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(
            stderr.contains("see: sekretbarilo help config"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains(MARKER), "{args:?}: {stderr}");
    }
    let (_, stderr) = run(&env, &repo, &["doctor"]);
    assert!(stderr.contains("[ERROR] allowlist is invalid"), "{stderr}");
}

#[test]
fn invalid_custom_rule_regex_fails_scan_and_doctor_with_hint_and_no_pattern_echo() {
    let env = IsolatedEnv::new();
    let repo = repo_with_config(
        &env,
        &format!(
            "[[rules]]\nid = \"custom-bad\"\ndescription = \"d\"\nregex = '[{MARKER}'\nsecret_group = 0\nkeywords = [\"custom\"]\n"
        ),
    );
    for args in [&["scan"][..], &["doctor"][..]] {
        let (out, stderr) = run(&env, &repo, args);
        assert_ne!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(
            stderr.contains("invalid regex in rule 'custom-bad'"),
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.contains("see: sekretbarilo help config"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains(MARKER), "{args:?}: {stderr}");
    }
}

#[test]
fn control_characters_in_custom_ids_cannot_forge_diagnostic_lines() {
    let env = IsolatedEnv::new();
    let id = "custom\\n[OK] forged";
    let repo = repo_with_config(
        &env,
        &format!(
            "[settings.rules]\n\"{id}\" = false\n\n[[rules]]\nid = \"{id}\"\ndescription = \"d\"\nregex = '(CUSTOM_[A-Z]{{10}})'\nsecret_group = 1\nkeywords = [\"custom_\"]\n"
        ),
    );
    for args in [&["doctor"][..], &["scan", "--trace-exemptions"][..]] {
        let (_, stderr) = run(&env, &repo, args);
        assert!(
            !stderr.lines().any(|l| l.starts_with("[OK] forged")),
            "{args:?}: {stderr}"
        );
    }
}
