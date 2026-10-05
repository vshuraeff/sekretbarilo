mod common;

#[test]
fn every_subcommand_supports_both_help_flags() {
    let env = common::IsolatedEnv::new();
    for subcommand in [
        "scan",
        "audit",
        "doctor",
        "entropy",
        "check-file",
        "check-codex",
        "redact-claude",
        "help",
        "install",
        "install pre-commit",
        "install all",
        "install agent-hook",
        "install agent-hook claude",
        "install agent-hook codex",
    ] {
        let reference = env
            .command()
            .args(if subcommand.starts_with("install") {
                vec!["install", "--help"]
            } else {
                vec!["--help"]
            })
            .output()
            .unwrap();
        assert!(reference.status.success());
        assert!(!reference.stderr.is_empty());
        for flag in ["--help", "-h"] {
            let output = env
                .command()
                .current_dir(env.root())
                .args(subcommand.split_whitespace())
                .arg(flag)
                .output()
                .unwrap();
            assert!(output.status.success(), "{subcommand} {flag}: {output:?}");
            assert!(output.stdout.is_empty(), "{subcommand} {flag}");
            assert_eq!(output.stderr, reference.stderr, "{subcommand} {flag}");
            assert!(!String::from_utf8_lossy(&output.stderr).contains("unknown flag"));
        }
    }
    assert!(!env.codex_home().join("hooks.json").exists());
    assert!(!env.home().join(".claude/settings.json").exists());
}

#[test]
fn help_topic_with_help_flag_prints_the_topic() {
    let env = common::IsolatedEnv::new();
    for topic in ["config", "rules"] {
        let reference = env
            .command()
            .current_dir(env.root())
            .args(["help", topic])
            .output()
            .unwrap();
        assert!(reference.status.success(), "help {topic}: {reference:?}");
        assert!(!reference.stdout.is_empty());
        for flag in ["--help", "-h"] {
            let output = env
                .command()
                .current_dir(env.root())
                .args(["help", topic, flag])
                .output()
                .unwrap();
            assert!(output.status.success(), "help {topic} {flag}: {output:?}");
            assert_eq!(output.stdout, reference.stdout, "help {topic} {flag}");
            assert!(output.stderr.is_empty(), "help {topic} {flag}");
        }
    }
}

#[test]
fn hook_help_does_not_wait_for_stdin() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let env = common::IsolatedEnv::new();
    for hook in ["check-file", "check-codex", "redact-claude"] {
        let mut child = env
            .command()
            .args([hook, "--help"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{hook} help waited for stdin");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{hook}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn hook_help_with_stdin_json_fails_closed_in_either_order() {
    let env = common::IsolatedEnv::new();
    for hook in ["check-file", "check-codex", "redact-claude"] {
        for help in ["--help", "-h"] {
            for flags in [[help, "--stdin-json"], ["--stdin-json", help]] {
                let output = env.command().arg(hook).args(flags).output().unwrap();
                if hook == "redact-claude" {
                    assert!(output.status.success(), "{flags:?}");
                    let response: serde_json::Value =
                        serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(response["continue"], false);
                    assert!(!response["stopReason"].as_str().unwrap().is_empty());
                } else {
                    assert_eq!(output.status.code(), Some(2), "{hook} {flags:?}");
                    assert!(output.stdout.is_empty());
                    assert!(
                        String::from_utf8_lossy(&output.stderr)
                            .contains("help cannot be combined with --stdin-json")
                    );
                }
            }
        }
    }
}

#[test]
fn help_lists_claude_install_settings_and_redact_examples() {
    for args in [["--help"].as_slice(), ["install", "--help"].as_slice()] {
        let output = std::process::Command::new(common::bin())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if args == ["--help"].as_slice() {
            for expected in [
                "heuristic is disabled by default",
                "[settings.rule_classes]",
                "rule-id switches override class switches",
                "\"generic-high-entropy-value\" = true",
                "report disabled rules and exemption decisions",
            ] {
                assert!(stderr.contains(expected), "{stderr}");
            }
        }
        for expected in [
            "--mode block|redact",
            "--settings <path>",
            "install agent-hook claude --mode redact",
        ] {
            assert!(stderr.contains(expected), "{args:?}: {stderr}");
        }
        if args == ["install", "--help"].as_slice() {
            let codex_hook = stderr.find("codex hook: modifies").unwrap();
            let settings = stderr.find("--settings <path>").unwrap();
            assert!(codex_hook < settings, "{stderr}");
            assert!(stderr.contains("CLAUDE_CONFIG_DIR"), "{stderr}");
        }
    }
}
