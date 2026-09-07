mod common;

#[test]
fn help_lists_claude_install_settings_and_redact_examples() {
    for args in [["--help"].as_slice(), ["install", "--help"].as_slice()] {
        let output = std::process::Command::new(common::bin())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
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
