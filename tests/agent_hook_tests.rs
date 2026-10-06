// integration tests for agent hooks: check-file and claude code hook installation
//
// these tests exercise the full end-to-end workflows using the compiled binary
// and the library API, including install + doctor verification flows.

mod common;

use common::{IsolatedEnv, bin};

// -- check-file E2E tests --

#[test]
fn e2e_check_file_clean_file() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("clean.py");
    std::fs::write(&file_path, "x = 42\nprint(x)\n").unwrap();

    let output = env
        .command()
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(output.status.code(), Some(0), "clean file should exit 0");
}

#[test]
fn e2e_check_file_with_secret() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("secret.py");
    std::fs::write(&file_path, "aws_key = \"AKIAIOSFODNN7REALKEYZ\"\n").unwrap();

    let output = env
        .command()
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "file with secret should exit 2 to block read"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[AGENT]"),
        "should output AGENT prefix in stderr"
    );
    assert!(
        stderr.contains("secret(s) detected"),
        "should report secrets detected"
    );
}

#[test]
fn e2e_check_file_detects_long_mixed_assignment_password() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("settings.yaml");
    let value: String = [
        'q', '2', 'r', 'Q', 't', '2', 'w', 'r', 'R', 'q', 'y', '2', 't', 'u', 'q', '5', 'i', 'r',
        'o', 'q', 'p', 'q',
    ]
    .into_iter()
    .collect();
    std::fs::write(&file_path, format!("x_password: \"{value}\"\n")).unwrap();

    let output = env
        .command()
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to execute check-file");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("generic-password-assignment"));
}

#[test]
fn e2e_check_file_stdin_json() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("secret.py");
    std::fs::write(&file_path, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n").unwrap();

    let payload = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = env
        .command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "file with github token should exit 2 via stdin-json to block read"
    );
}

#[test]
fn e2e_check_file_stdin_json_clean() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("clean.rs");
    std::fs::write(&file_path, "fn main() {\n    println!(\"hello\");\n}\n").unwrap();

    let payload = serde_json::json!({
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = env
        .command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "clean file should exit 0 via stdin-json"
    );
}

#[test]
fn e2e_check_file_no_arg_exits_2() {
    let env = IsolatedEnv::new();
    let output = env
        .command()
        .args(["check-file"])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "check-file with no arg should exit 2"
    );
}

#[test]
fn e2e_check_file_malformed_stdin_json() {
    let env = IsolatedEnv::new();
    let output = env
        .command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"not valid json{{{")
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed stdin JSON should exit 2"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[ERROR]"), "should output error message");
}

#[test]
fn e2e_check_file_binary_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("binary.dat");
    // write binary content with null bytes + a secret pattern
    let mut content = vec![0u8; 100];
    content.extend_from_slice(b"AKIAIOSFODNN7REALKEYZ");
    std::fs::write(&file_path, &content).unwrap();

    let output = env
        .command()
        .args(["check-file", file_path.to_str().unwrap()])
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "binary file should be skipped (exit 0)"
    );
}

#[test]
fn e2e_check_file_vendor_path_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let vendor_dir = dir.path().join("node_modules").join("pkg");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let file_path = vendor_dir.join("secret.js");
    std::fs::write(&file_path, "const key = \"AKIAIOSFODNN7REALKEYZ\";\n").unwrap();

    // use stdin-json with cwd context so vendor path is resolved
    let payload = serde_json::json!({
        "tool_input": {
            "file_path": file_path.to_str().unwrap()
        },
        "cwd": dir.path().to_str().unwrap()
    });

    let output = env
        .command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "vendor path should be skipped (exit 0)"
    );
}

/// run `check-file --stdin-json` on one file with the payload cwd set to its directory.
fn check_file_stdin_json(
    env: &IsolatedEnv,
    dir: &std::path::Path,
    file: &str,
) -> std::process::Output {
    use std::io::Write;

    let payload = serde_json::json!({
        "tool_input": {"file_path": dir.join(file).to_str().unwrap()},
        "cwd": dir.to_str().unwrap()
    });
    env.command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.to_string().as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run sekretbarilo")
}

#[test]
fn e2e_check_file_invalid_exclude_pattern_is_reported_without_its_text() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    std::fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    // a generated marker inside an unclosed class makes the pattern invalid
    let marker = format!(
        "mk{}x{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    env.write_user_config(&format!(
        "[audit]\nexclude_patterns = [\"^ok/\", \"[{marker}\"]\n"
    ));

    let output = check_file_stdin_json(&env, dir.path(), "main.rs");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(&marker),
        "pattern text reached stderr: {stderr}"
    );
    assert!(
        stderr.contains("exclude_patterns entry 2"),
        "the pattern index is reported: {stderr}"
    );
}

#[test]
fn e2e_check_file_vendor_and_lock_paths_skip_before_strict_config_loading() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let config_dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("sekretbarilo.toml"), "[audit\nnot toml").unwrap();
    std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
    std::fs::write(dir.path().join("node_modules/pkg/index.js"), "x\n").unwrap();
    std::fs::write(dir.path().join("package-lock.json"), "{}\n").unwrap();
    std::fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    for skipped in ["node_modules/pkg/index.js", "package-lock.json"] {
        let output = check_file_stdin_json(&env, dir.path(), skipped);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{skipped} skips with a broken config"
        );
    }
    // a path no hard-coded skip covers still fails closed on the same config
    let output = check_file_stdin_json(&env, dir.path(), "main.rs");
    assert_eq!(output.status.code(), Some(2));
}

/// disables the built-in rule that catches `generated_github_token`.
const DISABLE_GITHUB_PAT: &str = "[settings.rules]\n\"github-personal-access-token\" = false\n";

/// a rule no built-in matches, so only the layer carrying it can block its canary.
const CANARY_RULE: &str = "[[rules]]\nid = \"fixture-canary\"\ndescription = \"synthetic canary\"\nregex = 'CANARY=([A-Z0-9]+)'\nkeywords = [\"CANARY=\"]\nsecret_group = 1\n";

fn generated_github_token() -> String {
    let body: String = "q7Wm2Kx9Rt4Lp8Vz3Nc6".chars().cycle().take(36).collect();
    format!("ghp_{body}")
}

fn git_in_env(env: &IsolatedEnv, repo: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// write the user layer verbatim, without the heuristic opt-in `write_user_config` adds.
fn write_plain_user_layer(env: &IsolatedEnv, content: &str) {
    let dir = env.home().join(".config/sekretbarilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sekretbarilo.toml"), content).unwrap();
}

#[test]
fn e2e_check_file_drops_a_symlinked_workspace_layer_even_when_committed() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let outside = env.root().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let target = outside.join("permissive.toml");
    std::fs::write(&target, DISABLE_GITHUB_PAT).unwrap();
    std::os::unix::fs::symlink(&target, repo.join(".sekretbarilo.toml")).unwrap();
    git_in_env(&env, &repo, &["add", ".sekretbarilo.toml"]);
    git_in_env(
        &env,
        &repo,
        &["commit", "--no-verify", "-m", "add fixture config symlink"],
    );
    let token = generated_github_token();
    std::fs::write(repo.join("token.txt"), format!("{token}\n")).unwrap();

    let output = check_file_stdin_json(&env, &repo, "token.txt");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("ignoring untrusted in-workspace config"),
        "{stderr}"
    );
    assert!(!stderr.contains(&token), "raw token in stderr");

    // control: the same content as a trusted layer does disable the rule.
    std::fs::remove_file(repo.join(".sekretbarilo.toml")).unwrap();
    write_plain_user_layer(&env, DISABLE_GITHUB_PAT);
    let output = check_file_stdin_json(&env, &repo, "token.txt");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn e2e_check_file_keeps_the_user_layer_under_a_non_git_cwd() {
    // the isolated root holds HOME and with it the user layer, so the cwd's workspace covers
    // that layer; it is the user's config and stays trusted.
    let env = IsolatedEnv::new();
    write_plain_user_layer(&env, CANARY_RULE);
    let body: String = "Q7W2K9R4L8V3".chars().cycle().take(12).collect();
    std::fs::write(env.root().join("canary.txt"), format!("CANARY={body}\n")).unwrap();

    let output = check_file_stdin_json(&env, env.root(), "canary.txt");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("rule: fixture-canary"), "{stderr}");
    assert!(!stderr.contains("ignoring untrusted"), "{stderr}");
}

#[test]
fn e2e_check_file_cwd_through_a_symlink_into_another_repository_ignores_its_layer() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let other = env.root().join("other");
    std::fs::create_dir_all(&other).unwrap();
    git_in_env(&env, &other, &["init", "-q"]);
    git_in_env(&env, &other, &["config", "user.email", "test@test.invalid"]);
    git_in_env(&env, &other, &["config", "user.name", "Test"]);
    std::fs::write(other.join(".sekretbarilo.toml"), DISABLE_GITHUB_PAT).unwrap();
    git_in_env(&env, &other, &["add", ".sekretbarilo.toml"]);
    git_in_env(
        &env,
        &other,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    let linked = repo.join("linked");
    std::os::unix::fs::symlink(&other, &linked).unwrap();
    let token = generated_github_token();
    std::fs::write(other.join("token.txt"), format!("{token}\n")).unwrap();

    let output = check_file_stdin_json(&env, &linked, "token.txt");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("ignoring untrusted in-workspace config"),
        "{stderr}"
    );

    // control: in the other repository itself its committed layer applies.
    let output = check_file_stdin_json(&env, &other, "token.txt");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn e2e_check_file_cwd_through_a_link_into_a_nested_repository_judges_the_holder_layer() {
    // the target nests in the repository holding the link, so the holder's layer lies outside
    // the target; the agent works in the holder, which has not committed it. both sit under
    // HOME, where discovery from the link walks up to the holder.
    let env = IsolatedEnv::new();
    let holder = env.home().join("work");
    let nested = holder.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    for repo in [&holder, &nested] {
        git_in_env(&env, repo, &["init", "-q"]);
        git_in_env(&env, repo, &["config", "user.email", "test@test.invalid"]);
        git_in_env(&env, repo, &["config", "user.name", "Test"]);
    }
    std::fs::write(holder.join(".sekretbarilo.toml"), DISABLE_GITHUB_PAT).unwrap();
    let linked = holder.join("linked");
    std::os::unix::fs::symlink(&nested, &linked).unwrap();
    let token = generated_github_token();
    std::fs::write(nested.join("token.txt"), format!("{token}\n")).unwrap();

    let output = check_file_stdin_json(&env, &linked, "token.txt");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("ignoring untrusted in-workspace config"),
        "{stderr}"
    );
    assert!(!stderr.contains(&token), "raw token in stderr");

    // control: committed unmodified in the holder, the layer applies.
    git_in_env(&env, &holder, &["add", ".sekretbarilo.toml"]);
    git_in_env(
        &env,
        &holder,
        &["commit", "--no-verify", "-m", "add fixture config"],
    );
    let output = check_file_stdin_json(&env, &linked, "token.txt");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn e2e_check_file_exit_code_is_stable_when_stderr_reader_closes_early() {
    use std::io::{Read, Write};

    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();
    let file_path = dir.path().join("many-secrets.rs");
    let secret = "AKIAIOSFODNN7ABCDEFG";
    let mut content = String::new();
    for i in 0..5000 {
        content.push_str(&format!("const K{i}: &str = \"{secret}{i}\";\n"));
    }
    std::fs::write(&file_path, content).unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "tool_input": {"file_path": file_path},
        "cwd": dir.path(),
    }))
    .unwrap();

    let mut child = env
        .command()
        .args(["check-file", "--stdin-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-file");
    child.stdin.take().unwrap().write_all(&input).unwrap();

    let mut stdout = child.stdout.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let mut stderr = child.stderr.take().unwrap();
    let mut prefix = [0u8; 64];
    let _ = stderr.read(&mut prefix);
    drop(stderr);

    // Findings have been capped at MAX_RENDERED_FINDINGS (20) since 876172a, so this no longer
    // forces a blocking write through a full pipe buffer. It instead pins the exit-2 contract
    // upstream Codex depends on, under whichever profile cargo test uses.
    let status = child.wait().expect("failed to wait on sekretbarilo");
    assert_eq!(
        status.code(),
        Some(2),
        "an early-closing stderr reader must not change the exit code"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        assert!(
            status.signal().is_none(),
            "check-file was killed by signal {:?}",
            status.signal()
        );
    }
    assert!(stdout_reader.join().unwrap().is_empty());
}

// -- install agent-hook claude E2E tests --

#[test]
fn e2e_install_agent_hook_claude_local() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();

    let output = env
        .command()
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install agent-hook claude should exit 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[OK]"), "should output OK status");

    // verify the config was created
    let config_path = dir.path().join(".claude").join("settings.json");
    assert!(config_path.exists(), ".claude/settings.json should exist");

    let content = std::fs::read_to_string(&config_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed["hooks"]["PreToolUse"].is_array());
}

#[test]
fn e2e_install_agent_hook_claude_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let env = IsolatedEnv::new();

    // first install
    env.command()
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    // second install
    let output = env
        .command()
        .args(["install", "agent-hook", "claude"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already installed"),
        "second install should report already installed"
    );
}

// -- install agent-hook codex E2E tests --

fn codex_hook_command() -> String {
    format!("{} check-codex --stdin-json", bin())
}

fn codex_hooks_path(repo: &std::path::Path) -> std::path::PathBuf {
    repo.join(".codex/hooks.json")
}

fn write_codex_hooks(repo: &std::path::Path, value: &serde_json::Value) {
    let path = codex_hooks_path(repo);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn read_codex_hooks(repo: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(codex_hooks_path(repo)).unwrap()).unwrap()
}

#[test]
fn e2e_install_agent_hook_codex_pins_running_binary_path() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let output = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    let hooks = read_codex_hooks(&repo);
    let command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(std::path::Path::new(&bin()).is_absolute());
    assert_eq!(command, codex_hook_command());
    assert_ne!(command, "sekretbarilo check-codex --stdin-json");
}

#[test]
fn e2e_install_agent_hook_codex_updates_bare_command_in_place() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    write_codex_hooks(
        &repo,
        &serde_json::json!({"hooks": {"PreToolUse": [{
            "matcher": "^(apply_patch|Bash)$",
            "hooks": [{"type": "command", "command": "sekretbarilo check-codex --stdin-json"}]
        }]}}),
    );

    let output = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("updated codex cli hook configuration"),
        "{stderr}"
    );

    let hooks = read_codex_hooks(&repo);
    let groups = hooks["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    let handlers = groups[0]["hooks"].as_array().unwrap();
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["command"], codex_hook_command());
}

#[test]
fn e2e_install_agent_hook_codex_updates_stale_absolute_path_in_place() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let stale = repo.join("stale/sekretbarilo");
    write_codex_hooks(
        &repo,
        &serde_json::json!({"hooks": {"PreToolUse": [{
            "matcher": "^(apply_patch|Bash)$",
            "hooks": [{"type": "command", "command": format!("{} check-codex --stdin-json", stale.display())}]
        }]}}),
    );

    let output = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("updated codex cli hook configuration"),
        "{stderr}"
    );

    let hooks = read_codex_hooks(&repo);
    let groups = hooks["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["hooks"].as_array().unwrap().len(), 1);
    assert_eq!(groups[0]["hooks"][0]["command"], codex_hook_command());
}

#[test]
fn e2e_install_agent_hook_codex_is_idempotent_without_rewriting() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let first = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0));
    let hooks_path = codex_hooks_path(&repo);
    let before = std::fs::read(&hooks_path).unwrap();

    let second = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("already installed"), "{stderr}");
    assert_eq!(std::fs::read(&hooks_path).unwrap(), before);
}

#[test]
fn e2e_install_agent_hook_codex_preserves_other_sekretbarilo_subcommands() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    write_codex_hooks(
        &repo,
        &serde_json::json!({"hooks": {"PreToolUse": [{
            "matcher": "^(apply_patch|Bash)$",
            "hooks": [{"type": "command", "command": "sekretbarilo check-file --stdin-json"}]
        }]}}),
    );

    let output = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    let hooks = read_codex_hooks(&repo);
    let handlers = hooks["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
    assert_eq!(handlers.len(), 2);
    assert_eq!(
        handlers[0]["command"],
        "sekretbarilo check-file --stdin-json"
    );
    assert_eq!(handlers[1]["command"], codex_hook_command());
}

#[test]
fn e2e_install_agent_hook_codex_preserves_stop_hook_across_reinstall() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();
    let stop = serde_json::json!([{
        "matcher": "*",
        "hooks": [{"type": "command", "command": "codex-claude-notify", "timeout": 3}]
    }]);
    write_codex_hooks(
        &repo,
        &serde_json::json!({"hooks": {
            "Stop": stop,
            "PreToolUse": [{
                "matcher": "^(apply_patch|Bash)$",
                "hooks": [{"type": "command", "command": "sekretbarilo check-codex --stdin-json"}]
            }]
        }}),
    );

    let first = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0));
    let after_first = std::fs::read(codex_hooks_path(&repo)).unwrap();
    assert_eq!(read_codex_hooks(&repo)["hooks"]["Stop"], stop);

    let second = env
        .command()
        .args(["install", "agent-hook", "codex"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(std::fs::read(codex_hooks_path(&repo)).unwrap(), after_first);
    assert_eq!(read_codex_hooks(&repo)["hooks"]["Stop"], stop);
}

// -- install pre-commit E2E tests --

#[test]
fn e2e_install_pre_commit_local() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let output = env
        .command()
        .args(["install", "pre-commit"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install pre-commit should exit 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[OK]"), "should output OK status");

    // verify hook file exists
    let hook_file = repo.join(".git").join("hooks").join("pre-commit");
    assert!(hook_file.exists(), "pre-commit hook file should exist");

    let content = std::fs::read_to_string(&hook_file).unwrap();
    assert!(content.contains("sekretbarilo"));
}

// -- install all E2E tests --

#[test]
fn e2e_install_all_installs_both() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let output = env
        .command()
        .args(["install", "all"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(output.status.code(), Some(0), "install all should exit 0");

    // verify pre-commit hook
    let hook_file = repo.join(".git").join("hooks").join("pre-commit");
    assert!(
        hook_file.exists(),
        "pre-commit hook should exist after install all"
    );

    // verify claude hook config
    let config_path = repo.join(".claude").join("settings.json");
    assert!(
        config_path.exists(),
        ".claude/settings.json should exist after install all"
    );
}

// -- install + doctor workflow tests --

#[test]
fn e2e_install_agent_hook_then_doctor() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    // install claude hook
    env.command()
        .args(["install", "agent-hook", "claude"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    // run doctor and verify it finds the installed hook
    let output = env
        .command()
        .args(["doctor"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("claude code hook installed"),
        "doctor should detect installed local claude hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_install_pre_commit_then_doctor() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    // install pre-commit hook
    env.command()
        .args(["install", "pre-commit"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    // run doctor and verify it finds the installed hook
    let output = env
        .command()
        .args(["doctor"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[OK]") && stderr.contains("pre-commit hook installed"),
        "doctor should detect installed local pre-commit hook, got:\n{}",
        stderr
    );
}

// -- doctor breakage detection tests --

#[test]
fn e2e_doctor_detects_deleted_hook_after_install() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    // install pre-commit hook
    env.command()
        .args(["install", "pre-commit"])
        .current_dir(&repo)
        .output()
        .unwrap();

    // delete the hook file
    let hook_file = repo.join(".git").join("hooks").join("pre-commit");
    std::fs::remove_file(&hook_file).unwrap();

    // doctor should detect the missing hook
    let output = env
        .command()
        .args(["doctor"])
        .current_dir(&repo)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[NOT INSTALLED]"),
        "doctor should detect deleted hook, got:\n{}",
        stderr
    );
}

#[test]
fn e2e_doctor_detects_corrupt_claude_config() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    // install claude hook
    env.command()
        .args(["install", "agent-hook", "claude"])
        .current_dir(&repo)
        .output()
        .unwrap();

    // corrupt the JSON config
    let config_path = repo.join(".claude").join("settings.json");
    std::fs::write(&config_path, "not valid json{{{").unwrap();

    // doctor should detect the malformed config
    let output = env
        .command()
        .args(["doctor"])
        .current_dir(&repo)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[ERROR]") && stderr.contains("malformed JSON"),
        "doctor should detect corrupt JSON, got:\n{}",
        stderr
    );
}

// -- global flag tests --

#[test]
fn e2e_install_agent_hook_claude_global_flag() {
    // test that --global flag is accepted and creates file in the right location.
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let output = env
        .command()
        .args(["install", "agent-hook", "claude", "--global"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install agent-hook claude --global should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // verify the config was created under $HOME/.claude/settings.json
    let config_path = env.home().join(".claude").join("settings.json");
    assert!(
        config_path.exists(),
        "~/.claude/settings.json should exist after global install"
    );
}

#[test]
fn e2e_install_pre_commit_global_flag() {
    let env = IsolatedEnv::new();
    let repo = env.git_repo();

    let output = env
        .command()
        .args(["install", "pre-commit", "--global"])
        .current_dir(&repo)
        .output()
        .expect("failed to run sekretbarilo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "install pre-commit --global should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
