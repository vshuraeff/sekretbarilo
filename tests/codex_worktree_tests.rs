// check-codex trusts an in-workspace config layer only when git proves it tracked and
// unmodified against HEAD of the checkout the layer lives in. these tests pin that the
// answer is the same from a main checkout and from a linked worktree, whose `.git` is a
// gitdir pointer file rather than a directory.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::IsolatedEnv;
use serde_json::json;
use serial_test::serial;

const CONFIG_FILENAME: &str = ".sekretbarilo.toml";
const UNTRUSTED_WARNING: &str = "ignoring untrusted in-workspace config";
const PERMISSIVE_CONFIG: &str =
    "[[allowlist.rules]]\nid = \"aws-access-key-id\"\nregexes = [\".*\"]\n";

/// a main checkout and a linked worktree laid out as the harness does it: both under
/// HOME, the worktree beside the repository in `<workspace>/.worktrees/...`.
struct Checkouts {
    env: IsolatedEnv,
    main: PathBuf,
    worktree: PathBuf,
}

impl Checkouts {
    /// the main checkout holds one commit; `commit_config` decides whether that commit
    /// already tracks the permissive layer. the worktree is created from it on its own
    /// branch.
    fn new(commit_config: bool) -> Self {
        let env = IsolatedEnv::new();
        let workspace = env.home().join("work");
        let main = workspace.join("repo");
        let worktree = workspace
            .join(".worktrees")
            .join("repo")
            .join("task")
            .join("unit");
        std::fs::create_dir_all(&main).expect("failed to create main checkout dir");

        git(&env, &main, &["init", "-q"]);
        git(&env, &main, &["config", "user.email", "test@test.com"]);
        git(&env, &main, &["config", "user.name", "Test"]);
        std::fs::write(main.join("README.md"), "fixture\n").expect("failed to write README");
        git(&env, &main, &["add", "README.md"]);
        if commit_config {
            write_config(&main);
            git(&env, &main, &["add", CONFIG_FILENAME]);
        }
        git(&env, &main, &["commit", "--no-verify", "-q", "-m", "base"]);

        let worktree_arg = worktree.to_string_lossy().into_owned();
        git(
            &env,
            &main,
            &["worktree", "add", "-q", "-b", "task-unit", &worktree_arg],
        );
        assert!(
            worktree.join(".git").is_file(),
            "a linked worktree must carry a gitdir pointer file"
        );

        Self {
            env,
            main,
            worktree,
        }
    }

    fn check(&self, cwd: &Path) -> Output {
        run_check_codex(&self.env, cwd, &[])
    }

    /// run the hook with git variables inherited from its parent, as a hook launched
    /// from inside a git hook or a wrapper would see them
    fn check_with_env(&self, cwd: &Path, inherited: &[(&str, &Path)]) -> Output {
        run_check_codex(&self.env, cwd, inherited)
    }
}

/// the names `git rev-parse --local-env-vars` prints. fixture git calls drop them so a
/// polluted parent environment cannot redirect setup into another checkout.
const GIT_LOCAL_ENV_VARS: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

fn git(env: &IsolatedEnv, dir: &Path, args: &[&str]) {
    let mut command = Command::new("git");
    for name in GIT_LOCAL_ENV_VARS {
        command.env_remove(name);
    }
    let output = command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("HOME", env.home())
        .env("GIT_CONFIG_GLOBAL", env.git_config_global())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_config(dir: &Path) {
    std::fs::write(dir.join(CONFIG_FILENAME), PERMISSIVE_CONFIG)
        .expect("failed to write fixture config");
}

fn commit_config(env: &IsolatedEnv, dir: &Path) {
    write_config(dir);
    git(env, dir, &["add", CONFIG_FILENAME]);
    git(
        env,
        dir,
        &["commit", "--no-verify", "-q", "-m", "add config"],
    );
}

fn modify_config(dir: &Path) {
    let path = dir.join(CONFIG_FILENAME);
    let mut content = std::fs::read_to_string(&path).expect("failed to read fixture config");
    content.push_str("# local edit\n");
    std::fs::write(&path, content).expect("failed to modify fixture config");
}

/// an aws access key id built at run time, so no opaque value sits in the source
fn aws_key_id() -> String {
    let body: String = (0..16)
        .map(|index| {
            let byte = if index % 4 == 0 {
                b'2' + ((index * 3 + 1) % 8) as u8
            } else {
                b'A' + ((index * 11 + 7) % 26) as u8
            };
            char::from(byte)
        })
        .collect();
    format!("AKIA{body}")
}

fn run_check_codex(env: &IsolatedEnv, cwd: &Path, inherited: &[(&str, &Path)]) -> Output {
    let patch = format!(
        "*** Begin Patch\n*** Add File: src/fixture.rs\n+const KEY: &str = \"{}\";\n*** End Patch\n",
        aws_key_id()
    );
    let payload = serde_json::to_vec(&json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
        "cwd": cwd.to_string_lossy(),
    }))
    .expect("failed to encode apply_patch payload");

    let mut child = env
        .command()
        .args(["check-codex", "--stdin-json"])
        .env("XDG_CONFIG_HOME", env.home().join(".config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .envs(inherited.iter().copied())
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sekretbarilo check-codex");
    child
        .stdin
        .take()
        .expect("stdin was not piped")
        .write_all(&payload)
        .expect("failed to write payload to child stdin");
    child.wait_with_output().expect("failed to wait on child")
}

fn assert_trusted(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{context}: the layer should be trusted and allowlist the key\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains(UNTRUSTED_WARNING),
        "{context}: a trusted layer must not be reported as untrusted\nstderr:\n{stderr}"
    );
}

fn assert_discarded(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{context}: the layer should be discarded and the key blocked\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(UNTRUSTED_WARNING),
        "{context}: the discarded layer should be reported\nstderr:\n{stderr}"
    );
}

fn assert_blocked_without_layer(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{context}: the key should be blocked\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("secret(s) detected"),
        "{context}: the block should come from the scanner\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn main_checkout_trusts_only_a_tracked_unmodified_layer() {
    let checkouts = Checkouts::new(false);
    let main = &checkouts.main;

    assert_blocked_without_layer(&checkouts.check(main), "main checkout without a layer");

    write_config(main);
    assert_discarded(&checkouts.check(main), "untracked layer in main checkout");

    git(&checkouts.env, main, &["add", CONFIG_FILENAME]);
    assert_discarded(
        &checkouts.check(main),
        "staged, uncommitted layer in main checkout",
    );

    git(
        &checkouts.env,
        main,
        &["commit", "--no-verify", "-q", "-m", "add config"],
    );
    assert_trusted(&checkouts.check(main), "committed layer in main checkout");

    modify_config(main);
    assert_discarded(&checkouts.check(main), "modified layer in main checkout");
}

#[test]
#[serial]
fn linked_worktree_trusts_a_tracked_unmodified_layer() {
    let checkouts = Checkouts::new(true);
    let subdir = checkouts.worktree.join("src");
    std::fs::create_dir_all(&subdir).expect("failed to create worktree subdir");

    assert_trusted(
        &checkouts.check(&checkouts.worktree),
        "committed layer in linked worktree",
    );
    assert_trusted(
        &checkouts.check(&subdir),
        "committed layer seen from a linked worktree subdirectory",
    );
    assert_trusted(
        &checkouts.check(&checkouts.main),
        "committed layer in main checkout",
    );
}

#[test]
#[serial]
fn linked_worktree_discards_a_layer_modified_in_the_worktree() {
    let checkouts = Checkouts::new(true);
    modify_config(&checkouts.worktree);

    assert_discarded(
        &checkouts.check(&checkouts.worktree),
        "layer modified in linked worktree",
    );
    assert_trusted(
        &checkouts.check(&checkouts.main),
        "unmodified layer in main checkout beside a modified worktree",
    );
}

#[test]
#[serial]
fn linked_worktree_discards_an_untracked_layer() {
    let checkouts = Checkouts::new(false);
    write_config(&checkouts.worktree);

    assert_discarded(
        &checkouts.check(&checkouts.worktree),
        "untracked layer in linked worktree",
    );
    assert_blocked_without_layer(
        &checkouts.check(&checkouts.main),
        "main checkout beside a worktree with an untracked layer",
    );
}

#[test]
#[serial]
fn linked_worktree_discards_a_staged_uncommitted_layer() {
    let checkouts = Checkouts::new(false);
    write_config(&checkouts.worktree);
    git(
        &checkouts.env,
        &checkouts.worktree,
        &["add", CONFIG_FILENAME],
    );

    assert_discarded(
        &checkouts.check(&checkouts.worktree),
        "staged, uncommitted layer in linked worktree",
    );
}

#[test]
#[serial]
fn linked_worktree_judges_the_layer_against_its_own_head_not_the_main_checkout() {
    // committed only on the worktree's branch: trusted there, absent from main
    let checkouts = Checkouts::new(false);
    commit_config(&checkouts.env, &checkouts.worktree);
    assert_trusted(
        &checkouts.check(&checkouts.worktree),
        "layer committed on the worktree branch only",
    );
    assert_blocked_without_layer(
        &checkouts.check(&checkouts.main),
        "main checkout whose HEAD lacks the layer",
    );

    // committed only on the main branch: an identical untracked copy in the worktree
    // must still be discarded
    let checkouts = Checkouts::new(false);
    commit_config(&checkouts.env, &checkouts.main);
    write_config(&checkouts.worktree);
    assert_trusted(
        &checkouts.check(&checkouts.main),
        "layer committed on the main branch",
    );
    assert_discarded(
        &checkouts.check(&checkouts.worktree),
        "untracked copy in a worktree whose HEAD lacks the layer",
    );
}

#[test]
#[serial]
fn linked_worktree_ignores_a_modification_in_the_main_checkout() {
    let checkouts = Checkouts::new(true);
    modify_config(&checkouts.main);

    assert_discarded(
        &checkouts.check(&checkouts.main),
        "layer modified in main checkout",
    );
    assert_trusted(
        &checkouts.check(&checkouts.worktree),
        "unmodified layer in worktree beside a modified main checkout",
    );
}

#[test]
#[serial]
fn linked_worktree_trust_survives_the_relative_index_file_git_exports_to_commit_hooks() {
    // git exports GIT_INDEX_FILE=.git/index (relative) to commit hooks run from a main
    // checkout; inherited as is, it resolves inside the worktree, where `.git` is a file
    let checkouts = Checkouts::new(true);
    let relative_index = [("GIT_INDEX_FILE", Path::new(".git/index"))];

    assert_trusted(
        &checkouts.check_with_env(&checkouts.main, &relative_index),
        "main checkout with an inherited relative GIT_INDEX_FILE",
    );
    assert_trusted(
        &checkouts.check_with_env(&checkouts.worktree, &relative_index),
        "linked worktree with an inherited relative GIT_INDEX_FILE",
    );
}

#[test]
#[serial]
fn inherited_git_redirects_cannot_vouch_for_a_modified_layer() {
    let checkouts = Checkouts::new(true);
    modify_config(&checkouts.worktree);
    let main_git_dir = checkouts.main.join(".git");

    assert_discarded(
        &checkouts.check_with_env(
            &checkouts.worktree,
            &[("GIT_WORK_TREE", checkouts.main.as_path())],
        ),
        "worktree layer modified, GIT_WORK_TREE pointing at the clean main checkout",
    );
    assert_discarded(
        &checkouts.check_with_env(
            &checkouts.worktree,
            &[
                ("GIT_DIR", main_git_dir.as_path()),
                ("GIT_WORK_TREE", checkouts.main.as_path()),
            ],
        ),
        "worktree layer modified, GIT_DIR and GIT_WORK_TREE pointing at the main checkout",
    );

    let checkouts = Checkouts::new(true);
    modify_config(&checkouts.main);
    assert_discarded(
        &checkouts.check_with_env(
            &checkouts.main,
            &[("GIT_WORK_TREE", checkouts.worktree.as_path())],
        ),
        "main layer modified, GIT_WORK_TREE pointing at the clean worktree",
    );
}
