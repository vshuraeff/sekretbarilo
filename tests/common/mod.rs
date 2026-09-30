// Each integration test imports this module as its own crate-local module, so a helper used by
// one test binary is dead code from another binary's perspective.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// get the path to the compiled binary
pub fn bin() -> String {
    env!("CARGO_BIN_EXE_sekretbarilo").to_string()
}

/// user-config fragment that turns the default-off heuristic rule back on.
pub const ENABLE_HEURISTIC: &str = "[settings.rules]\n\"generic-high-entropy-value\" = true\n";

pub struct IsolatedEnv {
    _root: tempfile::TempDir,
    home: PathBuf,
    codex_home: PathBuf,
    git_config_global: PathBuf,
}

impl IsolatedEnv {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("failed to create isolated environment");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("failed to create isolated HOME");
        let codex_home = root.path().join("codex-home");
        std::fs::create_dir_all(&codex_home).expect("failed to create isolated CODEX_HOME");
        let git_config_global = root.path().join(".fake-gitconfig");
        std::fs::write(&git_config_global, "").expect("failed to create isolated git config");

        Self {
            _root: root,
            home,
            codex_home,
            git_config_global,
        }
    }

    /// an isolated environment whose user config opts in to the heuristic rule
    /// `generic-high-entropy-value`, which is off by default.
    pub fn with_heuristic() -> Self {
        let env = Self::new();
        env.write_user_config("");
        env
    }

    /// write the user-layer config, always prefixed with the heuristic opt-in.
    pub fn write_user_config(&self, config: &str) {
        let dir = self.home.join(".config/sekretbarilo");
        std::fs::create_dir_all(&dir).expect("failed to create config directory");
        std::fs::write(
            dir.join("sekretbarilo.toml"),
            format!("{ENABLE_HEURISTIC}{config}"),
        )
        .expect("failed to write user config");
    }

    pub fn root(&self) -> &Path {
        self._root.path()
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    pub fn git_config_global(&self) -> &Path {
        &self.git_config_global
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(bin());
        command
            .env("HOME", &self.home)
            .env("CODEX_HOME", &self.codex_home)
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env_remove("CLAUDE_CONFIG_DIR");
        command
    }

    /// initialize a throwaway git repo at `<root>/repo` inside this environment, using this
    /// environment's isolated git config so the repo's identity never touches the developer's
    /// real global git config. Returns the repo path.
    pub fn git_repo(&self) -> PathBuf {
        let repo_path = self.root().join("repo");
        std::fs::create_dir_all(&repo_path).expect("failed to create isolated repo dir");

        Command::new("git")
            .args(["init"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git init failed");
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git config user.email failed");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git config user.name failed");

        repo_path
    }
}

/// create a temp git repo for pre-commit hook install tests.
/// isolates from user's global git config to prevent core.hooksPath leakage.
pub fn setup_git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // create an empty file to use as global git config, preventing leakage
    // from the user's actual global config (e.g. core.hooksPath)
    let fake_global = root.join(".fake-gitconfig");
    std::fs::write(&fake_global, "").unwrap();

    Command::new("git")
        .args(["init"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .expect("git init failed");

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();

    dir
}

/// get the path to the fake global gitconfig inside a test repo dir
pub fn fake_gitconfig(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join(".fake-gitconfig")
}
