use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// marker comment used to identify our hook content
pub const HOOK_MARKER: &str = "# sekretbarilo pre-commit hook";

/// the hook script content that invokes sekretbarilo scan
fn hook_script() -> String {
    format!(
        r#"
{marker}
# resolve the sekretbarilo binary
SEKRETBARILO_BIN=""
if command -v sekretbarilo >/dev/null 2>&1; then
    SEKRETBARILO_BIN="sekretbarilo"
elif [ -x "$HOME/.cargo/bin/sekretbarilo" ]; then
    SEKRETBARILO_BIN="$HOME/.cargo/bin/sekretbarilo"
fi

if [ -n "$SEKRETBARILO_BIN" ]; then
    "$SEKRETBARILO_BIN" scan
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
        exit 1
    elif [ $exit_code -ne 0 ]; then
        echo "[ERROR] sekretbarilo exited with code $exit_code" >&2
        exit $exit_code
    fi
else
    echo "[WARN] sekretbarilo not found in PATH or ~/.cargo/bin/, skipping secret scan" >&2
    echo "[WARN] install with: cargo install sekretbarilo" >&2
fi
# end sekretbarilo"#,
        marker = HOOK_MARKER,
    )
}

#[derive(Debug)]
pub enum InstallError {
    NotARepository,
    GitNotFound,
    IoError(io::Error),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::NotARepository => write!(f, "not a git repository"),
            InstallError::GitNotFound => write!(f, "git not found in PATH"),
            InstallError::IoError(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<io::Error> for InstallError {
    fn from(e: io::Error) -> Self {
        InstallError::IoError(e)
    }
}

/// result of the install operation
#[derive(Debug, PartialEq)]
pub enum InstallResult {
    /// created a new pre-commit hook
    Created,
    /// appended to an existing pre-commit hook
    Appended,
    /// hook already contains sekretbarilo
    AlreadyInstalled,
}

impl std::fmt::Display for InstallResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallResult::Created => write!(f, "created new pre-commit hook"),
            InstallResult::Appended => write!(f, "appended to existing pre-commit hook"),
            InstallResult::AlreadyInstalled => write!(f, "sekretbarilo already installed in pre-commit hook"),
        }
    }
}

/// find the git hooks directory using `git rev-parse --git-path hooks`.
/// this respects core.hooksPath and worktree layouts.
fn find_hooks_dir() -> Result<PathBuf, InstallError> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                InstallError::GitNotFound
            } else {
                InstallError::IoError(e)
            }
        })?;

    if !output.status.success() {
        return Err(InstallError::NotARepository);
    }

    let hooks_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let path = PathBuf::from(&hooks_path);

    // git rev-parse --git-path returns paths relative to CWD, not repo root.
    // resolve relative paths against the current working directory.
    if path.is_relative() {
        let cwd = std::env::current_dir().map_err(InstallError::IoError)?;
        Ok(cwd.join(path))
    } else {
        Ok(path)
    }
}

/// find the global hooks directory.
/// uses `git config --global core.hooksPath` if set, otherwise defaults to `~/.config/git/hooks/`.
fn find_global_hooks_dir() -> Result<PathBuf, InstallError> {
    // check if core.hooksPath is configured globally
    let output = Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                InstallError::GitNotFound
            } else {
                InstallError::IoError(e)
            }
        })?;

    if output.status.success() {
        let hooks_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !hooks_path.is_empty() {
            let path = PathBuf::from(&hooks_path);
            // expand ~ if present
            if let Ok(stripped) = path.strip_prefix("~") {
                let home = home_dir().ok_or_else(|| {
                    InstallError::IoError(io::Error::new(
                        io::ErrorKind::NotFound,
                        "core.hooksPath contains ~ but home directory could not be determined",
                    ))
                })?;
                return Ok(home.join(stripped));
            }
            return Ok(path);
        }
    }

    // default to ~/.config/git/hooks/
    let home = home_dir().ok_or_else(|| {
        InstallError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })?;
    Ok(home.join(".config").join("git").join("hooks"))
}

/// get the user's home directory
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// install the pre-commit hook globally.
/// uses `git config --global core.hooksPath` or defaults to `~/.config/git/hooks/`.
/// sets core.hooksPath if not already configured.
pub fn install_global() -> Result<InstallResult, InstallError> {
    let hooks_dir = find_global_hooks_dir()?;

    // ensure core.hooksPath is set so git uses this directory
    let check = Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                InstallError::GitNotFound
            } else {
                InstallError::IoError(e)
            }
        })?;

    if !check.status.success()
        || String::from_utf8_lossy(&check.stdout).trim().is_empty()
    {
        // set core.hooksPath to our directory
        let dir_str = hooks_dir.to_str().ok_or_else(|| {
            InstallError::IoError(io::Error::new(
                io::ErrorKind::InvalidData,
                "hooks directory path contains non-UTF-8 characters",
            ))
        })?;
        let set_result = Command::new("git")
            .args(["config", "--global", "core.hooksPath", dir_str])
            .output()
            .map_err(InstallError::IoError)?;

        if !set_result.status.success() {
            return Err(InstallError::IoError(io::Error::other(
                "failed to set git config --global core.hooksPath",
            )));
        }
    }

    install(Some(&hooks_dir))
}

/// install the pre-commit hook into the given hooks directory.
/// if hooks_dir is None, auto-detects using git rev-parse.
pub fn install(hooks_dir: Option<&Path>) -> Result<InstallResult, InstallError> {
    let hooks_path = match hooks_dir {
        Some(dir) => dir.to_path_buf(),
        None => find_hooks_dir()?,
    };

    // create hooks directory if it doesn't exist
    fs::create_dir_all(&hooks_path)?;

    let hook_file = hooks_path.join("pre-commit");

    if hook_file.exists() {
        let existing = fs::read_to_string(&hook_file)?;

        // check if already installed
        if existing.contains(HOOK_MARKER) {
            return Ok(InstallResult::AlreadyInstalled);
        }

        // append to existing hook, inserting before trailing exit if present
        let script = hook_script();
        let content = insert_before_trailing_exit(&existing, &script);
        fs::write(&hook_file, content)?;
        make_executable(&hook_file)?;
        Ok(InstallResult::Appended)
    } else {
        // create new hook
        let content = format!("#!/bin/sh\n{}\n", hook_script());
        fs::write(&hook_file, content)?;
        make_executable(&hook_file)?;
        Ok(InstallResult::Created)
    }
}

/// insert the hook script before any trailing `exit` line in existing content.
/// if no trailing exit is found, appends at the end.
fn insert_before_trailing_exit(existing: &str, script: &str) -> String {
    let trimmed = existing.trim_end();
    // check if the last non-empty line starts with "exit"
    if let Some(last_line) = trimmed.lines().last() {
        let stripped = last_line.trim();
        if stripped.starts_with("exit ") || stripped == "exit" {
            // compute the byte offset of the last line directly
            let last_line_start = trimmed.len() - last_line.len();
            let before = &existing[..last_line_start];
            let exit_and_after = &existing[last_line_start..];
            return format!("{}{}\n{}", before, script, exit_and_after);
        }
    }
    // no trailing exit, just append
    format!("{}{}\n", existing, script)
}

/// set executable permission on a file (unix only)
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), io::Error> {
    let metadata = fs::metadata(path)?;
    let mut perms = metadata.permissions();
    let mode = perms.mode();
    // add execute bits for owner, group, other (matching read bits)
    let new_mode = mode | ((mode & 0o444) >> 2);
    perms.set_mode(new_mode);
    fs::set_permissions(path, perms)
}

/// no-op on non-unix platforms (git hooks don't need execute bits on windows)
#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn test_install_creates_new_hook() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("hooks");

        let result = install(Some(&hooks_dir)).unwrap();
        assert_eq!(result, InstallResult::Created);

        let hook = hooks_dir.join("pre-commit");
        assert!(hook.exists());

        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains(HOOK_MARKER));
        assert!(content.contains("\"$SEKRETBARILO_BIN\" scan"));

        // verify executable
        let perms = fs::metadata(&hook).unwrap().permissions();
        assert!(perms.mode() & 0o111 != 0);
    }

    #[test]
    fn test_install_appends_to_existing_hook() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let hook = hooks_dir.join("pre-commit");
        let existing = "#!/bin/sh\necho 'existing hook'\n";
        fs::write(&hook, existing).unwrap();

        let result = install(Some(&hooks_dir)).unwrap();
        assert_eq!(result, InstallResult::Appended);

        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.starts_with("#!/bin/sh\necho 'existing hook'"));
        assert!(content.contains(HOOK_MARKER));
        assert!(content.contains("\"$SEKRETBARILO_BIN\" scan"));
    }

    #[test]
    fn test_install_already_installed() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("hooks");

        // first install
        install(Some(&hooks_dir)).unwrap();

        // second install should detect already installed
        let result = install(Some(&hooks_dir)).unwrap();
        assert_eq!(result, InstallResult::AlreadyInstalled);

        // content should not be duplicated
        let content = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        let marker_count = content.matches(HOOK_MARKER).count();
        assert_eq!(marker_count, 1);
    }

    #[test]
    fn test_install_creates_hooks_directory() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("deeply").join("nested").join("hooks");

        let result = install(Some(&hooks_dir)).unwrap();
        assert_eq!(result, InstallResult::Created);
        assert!(hooks_dir.join("pre-commit").exists());
    }

    #[test]
    fn test_hook_script_content() {
        let script = hook_script();
        assert!(script.contains(HOOK_MARKER));
        assert!(script.contains("\"$SEKRETBARILO_BIN\" scan"));
        assert!(script.contains("exit_code=$?"));
        assert!(script.contains("command -v sekretbarilo"));
        // check end marker
        assert!(script.contains("# end sekretbarilo"));
    }

    #[test]
    fn test_hook_script_handles_missing_binary() {
        let script = hook_script();
        // should check PATH first
        assert!(script.contains("command -v sekretbarilo"));
        // should fall back to cargo bin
        assert!(script.contains(".cargo/bin/sekretbarilo"));
        // should warn when not found
        assert!(script.contains("[WARN] sekretbarilo not found"));
        // should suggest installation
        assert!(script.contains("cargo install sekretbarilo"));
    }

    #[test]
    fn test_hook_script_passes_exit_codes() {
        let script = hook_script();
        // captures exit code
        assert!(script.contains("exit_code=$?"));
        // exits with code 1 when secrets found
        assert!(script.contains("exit_code -eq 1"));
        // handles any non-zero exit code
        assert!(script.contains("exit_code -ne 0"));
    }

    #[test]
    fn test_hook_script_is_valid_posix_shell() {
        let script = hook_script();
        // should use POSIX-compatible constructs
        // no bashisms like [[ ]], use [ ] instead
        assert!(!script.contains("[["));
        assert!(!script.contains("]]"));
        // should use standard variable quoting
        assert!(script.contains("\"$SEKRETBARILO_BIN\""));
    }

    #[test]
    fn test_created_hook_is_valid_shell_script() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("hooks");

        install(Some(&hooks_dir)).unwrap();

        let content = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        // must start with shebang
        assert!(content.starts_with("#!/bin/sh\n"));
        // must contain the hook marker
        assert!(content.contains(HOOK_MARKER));
        // must contain the end marker
        assert!(content.contains("# end sekretbarilo"));
    }

    #[test]
    fn test_make_executable() {
        let tmp = setup_temp_dir();
        let file = tmp.path().join("test_file");
        fs::write(&file, "test").unwrap();

        // initially not executable
        let perms = fs::metadata(&file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o111, 0);

        make_executable(&file).unwrap();

        let perms = fs::metadata(&file).unwrap().permissions();
        assert!(perms.mode() & 0o100 != 0); // owner execute
    }

    #[test]
    fn test_existing_hook_preserves_content() {
        let tmp = setup_temp_dir();
        let hooks_dir = tmp.path().join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let hook = hooks_dir.join("pre-commit");
        let existing = "#!/bin/sh\n# my custom linter\npython lint.py\nexit $?\n";
        fs::write(&hook, existing).unwrap();

        install(Some(&hooks_dir)).unwrap();

        let content = fs::read_to_string(&hook).unwrap();
        // original content is preserved
        assert!(content.contains("# my custom linter"));
        assert!(content.contains("python lint.py"));
        // our hook is inserted before the exit
        assert!(content.contains("\"$SEKRETBARILO_BIN\" scan"));
        // exit should come AFTER our hook
        let hook_pos = content.find(HOOK_MARKER).unwrap();
        let exit_pos = content.rfind("exit $?").unwrap();
        assert!(
            hook_pos < exit_pos,
            "sekretbarilo hook should be inserted before trailing exit"
        );
    }

    #[test]
    fn test_insert_before_trailing_exit() {
        let existing = "#!/bin/sh\necho hello\nexit 0\n";
        let script = "\n# test hook\necho hook\n# end test";
        let result = insert_before_trailing_exit(existing, script);
        // hook should appear before exit
        let hook_pos = result.find("# test hook").unwrap();
        let exit_pos = result.rfind("exit 0").unwrap();
        assert!(hook_pos < exit_pos);
    }

    #[test]
    fn test_insert_without_trailing_exit() {
        let existing = "#!/bin/sh\necho hello\n";
        let script = "\n# test hook\necho hook\n# end test";
        let result = insert_before_trailing_exit(existing, script);
        // hook should be appended at end
        assert!(result.ends_with("# end test\n"));
    }

    #[test]
    fn test_find_global_hooks_dir_default() {
        // when HOME is set and no core.hooksPath configured,
        // should return ~/.config/git/hooks/ (or the configured path)
        let result = find_global_hooks_dir();
        // this should succeed as long as HOME is set
        assert!(result.is_ok());
        let path = result.unwrap();
        // path should either be from core.hooksPath or the default
        assert!(path.to_str().unwrap().contains("hooks") || path.to_str().unwrap().contains("git"));
    }

    #[test]
    fn test_home_dir() {
        // HOME should be set in test environment
        let home = home_dir();
        assert!(home.is_some());
    }
}
