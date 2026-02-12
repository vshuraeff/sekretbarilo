pub mod parser;

use std::process::Command;

pub use parser::DiffFile;

/// errors from git operations
#[derive(Debug)]
pub enum GitError {
    NotARepository,
    GitNotFound,
    CommandFailed(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::NotARepository => write!(f, "not a git repository"),
            GitError::GitNotFound => write!(f, "git not found in PATH"),
            GitError::CommandFailed(msg) => write!(f, "git command failed: {}", msg),
        }
    }
}

/// run `git diff --cached --unified=0 --diff-filter=d` and return raw output
pub fn get_staged_diff() -> Result<Vec<u8>, GitError> {
    // first check if we're in a git repo
    let rev_parse = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();

    match rev_parse {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GitError::GitNotFound);
        }
        Err(e) => {
            return Err(GitError::CommandFailed(e.to_string()));
        }
        Ok(output) if !output.status.success() => {
            return Err(GitError::NotARepository);
        }
        Ok(_) => {}
    }

    let output = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--unified=0",
            "--diff-filter=d",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
        ])
        .output()
        .map_err(|e| GitError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GitError::CommandFailed(stderr));
    }

    Ok(output.stdout)
}

/// result of checking staged files for .env files
#[derive(Debug)]
pub struct EnvFileCheck {
    pub blocked_files: Vec<String>,
}

/// check if any staged diff files are .env files that should be blocked.
/// returns a list of blocked file paths.
///
/// blocked patterns: .env, .env.local, .env.production, .env.*
/// allowed: .env.example, .env.sample, .env.template
pub fn check_env_files(files: &[DiffFile]) -> EnvFileCheck {
    let mut blocked = Vec::new();

    for file in files {
        if file.is_deleted {
            continue;
        }
        if is_blocked_env_file(&file.path) {
            blocked.push(file.path.clone());
        }
    }

    EnvFileCheck {
        blocked_files: blocked,
    }
}

/// determine if a file path is a blocked .env file (case-insensitive)
pub fn is_blocked_env_file(path: &str) -> bool {
    // split on both / and \ to handle windows-style paths
    let filename = match path.rsplit(['/', '\\']).next() {
        Some(f) => f,
        None => path,
    };

    let lower = filename.to_ascii_lowercase();

    // must start with ".env"
    if !lower.starts_with(".env") {
        return false;
    }

    // exact match: ".env"
    if lower == ".env" {
        return true;
    }

    // ".env.something" pattern
    if let Some(suffix) = lower.strip_prefix(".env.") {
        // allowed suffixes
        let allowed = ["example", "sample", "template"];
        if allowed.contains(&suffix) {
            return false;
        }
        // all other .env.* are blocked
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_exact_match() {
        assert!(is_blocked_env_file(".env"));
        assert!(is_blocked_env_file("path/to/.env"));
    }

    #[test]
    fn env_file_with_suffix() {
        assert!(is_blocked_env_file(".env.local"));
        assert!(is_blocked_env_file(".env.production"));
        assert!(is_blocked_env_file(".env.staging"));
        assert!(is_blocked_env_file(".env.development"));
        assert!(is_blocked_env_file("config/.env.local"));
    }

    #[test]
    fn env_file_allowed_suffixes() {
        assert!(!is_blocked_env_file(".env.example"));
        assert!(!is_blocked_env_file(".env.sample"));
        assert!(!is_blocked_env_file(".env.template"));
        assert!(!is_blocked_env_file("path/.env.example"));
    }

    #[test]
    fn env_file_case_insensitive() {
        assert!(is_blocked_env_file(".ENV"));
        assert!(is_blocked_env_file(".Env"));
        assert!(is_blocked_env_file(".Env.local"));
        assert!(is_blocked_env_file(".ENV.PRODUCTION"));
        assert!(is_blocked_env_file("path/to/.ENV"));
        // case-insensitive allowed suffixes
        assert!(!is_blocked_env_file(".ENV.EXAMPLE"));
        assert!(!is_blocked_env_file(".Env.Sample"));
    }

    #[test]
    fn non_env_files() {
        assert!(!is_blocked_env_file("src/main.rs"));
        assert!(!is_blocked_env_file("config.toml"));
        assert!(!is_blocked_env_file(".envrc")); // direnv file, not .env
        assert!(!is_blocked_env_file("environment.yml"));
    }

    #[test]
    fn env_file_backslash_separator() {
        assert!(is_blocked_env_file("config\\.env"));
        assert!(is_blocked_env_file("path\\to\\.env.local"));
        assert!(!is_blocked_env_file("path\\to\\.env.example"));
    }

    #[test]
    fn check_env_files_in_diff() {
        let files = vec![
            DiffFile {
                path: "src/main.rs".to_string(),
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                added_lines: vec![],
            },
            DiffFile {
                path: ".env".to_string(),
                is_new: true,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                added_lines: vec![],
            },
            DiffFile {
                path: ".env.example".to_string(),
                is_new: true,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                added_lines: vec![],
            },
        ];

        let check = check_env_files(&files);
        assert_eq!(check.blocked_files.len(), 1);
        assert_eq!(check.blocked_files[0], ".env");
    }

    #[test]
    fn check_env_deleted_files_not_blocked() {
        let files = vec![DiffFile {
            path: ".env".to_string(),
            is_new: false,
            is_deleted: true,
            is_renamed: false,
            is_binary: false,
            added_lines: vec![],
        }];

        let check = check_env_files(&files);
        assert!(check.blocked_files.is_empty());
    }
}
