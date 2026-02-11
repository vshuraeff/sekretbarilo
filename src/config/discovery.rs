// config file discovery - walks directory hierarchy to find .sekretbarilo.toml files

use std::path::{Path, PathBuf};

/// the config filename to look for at each directory level
const CONFIG_FILENAME: &str = ".sekretbarilo.toml";

/// the config filename used in system/xdg locations (without leading dot)
const SYSTEM_CONFIG_FILENAME: &str = "sekretbarilo.toml";

/// the directory name used in xdg config
const CONFIG_DIR_NAME: &str = "sekretbarilo";

/// discover all config files in priority order (lowest priority first):
/// 1. /etc/sekretbarilo.toml - system-wide defaults
/// 2. $XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml (or ~/.config/sekretbarilo/sekretbarilo.toml)
/// 3. directory hierarchy from home down to start_dir
pub fn discover_configs(start: &Path, home: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // canonicalize start/home so path comparisons are consistent with discover_hierarchy
    let canon_start = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    let canon_home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());

    // 1. system-wide config
    let system_config = PathBuf::from("/etc").join(SYSTEM_CONFIG_FILENAME);
    if system_config.is_file() {
        paths.push(system_config);
    }

    // 2. xdg user config
    let xdg_config = xdg_config_path(home);
    if xdg_config.is_file() {
        paths.push(xdg_config);
    }

    // 3. directory hierarchy (walks from start up to home)
    let hierarchy = discover_hierarchy(start, home);
    paths.extend(hierarchy);

    // 4. if start is outside home, the hierarchy walk returns empty.
    //    still check for a config at start itself so project-local config is never missed.
    if !canon_start.starts_with(&canon_home) {
        let local_config = canon_start.join(CONFIG_FILENAME);
        if local_config.is_file() && !paths.contains(&local_config) {
            paths.push(local_config);
        }
    }

    paths
}

/// resolve the xdg config file path.
/// uses $XDG_CONFIG_HOME if set, otherwise falls back to ~/.config.
fn xdg_config_path(home: &Path) -> PathBuf {
    xdg_config_path_with(home, std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
}

/// inner implementation that accepts an explicit xdg override for testability.
fn xdg_config_path_with(home: &Path, xdg_override: Option<PathBuf>) -> PathBuf {
    let xdg_base = xdg_override.unwrap_or_else(|| home.join(".config"));
    xdg_base.join(CONFIG_DIR_NAME).join(SYSTEM_CONFIG_FILENAME)
}

/// discover config files from the directory hierarchy.
/// walks from `start` up to `stop` (inclusive), collecting all
/// `.sekretbarilo.toml` files found along the way.
/// returns paths in priority order: lowest priority first (closest to `stop`)
/// so that later entries override earlier ones when merging.
pub fn discover_hierarchy(start: &Path, stop: &Path) -> Vec<PathBuf> {
    let start = match start.canonicalize() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let stop = match stop.canonicalize() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    // if start is above stop (doesn't start with stop prefix), return empty
    if !start.starts_with(&stop) {
        return Vec::new();
    }

    // collect directories from start up to stop
    let mut dirs = Vec::new();
    let mut current = start.as_path();
    loop {
        dirs.push(current.to_path_buf());
        if current == stop {
            break;
        }
        match current.parent() {
            Some(parent) if parent != current => {
                current = parent;
            }
            _ => break,
        }
    }

    // reverse so lowest priority (closest to stop/home) comes first
    dirs.reverse();

    // collect existing config files
    dirs.iter()
        .map(|dir| dir.join(CONFIG_FILENAME))
        .filter(|p| p.is_file())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discover_finds_configs_in_hierarchy() {
        let tmp = tempfile::tempdir().unwrap();
        // canonicalize to handle macOS /var -> /private/var symlink
        let root = tmp.path().canonicalize().unwrap();

        // create a nested directory structure
        let child = root.join("projects").join("myrepo");
        fs::create_dir_all(&child).unwrap();

        // place config at root and child
        fs::write(root.join(CONFIG_FILENAME), "[settings]\n").unwrap();
        fs::write(child.join(CONFIG_FILENAME), "[settings]\n").unwrap();

        let configs = discover_hierarchy(&child, &root);
        assert_eq!(configs.len(), 2);
        // root config should come first (lower priority)
        assert!(configs[0].starts_with(&root));
        assert!(configs[1].starts_with(&child));
    }

    #[test]
    fn discover_start_equals_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(CONFIG_FILENAME), "[settings]\n").unwrap();

        let configs = discover_hierarchy(root, root);
        assert_eq!(configs.len(), 1);
    }

    #[test]
    fn discover_start_above_stop_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let child = root.join("sub");
        fs::create_dir_all(&child).unwrap();

        // start is root, stop is child - start is "above" stop
        let configs = discover_hierarchy(root, &child);
        assert!(configs.is_empty());
    }

    #[test]
    fn discover_no_configs_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let child = root.join("a").join("b");
        fs::create_dir_all(&child).unwrap();

        let configs = discover_hierarchy(&child, root);
        assert!(configs.is_empty());
    }

    #[test]
    fn discover_nonexistent_start() {
        let configs = discover_hierarchy(Path::new("/nonexistent/path/abc"), Path::new("/tmp"));
        assert!(configs.is_empty());
    }

    #[test]
    fn discover_intermediate_config() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let mid = root.join("org");
        let child = mid.join("repo");
        fs::create_dir_all(&child).unwrap();

        // config only at the middle level
        fs::write(mid.join(CONFIG_FILENAME), "[settings]\n").unwrap();

        let configs = discover_hierarchy(&child, &root);
        assert_eq!(configs.len(), 1);
        assert!(configs[0].starts_with(&mid));
    }

    #[test]
    fn discover_symlink_handling() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let real_dir = root.join("real");
        fs::create_dir_all(&real_dir).unwrap();
        fs::write(real_dir.join(CONFIG_FILENAME), "[settings]\n").unwrap();

        // canonicalize resolves symlinks, so this just verifies no panic
        let configs = discover_hierarchy(&real_dir, root);
        assert_eq!(configs.len(), 1);
    }

    #[test]
    fn xdg_path_uses_override() {
        let home = Path::new("/home/testuser");
        let path = xdg_config_path_with(home, Some(PathBuf::from("/custom/config")));
        assert_eq!(
            path,
            PathBuf::from("/custom/config/sekretbarilo/sekretbarilo.toml")
        );
    }

    #[test]
    fn xdg_path_falls_back_to_dot_config() {
        let home = Path::new("/home/testuser");
        let path = xdg_config_path_with(home, None);
        assert_eq!(
            path,
            PathBuf::from("/home/testuser/.config/sekretbarilo/sekretbarilo.toml")
        );
    }

    #[test]
    fn xdg_config_path_with_custom_base() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();

        // create xdg config directory structure
        let xdg_dir = home.join("test-xdg").join("sekretbarilo");
        fs::create_dir_all(&xdg_dir).unwrap();
        fs::write(xdg_dir.join(SYSTEM_CONFIG_FILENAME), "[settings]\n").unwrap();

        let path = xdg_config_path_with(&home, Some(home.join("test-xdg")));
        assert!(path.is_file());
        assert!(path.to_string_lossy().contains("test-xdg"));
    }

    #[test]
    fn xdg_config_path_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();

        let path = xdg_config_path_with(&home, Some(home.join("no-such-xdg")));
        assert!(!path.is_file());
    }

    #[test]
    fn discover_configs_outside_home_finds_local_config() {
        // simulate a repo outside $HOME
        let home_tmp = tempfile::tempdir().unwrap();
        let home = home_tmp.path().canonicalize().unwrap();

        let repo_tmp = tempfile::tempdir().unwrap();
        let repo = repo_tmp.path().canonicalize().unwrap();

        // place config in repo root (which is outside home)
        fs::write(repo.join(CONFIG_FILENAME), "[settings]\n").unwrap();

        let configs = discover_configs(&repo, &home);
        // should find the local config even though repo is outside home
        assert!(
            configs.iter().any(|p| p.starts_with(&repo)),
            "expected to find config in repo outside home, got: {:?}",
            configs
        );
    }
}
