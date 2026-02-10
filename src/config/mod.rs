pub mod allowlist;

use crate::scanner::rules::{self, Rule};
use std::path::Path;

/// load the complete set of rules: defaults merged with optional user overrides
/// from `.sekretbarilo.toml` in the given directory (typically repo root)
pub fn load_rules(repo_root: Option<&Path>) -> Result<Vec<Rule>, String> {
    let defaults = rules::load_default_rules()?;

    if let Some(root) = repo_root {
        let config_path = root.join(".sekretbarilo.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("failed to read {}: {}", config_path.display(), e))?;
            let user_rules = rules::load_rules_from_str(&content)?;
            return Ok(rules::merge_rules(defaults, user_rules));
        }
    }

    Ok(defaults)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rules_without_repo_root() {
        let rules = load_rules(None).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn load_rules_with_nonexistent_config() {
        let rules = load_rules(Some(Path::new("/tmp/nonexistent"))).unwrap();
        assert!(!rules.is_empty()); // should fall back to defaults
    }
}
