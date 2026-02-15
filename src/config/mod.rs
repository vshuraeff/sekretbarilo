pub mod allowlist;
pub mod discovery;
pub mod merge;

use crate::scanner::rules::{self, Rule};
use allowlist::CompiledAllowlist;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// top-level project configuration from .sekretbarilo.toml
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
    /// user-defined rules (merged with defaults)
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// audit mode configuration
    #[serde(default)]
    pub audit: AuditConfig,
}

/// audit section of the config file
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditConfig {
    /// include untracked ignored files in audit (default: false)
    #[serde(default)]
    pub include_ignored: Option<bool>,
    /// additional patterns to exclude from audit (regex)
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// patterns to force-include during audit (regex)
    #[serde(default)]
    pub include_patterns: Vec<String>,
}

/// allowlist section of the config file
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowlistConfig {
    /// additional file path patterns to skip (regex)
    #[serde(default)]
    pub paths: Vec<String>,
    /// additional stopwords
    #[serde(default)]
    pub stopwords: Vec<String>,
    /// per-rule allowlist overrides
    #[serde(default)]
    pub rules: Vec<AllowlistRuleOverride>,
}

/// per-rule allowlist override in config
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowlistRuleOverride {
    pub id: String,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

/// settings section of the config file
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsConfig {
    /// global entropy threshold override
    pub entropy_threshold: Option<f64>,
    /// detect public keys as findings (default: false)
    pub detect_public_keys: Option<bool>,
}

/// load a single config file. returns None if the file doesn't exist or is empty.
/// returns Err for read errors on existing files or TOML parse errors (logged to stderr).
pub fn load_single_config(path: &Path) -> Option<ProjectConfig> {
    if !path.is_file() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.trim().is_empty() {
                return None;
            }
            match toml::from_str::<ProjectConfig>(&content) {
                Ok(config) => Some(config),
                Err(e) => {
                    eprintln!(
                        "[WARN] failed to parse {}: {} (skipping)",
                        path.display(),
                        e
                    );
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("[WARN] failed to read {}: {} (skipping)", path.display(), e);
            None
        }
    }
}

/// discover all config files (system, xdg, directory hierarchy) and load them.
/// returns configs in priority order (lowest priority first).
fn discover_and_load_configs(start_dir: &Path) -> Vec<ProjectConfig> {
    let home = dirs_home(start_dir);
    let config_paths = discovery::discover_configs(start_dir, &home);

    config_paths
        .iter()
        .filter_map(|path| load_single_config(path))
        .collect()
}

/// resolve the home directory for hierarchy walking.
fn dirs_home(fallback: &Path) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.to_path_buf())
}

/// load the project config by discovering and merging all config files
/// in the hierarchy from repo_root up to home directory.
pub fn load_project_config(repo_root: Option<&Path>) -> Result<ProjectConfig, String> {
    let start = match repo_root {
        Some(root) => root.to_path_buf(),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let configs = discover_and_load_configs(&start);

    if configs.is_empty() {
        return Ok(ProjectConfig::default());
    }

    Ok(merge::merge_all(configs))
}

/// load the complete set of rules: defaults merged with optional user overrides
/// from `.sekretbarilo.toml` in the given directory (typically repo root)
#[allow(dead_code)]
pub fn load_rules(repo_root: Option<&Path>) -> Result<Vec<Rule>, String> {
    let defaults = rules::load_default_rules()?;
    let config = load_project_config(repo_root)?;

    if config.rules.is_empty() {
        return Ok(defaults);
    }

    Ok(rules::merge_rules(defaults, config.rules))
}

/// load rules using an already-loaded project config (avoids parsing config twice)
pub fn load_rules_with_config(config: &ProjectConfig) -> Result<Vec<Rule>, String> {
    let defaults = rules::load_default_rules()?;

    if config.rules.is_empty() {
        return Ok(defaults);
    }

    Ok(rules::merge_rules(defaults, config.rules.clone()))
}

/// load config from explicit paths (strict mode: errors on missing/invalid files).
/// when paths is empty, returns default config.
pub fn load_project_config_from_paths(paths: &[PathBuf]) -> Result<ProjectConfig, String> {
    if paths.is_empty() {
        return Ok(ProjectConfig::default());
    }

    let mut configs = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.is_file() {
            return Err(format!("config file not found: {}", path.display()));
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        let config: ProjectConfig = toml::from_str(&content)
            .map_err(|e| format!("failed to parse {}: {}", path.display(), e))?;
        configs.push(config);
    }

    Ok(merge::merge_all(configs))
}

/// build a compiled allowlist from project config, incorporating both global
/// and per-rule allowlist settings. also merges per-rule allowlists from the
/// rules themselves with overrides from the config file.
pub fn build_allowlist(
    config: &ProjectConfig,
    rules: &[Rule],
) -> Result<CompiledAllowlist, String> {
    // collect per-rule allowlists from rule definitions + config overrides
    let mut per_rule: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();

    // first, gather from rule definitions themselves
    for rule in rules {
        if !rule.allowlist.regexes.is_empty() || !rule.allowlist.paths.is_empty() {
            per_rule.push((
                rule.id.clone(),
                rule.allowlist.regexes.clone(),
                rule.allowlist.paths.clone(),
            ));
        }
    }

    // then, merge/add from config file overrides
    for override_rule in &config.allowlist.rules {
        if let Some(existing) = per_rule
            .iter_mut()
            .find(|(id, _, _)| id == &override_rule.id)
        {
            existing.1.extend(override_rule.regexes.clone());
            existing.2.extend(override_rule.paths.clone());
        } else {
            per_rule.push((
                override_rule.id.clone(),
                override_rule.regexes.clone(),
                override_rule.paths.clone(),
            ));
        }
    }

    CompiledAllowlist::new(
        &config.allowlist.paths,
        &config.allowlist.stopwords,
        config.settings.entropy_threshold,
        &per_rule,
        config.settings.detect_public_keys.unwrap_or(false),
    )
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

    #[test]
    fn parse_full_config() {
        let toml = r#"
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]
stopwords = ["my-project-specific-safe-token"]

[[allowlist.rules]]
id = "generic-api-key"
regexes = ["MY_KNOWN_SAFE_KEY_.*"]

[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = ["test/.*"]

[settings]
entropy_threshold = 3.5

[[rules]]
id = "custom-token"
description = "Custom token"
regex = "(CUSTOM_[A-Z]{10})"
secret_group = 1
keywords = ["custom_"]
"#;
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.allowlist.paths.len(), 2);
        assert_eq!(config.allowlist.stopwords.len(), 1);
        assert_eq!(config.allowlist.rules.len(), 2);
        assert_eq!(config.settings.entropy_threshold, Some(3.5));
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn parse_empty_config() {
        let toml = "";
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert!(config.allowlist.paths.is_empty());
        assert!(config.allowlist.stopwords.is_empty());
        assert!(config.allowlist.rules.is_empty());
        assert!(config.settings.entropy_threshold.is_none());
        assert!(config.rules.is_empty());
    }

    #[test]
    fn parse_allowlist_only_config() {
        let toml = r#"
[allowlist]
paths = ["vendor/.*"]
stopwords = ["safe_token"]
"#;
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.allowlist.paths.len(), 1);
        assert_eq!(config.allowlist.stopwords.len(), 1);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn parse_audit_config() {
        let toml = r#"
[audit]
include_ignored = true
exclude_patterns = ["^vendor/", "^build/"]
include_patterns = ["\\.rs$"]
"#;
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.audit.include_ignored, Some(true));
        assert_eq!(config.audit.exclude_patterns, vec!["^vendor/", "^build/"]);
        assert_eq!(config.audit.include_patterns, vec!["\\.rs$"]);
    }

    #[test]
    fn parse_config_without_audit_section() {
        let toml = r#"
[settings]
entropy_threshold = 3.5
"#;
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert!(config.audit.include_ignored.is_none());
        assert!(config.audit.exclude_patterns.is_empty());
        assert!(config.audit.include_patterns.is_empty());
    }

    #[test]
    fn build_allowlist_from_config() {
        let config = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec!["test/.*".to_string()],
                stopwords: vec!["safe".to_string()],
                rules: vec![AllowlistRuleOverride {
                    id: "aws-access-key-id".to_string(),
                    regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                    paths: vec![],
                }],
            },
            settings: SettingsConfig {
                entropy_threshold: Some(4.0),
                detect_public_keys: None,
            },
            rules: vec![],
            ..Default::default()
        };

        let al = build_allowlist(&config, &[]).unwrap();
        assert!(al.is_path_skipped("test/fixtures/key.txt"));
        assert!(al.contains_stopword(b"safe_token_here"));
        assert_eq!(al.entropy_threshold_override, Some(4.0));
        assert!(al.is_rule_allowlisted("aws-access-key-id", b"AKIAIOSFODNN7EXAMPLE", "config.py"));
    }

    #[test]
    fn build_allowlist_merges_rule_allowlists() {
        let rules = vec![Rule {
            id: "aws-access-key-id".to_string(),
            description: "AWS key".to_string(),
            regex_pattern: "(AKIA[A-Z0-9]{16})".to_string(),
            secret_group: 1,
            keywords: vec!["akia".to_string()],
            entropy_threshold: None,
            allowlist: rules::RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
        }];

        let config = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec![],
                stopwords: vec![],
                rules: vec![AllowlistRuleOverride {
                    id: "aws-access-key-id".to_string(),
                    regexes: vec!["AKIATHISISALSOKNOWN".to_string()],
                    paths: vec!["test/.*".to_string()],
                }],
            },
            settings: SettingsConfig::default(),
            rules: vec![],
            ..Default::default()
        };

        let al = build_allowlist(&config, &rules).unwrap();
        // both the rule-defined and config-defined allowlist patterns should work
        assert!(al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIAIOSFODNN7EXAMPLE",
            "src/config.py"
        ));
        assert!(al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIATHISISALSOKNOWN",
            "src/config.py"
        ));
        assert!(al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIAANYVALUEHERE123",
            "test/fixtures/keys.yml"
        ));
    }

    #[test]
    fn load_from_paths_empty_returns_default() {
        let config = load_project_config_from_paths(&[]).unwrap();
        assert!(config.rules.is_empty());
        assert!(config.settings.entropy_threshold.is_none());
    }

    #[test]
    fn load_from_paths_missing_file_errors() {
        let result =
            load_project_config_from_paths(&[PathBuf::from("/tmp/nonexistent_sb_test.toml")]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn load_from_paths_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(
            &path,
            r#"
[settings]
entropy_threshold = 4.0

[allowlist]
stopwords = ["safe"]
"#,
        )
        .unwrap();

        let config = load_project_config_from_paths(&[path]).unwrap();
        assert_eq!(config.settings.entropy_threshold, Some(4.0));
        assert_eq!(config.allowlist.stopwords, vec!["safe"]);
    }

    #[test]
    fn load_from_paths_merge_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");

        std::fs::write(
            &a,
            r#"
[settings]
entropy_threshold = 3.0

[allowlist]
stopwords = ["from_a"]
"#,
        )
        .unwrap();
        std::fs::write(
            &b,
            r#"
[settings]
entropy_threshold = 5.0

[allowlist]
stopwords = ["from_b"]
"#,
        )
        .unwrap();

        let config = load_project_config_from_paths(&[a, b]).unwrap();
        // b overrides scalar
        assert_eq!(config.settings.entropy_threshold, Some(5.0));
        // lists merged
        assert_eq!(config.allowlist.stopwords, vec!["from_a", "from_b"]);
    }

    #[test]
    fn load_from_paths_invalid_toml_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let result = load_project_config_from_paths(&[path]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse"));
    }
}
