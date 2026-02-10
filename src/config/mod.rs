pub mod allowlist;

use crate::scanner::rules::{self, Rule};
use allowlist::CompiledAllowlist;
use serde::Deserialize;
use std::path::Path;

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
}

/// load the project config from .sekretbarilo.toml (if it exists)
pub fn load_project_config(repo_root: Option<&Path>) -> Result<ProjectConfig, String> {
    if let Some(root) = repo_root {
        let config_path = root.join(".sekretbarilo.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("failed to read {}: {}", config_path.display(), e))?;
            let config: ProjectConfig = toml::from_str(&content)
                .map_err(|e| format!("failed to parse {}: {}", config_path.display(), e))?;
            return Ok(config);
        }
    }
    Ok(ProjectConfig::default())
}

/// load the complete set of rules: defaults merged with optional user overrides
/// from `.sekretbarilo.toml` in the given directory (typically repo root)
pub fn load_rules(repo_root: Option<&Path>) -> Result<Vec<Rule>, String> {
    let defaults = rules::load_default_rules()?;
    let config = load_project_config(repo_root)?;

    if config.rules.is_empty() {
        return Ok(defaults);
    }

    Ok(rules::merge_rules(defaults, config.rules))
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
        if let Some(existing) = per_rule.iter_mut().find(|(id, _, _)| id == &override_rule.id) {
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
            },
            rules: vec![],
        };

        let al = build_allowlist(&config, &[]).unwrap();
        assert!(al.is_path_skipped("test/fixtures/key.txt"));
        assert!(al.contains_stopword(b"safe_token_here"));
        assert_eq!(al.entropy_threshold_override, Some(4.0));
        assert!(al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIAIOSFODNN7EXAMPLE",
            "config.py"
        ));
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
}
