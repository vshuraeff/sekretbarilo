// config merging - combines multiple ProjectConfig instances into one effective config

use std::collections::HashSet;

use super::{AllowlistConfig, AllowlistRuleOverride, AuditConfig, ProjectConfig, SettingsConfig};
use crate::scanner::rules::Rule;

/// merge two configs: overlay values win for scalars, lists are concatenated and deduplicated.
pub fn merge_two(base: ProjectConfig, overlay: ProjectConfig) -> ProjectConfig {
    ProjectConfig {
        allowlist: merge_allowlist(base.allowlist, overlay.allowlist),
        settings: merge_settings(base.settings, overlay.settings),
        rules: merge_rules_by_id(base.rules, overlay.rules),
        audit: merge_audit(base.audit, overlay.audit),
    }
}

/// merge a list of configs in order (first = lowest priority, last = highest).
pub fn merge_all(configs: Vec<ProjectConfig>) -> ProjectConfig {
    configs
        .into_iter()
        .fold(ProjectConfig::default(), merge_two)
}

/// merge allowlist configs: concatenate and deduplicate lists, merge rule overrides by id.
fn merge_allowlist(base: AllowlistConfig, overlay: AllowlistConfig) -> AllowlistConfig {
    AllowlistConfig {
        paths: dedup_strings(base.paths, overlay.paths),
        stopwords: dedup_strings(base.stopwords, overlay.stopwords),
        rules: merge_allowlist_rules(base.rules, overlay.rules),
    }
}

/// merge settings: overlay wins for present values.
fn merge_settings(base: SettingsConfig, overlay: SettingsConfig) -> SettingsConfig {
    SettingsConfig {
        entropy_threshold: overlay.entropy_threshold.or(base.entropy_threshold),
    }
}

/// merge rules by id: overlay rule with same id replaces base; new ids are appended.
fn merge_rules_by_id(base: Vec<Rule>, overlay: Vec<Rule>) -> Vec<Rule> {
    let mut merged = base;
    for rule in overlay {
        if let Some(pos) = merged.iter().position(|r| r.id == rule.id) {
            merged[pos] = rule;
        } else {
            merged.push(rule);
        }
    }
    merged
}

/// merge allowlist rule overrides by id: overlay overrides with same id replace base;
/// new ids are appended.
fn merge_allowlist_rules(
    base: Vec<AllowlistRuleOverride>,
    overlay: Vec<AllowlistRuleOverride>,
) -> Vec<AllowlistRuleOverride> {
    let mut merged = base;
    for rule in overlay {
        if let Some(pos) = merged.iter().position(|r| r.id == rule.id) {
            // merge regexes and paths for same id
            merged[pos].regexes = dedup_strings(
                std::mem::take(&mut merged[pos].regexes),
                rule.regexes,
            );
            merged[pos].paths = dedup_strings(
                std::mem::take(&mut merged[pos].paths),
                rule.paths,
            );
        } else {
            merged.push(rule);
        }
    }
    merged
}

/// merge audit configs: overlay wins for scalars, lists are concatenated and deduplicated.
fn merge_audit(base: AuditConfig, overlay: AuditConfig) -> AuditConfig {
    AuditConfig {
        include_ignored: overlay.include_ignored.or(base.include_ignored),
        exclude_patterns: dedup_strings(base.exclude_patterns, overlay.exclude_patterns),
        include_patterns: dedup_strings(base.include_patterns, overlay.include_patterns),
    }
}

/// concatenate two string vectors and deduplicate (preserving order, keeping first occurrence).
fn dedup_strings(mut a: Vec<String>, b: Vec<String>) -> Vec<String> {
    let mut seen: HashSet<String> = a.iter().cloned().collect();
    for s in b {
        if seen.insert(s.clone()) {
            a.push(s);
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::rules::RuleAllowlist;

    fn make_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            description: format!("{} rule", id),
            regex_pattern: format!("({})", id),
            secret_group: 1,
            keywords: vec![id.to_string()],
            entropy_threshold: None,
            allowlist: RuleAllowlist::default(),
        }
    }

    #[test]
    fn scalar_override_entropy_threshold() {
        let base = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(3.0),
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(4.5),
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.settings.entropy_threshold, Some(4.5));
    }

    #[test]
    fn scalar_base_preserved_when_overlay_is_none() {
        let base = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(3.0),
            },
            ..Default::default()
        };
        let overlay = ProjectConfig::default();
        let merged = merge_two(base, overlay);
        assert_eq!(merged.settings.entropy_threshold, Some(3.0));
    }

    #[test]
    fn list_merge_paths() {
        let base = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec!["vendor/.*".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec!["test/.*".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.allowlist.paths, vec!["vendor/.*", "test/.*"]);
    }

    #[test]
    fn list_merge_stopwords() {
        let base = ProjectConfig {
            allowlist: AllowlistConfig {
                stopwords: vec!["safe".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            allowlist: AllowlistConfig {
                stopwords: vec!["internal".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.allowlist.stopwords, vec!["safe", "internal"]);
    }

    #[test]
    fn rule_merge_by_id_override() {
        let base = ProjectConfig {
            rules: vec![make_rule("aws-key"), make_rule("github-token")],
            ..Default::default()
        };
        let overlay_rule = Rule {
            id: "aws-key".to_string(),
            description: "custom aws".to_string(),
            regex_pattern: "(CUSTOM_AWS.*)".to_string(),
            secret_group: 1,
            keywords: vec!["custom_aws".to_string()],
            entropy_threshold: Some(4.0),
            allowlist: RuleAllowlist::default(),
        };
        let overlay = ProjectConfig {
            rules: vec![overlay_rule],
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].id, "aws-key");
        assert_eq!(merged.rules[0].description, "custom aws");
        assert_eq!(merged.rules[0].entropy_threshold, Some(4.0));
        assert_eq!(merged.rules[1].id, "github-token");
    }

    #[test]
    fn rule_merge_by_id_append_new() {
        let base = ProjectConfig {
            rules: vec![make_rule("aws-key")],
            ..Default::default()
        };
        let overlay = ProjectConfig {
            rules: vec![make_rule("custom-rule")],
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].id, "aws-key");
        assert_eq!(merged.rules[1].id, "custom-rule");
    }

    #[test]
    fn empty_config_returns_defaults() {
        let merged = merge_all(vec![]);
        assert!(merged.allowlist.paths.is_empty());
        assert!(merged.allowlist.stopwords.is_empty());
        assert!(merged.rules.is_empty());
        assert!(merged.settings.entropy_threshold.is_none());
    }

    #[test]
    fn three_level_hierarchy() {
        let grandparent = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(2.0),
            },
            allowlist: AllowlistConfig {
                paths: vec!["vendor/.*".to_string()],
                stopwords: vec!["safe".to_string()],
                ..Default::default()
            },
            rules: vec![make_rule("rule-a")],
            ..Default::default()
        };
        let parent = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(3.0),
            },
            allowlist: AllowlistConfig {
                paths: vec!["generated/.*".to_string()],
                stopwords: vec!["internal".to_string()],
                ..Default::default()
            },
            rules: vec![make_rule("rule-b")],
            ..Default::default()
        };
        let child = ProjectConfig {
            settings: SettingsConfig {
                entropy_threshold: Some(4.5),
            },
            allowlist: AllowlistConfig {
                paths: vec!["tmp/.*".to_string()],
                stopwords: vec!["dev".to_string()],
                ..Default::default()
            },
            rules: vec![make_rule("rule-c")],
            ..Default::default()
        };

        let merged = merge_all(vec![grandparent, parent, child]);

        // scalar: child (most local) wins
        assert_eq!(merged.settings.entropy_threshold, Some(4.5));

        // lists: all concatenated
        assert_eq!(
            merged.allowlist.paths,
            vec!["vendor/.*", "generated/.*", "tmp/.*"]
        );
        assert_eq!(
            merged.allowlist.stopwords,
            vec!["safe", "internal", "dev"]
        );

        // rules: all appended (different ids)
        assert_eq!(merged.rules.len(), 3);
    }

    #[test]
    fn deduplication_of_list_entries() {
        let base = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec!["vendor/.*".to_string(), "test/.*".to_string()],
                stopwords: vec!["safe".to_string(), "example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            allowlist: AllowlistConfig {
                paths: vec!["vendor/.*".to_string(), "new/.*".to_string()],
                stopwords: vec!["safe".to_string(), "dev".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);

        // "vendor/.*" and "safe" should appear only once
        assert_eq!(
            merged.allowlist.paths,
            vec!["vendor/.*", "test/.*", "new/.*"]
        );
        assert_eq!(
            merged.allowlist.stopwords,
            vec!["safe", "example", "dev"]
        );
    }

    #[test]
    fn allowlist_rule_overrides_merge_by_id() {
        let base = ProjectConfig {
            allowlist: AllowlistConfig {
                rules: vec![AllowlistRuleOverride {
                    id: "aws-key".to_string(),
                    regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                    paths: vec!["test/.*".to_string()],
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            allowlist: AllowlistConfig {
                rules: vec![
                    AllowlistRuleOverride {
                        id: "aws-key".to_string(),
                        regexes: vec!["AKIANEWPATTERN12345".to_string()],
                        paths: vec![],
                    },
                    AllowlistRuleOverride {
                        id: "github-token".to_string(),
                        regexes: vec!["ghp_example".to_string()],
                        paths: vec![],
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);

        assert_eq!(merged.allowlist.rules.len(), 2);
        // aws-key should have both regexes merged
        let aws = merged.allowlist.rules.iter().find(|r| r.id == "aws-key").unwrap();
        assert_eq!(aws.regexes.len(), 2);
        assert_eq!(aws.paths.len(), 1);
        // github-token is new
        let gh = merged.allowlist.rules.iter().find(|r| r.id == "github-token").unwrap();
        assert_eq!(gh.regexes.len(), 1);
    }

    #[test]
    fn audit_config_merge_include_ignored_overlay_wins() {
        let base = ProjectConfig {
            audit: AuditConfig {
                include_ignored: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            audit: AuditConfig {
                include_ignored: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(merged.audit.include_ignored, Some(true));
    }

    #[test]
    fn audit_config_merge_include_ignored_base_preserved() {
        let base = ProjectConfig {
            audit: AuditConfig {
                include_ignored: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig::default();
        let merged = merge_two(base, overlay);
        assert_eq!(merged.audit.include_ignored, Some(true));
    }

    #[test]
    fn audit_config_merge_lists_concatenated() {
        let base = ProjectConfig {
            audit: AuditConfig {
                exclude_patterns: vec!["^vendor/".to_string()],
                include_patterns: vec![r"\.rs$".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            audit: AuditConfig {
                exclude_patterns: vec!["^build/".to_string()],
                include_patterns: vec![r"\.toml$".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(
            merged.audit.exclude_patterns,
            vec!["^vendor/", "^build/"]
        );
        assert_eq!(
            merged.audit.include_patterns,
            vec![r"\.rs$", r"\.toml$"]
        );
    }

    #[test]
    fn audit_config_merge_lists_deduplicated() {
        let base = ProjectConfig {
            audit: AuditConfig {
                exclude_patterns: vec!["^vendor/".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = ProjectConfig {
            audit: AuditConfig {
                exclude_patterns: vec!["^vendor/".to_string(), "^build/".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = merge_two(base, overlay);
        assert_eq!(
            merged.audit.exclude_patterns,
            vec!["^vendor/", "^build/"]
        );
    }
}
