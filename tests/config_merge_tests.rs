// integration tests for hierarchical config discovery and merging

use sekretbarilo::config::discovery::{discover_configs, discover_hierarchy};
use sekretbarilo::config::merge::{merge_all, merge_two};
use sekretbarilo::config::{
    AllowlistConfig, ProjectConfig, SettingsConfig, load_single_config,
};
use serial_test::serial;
use std::fs;
use tempfile::tempdir;

// -- 1.4.1: scalar override --

#[test]
fn scalar_override_local_entropy_threshold_overrides_parent() {
    let parent = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: Some(3.0),
        },
        ..Default::default()
    };
    let child = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: Some(4.5),
        },
        ..Default::default()
    };
    let merged = merge_two(parent, child);
    assert_eq!(merged.settings.entropy_threshold, Some(4.5));
}

// -- 1.4.2: list merge --

#[test]
fn list_merge_allowlist_paths_from_both_levels() {
    let parent = ProjectConfig {
        allowlist: AllowlistConfig {
            paths: vec!["vendor/.*".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let child = ProjectConfig {
        allowlist: AllowlistConfig {
            paths: vec!["test/fixtures/.*".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let merged = merge_two(parent, child);
    assert_eq!(merged.allowlist.paths.len(), 2);
    assert!(merged.allowlist.paths.contains(&"vendor/.*".to_string()));
    assert!(merged.allowlist.paths.contains(&"test/fixtures/.*".to_string()));
}

// -- 1.4.3: rule merge by id --

#[test]
fn rule_merge_child_overrides_parent_same_id() {
    use sekretbarilo::scanner::rules::RuleAllowlist;

    let parent_rule = sekretbarilo::scanner::rules::Rule {
        id: "aws-key".to_string(),
        description: "parent aws key".to_string(),
        regex_pattern: "(AKIA.*)".to_string(),
        secret_group: 1,
        keywords: vec!["akia".to_string()],
        entropy_threshold: None,
        allowlist: RuleAllowlist::default(),
    };
    let child_rule = sekretbarilo::scanner::rules::Rule {
        id: "aws-key".to_string(),
        description: "child aws key".to_string(),
        regex_pattern: "(AKIA[A-Z0-9]{16})".to_string(),
        secret_group: 1,
        keywords: vec!["akia".to_string()],
        entropy_threshold: Some(3.5),
        allowlist: RuleAllowlist::default(),
    };
    let new_rule = sekretbarilo::scanner::rules::Rule {
        id: "custom-token".to_string(),
        description: "custom".to_string(),
        regex_pattern: "(CUSTOM.*)".to_string(),
        secret_group: 1,
        keywords: vec!["custom".to_string()],
        entropy_threshold: None,
        allowlist: RuleAllowlist::default(),
    };

    let parent = ProjectConfig {
        rules: vec![parent_rule],
        ..Default::default()
    };
    let child = ProjectConfig {
        rules: vec![child_rule, new_rule],
        ..Default::default()
    };
    let merged = merge_two(parent, child);

    assert_eq!(merged.rules.len(), 2);
    let aws = merged.rules.iter().find(|r| r.id == "aws-key").unwrap();
    assert_eq!(aws.description, "child aws key");
    assert_eq!(aws.entropy_threshold, Some(3.5));
    assert!(merged.rules.iter().any(|r| r.id == "custom-token"));
}

// -- 1.4.4: empty/missing config --

#[test]
fn empty_config_returns_defaults() {
    let merged = merge_all(vec![]);
    assert!(merged.allowlist.paths.is_empty());
    assert!(merged.allowlist.stopwords.is_empty());
    assert!(merged.rules.is_empty());
    assert!(merged.settings.entropy_threshold.is_none());
}

#[test]
fn load_single_config_missing_file() {
    let result = load_single_config(std::path::Path::new("/nonexistent/config.toml"));
    assert!(result.is_none());
}

#[test]
fn load_single_config_empty_file() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".sekretbarilo.toml");
    fs::write(&path, "").unwrap();
    let result = load_single_config(&path);
    assert!(result.is_none());
}

#[test]
fn load_single_config_valid() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".sekretbarilo.toml");
    fs::write(
        &path,
        r#"
[settings]
entropy_threshold = 4.0

[allowlist]
paths = ["test/.*"]
"#,
    )
    .unwrap();
    let config = load_single_config(&path).unwrap();
    assert_eq!(config.settings.entropy_threshold, Some(4.0));
    assert_eq!(config.allowlist.paths.len(), 1);
}

#[test]
fn load_single_config_invalid_toml_returns_none() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".sekretbarilo.toml");
    fs::write(&path, "this is not valid toml [[[").unwrap();
    // should return None (warns to stderr, non-fatal)
    let result = load_single_config(&path);
    assert!(result.is_none());
}

// -- 1.4.5: three-level hierarchy --

#[test]
fn three_level_hierarchy_merges_correctly() {
    let grandparent = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: Some(2.0),
        },
        allowlist: AllowlistConfig {
            paths: vec!["vendor/.*".to_string()],
            stopwords: vec!["safe".to_string()],
            rules: vec![],
        },
        rules: vec![],
        ..Default::default()
    };
    let parent = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: Some(3.0),
        },
        allowlist: AllowlistConfig {
            paths: vec!["generated/.*".to_string()],
            stopwords: vec!["internal".to_string()],
            rules: vec![],
        },
        rules: vec![],
        ..Default::default()
    };
    let child = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: Some(4.5),
        },
        allowlist: AllowlistConfig {
            paths: vec!["tmp/.*".to_string()],
            stopwords: vec!["dev".to_string()],
            rules: vec![],
        },
        rules: vec![],
        ..Default::default()
    };

    let merged = merge_all(vec![grandparent, parent, child]);

    // most local (child) wins for scalars
    assert_eq!(merged.settings.entropy_threshold, Some(4.5));
    // all lists concatenated
    assert_eq!(merged.allowlist.paths.len(), 3);
    assert_eq!(merged.allowlist.stopwords.len(), 3);
}

// -- 1.4.6: deduplication --

#[test]
fn deduplication_of_list_entries() {
    let base = ProjectConfig {
        allowlist: AllowlistConfig {
            paths: vec!["vendor/.*".to_string(), "test/.*".to_string()],
            stopwords: vec!["safe".to_string()],
            rules: vec![],
        },
        ..Default::default()
    };
    let overlay = ProjectConfig {
        allowlist: AllowlistConfig {
            paths: vec!["vendor/.*".to_string(), "new/.*".to_string()],
            stopwords: vec!["safe".to_string(), "dev".to_string()],
            rules: vec![],
        },
        ..Default::default()
    };
    let merged = merge_two(base, overlay);

    // "vendor/.*" appears only once
    assert_eq!(
        merged.allowlist.paths.iter().filter(|p| *p == "vendor/.*").count(),
        1
    );
    assert_eq!(merged.allowlist.paths.len(), 3); // vendor, test, new
    // "safe" appears only once
    assert_eq!(
        merged.allowlist.stopwords.iter().filter(|s| *s == "safe").count(),
        1
    );
    assert_eq!(merged.allowlist.stopwords.len(), 2); // safe, dev
}

// -- discovery integration test --

#[test]
fn discover_hierarchy_finds_configs_in_directory_tree() {
    let tmp = tempdir().unwrap();
    // canonicalize to handle macOS /var -> /private/var symlink
    let root = tmp.path().canonicalize().unwrap();
    let child = root.join("org").join("repo");
    fs::create_dir_all(&child).unwrap();

    fs::write(
        root.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 2.0\n",
    )
    .unwrap();
    fs::write(
        child.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 4.0\n",
    )
    .unwrap();

    let paths = discover_hierarchy(&child, &root);
    assert_eq!(paths.len(), 2);
    // root config first (lower priority)
    assert!(paths[0].starts_with(&root));
    assert!(!paths[0].starts_with(&child));
    // child config second (higher priority)
    assert!(paths[1].starts_with(&child));
}

// -- end-to-end: discover + load + merge --

#[test]
fn end_to_end_discover_load_merge() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let child = root.join("projects").join("myapp");
    fs::create_dir_all(&child).unwrap();

    // parent config: set entropy threshold and an allowlist path
    fs::write(
        root.join(".sekretbarilo.toml"),
        r#"
[settings]
entropy_threshold = 2.5

[allowlist]
paths = ["vendor/.*"]
stopwords = ["org-safe"]
"#,
    )
    .unwrap();

    // child config: override entropy, add more allowlist entries
    fs::write(
        child.join(".sekretbarilo.toml"),
        r#"
[settings]
entropy_threshold = 4.0

[allowlist]
paths = ["test/.*"]
stopwords = ["project-safe"]
"#,
    )
    .unwrap();

    // discover and load
    let paths = discover_hierarchy(&child, root);
    assert_eq!(paths.len(), 2);

    let configs: Vec<ProjectConfig> = paths
        .iter()
        .filter_map(|p| load_single_config(p))
        .collect();
    assert_eq!(configs.len(), 2);

    let merged = merge_all(configs);
    // child wins for scalars
    assert_eq!(merged.settings.entropy_threshold, Some(4.0));
    // lists merged
    assert_eq!(merged.allowlist.paths, vec!["vendor/.*", "test/.*"]);
    assert_eq!(merged.allowlist.stopwords, vec!["org-safe", "project-safe"]);
}

// -- 2.4: additional config locations tests --

// 2.4.1: system config at /etc/ is lowest priority
// (cannot write to /etc in tests, so we test via discover_configs which
//  checks /etc but won't find a file there in test environment)

// 2.4.2: xdg config overrides system config
#[test]
#[serial]
fn xdg_config_is_discovered_when_env_set() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();
    let start = home.clone();

    // create xdg config dir
    let xdg_dir = home.join("custom-xdg").join("sekretbarilo");
    fs::create_dir_all(&xdg_dir).unwrap();
    fs::write(
        xdg_dir.join("sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 2.5\n",
    )
    .unwrap();

    // set XDG_CONFIG_HOME for this test
    std::env::set_var("XDG_CONFIG_HOME", home.join("custom-xdg"));
    let configs = discover_configs(&start, &home);
    std::env::remove_var("XDG_CONFIG_HOME");

    // should find the xdg config
    assert!(
        configs.iter().any(|p| p.to_string_lossy().contains("custom-xdg")),
        "expected xdg config in results: {:?}",
        configs
    );
}

// 2.4.3: directory hierarchy overrides xdg config (by position in the list)
#[test]
#[serial]
fn hierarchy_configs_come_after_xdg_in_priority() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();
    let child = home.join("projects").join("repo");
    fs::create_dir_all(&child).unwrap();

    // create xdg config
    let xdg_dir = home.join(".config").join("sekretbarilo");
    fs::create_dir_all(&xdg_dir).unwrap();
    fs::write(
        xdg_dir.join("sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 2.0\n",
    )
    .unwrap();

    // create project config
    fs::write(
        child.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 4.0\n",
    )
    .unwrap();

    // make sure XDG_CONFIG_HOME is not overriding the default
    let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::remove_var("XDG_CONFIG_HOME");

    let configs = discover_configs(&child, &home);

    // restore
    if let Some(val) = prev_xdg {
        std::env::set_var("XDG_CONFIG_HOME", val);
    }

    assert!(
        configs.len() >= 2,
        "expected at least 2 configs, got: {:?}",
        configs
    );

    // xdg config should come before project config
    let xdg_idx = configs.iter().position(|p| p.to_string_lossy().contains(".config/sekretbarilo"));
    let project_idx = configs.iter().position(|p| p.to_string_lossy().contains("projects/repo"));
    assert!(
        xdg_idx.unwrap() < project_idx.unwrap(),
        "xdg should have lower priority (earlier index) than project config"
    );
}

// 2.4.4: repo root config is highest priority (last in the list)
#[test]
#[serial]
fn repo_root_config_is_last_in_priority() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();
    let repo = home.join("work").join("myrepo");
    fs::create_dir_all(&repo).unwrap();

    // home-level config
    fs::write(
        home.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 2.0\n",
    )
    .unwrap();

    // repo root config
    fs::write(
        repo.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 5.0\n",
    )
    .unwrap();

    let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::remove_var("XDG_CONFIG_HOME");
    let configs = discover_configs(&repo, &home);
    if let Some(val) = prev_xdg {
        std::env::set_var("XDG_CONFIG_HOME", val);
    }

    // the last config should be the repo root one (highest priority)
    let last = configs.last().unwrap();
    assert!(
        last.starts_with(&repo),
        "expected repo config as highest priority, got: {:?}",
        last
    );
}

// 2.4.5: missing system/xdg configs are silently ignored
#[test]
#[serial]
fn missing_system_and_xdg_configs_silently_ignored() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();

    // no xdg or system configs exist, only a project config
    fs::write(
        home.join(".sekretbarilo.toml"),
        "[settings]\nentropy_threshold = 3.0\n",
    )
    .unwrap();

    let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
    // point xdg to a nonexistent dir
    std::env::set_var("XDG_CONFIG_HOME", home.join("nonexistent-xdg"));
    let configs = discover_configs(&home, &home);
    if let Some(val) = prev_xdg {
        std::env::set_var("XDG_CONFIG_HOME", val);
    } else {
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    // should still find the project config, no errors
    assert_eq!(configs.len(), 1);
    assert!(configs[0].starts_with(&home));
}

// test that xdg config loads and merges correctly with project config
// (uses load_single_config + merge_all directly to avoid env var race conditions)
#[test]
fn xdg_config_merges_with_project_config() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();

    // create xdg config with stopwords
    let xdg_dir = home.join("xdg-merge-cfg").join("sekretbarilo");
    fs::create_dir_all(&xdg_dir).unwrap();
    let xdg_path = xdg_dir.join("sekretbarilo.toml");
    fs::write(
        &xdg_path,
        r#"
[settings]
entropy_threshold = 2.0

[allowlist]
stopwords = ["xdg-safe"]
"#,
    )
    .unwrap();

    // create project config
    let project_path = home.join(".sekretbarilo.toml");
    fs::write(
        &project_path,
        r#"
[settings]
entropy_threshold = 4.0

[allowlist]
stopwords = ["project-safe"]
"#,
    )
    .unwrap();

    // load configs in priority order (xdg first = lower priority, project second = higher)
    let xdg_cfg = load_single_config(&xdg_path).unwrap();
    let project_cfg = load_single_config(&project_path).unwrap();
    let merged = merge_all(vec![xdg_cfg, project_cfg]);

    // project (local) wins for scalars
    assert_eq!(merged.settings.entropy_threshold, Some(4.0));
    // both stopwords present
    assert!(merged.allowlist.stopwords.contains(&"xdg-safe".to_string()));
    assert!(merged.allowlist.stopwords.contains(&"project-safe".to_string()));
}
