mod audit;
mod diff;
mod scanner;
mod config;
mod output;
mod hook;

use std::path::{Path, PathBuf};

use config::allowlist::CompiledAllowlist;
use config::ProjectConfig;
use scanner::rules::CompiledScanner;

fn main() {
    std::process::exit(run());
}

/// cli subcommand
#[derive(Debug, PartialEq)]
enum Command {
    Scan,
    Audit,
    Install,
    Help,
}

/// cli overrides that apply to both scan and audit
#[derive(Debug, Default)]
struct CliOverrides {
    config_paths: Vec<PathBuf>,
    no_defaults: bool,
    entropy_threshold: Option<f64>,
    allowlist_paths: Vec<String>,
    stopwords: Vec<String>,
    exclude_patterns: Vec<String>,
    include_patterns: Vec<String>,
    include_ignored: bool,
}

/// audit-specific flags parsed from cli
#[derive(Debug, Default)]
struct AuditFlags {
    history: bool,
    branch: Option<String>,
    since: Option<String>,
    until: Option<String>,
}

/// parse cli arguments into (command, overrides, audit_flags).
/// first positional arg is the subcommand (defaults to Scan).
fn parse_cli(args: &[String]) -> Result<(Command, CliOverrides, AuditFlags), String> {
    let mut command: Option<Command> = None;
    let mut overrides = CliOverrides::default();
    let mut audit_flags = AuditFlags::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            // subcommands
            "scan" | "install" | "audit" | "--help" | "-h" if command.is_none() => {
                command = Some(match args[i].as_str() {
                    "scan" => Command::Scan,
                    "audit" => Command::Audit,
                    "install" => Command::Install,
                    "--help" | "-h" => Command::Help,
                    _ => unreachable!(),
                });
            }

            // common flags
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err("--config requires a value".to_string());
                }
                overrides.config_paths.push(PathBuf::from(&args[i]));
            }
            "--no-defaults" => {
                overrides.no_defaults = true;
            }
            "--entropy-threshold" => {
                i += 1;
                if i >= args.len() {
                    return Err("--entropy-threshold requires a value".to_string());
                }
                let val: f64 = args[i]
                    .parse()
                    .map_err(|_| format!("invalid value for --entropy-threshold: '{}'", args[i]))?;
                overrides.entropy_threshold = Some(val);
            }
            "--allowlist-path" => {
                i += 1;
                if i >= args.len() {
                    return Err("--allowlist-path requires a value".to_string());
                }
                overrides.allowlist_paths.push(args[i].clone());
            }
            "--stopword" => {
                i += 1;
                if i >= args.len() {
                    return Err("--stopword requires a value".to_string());
                }
                overrides.stopwords.push(args[i].clone());
            }

            // audit-specific flags
            "--history" => {
                audit_flags.history = true;
            }
            "--branch" => {
                i += 1;
                if i >= args.len() {
                    return Err("--branch requires a value".to_string());
                }
                audit_flags.branch = Some(args[i].clone());
            }
            "--since" => {
                i += 1;
                if i >= args.len() {
                    return Err("--since requires a value".to_string());
                }
                audit_flags.since = Some(args[i].clone());
            }
            "--until" => {
                i += 1;
                if i >= args.len() {
                    return Err("--until requires a value".to_string());
                }
                audit_flags.until = Some(args[i].clone());
            }
            "--include-ignored" => {
                overrides.include_ignored = true;
            }
            "--exclude-pattern" => {
                i += 1;
                if i >= args.len() {
                    return Err("--exclude-pattern requires a value".to_string());
                }
                overrides.exclude_patterns.push(args[i].clone());
            }
            "--include-pattern" => {
                i += 1;
                if i >= args.len() {
                    return Err("--include-pattern requires a value".to_string());
                }
                overrides.include_patterns.push(args[i].clone());
            }

            other => {
                return Err(format!("unknown flag: {}", other));
            }
        }
        i += 1;
    }

    let command = command.unwrap_or(Command::Scan);

    // validate audit-only flags on non-audit commands
    if command != Command::Audit {
        if audit_flags.history {
            return Err("--history is only valid with audit".to_string());
        }
        if audit_flags.branch.is_some() {
            return Err("--branch is only valid with audit".to_string());
        }
        if audit_flags.since.is_some() {
            return Err("--since is only valid with audit".to_string());
        }
        if audit_flags.until.is_some() {
            return Err("--until is only valid with audit".to_string());
        }
        if !overrides.exclude_patterns.is_empty() {
            return Err("--exclude-pattern is only valid with audit".to_string());
        }
        if !overrides.include_patterns.is_empty() {
            return Err("--include-pattern is only valid with audit".to_string());
        }
        if overrides.include_ignored {
            return Err("--include-ignored is only valid with audit".to_string());
        }
    }

    Ok((command, overrides, audit_flags))
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let (command, overrides, audit_flags) = match parse_cli(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            eprintln!();
            print_usage();
            return 2;
        }
    };

    match command {
        Command::Help => {
            print_usage();
            0
        }
        Command::Install => run_install(),
        Command::Scan => run_scan(&overrides),
        Command::Audit => run_audit_cmd(&overrides, &audit_flags),
    }
}

fn print_usage() {
    eprintln!("sekretbarilo - secret scanner for git repositories");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  sekretbarilo              scan staged changes (default)");
    eprintln!("  sekretbarilo scan         scan staged changes");
    eprintln!("  sekretbarilo install      install git pre-commit hook");
    eprintln!("  sekretbarilo audit        scan all tracked files in working tree");
    eprintln!("  sekretbarilo --help       show this help");
    eprintln!();
    eprintln!("common flags:");
    eprintln!("  --config <path>           use explicit config file (repeatable, skips discovery)");
    eprintln!("  --no-defaults             skip embedded default rules");
    eprintln!("  --entropy-threshold <n>   override entropy threshold");
    eprintln!("  --allowlist-path <pat>    add path to allowlist (repeatable)");
    eprintln!("  --stopword <word>         add stopword (repeatable)");
    eprintln!();
    eprintln!("audit flags:");
    eprintln!("  --history                 scan full git history (all commits)");
    eprintln!("  --branch <name>           limit to commits reachable from branch (requires --history)");
    eprintln!("  --since <date>            only commits after date (requires --history)");
    eprintln!("  --until <date>            only commits before date (requires --history)");
    eprintln!("  --include-ignored         include untracked ignored files");
    eprintln!("  --exclude-pattern <pat>   add exclude pattern for audit (repeatable)");
    eprintln!("  --include-pattern <pat>   add include pattern for audit (repeatable)");
    eprintln!();
    eprintln!("examples:");
    eprintln!("  sekretbarilo scan --config rules.toml       scan with explicit config");
    eprintln!("  sekretbarilo scan --no-defaults              scan without built-in rules");
    eprintln!("  sekretbarilo scan --stopword mytoken         add a stopword");
    eprintln!("  sekretbarilo audit                           scan working tree");
    eprintln!("  sekretbarilo audit --history                 scan all commits");
    eprintln!("  sekretbarilo audit --history --branch main   scan main branch history");
    eprintln!("  sekretbarilo audit --history --since 2024-01-01");
    eprintln!("  sekretbarilo audit --exclude-pattern '^vendor/'");
    eprintln!("  sekretbarilo audit --config a.toml --config b.toml");
}

/// resolve the git repository root directory.
/// returns None if we can't determine it (non-fatal, falls back to defaults).
fn resolve_repo_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root))
}

/// apply cli overrides on top of a loaded project config.
/// scalars override, lists are appended and deduplicated via merge_two.
fn apply_cli_overrides(
    base: ProjectConfig,
    overrides: &CliOverrides,
) -> ProjectConfig {
    let cli_config = ProjectConfig {
        allowlist: config::AllowlistConfig {
            paths: overrides.allowlist_paths.clone(),
            stopwords: overrides.stopwords.clone(),
            rules: vec![],
        },
        settings: config::SettingsConfig {
            entropy_threshold: overrides.entropy_threshold,
        },
        rules: vec![],
        audit: config::AuditConfig {
            include_ignored: if overrides.include_ignored {
                Some(true)
            } else {
                None
            },
            exclude_patterns: overrides.exclude_patterns.clone(),
            include_patterns: overrides.include_patterns.clone(),
        },
    };

    config::merge::merge_two(base, cli_config)
}

/// build the scan context: config, compiled scanner, and allowlist.
/// handles --config, --no-defaults, and cli overrides.
fn build_scan_context(
    overrides: &CliOverrides,
    repo_root: Option<&Path>,
) -> Result<(ProjectConfig, CompiledScanner, CompiledAllowlist), String> {
    // step 1: load config
    let project_config = if !overrides.config_paths.is_empty() {
        config::load_project_config_from_paths(&overrides.config_paths)?
    } else {
        config::load_project_config(repo_root)?
    };

    // step 2: apply cli overrides
    let project_config = apply_cli_overrides(project_config, overrides);

    // step 3: load rules
    let rules = if overrides.no_defaults {
        let r = project_config.rules.clone();
        if r.is_empty() {
            eprintln!("[WARN] --no-defaults: no rules found in config, scan will find nothing");
        }
        r
    } else {
        config::load_rules_with_config(&project_config)?
    };

    // step 4: compile
    let compiled = scanner::rules::compile_rules(&rules)
        .map_err(|e| format!("failed to compile rules: {}", e))?;

    let allowlist = config::build_allowlist(&project_config, &rules)
        .map_err(|e| format!("failed to build allowlist: {}", e))?;

    Ok((project_config, compiled, allowlist))
}

fn run_install() -> i32 {
    match hook::install(None) {
        Ok(result) => {
            eprintln!("[OK] {}", result);
            0
        }
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            2
        }
    }
}

fn run_scan(overrides: &CliOverrides) -> i32 {
    // step 1: get the staged diff
    let raw_diff = match diff::get_staged_diff() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    if raw_diff.is_empty() {
        return 0;
    }

    // step 2: parse diff into file blocks
    let files = diff::parser::parse_diff(&raw_diff);

    // step 3: check for blocked .env files
    let env_check = diff::check_env_files(&files);

    // resolve repo root for config loading
    let repo_root = resolve_repo_root();

    // step 4: build scan context (config + scanner + allowlist)
    let (_project_config, compiled, allowlist) =
        match build_scan_context(overrides, repo_root.as_deref()) {
            Ok(ctx) => ctx,
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                return 2;
            }
        };

    // step 5: scan for secrets (exclude .env blocked files to avoid duplicate findings)
    let scannable_files: Vec<_> = files
        .iter()
        .filter(|f| !env_check.blocked_files.contains(&f.path))
        .cloned()
        .collect();
    let findings = scanner::engine::scan(&scannable_files, &compiled, &allowlist);

    // step 6: report findings
    let total = output::report_findings(&findings, &env_check.blocked_files);

    if total > 0 {
        1
    } else {
        0
    }
}

fn run_audit_cmd(overrides: &CliOverrides, audit_flags: &AuditFlags) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            eprintln!("[ERROR] not a git repository");
            return 2;
        }
    };

    // build scan context with cli overrides
    let (project_config, compiled, allowlist) =
        match build_scan_context(overrides, Some(&repo_root)) {
            Ok(ctx) => ctx,
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                return 2;
            }
        };

    let options = audit::AuditOptions {
        history: audit_flags.history,
        branch: audit_flags.branch.clone(),
        since: audit_flags.since.clone(),
        until: audit_flags.until.clone(),
        include_ignored: overrides.include_ignored,
    };

    audit::run_audit(&repo_root, &options, &project_config, &compiled, &allowlist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        if s.is_empty() {
            return vec![];
        }
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parse_cli_default_scan() {
        let (cmd, overrides, _) = parse_cli(&args("")).unwrap();
        assert_eq!(cmd, Command::Scan);
        assert!(!overrides.no_defaults);
        assert!(overrides.config_paths.is_empty());
    }

    #[test]
    fn parse_cli_explicit_scan() {
        let (cmd, _, _) = parse_cli(&args("scan")).unwrap();
        assert_eq!(cmd, Command::Scan);
    }

    #[test]
    fn parse_cli_audit() {
        let (cmd, _, _) = parse_cli(&args("audit")).unwrap();
        assert_eq!(cmd, Command::Audit);
    }

    #[test]
    fn parse_cli_install() {
        let (cmd, _, _) = parse_cli(&args("install")).unwrap();
        assert_eq!(cmd, Command::Install);
    }

    #[test]
    fn parse_cli_help() {
        let (cmd, _, _) = parse_cli(&args("--help")).unwrap();
        assert_eq!(cmd, Command::Help);
    }

    #[test]
    fn parse_cli_help_short() {
        let (cmd, _, _) = parse_cli(&args("-h")).unwrap();
        assert_eq!(cmd, Command::Help);
    }

    #[test]
    fn parse_cli_config_paths() {
        let (_, overrides, _) =
            parse_cli(&args("scan --config a.toml --config b.toml")).unwrap();
        assert_eq!(overrides.config_paths.len(), 2);
        assert_eq!(overrides.config_paths[0], PathBuf::from("a.toml"));
        assert_eq!(overrides.config_paths[1], PathBuf::from("b.toml"));
    }

    #[test]
    fn parse_cli_no_defaults() {
        let (_, overrides, _) = parse_cli(&args("scan --no-defaults")).unwrap();
        assert!(overrides.no_defaults);
    }

    #[test]
    fn parse_cli_entropy_threshold() {
        let (_, overrides, _) =
            parse_cli(&args("scan --entropy-threshold 4.5")).unwrap();
        assert_eq!(overrides.entropy_threshold, Some(4.5));
    }

    #[test]
    fn parse_cli_entropy_threshold_invalid() {
        let err = parse_cli(&args("scan --entropy-threshold abc")).unwrap_err();
        assert!(err.contains("invalid value"));
    }

    #[test]
    fn parse_cli_entropy_threshold_missing_value() {
        let err = parse_cli(&args("scan --entropy-threshold")).unwrap_err();
        assert!(err.contains("requires a value"));
    }

    #[test]
    fn parse_cli_allowlist_paths_repeatable() {
        let (_, overrides, _) =
            parse_cli(&args("scan --allowlist-path vendor/.* --allowlist-path test/.*")).unwrap();
        assert_eq!(overrides.allowlist_paths, vec!["vendor/.*", "test/.*"]);
    }

    #[test]
    fn parse_cli_stopwords_repeatable() {
        let (_, overrides, _) =
            parse_cli(&args("scan --stopword foo --stopword bar")).unwrap();
        assert_eq!(overrides.stopwords, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_cli_audit_flags() {
        let (cmd, overrides, flags) = parse_cli(&args(
            "audit --history --branch main --since 2024-01-01 --until 2024-12-31 --include-ignored",
        ))
        .unwrap();
        assert_eq!(cmd, Command::Audit);
        assert!(flags.history);
        assert_eq!(flags.branch, Some("main".to_string()));
        assert_eq!(flags.since, Some("2024-01-01".to_string()));
        assert_eq!(flags.until, Some("2024-12-31".to_string()));
        assert!(overrides.include_ignored);
    }

    #[test]
    fn parse_cli_audit_exclude_include_patterns() {
        let a: Vec<String> = vec![
            "audit", "--exclude-pattern", "^vendor/", "--include-pattern", r"\.rs$",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (_, overrides, _) = parse_cli(&a).unwrap();
        assert_eq!(overrides.exclude_patterns, vec!["^vendor/"]);
        assert_eq!(overrides.include_patterns, vec![r"\.rs$"]);
    }

    #[test]
    fn parse_cli_history_on_scan_rejected() {
        let err = parse_cli(&args("scan --history")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_branch_on_scan_rejected() {
        let err = parse_cli(&args("scan --branch main")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_since_on_scan_rejected() {
        let err = parse_cli(&args("scan --since 2024-01-01")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_until_on_scan_rejected() {
        let err = parse_cli(&args("scan --until 2024-12-31")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_exclude_pattern_on_scan_rejected() {
        let err = parse_cli(&args("scan --exclude-pattern ^vendor/")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_include_pattern_on_scan_rejected() {
        let err = parse_cli(&args("scan --include-pattern .rs$")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_include_ignored_on_scan_rejected() {
        let err = parse_cli(&args("scan --include-ignored")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_unknown_flag() {
        let err = parse_cli(&args("scan --bogus")).unwrap_err();
        assert!(err.contains("unknown flag"));
    }

    #[test]
    fn parse_cli_config_missing_value() {
        let err = parse_cli(&args("scan --config")).unwrap_err();
        assert!(err.contains("requires a value"));
    }

    #[test]
    fn parse_cli_all_common_flags_with_audit() {
        let (cmd, overrides, _) = parse_cli(&args(
            "audit --config rules.toml --no-defaults --entropy-threshold 3.5 --allowlist-path test/.* --stopword safe",
        )).unwrap();
        assert_eq!(cmd, Command::Audit);
        assert_eq!(overrides.config_paths.len(), 1);
        assert!(overrides.no_defaults);
        assert_eq!(overrides.entropy_threshold, Some(3.5));
        assert_eq!(overrides.allowlist_paths, vec!["test/.*"]);
        assert_eq!(overrides.stopwords, vec!["safe"]);
    }

    #[test]
    fn parse_cli_duplicate_scalar_last_wins() {
        let (_, overrides, _) =
            parse_cli(&args("scan --entropy-threshold 3.0 --entropy-threshold 4.5")).unwrap();
        assert_eq!(overrides.entropy_threshold, Some(4.5));
    }

    #[test]
    fn build_scan_context_defaults() {
        // should succeed with default overrides (no explicit config, using defaults)
        let overrides = CliOverrides::default();
        let result = build_scan_context(&overrides, None);
        assert!(result.is_ok());
    }

    #[test]
    fn build_scan_context_no_defaults_no_rules() {
        let overrides = CliOverrides {
            no_defaults: true,
            ..Default::default()
        };
        let result = build_scan_context(&overrides, None);
        // should succeed but with empty rules (warning emitted)
        assert!(result.is_ok());
    }

    #[test]
    fn build_scan_context_nonexistent_config() {
        let overrides = CliOverrides {
            config_paths: vec![PathBuf::from("/tmp/nonexistent_sekretbarilo_test.toml")],
            ..Default::default()
        };
        let result = build_scan_context(&overrides, None);
        assert!(result.is_err());
    }
}
