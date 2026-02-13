#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod agent;
mod audit;
mod config;
mod diff;
mod doctor;
mod hook;
mod output;
mod scanner;

use std::path::{Path, PathBuf};

use getargs::Arg;

use config::allowlist::CompiledAllowlist;
use config::ProjectConfig;
use doctor::resolve_repo_root;
use scanner::rules::CompiledScanner;

fn main() {
    std::process::exit(run());
}

/// cli subcommand
#[derive(Debug, PartialEq)]
enum Command {
    Scan,
    Audit,
    InstallPreCommit,
    InstallAgentHook,
    InstallAll,
    InstallHelp,
    CheckFile,
    Doctor,
    Help,
    Version,
}

/// install-specific flags parsed from cli
#[derive(Debug, Default)]
struct InstallFlags {
    global: bool,
}

/// check-file specific flags parsed from cli
#[derive(Debug, Default)]
struct CheckFileFlags {
    stdin_json: bool,
    file_path: Option<String>,
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

/// parse cli arguments into (command, overrides, audit_flags, check_file_flags, install_flags).
/// first positional arg is the subcommand. no subcommand shows help.
fn parse_cli(
    args: &[String],
) -> Result<
    (
        Command,
        CliOverrides,
        AuditFlags,
        CheckFileFlags,
        InstallFlags,
    ),
    String,
> {
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let mut opts = getargs::Options::new(args_str.into_iter());

    let mut command: Option<Command> = None;
    let mut overrides = CliOverrides::default();
    let mut audit_flags = AuditFlags::default();
    let mut check_file_flags = CheckFileFlags::default();
    let mut install_flags = InstallFlags::default();

    while let Some(arg) = opts.next_arg().map_err(|e| e.to_string())? {
        match arg {
            // subcommands (first positional sets the command)
            Arg::Positional(pos) if command.is_none() => {
                command = Some(match pos {
                    "scan" => Command::Scan,
                    "audit" => Command::Audit,
                    "doctor" => Command::Doctor,
                    "check-file" => Command::CheckFile,
                    "install" => parse_install_subcommand(&mut opts)?,
                    other => return Err(format!("unknown command: '{}'", other)),
                });
            }
            // positional after command (check-file file path)
            Arg::Positional(pos) => {
                if command == Some(Command::CheckFile) && check_file_flags.file_path.is_none() {
                    check_file_flags.file_path = Some(pos.to_string());
                } else {
                    return Err(format!("unexpected argument: '{}'", pos));
                }
            }
            // help (only before a subcommand; after one it falls through to unknown)
            Arg::Long("help") if command.is_none() => command = Some(Command::Help),
            Arg::Short('h') if command.is_none() => command = Some(Command::Help),
            // version
            Arg::Long("version") if command.is_none() => command = Some(Command::Version),
            Arg::Short('V') if command.is_none() => command = Some(Command::Version),
            // common flags
            Arg::Long("config") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                overrides.config_paths.push(PathBuf::from(val));
            }
            Arg::Long("no-defaults") => overrides.no_defaults = true,
            Arg::Long("entropy-threshold") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                let n: f64 = val
                    .parse()
                    .map_err(|_| format!("invalid value for --entropy-threshold: '{}'", val))?;
                overrides.entropy_threshold = Some(n);
            }
            Arg::Long("allowlist-path") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                overrides.allowlist_paths.push(val.to_string());
            }
            Arg::Long("stopword") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                overrides.stopwords.push(val.to_string());
            }
            // audit-specific flags
            Arg::Long("history") => audit_flags.history = true,
            Arg::Long("branch") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                audit_flags.branch = Some(val.to_string());
            }
            Arg::Long("since") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                audit_flags.since = Some(val.to_string());
            }
            Arg::Long("until") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                audit_flags.until = Some(val.to_string());
            }
            Arg::Long("include-ignored") => overrides.include_ignored = true,
            Arg::Long("exclude-pattern") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                overrides.exclude_patterns.push(val.to_string());
            }
            Arg::Long("include-pattern") => {
                let val = opts.value().map_err(|e| e.to_string())?;
                overrides.include_patterns.push(val.to_string());
            }
            // install flags
            Arg::Long("global") => install_flags.global = true,
            // check-file flags
            Arg::Long("stdin-json") => check_file_flags.stdin_json = true,
            // unknown
            Arg::Long(unknown) => return Err(format!("unknown flag: --{}", unknown)),
            Arg::Short(unknown) => return Err(format!("unknown flag: -{}", unknown)),
        }
    }

    let command = command.unwrap_or(Command::Help);

    // validate check-file flags
    if command != Command::CheckFile && check_file_flags.stdin_json {
        return Err("--stdin-json is only valid with check-file".to_string());
    }
    if check_file_flags.stdin_json && check_file_flags.file_path.is_some() {
        return Err("--stdin-json and file path argument are mutually exclusive".to_string());
    }

    // validate install flags
    let is_install_cmd = matches!(
        command,
        Command::InstallPreCommit
            | Command::InstallAgentHook
            | Command::InstallAll
            | Command::InstallHelp
    );
    if !is_install_cmd && install_flags.global {
        return Err("--global is only valid with install subcommands".to_string());
    }

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

    // validate that config-override flags are only accepted by scan and audit
    let accepts_config_flags = matches!(command, Command::Scan | Command::Audit);
    if !accepts_config_flags {
        if !overrides.config_paths.is_empty() {
            return Err("--config is only valid with scan or audit".to_string());
        }
        if overrides.no_defaults {
            return Err("--no-defaults is only valid with scan or audit".to_string());
        }
        if overrides.entropy_threshold.is_some() {
            return Err("--entropy-threshold is only valid with scan or audit".to_string());
        }
        if !overrides.allowlist_paths.is_empty() {
            return Err("--allowlist-path is only valid with scan or audit".to_string());
        }
        if !overrides.stopwords.is_empty() {
            return Err("--stopword is only valid with scan or audit".to_string());
        }
    }

    Ok((
        command,
        overrides,
        audit_flags,
        check_file_flags,
        install_flags,
    ))
}

/// parse the install subcommand target from the remaining args.
fn parse_install_subcommand<'a, I: Iterator<Item = &'a str>>(
    opts: &mut getargs::Options<&'a str, I>,
) -> Result<Command, String> {
    match opts.next_arg().map_err(|e| e.to_string())? {
        Some(Arg::Positional("pre-commit")) => Ok(Command::InstallPreCommit),
        Some(Arg::Positional("all")) => Ok(Command::InstallAll),
        Some(Arg::Positional("agent-hook")) => match opts.next_arg().map_err(|e| e.to_string())? {
            Some(Arg::Positional("claude")) => Ok(Command::InstallAgentHook),
            Some(Arg::Positional("codex")) => Err("codex agent hooks are not yet supported. \
                     codex cli does not currently provide a hooks api"
                .to_string()),
            Some(Arg::Positional(other)) => Err(format!(
                "unknown agent hook target: '{}'. supported: claude",
                other
            )),
            _ => Err("install agent-hook requires a target. supported: claude".to_string()),
        },
        Some(Arg::Long("help")) | Some(Arg::Short('h')) => Ok(Command::InstallHelp),
        Some(Arg::Positional(other)) => Err(format!(
            "unknown install target: '{}'. supported: pre-commit, agent-hook, all",
            other
        )),
        Some(Arg::Long(f)) => Err(format!(
            "unknown install flag: '--{}'. use 'install --help' for usage",
            f
        )),
        Some(Arg::Short(f)) => Err(format!(
            "unknown install flag: '-{}'. use 'install --help' for usage",
            f
        )),
        None => Ok(Command::InstallHelp),
    }
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let (command, overrides, audit_flags, check_file_flags, install_flags) = match parse_cli(&args)
    {
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
        Command::Version => {
            eprintln!("sekretbarilo {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Command::InstallPreCommit => run_install_pre_commit(install_flags.global),
        Command::InstallAgentHook => run_install_agent_hook(install_flags.global),
        Command::InstallAll => run_install_all(install_flags.global),
        Command::InstallHelp => {
            print_install_usage();
            0
        }
        Command::Scan => run_scan(&overrides),
        Command::Audit => run_audit_cmd(&overrides, &audit_flags),
        Command::CheckFile => agent::run_check_file(
            check_file_flags.stdin_json,
            check_file_flags.file_path.as_deref(),
        ),
        Command::Doctor => doctor::run_doctor(),
    }
}

fn print_usage() {
    eprintln!("sekretbarilo - secret scanner for git workflows and AI coding agents");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  sekretbarilo scan         scan staged changes");
    eprintln!("  sekretbarilo install      install hooks (see: sekretbarilo install --help)");
    eprintln!("  sekretbarilo audit        scan all tracked files in working tree");
    eprintln!("  sekretbarilo check-file   scan a single file for secrets (agent hook mode)");
    eprintln!("  sekretbarilo doctor       diagnose hook installation and configuration");
    eprintln!("  sekretbarilo --help       show this help");
    eprintln!("  sekretbarilo --version    show version");
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
    eprintln!(
        "  --branch <name>           limit to commits reachable from branch (requires --history)"
    );
    eprintln!("  --since <date>            only commits after date (requires --history)");
    eprintln!("  --until <date>            only commits before date (requires --history)");
    eprintln!("  --include-ignored         include untracked ignored files");
    eprintln!("  --exclude-pattern <pat>   add exclude pattern for audit (repeatable)");
    eprintln!("  --include-pattern <pat>   add include pattern for audit (repeatable)");
    eprintln!();
    eprintln!("check-file flags:");
    eprintln!("  --stdin-json              read file path from JSON on stdin (agent hook mode)");
    eprintln!();
    eprintln!("examples:");
    eprintln!("  sekretbarilo scan --config rules.toml              scan with explicit config");
    eprintln!("  sekretbarilo scan --no-defaults                    scan without built-in rules");
    eprintln!("  sekretbarilo scan --stopword mytoken               add a stopword");
    eprintln!("  sekretbarilo install pre-commit                    install git pre-commit hook");
    eprintln!("  sekretbarilo install agent-hook claude              install claude code hook");
    eprintln!("  sekretbarilo install all --global                  install all hooks globally");
    eprintln!("  sekretbarilo audit                                 scan working tree");
    eprintln!("  sekretbarilo audit --history                       scan all commits");
    eprintln!("  sekretbarilo audit --history --branch main         scan main branch history");
    eprintln!("  sekretbarilo audit --history --since 2024-01-01");
    eprintln!("  sekretbarilo audit --exclude-pattern '^vendor/'");
    eprintln!("  sekretbarilo check-file src/config.rs              scan a single file");
    eprintln!("  sekretbarilo check-file --stdin-json               read path from hook payload");
    eprintln!("  sekretbarilo doctor                                check installation health");
}

fn print_install_usage() {
    eprintln!("sekretbarilo install - install hooks for secret scanning");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  sekretbarilo install pre-commit          install git pre-commit hook");
    eprintln!("  sekretbarilo install agent-hook claude    install claude code agent hook");
    eprintln!("  sekretbarilo install all                  install all available hooks");
    eprintln!();
    eprintln!("flags:");
    eprintln!("  --global    install globally instead of locally");
    eprintln!("              pre-commit: uses git config --global core.hooksPath directory");
    eprintln!("              agent-hook: modifies ~/.claude/settings.json");
    eprintln!();
    eprintln!("examples:");
    eprintln!("  sekretbarilo install pre-commit              install local pre-commit hook");
    eprintln!("  sekretbarilo install pre-commit --global     install global pre-commit hook");
    eprintln!("  sekretbarilo install agent-hook claude        install local claude code hook");
    eprintln!("  sekretbarilo install agent-hook claude --global");
    eprintln!("  sekretbarilo install all                      install all hooks locally");
    eprintln!("  sekretbarilo install all --global             install all hooks globally");
}

/// apply cli overrides on top of a loaded project config.
/// scalars override, lists are appended and deduplicated via merge_two.
fn apply_cli_overrides(base: ProjectConfig, overrides: &CliOverrides) -> ProjectConfig {
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

fn run_install_pre_commit(global: bool) -> i32 {
    if global {
        match hook::install_global() {
            Ok(result) => {
                eprintln!("[OK] {}", result);
                0
            }
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                2
            }
        }
    } else {
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
}

fn run_install_agent_hook(global: bool) -> i32 {
    match agent::install_claude_hook(global) {
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

fn run_install_all(global: bool) -> i32 {
    // install pre-commit hook
    eprintln!("installing pre-commit hook...");
    let pre_commit_result = run_install_pre_commit(global);

    // install claude code agent hook
    eprintln!("installing claude code agent hook...");
    let agent_result = run_install_agent_hook(global);

    // return non-zero if either install failed
    if pre_commit_result != 0 || agent_result != 0 {
        return 2;
    }
    0
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
    fn parse_cli_default_help() {
        let (cmd, _, _, _, _) = parse_cli(&args("")).unwrap();
        assert_eq!(cmd, Command::Help);
    }

    #[test]
    fn parse_cli_explicit_scan() {
        let (cmd, _, _, _, _) = parse_cli(&args("scan")).unwrap();
        assert_eq!(cmd, Command::Scan);
    }

    #[test]
    fn parse_cli_audit() {
        let (cmd, _, _, _, _) = parse_cli(&args("audit")).unwrap();
        assert_eq!(cmd, Command::Audit);
    }

    #[test]
    fn parse_cli_install_bare_shows_help() {
        let (cmd, _, _, _, _) = parse_cli(&args("install")).unwrap();
        assert_eq!(cmd, Command::InstallHelp);
    }

    #[test]
    fn parse_cli_help() {
        let (cmd, _, _, _, _) = parse_cli(&args("--help")).unwrap();
        assert_eq!(cmd, Command::Help);
    }

    #[test]
    fn parse_cli_help_short() {
        let (cmd, _, _, _, _) = parse_cli(&args("-h")).unwrap();
        assert_eq!(cmd, Command::Help);
    }

    #[test]
    fn parse_cli_config_paths() {
        let (_, overrides, _, _, _) =
            parse_cli(&args("scan --config a.toml --config b.toml")).unwrap();
        assert_eq!(overrides.config_paths.len(), 2);
        assert_eq!(overrides.config_paths[0], PathBuf::from("a.toml"));
        assert_eq!(overrides.config_paths[1], PathBuf::from("b.toml"));
    }

    #[test]
    fn parse_cli_no_defaults() {
        let (_, overrides, _, _, _) = parse_cli(&args("scan --no-defaults")).unwrap();
        assert!(overrides.no_defaults);
    }

    #[test]
    fn parse_cli_entropy_threshold() {
        let (_, overrides, _, _, _) = parse_cli(&args("scan --entropy-threshold 4.5")).unwrap();
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
        let (_, overrides, _, _, _) = parse_cli(&args(
            "scan --allowlist-path vendor/.* --allowlist-path test/.*",
        ))
        .unwrap();
        assert_eq!(overrides.allowlist_paths, vec!["vendor/.*", "test/.*"]);
    }

    #[test]
    fn parse_cli_stopwords_repeatable() {
        let (_, overrides, _, _, _) =
            parse_cli(&args("scan --stopword foo --stopword bar")).unwrap();
        assert_eq!(overrides.stopwords, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_cli_audit_flags() {
        let (cmd, overrides, flags, _, _) = parse_cli(&args(
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
            "audit",
            "--exclude-pattern",
            "^vendor/",
            "--include-pattern",
            r"\.rs$",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (_, overrides, _, _, _) = parse_cli(&a).unwrap();
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
        let (cmd, overrides, _, _, _) = parse_cli(&args(
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
        let (_, overrides, _, _, _) = parse_cli(&args(
            "scan --entropy-threshold 3.0 --entropy-threshold 4.5",
        ))
        .unwrap();
        assert_eq!(overrides.entropy_threshold, Some(4.5));
    }

    #[test]
    fn parse_cli_check_file() {
        let (cmd, _, _, _, _) = parse_cli(&args("check-file")).unwrap();
        assert_eq!(cmd, Command::CheckFile);
    }

    #[test]
    fn parse_cli_check_file_with_path() {
        let (cmd, _, _, cf_flags, _) = parse_cli(&args("check-file src/main.rs")).unwrap();
        assert_eq!(cmd, Command::CheckFile);
        assert_eq!(cf_flags.file_path, Some("src/main.rs".to_string()));
        assert!(!cf_flags.stdin_json);
    }

    #[test]
    fn parse_cli_check_file_stdin_json() {
        let (cmd, _, _, cf_flags, _) = parse_cli(&args("check-file --stdin-json")).unwrap();
        assert_eq!(cmd, Command::CheckFile);
        assert!(cf_flags.stdin_json);
        assert!(cf_flags.file_path.is_none());
    }

    #[test]
    fn parse_cli_stdin_json_on_scan_rejected() {
        let err = parse_cli(&args("scan --stdin-json")).unwrap_err();
        assert!(err.contains("only valid with check-file"));
    }

    #[test]
    fn parse_cli_stdin_json_and_file_path_mutually_exclusive() {
        let err = parse_cli(&args("check-file --stdin-json src/main.rs")).unwrap_err();
        assert!(err.contains("mutually exclusive"));
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

    // -- install subcommand tests --

    #[test]
    fn parse_cli_install_pre_commit() {
        let (cmd, _, _, _, flags) = parse_cli(&args("install pre-commit")).unwrap();
        assert_eq!(cmd, Command::InstallPreCommit);
        assert!(!flags.global);
    }

    #[test]
    fn parse_cli_install_pre_commit_global() {
        let (cmd, _, _, _, flags) = parse_cli(&args("install pre-commit --global")).unwrap();
        assert_eq!(cmd, Command::InstallPreCommit);
        assert!(flags.global);
    }

    #[test]
    fn parse_cli_install_agent_hook_claude() {
        let (cmd, _, _, _, flags) = parse_cli(&args("install agent-hook claude")).unwrap();
        assert_eq!(cmd, Command::InstallAgentHook);
        assert!(!flags.global);
    }

    #[test]
    fn parse_cli_install_agent_hook_claude_global() {
        let (cmd, _, _, _, flags) = parse_cli(&args("install agent-hook claude --global")).unwrap();
        assert_eq!(cmd, Command::InstallAgentHook);
        assert!(flags.global);
    }

    #[test]
    fn parse_cli_install_all() {
        let (cmd, _, _, _, _) = parse_cli(&args("install all")).unwrap();
        assert_eq!(cmd, Command::InstallAll);
    }

    #[test]
    fn parse_cli_install_all_global() {
        let (cmd, _, _, _, flags) = parse_cli(&args("install all --global")).unwrap();
        assert_eq!(cmd, Command::InstallAll);
        assert!(flags.global);
    }

    #[test]
    fn parse_cli_install_unknown_target() {
        let err = parse_cli(&args("install bogus")).unwrap_err();
        assert!(err.contains("unknown install target"));
    }

    #[test]
    fn parse_cli_install_agent_hook_missing_target() {
        let err = parse_cli(&args("install agent-hook")).unwrap_err();
        assert!(err.contains("requires a target"));
    }

    #[test]
    fn parse_cli_install_agent_hook_codex_not_yet_supported() {
        let err = parse_cli(&args("install agent-hook codex")).unwrap_err();
        assert!(err.contains("not yet supported"));
    }

    #[test]
    fn parse_cli_install_agent_hook_unknown_agent() {
        let err = parse_cli(&args("install agent-hook bogus")).unwrap_err();
        assert!(err.contains("unknown agent hook target"));
    }

    #[test]
    fn parse_cli_global_on_scan_rejected() {
        let err = parse_cli(&args("scan --global")).unwrap_err();
        assert!(err.contains("only valid with install"));
    }

    #[test]
    fn parse_cli_install_help_flag() {
        let (cmd, _, _, _, _) = parse_cli(&args("install --help")).unwrap();
        assert_eq!(cmd, Command::InstallHelp);
    }

    #[test]
    fn parse_cli_install_help_short_flag() {
        let (cmd, _, _, _, _) = parse_cli(&args("install -h")).unwrap();
        assert_eq!(cmd, Command::InstallHelp);
    }

    #[test]
    fn parse_cli_doctor() {
        let (cmd, _, _, _, _) = parse_cli(&args("doctor")).unwrap();
        assert_eq!(cmd, Command::Doctor);
    }

    #[test]
    fn parse_cli_doctor_rejects_audit_flags() {
        let err = parse_cli(&args("doctor --history")).unwrap_err();
        assert!(err.contains("only valid with audit"));
    }

    #[test]
    fn parse_cli_doctor_rejects_global() {
        let err = parse_cli(&args("doctor --global")).unwrap_err();
        assert!(err.contains("only valid with install"));
    }

    #[test]
    fn parse_cli_doctor_rejects_config_flags() {
        let err = parse_cli(&args("doctor --config rules.toml")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }

    #[test]
    fn parse_cli_doctor_rejects_no_defaults() {
        let err = parse_cli(&args("doctor --no-defaults")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }

    #[test]
    fn parse_cli_doctor_rejects_entropy_threshold() {
        let err = parse_cli(&args("doctor --entropy-threshold 4.0")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }

    #[test]
    fn parse_cli_install_rejects_config_flags() {
        let err = parse_cli(&args("install pre-commit --config rules.toml")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }

    #[test]
    fn parse_cli_install_rejects_stopword() {
        let err = parse_cli(&args("install pre-commit --stopword foo")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }

    #[test]
    fn parse_cli_check_file_rejects_config_flags() {
        let err = parse_cli(&args("check-file --config rules.toml src/main.rs")).unwrap_err();
        assert!(err.contains("only valid with scan or audit"));
    }
}
