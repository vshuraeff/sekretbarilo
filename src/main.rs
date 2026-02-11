mod audit;
mod diff;
mod scanner;
mod config;
mod output;
mod hook;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("install") => run_install(),
        Some("scan") | None => run_scan(),
        Some("audit") => run_audit(&args[2..]),
        Some("--help" | "-h") => {
            print_usage();
            0
        }
        Some(cmd) => {
            eprintln!("[ERROR] unknown command: {}", cmd);
            eprintln!();
            print_usage();
            2
        }
    }
}

fn print_usage() {
    eprintln!("sekretbarilo - git pre-commit secret scanner");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  sekretbarilo              scan staged changes (default)");
    eprintln!("  sekretbarilo scan         scan staged changes");
    eprintln!("  sekretbarilo install      install git pre-commit hook");
    eprintln!("  sekretbarilo audit        scan all tracked files in working tree");
    eprintln!("  sekretbarilo --help       show this help");
    eprintln!();
    eprintln!("audit flags:");
    eprintln!("  --history                 scan full git history (all commits)");
    eprintln!("  --branch <name>           limit to commits reachable from branch (requires --history)");
    eprintln!("  --since <date>            only commits after date (requires --history)");
    eprintln!("  --until <date>            only commits before date (requires --history)");
    eprintln!("  --include-ignored         include untracked ignored files");
    eprintln!();
    eprintln!("examples:");
    eprintln!("  sekretbarilo audit                                 scan working tree");
    eprintln!("  sekretbarilo audit --history                       scan all commits");
    eprintln!("  sekretbarilo audit --history --branch main         scan main branch history");
    eprintln!("  sekretbarilo audit --history --since 2024-01-01    scan commits after date");
    eprintln!("  sekretbarilo audit --history --branch main --since 2024-01-01 --until 2024-06-30");
    eprintln!("                                                     scan main branch in date range");
}

/// resolve the git repository root directory.
/// returns None if we can't determine it (non-fatal, falls back to defaults).
fn resolve_repo_root() -> Option<std::path::PathBuf> {
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
    Some(std::path::PathBuf::from(root))
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

fn run_scan() -> i32 {
    // exit codes: 0 = no secrets, 1 = secrets found, 2 = internal error

    // step 1: get the staged diff
    let raw_diff = match diff::get_staged_diff() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    // empty diff = nothing staged, all clear
    if raw_diff.is_empty() {
        return 0;
    }

    // step 2: parse diff into file blocks
    let files = diff::parser::parse_diff(&raw_diff);

    // step 3: check for blocked .env files
    let env_check = diff::check_env_files(&files);

    // resolve repo root for config loading
    let repo_root = resolve_repo_root();

    // step 4: load project config (once, reused for rules and allowlist)
    let project_config = match config::load_project_config(repo_root.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] failed to load config: {}", e);
            return 2;
        }
    };

    // step 5: load rules (defaults + project overrides)
    let rules = match config::load_rules_with_config(&project_config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] failed to load rules: {}", e);
            return 2;
        }
    };

    // step 6: compile the scanner
    let compiled = match scanner::rules::compile_rules(&rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ERROR] failed to compile rules: {}", e);
            return 2;
        }
    };

    // step 7: build the allowlist
    let allowlist = match config::build_allowlist(&project_config, &rules) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[ERROR] failed to build allowlist: {}", e);
            return 2;
        }
    };

    // step 8: scan for secrets (exclude .env blocked files to avoid duplicate findings)
    let scannable_files: Vec<_> = files
        .iter()
        .filter(|f| !env_check.blocked_files.contains(&f.path))
        .cloned()
        .collect();
    let findings = scanner::engine::scan(&scannable_files, &compiled, &allowlist);

    // step 9: report findings
    let total = output::report_findings(&findings, &env_check.blocked_files);

    if total > 0 {
        1
    } else {
        0
    }
}

fn run_audit(args: &[String]) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            eprintln!("[ERROR] not a git repository");
            return 2;
        }
    };

    let mut options = audit::AuditOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--history" => options.history = true,
            "--branch" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("[ERROR] --branch requires a value");
                    return 2;
                }
                options.branch = Some(args[i].clone());
            }
            "--since" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("[ERROR] --since requires a value");
                    return 2;
                }
                options.since = Some(args[i].clone());
            }
            "--until" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("[ERROR] --until requires a value");
                    return 2;
                }
                options.until = Some(args[i].clone());
            }
            "--include-ignored" => options.include_ignored = true,
            other => {
                eprintln!("[ERROR] unknown audit flag: {}", other);
                eprintln!();
                print_usage();
                return 2;
            }
        }
        i += 1;
    }

    audit::run_audit(&repo_root, &options)
}
