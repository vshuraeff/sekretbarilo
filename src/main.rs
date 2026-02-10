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
    eprintln!("  sekretbarilo --help       show this help");
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
