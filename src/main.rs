mod diff;
mod scanner;
mod config;
mod output;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
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

    // step 4: load rules (defaults + project overrides)
    let rules = match config::load_rules(None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] failed to load rules: {}", e);
            return 2;
        }
    };

    // step 5: load project config
    let project_config = match config::load_project_config(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] failed to load config: {}", e);
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

    // step 8: scan for secrets
    let findings = scanner::engine::scan(&files, &compiled, &allowlist);

    // step 9: report findings
    let total = output::report_findings(&findings, &env_check.blocked_files);

    if total > 0 {
        1
    } else {
        0
    }
}
