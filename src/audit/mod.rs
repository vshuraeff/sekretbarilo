// audit mode: scan all tracked files in working tree for secrets

pub mod history;

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use rayon::prelude::*;
use regex::RegexBuilder;

use crate::config::allowlist::CompiledAllowlist;
use crate::config::{AuditConfig, ProjectConfig};
use crate::diff::parser::{AddedLine, DiffFile};
use crate::output::masking::mask_secret;
use crate::scanner::engine::{scan, Finding};
use crate::scanner::rules::CompiledScanner;

/// options for the audit command
#[derive(Default)]
pub struct AuditOptions {
    /// scan full git history instead of working tree
    pub history: bool,
    /// limit to commits reachable from this branch
    pub branch: Option<String>,
    /// only commits after this date
    pub since: Option<String>,
    /// only commits before this date
    pub until: Option<String>,
    /// include untracked ignored files in audit
    pub include_ignored: bool,
}

/// list all tracked files via `git ls-files -z` (NUL-delimited for safe filename handling).
/// returns (files, skipped_count) where skipped_count is the number of non-UTF8 filenames.
pub fn list_tracked_files(repo_root: &Path) -> Result<(Vec<String>, usize), String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git ls-files failed: {}", stderr));
    }

    let mut files = Vec::new();
    let mut skipped = 0usize;
    for entry in output.stdout.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        match String::from_utf8(entry.to_vec()) {
            Ok(s) => files.push(s),
            Err(_) => {
                // non-UTF8 filename: cannot construct a valid path, skip with warning
                eprintln!(
                    "[WARN] skipping file with non-UTF8 name (byte length {})",
                    entry.len()
                );
                skipped += 1;
            }
        }
    }

    Ok((files, skipped))
}

/// list untracked ignored files via `git ls-files -z --others --ignored --exclude-standard`.
/// returns (files, skipped_count) where skipped_count is the number of non-UTF8 filenames.
pub fn list_ignored_files(repo_root: &Path) -> Result<(Vec<String>, usize), String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
        ])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files --ignored: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git ls-files --ignored failed: {}", stderr));
    }

    let mut files = Vec::new();
    let mut skipped = 0usize;
    for entry in output.stdout.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        match String::from_utf8(entry.to_vec()) {
            Ok(s) => files.push(s),
            Err(_) => {
                eprintln!(
                    "[WARN] skipping ignored file with non-UTF8 name (byte length {})",
                    entry.len()
                );
                skipped += 1;
            }
        }
    }

    Ok((files, skipped))
}

/// apply exclude and include pattern filters to a file list.
/// exclude_patterns remove matching files; include_patterns force-include matching files
/// (even if they were excluded). patterns are matched as regex against the full path.
pub fn apply_audit_filters(
    files: Vec<String>,
    audit_config: &AuditConfig,
) -> Result<Vec<String>, String> {
    let exclude_regexes = compile_patterns(&audit_config.exclude_patterns)?;
    let include_regexes = compile_patterns(&audit_config.include_patterns)?;

    if exclude_regexes.is_empty() && include_regexes.is_empty() {
        return Ok(files);
    }

    let filtered = files
        .into_iter()
        .filter(|path| {
            let excluded = exclude_regexes.iter().any(|re| re.is_match(path));
            if excluded {
                // check if force-included
                include_regexes.iter().any(|re| re.is_match(path))
            } else {
                true
            }
        })
        .collect();

    Ok(filtered)
}

/// compile a list of pattern strings into regexes with size limit to prevent ReDoS
pub(crate) fn compile_patterns(patterns: &[String]) -> Result<Vec<regex::Regex>, String> {
    patterns
        .iter()
        .map(|p| {
            RegexBuilder::new(p)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("invalid audit pattern '{}': {}", p, e))
        })
        .collect()
}

/// read a file and convert it into a DiffFile where every line is treated as "added".
/// returns None if the file cannot be read (e.g. binary, missing).
/// if `error_count` is provided, increments it on read errors.
pub fn read_file_to_diff(
    path: &str,
    repo_root: &Path,
    error_count: Option<&std::sync::atomic::AtomicUsize>,
) -> Option<DiffFile> {
    let full_path = repo_root.join(path);
    let content = match std::fs::read(&full_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[WARN] failed to read {}: {} (skipping)", path, e);
            if let Some(counter) = error_count {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return None;
        }
    };

    // skip binary files (check for null bytes in first 8KB)
    let check_len = content.len().min(8192);
    if content[..check_len].contains(&0) {
        return None;
    }

    let added_lines: Vec<AddedLine> = content
        .split(|&b| b == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(i, line)| {
            // strip trailing \r from windows-style line endings
            let line = if line.last() == Some(&b'\r') {
                &line[..line.len() - 1]
            } else {
                line
            };
            AddedLine {
                line_number: i + 1,
                content: line.to_vec(),
            }
        })
        .collect();

    Some(DiffFile {
        path: path.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines,
    })
}

/// report audit findings to stderr.
/// returns the total number of findings.
pub fn report_audit_findings(
    findings: &[Finding],
    file_count: usize,
    error_count: usize,
) -> usize {
    let total = findings.len();
    let error_suffix = if error_count > 0 {
        format!(" ({} file(s) skipped or unreadable)", error_count)
    } else {
        String::new()
    };

    if total == 0 {
        eprintln!(
            "[AUDIT] audit complete. scanned {} file(s), 0 secret(s) found.{}",
            file_count, error_suffix
        );
        return 0;
    }

    eprintln!();
    eprintln!("[AUDIT] secret(s) detected in tracked files");
    eprintln!();

    for finding in findings {
        let masked = mask_secret(&finding.matched_value);
        eprintln!("  file: {}", finding.file);
        eprintln!("  line: {}", finding.line);
        eprintln!("  rule: {}", finding.rule_id);
        eprintln!("  match: {}", masked);
        eprintln!();
    }

    let affected_files: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.file.as_str()).collect();
    eprintln!(
        "[AUDIT] audit complete. scanned {} file(s), {} secret(s) in {} file(s).{}",
        file_count,
        total,
        affected_files.len(),
        error_suffix
    );
    eprintln!();

    total
}

/// validate that filter flags are only used with --history.
/// returns an error message if filters are used without --history.
pub fn validate_filter_options(options: &AuditOptions) -> Result<(), String> {
    if !options.history {
        if options.branch.is_some() {
            return Err("branch filter requires --history".to_string());
        }
        if options.since.is_some() {
            return Err("date filter requires --history".to_string());
        }
        if options.until.is_some() {
            return Err("date filter requires --history".to_string());
        }
    }
    Ok(())
}

/// run the audit: scan all tracked files in the working tree, or history if --history is set.
/// accepts pre-loaded config, scanner, and allowlist from the caller.
/// returns exit code: 0 = clean, 1 = secrets found, 2 = internal error.
pub fn run_audit(
    repo_root: &Path,
    options: &AuditOptions,
    project_config: &ProjectConfig,
    compiled: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> i32 {
    // step 0: validate filter options
    if let Err(e) = validate_filter_options(options) {
        eprintln!("[ERROR] {}", e);
        return 2;
    }

    // history mode: delegate to history scanner
    if options.history {
        return history::run_history_audit(
            repo_root,
            options,
            compiled,
            allowlist,
            &project_config.audit,
        );
    }

    // working-tree mode below
    let mut skipped_files = 0usize;
    let mut enumeration_errors = 0usize;

    // step 2: list tracked files
    let mut file_paths = match list_tracked_files(repo_root) {
        Ok((files, skipped)) => {
            skipped_files += skipped;
            files
        }
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    // step 3: include ignored files if requested (CLI flag or config)
    let include_ignored =
        options.include_ignored || project_config.audit.include_ignored.unwrap_or(false);
    if include_ignored {
        match list_ignored_files(repo_root) {
            Ok((ignored, skipped)) => {
                skipped_files += skipped;
                let existing: HashSet<String> = file_paths.iter().cloned().collect();
                for f in ignored {
                    if !existing.contains(&f) {
                        file_paths.push(f);
                    }
                }
            }
            Err(e) => {
                eprintln!("[WARN] failed to list ignored files: {}", e);
                enumeration_errors += 1;
            }
        }
    }

    // step 4: apply exclude/include pattern filters from config
    let file_paths = match apply_audit_filters(file_paths, &project_config.audit) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    if file_paths.is_empty() {
        if skipped_files > 0 || enumeration_errors > 0 {
            eprintln!(
                "[AUDIT] audit complete. 0 scannable file(s) ({} skipped, {} enumeration error(s)).",
                skipped_files, enumeration_errors
            );
            return 2;
        }
        eprintln!("[AUDIT] audit complete. 0 secret(s) found across 0 file(s).");
        return 0;
    }

    // step 5: read files and convert to DiffFile structs
    let (diff_files, read_errors) = read_tracked_files(&file_paths, repo_root);
    let total_errors = read_errors + skipped_files + enumeration_errors;
    let file_count = diff_files.len();

    // step 6: scan
    let findings = scan(&diff_files, compiled, allowlist);

    // step 7: report
    let total = report_audit_findings(&findings, file_count, total_errors);

    if total > 0 {
        1
    } else if total_errors > 0 {
        // incomplete scan: some files unreadable/skipped, cannot guarantee clean
        2
    } else {
        0
    }
}

/// read tracked files in parallel and convert to DiffFile structs.
/// returns (diff_files, error_count).
fn read_tracked_files(
    file_paths: &[String],
    repo_root: &Path,
) -> (Vec<DiffFile>, usize) {
    let error_count = std::sync::atomic::AtomicUsize::new(0);
    let files: Vec<DiffFile> = file_paths
        .par_iter()
        .filter_map(|p| read_file_to_diff(p, repo_root, Some(&error_count)))
        .collect();
    let errors = error_count.load(std::sync::atomic::Ordering::Relaxed);
    (files, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_file_to_diff_basic() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "line one\nline two\nline three\n").unwrap();

        let diff = read_file_to_diff("test.txt", dir.path(), None).unwrap();
        assert_eq!(diff.path, "test.txt");
        assert!(!diff.is_binary);
        assert_eq!(diff.added_lines.len(), 3);
        assert_eq!(diff.added_lines[0].line_number, 1);
        assert_eq!(diff.added_lines[0].content, b"line one");
        assert_eq!(diff.added_lines[1].line_number, 2);
        assert_eq!(diff.added_lines[2].line_number, 3);
    }

    #[test]
    fn read_file_to_diff_binary() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("binary.bin");
        let content = vec![0u8; 100];
        std::fs::write(&file_path, &content).unwrap();

        let result = read_file_to_diff("binary.bin", dir.path(), None);
        assert!(result.is_none());
    }

    #[test]
    fn read_file_to_diff_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_file_to_diff("nonexistent.txt", dir.path(), None);
        assert!(result.is_none());
    }

    #[test]
    fn audit_options_default() {
        let opts = AuditOptions::default();
        assert!(!opts.history);
        assert!(opts.branch.is_none());
        assert!(opts.since.is_none());
        assert!(opts.until.is_none());
        assert!(!opts.include_ignored);
    }

    #[test]
    fn report_audit_findings_empty() {
        let count = report_audit_findings(&[], 5, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn report_audit_findings_with_secrets() {
        let findings = vec![
            Finding {
                file: "config.py".to_string(),
                line: 10,
                rule_id: "aws-access-key-id".to_string(),
                matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
            },
        ];
        let count = report_audit_findings(&findings, 3, 0);
        assert_eq!(count, 1);
    }

    #[test]
    fn audit_config_default_excludes_ignored() {
        // default AuditConfig has include_ignored = None (treated as false)
        let config = AuditConfig::default();
        assert!(config.include_ignored.is_none());
        assert!(config.exclude_patterns.is_empty());
        assert!(config.include_patterns.is_empty());
    }

    #[test]
    fn apply_audit_filters_no_patterns() {
        let files = vec![
            "src/main.rs".to_string(),
            "vendor/lib.js".to_string(),
            "test/data.txt".to_string(),
        ];
        let config = AuditConfig::default();
        let result = apply_audit_filters(files.clone(), &config).unwrap();
        assert_eq!(result, files);
    }

    #[test]
    fn apply_audit_filters_exclude_patterns() {
        let files = vec![
            "src/main.rs".to_string(),
            "vendor/lib.js".to_string(),
            "vendor/other.js".to_string(),
            "test/data.txt".to_string(),
        ];
        let config = AuditConfig {
            exclude_patterns: vec!["^vendor/".to_string()],
            ..Default::default()
        };
        let result = apply_audit_filters(files, &config).unwrap();
        assert_eq!(result, vec!["src/main.rs", "test/data.txt"]);
    }

    #[test]
    fn apply_audit_filters_include_patterns_override_exclude() {
        let files = vec![
            "src/main.rs".to_string(),
            "vendor/lib.js".to_string(),
            "vendor/important.rs".to_string(),
            "test/data.txt".to_string(),
        ];
        let config = AuditConfig {
            exclude_patterns: vec!["^vendor/".to_string()],
            include_patterns: vec![r"\.rs$".to_string()],
            ..Default::default()
        };
        let result = apply_audit_filters(files, &config).unwrap();
        // vendor/lib.js is excluded, but vendor/important.rs is force-included
        assert_eq!(
            result,
            vec!["src/main.rs", "vendor/important.rs", "test/data.txt"]
        );
    }

    #[test]
    fn apply_audit_filters_invalid_pattern() {
        let files = vec!["src/main.rs".to_string()];
        let config = AuditConfig {
            exclude_patterns: vec!["[invalid".to_string()],
            ..Default::default()
        };
        let result = apply_audit_filters(files, &config);
        assert!(result.is_err());
    }

    #[test]
    fn compile_patterns_valid() {
        let patterns = vec![r"^vendor/".to_string(), r"\.min\.js$".to_string()];
        let result = compile_patterns(&patterns);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn compile_patterns_empty() {
        let result = compile_patterns(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_filter_options_history_with_branch_ok() {
        let opts = AuditOptions {
            history: true,
            branch: Some("main".to_string()),
            ..Default::default()
        };
        assert!(validate_filter_options(&opts).is_ok());
    }

    #[test]
    fn validate_filter_options_history_with_dates_ok() {
        let opts = AuditOptions {
            history: true,
            since: Some("2024-01-01".to_string()),
            until: Some("2024-12-31".to_string()),
            ..Default::default()
        };
        assert!(validate_filter_options(&opts).is_ok());
    }

    #[test]
    fn validate_filter_options_branch_without_history() {
        let opts = AuditOptions {
            history: false,
            branch: Some("main".to_string()),
            ..Default::default()
        };
        let err = validate_filter_options(&opts).unwrap_err();
        assert!(err.contains("branch filter requires --history"));
    }

    #[test]
    fn validate_filter_options_since_without_history() {
        let opts = AuditOptions {
            history: false,
            since: Some("2024-01-01".to_string()),
            ..Default::default()
        };
        let err = validate_filter_options(&opts).unwrap_err();
        assert!(err.contains("date filter requires --history"));
    }

    #[test]
    fn validate_filter_options_until_without_history() {
        let opts = AuditOptions {
            history: false,
            until: Some("2024-12-31".to_string()),
            ..Default::default()
        };
        let err = validate_filter_options(&opts).unwrap_err();
        assert!(err.contains("date filter requires --history"));
    }

    #[test]
    fn validate_filter_options_no_filters_ok() {
        let opts = AuditOptions::default();
        assert!(validate_filter_options(&opts).is_ok());
    }
}
