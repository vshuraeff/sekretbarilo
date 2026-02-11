// git history scanning: scan all commits for secrets without checkout

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

use regex::Regex;

use crate::config::allowlist::CompiledAllowlist;
use crate::config::AuditConfig;
use crate::diff::parser::{parse_diff, DiffFile};
use crate::output::masking::mask_secret;
use crate::scanner::engine::{scan, Finding};
use crate::scanner::rules::CompiledScanner;

use super::AuditOptions;

/// strip control characters and unicode bidi overrides from a string
/// to prevent terminal injection via malicious git author/email/branch/file fields.
fn sanitize_display(s: &str) -> String {
    s.chars()
        .filter(|&c| c >= ' ' || c == '\t')
        .filter(|&c| c != '\x7f')
        .filter(|&c| {
            !matches!(c,
                '\u{200E}'..='\u{200F}' | // LTR/RTL marks
                '\u{202A}'..='\u{202E}' | // bidi overrides
                '\u{2066}'..='\u{2069}'   // bidi isolates
            )
        })
        .collect()
}

/// metadata about a single git commit
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub email: String,
    pub date: String,
    /// unix timestamp for correct chronological ordering
    pub timestamp: i64,
}

/// a finding annotated with commit metadata
#[derive(Debug, Clone)]
pub struct HistoryFinding {
    pub finding: Finding,
    pub commit: CommitInfo,
}

/// validate that a branch exists in the repository.
/// uses `git rev-parse --verify refs/heads/<branch>` to prevent flag injection.
pub fn validate_branch(branch: &str, repo_root: &Path) -> Result<(), String> {
    // reject path traversal and other unsafe ref components
    if branch.contains("..") || branch.starts_with('/') || branch.starts_with('-') {
        return Err(format!(
            "invalid branch name '{}'. branch names cannot contain '..' or start with '/' or '-'.",
            branch
        ));
    }
    let ref_name = format!("refs/heads/{}", branch);
    let output = Command::new("git")
        .args(["rev-parse", "--verify", &ref_name])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to verify branch: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "branch '{}' does not exist. check the name and try again.",
            branch
        ));
    }
    Ok(())
}

/// validate a date string for use with git rev-list --since/--until.
/// rejects empty strings and control characters; lets git validate the actual format.
pub fn validate_date_format(date: &str) -> Result<(), String> {
    if date.is_empty() {
        return Err("date cannot be empty.".to_string());
    }
    if date.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "invalid date '{}': contains control characters.",
            date
        ));
    }
    Ok(())
}

/// resolve which branches contain each of the given commit hashes.
/// returns a map from commit hash to a sorted list of branch names.
/// only queries branches for the provided hashes (intended for deduped findings, not all commits).
pub fn get_branches_for_commits(
    hashes: &[String],
    repo_root: &Path,
) -> HashMap<String, Vec<String>> {
    hashes
        .par_iter()
        .map(|hash| {
            // skip hashes that don't look like hex (defense-in-depth)
            if !hash.bytes().all(|b| b.is_ascii_hexdigit()) || hash.is_empty() {
                return (hash.clone(), Vec::new());
            }
            let output = Command::new("git")
                .args(["branch", "--contains", hash, "--format=%(refname:short)"])
                .current_dir(repo_root)
                .output();

            let branches = match output {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let mut branches: Vec<String> = stdout
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    branches.sort();
                    branches
                }
                _ => {
                    // branch resolution is best-effort; warn and continue
                    eprintln!(
                        "[AUDIT] warning: could not resolve branches for commit {}",
                        hash
                    );
                    Vec::new()
                }
            };
            (hash.clone(), branches)
        })
        .collect()
}

/// list commits matching the audit options.
/// uses `git rev-list` with optional branch/date filters.
pub fn list_commits(repo_root: &Path, options: &AuditOptions) -> Result<Vec<CommitInfo>, String> {
    // validate filters before building the command
    if let Some(ref branch) = options.branch {
        validate_branch(branch, repo_root)?;
    }
    if let Some(ref since) = options.since {
        validate_date_format(since)?;
    }
    if let Some(ref until) = options.until {
        validate_date_format(until)?;
    }

    let mut args = vec!["rev-list".to_string()];

    if let Some(ref branch) = options.branch {
        args.push(format!("refs/heads/{}", branch));
    } else {
        args.push("--all".to_string());
    }

    if let Some(ref since) = options.since {
        args.push(format!("--since={}", since));
    }
    if let Some(ref until) = options.until {
        args.push(format!("--until={}", until));
    }

    // output format: hash, author, email, date, timestamp (one per line, 5 lines per commit)
    args.push("--format=%H%n%an%n%ae%n%aI%n%at".to_string());

    let output = Command::new("git")
        .args(&args)
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to run git rev-list: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git rev-list failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    let mut commits = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        // rev-list with --format outputs a "commit <hash>" header line before the format lines
        if line.starts_with("commit ") {
            i += 1;
            continue;
        }
        // expect 5 consecutive lines: hash, author, email, date, timestamp
        if i + 4 < lines.len() && !line.is_empty() {
            let hash = line.to_string();
            let author = lines[i + 1].to_string();
            let email = lines[i + 2].to_string();
            let date = lines[i + 3].to_string();
            let timestamp = lines[i + 4].trim().parse::<i64>().unwrap_or(0);
            commits.push(CommitInfo {
                hash,
                author,
                email,
                date,
                timestamp,
            });
            i += 5;
        } else {
            i += 1;
        }
    }

    Ok(commits)
}

/// list root commits (no parents) in the repository
fn list_root_commits(repo_root: &Path) -> Result<HashSet<String>, String> {
    let output = Command::new("git")
        .args(["rev-list", "--max-parents=0", "--all"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to list root commits: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git rev-list --max-parents=0 failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.trim().to_string())
        .collect())
}

/// get the diff for a single commit.
/// for root commits (no parent), uses --root flag.
pub fn get_commit_diff(
    hash: &str,
    is_root: bool,
    repo_root: &Path,
) -> Result<Vec<u8>, String> {
    let mut args = vec![
        "diff-tree".to_string(),
        "-p".to_string(),
        "--no-commit-id".to_string(),
        "-r".to_string(),
        "--unified=0".to_string(),
        "--diff-filter=d".to_string(),
        // -m splits merge commits into individual diffs against each parent,
        // ensuring secrets introduced during merge conflict resolution are detected
        "-m".to_string(),
    ];
    if is_root {
        args.push("--root".to_string());
    }
    args.push(hash.to_string());

    let output = Command::new("git")
        .args(&args)
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("failed to get diff for commit {}: {}", hash, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff-tree failed for {}: {}", hash, stderr));
    }

    Ok(output.stdout)
}

/// compiled audit path filters for history scanning
pub struct CompiledAuditFilters {
    exclude: Vec<Regex>,
    include: Vec<Regex>,
}

impl CompiledAuditFilters {
    /// compile audit config patterns into regex filters
    pub fn from_config(config: &AuditConfig) -> Result<Self, String> {
        Ok(Self {
            exclude: super::compile_patterns(&config.exclude_patterns)?,
            include: super::compile_patterns(&config.include_patterns)?,
        })
    }

    /// returns true if the path should be scanned (not excluded, or force-included)
    fn should_scan(&self, path: &str) -> bool {
        if self.exclude.is_empty() && self.include.is_empty() {
            return true;
        }
        let excluded = self.exclude.iter().any(|re| re.is_match(path));
        if excluded {
            self.include.iter().any(|re| re.is_match(path))
        } else {
            true
        }
    }
}

/// scan a single commit's diff for secrets.
/// increments `error_count` if the diff cannot be retrieved.
fn scan_commit(
    commit: &CommitInfo,
    is_root: bool,
    repo_root: &Path,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    audit_filters: &CompiledAuditFilters,
    error_count: &AtomicUsize,
) -> Vec<HistoryFinding> {
    let diff_bytes = match get_commit_diff(&commit.hash, is_root, repo_root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[WARN] {}", e);
            error_count.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
    };

    if diff_bytes.is_empty() {
        return Vec::new();
    }

    let diff_files: Vec<DiffFile> = parse_diff(&diff_bytes)
        .into_iter()
        .filter(|df| audit_filters.should_scan(&df.path))
        .collect();
    let findings = scan(&diff_files, scanner, allowlist);

    findings
        .into_iter()
        .map(|f| HistoryFinding {
            finding: f,
            commit: commit.clone(),
        })
        .collect()
}

/// deduplicate history findings: same rule + same file + same secret value
/// keeps the earliest commit by date (works correctly regardless of input order).
pub fn deduplicate_findings(findings: Vec<HistoryFinding>) -> Vec<HistoryFinding> {
    // key: (file, rule_id, matched_value) -> earliest finding
    let mut seen: HashMap<(String, String, Vec<u8>), HistoryFinding> = HashMap::new();

    for hf in findings {
        let key = (
            hf.finding.file.clone(),
            hf.finding.rule_id.clone(),
            hf.finding.matched_value.clone(),
        );
        seen.entry(key)
            .and_modify(|existing| {
                // keep the earlier commit by unix timestamp
                if hf.commit.timestamp < existing.commit.timestamp {
                    *existing = hf.clone();
                }
            })
            .or_insert(hf);
    }

    let mut result: Vec<HistoryFinding> = seen.into_values().collect();
    // sort by timestamp, then commit hash (for grouping), then file, then line
    result.sort_by(|a, b| {
        a.commit
            .timestamp
            .cmp(&b.commit.timestamp)
            .then(a.commit.hash.cmp(&b.commit.hash))
            .then(a.finding.file.cmp(&b.finding.file))
            .then(a.finding.line.cmp(&b.finding.line))
    });
    result
}

/// report history findings to stderr.
/// groups findings by commit, showing author email and branch containment.
/// `branch_map` maps commit hashes to the branches that contain them.
/// returns the total number of findings.
pub fn report_history_findings(
    findings: &[HistoryFinding],
    commit_count: usize,
    error_count: usize,
    branch_map: &HashMap<String, Vec<String>>,
) -> usize {
    write_history_findings(findings, commit_count, error_count, branch_map, &mut std::io::stderr())
}

/// write history findings to the given writer.
/// testable variant of `report_history_findings`.
pub(crate) fn write_history_findings(
    findings: &[HistoryFinding],
    commit_count: usize,
    error_count: usize,
    branch_map: &HashMap<String, Vec<String>>,
    out: &mut dyn std::io::Write,
) -> usize {
    let total = findings.len();
    let error_suffix = if error_count > 0 {
        format!(" ({} error(s))", error_count)
    } else {
        String::new()
    };

    if total == 0 {
        let _ = writeln!(
            out,
            "[AUDIT] scanned {} commit(s). 0 secret(s) found.{}",
            commit_count, error_suffix
        );
        return 0;
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "[AUDIT] secret(s) detected in git history");
    let _ = writeln!(out);

    // group by commit hash for readable output
    let mut current_hash = String::new();
    for hf in findings {
        if hf.commit.hash != current_hash {
            current_hash = hf.commit.hash.clone();
            let short_hash = if current_hash.len() >= 8 {
                &current_hash[..8]
            } else {
                &current_hash
            };
            let _ = writeln!(
                out,
                "  commit: {} ({} <{}>, {})",
                short_hash,
                sanitize_display(&hf.commit.author),
                sanitize_display(&hf.commit.email),
                sanitize_display(&hf.commit.date)
            );
            // show branch containment if available
            if let Some(branches) = branch_map.get(&current_hash) {
                if !branches.is_empty() {
                    let safe: Vec<String> =
                        branches.iter().map(|b| sanitize_display(b)).collect();
                    let _ = writeln!(out, "    branches: {}", safe.join(", "));
                }
            }
        }
        let masked = sanitize_display(&mask_secret(&hf.finding.matched_value));
        let _ = writeln!(out, "    file: {}", sanitize_display(&hf.finding.file));
        let _ = writeln!(out, "    line: {}", hf.finding.line);
        let _ = writeln!(out, "    rule: {}", sanitize_display(&hf.finding.rule_id));
        let _ = writeln!(out, "    match: {}", masked);
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "[AUDIT] scanned {} commit(s). {} secret(s) found.{}",
        commit_count, total, error_suffix
    );
    let _ = writeln!(out);

    total
}

/// run the history audit: scan all commits for secrets.
/// returns exit code: 0 = clean, 1 = secrets found, 2 = internal error.
pub fn run_history_audit(
    repo_root: &Path,
    options: &AuditOptions,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    audit_config: &AuditConfig,
) -> i32 {
    // step 1: compile audit path filters
    let audit_filters = match CompiledAuditFilters::from_config(audit_config) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] invalid audit filter pattern: {}", e);
            return 2;
        }
    };

    // step 2: list commits
    let commits = match list_commits(repo_root, options) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    if commits.is_empty() {
        eprintln!("[AUDIT] scanned 0 commit(s). 0 secret(s) found.");
        return 0;
    }

    let commit_count = commits.len();
    let error_count = AtomicUsize::new(0);

    // step 3: identify root commits for special handling.
    // this is required for correct scanning: without it, root commits produce empty diffs.
    let root_hashes = match list_root_commits(repo_root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return 2;
        }
    };

    // step 4: scan commits in parallel with progress reporting
    let progress = AtomicUsize::new(0);

    let all_findings: Vec<HistoryFinding> = commits
        .par_iter()
        .flat_map(|commit| {
            let is_root = root_hashes.contains(&commit.hash);
            let findings = scan_commit(
                commit,
                is_root,
                repo_root,
                scanner,
                allowlist,
                &audit_filters,
                &error_count,
            );

            let done = progress.fetch_add(1, Ordering::Relaxed) + 1;
            // report progress every 50 commits (approximate due to parallel execution)
            #[allow(clippy::manual_is_multiple_of)]
            if done % 50 == 0 {
                eprintln!(
                    "[AUDIT] scanned {}/{} commits...",
                    done, commit_count
                );
            }

            findings
        })
        .collect();

    let errors = error_count.load(Ordering::Relaxed);
    if errors > 0 {
        eprintln!(
            "[AUDIT] scanned {}/{} commits ({} error(s), see warnings above).",
            commit_count, commit_count, errors
        );
    } else {
        eprintln!(
            "[AUDIT] scanned {}/{} commits.",
            commit_count, commit_count
        );
    }

    // step 5: deduplicate
    let deduped = deduplicate_findings(all_findings);

    // step 6: resolve branches for commits that have findings
    let finding_hashes: Vec<String> = {
        let mut seen = HashSet::new();
        deduped
            .iter()
            .filter_map(|hf| {
                if seen.insert(hf.commit.hash.as_str()) {
                    Some(hf.commit.hash.clone())
                } else {
                    None
                }
            })
            .collect()
    };
    if !finding_hashes.is_empty() {
        eprintln!(
            "[AUDIT] resolving branches for {} commit(s)...",
            finding_hashes.len()
        );
    }
    let branch_map = get_branches_for_commits(&finding_hashes, repo_root);

    // step 7: report
    let total = report_history_findings(&deduped, commit_count, errors, &branch_map);

    if total > 0 {
        1
    } else if errors > 0 {
        // incomplete scan: some commits failed, cannot guarantee clean
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_info_fields() {
        let ci = CommitInfo {
            hash: "abc123".to_string(),
            author: "test user".to_string(),
            email: "test@example.com".to_string(),
            date: "2024-01-15T10:30:00+00:00".to_string(),
            timestamp: 1705312200,
        };
        assert_eq!(ci.hash, "abc123");
        assert_eq!(ci.author, "test user");
        assert_eq!(ci.email, "test@example.com");
        assert_eq!(ci.date, "2024-01-15T10:30:00+00:00");
        assert_eq!(ci.timestamp, 1705312200);
    }

    #[test]
    fn history_finding_wraps_finding() {
        let f = Finding {
            file: "config.py".to_string(),
            line: 10,
            rule_id: "aws-access-key-id".to_string(),
            matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
        };
        let ci = CommitInfo {
            hash: "abc123".to_string(),
            author: "test".to_string(),
            email: "test@test.com".to_string(),
            date: "2024-01-15".to_string(),
            timestamp: 1705276800,
        };
        let hf = HistoryFinding {
            finding: f.clone(),
            commit: ci.clone(),
        };
        assert_eq!(hf.finding.file, "config.py");
        assert_eq!(hf.commit.hash, "abc123");
    }

    #[test]
    fn deduplicate_keeps_earliest_commit() {
        let findings = vec![
            HistoryFinding {
                finding: Finding {
                    file: "config.py".to_string(),
                    line: 5,
                    rule_id: "aws-key".to_string(),
                    matched_value: b"AKIATEST".to_vec(),
                },
                commit: CommitInfo {
                    hash: "newer_commit".to_string(),
                    author: "dev".to_string(),
                    email: "dev@test.com".to_string(),
                    date: "2024-06-01".to_string(),
                    timestamp: 1717200000,
                },
            },
            HistoryFinding {
                finding: Finding {
                    file: "config.py".to_string(),
                    line: 5,
                    rule_id: "aws-key".to_string(),
                    matched_value: b"AKIATEST".to_vec(),
                },
                commit: CommitInfo {
                    hash: "older_commit".to_string(),
                    author: "dev".to_string(),
                    email: "dev@test.com".to_string(),
                    date: "2024-01-01".to_string(),
                    timestamp: 1704067200,
                },
            },
        ];

        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
        // should keep the older commit (last in input = earliest introducing commit)
        assert_eq!(deduped[0].commit.hash, "older_commit");
    }

    #[test]
    fn deduplicate_different_files_kept() {
        let findings = vec![
            HistoryFinding {
                finding: Finding {
                    file: "a.py".to_string(),
                    line: 1,
                    rule_id: "rule1".to_string(),
                    matched_value: b"secret".to_vec(),
                },
                commit: CommitInfo {
                    hash: "c1".to_string(),
                    author: "dev".to_string(),
                    email: "dev@test.com".to_string(),
                    date: "2024-01-01".to_string(),
                    timestamp: 1704067200,
                },
            },
            HistoryFinding {
                finding: Finding {
                    file: "b.py".to_string(),
                    line: 1,
                    rule_id: "rule1".to_string(),
                    matched_value: b"secret".to_vec(),
                },
                commit: CommitInfo {
                    hash: "c2".to_string(),
                    author: "dev".to_string(),
                    email: "dev@test.com".to_string(),
                    date: "2024-02-01".to_string(),
                    timestamp: 1706745600,
                },
            },
        ];

        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn deduplicate_empty_input() {
        let deduped = deduplicate_findings(Vec::new());
        assert!(deduped.is_empty());
    }

    #[test]
    fn report_history_findings_empty() {
        let branch_map = HashMap::new();
        let count = report_history_findings(&[], 10, 0, &branch_map);
        assert_eq!(count, 0);
    }

    #[test]
    fn report_history_findings_with_secrets() {
        let findings = vec![HistoryFinding {
            finding: Finding {
                file: "config.py".to_string(),
                line: 10,
                rule_id: "aws-key".to_string(),
                matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
            },
            commit: CommitInfo {
                hash: "abc12345def".to_string(),
                author: "dev".to_string(),
                email: "dev@test.com".to_string(),
                date: "2024-01-15".to_string(),
                timestamp: 1705276800,
            },
        }];
        let branch_map = HashMap::new();
        let count = report_history_findings(&findings, 5, 0, &branch_map);
        assert_eq!(count, 1);
    }

    #[test]
    fn validate_date_format_accepts_common_formats() {
        assert!(validate_date_format("2024-01-01").is_ok());
        assert!(validate_date_format("2024-01-01T12:00:00").is_ok());
        assert!(validate_date_format("2 weeks ago").is_ok());
        assert!(validate_date_format("yesterday").is_ok());
        assert!(validate_date_format("last week").is_ok());
        assert!(validate_date_format("Jan 15 2024").is_ok());
    }

    #[test]
    fn validate_date_format_rejects_empty_and_control_chars() {
        assert!(validate_date_format("").is_err());
        assert!(validate_date_format("2024\n-01-01").is_err());
        assert!(validate_date_format("date\x00here").is_err());
    }

    #[test]
    fn get_branches_for_commits_returns_branch_names() {
        // create a temp repo with two branches
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        Command::new("git")
            .args(["init"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(root)
            .output()
            .unwrap();

        // initial commit on main
        std::fs::write(root.join("readme.md"), "hello\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["branch", "-M", "main"])
            .current_dir(root)
            .output()
            .unwrap();

        // get the initial commit hash
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .unwrap();
        let init_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // create a feature branch with another commit
        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(root)
            .output()
            .unwrap();
        std::fs::write(root.join("feature.txt"), "feature\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "feature commit"])
            .current_dir(root)
            .output()
            .unwrap();
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .unwrap();
        let feature_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

        let branch_map =
            get_branches_for_commits(&[init_hash.clone(), feature_hash.clone()], root);

        // initial commit is on both main and feature
        let init_branches = branch_map.get(&init_hash).unwrap();
        assert!(init_branches.contains(&"main".to_string()));
        assert!(init_branches.contains(&"feature".to_string()));

        // feature commit is only on feature
        let feat_branches = branch_map.get(&feature_hash).unwrap();
        assert!(feat_branches.contains(&"feature".to_string()));
        assert!(!feat_branches.contains(&"main".to_string()));
    }

    #[test]
    fn report_history_findings_includes_email_and_branches() {
        let findings = vec![HistoryFinding {
            finding: Finding {
                file: "secret.py".to_string(),
                line: 3,
                rule_id: "aws-key".to_string(),
                matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
            },
            commit: CommitInfo {
                hash: "deadbeef12345678".to_string(),
                author: "Alice".to_string(),
                email: "alice@example.com".to_string(),
                date: "2024-03-01".to_string(),
                timestamp: 1709251200,
            },
        }];
        let mut branch_map = HashMap::new();
        branch_map.insert(
            "deadbeef12345678".to_string(),
            vec!["feature/auth".to_string(), "main".to_string()],
        );

        let mut buf = Vec::new();
        let count = write_history_findings(&findings, 1, 0, &branch_map, &mut buf);
        assert_eq!(count, 1);

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("alice@example.com"), "output should contain email");
        assert!(output.contains("Alice"), "output should contain author name");
        assert!(output.contains("branches: feature/auth, main"), "output should contain branches");
        assert!(output.contains("commit: deadbeef"), "output should contain short hash");
    }

    #[test]
    fn report_history_findings_skips_branches_when_empty() {
        let findings = vec![HistoryFinding {
            finding: Finding {
                file: "config.py".to_string(),
                line: 1,
                rule_id: "generic-secret".to_string(),
                matched_value: b"supersecret123".to_vec(),
            },
            commit: CommitInfo {
                hash: "cafebabe90abcdef".to_string(),
                author: "Bob".to_string(),
                email: "bob@test.com".to_string(),
                date: "2024-05-10".to_string(),
                timestamp: 1715299200,
            },
        }];
        // empty branch list for the commit
        let mut branch_map = HashMap::new();
        branch_map.insert("cafebabe90abcdef".to_string(), Vec::new());

        let mut buf = Vec::new();
        let count = write_history_findings(&findings, 1, 0, &branch_map, &mut buf);
        assert_eq!(count, 1);

        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("branches:"), "output should not contain branches line when empty");
        assert!(output.contains("bob@test.com"), "output should contain email");
    }
}
