pub mod masking;

use crate::scanner::engine::Finding;
use masking::mask_secret;

/// format and print findings to stderr.
/// returns the total number of issues (env files + secret findings).
pub fn report_findings(findings: &[Finding], blocked_env_files: &[String]) -> usize {
    let total = findings.len() + blocked_env_files.len();
    if total == 0 {
        return 0;
    }

    eprintln!();
    eprintln!("[ERROR] secret detected in staged changes");
    eprintln!();

    for env_file in blocked_env_files {
        eprintln!("  file: {}", env_file);
        eprintln!("  line: -");
        eprintln!("  rule: env-file-blocked");
        eprintln!("  match: (blocked file type)");
        eprintln!();
    }

    for finding in findings {
        let masked = mask_secret(&finding.matched_value);
        eprintln!("  file: {}", finding.file);
        eprintln!("  line: {}", finding.line);
        eprintln!("  rule: {}", finding.rule_id);
        eprintln!("  match: {}", masked);
        eprintln!();
    }

    eprintln!(
        "commit blocked. {} secret(s) found.",
        total
    );
    eprintln!("use `git commit --no-verify` to bypass (not recommended).");
    eprintln!();

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::engine::Finding;

    #[test]
    fn report_no_findings() {
        let count = report_findings(&[], &[]);
        assert_eq!(count, 0);
    }

    #[test]
    fn report_env_files_only() {
        let env_files = vec![".env".to_string(), ".env.local".to_string()];
        let count = report_findings(&[], &env_files);
        assert_eq!(count, 2);
    }

    #[test]
    fn report_findings_only() {
        let findings = vec![
            Finding {
                file: "src/config.rs".to_string(),
                line: 42,
                rule_id: "aws-access-key-id".to_string(),
                matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
            },
        ];
        let count = report_findings(&findings, &[]);
        assert_eq!(count, 1);
    }

    #[test]
    fn report_mixed_findings() {
        let findings = vec![
            Finding {
                file: "src/config.rs".to_string(),
                line: 42,
                rule_id: "aws-access-key-id".to_string(),
                matched_value: b"AKIAIOSFODNN7ABCDEFG".to_vec(),
            },
            Finding {
                file: "src/app.js".to_string(),
                line: 10,
                rule_id: "github-personal-access-token".to_string(),
                matched_value: b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".to_vec(),
            },
        ];
        let env_files = vec![".env".to_string()];
        let count = report_findings(&findings, &env_files);
        assert_eq!(count, 3);
    }
}
