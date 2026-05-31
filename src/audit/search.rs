// explicit search pass: scan lines for user-provided literal or regex patterns,
// independent of the secret-rule engine. produces distinct match records so
// reports can separate "user asked to find text" from "policy violation".

use std::collections::HashSet;
use std::io::Write;

use regex::Regex;

use super::history::sanitize_display;
use crate::diff::parser::DiffFile;

const SNIPPET_MAX_CHARS: usize = 200;

/// compiled set of user-search patterns. each entry carries the original
/// display string so reports can show what was searched for.
#[derive(Debug)]
pub struct SearchPatterns {
    compiled: Vec<(String, Regex)>,
}

/// a single hit from the user-search pass.
#[derive(Debug, Clone)]
pub struct SearchMatch {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub line_content: Vec<u8>,
}

impl SearchPatterns {
    /// compile literal (substring) and regex search patterns.
    /// literals are escaped before compilation so metacharacters are treated
    /// as plain text (`api.key` matches only `api.key`, not `apiXkey`).
    pub fn new(literals: &[String], regexes: &[String]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(literals.len() + regexes.len());
        for lit in literals {
            if lit.is_empty() {
                return Err("search literal cannot be empty".to_string());
            }
            let escaped = regex::escape(lit);
            let re = Regex::new(&escaped).map_err(|e| {
                sanitize_display(&format!("invalid literal search pattern '{}': {}", lit, e))
            })?;
            compiled.push((lit.clone(), re));
        }
        for pat in regexes {
            if pat.is_empty() {
                return Err("search regex cannot be empty".to_string());
            }
            let re = Regex::new(pat).map_err(|e| {
                sanitize_display(&format!("invalid regex search pattern '{}': {}", pat, e))
            })?;
            compiled.push((pat.clone(), re));
        }
        Ok(Self { compiled })
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }
}

/// run the user-search pass over added lines in each DiffFile.
/// records one match per matching pattern per line, so a line hit by
/// multiple patterns produces multiple records (every hit is shown).
pub fn run_search_pass(files: &[DiffFile], patterns: &SearchPatterns) -> Vec<SearchMatch> {
    let mut matches = Vec::new();
    if patterns.is_empty() {
        return matches;
    }
    for file in files {
        for line in &file.added_lines {
            let content = String::from_utf8_lossy(&line.content);
            for (display, re) in &patterns.compiled {
                if re.is_match(&content) {
                    matches.push(SearchMatch {
                        file: file.path.clone(),
                        line: line.line_number,
                        pattern: display.clone(),
                        line_content: line.content.clone(),
                    });
                }
            }
        }
    }
    matches
}

/// truncate control chars and oversize lines for terminal-safe display.
/// search hits are not masked; the user asked to find this text.
pub(crate) fn snippet_display(content: &[u8]) -> String {
    let s = String::from_utf8_lossy(content);
    // reuse the shared sanitizer so terminal-safety rules stay in one place
    let cleaned = sanitize_display(&s);
    let trimmed = cleaned.trim();
    if trimmed.chars().count() > SNIPPET_MAX_CHARS {
        let cut: String = trimmed.chars().take(SNIPPET_MAX_CHARS).collect();
        format!("{}…", cut)
    } else {
        trimmed.to_string()
    }
}

/// count distinct files across search matches.
fn distinct_files(matches: &[SearchMatch]) -> usize {
    let mut set = HashSet::new();
    for m in matches {
        set.insert(m.file.as_str());
    }
    set.len()
}

/// report working-tree search matches to stderr. returns the match count.
pub fn report_search_matches(matches: &[SearchMatch], scanned_file_count: usize) -> usize {
    write_search_matches(matches, scanned_file_count, &mut std::io::stderr())
}

/// testable variant of `report_search_matches`.
pub(crate) fn write_search_matches(
    matches: &[SearchMatch],
    scanned_file_count: usize,
    out: &mut dyn Write,
) -> usize {
    let total = matches.len();
    if total == 0 {
        let _ = writeln!(
            out,
            "[SEARCH] scanned {} file(s). 0 match(es).",
            scanned_file_count
        );
        return 0;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "[SEARCH] user-search match(es) found");
    let _ = writeln!(out);
    for m in matches {
        let _ = writeln!(out, "  file: {}", sanitize_display(&m.file));
        let _ = writeln!(out, "  line: {}", m.line);
        let _ = writeln!(out, "  pattern: {}", sanitize_display(&m.pattern));
        let _ = writeln!(out, "  match: {}", snippet_display(&m.line_content));
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "[SEARCH] {} match(es) in {} file(s) across {} scanned file(s).",
        total,
        distinct_files(matches),
        scanned_file_count
    );
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parser::{AddedLine, DiffFile};

    fn df(path: &str, lines: &[(usize, &str)]) -> DiffFile {
        DiffFile {
            path: path.to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: lines
                .iter()
                .map(|(n, s)| AddedLine {
                    line_number: *n,
                    content: s.as_bytes().to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn search_patterns_empty_by_default() {
        let p = SearchPatterns::new(&[], &[]).unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn search_patterns_literal_compiles() {
        let p = SearchPatterns::new(&["foo".to_string()], &[]).unwrap();
        assert!(!p.is_empty());
    }

    #[test]
    fn search_patterns_regex_compiles() {
        let p = SearchPatterns::new(&[], &[r"api.*key".to_string()]).unwrap();
        assert!(!p.is_empty());
    }

    #[test]
    fn search_patterns_invalid_regex_errors() {
        let err = SearchPatterns::new(&[], &["[invalid".to_string()]).unwrap_err();
        assert!(err.contains("invalid regex search pattern"));
    }

    #[test]
    fn search_patterns_empty_literal_errors() {
        let err = SearchPatterns::new(&["".to_string()], &[]).unwrap_err();
        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn run_search_pass_finds_literal() {
        let files = [df("a.rs", &[(1, "let foo = 1;"), (2, "bar()")])];
        let p = SearchPatterns::new(&["foo".to_string()], &[]).unwrap();
        let m = run_search_pass(&files, &p);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].file, "a.rs");
        assert_eq!(m[0].line, 1);
        assert_eq!(m[0].pattern, "foo");
    }

    #[test]
    fn run_search_pass_literal_does_not_expand_metachars() {
        // `api.key` must match literal dot, not any char
        let files = [df(
            "a.rs",
            &[(1, "api.key=abc"), (2, "apiXkey=xyz"), (3, "apikey=zzz")],
        )];
        let p = SearchPatterns::new(&["api.key".to_string()], &[]).unwrap();
        let m = run_search_pass(&files, &p);
        assert_eq!(m.len(), 1, "only literal 'api.key' should match");
        assert_eq!(m[0].line, 1);
    }

    #[test]
    fn run_search_pass_regex_matches() {
        let files = [df(
            "a.rs",
            &[(1, "apikey=1"), (2, "api_xxx_key=2"), (3, "nope")],
        )];
        let p = SearchPatterns::new(&[], &[r"api.*key".to_string()]).unwrap();
        let m = run_search_pass(&files, &p);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].line, 1);
        assert_eq!(m[1].line, 2);
    }

    #[test]
    fn run_search_pass_regex_case_sensitive_by_default() {
        // user must opt into case-insensitive with (?i) inline flag
        let files = [df("a.rs", &[(1, "ApiKey=1"), (2, "apikey=2")])];
        let p_sensitive = SearchPatterns::new(&[], &[r"apikey".to_string()]).unwrap();
        let m = run_search_pass(&files, &p_sensitive);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].line, 2);

        let p_insensitive = SearchPatterns::new(&[], &[r"(?i)apikey".to_string()]).unwrap();
        let m = run_search_pass(&files, &p_insensitive);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn run_search_pass_no_match_returns_empty() {
        let files = [df("a.rs", &[(1, "nothing here")])];
        let p = SearchPatterns::new(&["missing".to_string()], &[]).unwrap();
        assert!(run_search_pass(&files, &p).is_empty());
    }

    #[test]
    fn run_search_pass_no_patterns_returns_empty() {
        let files = [df("a.rs", &[(1, "anything")])];
        let p = SearchPatterns::new(&[], &[]).unwrap();
        assert!(run_search_pass(&files, &p).is_empty());
    }

    #[test]
    fn run_search_pass_multiple_patterns_same_line() {
        let files = [df("a.rs", &[(1, "foo and bar together")])];
        let p = SearchPatterns::new(&["foo".to_string(), "bar".to_string()], &[]).unwrap();
        let m = run_search_pass(&files, &p);
        assert_eq!(m.len(), 2, "both patterns should record on same line");
    }

    #[test]
    fn write_search_matches_empty() {
        let mut buf = Vec::new();
        let n = write_search_matches(&[], 10, &mut buf);
        assert_eq!(n, 0);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("scanned 10 file(s)"));
        assert!(out.contains("0 match(es)"));
    }

    #[test]
    fn write_search_matches_lists_hits() {
        let matches = vec![
            SearchMatch {
                file: "src/a.rs".to_string(),
                line: 4,
                pattern: "foo".to_string(),
                line_content: b"let foo = 1;".to_vec(),
            },
            SearchMatch {
                file: "src/b.rs".to_string(),
                line: 9,
                pattern: "foo".to_string(),
                line_content: b"foo();".to_vec(),
            },
        ];
        let mut buf = Vec::new();
        let n = write_search_matches(&matches, 42, &mut buf);
        assert_eq!(n, 2);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("src/a.rs"));
        assert!(out.contains("line: 4"));
        assert!(out.contains("pattern: foo"));
        assert!(out.contains("let foo = 1;"));
        assert!(out.contains("[SEARCH] 2 match(es) in 2 file(s)"));
    }

    #[test]
    fn snippet_display_truncates_oversize_and_strips_controls() {
        let long = "x".repeat(500);
        let s = snippet_display(long.as_bytes());
        assert!(s.chars().count() <= SNIPPET_MAX_CHARS + 1); // +1 for ellipsis
        assert!(s.ends_with('…'));

        let with_ctrl = b"hello\x07\x00world".to_vec();
        let s = snippet_display(&with_ctrl);
        // invalid utf8 survives via String::from_utf8_lossy; bell (0x07) is below ' ' so stripped
        assert!(!s.contains('\x07'));

        // bidi override + isolate chars are stripped (terminal spoofing guard)
        let with_bidi = "a\u{202E}b\u{2066}c".as_bytes().to_vec();
        let s = snippet_display(&with_bidi);
        assert!(!s.contains('\u{202E}'));
        assert!(!s.contains('\u{2066}'));
        assert_eq!(s, "abc");

        // c1 control (csi u+009b) and zero-width chars are stripped
        let with_c1 = "x\u{009B}2Jy\u{200B}z".as_bytes().to_vec();
        let s = snippet_display(&with_c1);
        assert!(!s.contains('\u{009B}'));
        assert!(!s.contains('\u{200B}'));
        assert_eq!(s, "x2Jyz");
    }

    #[test]
    fn run_search_pass_preserves_line_numbers() {
        let files = [df(
            "x.rs",
            &[(10, "unrelated"), (42, "target line"), (100, "other")],
        )];
        let p = SearchPatterns::new(&["target".to_string()], &[]).unwrap();
        let m = run_search_pass(&files, &p);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].line, 42);
    }
}
