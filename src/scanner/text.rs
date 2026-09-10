use std::collections::BTreeMap;
use std::ops::Range;

use crate::config::allowlist::CompiledAllowlist;
use crate::scanner::engine::{MatchContext, scan_matches};
use crate::scanner::rules::CompiledScanner;

/// a detected value's byte range in the original UTF-8 text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMatch {
    pub range: Range<usize>,
    pub rule_id: String,
}

/// scan complete text with value exclusions and without path or documentation exceptions.
/// scans lines and the complete field to preserve line anchors and multiline patterns.
/// ranges are deduplicated, sorted, and contain whole UTF-8 characters.
pub fn scan_text(
    text: &str,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<TextMatch> {
    let mut line_starts = vec![0];
    line_starts.extend(
        text.bytes()
            .enumerate()
            .filter_map(|(index, byte)| (byte == b'\n' || byte == b'\r').then_some(index + 1)),
    );
    let blocks = key_blocks(text);
    let public_ranges = if allowlist.detect_public_keys {
        Vec::new()
    } else {
        merge_ranges(
            blocks
                .iter()
                .filter(|block| block.public && block.terminated)
                .map(|block| block.header.start..block.end)
                .collect(),
        )
    };
    let ctx = MatchContext {
        file_path: None,
        input: text.as_bytes(),
        line_starts: &line_starts,
        scanner,
        allowlist,
        is_doc_file: false,
        generic_rule_disabled: false,
    };
    let mut matches = Vec::new();
    let mut candidates = vec![false; scanner.rules.len()];
    let mut emit = |rule_id: &str, mut range: Range<usize>| {
        let public_index = public_ranges.partition_point(|public| public.start <= range.start);
        if public_index > 0 && range.end <= public_ranges[public_index - 1].end {
            return;
        }
        let captured_end = range.end;
        let first_block = blocks.partition_point(|block| block.header.start < range.start);
        for block in blocks[first_block..]
            .iter()
            .take_while(|block| block.header.start < captured_end)
        {
            if captured_end >= block.header.end && (!block.public || allowlist.detect_public_keys) {
                range.end = range.end.max(block.end);
            }
        }
        // byte regexes may capture a fragment of a UTF-8 character.
        while !text.is_char_boundary(range.start) {
            range.start -= 1;
        }
        while !text.is_char_boundary(range.end) {
            range.end += 1;
        }
        matches.push(TextMatch {
            range,
            rule_id: rule_id.to_string(),
        });
    };
    scan_matches(&ctx, &mut candidates, &mut emit);
    if line_starts.len() > 1 {
        let mut offset = 0;
        for line in text.split_inclusive(['\r', '\n']) {
            let content = line.trim_end_matches(['\r', '\n']);
            if !content.is_empty() {
                let line_ctx = MatchContext {
                    input: content.as_bytes(),
                    line_starts: &[],
                    generic_rule_disabled: false,
                    ..ctx
                };
                scan_matches(&line_ctx, &mut candidates, |rule_id, range| {
                    emit(rule_id, offset + range.start..offset + range.end);
                });
            }
            offset += line.len();
        }
    }
    matches.sort_by(|a, b| {
        a.range
            .start
            .cmp(&b.range.start)
            .then(a.range.end.cmp(&b.range.end))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    matches.dedup();
    matches
}

/// replace detected values in memory, retaining every original CR and LF byte.
/// overlapping matches produce one replacement; multiline values retain their line breaks.
pub fn redact_text(text: &str, scanner: &CompiledScanner, allowlist: &CompiledAllowlist) -> String {
    let ranges = merge_ranges(
        scan_text(text, scanner, allowlist)
            .into_iter()
            .map(|found| found.range)
            .collect(),
    );
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;
    for range in ranges {
        redacted.push_str(&text[cursor..range.start]);
        redacted.push_str("[REDACTED]");
        for byte in text.as_bytes()[range.clone()].iter().copied() {
            if byte == b'\r' || byte == b'\n' {
                redacted.push(char::from(byte));
            }
        }
        cursor = range.end;
    }
    redacted.push_str(&text[cursor..]);
    redacted
}

fn merge_ranges(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start < previous.end
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

struct KeyBlock {
    header: Range<usize>,
    end: usize,
    public: bool,
    terminated: bool,
}

fn key_blocks(text: &str) -> Vec<KeyBlock> {
    let mut headers = Vec::new();
    let mut footers: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (start, _) in text.match_indices("-----") {
        let marker = &text[start + 5..];
        let (label_start, header) = if marker.starts_with("BEGIN") {
            (5, true)
        } else if marker.starts_with("END") {
            (3, false)
        } else {
            continue;
        };
        let rest = &marker[label_start..];
        let label_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_uppercase() || *byte == b' ')
            .count();
        let label = &rest[..label_len];
        if !rest[label_len..].starts_with("-----") {
            continue;
        }
        let public = label.ends_with("PUBLIC KEY") || label.ends_with("PUBLIC KEY BLOCK");
        if !public && !label.ends_with("PRIVATE KEY") && !label.ends_with("PRIVATE KEY BLOCK") {
            continue;
        }
        let end = start + 5 + label_start + label_len + 5;
        if header {
            headers.push((start..end, label, public));
        } else {
            footers.entry(label).or_default().push(end);
        }
    }
    headers
        .into_iter()
        .map(|(header, label, public)| {
            let footer = footers.get(label).and_then(|ends| {
                let index = ends.partition_point(|&end| end <= header.end);
                ends.get(index).copied()
            });
            KeyBlock {
                header,
                end: footer.unwrap_or(text.len()),
                public,
                terminated: footer.is_some(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::scanner::rules::{compile_rules, load_default_rules};

    #[test]
    fn entropy_redaction_preserves_controls_quotes_fields_and_line_endings() {
        let rules = load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let allowlist = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();
        let token: String = (b'A'..=b'Z').chain(b'a'..=b'f').map(char::from).collect();
        let controls = "GREETING=hello world\r\nNUMBER=12345\rPATHLIKE=/usr/local/bin/tooling\nWORD=configuration\n";
        let input = format!(
            "{controls}ALPHA={token}\r\n\t'{token}' \r{{\"key\\\" with space\":\"{token}\\\"suffix\",\"next\":\"{token}\"}}\n"
        );
        let expected = format!(
            "{controls}ALPHA=[REDACTED]\r\n\t'[REDACTED]' \r{{\"key\\\" with space\":\"[REDACTED]\",\"next\":\"[REDACTED]\"}}\n"
        );
        assert_eq!(redact_text(&input, &scanner, &allowlist), expected);
        let matches = scan_text(&input, &scanner, &allowlist);
        assert_eq!(matches.len(), 4);
        assert!(
            matches
                .iter()
                .all(|found| found.rule_id == "generic-high-entropy-value")
        );
    }
}
