use crate::diff::parser::{AddedLine, DiffFile};

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ENVIRONMENT_ID: &str = "*** Environment ID: ";
const ADD_FILE: &str = "*** Add File: ";
const DELETE_FILE: &str = "*** Delete File: ";
const UPDATE_FILE: &str = "*** Update File: ";
const MOVE_TO: &str = "*** Move to: ";
const END_OF_FILE: &str = "*** End of File";

/// A scannable file extracted from an `apply_patch` hunk.
///
/// `DiffFile::added_lines` contains only added content. Its `line_number`
/// values are sequential, one-based ordinals among added lines in this patch
/// file block; they are neither patch-text nor on-disk file line numbers.
/// `original_path` is set only for update-and-move hunks.
#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub diff_file: DiffFile,
    pub original_path: Option<String>,
}

/// Parse the Codex `apply_patch` mini-format into scannable file blocks.
pub fn parse_apply_patch(input: &[u8]) -> Result<Vec<ParsedFile>, String> {
    let input = std::str::from_utf8(input)
        .map_err(|_| "apply_patch input is not valid UTF-8".to_string())?;
    let lines = split_lines(input);
    let lines = unwrap_heredoc(&lines)?;

    if lines.is_empty() || lines[0].trim() != BEGIN_PATCH {
        return Err("The first line of the patch must be '*** Begin Patch'".to_string());
    }

    let last_content = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .ok_or_else(|| "The last line of the patch must be '*** End Patch'".to_string())?;
    if lines[last_content].trim() != END_PATCH {
        return Err("The last line of the patch must be '*** End Patch'".to_string());
    }

    let mut files = Vec::new();
    let mut index = 1;
    let mut hunk_count = 0;

    if index < lines.len() {
        let trimmed = lines[index].trim();
        if let Some(environment_id) = trimmed.strip_prefix(ENVIRONMENT_ID) {
            if environment_id.trim().is_empty() {
                return Err("apply_patch environment ID cannot be empty".to_string());
            }
            index += 1;
        }
    }

    while index < lines.len() {
        let trimmed = lines[index].trim();

        if trimmed == END_PATCH {
            index += 1;
            break;
        }

        if let Some(path) = trimmed.strip_prefix(ADD_FILE) {
            hunk_count += 1;
            let (file, next) = parse_add_hunk(&lines, index + 1, path)?;
            files.push(file);
            index = next;
            continue;
        }

        if let Some(path) = trimmed.strip_prefix(DELETE_FILE) {
            if path.is_empty() {
                return Err(format!(
                    "delete-file hunk at line {} has an empty path",
                    index + 1
                ));
            }
            hunk_count += 1;
            index += 1;
            continue;
        }

        if let Some(path) = trimmed.strip_prefix(UPDATE_FILE) {
            hunk_count += 1;
            let (file, next) = parse_update_hunk(&lines, index + 1, path)?;
            files.push(file);
            index = next;
            continue;
        }

        return Err(format!(
            "invalid apply_patch hunk header at line {}",
            index + 1
        ));
    }

    if hunk_count == 0 {
        return Err("apply_patch must contain at least one file hunk".to_string());
    }

    for (offset, line) in lines[index..].iter().enumerate() {
        if !line.trim().is_empty() {
            return Err(format!(
                "unexpected content after '*** End Patch' at line {}",
                index + offset + 1
            ));
        }
    }

    Ok(files)
}

fn parse_add_hunk(
    lines: &[&str],
    mut index: usize,
    path: &str,
) -> Result<(ParsedFile, usize), String> {
    if path.is_empty() {
        return Err(format!("add-file hunk at line {} has an empty path", index));
    }

    let mut added_lines = Vec::new();
    while index < lines.len() {
        let line = lines[index];
        if let Some(content) = line.strip_prefix('+') {
            push_added_line(&mut added_lines, content);
            index += 1;
            continue;
        }

        if is_top_level_directive(line.trim()) {
            break;
        }

        return Err(format!(
            "add-file content at line {} must start with '+'",
            index + 1
        ));
    }

    Ok((
        ParsedFile {
            diff_file: DiffFile {
                path: path.to_string(),
                is_new: true,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                added_lines,
            },
            original_path: None,
        },
        index,
    ))
}

fn parse_update_hunk(
    lines: &[&str],
    mut index: usize,
    original_path: &str,
) -> Result<(ParsedFile, usize), String> {
    if original_path.is_empty() {
        return Err(format!(
            "update-file hunk at line {} has an empty path",
            index
        ));
    }

    let mut move_path = None;
    if index < lines.len() {
        let update_line = lines[index].trim_end();
        if let Some(path) = update_line.strip_prefix(MOVE_TO) {
            if path.is_empty() {
                return Err(format!(
                    "move-to directive at line {} has an empty path",
                    index + 1
                ));
            }
            move_path = Some(path.to_string());
            index += 1;
        }
    }

    let mut added_lines = Vec::new();
    let mut saw_change_line = false;
    let mut chunk_open = false;
    let mut chunk_has_lines = false;
    let mut after_end_of_file = false;

    while index < lines.len() {
        let line = lines[index];
        let update_line = line.trim_end();

        if is_update_terminating_directive(update_line) {
            break;
        }

        if after_end_of_file {
            if update_line.is_empty() {
                index += 1;
                continue;
            }
            // Upstream parity: after an end-of-file marker, the next non-empty line must be
            // an `@@` hunk marker, not extra strictness of our own.
            if update_line != "@@" && !update_line.starts_with("@@ ") {
                return Err(format!(
                    "expected update hunk to start with '@@' after end-of-file marker at line {}",
                    index + 1
                ));
            }
        }

        if update_line == "@@" || update_line.starts_with("@@ ") {
            if chunk_open && !chunk_has_lines {
                return Err(format!(
                    "update chunk at line {} does not contain any lines",
                    index + 1
                ));
            }
            chunk_open = true;
            chunk_has_lines = false;
            after_end_of_file = false;
            index += 1;
            continue;
        }

        if update_line == END_OF_FILE {
            if !chunk_open || !chunk_has_lines {
                return Err(format!(
                    "end-of-file marker at line {} has no preceding change lines",
                    index + 1
                ));
            }
            after_end_of_file = true;
            index += 1;
            continue;
        }

        // Upstream intentionally handles a wholly empty raw line before the
        // ordinary space-prefixed context branch.
        if line.is_empty() {
            chunk_open = true;
            chunk_has_lines = true;
            saw_change_line = true;
            index += 1;
            continue;
        }

        if line.strip_prefix(' ').is_some() || line.strip_prefix('-').is_some() {
            chunk_open = true;
            chunk_has_lines = true;
            saw_change_line = true;
            index += 1;
            continue;
        }

        if let Some(content) = line.strip_prefix('+') {
            chunk_open = true;
            chunk_has_lines = true;
            saw_change_line = true;
            push_added_line(&mut added_lines, content);
            index += 1;
            continue;
        }

        return Err(format!(
            "update-file content at line {} must start with ' ', '+', or '-'",
            index + 1
        ));
    }

    if !saw_change_line && move_path.is_none() {
        return Err("update-file hunk does not contain any change lines".to_string());
    }
    if chunk_open && !chunk_has_lines {
        return Err("update-file hunk ends with an empty change chunk".to_string());
    }

    let target_path = move_path.as_deref().unwrap_or(original_path).to_string();
    let original_path = move_path.as_ref().map(|_| original_path.to_string());

    Ok((
        ParsedFile {
            diff_file: DiffFile {
                path: target_path,
                is_new: false,
                is_deleted: false,
                is_renamed: original_path.is_some(),
                is_binary: false,
                added_lines,
            },
            original_path,
        },
        index,
    ))
}

fn push_added_line(added_lines: &mut Vec<AddedLine>, content: &str) {
    // This is an ordinal within added content for one file block, not a patch
    // text or on-disk file line number.
    added_lines.push(AddedLine {
        line_number: added_lines.len() + 1,
        content: content.as_bytes().to_vec(),
    });
}

fn split_lines(input: &str) -> Vec<&str> {
    input
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

fn is_top_level_directive(line: &str) -> bool {
    line == END_PATCH
        || line.starts_with(ADD_FILE)
        || line.starts_with(DELETE_FILE)
        || line.starts_with(UPDATE_FILE)
}

fn is_update_terminating_directive(line: &str) -> bool {
    is_top_level_directive(line)
}

fn unwrap_heredoc<'a>(lines: &'a [&'a str]) -> Result<Vec<&'a str>, String> {
    let Some(first) = lines.first() else {
        return Ok(lines.to_vec());
    };
    let Some((strip_leading_tabs, terminator)) = heredoc_terminator(first) else {
        return Ok(lines.to_vec());
    };

    let Some(closing_index) = lines[1..]
        .iter()
        .position(|line| {
            if strip_leading_tabs {
                line.trim_start_matches('\t') == terminator
            } else {
                *line == terminator
            }
        })
        .map(|offset| offset + 1)
    else {
        return Err(format!(
            "heredoc wrapper is missing closing terminator '{terminator}'"
        ));
    };

    if lines[closing_index + 1..]
        .iter()
        .any(|line| !line.trim().is_empty())
    {
        return Err("unexpected content after heredoc terminator".to_string());
    }

    if strip_leading_tabs {
        Ok(lines[1..closing_index]
            .iter()
            .map(|line| line.trim_start_matches('\t'))
            .collect())
    } else {
        Ok(lines[1..closing_index].to_vec())
    }
}

fn heredoc_terminator(line: &str) -> Option<(bool, &str)> {
    let marker = line.find("<<")?;
    let mut rest = &line[marker + 2..];
    let strip_leading_tabs = rest.starts_with('-');
    if let Some(after_dash) = rest.strip_prefix('-') {
        rest = after_dash;
    }

    let quote = match rest.as_bytes().first().copied() {
        Some(b'\'') | Some(b'"') => {
            let quote = rest.as_bytes()[0];
            rest = &rest[1..];
            Some(quote)
        }
        _ => None,
    };

    let word_end = rest
        .bytes()
        .position(|byte| {
            if let Some(quote) = quote {
                byte == quote
            } else {
                byte.is_ascii_whitespace()
            }
        })
        .unwrap_or(rest.len());
    let word = &rest[..word_end];
    if word.is_empty()
        || !word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }

    let trailing = &rest[word_end..];
    let trailing = if let Some(quote) = quote {
        trailing.strip_prefix(char::from(quote))?
    } else {
        trailing
    };
    heredoc_trailing_is_tolerable(trailing).then_some((strip_leading_tabs, word))
}

fn heredoc_trailing_is_tolerable(trailing: &str) -> bool {
    let trailing = trailing.trim();
    if trailing.is_empty() || trailing.starts_with('#') {
        return true;
    }

    const OUTPUT_REDIRECTIONS: [&str; 8] = ["&>>", "2>>", "1>>", ">>", "&>", "2>", "1>", ">"];
    let Some(after_operator) = OUTPUT_REDIRECTIONS
        .iter()
        .find_map(|operator| trailing.strip_prefix(operator))
    else {
        return false;
    };

    let target_and_trailing = after_operator.trim_start();
    let target_end = target_and_trailing
        .find(char::is_whitespace)
        .unwrap_or(target_and_trailing.len());
    let (target, trailing) = target_and_trailing.split_at(target_end);
    if target.is_empty()
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
    {
        return false;
    }

    let trailing = trailing.trim_start();
    trailing.is_empty() || trailing.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents(file: &ParsedFile) -> Vec<&[u8]> {
        file.diff_file
            .added_lines
            .iter()
            .map(|line| line.content.as_slice())
            .collect()
    }

    #[test]
    fn fixture_a_add_file() {
        let patch = b"*** Begin Patch\n*** Add File: config.py\n+DEBUG = True\n+PORT = 8080\n+HOST = \"0.0.0.0\"\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        let file = &files[0];
        assert_eq!(file.diff_file.path, "config.py");
        assert!(file.diff_file.is_new);
        assert!(!file.diff_file.is_deleted);
        assert!(!file.diff_file.is_renamed);
        assert!(!file.diff_file.is_binary);
        assert_eq!(
            contents(file),
            vec![
                b"DEBUG = True".as_slice(),
                b"PORT = 8080".as_slice(),
                b"HOST = \"0.0.0.0\"".as_slice(),
            ]
        );
        assert_eq!(
            file.diff_file
                .added_lines
                .iter()
                .map(|line| line.line_number)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn fixture_b_update_file() {
        let patch = b"*** Begin Patch\n*** Update File: src/config.rs\n@@ impl Config\n pub name: String,\n-pub timeout: u32,\n+pub timeout_ms: u32,\n+pub retries: u8,\n pub verbose: bool,\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "src/config.rs");
        assert_eq!(files[0].original_path, None);
        assert_eq!(
            contents(&files[0]),
            vec![
                b"pub timeout_ms: u32,".as_slice(),
                b"pub retries: u8,".as_slice(),
            ]
        );
    }

    #[test]
    fn fixture_c_update_and_move() {
        let patch = b"*** Begin Patch\n*** Update File: path/update.py\n*** Move to: path/update2.py\n@@ def f():\n-    pass\n+    return 123\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "path/update2.py");
        assert_eq!(files[0].original_path, Some("path/update.py".to_string()));
        assert!(files[0].diff_file.is_renamed);
        assert_eq!(contents(&files[0]), vec![b"    return 123".as_slice()]);
    }

    #[test]
    fn pure_rename_without_changes_is_accepted() {
        let patch =
            b"*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "new.txt");
        assert_eq!(files[0].original_path, Some("old.txt".to_string()));
        assert!(files[0].diff_file.is_renamed);
        assert!(files[0].diff_file.added_lines.is_empty());
    }

    #[test]
    fn update_file_without_changes_is_rejected() {
        let patch = b"*** Begin Patch\n*** Update File: file.txt\n*** End Patch\n";
        assert!(parse_apply_patch(patch).is_err());
    }

    #[test]
    fn fixture_d_delete_file_is_not_scanned() {
        let patch = b"*** Begin Patch\n*** Delete File: obsolete.txt\n*** End Patch\n";
        assert!(parse_apply_patch(patch).unwrap().is_empty());
    }

    #[test]
    fn adversarial_content_lines_are_not_directives() {
        let patch = b"*** Begin Patch\n*** Update File: config.py\n@@\n line1\n+*** End Patch\n+*** Add File: evil.txt\n line2\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "config.py");
        assert_eq!(
            contents(&files[0]),
            vec![
                b"*** End Patch".as_slice(),
                b"*** Add File: evil.txt".as_slice(),
            ]
        );
    }

    #[test]
    fn fixture_f_missing_end_patch_is_an_error() {
        let patch = b"*** Begin Patch\n*** Add File: file.txt\n+hello\n";
        let error = parse_apply_patch(patch).unwrap_err();
        assert!(error.contains("last line"));
        assert!(error.contains("*** End Patch"));
    }

    #[test]
    fn whitespace_padded_top_level_directives_are_recognized() {
        let patch =
            b"  *** Begin Patch  \n  *** Add File: file.txt  \n+content\n  *** End Patch  \n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "file.txt");
        assert_eq!(contents(&files[0]), vec![b"content".as_slice()]);
    }

    #[test]
    fn whitespace_padded_end_patch_inside_update_hunk_is_treated_as_context() {
        // The padded inner marker is context, so it cannot hide added content.
        // The final unpadded marker ends the patch; a single padded marker is
        // a safe, known upstream-parity gap caused by this parser's pre-check.
        let patch = b"*** Begin Patch\n*** Update File: foo.txt\n@@\n-old\n+new\n  *** End Patch  \n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "foo.txt");
        assert_eq!(contents(&files[0]), vec![b"new".as_slice()]);
    }

    #[test]
    fn end_of_file_marker_is_consumed() {
        let patch = b"*** Begin Patch\n*** Update File: file.txt\n@@\n-old\n+new\n*** End of File\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();
        assert_eq!(contents(&files[0]), vec![b"new".as_slice()]);
    }

    #[test]
    fn end_of_file_marker_requires_next_hunk_marker() {
        let patch = b"*** Begin Patch\n*** Update File: file.txt\n@@\n-old\n+new\n*** End of File\n+more\n*** End Patch\n";
        assert!(parse_apply_patch(patch).is_err());
    }

    #[test]
    fn bare_empty_line_is_update_context() {
        let patch = b"*** Begin Patch\n*** Update File: file.txt\n@@\n\n+new\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();
        assert_eq!(contents(&files[0]), vec![b"new".as_slice()]);
    }

    #[test]
    fn crlf_strips_exactly_one_carriage_return() {
        let patch = b"*** Begin Patch\r\n*** Add File: file.txt\r\n+old\r\r\n*** End Patch\r\n";
        let files = parse_apply_patch(patch).unwrap();
        assert_eq!(contents(&files[0]), vec![b"old\r".as_slice()]);
    }

    #[test]
    fn multibyte_utf8_round_trips_verbatim() {
        let content = "naïve café ✅";
        let patch = format!("*** Begin Patch\n*** Add File: utf8.txt\n+{content}\n*** End Patch\n");
        let files = parse_apply_patch(patch.as_bytes()).unwrap();
        assert_eq!(contents(&files[0]), vec![content.as_bytes()]);
    }

    #[test]
    fn heredoc_wrapped_patch_matches_unwrapped_patch() {
        let patch = "*** Begin Patch\n*** Add File: file.txt\n+hello\n*** End Patch\n";
        let wrapped = format!("cat <<'EOF'\n{patch}EOF\n");
        let plain = parse_apply_patch(patch.as_bytes()).unwrap();
        let heredoc = parse_apply_patch(wrapped.as_bytes()).unwrap();

        assert_eq!(plain.len(), heredoc.len());
        assert_eq!(plain[0].diff_file.path, heredoc[0].diff_file.path);
        assert_eq!(contents(&plain[0]), contents(&heredoc[0]));
    }

    #[test]
    fn tab_indented_heredoc_terminator_matches_unwrapped_patch() {
        let patch = "*** Begin Patch\n*** Add File: file.txt\n+hello\n*** End Patch\n";
        let wrapped = format!("cat <<-'EOF'\n{patch}\tEOF\n");
        let plain = parse_apply_patch(patch.as_bytes()).unwrap();
        let heredoc = parse_apply_patch(wrapped.as_bytes()).unwrap();

        assert_eq!(plain.len(), heredoc.len());
        assert_eq!(plain[0].diff_file.path, heredoc[0].diff_file.path);
        assert_eq!(contents(&plain[0]), contents(&heredoc[0]));
    }

    #[test]
    fn tab_stripped_heredoc_body_matches_unwrapped_patch() {
        let patch = "*** Begin Patch\n*** Add File: file.txt\n+hello\n*** End Patch\n";
        let wrapped = "cat <<-'EOF'\n*** Begin Patch\n*** Add File: file.txt\n\t+hello\n*** End Patch\n\tEOF\n";
        let plain = parse_apply_patch(patch.as_bytes()).unwrap();
        let heredoc = parse_apply_patch(wrapped.as_bytes()).unwrap();

        assert_eq!(plain.len(), heredoc.len());
        assert_eq!(plain[0].diff_file.path, heredoc[0].diff_file.path);
        assert_eq!(contents(&plain[0]), contents(&heredoc[0]));
    }

    #[test]
    fn redirect_heredoc_opener_matches_unwrapped_patch() {
        let patch = "*** Begin Patch\n*** Add File: file.txt\n+hello\n*** End Patch\n";
        let wrapped = format!("cat <<'EOF' > patch.diff\n{patch}EOF\n");
        let plain = parse_apply_patch(patch.as_bytes()).unwrap();
        let heredoc = parse_apply_patch(wrapped.as_bytes()).unwrap();

        assert_eq!(plain.len(), heredoc.len());
        assert_eq!(plain[0].diff_file.path, heredoc[0].diff_file.path);
        assert_eq!(contents(&plain[0]), contents(&heredoc[0]));
    }

    #[test]
    fn comment_heredoc_opener_matches_unwrapped_patch() {
        let patch = "*** Begin Patch\n*** Add File: file.txt\n+hello\n*** End Patch\n";
        let wrapped = format!("cat <<'EOF' # apply the patch\n{patch}EOF\n");
        let plain = parse_apply_patch(patch.as_bytes()).unwrap();
        let heredoc = parse_apply_patch(wrapped.as_bytes()).unwrap();

        assert_eq!(plain.len(), heredoc.len());
        assert_eq!(plain[0].diff_file.path, heredoc[0].diff_file.path);
        assert_eq!(contents(&plain[0]), contents(&heredoc[0]));
    }

    #[test]
    fn add_file_accepts_an_empty_added_line() {
        let patch = b"*** Begin Patch\n*** Add File: file.txt\n+\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();
        assert_eq!(contents(&files[0]), vec![b"".as_slice()]);
    }

    #[test]
    fn add_file_accepts_no_added_lines() {
        let patch = b"*** Begin Patch\n*** Add File: empty.txt\n*** End Patch\n";
        let files = parse_apply_patch(patch).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].diff_file.path, "empty.txt");
        assert!(files[0].diff_file.added_lines.is_empty());
    }

    #[test]
    fn misplaced_move_to_is_rejected() {
        let patch = b"*** Begin Patch\n*** Update File: old.txt\n@@\n-old\n+new\n*** Move to: new.txt\n*** End Patch\n";
        assert!(parse_apply_patch(patch).is_err());
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert!(parse_apply_patch(&[0xff]).is_err());
    }
}
