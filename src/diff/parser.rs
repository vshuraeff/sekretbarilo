// unified diff parser

use bstr::ByteSlice;

/// a single added line from a diff hunk
#[derive(Debug, Clone, PartialEq)]
pub struct AddedLine {
    pub line_number: usize,
    pub content: Vec<u8>,
}

/// a parsed file block from a diff
#[derive(Debug, Clone)]
pub struct DiffFile {
    pub path: String,
    pub is_new: bool,
    pub is_deleted: bool,
    pub is_renamed: bool,
    pub is_binary: bool,
    pub added_lines: Vec<AddedLine>,
}

/// parse a unified diff into file blocks
pub fn parse_diff(input: &[u8]) -> Vec<DiffFile> {
    let mut files = Vec::new();
    let lines: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
    let len = lines.len();
    let mut i = 0;

    while i < len {
        let line = lines[i];

        // look for diff header: "diff --git a/... b/..."
        if line.starts_with(b"diff --git ") {
            let (file, consumed) = parse_file_block(&lines, i, len);
            files.push(file);
            i += consumed;
        } else {
            i += 1;
        }
    }

    files
}

/// parse a single file block starting at a "diff --git" line.
/// returns the DiffFile and the number of lines consumed.
fn parse_file_block(lines: &[&[u8]], start: usize, total: usize) -> (DiffFile, usize) {
    let header = lines[start];
    let path = extract_path_from_diff_header(header);

    let mut file = DiffFile {
        path,
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: Vec::new(),
    };

    let mut i = start + 1;

    // parse metadata lines between "diff --git" and first hunk or next diff
    while i < total {
        let line = lines[i];

        if line.starts_with(b"diff --git ") {
            // next file block
            break;
        }

        if line.starts_with(b"new file mode") {
            file.is_new = true;
        } else if line.starts_with(b"deleted file mode") {
            file.is_deleted = true;
        } else if line.starts_with(b"rename from ") || line.starts_with(b"rename to ") {
            file.is_renamed = true;
        } else if (line.starts_with(b"Binary files ") && line.ends_with(b" differ"))
            || line.starts_with(b"GIT binary patch")
        {
            file.is_binary = true;
        } else if line.starts_with(b"+++ b/") {
            // update path from the +++ line (more reliable for renames)
            if let Some(p) = line.get(6..) {
                if let Ok(s) = std::str::from_utf8(p) {
                    file.path = s.to_string();
                }
            }
        } else if line.starts_with(b"+++ /dev/null") {
            // deleted file, path stays from header
        } else if line.starts_with(b"@@") {
            // start of a hunk, parse it
            let (added, consumed) = parse_hunk(lines, i, total);
            file.added_lines.extend(added);
            i += consumed;
            continue;
        }

        i += 1;
    }

    let consumed = i - start;
    (file, consumed)
}

/// extract file path from "diff --git a/path b/path" header.
/// uses the b/path portion.
fn extract_path_from_diff_header(header: &[u8]) -> String {
    // format: "diff --git a/some/path b/some/path"
    // we want the part after the last " b/" to handle paths containing " b/"
    if let Some(pos) = header.rfind(b" b/") {
        let path_bytes = &header[pos + 3..];
        if let Ok(s) = std::str::from_utf8(path_bytes) {
            return s.to_string();
        }
    }
    // fallback: try to parse from a/ portion
    if let Some(pos) = header.find(b" a/") {
        let after_a = &header[pos + 3..];
        if let Some(space_pos) = after_a.rfind(b" b/") {
            let path_bytes = &after_a[..space_pos];
            if let Ok(s) = std::str::from_utf8(path_bytes) {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// parse a hunk starting at an @@ line.
/// returns added lines and the number of lines consumed.
fn parse_hunk(lines: &[&[u8]], start: usize, total: usize) -> (Vec<AddedLine>, usize) {
    let hunk_header = lines[start];
    let new_start_line = parse_hunk_header_new_start(hunk_header);

    let mut added = Vec::new();
    let mut new_line = new_start_line;
    let mut i = start + 1;

    while i < total {
        let line = lines[i];

        if line.starts_with(b"diff --git ") || line.starts_with(b"@@") {
            // next file or next hunk
            break;
        }

        if line.starts_with(b"+") {
            // added line: strip the leading '+' and record
            let content = line[1..].to_vec();
            added.push(AddedLine {
                line_number: new_line,
                content,
            });
            new_line += 1;
        } else if line.starts_with(b"-") {
            // removed line: does not affect new line numbering
        } else if line.starts_with(b" ") {
            // context line: advances new line number
            new_line += 1;
        } else if line.starts_with(b"\\") {
            // "\ No newline at end of file" - skip
        } else if line.is_empty() {
            // empty line in --unified=0 signals end of hunk content
            // (typically a trailing newline artifact from splitting on \n)
            break;
        }

        i += 1;
    }

    (added, i - start)
}

/// parse the new-file start line from a hunk header.
/// format: "@@ -old_start[,old_count] +new_start[,new_count] @@[ context]"
/// returns the new_start value.
fn parse_hunk_header_new_start(header: &[u8]) -> usize {
    // find "+NNN" after the first "@@"
    if let Some(plus_pos) = header.find(b"+") {
        let after_plus = &header[plus_pos + 1..];
        // read digits until ',' or ' ' or '@'
        let end = after_plus
            .iter()
            .position(|&b| !b.is_ascii_digit())
            .unwrap_or(after_plus.len());
        if end > 0 {
            if let Ok(s) = std::str::from_utf8(&after_plus[..end]) {
                if let Ok(n) = s.parse::<usize>() {
                    return n;
                }
            }
        }
    }
    1 // default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_diff_one_file() {
        let diff = b"\
diff --git a/src/main.rs b/src/main.rs
index 1234567..abcdefg 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,4 @@
 fn main() {
+    println!(\"hello\");
     // existing
 }
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/main.rs");
        assert!(!files[0].is_new);
        assert!(!files[0].is_deleted);
        assert!(!files[0].is_binary);
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 2);
        assert_eq!(files[0].added_lines[0].content, b"    println!(\"hello\");");
    }

    #[test]
    fn parse_diff_multiple_files() {
        let diff = b"\
diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
@@ -1 +1,2 @@
 line1
+line2
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
@@ -1 +1,2 @@
 lineA
+lineB
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "a.rs");
        assert_eq!(files[1].path, "b.rs");
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[1].added_lines.len(), 1);
    }

    #[test]
    fn parse_binary_file() {
        let diff = b"\
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_binary);
        assert_eq!(files[0].path, "image.png");
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn parse_new_file() {
        let diff = b"\
diff --git a/new.rs b/new.rs
new file mode 100644
--- /dev/null
+++ b/new.rs
@@ -0,0 +1,3 @@
+fn new_func() {
+    // new
+}
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_new);
        assert_eq!(files[0].path, "new.rs");
        assert_eq!(files[0].added_lines.len(), 3);
        assert_eq!(files[0].added_lines[0].line_number, 1);
        assert_eq!(files[0].added_lines[1].line_number, 2);
        assert_eq!(files[0].added_lines[2].line_number, 3);
    }

    #[test]
    fn parse_deleted_file() {
        let diff = b"\
diff --git a/old.rs b/old.rs
deleted file mode 100644
--- a/old.rs
+++ /dev/null
@@ -1,3 +0,0 @@
-fn old_func() {
-    // old
-}
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_deleted);
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn parse_renamed_file() {
        let diff = b"\
diff --git a/old_name.rs b/new_name.rs
rename from old_name.rs
rename to new_name.rs
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_renamed);
        assert_eq!(files[0].path, "new_name.rs");
    }

    #[test]
    fn parse_hunk_header_omitted_count() {
        // when count is omitted, it defaults to 1
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -5 +5 @@
-old line
+new line
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 5);
    }

    #[test]
    fn parse_multiple_hunks() {
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -1,3 +1,4 @@
 line1
+added_at_2
 line3
 line4
@@ -10,2 +11,3 @@
 line10
+added_at_12
+added_at_13
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 3);
        assert_eq!(files[0].added_lines[0].line_number, 2);
        assert_eq!(files[0].added_lines[0].content, b"added_at_2");
        assert_eq!(files[0].added_lines[1].line_number, 12);
        assert_eq!(files[0].added_lines[2].line_number, 13);
    }

    #[test]
    fn parse_no_newline_marker() {
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -1 +1 @@
-old
+new
\\ No newline at end of file
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].content, b"new");
    }

    #[test]
    fn parse_empty_diff() {
        let files = parse_diff(b"");
        assert!(files.is_empty());
    }

    #[test]
    fn parse_unified_zero_context() {
        // git diff --cached --unified=0 output
        let diff = b"\
diff --git a/config.rs b/config.rs
--- a/config.rs
+++ b/config.rs
@@ -0,0 +42 @@
+let api_key = \"sk-secret123\";
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 42);
    }

    #[test]
    fn extract_path_basic() {
        let header = b"diff --git a/src/main.rs b/src/main.rs";
        assert_eq!(extract_path_from_diff_header(header), "src/main.rs");
    }

    #[test]
    fn extract_path_renamed() {
        let header = b"diff --git a/old.rs b/new.rs";
        assert_eq!(extract_path_from_diff_header(header), "new.rs");
    }

    #[test]
    fn hunk_header_with_count() {
        let header = b"@@ -10,5 +20,3 @@ fn foo()";
        assert_eq!(parse_hunk_header_new_start(header), 20);
    }

    #[test]
    fn hunk_header_without_count() {
        let header = b"@@ -5 +7 @@";
        assert_eq!(parse_hunk_header_new_start(header), 7);
    }

    #[test]
    fn hunk_header_zero_start() {
        let header = b"@@ -0,0 +1,3 @@";
        assert_eq!(parse_hunk_header_new_start(header), 1);
    }

    #[test]
    fn parse_file_mode_change() {
        let diff = b"\
diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "script.sh");
        // mode-only change: no added lines, not treated as new/deleted/binary
        assert!(!files[0].is_new);
        assert!(!files[0].is_deleted);
        assert!(!files[0].is_binary);
        assert!(files[0].added_lines.is_empty());
    }

    // --- additional tests for plan 8.1 coverage ---

    #[test]
    fn line_number_mapping_with_mixed_changes() {
        // verifies correct line numbering when added, removed, and context lines interleave
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -1,7 +1,8 @@
 line1
-removed_line2
+added_line2
+added_line3
 line4
 line5
-removed_line6
+added_line6
 line7
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 3);
        // added_line2 replaces removed_line2, new line number = 2
        assert_eq!(files[0].added_lines[0].line_number, 2);
        assert_eq!(files[0].added_lines[0].content, b"added_line2");
        // added_line3 is inserted, new line number = 3
        assert_eq!(files[0].added_lines[1].line_number, 3);
        assert_eq!(files[0].added_lines[1].content, b"added_line3");
        // after context lines 4,5 (new lines 4,5), removed_line6 is replaced by added_line6
        // context: line4=4, line5=5, removed doesn't advance, added_line6=6
        assert_eq!(files[0].added_lines[2].line_number, 6);
        assert_eq!(files[0].added_lines[2].content, b"added_line6");
    }

    #[test]
    fn line_number_mapping_across_multiple_hunks() {
        // verifies line numbers reset correctly for each hunk
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -0,0 +1,2 @@
+first_line
+second_line
@@ -5,0 +7,1 @@
+inserted_at_7
@@ -20 +22 @@
-old_twenty
+new_at_22
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 4);
        assert_eq!(files[0].added_lines[0].line_number, 1);
        assert_eq!(files[0].added_lines[1].line_number, 2);
        assert_eq!(files[0].added_lines[2].line_number, 7);
        assert_eq!(files[0].added_lines[3].line_number, 22);
    }

    #[test]
    fn parse_renamed_file_with_content_changes() {
        let diff = b"\
diff --git a/old_name.rs b/new_name.rs
rename from old_name.rs
rename to new_name.rs
--- a/old_name.rs
+++ b/new_name.rs
@@ -1,3 +1,4 @@
 fn hello() {
+    println!(\"world\");
     // old comment
 }
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_renamed);
        assert_eq!(files[0].path, "new_name.rs");
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 2);
        assert_eq!(files[0].added_lines[0].content, b"    println!(\"world\");");
    }

    #[test]
    fn parse_git_binary_patch() {
        // git can also produce "GIT binary patch" markers
        let diff = b"\
diff --git a/data.bin b/data.bin
new file mode 100644
GIT binary patch
literal 1234
zcmb7EO>5gg5Ps
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_binary);
        assert!(files[0].is_new);
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn parse_mixed_diff_multiple_file_types() {
        // a single diff containing new, deleted, renamed, binary, and normal files
        let diff = b"\
diff --git a/new.rs b/new.rs
new file mode 100644
--- /dev/null
+++ b/new.rs
@@ -0,0 +1,2 @@
+fn new() {}
+fn also_new() {}
diff --git a/removed.rs b/removed.rs
deleted file mode 100644
--- a/removed.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-fn removed() {}
-fn also_removed() {}
diff --git a/old.rs b/renamed.rs
rename from old.rs
rename to renamed.rs
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
diff --git a/normal.rs b/normal.rs
--- a/normal.rs
+++ b/normal.rs
@@ -1 +1,2 @@
 existing
+added
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 5);

        // new file
        assert!(files[0].is_new);
        assert_eq!(files[0].path, "new.rs");
        assert_eq!(files[0].added_lines.len(), 2);

        // deleted file
        assert!(files[1].is_deleted);
        assert_eq!(files[1].path, "removed.rs");
        assert!(files[1].added_lines.is_empty());

        // renamed file
        assert!(files[2].is_renamed);
        assert_eq!(files[2].path, "renamed.rs");

        // binary file
        assert!(files[3].is_binary);
        assert_eq!(files[3].path, "image.png");
        assert!(files[3].added_lines.is_empty());

        // normal file
        assert!(!files[4].is_new);
        assert!(!files[4].is_deleted);
        assert!(!files[4].is_binary);
        assert_eq!(files[4].path, "normal.rs");
        assert_eq!(files[4].added_lines.len(), 1);
        assert_eq!(files[4].added_lines[0].content, b"added");
    }

    #[test]
    fn extract_path_deeply_nested() {
        let header =
            b"diff --git a/src/very/deep/nested/path/file.rs b/src/very/deep/nested/path/file.rs";
        assert_eq!(
            extract_path_from_diff_header(header),
            "src/very/deep/nested/path/file.rs"
        );
    }

    #[test]
    fn parse_diff_with_only_removals() {
        // a diff where lines are only removed, no additions
        let diff = b"\
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -5,3 +5,0 @@
-removed1
-removed2
-removed3
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "f.rs");
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn parse_diff_whitespace_only_lines() {
        // tests that lines with only whitespace after '+' are captured
        let diff = b"diff --git a/f.rs b/f.rs\n--- a/f.rs\n+++ b/f.rs\n@@ -1,2 +1,3 @@\n line1\n+    \n line3\n";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 1);
        // content should be the whitespace after '+'
        assert_eq!(files[0].added_lines[0].content, b"    ");
        assert_eq!(files[0].added_lines[0].line_number, 2);
    }

    #[test]
    fn hunk_header_with_context_label() {
        // hunk headers can have function/context labels after the second @@
        let header = b"@@ -100,5 +200,10 @@ impl Scanner {";
        assert_eq!(parse_hunk_header_new_start(header), 200);
    }

    #[test]
    fn hunk_header_large_line_numbers() {
        let header = b"@@ -99999,100 +123456,200 @@";
        assert_eq!(parse_hunk_header_new_start(header), 123456);
    }

    #[test]
    fn parse_empty_newlines_only_diff() {
        // input with only newlines, no actual diff content
        let files = parse_diff(b"\n\n\n");
        assert!(files.is_empty());
    }

    #[test]
    fn parse_new_file_with_single_line() {
        let diff = b"\
diff --git a/single.txt b/single.txt
new file mode 100644
--- /dev/null
+++ b/single.txt
@@ -0,0 +1 @@
+only line
\\ No newline at end of file
";
        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_new);
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 1);
        assert_eq!(files[0].added_lines[0].content, b"only line");
    }

    #[test]
    fn parse_diff_path_with_spaces() {
        let header = b"diff --git a/path with spaces/file.rs b/path with spaces/file.rs";
        // the current parser finds " b/" which will match at the correct position
        let path = extract_path_from_diff_header(header);
        assert_eq!(path, "path with spaces/file.rs");
    }
}
