// unified diff parser

/// a single added line from a diff hunk
#[derive(Debug, Clone)]
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
pub fn parse_diff(_input: &[u8]) -> Vec<DiffFile> {
    Vec::new()
}
