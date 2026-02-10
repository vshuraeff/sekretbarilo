// core scanning engine (aho-corasick + regex)

use crate::diff::parser::DiffFile;

/// a detected secret finding
#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub matched_value: Vec<u8>,
}

/// scan parsed diff files for secrets
pub fn scan(_files: &[DiffFile]) -> Vec<Finding> {
    Vec::new()
}
