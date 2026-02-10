// allowlist/whitelist logic
//
// provides global path filtering, stopword checking, variable reference
// detection, and documentation file exception handling.

use regex::bytes::Regex;

/// default file extensions to skip (binary and non-source files)
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "woff", "woff2", "ttf",
    "eot", "otf", "pdf", "exe", "dll", "so", "dylib", "zip", "gz", "tar",
    "bz2", "xz", "7z", "rar", "mp3", "mp4", "avi", "mov", "wav", "ogg",
    "webp", "webm",
];

/// default generated/lock files to skip
const GENERATED_FILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "Cargo.lock",
    "go.sum",
    "pnpm-lock.yaml",
    "composer.lock",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
];

/// default generated file extensions to skip
const GENERATED_EXTENSIONS: &[&str] = &["min.js", "min.css", "map"];

/// default vendor directories to skip
const VENDOR_DIRS: &[&str] = &[
    "node_modules/",
    "vendor/",
    ".bundle/",
    "bower_components/",
    "__pycache__/",
    ".git/",
];

/// the config file itself should always be skipped
const CONFIG_FILE: &str = ".sekretbarilo.toml";

/// default stopwords - if the captured secret contains any of these,
/// the finding is skipped
const DEFAULT_STOPWORDS: &[&str] = &[
    "example", "test", "sample", "placeholder", "dummy", "changeme", "fake",
    "mock", "todo", "fixme", "xxx", "lorem", "default", "replace_me",
    "insert_here", "your_", "my_", "<your", "${", "#{",
];

/// documentation file patterns
const DOC_EXTENSIONS: &[&str] = &["md", "rst", "txt", "adoc"];
const DOC_PREFIXES: &[&str] = &["readme", "changelog", "contributing", "license"];
const DOC_DIRS: &[&str] = &["docs/", "doc/", "documentation/", "wiki/"];

/// variable reference patterns (compiled lazily)
const VAR_PATTERNS: &[&str] = &[
    // shell/unix: ${VAR}, $VAR
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$",
    r"^\$[A-Za-z_][A-Za-z0-9_]*$",
    // windows: %VAR%
    r"^%[A-Za-z_][A-Za-z0-9_]*%$",
    // template engines: {{var}}, {{ var }}
    r"^\{\{\s*[A-Za-z_][A-Za-z0-9_.]*\s*\}\}$",
    // javascript/node: process.env.VAR
    r"^process\.env\.[A-Za-z_][A-Za-z0-9_]*$",
    // python: os.environ["VAR"], os.environ.get("VAR"), os.getenv("VAR")
    r#"^os\.environ\[['"][A-Za-z_][A-Za-z0-9_]*['"]\]$"#,
    r#"^os\.environ\.get\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)$"#,
    r#"^os\.getenv\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)$"#,
    // java: System.getenv("VAR")
    r#"^System\.getenv\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)$"#,
    // rust: std::env::var("VAR"), env::var("VAR")
    r#"^(?:std::)?env::var\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)$"#,
    // go: os.Getenv("VAR")
    r#"^os\.Getenv\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)$"#,
];

/// compiled allowlist configuration for use during scanning
pub struct CompiledAllowlist {
    /// compiled regex patterns for variable reference detection
    var_ref_patterns: Vec<Regex>,
    /// additional user-provided path patterns (regexes)
    user_path_patterns: Vec<Regex>,
    /// additional user-provided stopwords
    user_stopwords: Vec<String>,
    /// global entropy threshold override (if set by user config)
    pub entropy_threshold_override: Option<f64>,
    /// per-rule allowlist compiled regexes: maps rule_id -> (value_regexes, path_regexes)
    per_rule_allowlists: Vec<(String, Vec<Regex>, Vec<Regex>)>,
}

impl CompiledAllowlist {
    /// create a new allowlist with default settings only
    pub fn default_allowlist() -> Result<Self, String> {
        Self::new(&[], &[], None, &[])
    }

    /// create a compiled allowlist from user configuration
    pub fn new(
        user_paths: &[String],
        user_stopwords: &[String],
        entropy_override: Option<f64>,
        per_rule: &[(String, Vec<String>, Vec<String>)],
    ) -> Result<Self, String> {
        let mut var_ref_patterns = Vec::with_capacity(VAR_PATTERNS.len());
        for pattern in VAR_PATTERNS {
            let re = Regex::new(pattern)
                .map_err(|e| format!("failed to compile var ref pattern '{}': {}", pattern, e))?;
            var_ref_patterns.push(re);
        }

        let mut user_path_patterns = Vec::with_capacity(user_paths.len());
        for path_pattern in user_paths {
            let re = Regex::new(path_pattern)
                .map_err(|e| format!("failed to compile user path pattern '{}': {}", path_pattern, e))?;
            user_path_patterns.push(re);
        }

        let mut per_rule_allowlists = Vec::with_capacity(per_rule.len());
        for (rule_id, value_regexes, path_regexes) in per_rule {
            let mut compiled_values = Vec::new();
            for pattern in value_regexes {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("failed to compile allowlist regex for rule '{}': {}", rule_id, e))?;
                compiled_values.push(re);
            }
            let mut compiled_paths = Vec::new();
            for pattern in path_regexes {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("failed to compile allowlist path for rule '{}': {}", rule_id, e))?;
                compiled_paths.push(re);
            }
            per_rule_allowlists.push((rule_id.clone(), compiled_values, compiled_paths));
        }

        Ok(Self {
            var_ref_patterns,
            user_path_patterns,
            user_stopwords: user_stopwords.to_vec(),
            entropy_threshold_override: entropy_override,
            per_rule_allowlists,
        })
    }

    /// check if a file path should be skipped entirely (global path allowlist)
    pub fn is_path_skipped(&self, path: &str) -> bool {
        // skip the config file itself
        let filename = path.rsplit('/').next().unwrap_or(path);
        if filename == CONFIG_FILE {
            return true;
        }

        let lower = path.to_lowercase();

        // skip binary file extensions (without format! allocation per extension)
        if let Some(dot_pos) = lower.rfind('.') {
            let ext = &lower[dot_pos + 1..];
            for &bin_ext in BINARY_EXTENSIONS {
                if ext == bin_ext {
                    return true;
                }
            }
        }

        // skip generated file extensions (multi-part like .min.js)
        for &gen_ext in GENERATED_EXTENSIONS {
            if lower.ends_with(gen_ext) {
                let prefix_len = lower.len() - gen_ext.len();
                if prefix_len > 0 && lower.as_bytes()[prefix_len - 1] == b'.' {
                    return true;
                }
            }
        }

        // skip specific generated files
        for gen_file in GENERATED_FILES {
            if filename == *gen_file {
                return true;
            }
        }

        // skip vendor directories
        for vendor_dir in VENDOR_DIRS {
            if path.contains(vendor_dir) {
                return true;
            }
        }

        // check user-configured path patterns
        for pattern in &self.user_path_patterns {
            if pattern.is_match(path.as_bytes()) {
                return true;
            }
        }

        false
    }

    /// check if the captured secret value contains a stopword
    pub fn contains_stopword(&self, secret: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(secret).to_lowercase();

        for stopword in DEFAULT_STOPWORDS {
            if lower.contains(stopword) {
                return true;
            }
        }

        for stopword in &self.user_stopwords {
            if lower.contains(&stopword.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// check if the captured secret value is actually a variable reference
    pub fn is_variable_reference(&self, secret: &[u8]) -> bool {
        // also check for common inline patterns that appear within larger strings
        let s = String::from_utf8_lossy(secret);
        let trimmed = s.trim();

        for pattern in &self.var_ref_patterns {
            if pattern.is_match(trimmed.as_bytes()) {
                return true;
            }
        }

        false
    }

    /// check if the file is a documentation file
    pub fn is_documentation_file(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        let filename = lower.rsplit('/').next().unwrap_or(&lower);

        // check doc file extensions
        if let Some(ext) = filename.rsplit('.').next() {
            if DOC_EXTENSIONS.contains(&ext) {
                return true;
            }
        }

        // check doc file prefixes (README*, CHANGELOG*, etc.)
        for prefix in DOC_PREFIXES {
            if filename.starts_with(prefix) {
                return true;
            }
        }

        // check doc directories
        for &dir in DOC_DIRS {
            if lower.starts_with(dir) {
                return true;
            }
            // check for /docs/, /doc/, etc. in middle of path
            // without format! allocation
            if let Some(pos) = lower.find(dir) {
                if pos > 0 && lower.as_bytes()[pos - 1] == b'/' {
                    return true;
                }
            }
        }

        false
    }

    /// get the entropy threshold adjustment for documentation files.
    /// returns an additional amount to add to the base threshold.
    pub fn doc_entropy_bonus(&self) -> f64 {
        1.0
    }

    /// check per-rule allowlist: returns true if the finding should be skipped
    /// based on the rule's specific allowlist configuration
    pub fn is_rule_allowlisted(
        &self,
        rule_id: &str,
        secret: &[u8],
        file_path: &str,
    ) -> bool {
        for (id, value_regexes, path_regexes) in &self.per_rule_allowlists {
            if id == rule_id {
                // check value regexes
                for re in value_regexes {
                    if re.is_match(secret) {
                        return true;
                    }
                }
                // check path regexes
                for re in path_regexes {
                    if re.is_match(file_path.as_bytes()) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_al() -> CompiledAllowlist {
        CompiledAllowlist::default_allowlist().unwrap()
    }

    // -- global path allowlist tests (5.1) --

    #[test]
    fn skip_binary_extensions() {
        let al = default_al();
        assert!(al.is_path_skipped("image.png"));
        assert!(al.is_path_skipped("font.woff"));
        assert!(al.is_path_skipped("doc.pdf"));
        assert!(al.is_path_skipped("path/to/icon.ico"));
        assert!(al.is_path_skipped("path/to/img.JPG")); // case insensitive
    }

    #[test]
    fn skip_generated_files() {
        let al = default_al();
        assert!(al.is_path_skipped("package-lock.json"));
        assert!(al.is_path_skipped("yarn.lock"));
        assert!(al.is_path_skipped("Cargo.lock"));
        assert!(al.is_path_skipped("go.sum"));
        assert!(al.is_path_skipped("path/to/package-lock.json"));
    }

    #[test]
    fn skip_generated_extensions() {
        let al = default_al();
        assert!(al.is_path_skipped("app.min.js"));
        assert!(al.is_path_skipped("style.min.css"));
        assert!(al.is_path_skipped("bundle.js.map"));
    }

    #[test]
    fn skip_vendor_dirs() {
        let al = default_al();
        assert!(al.is_path_skipped("node_modules/lodash/index.js"));
        assert!(al.is_path_skipped("vendor/autoload.php"));
        assert!(al.is_path_skipped(".bundle/config"));
    }

    #[test]
    fn skip_config_file() {
        let al = default_al();
        assert!(al.is_path_skipped(".sekretbarilo.toml"));
        assert!(al.is_path_skipped("project/.sekretbarilo.toml"));
    }

    #[test]
    fn dont_skip_source_files() {
        let al = default_al();
        assert!(!al.is_path_skipped("src/main.rs"));
        assert!(!al.is_path_skipped("app/config.py"));
        assert!(!al.is_path_skipped("index.js"));
        assert!(!al.is_path_skipped("Cargo.toml"));
    }

    #[test]
    fn user_path_patterns() {
        let al = CompiledAllowlist::new(
            &["test/fixtures/.*".to_string(), "docs/examples/.*".to_string()],
            &[],
            None,
            &[],
        )
        .unwrap();
        assert!(al.is_path_skipped("test/fixtures/secret.txt"));
        assert!(al.is_path_skipped("docs/examples/config.yml"));
        assert!(!al.is_path_skipped("src/main.rs"));
    }

    // -- stopword tests (5.2) --

    #[test]
    fn default_stopwords_detected() {
        let al = default_al();
        assert!(al.contains_stopword(b"EXAMPLE_TOKEN_12345"));
        assert!(al.contains_stopword(b"test_api_key_abc"));
        assert!(al.contains_stopword(b"sample-secret-value"));
        assert!(al.contains_stopword(b"placeholder_key"));
        assert!(al.contains_stopword(b"changeme"));
        assert!(al.contains_stopword(b"fake-token-1234"));
        assert!(al.contains_stopword(b"MOCK_SECRET_KEY"));
    }

    #[test]
    fn real_secrets_not_stopworded() {
        let al = default_al();
        assert!(!al.contains_stopword(b"AKIAIOSFODNN7REALKEY"));
        assert!(!al.contains_stopword(b"ghp_ABCDEFreal1234567890abcdefgh"));
        assert!(!al.contains_stopword(b"sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
    }

    #[test]
    fn user_stopwords() {
        let al = CompiledAllowlist::new(
            &[],
            &["my-safe-token".to_string(), "internal-key".to_string()],
            None,
            &[],
        )
        .unwrap();
        assert!(al.contains_stopword(b"my-safe-token-12345"));
        assert!(al.contains_stopword(b"the-internal-key-here"));
        assert!(!al.contains_stopword(b"real-production-secret"));
    }

    // -- per-rule allowlist tests (5.3) --

    #[test]
    fn per_rule_value_allowlist() {
        let al = CompiledAllowlist::new(
            &[],
            &[],
            None,
            &[(
                "aws-access-key-id".to_string(),
                vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                vec![],
            )],
        )
        .unwrap();
        assert!(al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIAIOSFODNN7EXAMPLE",
            "config.py"
        ));
        assert!(!al.is_rule_allowlisted(
            "aws-access-key-id",
            b"AKIAIOSFODNN7REALKEY",
            "config.py"
        ));
    }

    #[test]
    fn per_rule_path_allowlist() {
        let al = CompiledAllowlist::new(
            &[],
            &[],
            None,
            &[(
                "generic-api-key".to_string(),
                vec![],
                vec!["test/.*".to_string()],
            )],
        )
        .unwrap();
        assert!(al.is_rule_allowlisted(
            "generic-api-key",
            b"some-api-key-value",
            "test/fixtures/keys.yml"
        ));
        assert!(!al.is_rule_allowlisted(
            "generic-api-key",
            b"some-api-key-value",
            "src/config.rs"
        ));
    }

    #[test]
    fn per_rule_wrong_rule_id() {
        let al = CompiledAllowlist::new(
            &[],
            &[],
            None,
            &[(
                "aws-access-key-id".to_string(),
                vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                vec![],
            )],
        )
        .unwrap();
        // different rule id should not match
        assert!(!al.is_rule_allowlisted(
            "github-token",
            b"AKIAIOSFODNN7EXAMPLE",
            "config.py"
        ));
    }

    // -- documentation file tests (5.4) --

    #[test]
    fn detect_doc_by_extension() {
        let al = default_al();
        assert!(al.is_documentation_file("README.md"));
        assert!(al.is_documentation_file("docs/guide.rst"));
        assert!(al.is_documentation_file("NOTES.txt"));
        assert!(al.is_documentation_file("path/to/file.adoc"));
    }

    #[test]
    fn detect_doc_by_prefix() {
        let al = default_al();
        assert!(al.is_documentation_file("README"));
        assert!(al.is_documentation_file("README.txt"));
        assert!(al.is_documentation_file("CHANGELOG"));
        assert!(al.is_documentation_file("CHANGELOG.md"));
        assert!(al.is_documentation_file("CONTRIBUTING.md"));
    }

    #[test]
    fn detect_doc_by_directory() {
        let al = default_al();
        assert!(al.is_documentation_file("docs/api.py"));
        assert!(al.is_documentation_file("doc/guide.html"));
        assert!(al.is_documentation_file("documentation/setup.txt"));
        assert!(al.is_documentation_file("project/docs/readme.md"));
    }

    #[test]
    fn non_doc_files() {
        let al = default_al();
        assert!(!al.is_documentation_file("src/main.rs"));
        assert!(!al.is_documentation_file("config.toml"));
        assert!(!al.is_documentation_file("app/models.py"));
    }

    // -- variable reference tests (5.5) --

    #[test]
    fn detect_shell_var_references() {
        let al = default_al();
        assert!(al.is_variable_reference(b"${DB_PASSWORD}"));
        assert!(al.is_variable_reference(b"$DB_PASSWORD"));
        assert!(al.is_variable_reference(b"${API_KEY}"));
    }

    #[test]
    fn detect_windows_var_references() {
        let al = default_al();
        assert!(al.is_variable_reference(b"%DB_PASSWORD%"));
        assert!(al.is_variable_reference(b"%API_KEY%"));
    }

    #[test]
    fn detect_template_var_references() {
        let al = default_al();
        assert!(al.is_variable_reference(b"{{db_password}}"));
        assert!(al.is_variable_reference(b"{{ api_key }}"));
    }

    #[test]
    fn detect_code_var_references() {
        let al = default_al();
        assert!(al.is_variable_reference(b"process.env.DB_PASSWORD"));
        assert!(al.is_variable_reference(b"os.environ[\"DB_PASSWORD\"]"));
        assert!(al.is_variable_reference(b"os.getenv(\"API_KEY\")"));
        assert!(al.is_variable_reference(b"System.getenv(\"SECRET\")"));
        assert!(al.is_variable_reference(b"env::var(\"SECRET_KEY\")"));
        assert!(al.is_variable_reference(b"os.Getenv(\"SECRET\")"));
    }

    #[test]
    fn real_secrets_not_var_references() {
        let al = default_al();
        assert!(!al.is_variable_reference(b"AKIAIOSFODNN7EXAMPLE"));
        assert!(!al.is_variable_reference(b"ghp_ABCDEFreal1234567890abcdefgh"));
        assert!(!al.is_variable_reference(b"sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(!al.is_variable_reference(b"my-actual-password-123"));
    }
}
