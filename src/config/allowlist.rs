// allowlist/whitelist logic
//
// provides global path filtering, stopword checking, variable reference
// detection, template line detection, and documentation file exception handling.

use memchr::memmem;
use regex::bytes::{Regex, RegexBuilder};

pub type PerRuleAllowlistWithKeys = (String, Vec<String>, Vec<String>, Vec<String>);
type CompiledPerRuleAllowlist = (String, Vec<Regex>, Vec<Regex>, Vec<Regex>);

/// default file extensions to skip (binary and non-source files)
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "woff", "woff2", "ttf", "eot", "otf", "pdf",
    "exe", "dll", "so", "dylib", "zip", "gz", "tar", "bz2", "xz", "7z", "rar", "mp3", "mp4", "avi",
    "mov", "wav", "ogg", "webp", "webm",
];

/// default generated/lock files to skip. credentials in a lockfile's resolved
/// url are invisible to the scanner, as they already are in package-lock.json.
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
    "bun.lock",
    "Gopkg.lock",
    "uv.lock",
    "flake.lock",
    "deno.lock",
    "pdm.lock",
    "mix.lock",
    "pubspec.lock",
    "npm-shrinkwrap.json",
    "Package.resolved",
    ".terraform.lock.hcl",
    "Podfile.lock",
    "Cartfile.resolved",
    "packages.lock.json",
    "Brewfile.lock.json",
];

/// basenames that skip generic-rule matching only.
const GENERIC_ONLY_FILES: &[&str] = &[
    ".gitignore",
    ".dockerignore",
    ".npmignore",
    ".prettierignore",
    ".eslintignore",
    ".gitattributes",
    ".helmignore",
];

/// default generated file extensions to skip
const GENERATED_EXTENSIONS: &[&str] = &["min.js", "min.css", "js.map", "css.map"];

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
/// generic-high-entropy-value uses user stopwords only through
/// `contains_user_stopword`, which uses substring matching, so these word
/// boundaries do not affect tier 3 behavior.
const DEFAULT_STOPWORDS: &[&str] = &[
    "example",
    "test",
    "sample",
    "placeholder",
    "dummy",
    "changeme",
    "fake",
    "mock",
    "todo",
    "fixme",
    "xxx",
    "lorem",
    "default",
    "replace_me",
    "insert_here",
    "your_",
    "my_",
    "your-",
    "my-",
    "<your",
];

/// documentation file patterns
const DOC_EXTENSIONS: &[&str] = &["md", "rst", "adoc"];
const DOC_PREFIXES: &[&str] = &["readme", "changelog", "contributing", "license"];
const DOC_DIRS: &[&str] = &["docs/", "doc/", "documentation/", "wiki/"];

/// check if `haystack` contains `needle` at a word boundary.
/// ascii alphanumeric and non-ascii bytes are word characters; `_` and ascii
/// punctuation or separators act as boundaries. a boundary at a needle edge
/// self-delimits, while a word edge requires a non-word neighbor. this prevents
/// "test" from matching inside "attestation" but still matches "test_key".
/// special case: "xxx" matches any run of 3+ identical characters (placeholder pattern).
fn contains_word(haystack: &str, needle: &str) -> bool {
    fn is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b >= 0x80
    }

    if needle.is_empty() {
        return false;
    }
    // special case: "xxx" detects X-placeholder patterns like "XXXX..." or "xxxx..."
    if needle == "xxx" {
        let bytes = haystack.as_bytes();
        let mut run = 0u8;
        for &b in bytes {
            if b == b'x' || b == b'X' {
                run += 1;
                if run >= 3 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        return false;
    }
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while let Some(pos) = memmem::find(&haystack.as_bytes()[start..], needle_bytes) {
        let abs_pos = start + pos;
        let is_word_edge = |b: u8| is_word_byte(b);
        let before_ok = !is_word_edge(needle_bytes[0])
            || abs_pos == 0
            || !is_word_byte(haystack.as_bytes()[abs_pos - 1]);
        let end_pos = abs_pos + needle.len();
        let after_ok = !is_word_edge(needle_bytes[needle_bytes.len() - 1])
            || end_pos >= haystack.len()
            || !is_word_byte(haystack.as_bytes()[end_pos]);
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// variable reference patterns (compiled lazily)
const VAR_PATTERNS: &[&str] = &[
    // shell/unix: ${VAR}, $VAR
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$",
    r"^\$[A-Za-z_][A-Za-z0-9_]*$",
    // windows: %VAR%
    r"^%[A-Za-z_][A-Za-z0-9_]*%$",
    // template engines: {{var}}, {{ var }}, {{ var | filter }}, {{ .Values.x }}
    // requires first char after {{ to be a letter/dot/underscore (not a quote)
    // to avoid matching hardcoded secrets in jinja2 literals like {{ 'sk_live_...' }}
    r"^\{\{-?\s*[A-Za-z_.][^}]*\}\}$",
    // triple-mustache (unescaped): {{{var}}}
    r"^\{\{\{\s*[\w.]+\s*\}\}\}$",
    // github actions: ${{ secrets.X }}, ${{ env.VAR }}
    r"^\$\{\{\s*[A-Za-z_.][^}]*\}\}$",
    // erb/ejs: <%= expr %>, <%- expr %>
    r"^<%[=-]?\s*[A-Za-z_$@][^%]*-?%>$",
    // php short: <?= $var ?>
    r"^<\?=\s*\$\w[^?]*\?>$",
    // terraform: ${var.name}, ${data.x.y}, ${local.x}, ${module.x}
    r"^\$\{(?:var|data|local|module)\.\w[\w.]*\}$",
    // shell defaults: ${VAR:-default}, ${VAR:=value}, ${VAR:+alt}, ${VAR:?err}
    r"^\$\{[A-Za-z_]\w*[:][+\-=?][^}]*\}$",
    // angle-bracket placeholders: <YOUR_API_KEY>, <token>
    r"^<[A-Za-z][\w-]*>$",
    // single-brace placeholders: {password}, {api_key} (max 30 chars to avoid matching random strings)
    r"^\{[A-Za-z_][\w]{0,30}\}$",
    // pug/spring: #{var}
    r"^#\{[\w.]+\}$",
    // velocity: $!{var}, $!var
    r"^\$!\{?[\w.]+\}?$",
    // ognl/struts: %{expr}
    r"^%\{.+\}$",
    // c# string format: {0}, {1}
    r"^\{[0-9]+\}$",
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

/// max compiled regex size for user-supplied patterns (1 MB).
/// prevents ReDoS from crafted .sekretbarilo.toml config.
const USER_REGEX_SIZE_LIMIT: usize = 1 << 20;

/// build a regex from user-supplied pattern with size limits
fn build_user_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(USER_REGEX_SIZE_LIMIT)
        .build()
}

/// build a path regex that is auto-anchored at the start.
/// prevents patterns like "test/.*" from matching "src/contest/file".
fn build_user_path_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let anchored = if pattern.starts_with('^') {
        pattern.to_string()
    } else {
        format!("^{}", pattern)
    };
    build_user_regex(&anchored)
}

/// check whether a key allowlist pattern contains at least one literal
/// character, i.e. is not composed entirely of `*`/`?` wildcards (which
/// would match every key).
pub(crate) fn key_pattern_has_literal(pattern: &str) -> bool {
    pattern.chars().any(|ch| ch != '*' && ch != '?')
}

fn build_key_pattern_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty() {
        return Err("key allowlist patterns must not be empty".to_string());
    }
    if !key_pattern_has_literal(pattern) {
        return Err(format!(
            "key pattern '{}' matches every key; patterns need at least one literal character",
            pattern
        ));
    }

    let mut regex = String::from("^");
    let mut literal = String::new();
    for ch in pattern.chars() {
        match ch {
            '*' => {
                regex.push_str(&regex::escape(&literal));
                literal.clear();
                regex.push_str(".*");
            }
            '?' => {
                regex.push_str(&regex::escape(&literal));
                literal.clear();
                regex.push('.');
            }
            _ => literal.push(ch),
        }
    }
    regex.push_str(&regex::escape(&literal));
    regex.push('$');

    build_user_regex(&regex).map_err(|e| e.to_string())
}

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
    /// whether to detect public keys as findings (default: false)
    pub detect_public_keys: bool,
    /// whether exemption-layer filtering is enabled (default: true)
    /// controls the whole 0.7.0 generic-rule recall/exemption policy, including call literals.
    pub exemption_layer: bool,
    /// whether exemption decisions are emitted as diagnostic findings (default: false)
    pub trace_exemptions: bool,
    /// per-rule allowlist compiled regexes: maps rule_id -> (value_regexes, path_regexes, key_patterns)
    per_rule_allowlists: Vec<CompiledPerRuleAllowlist>,
}

impl CompiledAllowlist {
    /// create a new allowlist with default settings only
    #[allow(dead_code)]
    pub fn default_allowlist() -> Result<Self, String> {
        Self::new(&[], &[], None, &[], false)
    }

    /// create a compiled allowlist from user configuration
    pub fn new(
        user_paths: &[String],
        user_stopwords: &[String],
        entropy_override: Option<f64>,
        per_rule: &[(String, Vec<String>, Vec<String>)],
        detect_public_keys: bool,
    ) -> Result<Self, String> {
        let per_rule_with_keys: Vec<_> = per_rule
            .iter()
            .map(|(id, regexes, paths)| (id.clone(), regexes.clone(), paths.clone(), Vec::new()))
            .collect();
        Self::new_with_keys(
            user_paths,
            user_stopwords,
            entropy_override,
            &per_rule_with_keys,
            detect_public_keys,
        )
    }

    /// create a compiled allowlist from user configuration with per-rule key patterns
    pub fn new_with_keys(
        user_paths: &[String],
        user_stopwords: &[String],
        entropy_override: Option<f64>,
        per_rule: &[PerRuleAllowlistWithKeys],
        detect_public_keys: bool,
    ) -> Result<Self, String> {
        let mut var_ref_patterns = Vec::with_capacity(VAR_PATTERNS.len());
        for pattern in VAR_PATTERNS {
            let re = Regex::new(pattern)
                .map_err(|e| format!("failed to compile var ref pattern '{}': {}", pattern, e))?;
            var_ref_patterns.push(re);
        }

        let mut user_path_patterns = Vec::with_capacity(user_paths.len());
        for path_pattern in user_paths {
            let re = build_user_path_regex(path_pattern).map_err(|e| {
                format!(
                    "failed to compile user path pattern '{}': {}",
                    path_pattern, e
                )
            })?;
            user_path_patterns.push(re);
        }

        let mut per_rule_allowlists = Vec::with_capacity(per_rule.len());
        for (rule_id, value_regexes, path_regexes, key_patterns) in per_rule {
            if !key_patterns.is_empty() && rule_id != "generic-high-entropy-value" {
                return Err(format!(
                    "allowlist keys are only supported for rule 'generic-high-entropy-value', not '{}'",
                    rule_id
                ));
            }
            let mut compiled_values = Vec::new();
            for pattern in value_regexes {
                let re = build_user_regex(pattern).map_err(|e| {
                    format!(
                        "failed to compile allowlist regex for rule '{}': {}",
                        rule_id, e
                    )
                })?;
                compiled_values.push(re);
            }
            let mut compiled_paths = Vec::new();
            for pattern in path_regexes {
                let re = build_user_path_regex(pattern).map_err(|e| {
                    format!(
                        "failed to compile allowlist path for rule '{}': {}",
                        rule_id, e
                    )
                })?;
                compiled_paths.push(re);
            }
            let mut compiled_keys = Vec::new();
            for pattern in key_patterns {
                let re = build_key_pattern_regex(pattern).map_err(|e| {
                    format!(
                        "failed to compile allowlist key pattern '{}' for rule '{}': {}",
                        pattern, rule_id, e
                    )
                })?;
                compiled_keys.push(re);
            }
            per_rule_allowlists.push((
                rule_id.clone(),
                compiled_values,
                compiled_paths,
                compiled_keys,
            ));
        }

        Ok(Self {
            var_ref_patterns,
            user_path_patterns,
            user_stopwords: user_stopwords.iter().map(|s| s.to_lowercase()).collect(),
            entropy_threshold_override: entropy_override,
            detect_public_keys,
            exemption_layer: true,
            trace_exemptions: false,
            per_rule_allowlists,
        })
    }

    // wired in the exemption-layer glue
    #[allow(dead_code)]
    /// returns whether a line is an import declaration eligible for exemption.
    pub fn is_import_line(&self, line: &[u8]) -> bool {
        const IMPORT_KEYWORDS: &[&[u8]] = &[
            b"import",
            b"from",
            b"use",
            b"package",
            b"require",
            b"#include",
            b"extern crate",
            b"using",
            b"@import",
            b"@use",
        ];

        let line = line.trim_ascii_start();
        let has_keyword = IMPORT_KEYWORDS.iter().any(|&keyword| {
            line.strip_prefix(keyword).is_some_and(|rest| {
                rest.first()
                    .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(')
            })
        });
        if !has_keyword || line.contains(&b'=') {
            return false;
        }

        !line.iter().enumerate().any(|(index, &byte)| {
            byte == b':'
                && (index == 0 || line[index - 1] != b':')
                && (index + 1 == line.len() || line[index + 1] != b':')
        })
    }

    // wired in the exemption-layer glue
    #[allow(dead_code)]
    /// returns whether a path skips generic-rule matching for exemption purposes.
    pub fn is_generic_rule_skipped_path(&self, path: &str) -> bool {
        let filename = path.rsplit('/').next().unwrap_or(path);
        GENERIC_ONLY_FILES.contains(&filename) || filename.eq_ignore_ascii_case("CODEOWNERS")
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

        // skip specific generated files (case-insensitive)
        for gen_file in GENERATED_FILES {
            if filename.eq_ignore_ascii_case(gen_file) {
                return true;
            }
        }

        // skip vendor directories (case-insensitive for macOS/Windows)
        // require path boundary: must start with the vendor dir or be preceded by '/'
        for vendor_dir in VENDOR_DIRS {
            if lower.starts_with(vendor_dir) {
                return true;
            }
            // check for /vendor_dir/ in middle of path without allocation
            if let Some(pos) = lower.find(vendor_dir)
                && pos > 0
                && lower.as_bytes()[pos - 1] == b'/'
            {
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

    /// check if the captured secret value contains a stopword.
    /// uses word-boundary matching to avoid false positives where a stopword
    /// appears as a substring of an unrelated word (e.g. "test" in "attestation").
    pub fn contains_stopword(&self, secret: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(secret).to_lowercase();

        for stopword in DEFAULT_STOPWORDS {
            if contains_word(&lower, stopword) {
                return true;
            }
        }

        for stopword in &self.user_stopwords {
            if contains_word(&lower, stopword.as_str()) {
                return true;
            }
        }

        false
    }

    /// match explicit user stopwords as case-insensitive substrings of opaque values.
    pub fn contains_user_stopword(&self, secret: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(secret).to_lowercase();
        self.user_stopwords
            .iter()
            .any(|stopword| !stopword.is_empty() && lower.contains(stopword.as_str()))
    }

    /// check if the captured secret is a placeholder pattern (e.g. XXXX...).
    /// this is a subset of the stopword check that applies to all rules,
    /// including tier 1 prefix-based rules.
    pub fn is_placeholder_pattern(&self, secret: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(secret).to_lowercase();
        contains_word(&lower, "xxx")
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

    /// check if a line contains template syntax markers.
    /// looks for jinja2/django/mustache/handlebars variable tags ({{...}}),
    /// block tags ({%...%}), comment tags ({#...#}),
    /// erb/ejs tags (<%...%>), and php short echo tags (<?=...?>).
    /// used to skip tier 2/3 findings on lines that are clearly templates.
    pub fn is_template_line(&self, line: &[u8]) -> bool {
        // jinja2/django/mustache/handlebars variable tags: {{ ... }}
        if memmem::find(line, b"{{").is_some() && memmem::find(line, b"}}").is_some() {
            return true;
        }
        // jinja2/django/twig block tags: {% ... %}
        if memmem::find(line, b"{%").is_some() && memmem::find(line, b"%}").is_some() {
            return true;
        }
        // jinja2/django comment tags: {# ... #}
        if memmem::find(line, b"{#").is_some() && memmem::find(line, b"#}").is_some() {
            return true;
        }
        // erb/ejs tags: <% ... %>
        if memmem::find(line, b"<%").is_some() && memmem::find(line, b"%>").is_some() {
            return true;
        }
        // php short echo tag: <?= ... ?> (template shorthand only, not <?php)
        if memmem::find(line, b"<?=").is_some() && memmem::find(line, b"?>").is_some() {
            return true;
        }
        false
    }

    /// check if the file is a documentation file
    pub fn is_documentation_file(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        let filename = lower.rsplit('/').next().unwrap_or(&lower);

        // check doc file extensions
        if let Some(ext) = filename.rsplit('.').next()
            && DOC_EXTENSIONS.contains(&ext)
        {
            return true;
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
            if let Some(pos) = lower.find(dir)
                && pos > 0
                && lower.as_bytes()[pos - 1] == b'/'
            {
                return true;
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
    pub fn is_rule_allowlisted(&self, rule_id: &str, secret: &[u8], file_path: &str) -> bool {
        self.rule_allowlisted(rule_id, secret, Some(file_path))
    }

    /// check value exclusions without applying any file path exclusions.
    pub fn is_rule_value_allowlisted(&self, rule_id: &str, secret: &[u8]) -> bool {
        self.rule_allowlisted(rule_id, secret, None)
    }

    fn rule_allowlisted(&self, rule_id: &str, secret: &[u8], file_path: Option<&str>) -> bool {
        for (id, value_regexes, path_regexes, _) in &self.per_rule_allowlists {
            if id == rule_id {
                // check value regexes
                for re in value_regexes {
                    if re.is_match(secret) {
                        return true;
                    }
                }
                // check path regexes
                if let Some(file_path) = file_path {
                    for re in path_regexes {
                        if re.is_match(file_path.as_bytes()) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// check whether a generic entropy assignment key is explicitly allowlisted.
    pub fn is_entropy_key_allowlisted(&self, key: &[u8]) -> bool {
        self.per_rule_allowlists
            .iter()
            .any(|(rule_id, _, _, key_patterns)| {
                rule_id == "generic-high-entropy-value"
                    && key_patterns.iter().any(|pattern| pattern.is_match(key))
            })
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
        assert!(al.is_path_skipped("bun.lock"));
        assert!(al.is_path_skipped("uv.lock"));
        assert!(al.is_path_skipped("flake.lock"));
        assert!(al.is_path_skipped("Package.resolved"));
        assert!(al.is_path_skipped(".terraform.lock.hcl"));
        assert!(al.is_path_skipped("terraform/grafana/.terraform.lock.hcl"));
        assert!(al.is_path_skipped("npm-shrinkwrap.json"));
        assert!(al.is_path_skipped("packages.lock.json"));
        assert!(!al.is_path_skipped("Gopkg.toml"));
    }

    #[test]
    fn generic_rule_skipped_paths() {
        let al = default_al();
        assert!(al.is_generic_rule_skipped_path(".gitignore"));
        assert!(al.is_generic_rule_skipped_path(".dockerignore"));
        assert!(al.is_generic_rule_skipped_path(".npmignore"));
        assert!(al.is_generic_rule_skipped_path(".prettierignore"));
        assert!(al.is_generic_rule_skipped_path(".eslintignore"));
        assert!(al.is_generic_rule_skipped_path(".gitattributes"));
        assert!(al.is_generic_rule_skipped_path(".helmignore"));
        assert!(al.is_generic_rule_skipped_path("docs/.gitignore"));
        assert!(al.is_generic_rule_skipped_path(".github/CODEOWNERS"));
        assert!(al.is_generic_rule_skipped_path("codeowners"));
        assert!(al.is_generic_rule_skipped_path("CODEOWNERS"));
        assert!(!al.is_generic_rule_skipped_path("gitignore"));
        assert!(!al.is_generic_rule_skipped_path(".gitignore.bak"));
        assert!(!al.is_generic_rule_skipped_path("x/.gitignored"));
    }

    #[test]
    fn skip_generated_extensions() {
        let al = default_al();
        assert!(al.is_path_skipped("app.min.js"));
        assert!(al.is_path_skipped("style.min.css"));
        assert!(al.is_path_skipped("bundle.js.map"));
        assert!(al.is_path_skipped("style.css.map"));
        // plain .map files should NOT be skipped
        assert!(!al.is_path_skipped("data.map"));
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
            &[
                "test/fixtures/.*".to_string(),
                "docs/examples/.*".to_string(),
            ],
            &[],
            None,
            &[],
            false,
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
        assert!(al.contains_stopword(b"your_secret_key_value_x1"));
        assert!(al.contains_stopword(b"my_super_secret_key_xyz1"));
        assert!(al.contains_stopword(b"your-secret-key-value-x1"));
        assert!(al.contains_stopword(b"my-api-key-here-x1"));
        assert!(!al.contains_stopword(b"myyour_x"));
        assert!(!al.contains_stopword(b"AKIAIOSFODNN7REALKEY"));
    }

    #[test]
    fn non_ascii_stopword_edges_require_boundaries() {
        let al = CompiledAllowlist::new(&[], &["é".into()], None, &[], false).unwrap();
        assert!(!al.contains_stopword("aébA1cD2fG3hJ4kL5".as_bytes()));
        assert!(al.contains_stopword("aéb é".as_bytes()));
    }

    #[test]
    fn digit_stopword_edges_require_boundaries() {
        let al = CompiledAllowlist::new(&[], &["key1".into()], None, &[], false).unwrap();
        assert!(!al.contains_stopword(b"key12"));
    }

    #[test]
    fn delimiter_terminated_default_stopwords_remain_matches() {
        let al = default_al();
        assert!(al.contains_stopword(b"your_password"));
        assert!(al.contains_stopword(b"my-secret"));
    }

    #[test]
    fn ascii_stopwords_keep_expected_boundary_behavior() {
        let al = default_al();
        assert!(al.contains_stopword(b"test_key"));
        assert!(al.contains_stopword(b"TEST-value"));
        assert!(!al.contains_stopword(b"latest"));
    }

    #[test]
    fn import_lines_are_eligible_for_exemption() {
        let al = default_al();
        assert!(al.is_import_line(b"use foo::bar;"));
        assert!(al.is_import_line(b"import { a as b } from './c';"));
        assert!(al.is_import_line(b"from x import y"));
        assert!(al.is_import_line(b"package main"));
        assert!(al.is_import_line(b"require(\"left-pad\")"));
        assert!(al.is_import_line(b"#include <stdio.h>"));
        assert!(al.is_import_line(b"extern crate serde;"));
        assert!(al.is_import_line(b"using System.Text;"));
        assert!(al.is_import_line(b"  import os"));
        assert!(al.is_import_line(b"@import \"styles.css\";"));
        assert!(al.is_import_line(b"@use \"theme\";"));
        assert!(!al.is_import_line(b"import_key=abcXYZ123"));
        assert!(!al.is_import_line(b"from: user@example.com"));
        assert!(!al.is_import_line(b"use this key: value"));
        assert!(!al.is_import_line(b"uses: actions/checkout@v4"));
        assert!(!al.is_import_line(b"imports = [...]"));
        assert!(!al.is_import_line(b"importantly, nothing"));
        assert!(!al.is_import_line(b"import x; TOKEN=placeholder"));
        assert!(!al.is_import_line(b"used = 1"));
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
            false,
        )
        .unwrap();
        assert!(al.contains_stopword(b"my-safe-token-12345"));
        assert!(al.contains_stopword(b"the-internal-key-here"));
        assert!(!al.contains_stopword(b"real-production-secret"));
    }

    #[test]
    fn user_only_stopwords_match_case_insensitive_substrings() {
        let al = CompiledAllowlist::new(&[], &["SaFe".into()], None, &[], false).unwrap();
        assert!(al.contains_user_stopword(b"SAFE_token"));
        assert!(al.contains_user_stopword(b"safeguard"));
        assert!(al.contains_user_stopword(b"prefixSAFEsuffix"));
        assert!(!al.contains_stopword(b"safeguard"));
        assert!(!al.contains_user_stopword(b"example_token"));
        assert!(!al.contains_user_stopword(b"XXX_token"));
        assert!(al.contains_stopword(b"example_token"));
        assert!(al.contains_stopword(b"XXX_token"));
        let explicit = CompiledAllowlist::new(&[], &["example".into()], None, &[], false).unwrap();
        assert!(explicit.contains_user_stopword(b"EXAMPLE_token"));
        let empty = CompiledAllowlist::new(&[], &[String::new()], None, &[], false).unwrap();
        assert!(!empty.contains_user_stopword(b"opaque_value"));
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
            false,
        )
        .unwrap();
        assert!(al.is_rule_allowlisted("aws-access-key-id", b"AKIAIOSFODNN7EXAMPLE", "config.py"));
        assert!(!al.is_rule_allowlisted("aws-access-key-id", b"AKIAIOSFODNN7REALKEY", "config.py"));
    }

    #[test]
    fn per_rule_key_allowlist_uses_case_sensitive_whole_key_patterns() {
        let al = CompiledAllowlist::new_with_keys(
            &[],
            &[],
            None,
            &[(
                "generic-high-entropy-value".to_string(),
                vec![],
                vec![],
                vec![
                    "TMPDIR".to_string(),
                    "GHOSTTY_*".to_string(),
                    "XPC_SERVICE_?AME".to_string(),
                    "A.B".to_string(),
                ],
            )],
            false,
        )
        .unwrap();

        assert!(al.is_entropy_key_allowlisted(b"TMPDIR"));
        assert!(!al.is_entropy_key_allowlisted(b"TMPDIR2"));
        assert!(!al.is_entropy_key_allowlisted(b"XTMPDIR"));
        assert!(!al.is_entropy_key_allowlisted(b"tmpdir"));
        assert!(al.is_entropy_key_allowlisted(b"GHOSTTY_RESOURCES_DIR"));
        assert!(al.is_entropy_key_allowlisted(b"XPC_SERVICE_NAME"));
        assert!(!al.is_entropy_key_allowlisted(b"XPC_SERVICE_NNAME"));
        assert!(al.is_entropy_key_allowlisted(b"A.B"));
        assert!(!al.is_entropy_key_allowlisted(b"AXB"));
    }

    #[test]
    fn per_rule_key_allowlist_rejects_wildcard_only_patterns() {
        for bad_pattern in ["*", "**", "?"] {
            let err = CompiledAllowlist::new_with_keys(
                &[],
                &[],
                None,
                &[(
                    "generic-high-entropy-value".to_string(),
                    vec![],
                    vec![],
                    vec![bad_pattern.to_string()],
                )],
                false,
            )
            .err()
            .unwrap();
            assert!(
                err.contains("matches every key"),
                "pattern '{}' should be rejected, got: {}",
                bad_pattern,
                err
            );
        }
    }

    #[test]
    fn per_rule_key_allowlist_accepts_patterns_with_a_literal_character() {
        let al = CompiledAllowlist::new_with_keys(
            &[],
            &[],
            None,
            &[(
                "generic-high-entropy-value".to_string(),
                vec![],
                vec![],
                vec!["TMP*".to_string(), "*_SOCK".to_string(), "A?B".to_string()],
            )],
            false,
        )
        .unwrap();
        assert!(al.is_entropy_key_allowlisted(b"TMPDIR"));
        assert!(al.is_entropy_key_allowlisted(b"SSH_AUTH_SOCK"));
        assert!(al.is_entropy_key_allowlisted(b"AXB"));
    }

    #[test]
    fn per_rule_key_allowlist_rejects_empty_patterns_and_unsupported_rules() {
        let empty = CompiledAllowlist::new_with_keys(
            &[],
            &[],
            None,
            &[(
                "generic-high-entropy-value".to_string(),
                vec![],
                vec![],
                vec![String::new()],
            )],
            false,
        )
        .err()
        .unwrap();
        assert!(empty.contains("must not be empty"));

        let unsupported = CompiledAllowlist::new_with_keys(
            &[],
            &[],
            None,
            &[(
                "aws-access-key-id".to_string(),
                vec![],
                vec![],
                vec!["TMPDIR".to_string()],
            )],
            false,
        )
        .err()
        .unwrap();
        assert!(unsupported.contains("only supported"));
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
            false,
        )
        .unwrap();
        assert!(al.is_rule_allowlisted(
            "generic-api-key",
            b"some-api-key-value",
            "test/fixtures/keys.yml"
        ));
        assert!(!al.is_rule_allowlisted("generic-api-key", b"some-api-key-value", "src/config.rs"));
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
            false,
        )
        .unwrap();
        // different rule id should not match
        assert!(!al.is_rule_allowlisted("github-token", b"AKIAIOSFODNN7EXAMPLE", "config.py"));
    }

    // -- documentation file tests (5.4) --

    #[test]
    fn detect_doc_by_extension() {
        let al = default_al();
        assert!(al.is_documentation_file("README.md"));
        assert!(al.is_documentation_file("docs/guide.rst"));
        assert!(al.is_documentation_file("path/to/file.adoc"));
        // .txt is intentionally NOT a doc extension to avoid weakening scans on files like secrets.txt
        assert!(!al.is_documentation_file("NOTES.txt"));
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

    // -- expanded template variable reference tests --

    #[test]
    fn detect_jinja2_helm_templates() {
        let al = default_al();
        // jinja2 with filters
        assert!(al.is_variable_reference(b"{{ password | default('') }}"));
        // helm: .Values.x
        assert!(al.is_variable_reference(b"{{ .Values.database.password }}"));
        // go template function
        assert!(al.is_variable_reference(b"{{ include \"mychart.name\" . }}"));
        // trim whitespace markers
        assert!(al.is_variable_reference(b"{{- .Values.secret -}}"));
    }

    #[test]
    fn detect_triple_mustache() {
        let al = default_al();
        assert!(al.is_variable_reference(b"{{{password}}}"));
        assert!(al.is_variable_reference(b"{{{ api.key }}}"));
    }

    #[test]
    fn detect_github_actions_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"${{ secrets.API_KEY }}"));
        assert!(al.is_variable_reference(b"${{ env.DATABASE_URL }}"));
        assert!(al.is_variable_reference(b"${{ github.token }}"));
    }

    #[test]
    fn detect_erb_ejs_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"<%= ENV['SECRET_KEY'] %>"));
        assert!(al.is_variable_reference(b"<%- config.password %>"));
        assert!(al.is_variable_reference(b"<% db_password %>"));
    }

    #[test]
    fn detect_php_short_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"<?= $db_password ?>"));
    }

    #[test]
    fn jinja2_literal_secrets_not_skipped() {
        let al = default_al();
        // hardcoded secrets inside {{ }} should NOT be treated as var refs
        assert!(!al.is_variable_reference(b"{{ 'sk_live_real_secret_key_here' }}"));
        assert!(!al.is_variable_reference(b"{{ \"ghp_ABCDEFreal1234567890abcde\" }}"));
    }

    #[test]
    fn detect_terraform_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"${var.db_password}"));
        assert!(al.is_variable_reference(b"${data.aws_ssm.secret}"));
        assert!(al.is_variable_reference(b"${local.api_key}"));
        assert!(al.is_variable_reference(b"${module.auth.token}"));
    }

    #[test]
    fn detect_shell_defaults() {
        let al = default_al();
        assert!(al.is_variable_reference(b"${DB_PASSWORD:-default}"));
        assert!(al.is_variable_reference(b"${API_KEY:=fallback}"));
        assert!(al.is_variable_reference(b"${TOKEN:+alternate}"));
        assert!(al.is_variable_reference(b"${SECRET:?error msg}"));
    }

    #[test]
    fn detect_angle_bracket_placeholders() {
        let al = default_al();
        assert!(al.is_variable_reference(b"<YOUR_API_KEY>"));
        assert!(al.is_variable_reference(b"<token>"));
        assert!(al.is_variable_reference(b"<api-key>"));
    }

    #[test]
    fn detect_single_brace_placeholders() {
        let al = default_al();
        assert!(al.is_variable_reference(b"{password}"));
        assert!(al.is_variable_reference(b"{api_key}"));
    }

    #[test]
    fn detect_pug_spring_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"#{db.password}"));
        assert!(al.is_variable_reference(b"#{apiKey}"));
    }

    #[test]
    fn detect_velocity_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"$!{password}"));
        assert!(al.is_variable_reference(b"$!apiKey"));
    }

    #[test]
    fn detect_ognl_struts_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"%{secret}"));
        assert!(al.is_variable_reference(b"%{#session.token}"));
    }

    #[test]
    fn detect_csharp_format_refs() {
        let al = default_al();
        assert!(al.is_variable_reference(b"{0}"));
        assert!(al.is_variable_reference(b"{1}"));
    }

    // -- template line detection tests --

    #[test]
    fn detect_template_lines() {
        let al = default_al();
        // jinja2/mustache/handlebars variable tags
        assert!(al.is_template_line(
            b"JICOFO_COMPONENT_SECRET: \"{{ jitsi_secret_map['JICOFO_COMPONENT_SECRET'] }}\""
        ));
        assert!(al.is_template_line(b"password: {{ db_password }}"));
        assert!(al.is_template_line(b"api_key = \"{{ lookup('vault', 'secret/key') }}\""));
        // jinja2 block tags
        assert!(al.is_template_line(b"{% if use_ssl %}password = {{ db_pass }}{% endif %}"));
        assert!(al.is_template_line(b"{% set api_key = vault_lookup('key') %}"));
        // jinja2 comment tags
        assert!(al.is_template_line(b"{# this sets the database password #}"));
        // erb tags
        assert!(
            al.is_template_line(b"<% if Rails.env.production? %>secret = <%= secret %><% end %>")
        );
        // php short echo tag (template shorthand)
        assert!(al.is_template_line(b"<?= $db_password ?>"));
        // regular <?php ... ?> is NOT a template marker (it's normal PHP code)
        assert!(!al.is_template_line(b"<?php echo $config['password']; ?>"));
    }

    #[test]
    fn non_template_lines_not_detected() {
        let al = default_al();
        assert!(!al.is_template_line(b"password = \"my_actual_secret_123\""));
        assert!(!al.is_template_line(b"api_key = \"sk_live_abc123def456\""));
        // partial markers should not match
        assert!(!al.is_template_line(b"x = 5 % 3 # modulo"));
        assert!(!al.is_template_line(b"price < 100"));
        // single braces are not template markers
        assert!(!al.is_template_line(b"let map = { password: \"secret\" };"));
    }
}
