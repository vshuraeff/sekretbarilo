// core scanning engine (aho-corasick + regex)

use rayon::prelude::*;
use std::ops::Range;

#[allow(unused_imports)]
pub use crate::scanner::text::{TextMatch, redact_text, scan_text};

use crate::config::SourcePosture;
use crate::config::allowlist::CompiledAllowlist;
use crate::diff::parser::DiffFile;
use crate::scanner::entropy;
use crate::scanner::hash_detect;
use crate::scanner::literals::{LineLiterals, LiteralTracker};
use crate::scanner::password;
use crate::scanner::pubkey;
use crate::scanner::rules::{CaptureIndices, CompiledScanner};
use crate::scanner::source_literals::{BodyKind, ParsedLine};

/// minimum number of files to trigger parallel processing with rayon
const PARALLEL_FILE_THRESHOLD: usize = 4;

/// the keywordless tier-3 rule that the exemption layer and the source postures govern.
const ENTROPY_RULE: &str = "generic-high-entropy-value";

/// the contextual rules that read a value under a credential name (`API_KEY`, `*_TOKEN`,
/// `*_SECRET`) in quoted and unquoted form.
const NAMED_KEY_RULES: [&str; 3] = [
    "generic-api-key",
    "generic-secret-assignment",
    "generic-token-assignment",
];

/// the share of distinct bytes, letters folded to one case, at or above which a value of token
/// length that clears its rule's entropy threshold is never taken for a source expression.
/// a member chain repeats the letters of its words and of the credential name it reads
/// (`config.providers.anthropic.api_key` 0.56, `os.environ.GITHUB_TOKEN` 0.65,
/// `app.config.SECRET_KEY` 0.76 at 3.98 bits, which the 3.5-bit secret rule would report); the
/// case fold keeps `settings.DJANGO_SECRET_KEY` at 0.62 rather than the 0.81 its mixed case gives.
/// the guard protects a value that clears its threshold with that many distinct bytes, such as a
/// random single-case value of 20 or 21 bytes over a 4.0-bit threshold, which needs 17 distinct
/// (`plmoknijuh.bqygtverfc` is 1.0). a longer random single-case value clears 4.0 bits with fewer
/// (17 of 24 is 0.71), as does one of 20 bytes over 3.5 bits (about 13 of 20), so those rest on
/// `wordlike_piece` alone; a random mixed-case value fails `wordlike_piece` before this matters.
const NEAR_DISTINCT_RATIO: f64 = 0.8;

/// an unquoted named value that reads as code or words, not a credential: a member chain or index
/// (`self.data.api_key`, `text[token_start`), a type or other identifier (`SecretStr`) or a name
/// made of words (`ingress-tls-secret`), optionally ending in a call-argument or statement `,`/`;`.
/// the shape is not enough: every alphanumeric piece must read as words or be a number, the value
/// must carry at least two letter words, or one below `LONE_WORD_MAX_LEN` bytes, so a lone letter
/// run of token length is never one, and no run of short groups may cross it. a value that could be a token standing alone (`MIN_ENTROPY_LENGTH` bytes
/// or more, the rule's own `entropy_floor` cleared, bytes near-distinct under
/// `NEAR_DISTINCT_RATIO`) is never one, whatever its pieces read as.
fn is_source_expression_value(
    value: &[u8],
    entropy_floor: Option<f64>,
    secret_reference_key: bool,
) -> bool {
    use crate::scanner::wordshape;
    let value = value
        .strip_suffix(b",")
        .or_else(|| value.strip_suffix(b";"))
        .unwrap_or(value);
    if !secret_reference_key
        && value.len() >= entropy::MIN_ENTROPY_LENGTH
        && entropy_floor.is_none_or(|threshold| entropy::shannon_entropy(value) >= threshold)
        && folded_distinct_ratio(value) >= NEAR_DISTINCT_RATIO
    {
        return false;
    }
    let mut letter_words = 0;
    for piece in value
        .split(|b| !b.is_ascii_alphanumeric())
        .filter(|piece| !piece.is_empty())
    {
        if piece.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Some(words) = wordshape::wordlike_piece(piece) else {
            return false;
        };
        letter_words += words.long + words.short + words.vowelless;
    }
    // a lone word is a word value only under the api and token rules' 16-byte minimum, where
    // the secret rule reads a chart's secret name (`existingSecret: postgresql`) or a bullet
    // (`- secret: required`); a longer lone letter run may be a token.
    (letter_words >= 2 || (letter_words == 1 && value.len() < LONE_WORD_MAX_LEN))
        // recall guard: an opaque value cut into short groups reads as words piece by piece
        && !wordshape::is_chunked_with_digits(value, b"")
}

/// whether the matched unquoted assignment names a secret reference rather than a secret value.
fn is_secret_reference_assignment(prefix: &[u8]) -> bool {
    fn compact_suffix(key: &[u8], suffix: &[u8]) -> bool {
        let mut bytes = key
            .iter()
            .rev()
            .filter(|byte| !matches!(**byte, b'_' | b'-'));
        suffix.iter().rev().all(|expected| {
            bytes
                .next()
                .is_some_and(|byte| byte.eq_ignore_ascii_case(expected))
        })
    }

    let prefix = prefix.trim_ascii_end();
    let prefix = prefix
        .strip_suffix(b":=")
        .or_else(|| prefix.strip_suffix(b"="))
        .or_else(|| prefix.strip_suffix(b":"))
        .unwrap_or(prefix)
        .trim_ascii_end();
    let key = prefix
        .rsplit(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
        .next()
        .unwrap_or_default();
    (key.get(..8)
        .is_some_and(|start| start.eq_ignore_ascii_case(b"existing"))
        && compact_suffix(key, b"secret"))
        || compact_suffix(key, b"secretname")
        || compact_suffix(key, b"secretref")
        || compact_suffix(key, b"secretkeyref")
}

/// the length below which one word alone reads as a word value (`is_source_expression_value`).
const LONE_WORD_MAX_LEN: usize = 16;

/// distinct bytes over length, ascii letters folded to lowercase.
fn folded_distinct_ratio(value: &[u8]) -> f64 {
    let mut seen = [false; 256];
    let mut distinct = 0_usize;
    for byte in value {
        let slot = &mut seen[usize::from(byte.to_ascii_lowercase())];
        if !*slot {
            *slot = true;
            distinct += 1;
        }
    }
    distinct as f64 / value.len().max(1) as f64
}

/// whether the unquoted value ending at `end` ends its word: the input ends there, or whitespace
/// or nul follows. the value class stops at a quote, backtick, `(` or non-ascii byte, and a value cut
/// there would be a prefix of the word, so the alternative is not read at all.
fn ends_word(input: &[u8], end: usize) -> bool {
    input
        .get(end)
        .is_none_or(|byte| byte.is_ascii_whitespace() || *byte == b'\0')
}

/// a detected secret finding
#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub matched_value: Vec<u8>,
}

/// scan parsed diff files for secrets using the compiled scanner.
/// this is the main entry point for the scanning engine.
///
/// pipeline per line:
///   1. global path allowlist (skip binary, vendor, generated files)
///   2. aho-corasick keyword pre-filter (single pass)
///   3. regex matching (keywordless rules and rules whose keywords matched)
///   4. extract secret via capture group
///      4a. source posture: classify paths only with path filters enabled; known
///      literal context gates code independently of exemption_layer. file/testpath
///      skips require exemption_layer; effective test-path skipping requires
///      apply_path_filters && exemption_layer && heuristic_skip_test_paths.
///      regex candidates own exactly matching normalized literal bodies, including
///      suppressed candidates; other bodies are evaluated without key context.
///      scan uses staged context; audit/check-file use their full file context;
///      history and other callers without context feed added lines only. unknown
///      lexical state or missing context lines always retain full posture.
///      4b. entropy value shape gates, switchable exemptions and assignment hex bypass
///      with a fixed 2.0-bit hex-symbol entropy floor
///      4c. user entropy-key allowlist (independent of the exemption switch)
///      4d. the unquoted `KEY=value` / `key: value` alternative of the named-key contextual
///      rules drops a word it read only in part and a path-shaped, reference-rooted, code or
///      word value (independent of the exemption switch)
///   5. per-rule allowlist check (value regex + path match)
///   6. variable references (URL passwords skip pure references only, not defaults)
///      6.5. template lines skip context-dependent and password/credential rules
///   7. stopwords (entropy values use user words; URL passwords use user words
///      and URL placeholders only; other rules retain their tier-specific filters)
///   8. hash detection (skip if it's a hash)
///      8.5. password strength veto for generic-password-assignment only
///      8.6. credential strength with entropy fallback; 8.7. public key filtering
///   9. entropy evaluation (with doc file bonus if applicable), except assignment
///      passwords, layer-enabled hex bypass values and exact-length hex values of the
///      named-key contextual rules; URL passwords use their
///      configured threshold, if any, without a password-strength veto
///
/// for diffs with many files, processing is parallelized with rayon.
pub fn scan(
    files: &[DiffFile],
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<Finding> {
    // filter to scannable files first (early exit for binary, deleted, allowlisted)
    let scannable: Vec<&DiffFile> = files
        .iter()
        .filter(|f| !f.is_deleted && !f.is_binary && !f.added_lines.is_empty())
        .filter(|f| !allowlist.is_path_skipped(&f.path))
        .collect();

    if scannable.is_empty() {
        return Vec::new();
    }

    // use parallel processing for large diffs
    if scannable.len() >= PARALLEL_FILE_THRESHOLD {
        let mut findings: Vec<Finding> = scannable
            .par_iter()
            .flat_map(|file| scan_file(file, scanner, allowlist))
            .collect();
        findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        findings
    } else {
        let mut findings = Vec::new();
        for file in &scannable {
            findings.extend(scan_file(file, scanner, allowlist));
        }
        findings
    }
}

/// scan traversal or outside-cwd patch paths without any path allowlist filtering.
/// called by codex apply_patch traversal handling in src/agent/codex.rs because
/// these paths must never be exempted by the normal path-filtering pipeline.
pub(crate) fn scan_without_path_filters(
    files: &[DiffFile],
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<Finding> {
    files
        .iter()
        .filter(|file| !file.is_deleted && !file.is_binary && !file.added_lines.is_empty())
        .flat_map(|file| scan_file_with_path_filters(file, scanner, allowlist, false))
        .collect()
}

/// scan a single file's added lines for secrets.
/// returns findings for this file only.
fn scan_file(
    file: &DiffFile,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<Finding> {
    scan_file_with_path_filters(file, scanner, allowlist, true)
}

fn scan_file_with_path_filters(
    file: &DiffFile,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
    apply_path_filters: bool,
) -> Vec<Finding> {
    // the documentation bonus is derived from the path, so a traversal path such as
    // docs/../src/x.rs must not raise the threshold: it applies only with path filters
    let is_doc = apply_path_filters && allowlist.is_documentation_file(&file.path);
    let generic_rule_skip = apply_path_filters
        .then(|| allowlist.generic_rule_skip(&file.path))
        .flatten();
    let language = apply_path_filters
        .then(|| crate::scanner::literals::language_for_path(&file.path))
        .flatten();
    let mut added_lines: Vec<_> = file.added_lines.iter().collect();
    added_lines.sort_by_key(|line| line.line_number);
    let mut literals = std::collections::HashMap::new();
    // parser posture: proved literal bodies and their kinds, per added line.
    let mut parsed_lines = std::collections::HashMap::new();
    let filter_literal_findings =
        apply_path_filters && crate::scanner::source_literals::supports_path(&file.path);
    if filter_literal_findings
        && allowlist.effective_source_posture() == SourcePosture::Literals
        && let Some(full) = &file.context
        && let Some(mut parsed) =
            crate::scanner::source_literals::analyze_with_kinds(&file.path, full)
    {
        let full_lines: Vec<_> = full.split(|&byte| byte == b'\n').collect();
        let exact_context = added_lines.iter().all(|added| {
            added
                .line_number
                .checked_sub(1)
                .and_then(|index| full_lines.get(index))
                .is_some_and(|line| {
                    line.strip_suffix(b"\r").unwrap_or(line)
                        == added.content.strip_suffix(b"\r").unwrap_or(&added.content)
                })
        }) && !added_lines
            .windows(2)
            .any(|pair| pair[0].line_number == pair[1].line_number);
        if exact_context {
            for added in &added_lines {
                if let Some(line) = parsed.get_mut(added.line_number - 1).and_then(Option::take) {
                    parsed_lines.insert(added.line_number, line);
                }
            }
        }
    }
    if let Some(language) = language
        && allowlist.effective_source_posture() == SourcePosture::Literals
    {
        let mut tracker = LiteralTracker::new(language);
        // tracker recovery cannot prove the state before a gap or lexical failure.
        let mut known = true;
        if let Some(full) = &file.context {
            let mut added = added_lines.iter().peekable();
            for (index, line) in full.split(|&byte| byte == b'\n').enumerate() {
                let number = index + 1;
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let line_literals = tracker.feed(line, number);
                known &= line_literals.known && tracker.is_known();
                while added.peek().is_some_and(|line| line.line_number < number) {
                    known = false;
                    added.next();
                }
                if let Some(added_line) = added.next_if(|line| line.line_number == number) {
                    known &= line
                        == added_line
                            .content
                            .strip_suffix(b"\r")
                            .unwrap_or(&added_line.content);
                    known &= !added.peek().is_some_and(|line| line.line_number == number);
                    if known {
                        literals.insert(number, line_literals);
                    }
                }
            }
        } else {
            for line in &added_lines {
                let content = line.content.strip_suffix(b"\r").unwrap_or(&line.content);
                let line_literals = tracker.feed(content, line.line_number);
                known &= line_literals.known && tracker.is_known();
                if known {
                    literals.insert(line.line_number, line_literals);
                }
            }
        }
    }
    // duplicate line numbers do not provide unambiguous lexical context.
    for pair in added_lines.windows(2) {
        if pair[0].line_number == pair[1].line_number {
            literals.remove(&pair[0].line_number);
            parsed_lines.remove(&pair[0].line_number);
        }
    }
    let num_rules = scanner.rules.len();

    // reusable bitset for candidate rules (avoids per-line vec allocation)
    let mut candidate_bits = vec![false; num_rules];
    let mut findings = Vec::new();
    let mut pubkey_tracker = pubkey::PubKeyBlockTracker::new();

    for added_line in &file.added_lines {
        // track PEM/PGP public key blocks across lines
        let in_pubkey_block = pubkey_tracker.feed_line(&added_line.content);

        // skip lines inside public key blocks (suppress false positives)
        // unless detect_public_keys is enabled
        if in_pubkey_block && !allowlist.detect_public_keys {
            continue;
        }

        let ctx = ScanLineContext {
            file_path: &file.path,
            apply_path_filters,
            line_number: added_line.line_number,
            line: &added_line.content,
            scanner,
            allowlist,
            is_doc_file: is_doc,
            generic_rule_skip,
            literals: literals.get(&added_line.line_number),
            parsed: parsed_lines.get(&added_line.line_number),
        };
        scan_line(&ctx, &mut candidate_bits, &mut findings);
    }

    findings
}

/// check if a rule detects public keys (gated behind detect_public_keys setting)
pub fn is_public_key_rule(rule_id: &str) -> bool {
    rule_id == "pem-public-key"
        || rule_id == "pgp-public-key-block"
        || rule_id == "openssh-public-key"
}

/// check if a rule targets password-type secrets
fn is_password_rule(rule_id: &str) -> bool {
    rule_id == "generic-password-assignment" || rule_id == "password-in-url"
}

// keep unquoted quote bytes only for line-start/export keys with whitespace and no `(` value byte.
// other generic entropy shapes retain the legacy pre-quote truncation boundary.
fn is_env_style_assignment(input: &[u8], key_start: usize, value: &[u8]) -> bool {
    if value.contains(&b'(') {
        return false;
    }

    let line_start = input[..key_start]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    let prefix = &input[line_start..key_start];
    if prefix.iter().all(|&byte| matches!(byte, b'\t' | b' ')) {
        return true;
    }

    let prefix = &prefix[prefix
        .iter()
        .position(|&byte| !matches!(byte, b'\t' | b' '))
        .unwrap_or(prefix.len())..];
    let Some(prefix) = prefix.strip_prefix(b"export") else {
        return false;
    };
    !prefix.is_empty() && prefix.iter().all(|&byte| matches!(byte, b'\t' | b' '))
}

/// shell script extensions where an unquoted `KEY=value` word is source syntax, not incidental
/// text; the config family (`config_syntax`), Dockerfiles and Makefiles get the same treatment
/// below.
const SHELL_SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "ksh", "fish"];

/// whether an already-lowercased leaf name is a Dockerfile (`Dockerfile`, `*.dockerfile`) or a
/// Makefile (`Makefile`, `*.mk`).
fn is_dockerfile_or_makefile_leaf(leaf_lower: &str) -> bool {
    leaf_lower == "dockerfile"
        || leaf_lower.ends_with(".dockerfile")
        || leaf_lower == "makefile"
        || leaf_lower.ends_with(".mk")
}

/// whether an unquoted `KEY=value` shell-word literal, and the stricter double-quoted shell
/// evaluation check below, apply on this surface: a shell script, the config/dotenv family
/// `config_syntax` recognizes, a Dockerfile, a Makefile, or the pathless surface
/// (`scan_text`/`redact_text`, env dumps). every other file -- Python, JS, Rust, Go, Ruby, Java,
/// ... -- treats `key=value` as a source expression, never a literal.
fn is_shell_word_literal_surface(file_path: Option<&str>) -> bool {
    let Some(path) = file_path else {
        return true;
    };
    if config_syntax(path).is_some() {
        return true;
    }
    let leaf = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if is_dockerfile_or_makefile_leaf(&leaf) {
        return true;
    }
    leaf.rsplit_once('.')
        .is_some_and(|(_, extension)| SHELL_SCRIPT_EXTENSIONS.contains(&extension))
}

/// whether every `.`-separated segment of `secret` is identifier-shaped
/// (`[A-Za-z_][A-Za-z0-9_]*`), with at least one dot present: a source-language dotted reference
/// (`cfg.pw1_x`) rather than a literal value.
fn is_dotted_identifier_chain(secret: &[u8]) -> bool {
    if !secret.contains(&b'.') {
        return false;
    }
    secret.split(|&byte| byte == b'.').all(|segment| {
        matches!(segment.first(), Some(&byte) if byte.is_ascii_alphabetic() || byte == b'_')
            && segment[1..]
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// whether an unquoted assignment value is shaped like a source-language expression rather than a
/// literal: a dotted identifier chain, or a value the capture had to stop right before a call,
/// index or statement-end token (`(`, `)`, `[`, `]`, `;`) that follows it directly in the source.
/// a single bare identifier without a dot is never rejected here: whether it counts as a literal
/// is entirely up to the surface gate above. on a shell-evaluated surface `;` separates commands
/// (`PW=value;cmd`), so it ends a literal word there instead of marking an expression.
fn is_expression_shape(
    input: &[u8],
    secret: &[u8],
    value_end: usize,
    shell_evaluated: bool,
) -> bool {
    let terminator = match input.get(value_end) {
        Some(b'(' | b')' | b'[' | b']') => true,
        Some(b';') => !shell_evaluated,
        _ => false,
    };
    terminator || is_dotted_identifier_chain(secret)
}

/// whether a double-quoted value's unescaped `$` or a backtick pair is evaluated on this surface:
/// a shell script, a dotenv file (`config_syntax` `Env`; sourced by a shell), a Dockerfile, a
/// Makefile, or the pathless surface. this is narrower than `is_shell_word_literal_surface`
/// above: YAML, INI and TOML are declarative formats no shell ever parses, so a double-quoted
/// value there keeps today's quote handling even though the same file admits the unquoted
/// `KEY=value` shell-word case.
fn is_shell_evaluated_surface(file_path: Option<&str>) -> bool {
    let Some(path) = file_path else {
        return true;
    };
    if config_syntax(path) == Some(ConfigSyntax::Env) {
        return true;
    }
    let leaf = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if is_dockerfile_or_makefile_leaf(&leaf) {
        return true;
    }
    leaf.rsplit_once('.')
        .is_some_and(|(_, extension)| SHELL_SCRIPT_EXTENSIONS.contains(&extension))
}

/// whether a double-quoted shell-surface value contains an unescaped `$` or any backtick: either
/// one the shell evaluates before the quotes produce a literal string.
fn shell_double_quote_requires_evaluation(secret: &[u8]) -> bool {
    let mut escaped = false;
    for &byte in secret {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'$' | b'`' => return true,
            _ => {}
        }
    }
    false
}

/// whether a password assignment's right-hand side is a concrete literal: a single-quoted value
/// (the shell never expands it), a double- or backtick-quoted value without interpolation -- on a
/// shell-evaluated surface (a shell script, a dotenv file, a Dockerfile, a Makefile, or the
/// pathless one) a double-quoted value additionally rejects an unescaped `$` or a backtick, since
/// the shell would evaluate it, and a backtick pair is always command substitution there, never a
/// literal, while YAML/INI/TOML and every other language keep their existing quote handling (a
/// backtick-quoted value there is a JS template literal or a Go raw string, unaffected) -- or a
/// shell assignment word (`KEY=value`, nothing around the `=`, at line start or after export) that
/// is confined to a shell/env/config surface and is not itself shaped like a source expression. an
/// unquoted source identifier or expression (`password = form.pw1`, `password: cfg.pw1`,
/// `password=cfg.pw1_x`) is neither; unquoted values in configuration files are decided by
/// `is_config_value_literal`.
fn is_concrete_password_literal(
    input: &[u8],
    file_path: Option<&str>,
    key_capture: Option<regex::bytes::Match<'_>>,
    value: &Range<usize>,
) -> bool {
    let secret = &input[value.clone()];
    let opening = value.start.checked_sub(1).map(|index| input[index]);
    if let Some(quote) = opening.filter(|byte| matches!(byte, b'"' | b'\'' | b'`')) {
        let shell_evaluated = is_shell_evaluated_surface(file_path);
        if quote == b'`' && shell_evaluated {
            // command substitution: evaluated even without a `$` inside (`` `cat</pw1` ``).
            return false;
        }
        if input.get(value.end) != Some(&quote)
            || secret
                .windows(2)
                .any(|pair| matches!(pair, b"${" | b"$(" | b"#{"))
        {
            return false;
        }
        return quote != b'"'
            || !shell_evaluated
            || !shell_double_quote_requires_evaluation(secret);
    }
    key_capture.is_some_and(|key| {
        input.get(key.end()..value.start) == Some(b"=".as_slice())
            && is_env_style_assignment(input, key.start(), secret)
            && is_shell_word_literal_surface(file_path)
            && !secret.iter().any(|&byte| matches!(byte, b'$' | b'`'))
            && !is_expression_shape(
                input,
                secret,
                value.end,
                is_shell_evaluated_surface(file_path),
            )
    })
}

/// configuration and data formats whose unquoted assignment values are data, not source
/// expressions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigSyntax {
    Yaml,
    Ini,
    Toml,
    Env,
}

/// the configuration format of a path, by extension first so `.env.yaml` stays yaml; a leaf of
/// `.env` or `.env.<suffix>` is a dotenv file whatever its suffix (`.envrc` is a shell script).
fn config_syntax(path: &str) -> Option<ConfigSyntax> {
    let leaf = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let by_extension = leaf
        .rsplit_once('.')
        .and_then(|(_, extension)| match extension {
            "yaml" | "yml" => Some(ConfigSyntax::Yaml),
            "ini" | "cfg" | "conf" | "properties" => Some(ConfigSyntax::Ini),
            "toml" => Some(ConfigSyntax::Toml),
            "env" => Some(ConfigSyntax::Env),
            _ => None,
        });
    by_extension.or_else(|| leaf.starts_with(".env.").then_some(ConfigSyntax::Env))
}

/// whether an unquoted password value in a configuration file is a concrete literal: the whole
/// value of a `key: value` yaml mapping entry (key after indentation and list markers), or of a
/// line-start `key = value` entry (`:` too in ini-style files), up to an end-of-line comment,
/// without whitespace, expansion or interpolation, and not a yaml alias, anchor or tag.
fn is_config_value_literal(
    input: &[u8],
    syntax: ConfigSyntax,
    key: Range<usize>,
    value: &Range<usize>,
) -> bool {
    let secret = &input[value.clone()];
    // a dotted identifier chain or a value cut short before a call/index/statement-end token is a
    // source expression on every surface, config files included (concern codex-cl-password-001).
    if is_expression_shape(input, secret, value.end, syntax == ConfigSyntax::Env) {
        return false;
    }
    // `%` and `@` are reserved yaml indicators that cannot start a plain scalar.
    let reserved_start: &[u8] = if syntax == ConfigSyntax::Yaml {
        b"*&!%@"
    } else {
        b"*&!"
    };
    if secret
        .first()
        .is_none_or(|byte| reserved_start.contains(byte))
        || secret
            .iter()
            .any(|&byte| byte.is_ascii_whitespace() || matches!(byte, b'$' | b'`'))
        || secret
            .windows(2)
            .any(|pair| matches!(pair, b"#{" | b"{{" | b"%("))
    {
        return false;
    }

    let mut key_start = key.start;
    let mut separator = &input[key.end..value.start];
    if let Some(quote) = key
        .start
        .checked_sub(1)
        .map(|index| input[index])
        .filter(|byte| matches!(byte, b'"' | b'\''))
    {
        let Some(rest) = separator.strip_prefix(&[quote]) else {
            return false;
        };
        separator = rest;
        key_start -= 1;
    }
    let separator_ok = match syntax {
        ConfigSyntax::Yaml => separator
            .trim_ascii_start()
            .strip_prefix(b":")
            .is_some_and(|gap| {
                !gap.is_empty() && gap.iter().all(|&byte| matches!(byte, b' ' | b'\t'))
            }),
        ConfigSyntax::Ini => matches!(separator.trim_ascii(), b"=" | b":"),
        ConfigSyntax::Toml | ConfigSyntax::Env => separator.trim_ascii() == b"=",
    };
    let prefix_ok = match syntax {
        ConfigSyntax::Yaml => {
            let line_start = input[..key_start]
                .iter()
                .rposition(|&byte| byte == b'\n')
                .map_or(0, |index| index + 1);
            let mut prefix = input[line_start..key_start].trim_ascii_start();
            while let Some(rest) = prefix.strip_prefix(b"-").filter(|rest| {
                rest.first()
                    .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
            }) {
                prefix = rest.trim_ascii_start();
            }
            prefix.is_empty()
        }
        _ => is_env_style_assignment(input, key_start, secret),
    };
    if !separator_ok || !prefix_ok {
        return false;
    }

    // a value the capture cut short (`abc,def`, `foo bar`) is not the whole plain value.
    let line_end = input[value.end..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(input.len(), |index| value.end + index);
    let tail = &input[value.end..line_end];
    let comment = tail.trim_ascii_start();
    comment.is_empty()
        || (comment.len() < tail.len()
            && (comment[0] == b'#' || (syntax == ConfigSyntax::Ini && comment[0] == b';')))
}

// find the legacy boundary when the env-style gate declines the full unquoted capture.
fn first_unescaped_quote(value: &[u8]) -> Option<usize> {
    let mut escaped = false;
    for (index, &byte) in value.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            return Some(index);
        }
    }
    None
}

/// a uri scheme name: a letter, then letters, digits, `+`, `-` or `.` (rfc 3986 section 3.1).
fn is_uri_scheme(key: &[u8]) -> bool {
    key.first().is_some_and(u8::is_ascii_alphabetic)
        && key
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// the text between a digest key and its value: a bare `:` for an unquoted value, as in a header
/// or a yaml field, and `:` or `=` before the opening quote, string prefix or raw-string `#`s of a
/// quoted value, as in json (`"integrity": "sha512-..."`) or an html attribute.
fn is_digest_separator(between: &[u8], quoted: bool) -> bool {
    if !quoted {
        return between.trim_ascii() == b":";
    }
    let Some(opening) = between
        .strip_suffix(b"\"")
        .or_else(|| between.strip_suffix(b"'"))
    else {
        return false;
    };
    let prefix = opening
        .iter()
        .rev()
        .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'#')
        .count();
    matches!(opening[..opening.len() - prefix].trim_ascii(), b":" | b"=")
}

/// check if a rule extracts credentials from connection strings/URLs.
/// these rules use the password strength heuristic to filter weak/placeholder
/// passwords, but still fall through to entropy evaluation as a safety net
/// for high-entropy tokens with limited character class diversity.
fn is_credential_rule(rule_id: &str) -> bool {
    rule_id.starts_with("database-connection-string-")
        || rule_id == "redis-connection-string"
        || rule_id == "mssql-connection-string"
}

/// context for scanning a single line
struct ScanLineContext<'a> {
    file_path: &'a str,
    apply_path_filters: bool,
    line_number: usize,
    line: &'a [u8],
    scanner: &'a CompiledScanner,
    allowlist: &'a CompiledAllowlist,
    is_doc_file: bool,
    generic_rule_skip: Option<&'static str>,
    literals: Option<&'a LineLiterals>,
    parsed: Option<&'a ParsedLine>,
}

/// scan a single line against all rules using the aho-corasick pre-filter.
/// uses a reusable bitset to avoid allocations per line.
fn scan_line(ctx: &ScanLineContext<'_>, candidate_bits: &mut [bool], findings: &mut Vec<Finding>) {
    let matches = MatchContext {
        file_path: ctx.apply_path_filters.then_some(ctx.file_path),
        input: ctx.line,
        line_starts: &[],
        scanner: ctx.scanner,
        allowlist: ctx.allowlist,
        is_doc_file: ctx.is_doc_file,
        generic_rule_skip: ctx.generic_rule_skip,
        // parser posture matches in full posture and clips the tier-3 findings afterwards.
        literals: if ctx.parsed.is_some() {
            None
        } else {
            ctx.literals
        },
    };
    let clip = ctx.parsed.and_then(|parsed| {
        ctx.scanner
            .rules
            .iter()
            .find(|rule| rule.id == ENTROPY_RULE)
            .map(|rule| (parsed, rule))
    });
    let mut seen = std::collections::HashSet::new();
    let mut push = |rule_id: &str, range: Range<usize>| {
        if seen.insert((rule_id.to_owned(), range.start, range.end)) {
            findings.push(Finding {
                file: ctx.file_path.to_string(),
                line: ctx.line_number,
                rule_id: rule_id.to_string(),
                matched_value: ctx.line[range].to_vec(),
            });
        }
    };
    scan_matches(&matches, candidate_bits, |rule_id, range| match clip {
        Some((parsed, rule)) if rule_id == ENTROPY_RULE => {
            clip_to_literal_bodies(&matches, rule, parsed, range, &mut push);
        }
        _ => push(rule_id, range),
    });
}

/// parser posture: a surviving tier-3 finding keeps only the proved literal text it covers. a
/// finding disjoint from every body is code; one inside a single string body stands as evaluated;
/// otherwise each body segment it touches is evaluated again as a keyless literal body, so an
/// interpolation hole, a string prefix or regex delimiters never lend their bytes to a value, and
/// a regex body reaches the regex step. pieces of which none is reported on its own stand whole
/// when together they read as one chunked token, and so does a python finding holding a hole whose
/// expression and format specification read as one (`format_spec_holes`).
fn clip_to_literal_bodies(
    ctx: &MatchContext<'_>,
    rule: &crate::scanner::rules::CompiledRule,
    parsed: &ParsedLine,
    range: Range<usize>,
    emit: &mut impl FnMut(&str, Range<usize>),
) {
    let segments: Vec<Range<usize>> = parsed
        .literals
        .bodies
        .iter()
        .filter(|body| range.start < body.end && body.start < range.end)
        .map(|body| range.start.max(body.start)..range.end.min(body.end))
        .collect();
    match segments.as_slice() {
        [] => trace_exemption(ctx, emit, "code", range),
        [segment] if *segment == range && parsed.body_kind(segment) != BodyKind::Regex => {
            emit(ENTROPY_RULE, range);
        }
        // a python format specification is literal text python hands to `__format__` verbatim,
        // behind an expression the parser reads as code. a token cut into short groups by `:`
        // puts its first group in that expression and the rest in the specification: when the
        // specification of a hole is no format mini-language and the hole's text reads as a run
        // of short groups, nested replacement fields breaking the run, the hole is not proved to
        // be a name and a specification, and the finding stands whole, as the full posture
        // evaluated it. a mini-language specification (`:>12`, `:08x`) holds no token, so a run
        // across it is the expression's attribute chain.
        _ if is_python_path(ctx.file_path)
            && format_spec_holes(ctx.input, range.clone(), &parsed.literals.bodies)
                .iter()
                .any(|(hole, specification)| {
                    !is_format_mini_language(specification)
                        && crate::scanner::wordshape::is_chunked_with_digits(
                            &ctx.input[hole.clone()],
                            b"{}",
                        )
                }) =>
        {
            emit(ENTROPY_RULE, range);
        }
        _ => {
            if segments.len() > 1 || segments[0] != range {
                trace_exemption(ctx, emit, "clip", range.clone());
            }
            let mut reported = false;
            for segment in &segments {
                evaluate_candidate(
                    ctx,
                    rule,
                    Candidate::Call(segment.clone()),
                    &mut |rule_id: &str, found: Range<usize>| {
                        reported |= rule_id == ENTROPY_RULE;
                        emit(rule_id, found);
                    },
                    &mut unowned,
                );
            }
            // pieces of one value cut apart by holes or by implicit concatenation, none reported
            // on its own: when the pieces together read as a run of short groups, they are one
            // chunked token and the finding stands whole, as the full posture evaluated it. the
            // parser proves a hole's bytes to be code, so the run is read over the literal pieces.
            if !reported
                && segments.len() > 1
                && segments
                    .iter()
                    .all(|segment| parsed.body_kind(segment) != BodyKind::Regex)
            {
                let mut pieces = Vec::with_capacity(range.len() + segments.len());
                for segment in &segments {
                    pieces.extend_from_slice(&ctx.input[segment.clone()]);
                    pieces.push(b' ');
                }
                if crate::scanner::wordshape::is_chunked_with_digits(&pieces, b"") {
                    emit(ENTROPY_RULE, range);
                }
            }
        }
    }
}

/// the f-string holes inside `range` that hold a format specification: the text between each
/// hole's braces, and the specification's own text with its nested replacement fields left out.
/// a hole is a `{` outside every literal body, closed by the `}` that matches it, holding a `:`
/// outside every body at the hole's own nesting level. the parser reads the text before that `:`
/// as the hole's expression and conversion, and the text after it as the specification, whose
/// literal pieces are bodies. brackets inside a body are text, not nesting.
fn format_spec_holes(
    input: &[u8],
    range: Range<usize>,
    bodies: &[Range<usize>],
) -> Vec<(Range<usize>, Vec<u8>)> {
    let bodied = |index: usize| {
        bodies
            .iter()
            .any(|body| body.start <= index && index < body.end)
    };
    let mut holes = Vec::new();
    let mut index = range.start;
    while index < range.end {
        if input[index] != b'{' || bodied(index) {
            index += 1;
            continue;
        }
        let mut depth = 0_usize;
        let mut specification: Option<Vec<u8>> = None;
        let mut close = None;
        for (inner, &byte) in input[..range.end].iter().enumerate().skip(index + 1) {
            if bodied(inner) {
                if depth == 0
                    && let Some(text) = specification.as_mut()
                {
                    text.push(byte);
                }
                continue;
            }
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b'}' if depth == 0 => {
                    close = Some(inner);
                    break;
                }
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                b':' if depth == 0 && specification.is_none() => specification = Some(Vec::new()),
                _ => {}
            }
        }
        let Some(close) = close else {
            break;
        };
        if let Some(specification) = specification {
            holes.push((index + 1..close, specification));
        }
        index = close + 1;
    }
    holes
}

/// whether a format specification, its nested replacement fields left out, is python's format
/// mini-language: `[[fill]align][sign][z][#][0][width][grouping][.[precision][grouping]][type]`,
/// where a nested field may have supplied any part.
fn is_format_mini_language(specification: &[u8]) -> bool {
    let align = |at: usize| matches!(specification.get(at), Some(b'<' | b'>' | b'=' | b'^'));
    let mut index = if align(1) { 2 } else { usize::from(align(0)) };
    let optional = |index: &mut usize, accepted: &[u8]| {
        if specification
            .get(*index)
            .is_some_and(|byte| accepted.contains(byte))
        {
            *index += 1;
        }
    };
    let digits = |index: &mut usize| {
        while specification.get(*index).is_some_and(u8::is_ascii_digit) {
            *index += 1;
        }
    };
    optional(&mut index, b"+- ");
    optional(&mut index, b"z");
    optional(&mut index, b"#");
    digits(&mut index);
    optional(&mut index, b"_,");
    if specification.get(index) == Some(&b'.') {
        index += 1;
        digits(&mut index);
        optional(&mut index, b"_,");
    }
    optional(&mut index, b"bcdeEfFgGnosxX%");
    index == specification.len()
}

/// matching policy shared by line-oriented diffs and complete tool text.
pub(super) struct MatchContext<'a> {
    pub file_path: Option<&'a str>,
    pub input: &'a [u8],
    pub line_starts: &'a [usize],
    pub scanner: &'a CompiledScanner,
    pub allowlist: &'a CompiledAllowlist,
    pub is_doc_file: bool,
    pub generic_rule_skip: Option<&'static str>,
    pub literals: Option<&'a LineLiterals>,
}

/// diagnostic only; pseudo-findings count as findings for scan/audit exit codes when the flag is on, and the flag exists only on the CLI so hook surfaces never see them.
fn trace_exemption(
    ctx: &MatchContext<'_>,
    emit: &mut impl FnMut(&str, std::ops::Range<usize>),
    name: &str,
    range: std::ops::Range<usize>,
) {
    if ctx.allowlist.trace_exemptions {
        emit(&format!("exempt:{name}"), range);
    }
}

impl MatchContext<'_> {
    fn surrounding_lines(&self, range: Range<usize>) -> &[u8] {
        &self.input[self.surrounding_range(range)]
    }

    fn surrounding_range(&self, range: Range<usize>) -> Range<usize> {
        let start_index = self
            .line_starts
            .partition_point(|&start| start <= range.start);
        let end_index = self.line_starts.partition_point(|&start| start < range.end);
        let start = self
            .line_starts
            .get(start_index.saturating_sub(1))
            .copied()
            .unwrap_or(0);
        let end = self
            .line_starts
            .get(end_index)
            .copied()
            .unwrap_or(self.input.len());
        start..end
    }
}

pub(super) fn scan_matches(
    ctx: &MatchContext<'_>,
    candidate_bits: &mut [bool],
    mut emit: impl FnMut(&str, Range<usize>),
) {
    let mut seen = std::collections::HashSet::new();
    let mut emit = |rule_id: &str, range: Range<usize>| {
        if seen.insert((rule_id.to_owned(), range.start, range.end)) {
            emit(rule_id, range);
        }
    };
    // keywordless rules are always eligible; reset all other candidate bits.
    let mut has_candidates = false;
    for (bit, rule) in candidate_bits.iter_mut().zip(&ctx.scanner.rules) {
        *bit = rule.keywords.is_empty();
        has_candidates |= *bit;
    }

    // step 2: aho-corasick keyword pre-filter
    // find which rules have keywords present in this line.
    // uses overlapping iteration to ensure longer keywords (e.g. "age-secret-key-")
    // are found even when a shorter keyword (e.g. "secret") overlaps with them.
    for mat in ctx.scanner.automaton.find_overlapping_iter(ctx.input) {
        let pattern_idx = mat.pattern().as_usize();
        if let Some(rule_indices) = ctx.scanner.keyword_to_rules.get(pattern_idx) {
            for &rule_idx in rule_indices {
                if !candidate_bits[rule_idx] {
                    candidate_bits[rule_idx] = true;
                    has_candidates = true;
                }
            }
        }
    }

    if !has_candidates {
        return;
    }

    // step 3: regex matching only for candidate rules
    for (rule_idx, &is_candidate) in candidate_bits.iter().enumerate() {
        if !is_candidate || rule_idx >= ctx.scanner.rules.len() {
            continue;
        }

        let rule = &ctx.scanner.rules[rule_idx];
        let is_entropy_value = rule.id == "generic-high-entropy-value";

        // step 0: skip public key detection rules unless enabled
        if is_public_key_rule(&rule.id) && !ctx.allowlist.detect_public_keys {
            continue;
        }

        // evaluate all matches for this rule on the line, not just the first.
        // if the first match is filtered (allowlist/stopword/var-ref), a later
        // match on the same line could still be a real secret.
        let candidates: Vec<_> = if is_entropy_value {
            entropy_captures(
                &rule.regex,
                &rule.capture_indices,
                ctx.input,
                rule.entropy_threshold,
            )
        } else {
            rule.regex.captures_iter(ctx.input).collect()
        };
        let scopes = if is_entropy_value {
            assignment_scopes(&candidates, ctx.input.len(), &rule.capture_indices)
        } else {
            vec![0..ctx.input.len(); candidates.len()]
        };
        let mut owned_ranges = Vec::new();
        for (captures, scope) in candidates.into_iter().zip(scopes) {
            evaluate_candidate(
                ctx,
                rule,
                Candidate::Regex(captures, scope),
                &mut emit,
                &mut |range| {
                    if is_entropy_value && ctx.literals.is_some() {
                        owned_ranges.push(range);
                    }
                },
            );
        }
        // literal bodies exist only on diff lines, where line_starts is []. the call collector
        // carries paren context across the line breaks of multi-line text; its per-line text
        // passes collect a subset of the same ranges, which scan_text deduplicates.
        if is_entropy_value {
            if let Some(literals) = ctx.literals {
                for range in &literals.bodies {
                    if !owned_ranges.contains(range) {
                        evaluate_candidate(
                            ctx,
                            rule,
                            Candidate::Call(range.clone()),
                            &mut emit,
                            &mut |_| {},
                        );
                    }
                }
            } else if ctx.allowlist.exemption_layer {
                crate::scanner::calllit::collect(ctx.input, |range| {
                    evaluate_candidate(ctx, rule, Candidate::Call(range), &mut emit, &mut |_| {});
                });
            }
        }
    }
}

/// the tier-3 rule's own capture cursor. an unquoted boundary may consume the next assignment's
/// key, so the scan resumes after the value. a quoted body holding whitespace is a phrase, not a
/// value: a stray quote byte can pair with a later one across whole assignments, so the scan
/// resumes inside the body and evaluates the assignments it contains on their own. a quoted body
/// consisting of a shell default is revisited so its operand is judged separately. a key the
/// grammar misread (`misread_key_resume`) is no candidate, and the scan resumes after its
/// separator so the text behind it is still read.
fn entropy_captures<'h>(
    regex: &regex::bytes::Regex,
    indices: &CaptureIndices,
    input: &'h [u8],
    entropy_floor: Option<f64>,
) -> Vec<regex::bytes::Captures<'h>> {
    let mut found = Vec::new();
    let mut offset = 0;
    while offset <= input.len() {
        let Some(captures) = regex.captures_at(input, offset) else {
            break;
        };
        let Some(matched) = captures.get(0) else {
            break;
        };
        let floor = matched.start().saturating_add(1);
        if let Some(resume) = misread_key_resume(input, &captures, indices, entropy_floor) {
            offset = resume.max(floor);
            continue;
        }
        let rescan_body = indices
            .entropy_rescan_groups
            .into_iter()
            .filter_map(|index| index.and_then(|index| captures.get(index)))
            .find(|body| {
                let bytes = body.as_bytes();
                bytes.iter().any(u8::is_ascii_whitespace)
                    || (bytes.starts_with(b"${")
                        && bytes.ends_with(b"}")
                        && bytes.windows(2).any(|pair| pair == b":-" || pair == b":="))
            });
        offset = match rescan_body {
            Some(body) => body.start(),
            None => indices
                .entropy_unquoted
                .and_then(|index| captures.get(index))
                .map_or(matched.end(), |value| value.end()),
        }
        .max(floor);
        found.push(captures);
    }
    found
}

/// a key the value grammar misread, with the offset after its separator: the first `:` of a `::`
/// scope separator (`std::env`, `Acquire::Check`), the name of a posix bracket class
/// (`[[:space:]]`), or the letter of a backslash escape standing alone as the key (`\n: `). no
/// supported format writes a credential as `key::value` or `[:key:]`, and an escape letter is not
/// a name. the misreading is proved only for a value that is code of words (`is_word_code`): a
/// value carrying an opaque run (`Type::<token>`, `[[:alnum:]]<token>`, `\n: <token>`) or a run of
/// short groups keeps the capture, so the text behind the name is judged as it was before the name
/// was recognized. a run of groups is read up to an `=`, where the resumed scan reads the text
/// after it as the value of a new assignment (`Acquire::Check-Valid-Until=false`).
fn misread_key_resume(
    input: &[u8],
    captures: &regex::bytes::Captures<'_>,
    indices: &CaptureIndices,
    entropy_floor: Option<f64>,
) -> Option<usize> {
    let key = captures.get(indices.entropy_key?)?;
    let separator = key.end()
        + input[key.end()..]
            .iter()
            .take_while(|&&byte| matches!(byte, b' ' | b'\t'))
            .count();
    let colon = input.get(separator) == Some(&b':');
    let next = input.get(separator + 1).copied();
    let before = |back: usize| key.start().checked_sub(back).map(|index| input[index]);
    let resume = if colon
        && (next == Some(b':')
            || (next == Some(b']') && before(1) == Some(b':') && before(2) == Some(b'[')))
    {
        separator + 2
    } else if escaped_key(input, key.range()) {
        separator + 1
    } else {
        return None;
    };
    indices
        .entropy_value_groups
        .into_iter()
        .find_map(|index| index.and_then(|index| captures.get(index)))
        .is_none_or(|value| is_word_code(value.as_bytes(), b"=", entropy_floor))
        .then_some(resume)
}

/// whether text reads as code built from words: every run of letters and digits between other
/// bytes (`_` included) is a word part (`is_word_part`), and no run of short groups crosses the
/// text between two `run_breaks` bytes (`wordshape::is_chunked_with_digits`). the chunk guard reads
/// every alphanumeric byte, so a token cut into short pieces by the structure around it (`.`,
/// `::`, `_`, brackets, holes) is still one token. a run of letters and digits, joined or not by
/// the `+`, `/`, `_` and `-` of the encoded-token alphabets, is judged whole as well: one that
/// could be a token standing alone (it reaches the entropy length and clears `entropy_floor`, the
/// rule's own threshold) must be word structured (`wordshape::is_word_structured`, the wordshape
/// step that token would face), so neither a token whose joiners cut it into pieces that each
/// pass as a word nor one whose humps happen to read as words is taken for code.
fn is_word_code(text: &[u8], run_breaks: &[u8], entropy_floor: Option<f64>) -> bool {
    use crate::scanner::wordshape;
    !wordshape::is_chunked_with_digits(text, run_breaks)
        && text
            .split(|&byte| !byte.is_ascii_alphanumeric())
            .filter(|part| !part.is_empty())
            .all(is_word_part)
        && text
            .split(|&byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-'))
            })
            .filter(|run| {
                run.len() >= entropy::MIN_ENTROPY_LENGTH
                    && entropy_floor
                        .is_none_or(|threshold| entropy::passes_entropy_check(run, threshold))
            })
            .all(wordshape::is_word_structured)
}

/// whether a run of letters and digits reads as words. a part shorter than `MIN_ENTROPY_LENGTH` is
/// a word piece or a number of at most four digits (`wordshape::wordlike_piece`). a part as long as
/// a token is its words: each a lowercase or capitalized word of four to nineteen letters that
/// reads as a word (`wordshape::has_wordlike_vowels`) or a vocabulary short word, with at most one
/// run of at most four digits (`InvalidParameterValue`, `AllowInsecureRepositories`), or it is
/// word structured as a value (`wordshape::is_word_structured`). the humps and digit runs of a
/// random token mostly leave words of one to three letters outside the vocabulary; the rare token
/// that reads as words here still meets `is_word_code`'s whole-run check, so it is exempted no
/// more often than the same token standing alone.
fn is_word_part(part: &[u8]) -> bool {
    use crate::scanner::wordshape;
    if part.len() < entropy::MIN_ENTROPY_LENGTH {
        return wordshape::wordlike_piece(part).is_some();
    }
    let mut digit_runs = 0;
    let words_read = wordshape::identifier_words(part).is_some_and(|words| {
        words.iter().all(|word| {
            if word[0].is_ascii_digit() {
                digit_runs += 1;
                digit_runs == 1 && word.len() <= 4
            } else if word.len() < 4 {
                wordshape::is_short_word(word)
            } else {
                word.len() < entropy::MIN_ENTROPY_LENGTH
                    && word[1..].iter().all(u8::is_ascii_lowercase)
                    && wordshape::has_wordlike_vowels(word)
            }
        })
    });
    words_read || wordshape::is_word_structured(part)
}

/// an identifier key of one letter behind an odd run of backslashes is an escape sequence.
fn escaped_key(input: &[u8], key: Range<usize>) -> bool {
    key.len() == 1
        && input[key.start].is_ascii_alphabetic()
        && input[..key.start]
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\\')
            .count()
            % 2
            == 1
}

/// the text one tier-3 capture spans: from its key, or its value when keyless, to the value end.
fn assignment_span(
    captures: &regex::bytes::Captures<'_>,
    indices: &CaptureIndices,
) -> Range<usize> {
    let value = indices
        .entropy_value_groups
        .into_iter()
        .find_map(|index| index.and_then(|index| captures.get(index)))
        .or_else(|| captures.get(0))
        .map_or(0..0, |value| value.range());
    let start = indices
        .entropy_key
        .and_then(|index| captures.get(index))
        .map_or(value.start, |key| key.start());
    start..value.end
}

/// the stretch of input each tier-3 candidate owns for its hash-context check: from the end of the
/// nearest earlier candidate's value to the start of the nearest later candidate's key (or value,
/// when it has no key). a context word such as `sha256` before one assignment says nothing about
/// the next one on the same line, while words around the assignment itself (`checksum secret =
/// ...`, a trailing `# sha256` comment) still belong to it.
fn assignment_scopes(
    candidates: &[regex::bytes::Captures<'_>],
    len: usize,
    indices: &CaptureIndices,
) -> Vec<Range<usize>> {
    // a lone candidate owns the whole input. the general case below gives an empty span only its
    // own point, but an empty span holds an empty value, which never reaches the hash check, so
    // the span is not worth its capture-name lookups on the common single-assignment line.
    if candidates.len() < 2 {
        return vec![0..len; candidates.len()];
    }
    let spans: Vec<Range<usize>> = candidates
        .iter()
        .map(|captures| assignment_span(captures, indices))
        .collect();
    let mut ends: Vec<usize> = spans.iter().map(|span| span.end).collect();
    let mut starts: Vec<usize> = spans.iter().map(|span| span.start).collect();
    ends.sort_unstable();
    starts.sort_unstable();
    spans
        .iter()
        .map(|span| {
            let before = ends.partition_point(|&end| end <= span.start);
            let left = before.checked_sub(1).map_or(0, |index| ends[index]);
            let after = starts.partition_point(|&start| start < span.end);
            let right = starts.get(after).copied().unwrap_or(len);
            left..right.max(left)
        })
        .collect()
}

/// the body of a delimited regex literal, `/body/flags`, when an unquoted or bare capture is one:
/// flags are ascii letters, trailing `,` `;` `)` close the surrounding syntax, and the body holds
/// no unescaped `/` outside a bracket class, which a path or a base64 run between slashes does.
fn regex_literal_body(value: &[u8]) -> Option<Range<usize>> {
    let trimmed = value.len()
        - value
            .iter()
            .rev()
            .take_while(|&&byte| matches!(byte, b',' | b';' | b')'))
            .count();
    let value = &value[..trimmed];
    let flags = value
        .iter()
        .rev()
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    let close = value.len().checked_sub(flags + 1)?;
    if value.first() != Some(&b'/')
        || value[close] != b'/'
        || close < 2
        || matches!(value[1], b'/' | b'*')
    {
        return None;
    }
    let body = &value[1..close];
    let mut escaped = false;
    let mut class = false;
    for &byte in body {
        match byte {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return None,
            _ => {}
        }
    }
    (!escaped).then_some(1..close)
}

/// whether a regex-shaped value carries a token its pattern syntax would hide: a run of
/// `MIN_ENTROPY_LENGTH` or more base64 bytes (letters, digits, `+`, `/`, `-`, `_`; a pattern reads
/// `+` as a quantifier and `/` as a delimiter, a token as its own bytes), or a run of short groups
/// across literal text and bracket-class contents, with counted repetitions and escaped
/// punctuation read as separators (`is_chunked_with_digits`), as in a token cut by `\.` or `|` into
/// short pieces. an escape of any byte but a class letter (`is_class_escape`) writes that byte, so
/// the byte belongs to the value in both checks: an escaped base64 byte continues the run, and an
/// escaped letter or digit is a piece of its own, as an unescaped one-letter piece would be. a
/// token escaped before every other byte keeps its run and its groups.
fn pattern_carries_token(pattern: &[u8]) -> bool {
    let mut run = 0;
    let mut index = 0;
    while index < pattern.len() {
        // a class escape ends the run before it, and its letter opens the next one.
        let (byte, width, joins) = match (pattern[index], pattern.get(index + 1)) {
            (b'\\', Some(&escaped)) => (escaped, 2, !is_class_escape(escaped)),
            (b'\\', None) => (b'\\', 1, false),
            (byte, _) => (byte, 1, true),
        };
        run = match (is_run_byte(byte), joins) {
            (false, _) => 0,
            (true, true) => run + 1,
            (true, false) => 1,
        };
        if run >= entropy::MIN_ENTROPY_LENGTH {
            return true;
        }
        index += width;
    }
    let mut literal = Vec::with_capacity(pattern.len());
    let mut index = 0;
    while index < pattern.len() {
        let skip = match pattern[index] {
            b'\\' => {
                if let Some(&escaped) = pattern.get(index + 1)
                    && escaped.is_ascii_alphanumeric()
                    && !is_class_escape(escaped)
                {
                    literal.extend_from_slice(&[b' ', escaped]);
                }
                2
            }
            b'[' => {
                // a bracket class, its leading `]` and escaped bytes included.
                let mut end = index + 1;
                if pattern.get(end) == Some(&b'^') {
                    end += 1;
                }
                if pattern.get(end) == Some(&b']') {
                    end += 1;
                }
                while end < pattern.len() && pattern[end] != b']' {
                    end += if pattern[end] == b'\\' { 2 } else { 1 };
                }
                literal.extend_from_slice(&pattern[index..end.min(pattern.len())]);
                end + 1 - index
            }
            b'{' => pattern[index + 1..]
                .iter()
                .position(|&byte| byte == b'}')
                .filter(|&close| {
                    close > 0
                        && pattern[index + 1..index + 1 + close]
                            .iter()
                            .all(|byte| byte.is_ascii_digit() || *byte == b',')
                })
                .map_or(1, |close| close + 2),
            _ => 0,
        };
        if skip == 0 {
            literal.push(pattern[index]);
            index += 1;
        } else {
            literal.push(b' ');
            index += skip;
        }
    }
    crate::scanner::wordshape::is_chunked_with_digits(&literal, b"")
}

/// a byte of a token run in `pattern_carries_token`: a letter, a digit, `+`, `/`, `-` or `_`.
fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// the letters whose escape names a class or a boundary rather than the letter itself (`\d`, `\w`,
/// `\s`, `\b` and their negations), the letter escapes `regexshape::is_regex_shaped` reads as
/// regex syntax. eight letters carry three bits a byte, under the tier-3 entropy gate.
fn is_class_escape(byte: u8) -> bool {
    matches!(byte, b'b' | b'B' | b'd' | b'D' | b'w' | b'W' | b's' | b'S')
}

/// whether an unquoted capture is the pattern argument of a command or option that takes a
/// regular expression: the word before its key, past one opening quote, is `grep`, `egrep`, `rg`,
/// `sed` or `awk`, a `--regexp`, `--extended-regexp` or `--perl-regexp` option, or a short-option
/// cluster carrying `E` or `P` (`-E`, `-Eqi`, `-oP`).
fn follows_regex_command(input: &[u8], start: usize) -> bool {
    let line_start = input[..start]
        .iter()
        .rposition(|&byte| matches!(byte, b'\n' | b'\r'))
        .map_or(0, |index| index + 1);
    let before = input[line_start..start].trim_ascii_end();
    let before = before
        .strip_suffix(b"'")
        .or_else(|| before.strip_suffix(b"\""))
        .unwrap_or(before)
        .trim_ascii_end();
    let word = &before[before
        .iter()
        .rposition(|byte| byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1)..];
    matches!(
        word,
        b"grep"
            | b"egrep"
            | b"rg"
            | b"sed"
            | b"awk"
            | b"--regexp"
            | b"--extended-regexp"
            | b"--perl-regexp"
    ) || word.strip_prefix(b"-").is_some_and(|cluster| {
        !cluster.is_empty()
            && cluster.iter().all(u8::is_ascii_alphabetic)
            && cluster.iter().any(|byte| matches!(byte, b'E' | b'P'))
    })
}

/// the ownership sink of a candidate that owns no literal body. a named function rather than a
/// closure, so the recursive evaluation of literal segments instantiates no new closure type.
fn unowned(_: Range<usize>) {}

/// the string prefix letters written before the opening quote of a quoted body starting at
/// `body_start`: at most two letters, not the tail of a longer word.
fn string_prefix(input: &[u8], body_start: usize) -> &[u8] {
    let quote = body_start.saturating_sub(1);
    let letters = input[..quote]
        .iter()
        .rev()
        .take(2)
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    let start = quote - letters;
    if input[..start]
        .last()
        .is_some_and(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return &[];
    }
    &input[start..quote]
}

/// a python string prefix that makes `{...}` an interpolation hole: `f` or `t` (template
/// strings), alone or combined with `r`.
fn is_interpolating_prefix(prefix: &[u8]) -> bool {
    prefix
        .iter()
        .any(|byte| matches!(byte.to_ascii_lowercase(), b'f' | b't'))
        && prefix
            .iter()
            .all(|byte| matches!(byte.to_ascii_lowercase(), b'f' | b't' | b'r'))
}

/// whether a path names python source (`.py`, `.pyi`), the one surface where `f"..."` and
/// `t"..."` are interpolating strings. the pathless text of the redact hook, shell, dotenv and
/// configuration files, and every other language read them as literal data.
fn is_python_path(file_path: Option<&str>) -> bool {
    file_path.is_some_and(|path| {
        let leaf = path.rsplit('/').next().unwrap_or(path);
        leaf.rsplit_once('.').is_some_and(|(_, extension)| {
            extension.eq_ignore_ascii_case("py") || extension.eq_ignore_ascii_case("pyi")
        })
    })
}

/// the literal segments of the f-string or t-string body at `body` (`interpolated_literal_segments`),
/// read only where its holes are proved to be code: on a python file outside the rust and go
/// tracker, for a body of graphic bytes that clears the entropy length behind an interpolating
/// prefix.
fn python_hole_segments(
    ctx: &MatchContext<'_>,
    body: Range<usize>,
    entropy_floor: Option<f64>,
) -> Option<Vec<Range<usize>>> {
    let text = &ctx.input[body.clone()];
    if ctx.literals.is_some()
        || !is_python_path(ctx.file_path)
        || text.len() < entropy::MIN_ENTROPY_LENGTH
        || !text.iter().all(u8::is_ascii_graphic)
        || !is_interpolating_prefix(string_prefix(ctx.input, body.start))
    {
        return None;
    }
    interpolated_literal_segments(text, entropy_floor)
}

/// the literal text of an f-string or t-string body, as ranges of the body: the runs outside its
/// `{...}` holes. `{{` and `}}` are literal braces and a backslash escape is literal text. the
/// reading is taken only when every hole is code of words (`word_hole_end`) and no run of short
/// groups crosses the whole body, holes and literal text together (`is_chunked_with_digits`), so a
/// token cut into short pieces by holes stays one candidate. `None` when the body holds no hole,
/// a hole is anything else, or a lone `}` stands outside a hole: such a body is judged whole.
fn interpolated_literal_segments(
    body: &[u8],
    entropy_floor: Option<f64>,
) -> Option<Vec<Range<usize>>> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut holes = 0_usize;
    while index < body.len() {
        match (body[index], body.get(index + 1)) {
            (b'\\', _) | (b'{', Some(b'{')) | (b'}', Some(b'}')) => index += 2,
            (b'}', _) => return None,
            (b'{', _) => {
                let end = word_hole_end(body, index)?;
                if !is_word_code(&body[index + 1..end - 1], b"", entropy_floor) {
                    return None;
                }
                segments.push(start..index);
                index = end;
                start = end;
                holes += 1;
            }
            _ => index += 1,
        }
    }
    segments.push(start.min(body.len())..body.len());
    segments.retain(|segment| !segment.is_empty());
    (holes > 0 && !crate::scanner::wordshape::is_chunked_with_digits(body, b"")).then_some(segments)
}

/// the deepest call or subscript nesting an f-string hole may hold.
const MAX_HOLE_DEPTH: usize = 4;

/// the end of the f-string hole whose `{` is at `open`, past its `}`, when the hole holds one
/// expression built from names (`hole_expression_end`) and at most an `!r`, `!s` or `!a`
/// conversion. a quoted string, a backslash, a format spec after `:`, an operator, a space or a
/// nested brace is no such hole, and the body holding it is judged whole.
fn word_hole_end(body: &[u8], open: usize) -> Option<usize> {
    let mut index = hole_expression_end(body, open + 1, 0)?;
    if body.get(index) == Some(&b'!') {
        if !matches!(body.get(index + 1), Some(b'r' | b's' | b'a')) {
            return None;
        }
        index += 2;
    }
    (body.get(index) == Some(&b'}')).then_some(index + 1)
}

/// the end of an expression in an f-string hole: a name followed by any number of member accesses
/// (`.name`), calls (`(args)`) and subscripts (`[index]`).
fn hole_expression_end(body: &[u8], start: usize, depth: usize) -> Option<usize> {
    if depth > MAX_HOLE_DEPTH {
        return None;
    }
    let mut index = hole_name_end(body, start)?;
    loop {
        index = match body.get(index) {
            Some(b'.') => hole_name_end(body, index + 1)?,
            Some(b'(') => hole_arguments_end(body, index + 1, b')', depth + 1)?,
            Some(b'[') => hole_arguments_end(body, index + 1, b']', depth + 1)?,
            _ => return Some(index),
        };
    }
}

/// the end of a call's argument list or a subscript, entered after its opener: expressions or
/// numbers of at most four digits, a call's optionally behind a keyword `name=` and separated by
/// `,`, closed by `close`. a call may be empty; a subscript holds one item.
fn hole_arguments_end(body: &[u8], start: usize, close: u8, depth: usize) -> Option<usize> {
    let call = close == b')';
    if call && body.get(start) == Some(&b')') {
        return Some(start + 1);
    }
    let mut index = start;
    loop {
        if call
            && let Some(end) = hole_name_end(body, index)
            && body.get(end) == Some(&b'=')
            && body.get(end + 1) != Some(&b'=')
        {
            index = end + 1;
        }
        let digits = body
            .get(index..)?
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        index = if (1..=4).contains(&digits) {
            index + digits
        } else {
            hole_expression_end(body, index, depth)?
        };
        match body.get(index) {
            Some(b',') if call => index += 1,
            Some(&byte) if byte == close => return Some(index + 1),
            _ => return None,
        }
    }
}

/// the end of a name in an f-string hole: a letter or `_`, then letters, digits and `_`.
fn hole_name_end(body: &[u8], start: usize) -> Option<usize> {
    let tail = body.get(start..)?;
    tail.first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        .then(|| {
            start
                + tail
                    .iter()
                    .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                    .count()
        })
}

/// the reading of an unquoted assignment value, which the grammar captures as a shell word: a
/// string prefix and its quotes, a `&&` and the word after it all stay inside it. the value is
/// narrowed only where that is proved:
///
/// - a shell `&&` list operator followed by a command word that is code of words ends the value
///   before it (`list_operator_end`); an opaque word stays part of the value;
/// - a quoted string behind a language string prefix or the `#`s of a swift raw string
///   (`prefixed_quoted_body`) is read as its body, as a double- or single-quoted value, when the
///   assignment is not env-style, where the legacy boundary below left only the prefix. an
///   env-style value stays the whole word a shell reads (`VALUE=b"x"<word>` is one word, and on
///   the pathless surface, a shell script or a file of unknown language `f"{...}"` is literal
///   data), and is read as its body only when the string closes the value on a source file whose
///   language has string prefixes (the rust and go tracker, or a file the parser posture reads)
///   and the body opens no `{`, unless each such brace is a python f-string hole of code
///   (`python_hole_segments`): a brace the grammar cannot prove to be a hole would hand the body
///   to the template step the whole word never met;
/// - any other value of a non-env-style assignment ends at its first unescaped quote, the legacy
///   boundary.
fn read_unquoted_value(
    ctx: &MatchContext<'_>,
    key_start: usize,
    mut value: Range<usize>,
    entropy_floor: Option<f64>,
) -> (CaptureKind, Range<usize>) {
    if let Some(end) = list_operator_end(&ctx.input[value.clone()], entropy_floor) {
        value.end = value.start + end;
    }
    let secret = &ctx.input[value.clone()];
    let env_style = is_env_style_assignment(ctx.input, key_start, secret);
    if let Some((kind, body, end)) = prefixed_quoted_body(secret) {
        let body = value.start + body.start..value.start + body.end;
        let source_file = ctx.literals.is_some()
            || ctx
                .file_path
                .is_some_and(crate::scanner::source_literals::supports_path);
        if !env_style
            || (end == secret.len()
                && source_file
                && (!ctx.input[body.clone()].contains(&b'{')
                    || python_hole_segments(ctx, body.clone(), entropy_floor).is_some()))
        {
            return (kind, body);
        }
    } else if !env_style && let Some(end) = first_unescaped_quote(secret) {
        value.end = value.start + end;
    }
    (CaptureKind::Unquoted, value)
}

/// a quoted string opening an unquoted value behind a string prefix -- python `r b u f t`, c and
/// c++ `L u U u8` and their `R` raw forms, one or two letters -- or behind the `#`s of a swift raw
/// string: the quote kind, the body and the end of the closing delimiter, as offsets into the
/// value. the body follows the grammar's quoted values (a backslash escapes the next byte, `''`
/// continues a single-quoted body, a raw body has no escapes and closes on `"` and a run of `#`).
/// `None` when the value opens otherwise or its body does not close inside the value.
fn prefixed_quoted_body(value: &[u8]) -> Option<(CaptureKind, Range<usize>, usize)> {
    let hashes = value.iter().take_while(|&&byte| byte == b'#').count();
    let open = if hashes > 0 {
        hashes
    } else if value.starts_with(b"u8R") {
        3
    } else if value.starts_with(b"u8") {
        2
    } else {
        value
            .iter()
            .take(2)
            .take_while(|byte| b"rRbBuUfFtTL".contains(byte))
            .count()
    };
    let quote = *value.get(open)?;
    if open == 0 || !(quote == b'"' || (quote == b'\'' && hashes == 0)) {
        return None;
    }
    let start = open + 1;
    let mut index = start;
    let close = loop {
        let byte = *value.get(index)?;
        match byte {
            b'\\' if hashes == 0 => index += 2,
            b'\'' if quote == b'\'' && value.get(index + 1) == Some(&b'\'') => index += 2,
            _ if byte == quote => break index,
            _ => index += 1,
        }
    };
    let mut end = close + 1;
    if hashes > 0 {
        let closing = value[end..]
            .iter()
            .take_while(|&&byte| byte == b'#')
            .count();
        if closing == 0 {
            return None;
        }
        end += closing;
    }
    let kind = if quote == b'"' {
        CaptureKind::Double
    } else {
        CaptureKind::Single
    };
    Some((kind, start..close, end))
}

/// where a shell `&&` list operator ends an unquoted value: before the first `&&` whose command
/// word (a letter or `_`, then letters, digits, `_` and `-`) ends the value or is followed by `;`,
/// when that word is code of words (`is_word_code`), so `KEY=<value>&&make` reports the value
/// alone. an opaque word (`KEY=<value>&&<token>`) leaves the whole value, as the shell word it is.
fn list_operator_end(value: &[u8], entropy_floor: Option<f64>) -> Option<usize> {
    let mut from = 1;
    while let Some(offset) = value.get(from..)?.windows(2).position(|pair| pair == b"&&") {
        let operator = from + offset;
        let word = &value[operator + 2..];
        let length = word
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            .count();
        if word
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && matches!(word.get(length), None | Some(b';'))
        {
            return is_word_code(&word[..length], b"", entropy_floor).then_some(operator);
        }
        from = operator + 1;
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureKind {
    Unquoted,
    Bare,
    Double,
    Single,
    Bracket,
    Call,
    Other,
}

/// a regex candidate carries the stretch of input its assignment owns (`assignment_scopes`).
enum Candidate<'a> {
    Regex(regex::bytes::Captures<'a>, Range<usize>),
    Call(Range<usize>),
}

impl<'a> Candidate<'a> {
    fn get(&self, index: usize) -> Option<regex::bytes::Match<'a>> {
        match self {
            Self::Regex(captures, _) => captures.get(index),
            Self::Call(_) => None,
        }
    }

    fn named(&self, index: Option<usize>) -> Option<regex::bytes::Match<'a>> {
        index.and_then(|index| self.get(index))
    }

    fn call_range(&self) -> Option<Range<usize>> {
        match self {
            Self::Regex(..) => None,
            Self::Call(range) => Some(range.clone()),
        }
    }

    fn scope(&self) -> Option<Range<usize>> {
        match self {
            Self::Regex(_, scope) => Some(scope.clone()),
            Self::Call(_) => None,
        }
    }

    fn kind(&self, original_range: &Range<usize>, indices: &CaptureIndices) -> CaptureKind {
        if matches!(self, Self::Call(_)) {
            return CaptureKind::Call;
        }
        indices
            .kind_groups
            .into_iter()
            .zip([
                CaptureKind::Other,
                CaptureKind::Unquoted,
                CaptureKind::Bare,
                CaptureKind::Double,
                CaptureKind::Single,
                CaptureKind::Bracket,
            ])
            .find_map(|(index, kind)| {
                self.named(index)
                    .filter(|matched| matched.range() == *original_range)
                    .map(|_| kind)
            })
            .unwrap_or(CaptureKind::Other)
    }
}

/// call bodies have no key: key allowances and the assignment-only hex bypass cannot apply.
/// a 40-byte hex body below 4.0 bits therefore remains a recall residual.
fn evaluate_candidate(
    ctx: &MatchContext<'_>,
    rule: &crate::scanner::rules::CompiledRule,
    captures: Candidate<'_>,
    emit: &mut impl FnMut(&str, Range<usize>),
    normalized: &mut impl FnMut(Range<usize>),
) {
    let is_entropy_value = rule.id == "generic-high-entropy-value";
    // step 4: extract secret value via capture group
    let secret_match = captures
        .get(rule.secret_group)
        .or_else(|| {
            rule.secret_groups
                .iter()
                .find_map(|&group| captures.get(group))
        })
        .or_else(|| captures.get(0));
    let Some(original_range) = captures
        .call_range()
        .or_else(|| secret_match.map(|m| m.range()))
    else {
        return;
    };
    let mut kind = captures.kind(&original_range, &rule.capture_indices);
    let mut secret_range = original_range.clone();
    let mut secret = &ctx.input[secret_range.clone()];

    // the unquoted alternative of a named-key contextual rule: its value is judged on its own.
    // one trailing `,`/`;` is a shell or call separator, never part of the credential, so it is
    // neither reported nor masked; the word-end check still reads the untrimmed word.
    let unquoted_arm = !is_entropy_value
        && captures
            .named(rule.capture_indices.context_unquoted)
            .is_some_and(|value| value.range() == original_range);
    let unquoted_word_ends = unquoted_arm
        && (ends_word(ctx.input, original_range.end)
            || (ctx.input.get(original_range.end) == Some(&b'"')
                && captures
                    .get(0)
                    .is_some_and(|matched| ctx.input[matched.start()] == b'"')
                && ends_word(ctx.input, original_range.end + 1)));
    if unquoted_arm && matches!(secret.last(), Some(b',' | b';')) && secret.len() > 1 {
        secret_range.end -= 1;
        secret = &ctx.input[secret_range.clone()];
    }

    if is_entropy_value
        && kind == CaptureKind::Unquoted
        && let Some(key) = captures.named(rule.capture_indices.entropy_key)
    {
        (kind, secret_range) =
            read_unquoted_value(ctx, key.start(), secret_range, rule.entropy_threshold);
        secret = &ctx.input[secret_range.clone()];
    }

    // a python f-string or t-string body is literal text around `{...}` holes of code. on a python
    // file, when every hole is code of words (`interpolated_literal_segments`), each literal run is
    // judged on its own as a keyless literal body, so a hole never lends its bytes to a value; the
    // parser posture's clip then finds each segment inside a literal body. any other body is judged
    // whole: on every other surface `f"{...}"` is literal data, and a hole holding a quoted string,
    // an escape, a format spec or an opaque run is not proved to be code. a phrase body keeps its
    // whole-value outcome, and the rust and go tracker, whose languages have no such string, keeps
    // its own body check.
    if is_entropy_value
        && matches!(kind, CaptureKind::Double | CaptureKind::Single)
        && let Some(segments) =
            python_hole_segments(ctx, secret_range.clone(), rule.entropy_threshold)
    {
        normalized(secret_range.clone());
        trace_exemption(ctx, emit, "hole", secret_range.clone());
        for segment in segments {
            let segment = secret_range.start + segment.start..secret_range.start + segment.end;
            evaluate_candidate(ctx, rule, Candidate::Call(segment), emit, &mut unowned);
        }
        return;
    }

    // a uri scheme read as a key splits `https://host/...` into the key `https` and the value
    // `//host/...`. a split value that would be reported becomes the whole url again, from its
    // scheme and without a key, so the url steps judge the complete url. the split value has
    // already met the entropy gate, which the url is not measured against again; a split value
    // the path check, the reference path step or the entropy gate would drop keeps that outcome,
    // so re-anchoring only ever narrows what is reported.
    let mut key_match = captures.named(rule.capture_indices.entropy_key);
    let mut reanchored = false;
    if is_entropy_value
        && kind == CaptureKind::Unquoted
        && let Some(key) = key_match
        && key.end() + 1 == secret_range.start
        && ctx.input[key.end()] == b':'
        && secret.starts_with(b"//")
        && is_uri_scheme(key.as_bytes())
        && secret.len() >= entropy::MIN_ENTROPY_LENGTH
        && secret.iter().all(u8::is_ascii_graphic)
        && !entropy::is_path_shaped(secret)
        && !(ctx.allowlist.exemption_layer && entropy::is_reference_rooted(secret))
        && effective_threshold(ctx, rule)
            .is_none_or(|threshold| entropy::passes_entropy_check(secret, threshold))
    {
        secret_range.start = key.start();
        secret = &ctx.input[secret_range.clone()];
        key_match = None;
        reanchored = true;
    }

    // ownership precedes all dispositions, including key allowlisting.
    normalized(secret_range.clone());
    if is_entropy_value
        && kind != CaptureKind::Call
        && let Some(literals) = ctx.literals
        && !literals
            .bodies
            .iter()
            .any(|body| body.start <= secret_range.start && secret_range.end <= body.end)
    {
        trace_exemption(ctx, emit, "code", secret_range.clone());
        return;
    }

    if secret.is_empty() {
        return;
    }
    // payload checks use only the configured inner capture, keeping fixed provider prefixes out
    // of the entropy measurement.
    if let Some(payload) = rule.payload_group.and_then(|group| captures.get(group)) {
        let payload = payload.as_bytes();
        if rule
            .min_payload_entropy
            .is_some_and(|floor| entropy::shannon_entropy(payload) < floor)
            || (rule.reject_hex_payload && payload.iter().all(u8::is_ascii_hexdigit))
        {
            return;
        }
    }
    if rule.id == "generic-password-assignment"
        && let Some(key_match) = captures.named(rule.capture_indices.password_key)
    {
        let key = key_match.as_bytes();
        let key = if key.len() >= 2
            && matches!(key[0], b'\'' | b'"' | b'`')
            && key[0] == key[key.len() - 1]
        {
            &key[1..key.len() - 1]
        } else {
            key
        };
        if matches!(key, b"PWD" | b"OLDPWD") {
            return;
        }
    }
    // the unquoted alternative of a named-key contextual rule reads a whole shell or yaml word,
    // which may be a filesystem path (`SECRET_KEY=/run/secrets/key`), a path rooted at a
    // variable reference or a source expression rather than a credential. a run that stops
    // before its word ends is no reading at all. this is part of that alternative's own
    // reading, independent of the heuristic rule's exemption layer and its switch.
    if unquoted_arm
        && (!unquoted_word_ends
            || entropy::is_path_shaped(secret)
            || entropy::is_reference_rooted(secret)
            || is_source_expression_value(
                secret,
                effective_threshold(ctx, rule),
                captures.get(0).is_some_and(|matched| {
                    is_secret_reference_assignment(
                        &ctx.input[matched.start()..original_range.start],
                    )
                }),
            ))
    {
        return;
    }
    if is_entropy_value
        && (secret.len() < entropy::MIN_ENTROPY_LENGTH || !secret.iter().all(u8::is_ascii_graphic))
    {
        return;
    }
    if is_entropy_value && entropy::is_path_shaped(secret) {
        return;
    }

    let line = ctx.surrounding_lines(
        captures
            .get(0)
            .map(|m| m.range())
            .unwrap_or_else(|| original_range.clone()),
    );
    let key_bytes = key_match.map(|key_match| {
        let key = key_match.as_bytes();
        if key.len() >= 2 && matches!(key[0], b'\'' | b'"') && key[0] == key[key.len() - 1] {
            &key[1..key.len() - 1]
        } else {
            key
        }
    });
    let mut hex_bypass = false;
    if is_entropy_value && ctx.allowlist.exemption_layer {
        if let Some(label) = ctx.generic_rule_skip.or_else(|| {
            (ctx.allowlist.heuristic_skip_test_paths
                && ctx.literals.is_some_and(|literals| {
                    literals.known
                        && literals.test_span.as_ref().is_some_and(|span| {
                            span.start <= secret_range.start && secret_range.end <= span.end
                        })
                }))
            .then_some("testpath")
        }) {
            trace_exemption(ctx, emit, label, secret_range.clone());
            return;
        }
        if kind != CaptureKind::Call && ctx.allowlist.is_import_line(line) {
            trace_exemption(ctx, emit, "import", secret_range.clone());
            return;
        }
        if let Some(inner) = crate::scanner::urlshape::unwrap_markdown_target(secret) {
            secret = &secret[inner.clone()];
            secret_range = secret_range.start + inner.start..secret_range.start + inner.end;
            if secret.len() < entropy::MIN_ENTROPY_LENGTH {
                trace_exemption(ctx, emit, "markdown", secret_range.clone());
                return;
            }
        }
        // a variable reference counts as a word of the path it roots or carries; only this
        // in-layer step applies it, so the layer switch restores the plain entropy gate.
        if entropy::is_path_shaped(secret) || entropy::is_reference_rooted(secret) {
            trace_exemption(ctx, emit, "path", secret_range.clone());
            return;
        }
        if (kind == CaptureKind::Bare
            && key_bytes.is_none()
            && ctx.surrounding_lines(secret_range.clone()).trim_ascii() == secret
            && entropy::is_relative_id_path(secret))
            || (matches!(
                kind,
                CaptureKind::Unquoted | CaptureKind::Double | CaptureKind::Single
            ) && key_bytes.is_some_and(|key| !key.is_empty())
                && entropy::is_keyed_relative_path(secret))
        {
            trace_exemption(ctx, emit, "relpath", secret_range.clone());
            return;
        }
        if kind == CaptureKind::Bare
            && key_bytes.is_none()
            && ctx.surrounding_lines(secret_range.clone()).trim_ascii() == secret
            && entropy::is_mktemp_path(secret)
        {
            trace_exemption(ctx, emit, "mktemp", secret_range.clone());
            return;
        }
        if crate::scanner::urlshape::is_pinned_action_ref(key_bytes, secret) {
            trace_exemption(ctx, emit, "pin", secret_range.clone());
            return;
        }
        if crate::scanner::urlshape::is_credential_free_url(secret) {
            trace_exemption(ctx, emit, "url", secret_range.clone());
            return;
        }
        // a url is exempt only through the url predicate, never through regex, word, or
        // expression shape.
        let url_shaped = crate::scanner::urlshape::is_url_shaped(secret);
        // the regex step reads the whole value of a quoted, bracketed or literal-body capture, and
        // the body of an unquoted or bare capture that is delimited as a regex literal
        // (`/body/flags`) or is the pattern argument of a regex-taking command or option. it runs
        // on every surface, the pathless text of the redact hook included. on the pathless surface
        // and for an unquoted or bare capture, the readings this step did not have before, a
        // pattern that carries a token (`pattern_carries_token`) is not exempted.
        let regex_body = match kind {
            CaptureKind::Double
            | CaptureKind::Single
            | CaptureKind::Bracket
            | CaptureKind::Call => Some(0..secret.len()),
            CaptureKind::Unquoted | CaptureKind::Bare => regex_literal_body(secret).or_else(|| {
                key_match
                    .is_some_and(|key| follows_regex_command(ctx.input, key.start()))
                    .then_some(0..secret.len())
            }),
            CaptureKind::Other => None,
        };
        let widened_reading =
            ctx.file_path.is_none() || matches!(kind, CaptureKind::Unquoted | CaptureKind::Bare);
        if !url_shaped
            && regex_body.is_some_and(|body| {
                let pattern = &secret[body];
                crate::scanner::regexshape::is_regex_shaped(pattern)
                    && !(widened_reading && pattern_carries_token(pattern))
            })
        {
            trace_exemption(ctx, emit, "regex", secret_range.clone());
            return;
        }
        let core_end = secret_range.end
            - secret
                .iter()
                .rev()
                .take_while(|&&byte| matches!(byte, b';' | b','))
                .count();
        if matches!(kind, CaptureKind::Unquoted | CaptureKind::Bare)
            && !url_shaped
            && let Some(span) =
                crate::scanner::syntax::expression_span(ctx.input, secret_range.start, 4096)
            && span.start <= secret_range.start
            && span.end >= core_end
        {
            trace_exemption(ctx, emit, "syntax", secret_range.clone());
            return;
        }
        if crate::scanner::wordshape::is_word_structured(secret) && !url_shaped {
            trace_exemption(ctx, emit, "wordshape", secret_range.clone());
            return;
        }
        if crate::scanner::litshape::is_symbol_table(secret) && !url_shaped {
            trace_exemption(ctx, emit, "symbols", secret_range.clone());
            return;
        }
        if crate::scanner::litshape::is_format_template(secret) && !url_shaped {
            trace_exemption(ctx, emit, "template", secret_range.clone());
            return;
        }
        if key_match.is_some_and(|key| {
            is_digest_separator(
                &ctx.input[key.end()..secret_range.start],
                matches!(kind, CaptureKind::Double | CaptureKind::Single),
            )
        }) && hash_detect::is_digest_record(key_bytes, secret)
        {
            trace_exemption(ctx, emit, "digest", secret_range.clone());
            return;
        }

        // hex_bypass values meeting the floor skip the shannon-entropy gate at the final step and
        // are emitted if they clear every other gate; this is the one place the layer
        // makes the rule stricter (it admits exact-length hex assignment values that
        // would otherwise fail the shannon gate).
        // the 0.6.x hash context exemption keeps precedence over the hex policy: a hex value whose
        // own assignment carries a hash context word is a hash, not a secret. the word is looked
        // for in the stretch of the line the assignment owns, so a digest assigned before it on
        // the same line does not turn a later hex value into a hash.
        let line_range = ctx.surrounding_range(
            captures
                .get(0)
                .map(|m| m.range())
                .unwrap_or_else(|| original_range.clone()),
        );
        let hash_scope = captures.scope().map_or(line, |scope| {
            let start = scope.start.clamp(line_range.start, line_range.end);
            &ctx.input[start..scope.end.clamp(start, line_range.end)]
        });
        hex_bypass = matches!(
            kind,
            CaptureKind::Double
                | CaptureKind::Single
                | CaptureKind::Bracket
                | CaptureKind::Unquoted
        ) && hash_detect::is_hex_policy_candidate(key_bytes, secret)
            && !hash_detect::is_hash_in_context(
                secret
                    .strip_prefix(b"0x")
                    .or_else(|| secret.strip_prefix(b"0X"))
                    .unwrap_or(secret),
                hash_scope,
            )
            && hex_symbol_entropy(secret) >= HEX_BYPASS_MIN_ENTROPY;
    }

    if is_entropy_value
        && let Some(key) = key_bytes
        && !key.is_empty()
        && ctx.allowlist.is_entropy_key_allowlisted(key)
    {
        return;
    }

    // step 5: per-rule allowlist check
    let allowlisted = match ctx.file_path {
        Some(path) => ctx.allowlist.is_rule_allowlisted(&rule.id, secret, path),
        None => ctx.allowlist.is_rule_value_allowlisted(&rule.id, secret),
    };
    if allowlisted {
        return;
    }

    // step 6: variable reference detection
    let is_reference = if rule.id == "password-in-url" {
        password::is_pure_reference(secret)
    } else {
        ctx.allowlist.is_variable_reference(secret)
    };
    if is_reference {
        return;
    }

    // step 6.5: template line detection for context-dependent rules.
    // if the line contains template syntax (jinja2, erb, php block tags),
    // skip findings from context-dependent rules (tier 2/3). tier 1
    // prefix rules are NOT affected — a real AKIA... key on a template
    // line is still a finding, even if the rule uses entropy.
    if !is_entropy_value
        && (rule.context_dependent || is_password_rule(&rule.id) || is_credential_rule(&rule.id))
        && ctx.allowlist.is_template_line(line)
    {
        return;
    }

    // step 7: stopword filter.
    // tier 1 rules (no entropy threshold) only check for placeholder
    // patterns (e.g. XXXX...) to avoid false positives on format
    // examples, but skip word-based stopwords since tokens like
    // sk_test_ inherently contain "test".
    // tier 2+ rules, password rules, and credential rules get the
    // full stopword check.
    if NAMED_KEY_RULES.contains(&rule.id.as_str()) && ctx.allowlist.contains_user_stopword(secret) {
        return;
    }
    if rule.id == "password-in-url" {
        if password::is_url_password_placeholder(secret)
            || ctx.allowlist.contains_user_stopword(secret)
        {
            return;
        }
    } else if is_entropy_value {
        if ctx.allowlist.contains_user_stopword(secret) {
            return;
        }
    } else if rule.entropy_threshold.is_some()
        || is_password_rule(&rule.id)
        || is_credential_rule(&rule.id)
    {
        if ctx.allowlist.contains_stopword(secret) {
            return;
        }
    } else if ctx.allowlist.is_placeholder_pattern(secret) {
        return;
    }

    // step 8: hash detection - skip hashes
    // a named-key unquoted value reads hash context from its own assignment only, so a digest
    // elsewhere on the line (`CHECKSUM=<hex> API_KEY=<hex>`) cannot veto it.
    let hash_scope = if unquoted_arm {
        captures
            .get(0)
            .map_or(secret, |m| &ctx.input[m.start()..secret_range.end])
    } else {
        line
    };
    let hash_value = secret
        .strip_prefix(b"0x")
        .or_else(|| secret.strip_prefix(b"0X"))
        .unwrap_or(secret);
    if !is_entropy_value && hash_detect::is_hash_in_context(hash_value, hash_scope) {
        return;
    }

    // step 8.5: password strength heuristic for assignment passwords only.
    // weak/placeholder passwords are allowed through; only strong
    // passwords are flagged as real secrets. the short and lowercase
    // branches of the heuristic apply to concrete literals only; an
    // unquoted value other than a shell assignment word counts as one
    // only in a configuration file.
    if rule.id == "generic-password-assignment" {
        let key = captures.named(rule.capture_indices.password_key);
        let concrete_literal =
            is_concrete_password_literal(ctx.input, ctx.file_path, key, &secret_range)
                || ctx
                    .file_path
                    .and_then(config_syntax)
                    .zip(key)
                    .is_some_and(|(syntax, key)| {
                        is_config_value_literal(ctx.input, syntax, key.range(), &secret_range)
                    });
        if !password::is_strong_assignment_password(secret, concrete_literal) {
            return;
        }
    }

    // step 8.6: for credential rules, filter weak passwords but
    // preserve high-entropy tokens as a safety net for generated
    // passwords with limited character class diversity (e.g. hex).
    // uses raw shannon entropy (no min-length gate) since connection
    // string passwords are typically short.
    if is_credential_rule(&rule.id) && !password::is_strong_password(secret) {
        let threshold = rule.entropy_threshold.unwrap_or(3.5);
        if entropy::shannon_entropy(secret) < threshold {
            return;
        }
    }

    // step 8.7: OpenSSH public key detection (single-line format).
    // lines like "ssh-rsa AAAA... user@host" contain high-entropy
    // base64 that triggers token rules. skip unless detect_public_keys is on.
    if !ctx.allowlist.detect_public_keys && pubkey::is_openssh_public_key(line) {
        return;
    }

    // a hex value under a credential name (32 to 128 digits, optionally `0x`,
    // one trailing `,`/`;` aside): sixteen symbols cap its shannon entropy at 4.0 bits, so the
    // named-key rules' 4.0-bit gate would drop nearly every random hex key. it is measured by its
    // hex symbols instead, as the heuristic rule's hex policy does; a digest with hash context on
    // its line has already been dropped at step 8.
    let named_key_hex = NAMED_KEY_RULES.contains(&rule.id.as_str()) && {
        let value = secret
            .strip_suffix(b",")
            .or_else(|| secret.strip_suffix(b";"))
            .unwrap_or(secret);
        let payload = value
            .strip_prefix(b"0x")
            .or_else(|| value.strip_prefix(b"0X"))
            .unwrap_or(value);
        (32..=128).contains(&payload.len())
            && payload.iter().all(u8::is_ascii_hexdigit)
            && hex_symbol_entropy(payload) >= HEX_BYPASS_MIN_ENTROPY
    };

    // step 9: entropy evaluation (if rule requires it).
    // assignment passwords skip entropy check -- the password strength
    // heuristic (step 8.5) already validates these. the entropy
    // min-length threshold would otherwise reject strong passwords
    // shorter than MIN_ENTROPY_LENGTH (e.g. 12-char passwords).
    if rule.id != "generic-password-assignment"
        && !hex_bypass
        && !named_key_hex
        && !reanchored
        && let Some(mut threshold) = effective_threshold(ctx, rule)
    {
        // apply doc file bonus (raise threshold = less likely to flag)
        if ctx.is_doc_file && !is_entropy_value {
            threshold += ctx.allowlist.doc_entropy_bonus();
        }
        if !entropy::passes_entropy_check(secret, threshold) {
            return;
        }
    }

    emit(&rule.id, secret_range);
}

/// a uniformly random 32-hex value has expected entropy about 3.6 bits (observed minimum 2.65 in
/// 1e6 samples); the 2.0-bit floor excludes only repeated-pattern / low-diversity values while
/// admitting real random hex secrets. 3.0 was rejected: 112 of 1e6 random 32-hex samples fell
/// below it.
const HEX_BYPASS_MIN_ENTROPY: f64 = 2.0;

/// called only after hex policy validation; prefix and case add no symbol diversity.
fn hex_symbol_entropy(value: &[u8]) -> f64 {
    let payload = value
        .strip_prefix(b"0x")
        .or_else(|| value.strip_prefix(b"0X"))
        .unwrap_or(value);
    let mut counts = [0_u32; 16];
    for byte in payload {
        let symbol = match byte.to_ascii_lowercase() {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte.to_ascii_lowercase() - b'a' + 10,
            _ => unreachable!("hex policy validated the payload"),
        };
        counts[usize::from(symbol)] += 1;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = f64::from(count) / payload.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

/// a rule's entropy threshold with the global override applied as a floor (never lowered).
fn effective_threshold(
    ctx: &MatchContext<'_>,
    rule: &crate::scanner::rules::CompiledRule,
) -> Option<f64> {
    rule.entropy_threshold.map(|threshold| {
        ctx.allowlist
            .entropy_threshold_override
            .map_or(threshold, |floor| threshold.max(floor))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parser::{AddedLine, DiffFile};
    use crate::scanner::rules::{Rule, RuleAllowlist, compile_rules, load_default_rules};

    #[test]
    fn exemption_trace_order_and_retargeted_ranges() {
        let scanner = make_scanner(vec![make_rule(
            "generic-high-entropy-value",
            r"(?:(?P<entropy_key>uses): |use crate::)?(?P<entropy_unquoted>[^\s]+)",
            2,
            vec![],
            Some(4.0),
        )]);
        let mut al = default_al();
        al.trace_exemptions = true;
        let token: String = (0..32)
            .map(|index| char::from(if index % 2 == 0 { b'A' } else { b'a' } + index % 26))
            .collect();
        let digest: String = (0..40)
            .map(|index| char::from_digit(index % 16, 16).unwrap())
            .collect();
        let import = format!("use crate::{token};");
        let pin = format!("uses: actions/checkout@{digest}");
        let cases = [
            ("file", token.as_str(), token.as_str(), true),
            ("import", import.as_str(), &import[11..], false),
            ("markdown", "[documentation](tiny)", "tiny", false),
            (
                "path",
                "[docs](./relative/folder/report.md)",
                "./relative/folder/report.md",
                false,
            ),
            ("pin", pin.as_str(), &pin[6..], false),
            (
                "url",
                "https://github.com/owner/repo/compare/v1.0.0...v1.1.0",
                "https://github.com/owner/repo/compare/v1.0.0...v1.1.0",
                false,
            ),
            (
                "syntax",
                "sum(rate(node_tcp_connections[5m]))",
                "sum(rate(node_tcp_connections[5m]))",
                false,
            ),
            (
                "wordshape",
                "hummingbot.strategy.strategy_v2_base.ExecutorOrchestrator",
                "hummingbot.strategy.strategy_v2_base.ExecutorOrchestrator",
                false,
            ),
        ];
        for (name, input, value, generic_rule_disabled) in cases {
            let ctx = MatchContext {
                file_path: None,
                input: input.as_bytes(),
                line_starts: &[],
                scanner: &scanner,
                allowlist: &al,
                is_doc_file: false,
                generic_rule_skip: generic_rule_disabled.then_some("file"),
                literals: None,
            };
            let mut found = Vec::new();
            scan_matches(&ctx, &mut [false], |id, range| {
                found.push((id.to_owned(), range))
            });
            let start = input.find(value).unwrap();
            assert_eq!(
                found,
                vec![(format!("exempt:{name}"), start..start + value.len())],
                "{name}"
            );
        }

        let regex_scanner = make_scanner(vec![make_rule(
            "generic-high-entropy-value",
            r#"pattern = "(?P<entropy_double>[^"]+)""#,
            1,
            vec![],
            Some(4.0),
        )]);
        let regex = r"(?i)^(?:[A-Za-z0-9_-]{20,64}\.){2}[A-Za-z0-9_-]{20,64}$";
        assert!(regex.len() >= entropy::MIN_ENTROPY_LENGTH);
        assert!(entropy::shannon_entropy(regex.as_bytes()) >= 4.0);
        let input = format!("pattern = \"{regex}\"");
        let ctx = MatchContext {
            file_path: Some("src/pattern.rs"),
            input: input.as_bytes(),
            line_starts: &[],
            scanner: &regex_scanner,
            allowlist: &al,
            is_doc_file: false,
            generic_rule_skip: None,
            literals: None,
        };
        let mut found = Vec::new();
        scan_matches(&ctx, &mut [false], |id, range| {
            found.push((id.to_owned(), range))
        });
        let start = input.find(regex).unwrap();
        assert_eq!(
            found,
            vec![("exempt:regex".to_owned(), start..start + regex.len())]
        );

        let mut layer_off = default_al();
        layer_off.exemption_layer = false;
        let ctx = MatchContext {
            file_path: Some("src/pattern.rs"),
            input: input.as_bytes(),
            line_starts: &[],
            scanner: &regex_scanner,
            allowlist: &layer_off,
            is_doc_file: false,
            generic_rule_skip: None,
            literals: None,
        };
        let mut found = Vec::new();
        scan_matches(&ctx, &mut [false], |id, range| {
            found.push((id.to_owned(), range))
        });
        assert_eq!(
            found,
            vec![(
                ("generic-high-entropy-value").to_owned(),
                start..start + regex.len()
            )]
        );

        let unquoted_scanner = make_scanner(vec![make_rule(
            "generic-high-entropy-value",
            r"(?P<entropy_unquoted>[^\s]+)",
            1,
            vec![],
            Some(4.0),
        )]);
        let ctx = MatchContext {
            file_path: Some("src/pattern.rs"),
            input: regex.as_bytes(),
            line_starts: &[],
            scanner: &unquoted_scanner,
            allowlist: &al,
            is_doc_file: false,
            generic_rule_skip: None,
            literals: None,
        };
        let mut found = Vec::new();
        scan_matches(&ctx, &mut [false], |id, range| {
            found.push((id.to_owned(), range))
        });
        assert!(!found.iter().any(|(id, _)| id == "exempt:regex"));

        let input = format!("[docs]({token})");
        let expected = "[docs]([REDACTED])";
        assert_eq!(redact_text(&input, &scanner, &al), expected);
        let matches = scan_text(&input, &scanner, &al);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "generic-high-entropy-value");
        assert_eq!(&input[matches[0].range.clone()], token);
    }

    fn make_rule(
        id: &str,
        pattern: &str,
        group: usize,
        keywords: Vec<&str>,
        threshold: Option<f64>,
    ) -> Rule {
        Rule {
            id: id.into(),
            description: id.into(),
            regex_pattern: pattern.into(),
            secret_group: group,
            secret_groups: Vec::new(),
            keywords: keywords.into_iter().map(String::from).collect(),
            entropy_threshold: threshold,
            payload_group: None,
            min_payload_entropy: None,
            reject_hex_payload: false,
            allowlist: RuleAllowlist::default(),
            class: None,
        }
    }

    fn make_scanner(rules: Vec<Rule>) -> CompiledScanner {
        compile_rules(&rules).unwrap()
    }

    fn make_file(path: &str, lines: Vec<(usize, &[u8])>) -> DiffFile {
        DiffFile {
            path: path.to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            context: None,
            added_lines: lines
                .into_iter()
                .map(|(num, content)| AddedLine {
                    line_number: num,
                    content: content.to_vec(),
                })
                .collect(),
        }
    }

    fn default_al() -> CompiledAllowlist {
        CompiledAllowlist::default_allowlist().unwrap()
    }

    fn generated_token() -> String {
        (0..32)
            .map(|index| {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                char::from(base + (index * 7 % 26))
            })
            .collect()
    }

    fn github_token() -> String {
        let body: String = generated_token().chars().cycle().take(36).collect();
        format!("ghp_{body}")
    }

    #[test]
    fn scan_without_path_filters_reports_original_paths() {
        let scanner = compile_rules(&load_default_rules().unwrap()).unwrap();
        let token = generated_token();
        let line = format!("token = \"{token}\"");
        for path in [
            "../tests/config.rs",
            "/elsewhere/tests/config.rs",
            "tests/../../node_modules/config.js",
            "../Cargo.lock",
            "../config.png",
            "../config.min.js",
            "../.gitignore",
        ] {
            for per_rule in [false, true] {
                let paths = if per_rule { vec![] } else { vec![".*".into()] };
                let rules = if per_rule {
                    vec![(
                        "generic-high-entropy-value".into(),
                        vec![],
                        vec![".*".into()],
                    )]
                } else {
                    vec![]
                };
                let al = CompiledAllowlist::new(&paths, &[], None, &rules, false).unwrap();
                let files = [make_file(path, vec![(7, line.as_bytes())])];
                let regular = scan(&files, &scanner, &al);
                if per_rule {
                    assert!(regular.len() <= 1);
                    assert!(
                        regular
                            .iter()
                            .all(|finding| finding.rule_id == "generic-token-assignment")
                    );
                } else {
                    assert!(regular.is_empty());
                }
                let findings = scan_without_path_filters(&files, &scanner, &al);
                assert_eq!(findings.len(), 2, "{path}, per_rule={per_rule}");
                for finding in findings {
                    assert_eq!(finding.file, path);
                    assert_eq!(finding.line, 7);
                    assert_eq!(finding.matched_value, token.as_bytes());
                }
            }
        }
    }

    #[test]
    fn scan_without_path_filters_preserves_value_checks_and_skips_doc_bonus() {
        let token = generated_token();
        let line = format!("token = \"{token}\"");
        let scanner = make_scanner(vec![make_rule(
            "fixture",
            r#"token = "([^"]+)""#,
            1,
            vec!["token"],
            Some(entropy::shannon_entropy(token.as_bytes()) - 0.5),
        )]);
        let value_rules = vec![("fixture".into(), vec![".*".into()], vec![])];
        let value_al = CompiledAllowlist::new(&[], &[], None, &value_rules, false).unwrap();
        let stopword_al = CompiledAllowlist::new(&[], &[token], None, &[], false).unwrap();
        for (al, path, expected_scan, expected_unfiltered) in [
            (default_al(), "../src/config.rs", 1, 1),
            (default_al(), "../docs/guide.md", 0, 1),
            (default_al(), "docs/../src/config.rs", 0, 1),
            (value_al, "../src/config.rs", 0, 0),
            (stopword_al, "../src/config.rs", 0, 0),
        ] {
            let files = [make_file(path, vec![(3, line.as_bytes())])];
            assert_eq!(scan(&files, &scanner, &al).len(), expected_scan, "{path}");
            assert_eq!(
                scan_without_path_filters(&files, &scanner, &al).len(),
                expected_unfiltered,
                "{path}"
            );
        }
        let files = [make_file(
            "../src/config.rs",
            vec![
                (1, b"-----BEGIN PUBLIC KEY-----"),
                (2, line.as_bytes()),
                (3, b"-----END PUBLIC KEY-----"),
            ],
        )];
        let al = default_al();
        assert!(scan(&files, &scanner, &al).is_empty());
        assert!(scan_without_path_filters(&files, &scanner, &al).is_empty());
    }

    #[test]
    fn scan_keywordless_only_scanner() {
        let scanner = make_scanner(vec![make_rule("always", r"opaque", 0, vec![], None)]);
        let file = make_file("config.txt", vec![(1, b"opaque"), (2, b"clean")]);
        let findings = scan(&[file], &scanner, &default_al());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "always");
        assert_eq!(findings[0].matched_value, b"opaque");
        assert_eq!(scan_text("opaque", &scanner, &default_al()).len(), 1);
    }

    #[test]
    fn scan_mixed_rules_preserves_and_resets_keyword_prefilter() {
        let scanner = make_scanner(vec![
            make_rule("always", r"opaque", 0, vec![], None),
            make_rule("prefiltered", r"opaque", 0, vec!["marker"], None),
        ]);
        let file = make_file("config.txt", vec![(1, b"marker opaque"), (2, b"opaque")]);
        let findings = scan(&[file], &scanner, &default_al());
        let ids: Vec<_> = findings
            .iter()
            .map(|finding| (finding.line, finding.rule_id.as_str()))
            .collect();
        assert_eq!(ids, [(1, "always"), (1, "prefiltered"), (2, "always")]);
        let matches = scan_text("opaque", &scanner, &default_al());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "always");
    }

    #[test]
    fn scan_empty_rules() {
        let scanner = make_scanner(vec![]);
        let file = make_file("config.txt", vec![(1, b"opaque")]);
        assert!(scan(&[file], &scanner, &default_al()).is_empty());
        assert!(scan_text("opaque", &scanner, &default_al()).is_empty());
    }

    #[test]
    fn scan_empty_files() {
        let scanner = make_scanner(vec![make_rule(
            "test",
            r"secret_[a-z]+",
            0,
            vec!["secret_"],
            None,
        )]);
        let al = default_al();
        let files: Vec<DiffFile> = vec![];
        let findings = scan(&files, &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_detects_keyword_match() {
        let scanner = make_scanner(vec![make_rule(
            "aws-access-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        let file = make_file(
            "config.rs",
            vec![(42, b"let key = \"AKIAIOSFODNN7ABCDEFGH\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].file, "config.rs");
        assert_eq!(findings[0].line, 42);
    }

    #[test]
    fn scan_skips_no_keyword_match() {
        let scanner = make_scanner(vec![make_rule(
            "aws-access-key",
            r"AKIA[A-Z0-9]{16}",
            0,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        // line has no "akia" keyword
        let file = make_file("config.rs", vec![(1, b"let x = 42;")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_deleted_files() {
        let scanner = make_scanner(vec![make_rule(
            "test",
            r"AKIA[A-Z0-9]{16}",
            0,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        let mut file = make_file("old.rs", vec![(1, b"AKIAIOSFODNN7ABCDEFGH")]);
        file.is_deleted = true;
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_binary_files() {
        let scanner = make_scanner(vec![make_rule(
            "test",
            r"AKIA[A-Z0-9]{16}",
            0,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        let mut file = make_file("image.png", vec![(1, b"AKIAIOSFODNN7ABCDEFGH")]);
        file.is_binary = true;
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_entropy_filter_blocks_low_entropy() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            Some(3.5),
        )]);
        let al = default_al();
        // low entropy secret (repeated chars)
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aaaaaaaaaaaaaaaaaaaaaaaa\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_entropy_filter_allows_high_entropy() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            Some(3.0),
        )]);
        let al = default_al();
        // high entropy secret
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_skips_sha256_hash_with_context() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            None,
        )]);
        let al = default_al();
        // the captured value is exactly 64 hex chars (SHA-256) in a line with checksum context
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_detects_hex_secret_at_hash_length() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            None,
        )]);
        let al = default_al();
        // 64 hex chars but no hash context - should be detected as a secret
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(
            findings.len(),
            1,
            "hex secret without hash context should be detected"
        );
    }

    #[test]
    fn scan_skips_git_commit_hash_in_context() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            None,
        )]);
        let al = default_al();
        // 40-char hex (SHA-1) in a line with "commit" context
        let file = make_file(
            "config.rs",
            vec![(
                1,
                b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_multiple_files_multiple_rules() {
        let scanner = make_scanner(vec![
            make_rule("aws-key", r"(AKIA[A-Z0-9]{16})", 1, vec!["akia"], None),
            make_rule(
                "github-token",
                r"(ghp_[0-9a-zA-Z]{36})",
                1,
                vec!["ghp_"],
                None,
            ),
        ]);
        let al = default_al();
        let file1 = make_file("aws.rs", vec![(10, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")]);
        let github_line = format!("token = \"{}\"", github_token());
        let file2 = make_file("github.rs", vec![(20, github_line.as_bytes())]);
        let findings = scan(&[file1, file2], &scanner, &al);
        assert_eq!(findings.len(), 2);
        // with parallel processing, order may vary, so check both exist
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "aws-key" && f.file == "aws.rs")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "github-token" && f.file == "github.rs")
        );
    }

    #[test]
    fn scan_capture_group_zero_uses_full_match() {
        let scanner = make_scanner(vec![make_rule(
            "prefix-token",
            r"ghp_[0-9a-zA-Z]{36}",
            0,
            vec!["ghp_"],
            None,
        )]);
        let al = default_al();
        let token = github_token();
        let file = make_file("test.rs", vec![(1, token.as_bytes())]);
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].matched_value, token.as_bytes());
    }

    #[test]
    fn scan_with_default_rules_detects_aws_key() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let file = make_file(
            "config.py",
            vec![(5, b"AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.iter().any(|f| f.rule_id == "aws-access-key-id"),
            "expected aws-access-key-id finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn scan_with_default_rules_detects_github_token() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let line = format!("TOKEN = \"{}\"", github_token());
        let file = make_file("config.py", vec![(5, line.as_bytes())]);
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "github-personal-access-token"),
            "expected github-personal-access-token finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn scan_with_default_rules_detects_pem_key() {
        let rules = crate::scanner::rules::load_default_rules().unwrap();
        let scanner = compile_rules(&rules).unwrap();
        let al = default_al();
        let file = make_file("key.pem", vec![(1, b"-----BEGIN RSA PRIVATE KEY-----")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.iter().any(|f| f.rule_id == "pem-private-key"),
            "expected pem-private-key finding, got: {:?}",
            findings
        );
    }

    // -- allowlist integration tests --

    #[test]
    fn scan_skips_allowlisted_paths() {
        let scanner = make_scanner(vec![make_rule(
            "aws-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        // file in a vendor directory
        let file = make_file(
            "node_modules/some-lib/config.js",
            vec![(1, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip vendor directory files");
    }

    #[test]
    fn scan_skips_binary_extension_paths() {
        let scanner = make_scanner(vec![make_rule(
            "aws-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        let file = make_file("screenshot.png", vec![(1, b"AKIAIOSFODNN7ABCDEFGH")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip binary file extensions");
    }

    #[test]
    fn scan_skips_generated_files() {
        let scanner = make_scanner(vec![make_rule(
            "aws-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        let file = make_file("package-lock.json", vec![(1, b"AKIAIOSFODNN7ABCDEFGH")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip generated files");
    }

    #[test]
    fn scan_skips_stopword_secrets() {
        // stopword filtering only applies to rules with entropy thresholds (tier 2+)
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            Some(3.5),
        )]);
        let al = default_al();
        let file = make_file(
            "config.rs",
            vec![(1, b"secret = \"example_token_for_testing\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(
            findings.is_empty(),
            "should skip secrets containing stopwords"
        );
    }

    #[test]
    fn scan_skips_variable_references() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            None,
        )]);
        let al = default_al();
        let file = make_file("config.rs", vec![(1, b"secret = \"${DB_PASSWORD}\"")]);
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip variable references");
    }

    #[test]
    fn scan_skips_process_env_references() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            None,
        )]);
        let al = default_al();
        let file = make_file(
            "config.js",
            vec![(1, b"secret = \"process.env.SECRET_KEY\"")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty(), "should skip process.env references");
    }

    #[test]
    fn scan_with_per_rule_allowlist() {
        let rules = vec![Rule {
            id: "aws-key".to_string(),
            description: "AWS key".to_string(),
            regex_pattern: r"(AKIA[A-Z0-9]{16})".to_string(),
            secret_group: 1,
            secret_groups: Vec::new(),
            keywords: vec!["akia".to_string()],
            entropy_threshold: None,
            payload_group: None,
            min_payload_entropy: None,
            reject_hex_payload: false,
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
            class: None,
        }];
        let scanner = compile_rules(&rules).unwrap();
        let al = crate::config::build_allowlist(&crate::config::ProjectConfig::default(), &rules)
            .unwrap();

        // the example key should be skipped
        let file1 = make_file("config.py", vec![(5, b"key = \"AKIAIOSFODNN7EXAMPLE\"")]);
        let findings1 = scan(&[file1], &scanner, &al);
        assert!(
            findings1.is_empty(),
            "example AWS key should be allowlisted"
        );

        // a real key should be detected
        let file2 = make_file("config.py", vec![(5, b"key = \"AKIAIOSFODNN7ABCDEFG\"")]);
        let findings2 = scan(&[file2], &scanner, &al);
        assert_eq!(findings2.len(), 1, "real AWS key should be detected");
    }

    #[test]
    fn scan_doc_files_get_entropy_bonus() {
        let scanner = make_scanner(vec![make_rule(
            "generic-secret",
            r#"(?i)secret\s*=\s*['"]([^'"]+)['"]"#,
            1,
            vec!["secret"],
            Some(3.0),
        )]);
        let al = default_al();

        // a value with moderate entropy that would trigger in source code
        let line = b"secret = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"";

        // in a source file, it should be detected
        let src_file = make_file("src/config.rs", vec![(1, line)]);
        let findings_src = scan(&[src_file], &scanner, &al);
        assert!(!findings_src.is_empty(), "should detect in source files");

        // in a doc file (README.md), the raised threshold allows it through.
        // with 1.0 bonus, threshold becomes 4.0 instead of 3.0, so the
        // same string that triggers in source should not trigger in docs.
        let doc_file = make_file("README.md", vec![(1, line)]);
        let findings_doc = scan(&[doc_file], &scanner, &al);
        assert!(
            findings_doc.len() <= findings_src.len(),
            "doc files should not flag more than source files"
        );
    }

    #[test]
    fn scan_detects_second_match_when_first_filtered() {
        let scanner = make_scanner(vec![make_rule(
            "aws-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        // set up an allowlist that skips the example key but not a real one
        let rules = vec![crate::scanner::rules::Rule {
            id: "aws-key".to_string(),
            description: "AWS key".to_string(),
            regex_pattern: r"(AKIA[A-Z0-9]{16})".to_string(),
            secret_group: 1,
            secret_groups: Vec::new(),
            keywords: vec!["akia".to_string()],
            entropy_threshold: None,
            payload_group: None,
            min_payload_entropy: None,
            reject_hex_payload: false,
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
            class: None,
        }];
        let al = crate::config::build_allowlist(&crate::config::ProjectConfig::default(), &rules)
            .unwrap();

        // line has two AWS keys: first is the allowlisted example, second is real
        let file = make_file(
            "config.py",
            vec![(
                5,
                b"keys = [\"AKIAIOSFODNN7EXAMPLE\", \"AKIAIOSFODNN7ABCDEFG\"]",
            )],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(
            findings.len(),
            1,
            "should detect the second (real) key even though first is allowlisted"
        );
        assert_eq!(findings[0].matched_value, b"AKIAIOSFODNN7ABCDEFG");
    }

    #[test]
    fn scan_skips_files_with_no_added_lines() {
        let scanner = make_scanner(vec![make_rule(
            "test",
            r"secret_[a-z]+",
            0,
            vec!["secret_"],
            None,
        )]);
        let al = default_al();
        let file = DiffFile {
            path: "empty.rs".to_string(),
            is_new: false,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            context: None,
            added_lines: vec![],
        };
        let findings = scan(&[file], &scanner, &al);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_parallel_with_many_files() {
        let scanner = make_scanner(vec![make_rule(
            "aws-key",
            r"(AKIA[A-Z0-9]{16})",
            1,
            vec!["akia"],
            None,
        )]);
        let al = default_al();
        // create enough files to trigger parallel processing
        let files: Vec<DiffFile> = (0..10)
            .map(|i| {
                make_file(
                    &format!("file{}.rs", i),
                    vec![(1, b"key = \"AKIAIOSFODNN7ABCDEFGH\"")],
                )
            })
            .collect();
        let findings = scan(&files, &scanner, &al);
        assert_eq!(findings.len(), 10);
    }

    #[test]
    fn source_expression_values_and_the_recall_guard() {
        // code and word values under a credential-named key
        for (value, floor) in [
            (&b"self.data.api_key"[..], 4.0),
            (b"endpoint.api_key,", 4.0),
            (b"text[token_start", 4.0),
            (b"self.config.api_key", 4.0),
            (b"app.config.SECRET_KEY", 3.5),
            (b"settings.DJANGO_SECRET_KEY", 3.5),
            (b"config.providers.anthropic.api_key", 4.0),
            (b"SecretStr", 3.5),
            (b"ingress-tls-secret", 3.5),
        ] {
            assert!(
                is_source_expression_value(value, Some(floor), false),
                "{}",
                String::from_utf8_lossy(value)
            );
        }
        // the guard: token length, the rule's threshold cleared, near-distinct bytes
        assert!(folded_distinct_ratio(b"plmoknijuh.bqygtverfc") >= NEAR_DISTINCT_RATIO);
        assert!(!is_source_expression_value(
            b"plmoknijuh.bqygtverfc",
            Some(4.0),
            false
        ));
        assert!(!is_source_expression_value(
            b"plmoknijuh.bqygtverfc;",
            Some(4.0),
            false
        ));
        // the case fold: a mixed-case chain is judged by its letters, not their case
        assert!(folded_distinct_ratio(b"settings.DJANGO_SECRET_KEY") < NEAR_DISTINCT_RATIO);
        // a lone word is a word value only below 16 bytes
        assert!(is_source_expression_value(b"postgresql", Some(3.5), false));
        assert!(is_source_expression_value(b"required", Some(3.5), false));
        // a lone letter run of token length or an opaque piece is never a word value
        assert!(!is_source_expression_value(
            b"plmoknijuhbqygtv",
            Some(4.0),
            false
        ));
        assert!(!is_source_expression_value(b"kx7mq2pl", Some(3.5), false));
        assert!(!is_source_expression_value(
            b"q8Vn3sY6.Kp4Zr9Tw",
            Some(4.0),
            false
        ));
        assert!(!is_source_expression_value(
            b"abcd-efgh-ijkl-mnop",
            Some(4.0),
            false
        ));
    }

    #[test]
    fn a_context_value_must_end_its_word() {
        assert!(ends_word(b"API_KEY=value", 13));
        assert!(ends_word(b"API_KEY=value rest", 13));
        assert!(ends_word(b"API_KEY=value\r\n", 13));
        assert!(ends_word(b"API_KEY=value\0next", 13));
        assert!(!ends_word(b"API_KEY=value\"x\"", 13));
        assert!(!ends_word(b"API_KEY=value(x)", 13));
    }
}
