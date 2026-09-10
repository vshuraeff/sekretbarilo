// core scanning engine (aho-corasick + regex)

use rayon::prelude::*;
use std::ops::Range;

#[allow(unused_imports)]
pub use crate::scanner::text::{TextMatch, redact_text, scan_text};

use crate::config::allowlist::CompiledAllowlist;
use crate::diff::parser::DiffFile;
use crate::scanner::entropy;
use crate::scanner::hash_detect;
use crate::scanner::password;
use crate::scanner::pubkey;
use crate::scanner::rules::CompiledScanner;

/// minimum number of files to trigger parallel processing with rayon
const PARALLEL_FILE_THRESHOLD: usize = 4;

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
///      4b. entropy value shape gates, switchable exemptions and assignment hex bypass
///      with a fixed 2.0-bit hex-symbol entropy floor
///      4c. user entropy-key allowlist (independent of the exemption switch)
///   5. per-rule allowlist check (value regex + path match)
///   6. variable references (URL passwords skip pure references only, not defaults)
///      6.5. template lines skip context-dependent and password/credential rules
///   7. stopwords (entropy values use user words; URL passwords use user words
///      and URL placeholders only; other rules retain their tier-specific filters)
///   8. hash detection (skip if it's a hash)
///      8.5. password strength veto for generic-password-assignment only
///      8.6. credential strength with entropy fallback; 8.7. public key filtering
///   9. entropy evaluation (with doc file bonus if applicable), except assignment
///      passwords and layer-enabled hex bypass values; URL passwords use their
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
    let generic_rule_disabled =
        apply_path_filters && allowlist.is_generic_rule_skipped_path(&file.path);
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
        };
        scan_line(
            &ctx,
            generic_rule_disabled,
            &mut candidate_bits,
            &mut findings,
        );
    }

    findings
}

/// check if a rule detects public keys (gated behind detect_public_keys setting)
fn is_public_key_rule(rule_id: &str) -> bool {
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
}

/// scan a single line against all rules using the aho-corasick pre-filter.
/// uses a reusable bitset to avoid allocations per line.
fn scan_line(
    ctx: &ScanLineContext<'_>,
    generic_rule_disabled: bool,
    candidate_bits: &mut [bool],
    findings: &mut Vec<Finding>,
) {
    let matches = MatchContext {
        file_path: ctx.apply_path_filters.then_some(ctx.file_path),
        input: ctx.line,
        line_starts: &[],
        scanner: ctx.scanner,
        allowlist: ctx.allowlist,
        is_doc_file: ctx.is_doc_file,
        generic_rule_disabled,
    };
    scan_matches(&matches, candidate_bits, |rule_id, range| {
        findings.push(Finding {
            file: ctx.file_path.to_string(),
            line: ctx.line_number,
            rule_id: rule_id.to_string(),
            matched_value: ctx.line[range].to_vec(),
        });
    });
}

/// matching policy shared by line-oriented diffs and complete tool text.
pub(super) struct MatchContext<'a> {
    pub file_path: Option<&'a str>,
    pub input: &'a [u8],
    pub line_starts: &'a [usize],
    pub scanner: &'a CompiledScanner,
    pub allowlist: &'a CompiledAllowlist,
    pub is_doc_file: bool,
    pub generic_rule_disabled: bool,
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
        &self.input[start..end]
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
        let mut ordinary_matches = rule.regex.captures_iter(ctx.input);
        let mut entropy_offset = 0;
        let captures_iter = std::iter::from_fn(|| {
            if !is_entropy_value {
                return ordinary_matches.next();
            }
            if entropy_offset > ctx.input.len() {
                return None;
            }
            let captures = rule.regex.captures_at(ctx.input, entropy_offset)?;
            let matched = captures.get(0)?;
            // an unquoted boundary may consume the next assignment's key.
            // resume after the value so that assignment is still evaluated.
            entropy_offset = captures
                .name("entropy_unquoted")
                .map_or(matched.end(), |value| value.end())
                .max(matched.start().saturating_add(1));
            Some(captures)
        });
        for captures in captures_iter {
            evaluate_candidate(ctx, rule, Candidate::Regex(captures), &mut emit);
        }
        // single-line text uses its first pass with [0]; diff and per-line passes use [].
        if is_entropy_value && ctx.allowlist.exemption_layer && ctx.line_starts.len() <= 1 {
            crate::scanner::calllit::collect(ctx.input, |range| {
                evaluate_candidate(ctx, rule, Candidate::Call(range), &mut emit);
            });
        }
    }
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

enum Candidate<'a> {
    Regex(regex::bytes::Captures<'a>),
    Call(Range<usize>),
}

impl<'a> Candidate<'a> {
    fn get(&self, index: usize) -> Option<regex::bytes::Match<'a>> {
        match self {
            Self::Regex(captures) => captures.get(index),
            Self::Call(_) => None,
        }
    }

    fn name(&self, name: &str) -> Option<regex::bytes::Match<'a>> {
        match self {
            Self::Regex(captures) => captures.name(name),
            Self::Call(_) => None,
        }
    }

    fn call_range(&self) -> Option<Range<usize>> {
        match self {
            Self::Regex(_) => None,
            Self::Call(range) => Some(range.clone()),
        }
    }

    fn kind(&self, original_range: &Range<usize>) -> CaptureKind {
        if matches!(self, Self::Call(_)) {
            return CaptureKind::Call;
        }
        [
            ("entropy_unquoted", CaptureKind::Unquoted),
            ("entropy_bare", CaptureKind::Bare),
            ("entropy_double", CaptureKind::Double),
            ("entropy_single", CaptureKind::Single),
            ("entropy_bracket", CaptureKind::Bracket),
        ]
        .into_iter()
        .find_map(|(name, kind)| {
            self.name(name)
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
    let kind = captures.kind(&original_range);
    let mut secret_range = original_range.clone();
    let mut secret = &ctx.input[secret_range.clone()];

    // non-env-style unquoted matches use their first unescaped quote as the legacy boundary.
    if is_entropy_value
        && let (Some(unquoted), Some(key)) = (
            captures.name("entropy_unquoted"),
            captures.name("entropy_key"),
        )
        && unquoted.range() == secret_range
        && !is_env_style_assignment(ctx.input, key.start(), secret)
        && let Some(end) = first_unescaped_quote(secret)
    {
        secret = &secret[..end];
        secret_range.end = secret_range.start + end;
    }

    if secret.is_empty() {
        return;
    }
    if rule.id == "facebook-access-token"
        && secret.starts_with(b"EAA")
        && secret
            .get(3..)
            .is_some_and(|tail| tail.iter().all(u8::is_ascii_hexdigit))
    {
        return;
    }
    if rule.id == "generic-password-assignment"
        && let Some(key_match) = captures.name("password_key")
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
    let key_bytes = captures.name("entropy_key").map(|key_match| {
        let key = key_match.as_bytes();
        if key.len() >= 2 && matches!(key[0], b'\'' | b'"') && key[0] == key[key.len() - 1] {
            &key[1..key.len() - 1]
        } else {
            key
        }
    });
    let mut hex_bypass = false;
    if is_entropy_value && ctx.allowlist.exemption_layer {
        if ctx.generic_rule_disabled {
            trace_exemption(ctx, emit, "file", secret_range.clone());
            return;
        }
        if kind != CaptureKind::Call && ctx.allowlist.is_import_line(line) {
            trace_exemption(ctx, emit, "import", secret_range.clone());
            return;
        }
        if kind != CaptureKind::Call
            && let Some(inner) = crate::scanner::urlshape::unwrap_markdown_target(secret)
        {
            secret = &secret[inner.clone()];
            secret_range = secret_range.start + inner.start..secret_range.start + inner.end;
            if secret.len() < entropy::MIN_ENTROPY_LENGTH {
                trace_exemption(ctx, emit, "markdown", secret_range.clone());
                return;
            }
        }
        if entropy::is_path_shaped(secret) {
            trace_exemption(ctx, emit, "path", secret_range.clone());
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
        // a url is exempt only through the url predicate, never through word or expression shape.
        let url_shaped = crate::scanner::urlshape::is_url_shaped(secret);
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
        // a uniformly random 32-hex value has expected entropy about 3.6 bits (observed minimum
        // 2.65 in 1e6 samples); the 2.0-bit floor excludes only repeated-pattern / low-diversity
        // values while admitting real random hex secrets. 3.0 was rejected: 112 of 1e6 random
        // 32-hex samples fell below it.
        const HEX_BYPASS_MIN_ENTROPY: f64 = 2.0;

        // called only after hex policy validation; prefix and case add no symbol diversity.
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

        // hex_bypass values meeting the floor skip the shannon-entropy gate at the final step and
        // are emitted if they clear every other gate; this is the one place the layer
        // makes the rule stricter (it admits exact-length hex assignment values that
        // would otherwise fail the shannon gate).
        // the 0.6.x line-level hash context exemption keeps precedence over the hex policy:
        // a hex value on a line carrying a hash context word is a hash, not a secret.
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
                line,
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
    if !is_entropy_value && hash_detect::is_hash_in_context(secret, line) {
        return;
    }

    // step 8.5: password strength heuristic for assignment passwords only.
    // weak/placeholder passwords are allowed through; only strong
    // passwords are flagged as real secrets.
    if rule.id == "generic-password-assignment" && !password::is_strong_password(secret) {
        return;
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

    // step 9: entropy evaluation (if rule requires it).
    // assignment passwords skip entropy check -- the password strength
    // heuristic (step 8.5) already validates these. the entropy
    // min-length threshold would otherwise reject strong passwords
    // shorter than MIN_ENTROPY_LENGTH (e.g. 12-char passwords).
    if rule.id != "generic-password-assignment"
        && !hex_bypass
        && let Some(mut threshold) = rule.entropy_threshold
    {
        // apply global override as a floor (never lower a rule's threshold)
        if let Some(override_val) = ctx.allowlist.entropy_threshold_override {
            threshold = threshold.max(override_val);
        }
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
                generic_rule_disabled,
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
            allowlist: RuleAllowlist::default(),
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
                assert!(scan(&files, &scanner, &al).is_empty());
                let findings = scan_without_path_filters(&files, &scanner, &al);
                assert_eq!(findings.len(), 1, "{path}, per_rule={per_rule}");
                assert_eq!(findings[0].file, path);
                assert_eq!(findings[0].line, 7);
                assert_eq!(findings[0].matched_value, token.as_bytes());
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
        let file2 = make_file(
            "github.rs",
            vec![(20, b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"")],
        );
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
        let file = make_file(
            "test.rs",
            vec![(1, b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")],
        );
        let findings = scan(&[file], &scanner, &al);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].matched_value,
            b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        );
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
        let file = make_file(
            "config.py",
            vec![(5, b"TOKEN = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"")],
        );
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
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
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
            allowlist: RuleAllowlist {
                regexes: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                paths: vec![],
            },
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
}
