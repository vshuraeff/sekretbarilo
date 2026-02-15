---
layout: default
title: Architecture
nav_order: 8
---

# Architecture & Internals

sekretbarilo is a high-performance secret scanner written in Rust. This page explains how it works internally, from the ground up.

## Project Structure

```
src/
  main.rs           - cli entry point, hand-rolled command parsing
  lib.rs            - library exports
  agent/mod.rs      - agent hook support (claude code integration)
  audit/
    mod.rs          - working tree scanning
    history.rs      - git history scanning with branch resolution
  config/
    mod.rs          - config loading and merging
    allowlist.rs    - allowlist compilation
    discovery.rs    - hierarchical config file discovery
    merge.rs        - config merge logic
    rules.toml      - 109 built-in detection rules
  diff/
    mod.rs          - git diff retrieval
    parser.rs       - unified diff parser
  doctor/mod.rs     - diagnostic health checks
  hook/mod.rs       - git pre-commit hook installation
  output/
    mod.rs          - finding reports
    masking.rs      - secret value masking
  scanner/
    engine.rs       - main scanning pipeline
    rules.rs        - rule compilation
    entropy.rs      - shannon entropy calculation
    hash_detect.rs  - hash detection (sha-1, sha-256, md5)
    password.rs     - password strength heuristics
    pubkey.rs       - public key block detection and tracking
```

## Scanning Pipeline (Core Engine)

The scanner processes files through a multi-stage pipeline optimized for speed and accuracy:

### 1. Git Diff Retrieval
```bash
git diff --cached --unified=0 --diff-filter=d
```
- retrieves only staged changes
- `--unified=0` minimizes context (we only scan added lines)
- `--diff-filter=d` excludes deleted files (no scanning needed)

### 2. Unified Diff Parsing
- splits diff into `DiffFile` structs with metadata:
  - `path`: file path
  - `is_new`, `is_deleted`, `is_renamed`, `is_binary`: file status flags
  - `added_lines`: vector of `AddedLine` structs with `line_number` and `content`
- handles multi-file diffs, multiple hunks per file, and edge cases:
  - binary files (via `Binary files ... differ` marker)
  - renames (extracts final path from `+++ b/` header)
  - root commits (with `--root` flag)

### 3. .env File Blocking
- immediate, unconditional block for `.env`, `.env.local`, `.env.production`
- excludes `.env.example`, `.env.template` (safe examples)
- prevents accidental exposure before scanning

### 4. Global Path Allowlist Check
pre-filters files to skip scanning:
- **binary extensions**: `.png`, `.jpg`, `.exe`, `.so`, `.woff2`, etc.
- **vendor directories**: `node_modules/`, `vendor/`, `.venv/`, etc.
- **generated files**: `package-lock.json`, `Cargo.lock`, minified `.min.js`
- **documentation**: `README.md`, `docs/`, `*.rst` (with entropy bonus)

### 5. Public Key Block Suppression
- tracks multi-line PEM/PGP public key blocks via `PubKeyBlockTracker`
- when `detect_public_keys` is disabled (default), lines inside public key blocks are skipped entirely
- prevents base64 content in public keys from triggering token rules (e.g., `EAA` → `facebook-access-token`)
- also detects single-line OpenSSH public keys (`ssh-rsa AAAA...`, etc.)
- gated rules (`pem-public-key`, `pgp-public-key-block`, `openssh-public-key`) are skipped unless enabled

### 6. Aho-Corasick Keyword Pre-filter
- single-pass scan across all rules' keywords simultaneously
- case-insensitive matching via aho-corasick automaton
- builds a bitset of "candidate rules" whose keywords matched
- drastically reduces regex evaluations (only ~2-5% of lines trigger regex)

**Example**: Line contains "akia" → activates `aws-access-key-id` rule

### 7. Regex Evaluation
- only evaluates regexes for rules whose keywords matched
- uses `regex::bytes` crate for binary-safe matching
- extracts full matches or capture groups via `secret_group` field
- handles multiple matches per line (iterates `captures_iter`)

**Example**: `(AKIA[A-Z0-9]{16})` matches `AKIAIOSFODNN7EXAMPLE`

### 8. Secret Extraction
- if `secret_group > 0`, extracts capture group value
- if `secret_group == 0`, uses full match
- skips empty matches

### 9. Per-Rule Allowlist Check
each rule can define:
- **value regexes**: patterns to match against extracted secret (e.g., `AKIAIOSFODNN7EXAMPLE`)
- **path patterns**: file path regexes to skip (e.g., `test/.*`)

### 10. Variable Reference Detection
skips values that are template variables, not real secrets:
- `$VAR`, `${VAR}`, `%VAR%` (shell variables)
- `process.env.VAR` (node.js)
- `os.environ['VAR']` (python)
- `ENV['VAR']` (ruby)

### 11. Stopword Filtering
rules with `entropy_threshold` (tier 2+) check for common safe words:
- built-in: `test`, `example`, `fake`, `placeholder`, `changeme`, `dummy`, `mock`
- user-configurable via `[allowlist] stopwords = [...]`
- **tier 1 rules** (no entropy threshold) only check placeholder patterns (`XXXX...`, `****...`) to allow tokens like `sk_test_` that inherently contain "test"

### 12. Hash Detection
prevents false positives on git commit hashes and checksums:
- **full-length hashes**: 32 (md5), 40 (sha-1), 64 (sha-256) hex chars
- **abbreviated hashes**: 7-12 hex chars
- requires context keywords on the same line: `commit`, `sha`, `hash`, `checksum`, `digest`, `integrity`
- uses word-boundary matching to avoid false matches (`hash` inside `HashMap`)

**Example**: `sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` → skipped

### 13. Password Strength Heuristics
for `generic-password-assignment` and `password-in-url` rules only:
- **weak passwords allowed**: `password`, `admin`, `123456`, `changeme`
- **strong passwords blocked**: complex passwords with high entropy + character classes
- scoring:
  - shannon entropy (0-5)
  - character class bonus (uppercase + lowercase + digits + special ≥ 3 → +1.0, all 4 → +2.0)
  - length bonus (≥12 chars → +0.5, ≥20 chars → +1.0)
  - dictionary penalty (-4.0)
  - threshold: 6.0

**Rationale**: `password=test` is a placeholder, `password=Kj8#mP2!xQ9vL4nR` is a real secret

### 14. Shannon Entropy Evaluation
for rules with `entropy_threshold` set:
- calculates shannon entropy over all 256 byte values
- min length: 20 characters (shorter strings skip entropy check)
- documentation file bonus: +1.0 to threshold (raises bar for false positives in docs)
- global override: `--entropy-threshold` or `[settings] entropy_threshold = 3.5` sets a floor

**Formula**: `H = -Σ(p_i * log2(p_i))` where `p_i` is frequency of byte `i`

**Example**: `aaaaaaaaaaaaaaaaaaaaaaaa` → entropy ≈ 0.0 (blocked), `aB3dEf7hIj1kLmN0pQrStUvWxYz` → entropy ≈ 4.2 (allowed)

### 15. Output with Masking
- secret values always masked: `AK**************FG` (first 2 + last 2 chars)
- short values (≤4 chars): fully masked with `xxxx`
- prefixes: `[ERROR]` (scan), `[AUDIT]` (audit), `[AGENT]` (check-file)

---

## Audit Pipeline

### Working Tree Mode (`sekretbarilo audit`)

1. **enumerate tracked files**: `git ls-files -z` (nul-delimited for safe filenames)
2. **optional: include ignored files**: `git ls-files -z --others --ignored --exclude-standard`
3. **apply exclude/include patterns**: filter via regex (from `[audit]` section)
4. **read files in parallel**: rayon thread pool, converts to synthetic `DiffFile` structs
5. **feed through scanner engine**: same pipeline as scan mode
6. **report findings**: grouped by file, with masked values

**Optimizations**:
- parallel file reads via rayon (4+ files)
- binary detection: checks first 8KB for null bytes
- error handling: read failures reported but don't stop scanning

### Git History Mode (`sekretbarilo audit --history`)

1. **list commits**: `git rev-list --all --format=%H%n%an%n%ae%n%aI%n%at`
   - optional filters: `--branch`, `--since`, `--until`
   - parses: hash, author, email, date, timestamp (unix)

2. **identify root commits**: `git rev-list --max-parents=0 --all`
   - required for correct scanning (root commits need `--root` flag)

3. **extract per-commit diffs**: `git diff-tree -p --no-commit-id -r --unified=0 --diff-filter=d -m <hash>`
   - `-m` splits merge commits into individual diffs per parent (catches secrets in conflict resolution)
   - `--root` for root commits

4. **parallel commit processing**: rayon parallelizes commit scanning
   - progress reporting every 50 commits
   - error count tracked atomically

5. **deduplication**: same secret + same file + same rule = keep earliest commit by timestamp
   - key: `(file, rule_id, matched_value)` → earliest `HistoryFinding`
   - sorts by timestamp, then commit hash, then file, then line

6. **branch resolution**: `git branch --contains <hash> --format=%(refname:short)`
   - only queries commits with findings (not all commits)
   - parallel resolution via rayon
   - best-effort: failures warned but don't stop reporting

7. **report findings**: grouped by commit, shows author email + branches
   - sanitizes output: strips control chars and bidi overrides (prevents terminal injection)

---

## Check-File Pipeline (Agent Hooks)

Triggered by claude code when reading a file via the `Read` tool.

### Input Modes
1. **stdin json** (`--stdin-json`): reads hook payload from stdin
   ```json
   {
     "tool_input": {"file_path": "/path/to/file.rs"},
     "cwd": "/project/root"
   }
   ```
2. **direct path**: `sekretbarilo check-file src/config.rs`

### Pipeline

1. **parse stdin json payload** (if `--stdin-json`):
   - reads up to 1 MB from stdin (prevents unbounded memory)
   - extracts `file_path` and optional `cwd`

2. **resolve file path**:
   - absolute paths: computes relative path from `cwd` for better vendor/pattern detection
   - relative paths: validates against path traversal (blocks `../../etc/passwd`)
   - returns `(relative_path, base_dir)`

3. **validate base directory**: checks `base_dir.is_dir()`

4. **.env blocking**: unconditional block for `.env` files (same policy as scan)

5. **fast-path rejection (default allowlist only)**:
   - uses hardcoded patterns (binary, vendor, lock files)
   - skips config loading for obvious skips (performance optimization)

6. **load hierarchical config**:
   - discovers configs from `base_dir` up to home directory
   - merges all found configs

7. **full fast-path rejection (with user config)**:
   - applies user-defined allowlist paths
   - applies audit exclude patterns

8. **read file**:
   - converts to synthetic `DiffFile` (all lines treated as "added")
   - binary detection: first 8KB null byte check
   - error handling: read errors block (fail closed)

9. **compile scanner**: builds `CompiledScanner` from merged rules

10. **scan**: runs through scanner engine (same pipeline as scan mode)

11. **report findings** (to stderr):
    ```
    [AGENT] secret(s) detected in /path/to/file.rs
      line: 42
      rule: aws-access-key-id
      match: AK**************FG
    ```

12. **exit code**:
    - `0` = clean (claude reads file)
    - `2` = secrets found or error (claude blocks read)

**Key Design**: fail closed. errors (read failure, config error) exit 2 to prevent exposing secrets.

---

## Configuration System

### Hierarchical Discovery

searches for `.sekretbarilo.toml` in order (lowest → highest priority):

1. `/etc/sekretbarilo/sekretbarilo.toml` (system-wide)
2. `~/.config/sekretbarilo/sekretbarilo.toml` (user)
3. `.sekretbarilo.toml` in each directory from repo root → home

**merge strategy**:
- **scalars**: highest priority wins (e.g., `entropy_threshold`)
- **lists**: concatenated + deduplicated (e.g., `stopwords`, `paths`)
- **rules**: same `id` overrides, new `id` appends

### TOML Format

```toml
[settings]
entropy_threshold = 3.5

[allowlist]
paths = ["test/.*", "vendor/.*"]
stopwords = ["my-project-safe-token"]

[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = ["test/.*"]

[audit]
include_ignored = true
exclude_patterns = ["^build/", "^dist/"]
include_patterns = ["\\.rs$"]

[[rules]]
id = "custom-token"
description = "Custom API token"
regex = "(CUSTOM_[A-Z]{10})"
secret_group = 1
keywords = ["custom_"]
entropy_threshold = 3.5
```

### Rule Compilation

1. **load default rules**: embedded `config/rules.toml` (109 rules)
2. **merge user rules**: overrides by `id`, appends new rules
3. **compile regexes**: `regex::bytes::RegexBuilder` with 1 MB size limit
4. **build aho-corasick automaton**: all keywords (case-insensitive, deduplicated)
5. **map keywords → rules**: `keyword_to_rules[pattern_idx] = [rule_idx, ...]`

**Result**: `CompiledScanner` struct with `automaton`, `keyword_to_rules`, `rules`

---

## Hook Installation

### Pre-Commit Hook

**local**: `.git/hooks/pre-commit`
```bash
sekretbarilo install pre-commit
```

**global**: `~/.config/git/hooks/pre-commit` + `git config --global core.hooksPath`
```bash
sekretbarilo install pre-commit --global
```

**generated script**:
```sh
#!/bin/sh
# sekretbarilo pre-commit hook
# resolve the sekretbarilo binary
SEKRETBARILO_BIN=""
if command -v sekretbarilo >/dev/null 2>&1; then
    SEKRETBARILO_BIN="sekretbarilo"
elif [ -x "$HOME/.cargo/bin/sekretbarilo" ]; then
    SEKRETBARILO_BIN="$HOME/.cargo/bin/sekretbarilo"
fi

if [ -n "$SEKRETBARILO_BIN" ]; then
    "$SEKRETBARILO_BIN" scan
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
        exit 1
    elif [ $exit_code -ne 0 ]; then
        echo "[ERROR] sekretbarilo exited with code $exit_code" >&2
        exit $exit_code
    fi
else
    echo "[WARN] sekretbarilo not found in PATH or ~/.cargo/bin/, skipping secret scan" >&2
    echo "[WARN] install with: cargo install sekretbarilo" >&2
fi
# end sekretbarilo
```

**features**:
- POSIX-compatible (no bashisms)
- idempotent: detects existing installation via marker comment
- appends to existing hooks (inserts before trailing `exit`)
- graceful degradation: warns if binary not found but doesn't fail
- sets executable permission (`chmod +x`)

### Agent Hook (Claude Code)

**local**: `.claude/settings.json`
```bash
sekretbarilo install agent-hook claude
```

**global**: `~/.claude/settings.json`
```bash
sekretbarilo install agent-hook claude --global
```

**settings.json structure**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-file --stdin-json",
            "timeout": 10,
            "statusMessage": "Scanning file for secrets..."
          }
        ]
      }
    ]
  }
}
```

**features**:
- reads/creates `.claude/settings.json` or `~/.claude/settings.json`
- idempotent: detects existing entries, updates old command formats
- preserves existing settings and other hook matchers
- appends to existing `Read` matcher if present
- atomic write: temp file + rename (prevents corruption)

---

## Output & Masking

### Masking Strategy

all secret values masked before display:

| Length | Display |
|--------|---------|
| 1-5 chars | `xxxxx` (fully masked) |
| 6+ chars | `AB**********YZ` (first 2 + last 2) |

**rationale**: prevents accidental exposure in logs/screenshots while allowing identification

### Output Prefixes

- `[ERROR]`: scan command findings (blocks commit)
- `[AUDIT]`: audit command findings (informational)
- `[AGENT]`: check-file command findings (blocks read)

### Terminal Safety

history mode sanitizes all displayed fields:
- strips control characters (`\x00-\x1f`, `\x7f`)
- strips bidi overrides (`\u{202A}-\u{202E}`)
- prevents terminal injection via malicious git author/email/branch/file names

---

## Design Decisions

### Fail Closed
errors exit 2 (block) rather than 0 (allow):
- config parse errors → block
- file read errors → block
- rule compilation errors → block

**rationale**: better to over-block than expose secrets

### No Network
everything runs locally:
- no telemetry
- no remote rule updates
- no API calls

**rationale**: privacy, security, offline support

### POSIX Hooks
generated hooks use only POSIX shell features:
- `[ ]` not `[[ ]]`
- `command -v` not `which`
- `"$VAR"` quoting everywhere

**rationale**: works on all shells (sh, bash, zsh, dash)

### Graceful Degradation
hooks warn but don't fail if binary not found:
```
[WARN] sekretbarilo not found in PATH or ~/.cargo/bin/, skipping secret scan
```

**rationale**: doesn't break workflows if binary is temporarily missing

### Stdin Limit
check-file limits stdin to 1 MB:
```rust
std::io::stdin().take(1_048_576).read_to_string(&mut input)
```

**rationale**: prevents unbounded memory consumption from malicious payloads

### Regex Size Limit
all regexes compiled with 1 MB limit:
```rust
RegexBuilder::new(&pattern).size_limit(1 << 20).build()
```

**rationale**: prevents ReDoS (regular expression denial of service)

### Parallel Processing
uses rayon for parallel file/commit processing:
- threshold: 4+ files/commits
- automatic work-stealing
- respects available CPU cores

**rationale**: 10-100x speedup on large repos

### Binary-Safe Scanning
uses `regex::bytes` and `Vec<u8>` everywhere:
- handles non-UTF-8 files
- no allocation for UTF-8 conversion

**rationale**: supports all file encodings

---

## Performance Characteristics

### Scan Mode (Staged Changes)
- **cold start**: ~50-100ms (config load + rule compilation)
- **incremental**: ~5-10ms per file
- **bottleneck**: regex evaluation (mitigated by aho-corasick pre-filter)

### Audit Mode (Working Tree)
- **small repos** (< 1000 files): ~1-2 seconds
- **large repos** (10,000+ files): ~10-30 seconds
- **bottleneck**: file I/O (mitigated by parallel reads)

### History Mode (All Commits)
- **small repos** (< 100 commits): ~5-10 seconds
- **large repos** (10,000+ commits): ~5-10 minutes
- **bottleneck**: `git diff-tree` execution (mitigated by parallel processing)

### Memory Usage
- **scan mode**: ~5-10 MB
- **audit mode**: ~50-100 MB (buffered file contents)
- **history mode**: ~100-500 MB (buffered diffs + findings)

### Optimization Techniques
1. **aho-corasick pre-filter**: reduces regex evaluations by 95%+
2. **rayon parallelism**: 10-100x speedup on multi-core
3. **binary-safe bytes**: no UTF-8 conversion overhead
4. **reusable bitsets**: avoids per-line allocations
5. **early termination**: skips binary/vendor/lock files immediately

---

## Testing Strategy

### Unit Tests
- scanner engine: keyword matching, regex extraction, entropy calculation
- diff parser: edge cases (binary, renames, root commits, multiple hunks)
- config merging: scalar override, list concatenation, rule merging
- allowlist compilation: path patterns, stopwords, per-rule allowlists

### Integration Tests
- default rules: all 109 rules compile and detect known secrets
- hook installation: idempotency, appending, preservation of existing hooks
- agent hook: JSON parsing, path resolution, fast-path rejection

### Property-Based Testing
- entropy calculation: monotonic increase with randomness
- masking: never exposes full secret value
- hash detection: SHA-1/SHA-256/MD5 lengths with context

---

## Security Considerations

### Threat Model
**in-scope**:
- accidental secret commits (developer error)
- copy-paste from documentation (example secrets)
- weak passwords in config files

**out-of-scope**:
- intentional malicious commits (insider threat)
- encrypted/obfuscated secrets
- secrets split across multiple lines

### Attack Surface
1. **malicious config files**: TOML parsing uses `serde_toml` (memory-safe)
2. **malicious git payloads**: binary-safe parsing, control char stripping
3. **ReDoS via user regexes**: 1 MB size limit enforced
4. **path traversal**: canonicalization + prefix check in check-file mode
5. **terminal injection**: sanitizes author/email/branch/file names before display

### Sandboxing
agent hook mode:
- reads only the target file (no directory traversal)
- no network access
- no temp file creation
- read-only access to config files

---

## Future Work

### Performance
- incremental scanning (cache results per file hash)
- rule priority ordering (check high-confidence rules first)
- streaming diff parsing (avoid buffering full diffs)

### Features
- custom entropy models per rule (hex-only, base64-only)
- machine learning-based false positive reduction
- integration with secret management systems (vault, 1password)

### Accuracy
- context-aware scanning (understand variable assignments)
- cross-file analysis (detect secrets split across imports)
- semantic analysis (distinguish API keys from UUIDs)
