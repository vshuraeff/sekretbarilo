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
  agent/
    mod.rs          - check-file command, path resolution, stdin json parsing
    claude.rs       - claude code hook installation (settings.json)
    codex.rs        - check-codex command, codex cli hook installation
    apply_patch.rs  - extraction of added lines from codex apply_patch payloads
    hooks_json.rs   - shared reader/writer for claude and codex hook json
  audit/
    mod.rs          - working tree scanning
    history.rs      - git history scanning with branch resolution
    search.rs       - user-search pass (--search / --search-regex)
  config/
    mod.rs          - config loading and merging
    allowlist.rs    - allowlist compilation
    discovery.rs    - hierarchical config file discovery
    merge.rs        - config merge logic
    rules.toml      - 112 built-in detection rules
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
- excludes `.env.example`, `.env.sample`, `.env.template` (safe examples)
- prevents accidental exposure before scanning
- reported as rule `env-file-blocked` with `line: -` and `match: (blocked file type)` — the file is never read

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
- drastically reduces regex evaluations: a line that matches no keyword never reaches a regex

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
- **key patterns**: assignment-key wildcard patterns to skip (e.g., `TMPDIR`, `GHOSTTY_*`); applies only to `generic-high-entropy-value` matches

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
  - short-value penalty (< 6 chars → -2.0)
  - score is clamped at 0.0; threshold: 6.0

**Rationale**: `password=test` is a placeholder, `password=Kj8#mP2!xQ9vL4nR` is a real secret

### 14. Shannon Entropy Evaluation
for rules with `entropy_threshold` set:
- calculates shannon entropy over all 256 byte values
- min length: 20 characters (shorter strings skip entropy check)
- documentation file bonus: +1.0 to threshold (raises bar for false positives in docs)
- global override: `--entropy-threshold` or `[settings] entropy_threshold = 3.5` sets a floor

**Formula**: `H = -Σ(p_i * log2(p_i))` where `p_i` is frequency of byte `i`

**Example**: `aaaaaaaaaaaaaaaaaaaaaaaa` → entropy ≈ 0.0 (blocked), `aB3dEf7hIj1kLmN0pQrStUvWxYz` → entropy ≈ 4.2 (allowed)

**Baseline**: the measured entropy of short random passwords, and why the 20-character and 4.0 gates are left unchanged, are recorded in [ADR 0001](../adr/0001-entropy-baseline-8-char-password.md).

### 15. Output with Masking
- diagnostic secret values masked: `AK**************FG` (first 2 + last 2 chars)
- short values (≤5 chars): fully masked with one `x` per character (`abc` → `xxx`)
- prefixes: `[ERROR]` (scan), `[AUDIT]` (audit), `[AGENT]` (check-file / check-codex), `[SEARCH]` (user-search pass)

`redact-claude` uses full `[REDACTED]` replacement instead of diagnostic prefix/suffix masking.

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
   - commit hashes are abbreviated in the report

### User-Search Pass (`--search` / `--search-regex`)

an additive pass that runs alongside the rule-based audit, never instead of it:

1. **compile patterns**: `--search` literals and `--search-regex` patterns (both repeatable)
2. **reuse the same file set**: whatever the audit pass enumerated, after exclude/include filtering
3. **report separately**: matches are printed under `[SEARCH]` with a trailing count line
4. **unmasked**: search hits show the matched text verbatim — the user asked for this exact string

audit-only by design: the flags are rejected on `scan`. a search match alone is enough to make the
command exit 1, even when the rule-based pass found nothing.

---

## Check-File Pipeline (Claude Code Agent Hook)

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

6. **load hierarchical config (trusted loader)**:
   - discovers configs from `base_dir` up to home directory
   - merges all found configs
   - a `.sekretbarilo.toml` **inside the git working tree** is honoured only when it is git-tracked
     and unmodified against `HEAD`; otherwise the whole layer is dropped with
     `[WARN] ignoring untrusted in-workspace config: <path>`
   - this trust check applies to the agent-hook paths only (`check-file`, `check-codex`, `redact-claude`) — `scan`
     and `audit` load in-workspace configs unconditionally. see
     [Configuration]({{ '/configuration/' | relative_url }}) for the full rules

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

      file: file.rs
      line: 42
      rule: aws-access-key-id
      match: AK**************FG

    file contains 1 secret(s). reading blocked to prevent secret exposure.
    ```

12. **exit code**:
    - `0` = clean (claude reads file)
    - `2` = secrets found or error (claude blocks read)

**Key Design**: fail closed. errors (read failure, config error) exit 2 to prevent exposing secrets.

---

## Redact-Claude Pipeline (Claude Code PostToolUse)

`sekretbarilo redact-claude --stdin-json` receives the successful tool result, after execution. It is an in-memory output editor: it does not read or modify the source file to redact it.

1. **bounded input**: read at most 10 MiB and parse the PostToolUse payload.
2. **select text fields**: Bash stdout/stderr and text blocks, text-file Read content, and Grep content/result lines and filename arrays. Preserve the complete response structure, counters, and unknown metadata.
3. **trusted configuration**: load the existing trusted layers; use rules, entropy, password heuristics, and value exceptions without path exclusions or documentation relaxations.
4. **exact ranges**: the shared scanner exposes captured byte ranges through `scan_text`, while the existing `scan` / `Finding` interface remains intact. Extend key-block ranges, merge overlaps, and apply the pure `redact_text` function, preserving UTF-8 and CR/LF.
5. **bounded replacement**: return exit 0 with `hookSpecificOutput.updatedToolOutput`, or no stdout when clean. Limit the complete serialized response to 10 MiB.
6. **errors**: return `continue: false` and a fixed safe reason, plus a replacement hiding every supported text field when its structure is available and the fallback fits. Use fallible stdout/stderr writes; failed stdout delivery exits 1 with a safe stderr diagnostic if possible. A PostToolUse exit 2 cannot remove existing output.

For supported formats, installation/version requirements, and failure/telemetry limitations, see [Agent Hooks]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}).

---

## Check-Codex Pipeline (Codex CLI Agent Hook)

Triggered by the Codex CLI *before* it runs a tool, not after. `check-codex` inspects what the agent
is about to write, so a secret is caught before it reaches the working tree.

The hook is registered with matcher `^(apply_patch|Bash)$` and runs
`sekretbarilo check-codex --stdin-json`. The command is internal: it only reads a hook payload from
stdin, and refuses to run without `--stdin-json`.

### Payload

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "apply_patch",
  "tool_input": {"command": "*** Begin Patch\n..."},
  "cwd": "/project/root"
}
```

a payload that does not match this schema is rejected with
`Codex hook payload schema mismatch: <detail>` and exit 2 — fail closed, same as `check-file`.

### Pipeline

1. **parse payload**: 10 MiB stdin limit
2. **extract scannable text**, by tool:
   - `apply_patch`: parses the patch envelope and takes only the added lines, keeping the target
     path so findings are attributed to the file the agent is creating or editing
   - `Bash`: scans the command string itself, attributed to the synthetic path `<bash-command>`
3. **load config** through the same trusted loader as `check-file` (see step 6 above)
4. **scan** through the shared scanner engine
5. **report findings** (to stderr):
   ```
   [AGENT] Codex apply_patch blocked: secret(s) detected
     file: src/creds.py
     line: 1
     rule: github-personal-access-token
     match: gh**************************************AB
   apply_patch action blocked to prevent secret exposure. total findings: 1.
   ```
6. **exit code**:
   - `0` = clean (codex runs the tool)
   - `2` = secrets found or error (codex blocks the tool call)

**Codex-specific caveat**: Codex silently skips hooks it has not been asked to trust. Installing the
hook is not enough — it must also be approved with `/hooks` in the Codex TUI, and `doctor` reports
the approval entry separately from the installation itself.

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

**trust**: on the agent-hook paths (`check-file`, `check-codex`, `redact-claude`) an in-workspace config layer is
dropped unless it is git-tracked and clean against `HEAD` — an agent that writes its own
`.sekretbarilo.toml` cannot allowlist its way past the scanner. `scan` and `audit` are unaffected.
[Configuration]({{ '/configuration/' | relative_url }}) documents the exact conditions.

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

# key patterns apply only to generic-high-entropy-value assignment matches
[[allowlist.rules]]
id = "generic-high-entropy-value"
keys = ["TMPDIR", "GHOSTTY_*"]

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

1. **load default rules**: embedded `config/rules.toml` (112 rules)
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

`--mode block|redact` selects the Claude mode. Omitting it preserves the selected file's installed mode, defaulting to `block` for a new installation. Redaction requires Claude Code >= 2.1.121 before any change to Claude settings; it installs synchronous `PostToolUse` / `^(Bash|Read|Grep)$` with a 10-second timeout.

The installer records the absolute path reported by the OS for the running executable and quotes shell-sensitive paths; it warns and uses the bare `sekretbarilo` name only when the path lookup fails or is not valid UTF-8. On macOS, an invocation through a symlink such as Homebrew's `/usr/local/bin/sekretbarilo` keeps that path. On Linux, `current_exe` reports the resolved target, so Homebrew-on-Linux records a Cellar path; when `brew upgrade` removes that target, the hook remains broken until installation is rerun from the new binary, and doctor reports the old path as missing. Doctor checks an absolute configured path's filesystem metadata, executable bit, and canonical identity relative to the running binary. It never executes a binary selected by Claude settings and does not report a version for it; a bare name receives a warning because Claude Code resolves it under its own `PATH`.

**settings.json structure (`block`)**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "<absolute-path-to-running-sekretbarilo> check-file --stdin-json",
            "statusMessage": "Scanning file for secrets...",
            "timeout": 10,
            "type": "command"
          }
        ],
        "matcher": "Read"
      }
    ]
  }
}
```

**features**:
- reads/creates `.claude/settings.json` or `~/.claude/settings.json`
- idempotent: detects entries across events, updates the selected or preserved mode, removes duplicate sekretbarilo handlers
- preserves existing settings and other hook matchers
- preserves other handler/group order; reports local/global blocking-Read conflicts with redaction
- atomic write: temp file + rename (prevents corruption)

### Agent Hook (Codex CLI)

**local**: `.codex/hooks.json`
```bash
sekretbarilo install agent-hook codex
```

**global**: `$CODEX_HOME/hooks.json`, defaulting to `~/.codex/hooks.json`
```bash
sekretbarilo install agent-hook codex --global
```

**hooks.json structure**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "sekretbarilo check-codex --stdin-json",
            "statusMessage": "Scanning tool input for secrets...",
            "timeout": 10,
            "type": "command"
          }
        ],
        "matcher": "^(apply_patch|Bash)$"
      }
    ]
  }
}
```

**features**:
- shares its json reader/writer with the claude installer (`agent/hooks_json.rs`), so idempotency,
  preservation of unrelated entries and atomic writes behave identically
- reports the detected Codex version when `codex` is on `PATH`
- warns, on every install, that Codex ignores unapproved hooks until you run `/hooks` in its TUI

### Install All

```bash
sekretbarilo install all           # pre-commit + claude + codex, locally
sekretbarilo install all --global  # the same three, globally
```

runs the three installers in sequence and prints each one's result. accepts `--mode block|redact` for Claude with the same preservation/default/version policy as the standalone installer.

---

## Doctor

`sekretbarilo doctor` runs five groups of checks and prints each result with a status label:

| Group | Checks |
|-------|--------|
| `git pre-commit hook` | local and global hook present, carries the sekretbarilo marker |
| `claude code agent hook` | local and global `settings.json` entries, command metadata, and canonical identity relative to the running binary; the configured binary is never executed |
| `codex cli agent hook` | local and global `hooks.json` entries, the matching approval entry in Codex's `config.toml`, and whether `codex` is on `PATH` |
| `configuration` | which config files were discovered, whether an in-workspace layer is untrusted, rule count, rule compilation |
| `sekretbarilo binary` | binary reachable on `PATH` |

status labels are `[OK]`, `[WARN]`, `[ERROR]` and `[NOT INSTALLED]`. only `[WARN]` and `[ERROR]`
count as issues: doctor exits 1 if any check is an issue, 0 otherwise. a missing hook is
`[NOT INSTALLED]`, which is informational and does not by itself fail the command.

the codex approval check is deliberately weaker than the others. it looks for a positional entry
under `[hooks.state]` in Codex's `config.toml` and does not validate Codex's own trust hash, so an
`[OK]` there means "an approval entry exists", not "the hook will definitely run". it can never
produce a false `[OK]` for a *missing* approval, only an over-optimistic one for a stale hash.

---

## Output & Masking

### Masking Strategy

diagnostic secret values masked before display:

| Length | Display |
|--------|---------|
| 1-5 chars | `xxx` — one `x` per character, length preserved, value fully hidden |
| 6+ chars | `AB**********YZ` (first 2 + last 2) |

**rationale**: prevents accidental exposure in logs/screenshots while allowing identification

### Output Prefixes

- `[ERROR]`: scan command findings (blocks commit), and fatal errors on any command
- `[AUDIT]`: audit command findings and progress (informational)
- `[AGENT]`: check-file findings (blocks read) and check-codex findings (blocks the tool call)
- `[SEARCH]`: user-search pass results — **not** masked
- `[OK]` / `[WARN]` / `[NOT INSTALLED]` / `[INFO]`: install and doctor status lines

diagnostics go to stderr. `redact-claude` writes replacement/stop JSON to stdout, using full `[REDACTED]` values and preserving the response structure.

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

### Trusted Config on Agent Paths
`check-file`, `check-codex`, and `redact-claude` drop an in-workspace `.sekretbarilo.toml` unless git says it is
tracked and unmodified:
```
[WARN] ignoring untrusted in-workspace config: /project/root/.sekretbarilo.toml
```

**rationale**: the agent being scanned can write files in the workspace. if an untracked config
counted, an agent could allowlist itself past the hook it is supposed to be constrained by.
`scan` and `audit` are run by a human and keep the unconditional behaviour.

### Stdin Limit
`check-file` limits stdin to 1 MB:
```rust
std::io::stdin().take(1_048_576).read_to_string(&mut input)
```

`check-codex` and `redact-claude` cap input at 10 MiB. Redaction also caps its serialized hook response at 10 MiB.

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

per-invocation wall clock, measured on macOS 15.7 / Intel Core i9-9900K @ 3.60GHz, 50 invocations
of `sekretbarilo scan` against a one-file staged diff:

| Component | Cost |
|-----------|------|
| process spawn (`--version` as a floor) | ~13 ms |
| `git diff --cached` subprocess | ~10 ms |
| rule compilation (112 rules, delta vs `--no-defaults`) | ~11 ms |
| **whole `sekretbarilo scan` invocation** | **~53 ms** |

the in-process scan itself is microseconds ([Performance]({{ '/performance/' | relative_url }}));
essentially all of the wall clock is fixed startup cost, so it does not grow with commit size until
the diff is very large. these figures are hardware- and OS-dependent — treat them as a shape, not a
guarantee.

**bottleneck**: fixed startup, not scanning. regex evaluation is the scanning-side cost, mitigated
by the aho-corasick pre-filter.

### Audit and History Modes

no published figures. both are dominated by I/O and by `git` subprocesses rather than by the
scanner, so they track repository size, filesystem speed and core count more than anything
sekretbarilo controls. measure on your own repository:

```sh
time sekretbarilo audit
time sekretbarilo audit --history
```

**audit bottleneck**: file I/O, mitigated by parallel reads.
**history bottleneck**: `git diff-tree` execution, mitigated by parallel commit processing and by
resolving branches only for commits that produced findings.

### Optimization Techniques
1. **aho-corasick pre-filter**: most lines match no keyword at all and never reach a regex
2. **rayon parallelism**: audit and history work scales with available cores
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
one file per area under `tests/`:
- default rules: all 112 rules compile and detect known secrets
- false positives: a corpus that must stay clean
- hook installation: idempotency, appending, preservation of existing hooks
- claude agent hook: JSON parsing, path resolution, fast-path rejection
- codex agent hook: payload schema, `apply_patch` and `Bash` extraction, config trust
- doctor: each check group, and the exit code it produces
- audit, history and the user-search pass
- public key suppression, config merge precedence, CLI flag overrides
- hook panic safety: a panic must not turn into a silent allow

git-dependent tests build temp repos with `tempfile` and are serialized with `serial_test`, since
they mutate global git state.

---

## Security Considerations

### Threat Model
**in-scope**:
- accidental secret commits (developer error)
- copy-paste from documentation (example secrets)
- weak passwords in config files

- an AI agent writing a secret into the working tree, before the write lands (`check-codex`)
- an AI agent reading a file that already contains one (`check-file`)
- detected secrets in successful Claude Bash/Read/Grep text results (`redact-claude`)

**out-of-scope**:
- intentional malicious commits (insider threat)
- encrypted/obfuscated secrets
- secrets obfuscated or split so that no detector matches them; redaction handles matched multiline captures and PEM/PGP blocks

### Attack Surface
1. **malicious config files**: TOML parsing uses `serde_toml` (memory-safe)
2. **malicious git payloads**: binary-safe parsing, control char stripping
3. **ReDoS via user regexes**: 1 MB size limit enforced
4. **path traversal**: canonicalization + prefix check in check-file mode
5. **terminal injection**: sanitizes author/email/branch/file names before display
6. **agent-authored config**: an in-workspace config layer is ignored on the agent-hook paths
   unless git-tracked and clean
7. **hostile hook payloads**: bounded stdin and strict schemas; blocking hooks exit 2 on parse failure, while redaction returns stop JSON and a fully masked fallback when possible

### Sandboxing
agent hook mode:
- `check-file` reads only the target file (no directory traversal); `check-codex` reads no file at
  all, only the payload the agent is about to act on
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
