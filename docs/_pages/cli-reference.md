---
layout: default
title: CLI Reference
nav_order: 4
---

# CLI Reference

comprehensive reference for all sekretbarilo commands, flags, and options.

## Commands

### `sekretbarilo scan`

scans staged git changes for secrets. this is the command executed by the pre-commit hook automatically.

**behavior:**
- runs `git diff --cached --unified=0 --diff-filter=d` to get staged changes
- scans only the added lines in the diff
- blocks .env files unconditionally (even if no secrets detected)
- uses fast-path detection for binary files, vendor directories, and lock files
- returns exit code 1 if secrets are found, 0 if clean, 2 on internal error

**flags:** all common flags plus scan-specific flags

**examples:**
```sh
# basic scan of staged changes
sekretbarilo scan

# scan with custom config file
sekretbarilo scan --config my-rules.toml

# scan with multiple config files (merged)
sekretbarilo scan --config base.toml --config overrides.toml

# scan without built-in default rules
sekretbarilo scan --no-defaults --config custom.toml

# scan with runtime allowlist additions
sekretbarilo scan --allowlist-path 'vendor/.*' --stopword mytoken

# scan with custom entropy threshold
sekretbarilo scan --entropy-threshold 4.5
```

---

### `sekretbarilo audit`

scans tracked files in the working tree or git history for secrets. supports two modes:

**working tree mode (default):**
- scans all tracked files via `git ls-files`
- optionally includes ignored files with `--include-ignored`
- applies exclude/include pattern filters

**history mode (`--history`):**
- scans every commit in git history without checking out branches
- supports filtering by branch, date range, and patterns
- more resource-intensive than working tree mode

**flags:** all common flags plus audit-specific flags

**examples:**
```sh
# scan all tracked files in working tree
sekretbarilo audit

# scan with pattern filters
sekretbarilo audit --exclude-pattern '^vendor/' --include-pattern '\.rs$'

# scan including ignored files
sekretbarilo audit --include-ignored

# scan entire git history
sekretbarilo audit --history

# scan history for specific branch
sekretbarilo audit --history --branch main

# scan history with date range
sekretbarilo audit --history --since 2024-01-01 --until 2024-12-31

# scan history for branch with date filters
sekretbarilo audit --history --branch develop --since 2024-06-01

# combine config override with history scan
sekretbarilo audit --history --config custom.toml --no-defaults
```

---

### `sekretbarilo install`

installs hooks for automatic secret scanning. supports three targets:

#### `sekretbarilo install pre-commit`

installs git pre-commit hook that runs `sekretbarilo scan` before each commit.

**local mode (default):**
- installs to `.git/hooks/pre-commit` in current repository
- uses `git rev-parse --git-path hooks` to find correct hooks directory
- creates hook with executable permissions
- preserves existing pre-commit hooks if they don't contain sekretbarilo

**global mode (`--global`):**
- installs to global git hooks directory (configured via `core.hooksPath`)
- default location: `~/.config/git/hooks/` on unix systems
- applies to all repositories on the system
- requires `git config --global core.hooksPath` to be set or uses default

**examples:**
```sh
# install local pre-commit hook
sekretbarilo install pre-commit

# install global pre-commit hook
sekretbarilo install pre-commit --global
```

#### `sekretbarilo install agent-hook claude`

installs claude code agent hook that intercepts file reads and scans them before claude accesses the content.

**local mode (default):**
- installs to `.claude/settings.json` in project root
- uses git repository root if available, falls back to current directory
- creates or updates `hooks.PreToolUse` array with Read matcher
- preserves existing claude code settings and other hooks

**global mode (`--global`):**
- installs to `~/.claude/settings.json` in home directory
- applies to all projects using claude code
- useful for system-wide secret protection

**hook behavior:**
- intercepts `Read` tool calls before execution
- runs `sekretbarilo check-file --stdin-json` with file path payload
- blocks file reading if secrets detected (exit code 2)
- allows reading if clean (exit code 0)
- fast-path rejection for vendor files, binaries, and lock files

**examples:**
```sh
# install local claude code hook
sekretbarilo install agent-hook claude

# install global claude code hook
sekretbarilo install agent-hook claude --global
```

#### `sekretbarilo install all`

installs all available hooks (pre-commit + claude code agent hook).

**examples:**
```sh
# install all hooks locally
sekretbarilo install all

# install all hooks globally
sekretbarilo install all --global
```

---

### `sekretbarilo check-file`

scans a single file for secrets. used by agent hooks (claude code) but can also be invoked manually.

**behavior:**
- reads and scans a single file path
- applies same scanning rules as `scan` and `audit` commands
- fast-path rejection for .env files, vendor directories, binaries, lock files
- supports both positional file argument and stdin JSON payload mode

**flags:** check-file-specific flags only

**exit codes:**
- 0 = clean (no secrets found)
- 2 = secrets found or error (used by hooks to block file access)

**examples:**
```sh
# scan a single file
sekretbarilo check-file src/config.rs

# scan file from stdin JSON payload (agent hook mode)
echo '{"tool_input":{"file_path":"/path/to/file.rs"},"cwd":"/project"}' | sekretbarilo check-file --stdin-json
```

---

### `sekretbarilo doctor`

runs diagnostic health checks for hook installations, configuration, and binary availability.

**checks performed:**
- git pre-commit hook status (local and global)
- claude code agent hook status (local and global)
- configuration discovery and validation
- rules compilation
- binary availability in PATH

**exit codes:**
- 0 = all checks passed
- 1 = issues found (warnings or errors)

**examples:**
```sh
# run all diagnostic checks
sekretbarilo doctor
```

**sample output:**
```
git pre-commit hook:
  [OK] local pre-commit hook installed
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [OK] local claude code hook installed (/project/.claude/settings.json)
  [NOT INSTALLED] global claude code hook not found

configuration:
  [OK] config file: /project/.sekretbarilo.toml
  [OK] 42 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

---

### `sekretbarilo --version`

displays the installed version.

**examples:**
```sh
sekretbarilo --version
sekretbarilo -V
```

---

### `sekretbarilo --help`

displays usage information and examples.

**examples:**
```sh
# show general help
sekretbarilo --help
sekretbarilo -h

# show install-specific help
sekretbarilo install --help
sekretbarilo install -h
```

---

## Common Flags

these flags apply to both `scan` and `audit` commands:

| Flag | Type | Description |
|------|------|-------------|
| `--config <path>` | repeatable | use explicit config file (skips auto-discovery). can be specified multiple times to merge configs. |
| `--no-defaults` | boolean | skip embedded default rules. only uses rules from explicit `--config` files. warning: will find nothing if no custom rules provided. |
| `--entropy-threshold <n>` | float | override entropy threshold for high-entropy detection. default varies by rule. typical range: 3.0-5.0. |
| `--allowlist-path <pattern>` | repeatable | add path pattern to allowlist (regex). can be specified multiple times. appended to config-defined patterns. |
| `--stopword <word>` | repeatable | add stopword to filter out false positives. can be specified multiple times. appended to config-defined stopwords. |

---

## Audit-Specific Flags

these flags only apply to the `audit` command:

| Flag | Type | Description | Requires |
|------|------|-------------|----------|
| `--history` | boolean | scan full git history (all commits) instead of working tree. |  |
| `--branch <name>` | string | limit history scan to commits reachable from specified branch. | `--history` |
| `--since <date>` | string | only scan commits after this date. accepts git date formats (YYYY-MM-DD, relative dates). | `--history` |
| `--until <date>` | string | only scan commits before this date. accepts git date formats. | `--history` |
| `--include-ignored` | boolean | include untracked ignored files in working tree scan (respects .gitignore). |  |
| `--exclude-pattern <pattern>` | repeatable | exclude files matching regex pattern. can be specified multiple times. |  |
| `--include-pattern <pattern>` | repeatable | force-include files matching regex pattern (overrides exclusions). can be specified multiple times. |  |

---

## Check-File Flags

these flags only apply to the `check-file` command:

| Flag | Type | Description |
|------|------|-------------|
| `--stdin-json` | boolean | read file path from JSON payload on stdin (agent hook mode). mutually exclusive with positional file path argument. |

---

## Install Flags

these flags only apply to `install` subcommands:

| Flag | Type | Description |
|------|------|-------------|
| `--global` | boolean | install globally instead of locally. for pre-commit: uses `git config --global core.hooksPath`. for agent-hook: modifies `~/.claude/settings.json`. |

---

## Exit Codes

sekretbarilo uses different exit codes to indicate scan results and errors:

### `scan` and `audit`

| Exit Code | Meaning |
|-----------|---------|
| 0 | clean - no secrets found |
| 1 | secrets found |
| 2 | internal error (config error, git error, scan error) |

### `check-file`

| Exit Code | Meaning |
|-----------|---------|
| 0 | clean - no secrets found |
| 2 | secrets found or error (blocks file reading in hook context) |

note: `check-file` uses exit code 2 for both secrets and errors to ensure fail-closed behavior in agent hooks. this prevents claude from reading files when scanning fails.

### `doctor`

| Exit Code | Meaning |
|-----------|---------|
| 0 | all checks passed |
| 1 | issues found (warnings or errors) |

### `install`

| Exit Code | Meaning |
|-----------|---------|
| 0 | installation successful |
| 2 | installation failed |

---

## Usage Examples

### basic workflow

```sh
# install pre-commit hook
sekretbarilo install pre-commit

# stage some changes
git add .

# scan runs automatically on commit
git commit -m "add feature"

# manually scan staged changes
sekretbarilo scan
```

### custom configuration

```sh
# scan with project-specific rules
sekretbarilo scan --config .sekretbarilo.toml

# scan without defaults (only custom rules)
sekretbarilo scan --no-defaults --config custom-rules.toml

# merge multiple configs
sekretbarilo scan --config base.toml --config team-rules.toml --config local-overrides.toml
```

### audit working tree

```sh
# scan all tracked files
sekretbarilo audit

# scan with vendor exclusion
sekretbarilo audit --exclude-pattern '^vendor/' --exclude-pattern '^node_modules/'

# scan only source files
sekretbarilo audit --include-pattern '\.rs$' --include-pattern '\.go$'

# scan including gitignored files
sekretbarilo audit --include-ignored
```

### audit git history

```sh
# scan entire history
sekretbarilo audit --history

# scan main branch only
sekretbarilo audit --history --branch main

# scan last 30 days
sekretbarilo audit --history --since '30 days ago'

# scan specific date range
sekretbarilo audit --history --since 2024-01-01 --until 2024-12-31

# scan feature branch since divergence from main
sekretbarilo audit --history --branch feature/new-api --since 2024-06-01
```

### runtime allowlist and stopwords

```sh
# add temporary allowlist patterns
sekretbarilo scan --allowlist-path 'test/fixtures/.*' --allowlist-path 'examples/.*'

# add temporary stopwords
sekretbarilo scan --stopword exampletoken --stopword testkey123

# combine with config
sekretbarilo scan --config base.toml --stopword local_dev_key
```

### entropy threshold tuning

```sh
# lower threshold (more sensitive, more false positives)
sekretbarilo scan --entropy-threshold 3.0

# higher threshold (less sensitive, fewer false positives)
sekretbarilo scan --entropy-threshold 5.0

# audit with adjusted threshold
sekretbarilo audit --entropy-threshold 4.2
```

### agent hooks

```sh
# install claude code hook locally
sekretbarilo install agent-hook claude

# install globally for all projects
sekretbarilo install agent-hook claude --global

# manually check a file (simulates hook behavior)
sekretbarilo check-file src/config.rs

# test hook with JSON payload
echo '{"tool_input":{"file_path":"'$(pwd)'/src/main.rs"}}' | sekretbarilo check-file --stdin-json
```

### diagnostics

```sh
# run health checks
sekretbarilo doctor

# verify hook installations
sekretbarilo doctor | grep hook

# check configuration validity
sekretbarilo doctor | grep config
```

### combining flags

```sh
# scan with all custom settings
sekretbarilo scan \
  --config custom.toml \
  --no-defaults \
  --entropy-threshold 4.0 \
  --allowlist-path 'vendor/.*' \
  --stopword safe_test_key

# comprehensive history audit
sekretbarilo audit \
  --history \
  --branch develop \
  --since 2024-01-01 \
  --exclude-pattern '^vendor/' \
  --exclude-pattern '\.min\.js$' \
  --include-pattern '\.env\.example$'

# audit with config overrides
sekretbarilo audit \
  --config .sekretbarilo.toml \
  --entropy-threshold 3.8 \
  --include-ignored \
  --exclude-pattern '^build/'
```

---

## Flag Validation Rules

sekretbarilo validates flag combinations to prevent misuse:

| Flag | Valid With | Invalid With |
|------|------------|--------------|
| `--config` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--no-defaults` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--entropy-threshold` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--allowlist-path` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--stopword` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--history` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--branch` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--since` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--until` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--exclude-pattern` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--include-pattern` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--include-ignored` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--stdin-json` | `check-file` | `scan`, `audit`, `install`, `doctor` |
| `--global` | `install` subcommands | `scan`, `audit`, `check-file`, `doctor` |

attempting to use invalid flag combinations will result in an error message and exit code 2.

---

## Pattern Syntax

patterns used in `--allowlist-path`, `--exclude-pattern`, and `--include-pattern` use rust regex syntax:

| Pattern | Matches |
|---------|---------|
| `^vendor/` | files starting with "vendor/" |
| `\.min\.js$` | files ending with ".min.js" |
| `test/.*` | all files under "test/" directory |
| `\.(png\|jpg\|gif)$` | files with image extensions |
| `node_modules\|vendor` | files containing "node_modules" or "vendor" |

patterns are matched against the full file path relative to repository root.

---

## Date Formats

date arguments for `--since` and `--until` support git date formats:

| Format | Example |
|--------|---------|
| absolute | `2024-01-01`, `2024-12-31` |
| relative | `30 days ago`, `1 week ago`, `yesterday` |
| iso 8601 | `2024-01-01T00:00:00Z` |

see `git help log` for full list of supported date formats.

---

## Configuration Hierarchy

when no `--config` flag is specified, sekretbarilo auto-discovers and merges configs in this order:

1. embedded default rules (skipped if `--no-defaults`)
2. `~/.sekretbarilo.toml` (global user config)
3. `~/.config/sekretbarilo/config.toml` (xdg config)
4. `.sekretbarilo.toml` (repository root)
5. `.sekretbarilo.toml` (current directory)

cli flags override config file values. repeatable flags (allowlist-path, stopword) are appended, not replaced.

when `--config` is specified, auto-discovery is skipped and only the specified files are loaded.
