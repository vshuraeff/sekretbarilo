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

installs hooks for automatic secret scanning. supports four targets:

#### `sekretbarilo install pre-commit`

installs git pre-commit hook that runs `sekretbarilo scan` before each commit.

**local mode (default):**
- uses `git rev-parse --git-path hooks` to find the hooks directory, normally `.git/hooks/`
- creates hook with executable permissions
- preserves existing pre-commit hooks if they don't contain sekretbarilo

**global mode (`--global`):**
- installs to the directory named by `git config --global core.hooksPath`, defaulting to `~/.config/git/hooks/`
- sets `core.hooksPath` globally when it is not already configured
- applies to all repositories on the system

**note on precedence:** `core.hooksPath` does not layer with `.git/hooks/` — it *replaces* it. Once a global hook is installed, git runs only the hook in `core.hooksPath`, in every repository, and a per-repository `.git/hooks/pre-commit` is never executed. `git rev-parse --git-path hooks` reports the same directory, so a subsequent local `install pre-commit` writes to the global file too. Unset `core.hooksPath` to go back to per-repository hooks.

**examples:**
```sh
# install local pre-commit hook
sekretbarilo install pre-commit

# install global pre-commit hook
sekretbarilo install pre-commit --global
```

#### `sekretbarilo install agent-hook claude`

installs the claude code hook in `block` or `redact` mode. `--mode block|redact` selects the mode; omitted, it preserves the mode already installed in the selected settings file or chooses `block` for a new installation.

**local mode (default):**
- installs to `.claude/settings.json` in project root
- uses git repository root if available, falls back to current directory
- configures `PreToolUse` / `Read` for `block`, or synchronous `PostToolUse` / `^(Bash|Read|Grep)$` for `redact`, with a 10-second timeout
- preserves existing claude code settings and other hooks

**global mode (`--global`):**
- installs to `~/.claude/settings.json` in home directory, or `$CLAUDE_CONFIG_DIR/settings.json` when that variable is set and non-empty
- applies to all projects using claude code
- useful for system-wide secret protection

**explicit file (`--settings <path>`):**
- installs into exactly that file instead of the local or global default; mutually exclusive with `--global`
- a relative path resolves against the current directory of the invocation, not the repository root; works outside a git repository
- the file is created if absent; existing content and other hooks are preserved exactly as with the default locations, and `--mode` still selects or preserves the claude mode
- installing into an arbitrary file does not register a new claude code profile: claude picks it up only when the file is one of its standard settings files, when claude itself is launched with its own `--settings <path>` flag (see the [claude code cli reference](https://code.claude.com/docs/en/cli-reference)), or when the file is the `settings.json` of the profile directory named by `CLAUDE_CONFIG_DIR` (see the [claude directory docs](https://code.claude.com/docs/en/claude-directory))

**block behavior:**
- intercepts `Read` tool calls before execution
- runs the OS-reported absolute path of the binary that installed it with `check-file --stdin-json` and the file path payload when that path is available
- blocks file reading if secrets detected (exit code 2)
- allows reading if clean (exit code 0)
- fast-path rejection for vendor files, binaries, and lock files

**redact behavior:**

- runs the OS-reported absolute path of the binary that installed it with `redact-claude --stdin-json` after a successful `Bash`, `Read`, or `Grep` tool call when that path is available
- replaces detected secret values in supported text with `[REDACTED]`, preserving response structure and source files
- uses value exceptions and trusted rules; path exclusions and documentation relaxations do not apply
- requires a known claude code version >= 2.1.121 before changing settings

switches only sekretbarilo handlers in the selected file, atomically and without duplicates. other handlers and their order are preserved. The installer writes the absolute path reported by the OS for the running executable and quotes shell-sensitive paths. On macOS, a symlinked invocation such as Homebrew's `/usr/local/bin/sekretbarilo` is retained. On Linux, `current_exe` reports the resolved target, so Homebrew-on-Linux records a Cellar path; after `brew upgrade` removes that target, rerun `sekretbarilo install agent-hook claude` from the new binary. Doctor reports the old path as missing. If the path lookup fails or is not valid UTF-8, the installer warns and writes a bare `sekretbarilo` command. Installation and `doctor` warn if a blocking Read hook in another settings scope conflicts with redaction.

**examples:**
```sh
# install local claude code hook
sekretbarilo install agent-hook claude

# install global claude code hook
sekretbarilo install agent-hook claude --global

# switch this project to output redaction
sekretbarilo install agent-hook claude --mode redact

# switch back to blocking file reads
sekretbarilo install agent-hook claude --mode block

# target an explicit settings file instead of local/global
sekretbarilo install agent-hook claude --settings .claude/settings.local.json --mode redact
```

#### `sekretbarilo install agent-hook codex`

installs codex cli agent hook that intercepts patches and shell commands and scans them before codex applies or runs them.

**local mode (default):**
- installs to `.codex/hooks.json` in the repository root
- creates or updates the `PreToolUse` entry whose matcher is the regex `^(apply_patch|Bash)$`, with a 10 second timeout
- preserves existing codex hooks

**global mode (`--global`):**
- installs to `$CODEX_HOME/hooks.json`, defaulting to `~/.codex/hooks.json` when `CODEX_HOME` is unset
- applies to all projects using codex cli
- layers are additive: a global hook and a project hook both run

**hook behavior:**
- intercepts `apply_patch` and `Bash` tool calls before execution
- runs `sekretbarilo check-codex --stdin-json` with the `PreToolUse` payload
- for `apply_patch`: scans the lines being added, blocks `.env` targets unconditionally
- for `Bash`: scans the raw command string
- blocks the tool call if secrets detected (exit code 2), allows it if clean (exit code 0)

**trust:** codex does not run a newly installed hook until it is approved with `/hooks` in the codex tui. an unapproved hook is skipped silently. sekretbarilo does not write the trust state itself. see [agent hooks]({{ '/agent-hooks/#hook-trust' | relative_url }}).

**note:** codex can also express hooks as a `[hooks]` table in `config.toml`. sekretbarilo writes only `hooks.json` and never modifies `config.toml`.

**hand-editing `hooks.json`:** the root object accepts only the keys `hooks` and `description`. an unrecognised top-level key makes codex drop that layer's hooks entirely, with only a log warning, so a typo at the root silently disarms the file. `timeout` is in seconds (default 600 when omitted), event keys are PascalCase, and `matcher` is a regex. codex cli `0.145.0` has no `hooks list`/`hooks validate` subcommand — use `sekretbarilo doctor` to check the installation. see [agent hooks]({{ '/agent-hooks/#where-the-configuration-lives' | relative_url }}).

**examples:**
```sh
# install local codex cli hook
sekretbarilo install agent-hook codex

# install global codex cli hook
sekretbarilo install agent-hook codex --global
```

#### `sekretbarilo install all`

installs all available hooks (pre-commit + claude code agent hook + codex cli agent hook), reporting each step. `--mode block|redact` selects the claude mode; omitted, it preserves the existing mode or chooses `block` for a new installation. redaction requires a known supported claude version. when `codex` is neither on `PATH` nor has a `$CODEX_HOME` directory (default `~/.codex`), its step prints `[SKIP] codex cli not detected on this machine` and continues.

`--settings <path>` applies only to the claude step, installing into that exact file instead of the local/global default; the pre-commit and codex steps keep their normal local/global behavior. it is mutually exclusive with `--global`.

**examples:**
```sh
# install all hooks locally
sekretbarilo install all

# install all hooks globally
sekretbarilo install all --global

# install all hooks locally with claude output redaction
sekretbarilo install all --mode redact

# target an explicit claude settings file for the claude step only
sekretbarilo install all --settings .claude/settings.local.json --mode redact
```

---

### `sekretbarilo check-file`

scans a single file for secrets. used by agent hooks (claude code) but can also be invoked manually.

**behavior:**
- reads and scans a single file path
- applies same scanning rules as `scan` and `audit` commands
- fast-path rejection for .env files, vendor directories, binaries, lock files
- supports both positional file argument and stdin JSON payload mode
- stdin is capped at 1 MB in `--stdin-json` mode; a larger payload is truncated, fails to parse, and blocks
- honors a `.sekretbarilo.toml` inside the git working tree only when it is tracked and unmodified; otherwise the layer is dropped with `[WARN] ignoring untrusted in-workspace config: <path>`. see [configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }})

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

### `sekretbarilo redact-claude`

edits supported claude tool output in memory. requires `--stdin-json` and a `PostToolUse` payload. source files are unchanged.

**behavior:**

- scans `Bash` stdout/stderr and text blocks, text-file `Read` content, and `Grep` content/result lines and filename arrays; preserves Grep counters
- replaces whole captured secret values with `[REDACTED]`, merging overlapping ranges and masking repeated values
- preserves JSON structure, unknown metadata, surrounding UTF-8 text, and line endings, including CRLF and line breaks inside multiline secrets
- expands PEM/PGP findings through the matching end marker, or to the end of the text field if it is missing; applies the same policy to public keys when detection is enabled
- uses trusted hierarchical config, current rules, entropy thresholds, password heuristics, stopwords, and value exceptions; ignores path exclusions and documentation relaxations, and scans `.env` output by content
- caps input and the complete serialized hook response at 10 MiB each

**output (exit 0):**

- clean: no stdout
- masked: JSON containing `hookSpecificOutput.hookEventName: "PostToolUse"` and `hookSpecificOutput.updatedToolOutput`
- error: JSON with `continue: false` and a fixed safe `stopReason`; when the response structure is available and fits the limit, also replaces all supported text

exit 2 does not remove a PostToolUse result. parsing, config, scanning, or size failures use the stop JSON instead. stdout/stderr writes are fallible and do not print original secrets. failed stdout delivery exits 1 and attempts a fixed safe stderr diagnostic; it cannot guarantee replacement.

MCP, images/PDFs/notebooks, other tools, and a file-editing command are outside scope. `PostToolUseFailure` lacks the replacement contract. original telemetry, hook crashes/timeouts, failed output delivery, and competing replacements by another hook are not covered by a masking guarantee. entropy is used by existing detectors, not as an arbitrary random-string search. see [agent hooks]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}) for the contract and a synthetic smoke-check procedure.

**example:**
```sh
# invoked by the claude PostToolUse hook
sekretbarilo redact-claude --stdin-json
```

---

### `sekretbarilo check-codex`

entry point for the codex cli agent hook. reads a `PreToolUse` payload on stdin and decides whether codex may proceed with the tool call. this command is invoked by codex, not by hand.

**`--stdin-json` is required.** the bare command has no other source of input, so it exits 2 with `[ERROR] check-codex reads its payload from stdin and requires --stdin-json`. the command written by `install agent-hook codex` already passes the flag, so installed hooks need no change.

**behavior:**
- `apply_patch`: parses the patch and scans the lines being added (context and removed lines are discarded); skips target paths the same way `check-file` does — binaries, vendor dirs, lock files, generated files, configured path patterns. a pure rename (`*** Update File:` plus `*** Move to:` with no change lines) adds nothing and is allowed
- `.env` policy: a patch writing to a `.env` file is blocked before config is even loaded, so no allowlist can override it. for a move, either the original or the destination path triggers the block. `.env.example`, `.env.sample`, `.env.template` are allowed
- `Bash`: scans the raw command string, catching exported credentials, tokens in request headers, and heredocs that write secrets to a file
- loads the same hierarchical `.sekretbarilo.toml` as every other command, with two exceptions: an in-workspace config layer must be git-tracked and unmodified (see [configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }})), and path allowlists are dropped for `Bash`, since a command has no file path to match against. stopwords, per-rule value regexes, and entropy thresholds still apply
- writes the block reason to stderr, where codex picks it up and surfaces it to the model. nothing is ever written to stdout
- secret values in the reason are masked; file paths and rule names, which come from the patch, are stripped of control characters and bidirectional overrides before being printed
- at most 20 findings are rendered in the reason, followed by `... and N more finding(s) omitted`; the closing `total findings: N.` line always carries the true count
- a clean patch or command produces no output at all
- an event other than `PreToolUse`, or a tool other than `apply_patch`/`Bash`, is allowed without scanning
- stdin is capped at 10 MiB; an oversized payload is blocked, not truncated

**flags:** `--stdin-json` only, and it is mandatory

**exit codes:**
- 0 = allow the tool call
- 2 = block the tool call (secrets found, `.env` target, or error)

**examples:**
```sh
# invoked by the codex hook, not by hand
sekretbarilo check-codex --stdin-json
```

---

### `sekretbarilo doctor`

runs diagnostic health checks for hook installations, configuration, and binary availability.

**checks performed:**
- git pre-commit hook status (local and global)
- claude code agent hook mode and status (local and global), including outdated/duplicate handlers, conflicts between redaction and a blocking Read hook in another scope, and the configured hook binary's filesystem metadata and identity relative to the running binary
- codex cli agent hook status (local and global), including unrecognised root keys, the `[hooks.state]` approval entry for the hook's own position, and the `codex` binary on PATH
- configuration discovery and validation, including a warning for any in-workspace config the agent hooks will ignore
- rules compilation
- binary availability in PATH

**`--settings <path>`:** adds that file as an extra "explicit" scope next to local, local override, and global, deduplicated when it names the same file as another scope. the same mode, Claude Code redact-version, and blocking-Read-hook conflict diagnostics apply to it. doctor never creates or edits the file; a missing or malformed explicit file is reported as an issue and gives exit 1. doctor inspecting the file is not proof that a running claude code session has loaded it — see the profile-activation note under `install agent-hook claude`.

For a bare hook command, doctor warns that Claude Code resolves the name under its own `PATH` and that reinstalling pins an absolute path; it does not resolve the name under doctor's `PATH`. For an absolute command, doctor uses fallible filesystem metadata to distinguish a missing target from other I/O errors, requires a regular executable file, and canonicalizes the configured and running paths only for an identity comparison. It never launches the configured executable and never claims a version for it.

**exit codes:**
- 0 = all checks passed
- 1 = issues found (warnings or errors)

**examples:**
```sh
# run all diagnostic checks
sekretbarilo doctor

# also inspect an explicit claude settings file
sekretbarilo doctor --settings .claude/settings.local.json
```

**sample output:**
```
git pre-commit hook:
  [NOT INSTALLED] local pre-commit hook not found
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [NOT INSTALLED] local claude code hook not found
  [NOT INSTALLED] global claude code hook not found

codex cli agent hook:
  [OK] local codex cli hook installed (/project/.codex/hooks.json)
  [WARN] local codex cli hook approval entry not found in /home/user/.codex/config.toml; codex silently skips unapproved hooks; approve it with /hooks in the Codex TUI
  [NOT INSTALLED] global codex cli hook not found
  [OK] codex found in PATH (codex-cli 0.145.0)

configuration:
  [OK] config file: /project/.sekretbarilo.toml
  [WARN] /project/.sekretbarilo.toml is untracked or has uncommitted changes; the check-file/check-codex agent hooks ignore this config layer entirely until it is committed
  [OK] 112 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

the codex approval check is positional — codex keys approval by file, event, and index, so a hook appended after somebody else's codex hooks needs its own `/hooks` approval. see [agent hooks]({{ '/agent-hooks/#the-approval-check-is-positional' | relative_url }}).

---

### `sekretbarilo --version`

displays the installed version on stderr, so capture it with `2>&1` in scripts. `redact-claude` replacement/stop JSON is an exception to the usual stderr output convention.

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
| `--detect-public-keys` | boolean | report public keys (PEM, PGP, OpenSSH) as findings. by default, public keys are suppressed to reduce noise. |

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
| `--search <text>` | repeatable | literal substring to search for across scanned files and/or history. regex metacharacters are escaped automatically, so `api.key` matches only literal `api.key`. reports appear in a separate `[SEARCH]` block and do not run through the secret-rule engine (no allowlist/stopword suppression). |  |
| `--search-regex <pattern>` | repeatable | regex pattern to search for. case-sensitive by default; prefix with `(?i)` for case-insensitive matching. |  |

`--search` and `--search-regex` are independent of the secret-rule engine. Use them to find arbitrary text or patterns in the working tree (default) or across full history (`--history`). Combine with `--no-defaults` to skip the embedded secret rules — note that rules loaded from a `--config` file still run, so this is only a pure search mode when no custom rules are configured. Exit code is `1` when a secret **or** a search match is found.

> `--search` is not the same as `--stopword`. `--stopword` *suppresses* secret findings whose captured value contains the word; `--search` actively looks for text.

---

## Check-File Flags

these flags only apply to the `check-file` command:

| Flag | Type | Description |
|------|------|-------------|
| `--stdin-json` | boolean | read file path from JSON payload on stdin (agent hook mode). mutually exclusive with positional file path argument. |

---

## Check-Codex Flags

these flags only apply to the `check-codex` command:

| Flag | Type | Description |
|------|------|-------------|
| `--stdin-json` | boolean | **required.** read the codex `PreToolUse` payload from stdin. this is the only supported mode; the bare `check-codex` exits 2. codex always invokes the command this way. |

---

## Redact-Claude Flags

| Flag | Type | Description |
|------|------|-------------|
| `--stdin-json` | boolean | **required.** read the claude `PostToolUse` payload from stdin. configuration is loaded through trusted hierarchical discovery. |

---

## Install Flags

these flags only apply to `install` subcommands:

| Flag | Type | Description |
|------|------|-------------|
| `--global` | boolean | install globally instead of locally. for pre-commit: uses `git config --global core.hooksPath`. for `agent-hook claude`: modifies `~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json` when that variable is set and non-empty. for `agent-hook codex`: modifies `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`). |
| `--mode <block\|redact>` | choice | only for `install agent-hook claude` and `install all`. omitted: preserve the selected file's installed claude mode, defaulting to `block` for a new install. |
| `--settings <path>` | string | for `install agent-hook claude`, `install all` (claude step only), and `doctor`: target this exact claude code settings file instead of the local/global default. mutually exclusive with `--global`. a relative path resolves against the current directory, not the repo root, and works outside a git repository. |

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

### `redact-claude`

| Exit Code | Meaning |
|-----------|---------|
| 0 | clean (no stdout), masked (replacement JSON), or error (stop JSON) |
| 1 | failed to deliver JSON on stdout; replacement cannot be guaranteed |

inspect the JSON output to distinguish masking from `continue: false`. exit 2 is not used as a mechanism for removing an existing result.

### `check-codex`

| Exit Code | Meaning |
|-----------|---------|
| 0 | clean - codex may proceed with the tool call |
| 2 | secrets found, `.env` target, or error (blocks the tool call) |

note: like `check-file`, `check-codex` fails closed - an error blocks the patch or command rather than letting it through unscanned.

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

### user-search (arbitrary text or regex)

```sh
# find a literal substring in the working tree
sekretbarilo audit --search "api_key"

# same thing across all commits in history
sekretbarilo audit --history --search "api_key"

# dots in --search are literal (will NOT match 'apiXkey')
sekretbarilo audit --search "api.key"

# regex search (case-sensitive; prefix with (?i) to ignore case)
sekretbarilo audit --search-regex "TOKEN_[A-Z]+"
sekretbarilo audit --history --search-regex "(?i)internal.*url"

# multiple patterns at once (repeat the flag)
sekretbarilo audit --search "FIXME" --search "TODO" --search-regex "HACK\s*\(.+\)"

# skip the embedded secret rules (custom --config rules, if any, still run)
sekretbarilo audit --history --search "my_flag" --no-defaults

# combine with path filters to narrow scope
sekretbarilo audit --search "todo" --exclude-pattern '^vendor/'
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

### public key detection

```sh
# scan staged changes and also report public keys
sekretbarilo scan --detect-public-keys

# audit working tree including public key findings
sekretbarilo audit --detect-public-keys
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

# install codex cli hook locally, then approve it with /hooks inside codex
sekretbarilo install agent-hook codex

# install codex cli hook globally
sekretbarilo install agent-hook codex --global

# install pre-commit plus every agent hook available on this machine
sekretbarilo install all --global

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
| `--detect-public-keys` | `scan`, `audit` | `install`, `check-file`, `doctor` |
| `--history` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--branch` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--since` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--until` | `audit --history` | `scan`, `audit` (without `--history`) |
| `--exclude-pattern` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--include-pattern` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--search` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--search-regex` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--include-ignored` | `audit` | `scan`, `install`, `check-file`, `doctor` |
| `--stdin-json` | `check-file`; required for `check-codex`, `redact-claude` | `scan`, `audit`, `install`, `doctor`; also rejected alongside a positional path on `check-file` |
| `--global` | `install` subcommands | `scan`, `audit`, `check-file`, `check-codex`, `redact-claude`, `doctor` |
| `--mode` | `install agent-hook claude`, `install all` | other commands and install targets |
| `--settings` | `install agent-hook claude`, `install all`, `doctor` | other commands; rejected alongside `--global` |

invalid flag combinations normally produce an error message and exit code 2. `redact-claude` instead emits fixed stop JSON with exit 0, without echoing arguments.

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

when no `--config` flag is specified, sekretbarilo auto-discovers and merges configs in this order (lowest priority first):

1. embedded default rules (skipped if `--no-defaults`)
2. `/etc/sekretbarilo.toml` (system-wide)
3. `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml`, falling back to `~/.config/sekretbarilo/sekretbarilo.toml`
4. every `.sekretbarilo.toml` in the directory hierarchy from `$HOME` down to the starting directory, ending with `~/.sekretbarilo.toml` at the top and the project's own file at the bottom

cli flags override config file values. repeatable flags (allowlist-path, stopword) are appended, not replaced.

when `--config` is specified, auto-discovery is skipped and only the specified files are loaded.

`check-file`, `check-codex`, and `redact-claude` apply one further rule: a config file inside the git working tree counts only when it is tracked and unmodified. `redact-claude` also ignores path exclusions and documentation relaxations while preserving value exceptions. see [configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }}).
