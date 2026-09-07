# sekretbarilo

[![CI](https://github.com/vshuraeff/sekretbarilo/actions/workflows/ci.yml/badge.svg)](https://github.com/vshuraeff/sekretbarilo/actions/workflows/ci.yml)
[![Release](https://github.com/vshuraeff/sekretbarilo/actions/workflows/release.yml/badge.svg)](https://github.com/vshuraeff/sekretbarilo/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/vshuraeff/sekretbarilo)](https://github.com/vshuraeff/sekretbarilo/releases)
[![License: MIT](https://img.shields.io/github/license/vshuraeff/sekretbarilo)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/vshuraeff/sekretbarilo)

High-performance secret scanner for git workflows and AI coding agents. Catches API keys, credentials, and secrets before they leak.

*sekretbarilo* means "secret keeper" in Esperanto.

## Features

- **Fast**: ~2.5 µs per commit, ~3.7 ms for 400-file diffs; parallel audit via rayon
- **113 built-in rules** in three precision tiers (prefix-based, context-aware, catch-all) — see [rules reference](docs/_pages/rules-reference.md)
- **Low false positives**: entropy analysis, stopword filtering, hash/variable detection, template-aware, public key suppression
- **Pre-commit hook**: scans staged changes on every commit
- **Working tree & history audit**: scan tracked files or full git history with deduplication and branch resolution
- **Agent hooks**: blocks Claude Code file reads or masks secrets in `Bash`, `Read`, and `Grep` results; blocks Codex CLI from writing secrets via `apply_patch` or `Bash`
- **Health diagnostics**: `doctor` command checks hooks, config, and binary availability
- **Hierarchical config**: `.sekretbarilo.toml` at system, user, and project levels
- **Zero config needed**: works out of the box with sensible defaults
- **Blocks .env files**: prevents committing them and reading them in Claude `block` mode; `redact` scans their returned content

## Installation

### Homebrew (macOS and Linux)

```sh
brew install vshuraeff/tap/sekretbarilo
```

### GitHub Releases

Download pre-built binaries from the [releases page](https://github.com/vshuraeff/sekretbarilo/releases):

- `aarch64-apple-darwin` / `x86_64-apple-darwin` (macOS)
- `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` (Linux)
- `.deb` packages for Debian/Ubuntu (amd64 + arm64)

### From source

```sh
cargo install --path .
```

## Quick start

### Pre-commit hook

```sh
# install in current repo
sekretbarilo install pre-commit

# install globally (all repos)
sekretbarilo install pre-commit --global

# manually scan staged changes
sekretbarilo scan
```

The global install works through `core.hooksPath` (default `~/.config/git/hooks`), setting it when unset. It applies to every repository immediately, and — being how git works — it replaces per-repository `.git/hooks/` rather than layering with it.

### Audit

```sh
# scan working tree
sekretbarilo audit

# scan full git history
sekretbarilo audit --history

# filter by branch or date
sekretbarilo audit --history --branch main --since 2024-01-01

# find arbitrary text in working tree (literal substring, dots are literal)
sekretbarilo audit --search "api.key"

# find regex across full history (case-sensitive; use (?i) prefix for ci)
sekretbarilo audit --history --search-regex "TOKEN_[A-Z]+"

# skip embedded default rules; custom config rules (if any) still apply
sekretbarilo audit --history --search "my_flag" --no-defaults
```

### Agent hooks (Claude Code)

```sh
# install in current project
sekretbarilo install agent-hook claude

# install globally
sekretbarilo install agent-hook claude --global

# mask tool results instead of blocking file reads (Claude Code >= 2.1.121)
sekretbarilo install agent-hook claude --mode redact

# switch back to blocking reads
sekretbarilo install agent-hook claude --mode block

# target an explicit settings file instead of the local/global default
sekretbarilo install agent-hook claude --settings .claude/settings.local.json --mode redact

# install all hooks at once
sekretbarilo install all --global
```

`--settings <path>` installs into that exact file instead of the local or global default, is mutually exclusive with `--global`, and works outside a git repository; a relative path resolves against the current directory, not the repo root. Installing into an arbitrary file does not register a new Claude Code profile: Claude only picks it up when it is one of its standard settings files, when Claude itself is launched with its own [`--settings <path>`](https://code.claude.com/docs/en/cli-reference) flag, or when the file is the `settings.json` of the profile directory named by [`CLAUDE_CONFIG_DIR`](https://code.claude.com/docs/en/claude-directory).

The default for a new installation is `block`: a `PreToolUse` hook scans files before `Read` and blocks secrets or `.env` files. Binary files, vendor directories, and lock files are fast-path skipped. Omitting `--mode` preserves the mode already installed in the selected settings file, including when running `install all`.

`redact` installs a synchronous `PostToolUse` hook for `Bash`, `Read`, and `Grep`. Tools execute normally; detected secret values in supported text results become `[REDACTED]` before the result reaches the model. This is an **in-memory output editor**: source files are unchanged. Eligible high-entropy values are redacted regardless of variable name, so harmless base64 blobs or checksums may also be redacted. Response structure, metadata, surrounding text, UTF-8, and line endings are preserved. For example, `cat config.txt` can return:

```text
host = localhost
password = [REDACTED]
port = 5432
```

`redact` uses the same trusted configuration, rules, entropy thresholds, password heuristics, and value exceptions. Path exclusions and documentation relaxations do not apply; `.env` output is scanned by content. Installation checks Claude Code >= 2.1.121 before changing protection, and installation/`doctor` warn about a blocking Read hook in another settings scope. See [redaction behavior and limits](docs/_pages/agent-hooks.md#redact-mode-output-editor), including unsupported tools, hook failures, and telemetry.

Password assignments are detected with double quotes, single quotes, backticks, or no quotes. Existing strength and placeholder checks apply to every form.

### Agent hooks (Codex CLI)

```sh
# install in current project (.codex/hooks.json)
sekretbarilo install agent-hook codex

# install globally ($CODEX_HOME/hooks.json, default ~/.codex/hooks.json)
sekretbarilo install agent-hook codex --global
```

Adds a `PreToolUse` hook on the `apply_patch` and `Bash` tools. For `apply_patch` sekretbarilo scans the lines being added and blocks patches targeting `.env` files outright; for `Bash` it scans the command string, catching exported credentials, tokens in `curl -H` headers, and heredocs that write secrets to a file. A block is an exit code 2 with a masked reason on stderr, which Codex surfaces to the model. The reason renders at most 20 findings (the closing `total findings: N.` line still carries the true count), and file paths and rule names taken from the patch are stripped of control characters before printing.

`check-codex` requires `--stdin-json` — the bare command exits 2. The installer already writes the flag, so existing installations are unaffected.

**Codex will not run a newly installed hook until you approve it** — run `/hooks` in the Codex TUI. An unapproved hook is skipped silently. sekretbarilo does not write the trust state itself: the trust hash is an internal Codex detail, and a security tool that grants itself trust defeats the point of the trust model. For non-interactive use, Codex offers `--dangerously-bypass-hook-trust`, which disables the check for every hook in the session.

Verified on codex-cli `0.145.0`; older releases may not deliver `PreToolUse` for `apply_patch`. Note two limits: Codex has no Read-equivalent tool, so the hook cannot stop the agent from *reading* a file with secrets, and the `Bash` check is a text scan — a guardrail against accidental leakage, not a sandbox. See the [agent hooks docs](docs/_pages/agent-hooks.md) for details.

`sekretbarilo install all` sets up the pre-commit hook plus every agent hook at once. `--mode block|redact` selects the Claude mode; omitted, it preserves the installed mode or chooses `block` for a new installation. Selecting `redact` requires a supported Claude version. `--settings <path>` applies only to the Claude step; the pre-commit and Codex steps keep their normal local/global behavior. The Codex step is skipped when `codex` is neither on `PATH` nor has a `$CODEX_HOME` directory.

### Diagnostics

```sh
sekretbarilo doctor

# also inspect an explicit Claude Code settings file
sekretbarilo doctor --settings .claude/settings.local.json
```

Checks pre-commit hooks (local/global), Claude Code hooks, Codex CLI hooks, configuration, and PATH availability. `--settings <path>` adds that file as an extra "explicit" scope next to local and global, deduplicated when it names the same file; doctor never creates or edits it, and a missing or malformed file is reported as an issue.

## CLI reference

### Common flags (scan, audit)

| Flag | Description |
|------|-------------|
| `--config <path>` | Explicit config file (repeatable, merged in order) |
| `--no-defaults` | Skip built-in rules, use only config rules |
| `--entropy-threshold <n>` | Override global entropy threshold |
| `--allowlist-path <pattern>` | Add path allowlist pattern (repeatable) |
| `--stopword <word>` | Add stopword (repeatable) |
| `--detect-public-keys` | Report public keys as findings (default: suppressed) |

### Audit-only flags

| Flag | Description |
|------|-------------|
| `--history` | Scan git history instead of working tree |
| `--branch <name>` | Limit to branch (requires `--history`) |
| `--since <date>` | Commits after date (requires `--history`) |
| `--until <date>` | Commits before date (requires `--history`) |
| `--include-ignored` | Include untracked ignored files |
| `--exclude-pattern <p>` | Exclude pattern (repeatable) |
| `--include-pattern <p>` | Force-include pattern (repeatable) |
| `--search <text>` | Literal substring to search for (repeatable; metacharacters are escaped) |
| `--search-regex <pattern>` | Regex pattern to search for (repeatable; case-sensitive) |

`--search`/`--search-regex` report hits in a separate `[SEARCH]` block and do not affect secret-rule output. Combine with `--no-defaults` to skip the embedded secret rules — note that custom rules from config files still run, so this is only a pure search mode if no custom rules are configured. Both flags work in working-tree and `--history` modes. Exit code is `1` when a secret **or** a search match is found.

> Note: `--stopword` is an *allowlist* (suppresses findings whose secret value contains the word), not a search filter. For searching use `--search`/`--search-regex`.

### Other flags

| Flag | Description |
|------|-------------|
| `--stdin-json` | Read the hook payload from stdin JSON (`check-file`; required for `check-codex` and `redact-claude`) |
| `--global` | Install globally (install). For the Claude step, honours `CLAUDE_CONFIG_DIR` when set, writing `$CLAUDE_CONFIG_DIR/settings.json` instead of `~/.claude/settings.json` |
| `--mode block\|redact` | Select Claude hook mode (`install agent-hook claude`, `install all`) |
| `--settings <path>` | Target an explicit Claude Code settings file (`install agent-hook claude`, `install all`, `doctor`); mutually exclusive with `--global` |

## Exit codes

| Command | 0 | 1 | 2 |
|---------|---|---|---|
| `scan`, `audit`, `doctor` | Clean | Secrets found | Error |
| `check-file` | Clean / skipped | — | Secrets found or error |
| `check-codex` | Allow tool call | — | Block tool call (secrets, `.env` target, or error) |
| `redact-claude` | No change, replacement JSON, or stop JSON on error | Output delivery failed | Not used to remove output |

`check-file` and `check-codex` use exit 2 for both secrets and errors to block the tool call. `redact-claude` normally exits 0: clean output has no stdout; masking returns `hookSpecificOutput.updatedToolOutput`. Errors and the 10 MiB input/output limits return `continue: false` with a fixed safe reason and, when possible, a replacement hiding all supported text. Failed stdout delivery exits 1. A PostToolUse exit 2 does not remove a result that already exists.

## Configuration

Create `.sekretbarilo.toml` in your repo root, or use `--config <path>` to skip hierarchical discovery.

### Lookup order (lowest to highest priority)

1. `/etc/sekretbarilo.toml` (system)
2. `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` (user)
3. `~/.sekretbarilo.toml` (home)
4. Parent directories from `$HOME` to repo root
5. `.sekretbarilo.toml` (project)

**Merge strategy**: scalars — last wins; lists — merged and deduplicated; rules by `id` — last wins.

### Agent hooks require an in-repo config to be committed

`check-file`, `check-codex`, and `redact-claude` honour a `.sekretbarilo.toml` located inside the git working tree only when it is **git-tracked and unmodified relative to `HEAD`**. Otherwise the whole layer is dropped with a warning on stderr. Layers above the repo root, the user config, and the system config are unaffected, and `scan`/`audit` are not affected at all.

The reason: an agent that can write files can write a permissive config, and that patch carries no secret, so it passes — after which every later check is neutered. A dropped layer is dropped whole rather than partially, because a `[[rules]]` entry reusing a built-in `id` replaces that rule. `sekretbarilo doctor` flags any in-workspace config the hooks will ignore. The fix is to commit it.

### Allowlists

```toml
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]
stopwords = ["my-safe-token"]

[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]

[[allowlist.rules]]
id = "generic-api-key"
paths = ["test/.*"]
```

### Custom rules

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
entropy_threshold = 3.5

[rules.allowlist]
regexes = ["test_token_.*"]
paths = ["test/.*"]
```

### Settings

```toml
[settings]
entropy_threshold = 3.5
detect_public_keys = true  # report public keys as findings (default: false)

[audit]
exclude_patterns = ["^vendor/", "^build/"]
include_patterns = ["\\.rs$"]
```

## False positive reduction

- **Entropy thresholds**: tier 2/3 rules filter low-randomness strings (+1.0 bonus for doc files)
- **Stopwords**: `example`, `test`, `placeholder`, `changeme`, `fake`, `mock`, `dummy`, etc.
- **Hash detection**: SHA-1, SHA-256, MD5, git commit hashes
- **Variable references**: `${VAR}`, `$VAR`, `process.env.VAR`, `os.environ["VAR"]`, `System.getenv("VAR")`, etc.
- **Template handling**: Jinja2/Helm/Mustache/Handlebars `{{ }}`, GitHub Actions `${{ }}`, ERB `<%= %>`, Terraform `${var.}`, and more
- **Public key suppression**: PEM, PGP, and OpenSSH public key blocks are suppressed by default (opt-in via `--detect-public-keys`)
- **Password strength**: only flags strong passwords (8+ chars, mixed case, digits)
- **Path allowlists**: binary files, generated files, lock files, vendor dirs auto-skipped

## Performance

| Scenario | Time |
|---|---|
| Empty diff | ~48 ns |
| Typical commit (1 file, 10 lines) | ~2.5 µs |
| Medium commit (10 files, 500 lines) | ~168 µs |
| Large commit (100 files, 5000 lines) | ~679 µs |
| Very large (400 files, 40K lines) | ~3.7 ms |

Aho-corasick single-pass keyword matching, one-time regex compilation, byte-level processing, rayon parallelism.

```sh
cargo bench
```

## Bypassing

```sh
git commit --no-verify
```

Prefer adding allowlist entries to `.sekretbarilo.toml` instead.

## License

MIT
