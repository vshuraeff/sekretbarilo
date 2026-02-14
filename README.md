# sekretbarilo

High-performance secret scanner for git workflows and AI coding agents. Catches API keys, credentials, and secrets before they leak.

*sekretbarilo* means "secret keeper" in Esperanto.

## Features

- **Fast**: ~2.5 µs per commit, ~3.7 ms for 400-file diffs; parallel audit via rayon
- **109 built-in rules** in three precision tiers (prefix-based, context-aware, catch-all) — see [rules reference](docs/_pages/rules-reference.md)
- **Low false positives**: entropy analysis, stopword filtering, hash/variable detection, template-aware
- **Pre-commit hook**: scans staged changes on every commit
- **Working tree & history audit**: scan tracked files or full git history with deduplication and branch resolution
- **Agent hooks**: blocks AI agents (Claude Code) from reading files with secrets
- **Health diagnostics**: `doctor` command checks hooks, config, and binary availability
- **Hierarchical config**: `.sekretbarilo.toml` at system, user, and project levels
- **Zero config needed**: works out of the box with sensible defaults
- **Blocks .env files**: prevents committing or reading `.env`, `.env.local`, `.env.production`, etc.

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

### Audit

```sh
# scan working tree
sekretbarilo audit

# scan full git history
sekretbarilo audit --history

# filter by branch or date
sekretbarilo audit --history --branch main --since 2024-01-01
```

### Agent hooks (Claude Code)

```sh
# install in current project
sekretbarilo install agent-hook claude

# install globally
sekretbarilo install agent-hook claude --global

# install all hooks at once
sekretbarilo install all --global
```

Adds a `PreToolUse` hook on the `Read` tool. When Claude Code reads a file, sekretbarilo scans it first and blocks the read if secrets are found. Binary files, vendor directories, and lock files are fast-path skipped.

### Diagnostics

```sh
sekretbarilo doctor
```

Checks pre-commit hooks (local/global), Claude Code hooks, configuration, and PATH availability.

## CLI reference

### Common flags (scan, audit)

| Flag | Description |
|------|-------------|
| `--config <path>` | Explicit config file (repeatable, merged in order) |
| `--no-defaults` | Skip built-in rules, use only config rules |
| `--entropy-threshold <n>` | Override global entropy threshold |
| `--allowlist-path <pattern>` | Add path allowlist pattern (repeatable) |
| `--stopword <word>` | Add stopword (repeatable) |

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

### Other flags

| Flag | Description |
|------|-------------|
| `--stdin-json` | Read file path from stdin JSON (check-file) |
| `--global` | Install globally (install) |

## Exit codes

| Command | 0 | 1 | 2 |
|---------|---|---|---|
| `scan`, `audit`, `doctor` | Clean | Secrets found | Error |
| `check-file` | Clean / skipped | — | Secrets found or error |

`check-file` uses exit 2 for both secrets and errors to fail closed — Claude Code blocks any non-zero exit.

## Configuration

Create `.sekretbarilo.toml` in your repo root, or use `--config <path>` to skip hierarchical discovery.

### Lookup order (lowest to highest priority)

1. `/etc/sekretbarilo.toml` (system)
2. `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` (user)
3. `~/.sekretbarilo.toml` (home)
4. Parent directories from `$HOME` to repo root
5. `.sekretbarilo.toml` (project)

**Merge strategy**: scalars — last wins; lists — merged and deduplicated; rules by `id` — last wins.

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

[audit]
exclude_patterns = ["^vendor/", "^build/"]
include_patterns = ["\\.rs$"]
```

## False positive reduction

- **Entropy thresholds**: tier 2/3 rules filter low-randomness strings (+1.0 bonus for doc files)
- **Stopwords**: `example`, `test`, `placeholder`, `changeme`, `fake`, `mock`, `dummy`, etc.
- **Hash detection**: SHA-1, SHA-256, MD5, git commit hashes
- **Variable references**: `${VAR}`, `$VAR`, `process.env.VAR`, `os.environ["VAR"]`, `System.getenv("VAR")`, etc.
- **Template handling**: Jinja2/Helm `{{ }}`, GitHub Actions `${{ }}`, ERB `<%= %>`, Terraform `${var.}`, and more
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
