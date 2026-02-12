# sekretbarilo

Secret scanner for git repositories. Scans staged commits, working trees, and full git history for API keys, credentials, and secrets.

*sekretbarilo* means "secret keeper" in Esperanto.

## Features

- **Fast**: a typical commit scans in ~2.5 µs, a 400-file diff in ~3.7 ms; audits run files and commits in parallel via rayon
- **Three-tier rule system**: 43 built-in rules organized by precision (prefix-based, context-aware, catch-all)
- **Low false positives**: Shannon entropy analysis, stopword filtering, hash detection, variable reference detection
- **Pre-commit hook**: automatic scanning of staged changes on every commit
- **Working tree audit**: scan all tracked (and optionally ignored) files for secrets
- **Git history audit**: scan every commit across all branches with deduplication, author tracking, and branch resolution
- **Agent hooks**: integrates with AI coding agents (Claude Code) to scan files before they are read
- **Health diagnostics**: `doctor` command checks hook installation, configuration, and binary availability
- **Configurable**: hierarchical `.sekretbarilo.toml` (system, user, project) for allowlists, custom rules, and overrides
- **Zero config needed**: works out of the box with sensible defaults
- **Blocks .env files**: automatically prevents committing `.env`, `.env.local`, `.env.production` etc.

## Installation

### From source

```sh
cargo install --path .
```

### Build from repository

```sh
git clone https://github.com/vshuraeff/sekretbarilo.git
cd sekretbarilo
cargo build --release
# binary is at target/release/sekretbarilo
```

## Quick start

### Pre-commit hook

Install the git pre-commit hook in your repository:

```sh
cd your-project
sekretbarilo install pre-commit
```

This creates (or appends to) `.git/hooks/pre-commit`. From now on, every `git commit` automatically scans staged changes for secrets.

To install globally (applies to all repositories):

```sh
sekretbarilo install pre-commit --global
```

To manually scan staged changes:

```sh
sekretbarilo scan
```

### Audit your repository

Scan all tracked files in the working tree:

```sh
sekretbarilo audit
```

Scan the full git history for secrets (without switching branches):

```sh
sekretbarilo audit --history
```

Filter history scans by branch or date range:

```sh
sekretbarilo audit --history --branch main
sekretbarilo audit --history --since 2024-01-01
sekretbarilo audit --history --since 2024-01-01 --until 2024-06-30
sekretbarilo audit --history --branch main --since 2024-01-01
```

Include untracked ignored files in the audit:

```sh
sekretbarilo audit --include-ignored
```

### Agent hooks (Claude Code)

Install a hook so Claude Code scans every file for secrets before reading it:

```sh
# install in current project (.claude/settings.json)
sekretbarilo install agent-hook claude

# install globally (~/.claude/settings.json)
sekretbarilo install agent-hook claude --global
```

This adds a `PreToolUse` hook for the `Read` tool. When Claude Code reads a file, sekretbarilo scans it first and blocks the read if secrets are found, preventing accidental exposure of credentials to the agent.

You can also scan a single file directly:

```sh
# scan a file by path
sekretbarilo check-file src/config.rs

# read file path from Claude Code hook JSON payload on stdin
sekretbarilo check-file --stdin-json
```

Install all hooks at once (pre-commit + agent hooks):

```sh
sekretbarilo install all
sekretbarilo install all --global
```

### Diagnosing your setup

Check installation health across all hook types and configuration:

```sh
sekretbarilo doctor
```

The `doctor` command checks:
- Git pre-commit hook (local and global): installed, executable, correct marker
- Claude Code hook (local and global): installed, correct matcher and command
- Configuration: config files found, rules compile successfully
- Binary availability: sekretbarilo is findable in PATH

### Note on Codex CLI

Codex CLI does not currently support a hooks system. The `install agent-hook codex` subcommand is reserved for future use. If Codex adds a hooks API, sekretbarilo will add support. An alternative approach under consideration is running sekretbarilo as an MCP tool server, which would work with any agent that supports MCP.

## CLI flags

Both `scan` and `audit` commands accept the following flags:

| Flag | Description |
|------|-------------|
| `--config <path>` | Use explicit config file instead of hierarchical discovery. Repeatable; multiple configs are merged in order (last wins for scalars, lists are combined). |
| `--no-defaults` | Skip embedded default rules. Only use rules from config file(s). |
| `--entropy-threshold <n>` | Override the global entropy threshold. |
| `--allowlist-path <pattern>` | Add a path pattern to the allowlist. Repeatable. |
| `--stopword <word>` | Add a stopword. Repeatable. |

Check-file flags:

| Flag | Description |
|------|-------------|
| `--stdin-json` | Read file path from JSON payload on stdin (agent hook mode). |

Install flags:

| Flag | Description |
|------|-------------|
| `--global` | Install globally instead of per-project. |

Audit-only flags:

| Flag | Description |
|------|-------------|
| `--history` | Scan full git history instead of working tree. |
| `--branch <name>` | Limit to commits reachable from branch (requires `--history`). |
| `--since <date>` | Only commits after date (requires `--history`). |
| `--until <date>` | Only commits before date (requires `--history`). |
| `--include-ignored` | Include untracked ignored files. |
| `--exclude-pattern <pattern>` | Add an exclude pattern for audit. Repeatable. |
| `--include-pattern <pattern>` | Add an include pattern for audit (overrides excludes). Repeatable. |

### Examples

```sh
# scan with a custom config file (skips hierarchical discovery)
sekretbarilo scan --config my-rules.toml

# scan with only custom rules, no built-in defaults
sekretbarilo scan --no-defaults --config my-rules.toml

# merge two config files (b.toml overrides a.toml for scalars)
sekretbarilo audit --config a.toml --config b.toml

# override entropy threshold for a one-off scan
sekretbarilo scan --entropy-threshold 4.5

# add a stopword to suppress known-safe values
sekretbarilo scan --stopword my-known-safe-token

# skip a directory from audit
sekretbarilo audit --exclude-pattern '^vendor/'

# combine CLI flags with config files
sekretbarilo audit --config ci-rules.toml --stopword test-token --exclude-pattern '^fixtures/'

# install claude code agent hook (project-local)
sekretbarilo install agent-hook claude

# install all hooks globally
sekretbarilo install all --global

# scan a single file for secrets
sekretbarilo check-file src/config.rs

# check installation health
sekretbarilo doctor
```

## Audit mode

Audit mode scans the entire working tree or full git history for secrets, reusing the same scanning engine as the pre-commit hook.

### Working tree audit

Scans all tracked files in the current working tree using the same scanning engine as the pre-commit hook. Files are read and processed in parallel via rayon.

```sh
sekretbarilo audit
```

### Git history audit

Scans every commit in the repository (or a filtered subset) without checking out any branches. Commits are processed in parallel, findings are deduplicated (same secret in the same file keeps the earliest introducing commit), and branches containing each finding are resolved automatically.

```sh
sekretbarilo audit --history
```

History audit output includes author, email, date, and branch containment per commit:

```
  commit: abc12345 (John Doe <john@example.com>, 2024-01-15T10:30:00+00:00)
    branches: main, feature/auth
    file: config.py
    line: 7
    rule: aws-access-key-id
    match: AK**************QA
```

Audit findings use `[AUDIT]` prefix and the same exit codes as scan mode.

### Audit configuration

```toml
[audit]
include_ignored = false                  # include untracked ignored files (default: false)
exclude_patterns = ["^vendor/", "^build/"]  # regex patterns to exclude from audit
include_patterns = ["\\.rs$"]            # regex patterns to force-include (overrides excludes)
```

## How it works

### Pre-commit scan pipeline

1. Runs `git diff --cached --unified=0 --diff-filter=d` to get staged changes
2. Parses the unified diff into per-file blocks with line numbers
3. Blocks `.env` files immediately (except `.env.example`, `.env.sample`, `.env.template`)
4. Runs aho-corasick keyword pre-filter (single pass, maps keywords to rules)
5. Evaluates only matching rules' regexes against the diff content
6. Checks Shannon entropy on captured secret groups
7. Applies password strength heuristics
8. Filters out hashes (SHA-1, SHA-256, MD5, git commit hashes)
9. Applies stopword and allowlist filtering
10. Reports findings with masked secret values

### Audit pipeline

1. **Working tree**: `git ls-files` enumerates tracked files, reads them in parallel, and feeds them through the same scanning engine
2. **History**: `git rev-list` enumerates commits, `git diff-tree` extracts per-commit diffs (with `--root` for root commits), commits are scanned in parallel via rayon, findings are deduplicated, and branches are resolved via `git branch --contains`

Both modes share the same scanner engine, rules, allowlists, and output formatting.

## Exit codes

### `scan`, `audit`, `doctor`

| Code | Meaning |
|------|---------|
| 0 | No secrets found (or all checks passed for `doctor`) |
| 1 | Secrets detected (or issues found for `doctor`) |
| 2 | Internal error (config parse failure, git not found, etc.) |

### `check-file`

| Code | Meaning |
|------|---------|
| 0 | Clean (no secrets found, or file skipped as binary/allowlisted) |
| 2 | Secrets found or error (Claude Code blocks the read on exit 2) |

## Output format

When secrets are detected, the output looks like:

```
[ERROR] secret detected in staged changes

  file: src/config.rs
  line: 42
  rule: aws-access-key-id
  match: AK**************QA

  file: .env
  line: -
  rule: env-file-blocked
  match: (blocked file type)

commit blocked. 2 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

Secret values are always masked — only the first 2 and last 2 characters are shown.

## Configuration

Create a `.sekretbarilo.toml` file in your repository root to customize behavior. Alternatively, use `--config <path>` to specify config files explicitly (this skips hierarchical discovery entirely).

### Config file lookup order

sekretbarilo searches for config files in the following locations (lowest priority first):

| Priority | Location | Description |
|----------|----------|-------------|
| 1 (lowest) | `/etc/sekretbarilo.toml` | System-wide defaults |
| 2 | `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` | User-level defaults (falls back to `~/.config/sekretbarilo/sekretbarilo.toml`) |
| 3 | `~/.sekretbarilo.toml` | Home directory config |
| 4..N | Parent directories from `$HOME` down to repo root | Hierarchical project configs |
| N+1 (highest) | `.sekretbarilo.toml` in current directory | Project-specific config |

All found config files are loaded and merged. The merge strategy is:

- **Scalar fields** (e.g., `entropy_threshold`): the most local (highest priority) value wins
- **List fields** (e.g., `allowlist.paths`, `allowlist.stopwords`): concatenated from all levels, deduplicated
- **Rules** (by `id`): if the same rule `id` appears at multiple levels, the most local definition wins; rules with unique ids from all levels are combined

This allows you to set organization-wide defaults in `~/.config/sekretbarilo/sekretbarilo.toml` and override them per-project.

#### Example: multi-level config

System-wide (`/etc/sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 3.0

[allowlist]
stopwords = ["company-safe-token"]
```

User-level (`~/.config/sekretbarilo/sekretbarilo.toml`):
```toml
[allowlist]
paths = ["vendor/.*"]
```

Project-level (`.sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 4.0

[allowlist]
stopwords = ["project-specific-token"]
```

Effective merged config:
```toml
# entropy_threshold = 4.0 (project wins)
# allowlist.stopwords = ["company-safe-token", "project-specific-token"] (merged)
# allowlist.paths = ["vendor/.*"] (from user config)
```

### Allowlist paths

Skip scanning for files matching these regex patterns:

```toml
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]
```

### Additional stopwords

Findings containing these strings in the secret value are skipped:

```toml
[allowlist]
stopwords = ["my-project-specific-safe-token"]
```

### Per-rule allowlists

Override allowlists for specific rules:

```toml
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]

[[allowlist.rules]]
id = "generic-api-key"
paths = ["test/.*", "spec/.*"]
```

### Global settings

```toml
[settings]
entropy_threshold = 3.5
```

### Custom rules

Add project-specific detection rules:

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
```

Optional fields for custom rules:
- `entropy_threshold` - minimum Shannon entropy for the captured group
- `allowlist.regexes` - value patterns to skip
- `allowlist.paths` - file path patterns to skip

## Built-in rules

### Tier 1: prefix-based (very low false positives)

These rules detect secrets with distinctive prefixes and rarely produce false positives.

| Rule ID | Description |
|---------|-------------|
| aws-access-key-id | AWS access key ID (AKIA...) |
| github-personal-access-token | GitHub PAT (ghp_...) |
| github-oauth-token | GitHub OAuth token (gho_...) |
| github-app-token | GitHub app token (ghs_...) |
| github-refresh-token | GitHub refresh token (ghr_...) |
| github-fine-grained-pat | GitHub fine-grained PAT (github_pat_...) |
| gitlab-personal-access-token | GitLab PAT (glpat-...) |
| slack-bot-token | Slack bot token (xoxb-...) |
| slack-user-token | Slack user token (xoxp-...) |
| slack-app-token | Slack app token (xapp-...) |
| stripe-secret-key-live | Stripe live secret key (sk_live_...) |
| stripe-secret-key-test | Stripe test secret key (sk_test_...) |
| stripe-publishable-key-live | Stripe live publishable key (pk_live_...) |
| sendgrid-api-key | SendGrid API key (SG....) |
| pem-private-key | PEM private key block |
| jwt-token | JWT token (eyJ...) |
| digitalocean-personal-access-token | DigitalOcean PAT (dop_v1_...) |
| digitalocean-oauth-token | DigitalOcean OAuth (doo_v1_...) |
| digitalocean-refresh-token | DigitalOcean refresh (dor_v1_...) |
| npm-access-token | npm token (npm_...) |
| pypi-api-token | PyPI token (pypi-...) |
| docker-hub-pat | Docker Hub PAT (dckr_pat_...) |
| new-relic-api-key | New Relic key (NRAK-...) |
| terraform-cloud-token | Terraform Cloud token (*.atlasv1.*) |
| anthropic-api-key | Anthropic key (sk-ant-...) |
| openai-api-key-legacy | OpenAI key legacy format (sk-...T3BlbkFJ...) |
| openai-api-key | OpenAI key project format (sk-proj-...) |

### Tier 2: context-aware (medium false positives)

These rules require keyword context and/or entropy checks.

| Rule ID | Description |
|---------|-------------|
| aws-secret-access-key | AWS secret access key |
| database-connection-string-postgres | PostgreSQL connection string |
| database-connection-string-mysql | MySQL connection string |
| database-connection-string-mongodb | MongoDB connection string |
| redis-connection-string | Redis connection string with password |
| generic-password-assignment | Password assignment in code |
| generic-secret-assignment | Secret/token assignment in code |
| password-in-url | Password embedded in URL |
| http-bearer-token | HTTP bearer token |
| http-basic-auth | HTTP basic auth header |
| webhook-url-with-token | Slack/Discord webhook URL |
| azure-storage-account-key | Azure storage account key |
| cloudflare-api-key | Cloudflare API key |
| datadog-api-key | Datadog API key |
| heroku-api-key | Heroku API key |

### Tier 3: catch-all (highest false positive risk)

| Rule ID | Description |
|---------|-------------|
| generic-api-key | Generic API key pattern (keyword + assignment + high entropy) |

## False positive reduction

sekretbarilo uses several techniques to minimize false positives:

- **Entropy thresholds**: tier 2 and 3 rules require minimum Shannon entropy on the captured secret value, filtering out low-randomness strings
- **Stopwords**: findings containing words like `example`, `test`, `placeholder`, `changeme`, `dummy`, `fake`, `mock` etc. are automatically skipped
- **Hash detection**: SHA-1, SHA-256, MD5, and git commit hashes are recognized and allowed
- **Variable references**: patterns like `${VAR}`, `$VAR`, `process.env.VAR`, `os.environ["VAR"]`, `System.getenv("VAR")` are detected and skipped
- **Documentation awareness**: files in docs directories or with markdown/text extensions get a higher entropy threshold, reducing noise from example code
- **Path allowlists**: binary files, generated files, lock files, and vendor directories are automatically skipped

### Default stopwords

`example`, `test`, `sample`, `placeholder`, `dummy`, `changeme`, `fake`, `mock`, `todo`, `fixme`, `xxx`, `lorem`, `default`, `replace_me`, `insert_here`, `your_`, `my_`

### Default skipped paths

- Binary: `.png`, `.jpg`, `.gif`, `.pdf`, `.exe`, `.dll`, `.zip`, `.gz`, `.tar`, `.mp3`, `.mp4`, etc.
- Generated: `.min.js`, `.min.css`, `.map`
- Lock files: `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`, `pnpm-lock.yaml`, etc.
- Vendor: `node_modules/`, `vendor/`, `.bundle/`, `bower_components/`, `__pycache__/`, `.git/`

## Performance

Benchmark environment: 
- `MacOS 15.7`
- `Intel(R) Core(TM) i9-9900 CPU @ 3.60GHz`
- `criterion`
 
### Scan benchmarks

| Scenario | Scale | Time |
|---|---|---|
| Empty diff | 0 lines | ~48 ns |
| Typical commit | 1 file, 10 lines | ~2.5 µs |
| Medium commit | 10 files, 500 lines | ~168 µs |
| With secrets | 10 files | ~199 µs |
| Large commit | 100 files, 5000 lines | ~679 µs |
| Very large commit | 400 files, 40000 lines | ~3.7 ms |

### Diff parsing

| Scale | Time |
|---|---|
| 1 file, 10 lines | ~1.4 µs |
| 10 files, 50 lines each | ~37 µs |
| 100 files, 50 lines each | ~435 µs |

### Keyword matching

| Method | Time | Ratio |
|---|---|---|
| Aho-corasick | ~44 µs | 1x |
| Naive contains | ~4.2 ms | ~96x slower |

### Key optimizations

- Aho-corasick automaton for single-pass keyword matching across all rules
- Regex compilation happens once at startup
- Only rules whose keywords match are evaluated (skipping most regex checks)
- Byte-level processing (`&[u8]`) avoids UTF-8 conversion overhead
- Parallel file processing with rayon for working tree audits and history scans
- Early exit on binary files and allowlisted paths
- History audit deduplicates findings and only resolves branches for commits with secrets

Run benchmarks:

```sh
cargo bench
```

## Bypassing the hook

In rare cases where you need to commit despite a finding (e.g., a known false positive):

```sh
git commit --no-verify
```

The recommended approach is to add an allowlist entry to `.sekretbarilo.toml` instead.

## License

MIT
