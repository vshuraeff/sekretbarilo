# sekretbarilo

High-performance Rust git pre-commit hook that scans staged changes for secrets, API keys, and credentials before they reach your repository.

*sekretbarilo* means "secret keeper" in Esperanto.

## Features

- **Fast**: typical commits scan in ~2.5 µs; even 400-file diffs complete in under 4 ms
- **Three-tier rule system**: 42 built-in rules organized by precision (prefix-based, context-aware, catch-all)
- **Low false positives**: Shannon entropy analysis, stopword filtering, hash detection, variable reference detection
- **Audit mode**: scan all tracked files or full git history for secrets (`sekretbarilo audit`)
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
git clone https://github.com/your-org/sekretbarilo.git
cd sekretbarilo
cargo build --release
# binary is at target/release/sekretbarilo
```

## Quick start

Install the git pre-commit hook in your repository:

```sh
cd your-project
sekretbarilo install
```

This creates (or appends to) `.git/hooks/pre-commit`. From now on, every `git commit` automatically scans staged changes for secrets.

To manually scan staged changes:

```sh
sekretbarilo scan
```

Or simply:

```sh
sekretbarilo
```

## Audit mode

Scan all tracked files in the working tree for secrets:

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

Audit findings use `[AUDIT]` prefix and the same exit codes as scan mode.

History audit output includes author email and branch containment per commit:

```
  commit: abc12345 (John Doe <john@example.com>, 2024-01-15T10:30:00+00:00)
    branches: main, feature/auth
    file: config.py
    line: 7
    rule: aws-access-key-id
    match: AK**************QA
```

### Audit configuration

```toml
[audit]
include_ignored = false                  # include untracked ignored files (default: false)
exclude_patterns = ["^vendor/", "^build/"]  # regex patterns to exclude from audit
include_patterns = ["\\.rs$"]            # regex patterns to force-include (overrides excludes)
```

## How it works

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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found, commit allowed |
| 1 | Secrets detected, commit blocked |
| 2 | Internal error (config parse failure, git not found, etc.) |

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

Secret values are always masked - only the first 2 and last 2 characters are shown.

## Configuration

Create a `.sekretbarilo.toml` file in your repository root to customize behavior.

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
| openai-api-key | OpenAI key (sk-...T3BlbkFJ...) |

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

sekretbarilo is designed for speed — a pre-commit hook should never slow down your workflow.

| scenario | scale | time |
|---|---|---|
| typical commit | 1 file, 10 lines | ~2.5 µs |
| medium commit | 10 files, 500 lines | ~170 µs |
| large commit | 100 files, 5000 lines | ~680 µs |
| very large commit | 400 files, 40000 lines | ~3.7 ms |

Throughput scales sub-linearly — the aho-corasick pre-filter skips clean lines, reaching ~10.7M lines/sec on large diffs. Aho-corasick keyword matching is **~96x faster** than naive string search.

Key optimizations:
- Aho-corasick automaton for single-pass keyword matching across all rules
- Regex compilation happens once at startup
- Only rules whose keywords match are evaluated (skipping most regex checks)
- Byte-level processing (`&[u8]`) avoids UTF-8 conversion overhead
- Parallel file processing with rayon for large diffs
- Early exit on binary files and allowlisted paths

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
