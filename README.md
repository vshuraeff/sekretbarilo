# sekretbarilo

High-performance Rust git pre-commit hook that scans staged changes for secrets, API keys, and credentials before they reach your repository.

*sekretbarilo* means "secret keeper" in Esperanto.

## Features

- **Fast**: sub-millisecond scans on typical commits using aho-corasick multi-pattern matching
- **Three-tier rule system**: 42 built-in rules organized by precision (prefix-based, context-aware, catch-all)
- **Low false positives**: Shannon entropy analysis, stopword filtering, hash detection, variable reference detection
- **Configurable**: project-level `.sekretbarilo.toml` for allowlists, custom rules, and overrides
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

sekretbarilo is designed for speed - a pre-commit hook should never slow down your workflow.

- Typical commits (1-10 files, <100 changed lines): **< 1ms**
- Medium commits (10-50 files): **< 10ms**
- Large commits (several MB diff): **< 100ms**

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
