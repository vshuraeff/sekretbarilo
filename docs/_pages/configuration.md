---
layout: default
title: Configuration
nav_order: 3
---

# Configuration
{: .no_toc }

sekretbarilo uses hierarchical `.sekretbarilo.toml` configuration files to customize scanning behavior, add allowlists, define custom detection rules, and configure audit options. Configuration is entirely optional - the tool works out of the box with sensible defaults.

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Hierarchical Config Discovery

When you run `sekretbarilo`, it searches for configuration files in multiple locations and merges them together. This allows you to set organization-wide defaults at the user or system level and override them per-project.

### Discovery Order

Config files are searched in this order (lowest to highest priority):

| Priority | Location | Description |
|----------|----------|-------------|
| 1 (lowest) | `/etc/sekretbarilo.toml` | System-wide defaults (all users) |
| 2 | `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` | User-level defaults (falls back to `~/.config/sekretbarilo/sekretbarilo.toml` if `XDG_CONFIG_HOME` is not set) |
| 3 | `~/.sekretbarilo.toml` | Home directory config (legacy location) |
| 4..N | Parent directories from `$HOME` down to current directory | Hierarchical project configs (walks from home down to repo root) |
| N+1 (highest) | `.sekretbarilo.toml` in current directory | Project-specific config (highest priority) |

All found config files are loaded and merged automatically. This hierarchy allows you to define:
- Organization-wide rules and allowlists in `/etc/sekretbarilo.toml` or `~/.config/sekretbarilo/sekretbarilo.toml`
- Per-organization or per-team overrides in intermediate directories (e.g., `~/work/.sekretbarilo.toml`)
- Project-specific rules and allowlists in `.sekretbarilo.toml` at the repo root

### Example Directory Structure

```
/etc/sekretbarilo.toml                         # priority 1 (system-wide)
~/.config/sekretbarilo/sekretbarilo.toml       # priority 2 (user-level)
~/.sekretbarilo.toml                           # priority 3 (legacy home)
~/work/acme/.sekretbarilo.toml                 # priority 4 (org-level)
~/work/acme/project-x/.sekretbarilo.toml       # priority 5 (project-level, highest)
```

When running `sekretbarilo` from `~/work/acme/project-x/`, all five configs will be loaded and merged in priority order.

---

## Merge Strategy

sekretbarilo merges all discovered config files using the following rules:

### Scalars

**Highest priority wins.** The most local (closest to current directory) config value takes precedence.

Example: if `entropy_threshold` is set to `3.0` in the user config and `4.5` in the project config, the effective value is `4.5`.

### Lists

**Concatenated and deduplicated.** All list entries from all config levels are combined, with duplicates removed.

Example: if user config has `paths = ["vendor/.*"]` and project config has `paths = ["test/.*"]`, the effective list is `["vendor/.*", "test/.*"]`.

### Rules

**Merged by `id`.** If the same rule `id` appears at multiple levels, the most local (highest priority) definition wins. Rules with unique IDs from all levels are combined.

Example:
- User config defines `aws-access-key-id` rule with `entropy_threshold = 3.0`
- Project config defines `aws-access-key-id` rule with `entropy_threshold = 4.0` (overrides)
- Project config also defines `custom-internal-token` rule (appends)
- Effective ruleset: `aws-access-key-id` with threshold `4.0` + `custom-internal-token` + all other rules from user config

---

## Config Sections

A `.sekretbarilo.toml` file can contain the following sections:

### `[settings]`

Global settings that affect scanning behavior.

```toml
[settings]
# minimum shannon entropy for tier 2/3 rules (default: none, uses per-rule thresholds)
# valid range: 0.0 - 8.0 (typical values: 3.0 - 4.5)
# lower values = more sensitive (more potential secrets detected)
# higher values = less sensitive (fewer false positives)
entropy_threshold = 3.5

# report public keys (PEM, PGP, OpenSSH) as findings (default: false)
# when false, public key material is suppressed to reduce noise
detect_public_keys = false
```

**Notes:**
- `entropy_threshold` is optional. If not set, each rule uses its own built-in threshold (if any).
- Setting a global threshold here overrides all per-rule thresholds.
- Tier 1 rules (prefix-based) don't use entropy checks, so this setting doesn't affect them.
- Use this to tune sensitivity globally without modifying individual rules.
- `detect_public_keys` enables 3 gated rules (`pem-public-key`, `pgp-public-key-block`, `openssh-public-key`). When disabled (default), lines inside public key blocks are also suppressed to avoid false positives from base64 content. Can be overridden with `--detect-public-keys` CLI flag.

### `[allowlist]`

Global allowlists that skip findings based on file path or secret value.

```toml
[allowlist]
# file path patterns to skip (regex, matched against full relative path)
paths = [
  "test/fixtures/.*",           # skip all files in test/fixtures/
  "docs/examples/.*",            # skip documentation examples
  "vendor/.*",                   # skip vendored dependencies
  ".*\\.min\\.js$",              # skip minified javascript
]

# additional stopwords (findings containing these strings are skipped)
# these are merged with the built-in default stopwords
stopwords = [
  "my-project-specific-safe-token",
  "known-test-api-key-12345",
  "company-safe-prefix",
]
```

**Default stopwords** (always active, even if not listed):
- `example`, `test`, `sample`, `placeholder`, `dummy`, `changeme`, `fake`, `mock`, `todo`, `fixme`, `xxx`, `lorem`, `default`, `replace_me`, `insert_here`, `your_`, `my_`

**Default allowlisted paths** (built-in, automatically skipped):
- Binary files: `.png`, `.jpg`, `.gif`, `.pdf`, `.exe`, `.dll`, `.zip`, `.gz`, `.tar`, `.mp3`, `.mp4`, etc.
- Generated files: `.min.js`, `.min.css`, `.map`
- Lock files: `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`, `pnpm-lock.yaml`, etc.
- Vendor directories: `node_modules/`, `vendor/`, `.bundle/`, `bower_components/`, `__pycache__/`, `.git/`

### `[[allowlist.rules]]`

Per-rule allowlist overrides. These allow you to skip findings for specific rules based on value pattern or file path.

```toml
# skip known safe AWS key (official example key from AWS docs)
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = []

# skip generic-api-key findings in test files
[[allowlist.rules]]
id = "generic-api-key"
regexes = []
paths = ["test/.*", "spec/.*"]

# skip specific known-safe JWT token value
[[allowlist.rules]]
id = "jwt-token"
regexes = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\..*"]  # example jwt header
paths = []

# combine value and path allowlists
[[allowlist.rules]]
id = "github-personal-access-token"
regexes = ["ghp_[0-9a-zA-Z]{36}"]                          # skip tokens matching this pattern
paths = ["fixtures/github/.*", "testdata/.*"]              # skip findings in these paths
```

**Notes:**
- `id` must match an existing rule ID (built-in or custom).
- `regexes` are matched against the captured secret value (not the whole line).
- `paths` are matched against the file path.
- Both `regexes` and `paths` can be empty (use only one or both).
- Per-rule allowlists from config files are **merged** with allowlists defined in the rule itself (from `rules.toml`).

### `[audit]`

Audit-specific configuration (only affects `sekretbarilo audit` command).

```toml
[audit]
# include untracked ignored files in audit (default: false)
# when true, files matched by .gitignore are also scanned
include_ignored = false

# additional patterns to exclude from audit (regex, matched against file path)
# these are merged with the global allowlist.paths
exclude_patterns = [
  "^vendor/",
  "^build/",
  "^dist/",
  "^target/",
]

# patterns to force-include during audit (regex, matched against file path)
# these override exclude_patterns (if a file matches both, it's included)
include_patterns = [
  "\\.rs$",      # force-include all rust files
  "\\.toml$",    # force-include all toml files
]
```

**Notes:**
- `include_ignored = true` includes files matched by `.gitignore` (useful for scanning generated files, build artifacts, etc.).
- `exclude_patterns` is useful for skipping large directories that don't contain sensitive data.
- `include_patterns` takes precedence over `exclude_patterns`.
- Patterns are matched using regex (not glob).

### `[[rules]]`

Custom detection rules. These are merged with the 109 built-in rules.

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
```

**Required fields:**
- `id` - unique identifier for the rule (used for allowlist overrides and merging)
- `description` - human-readable description (shown in findings)
- `regex` - regex pattern to match secrets (must have at least one capture group)
- `secret_group` - which capture group contains the secret (1-indexed, typically `1`)
- `keywords` - list of lowercase keywords for aho-corasick pre-filter (improves performance by only running regex on matching lines)

**Optional fields:**

```toml
[[rules]]
id = "custom-high-entropy-token"
description = "Custom high-entropy token"
regex = "(?i)custom[-_]?token\\s*[=:]\\s*['\"]([^'\"]{20,})['\"]"
secret_group = 1
keywords = ["custom_token", "custom-token"]
entropy_threshold = 4.0    # require minimum shannon entropy of 4.0 for this rule

[rules.allowlist]
regexes = ["CUSTOM_SAFE_TOKEN_.*"]   # skip values matching this pattern
paths = ["test/.*"]                   # skip findings in test files
```

- `entropy_threshold` - minimum Shannon entropy for the captured secret (0.0 - 8.0). If not set, global `settings.entropy_threshold` is used (if set).
- `allowlist.regexes` - value patterns to skip (merged with `[[allowlist.rules]]` overrides)
- `allowlist.paths` - file path patterns to skip (merged with `[[allowlist.rules]]` overrides)

---

## Practical Examples

### Example 1: Organization-Wide Config

**File:** `/etc/sekretbarilo.toml` (system-wide) or `~/.config/sekretbarilo/sekretbarilo.toml` (user-level)

```toml
# organization-wide defaults for acme corp

[settings]
entropy_threshold = 3.0

[allowlist]
# skip known safe example tokens from acme internal docs
stopwords = [
  "acme-safe-example-token",
  "acme-test-key-12345",
]

# skip vendor directories and generated files
paths = [
  "vendor/.*",
  "node_modules/.*",
  "dist/.*",
  "build/.*",
]

# define custom rule for acme internal tokens
[[rules]]
id = "acme-internal-token"
description = "Acme internal service token"
regex = "(ACME_[A-Z0-9]{40})"
secret_group = 1
keywords = ["acme_"]
entropy_threshold = 3.5
```

### Example 2: Project-Specific Config

**File:** `.sekretbarilo.toml` (in repo root)

```toml
# project-specific config for project-x

[settings]
# override org-wide threshold for this project
entropy_threshold = 4.5

[allowlist]
# add project-specific safe tokens
stopwords = [
  "project-x-test-api-key",
]

# skip test fixtures and documentation
paths = [
  "test/fixtures/.*",
  "docs/examples/.*",
]

# allowlist known false positives
[[allowlist.rules]]
id = "aws-access-key-id"
# skip the official aws example key
regexes = ["AKIAIOSFODNN7EXAMPLE"]

[[allowlist.rules]]
id = "generic-api-key"
# skip generic-api-key findings in test files
paths = ["test/.*", "spec/.*"]

# define project-specific detection rule
[[rules]]
id = "project-x-session-token"
description = "Project-X session token"
regex = "(PX_SESSION_[a-f0-9]{64})"
secret_group = 1
keywords = ["px_session_"]
```

### Example 3: Multi-Level Merge

**System config** (`/etc/sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 3.0

[allowlist]
stopwords = ["company-safe-token"]
paths = ["vendor/.*"]
```

**User config** (`~/.config/sekretbarilo/sekretbarilo.toml`):
```toml
[allowlist]
paths = ["node_modules/.*"]
stopwords = ["my-test-token"]
```

**Project config** (`.sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 4.0

[allowlist]
stopwords = ["project-specific-token"]
paths = ["test/.*"]
```

**Effective merged config:**
```toml
# entropy_threshold = 4.0 (project wins, highest priority)

# allowlist.stopwords = [
#   "company-safe-token",     # from system
#   "my-test-token",          # from user
#   "project-specific-token", # from project
# ]

# allowlist.paths = [
#   "vendor/.*",              # from system
#   "node_modules/.*",        # from user
#   "test/.*",                # from project
# ]
```

### Example 4: Custom Rule for Internal Tokens

```toml
# detect company-specific tokens with custom prefix

[[rules]]
id = "mycompany-api-token"
description = "MyCompany API token"
regex = "(MYCO_API_[A-Z0-9_]{32,64})"
secret_group = 1
keywords = ["myco_api_"]
entropy_threshold = 3.5

[rules.allowlist]
# skip known safe test tokens
regexes = [
  "MYCO_API_TEST_.*",
  "MYCO_API_EXAMPLE_.*",
]
# skip findings in test files
paths = [
  "test/.*",
  "spec/.*",
  "fixtures/.*",
]
```

### Example 5: Allowlisting Known False Positives

```toml
# scenario: a project uses git commit hashes that look like secrets
# (they're already filtered by default, but this shows the pattern)

# skip specific known-safe jwt token in documentation
[[allowlist.rules]]
id = "jwt-token"
regexes = [
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\\..*",
]

# skip generic-api-key findings in specific files
[[allowlist.rules]]
id = "generic-api-key"
paths = [
  "docs/api-examples\\.md",
  "README\\.md",
  "CONTRIBUTING\\.md",
]

# skip aws keys in terraform examples
[[allowlist.rules]]
id = "aws-access-key-id"
paths = ["examples/terraform/.*"]
```

### Example 6: Using `--config` Flag

The `--config <path>` flag skips hierarchical discovery entirely and loads only the specified config file(s).

```sh
# use a single custom config file (no auto-discovery)
sekretbarilo scan --config my-rules.toml

# merge two config files (b.toml overrides a.toml for scalars)
sekretbarilo audit --config a.toml --config b.toml

# use project config + ci overrides
sekretbarilo scan --config .sekretbarilo.toml --config ci-overrides.toml
```

**ci-overrides.toml** (stricter settings for ci/cd):
```toml
[settings]
# stricter entropy threshold for ci
entropy_threshold = 4.5

[audit]
# include ignored files in ci audit
include_ignored = true
```

### Example 7: Using `--no-defaults`

The `--no-defaults` flag skips all built-in rules and uses only custom rules from your config file(s).

```sh
# scan with only custom rules (no built-in aws, github, etc. rules)
sekretbarilo scan --no-defaults --config my-custom-rules.toml
```

**my-custom-rules.toml:**
```toml
# only detect company-specific secrets

[[rules]]
id = "acme-token"
description = "Acme service token"
regex = "(ACME_[A-Z0-9]{32})"
secret_group = 1
keywords = ["acme_"]

[[rules]]
id = "acme-api-key"
description = "Acme API key"
regex = "(?i)acme[-_]?api[-_]?key\\s*[=:]\\s*['\"]([^'\"]{20,})['\"]"
secret_group = 1
keywords = ["acme_api", "acme-api"]
entropy_threshold = 4.0
```

### Example 8: CI/CD Configuration

**Scenario:** You want to run sekretbarilo in ci/cd with stricter settings than local development.

**.github/workflows/secrets-scan.yml:**
```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install sekretbarilo
        run: cargo install --git https://github.com/vshuraeff/sekretbarilo
      - name: Scan for secrets
        run: |
          # use ci-specific config with stricter settings
          sekretbarilo audit --config .sekretbarilo.toml --config .sekretbarilo-ci.toml
```

**.sekretbarilo-ci.toml** (ci overrides):
```toml
[settings]
# stricter entropy threshold for ci
entropy_threshold = 4.5

[audit]
# include ignored files in ci (scan everything)
include_ignored = true
# no exclude patterns in ci (scan all files)
exclude_patterns = []

[allowlist]
# remove test-specific stopwords in ci (be more strict)
stopwords = []
```

This setup uses the project config (`.sekretbarilo.toml`) as a base and applies ci-specific overrides from `.sekretbarilo-ci.toml`, resulting in stricter scanning in ci than in local development.

---

## Skipping Hierarchical Discovery

By default, sekretbarilo discovers and merges all config files in the hierarchy. To skip this behavior and use only explicit config files:

```sh
# use only this config file (no auto-discovery)
sekretbarilo scan --config my-config.toml

# merge multiple explicit config files (order matters: last wins for scalars)
sekretbarilo scan --config base.toml --config overrides.toml
```

When `--config` is provided, hierarchical discovery is completely skipped. Only the specified file(s) are loaded and merged.

---

## CLI Overrides

You can override config settings via command-line flags (these take precedence over all config files):

```sh
# override global entropy threshold
sekretbarilo scan --entropy-threshold 4.5

# add stopwords
sekretbarilo scan --stopword my-known-safe-token --stopword another-safe-value

# add allowlist paths
sekretbarilo audit --allowlist-path "^vendor/" --allowlist-path "^build/"

# combine config file with cli overrides
sekretbarilo scan --config .sekretbarilo.toml --stopword test-override
```

**Available CLI flags:**
- `--config <path>` - explicit config file (repeatable, skips auto-discovery)
- `--no-defaults` - skip built-in rules (use only custom rules from config)
- `--entropy-threshold <n>` - override global entropy threshold
- `--stopword <word>` - add a stopword (repeatable)
- `--allowlist-path <pattern>` - add a path pattern to allowlist (repeatable)
- `--exclude-pattern <pattern>` - add an audit exclude pattern (repeatable, audit only)
- `--include-pattern <pattern>` - add an audit include pattern (repeatable, audit only)
- `--detect-public-keys` - report public keys as findings (default: suppressed)

See the [CLI reference](../README.md#cli-flags) for a complete list of available flags.

---

## Config Validation

sekretbarilo validates config files at load time:

- **Missing files:** If a discovered config file doesn't exist, it's silently skipped (no error).
- **Empty files:** Empty config files are silently skipped.
- **Parse errors:** Invalid toml syntax logs a warning to stderr and skips the file (non-fatal).
- **Invalid regex:** Invalid regex patterns in rules or allowlists cause an error (fatal).
- **Missing required fields:** Rules without required fields (`id`, `description`, `regex`, `secret_group`, `keywords`) cause an error (fatal).

**Example validation error:**
```
[ERROR] failed to compile rule 'custom-token': regex parse error: unclosed group
```

To validate your config without running a scan:

```sh
# validate config by attempting to load it
sekretbarilo audit --config .sekretbarilo.toml --help
```

If there are parse errors, they'll be printed to stderr before the help message appears.

---

## Tips and Best Practices

### Start Simple

Begin with a minimal config and add rules/allowlists as needed:

```toml
# minimal starting point
[allowlist]
paths = ["vendor/.*", "node_modules/.*"]
```

### Use Comments

toml supports comments - use them to document why specific allowlists or rules exist:

```toml
# skip the official aws example key from their documentation
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
```

### Test Your Rules

When adding custom rules, test them on your codebase to check for false positives:

```sh
# test a new rule by adding it to a temporary config
sekretbarilo audit --config test-rules.toml
```

### Use Per-Rule Allowlists

Instead of global allowlists, use per-rule allowlists when possible (more precise, less risk of skipping actual secrets):

```toml
# prefer this (per-rule)
[[allowlist.rules]]
id = "jwt-token"
paths = ["docs/.*"]

# over this (global, affects all rules)
[allowlist]
paths = ["docs/.*"]
```

### Tune Entropy Thresholds

If you're getting too many false positives from tier 2/3 rules, increase the entropy threshold:

```toml
[settings]
# default is rule-specific (typically 3.0-4.0)
# increase to 4.5 to reduce false positives
entropy_threshold = 4.5
```

Typical values:
- `3.0` - sensitive (more findings, more false positives)
- `3.5` - balanced (default for most tier 2 rules)
- `4.0` - strict (fewer findings, fewer false positives)
- `4.5` - very strict (catch-all rules only)

### Use Multiple Configs for Different Contexts

Create separate config files for different scanning contexts:

```sh
# local development (permissive)
sekretbarilo scan

# ci/cd (strict)
sekretbarilo audit --config .sekretbarilo.toml --config .sekretbarilo-ci.toml

# pre-commit (balanced)
sekretbarilo scan --config .sekretbarilo.toml
```

---

## See Also

- [Getting Started]({{ '/getting-started/' | relative_url }}) - installation and quick start
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - complete list of command-line flags
- [Rules Reference]({{ '/rules-reference/' | relative_url }}) - default detection rules
