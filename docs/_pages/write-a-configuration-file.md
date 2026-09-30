---
title: Write a configuration file
description: Adapt a ready-made .sekretbarilo.toml for an organisation, a project, custom tokens, known false positives, explicit config files and a stricter CI run.
section: how-to
---

Each example below is a configuration you can copy and adapt. The meaning of every key is in the [Configuration reference]({{ '/configuration/' | relative_url }}), and how several files combine is described under [Merge Strategy]({{ '/configuration/#merge-strategy' | relative_url }}).

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

For how this file combines with the organisation-wide one above it, see the [multi-level merge example]({{ '/configuration/#example-multi-level-merge' | relative_url }}).

### Example 3: Custom Rule for Internal Tokens

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

### Example 4: Allowlisting Known False Positives

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

### Example 5: Using `--config` Flag

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
# higher entropy threshold for ci (fewer low-entropy false positives)
entropy_threshold = 4.5

[audit]
# include ignored files in ci audit
include_ignored = true
```

### Example 6: Using `--no-defaults`

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

### Example 7: CI/CD Configuration

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
# higher entropy threshold for ci (fewer low-entropy false positives)
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

### Select rule classes

In 0.9.0, signature and contextual rules are enabled while the keywordless
heuristic rule is disabled. To include prefix-less random values in scans and
tool-output redaction, opt in explicitly:

```toml
[settings.rule_classes]
heuristic = true
```

For one rule, use `[settings.rules]` with `"generic-high-entropy-value" = true`
instead. Per-rule switches beat class switches, and nearer configuration layers
can reverse the same key. See [Configuration]({{ '/configuration/' | relative_url }})
for merge precedence and the deprecated test-path setting alias.

### Tune Entropy Thresholds

If you're getting too many false positives from rules with entropy thresholds, increase the entropy threshold:

```toml
[settings]
# default is rule-specific (typically 3.0-4.0)
# increase to 4.5 to reduce false positives
entropy_threshold = 4.5
```

Typical values (a higher threshold is less strict: it requires more entropy to
match, so it yields fewer findings):
- `3.0` - strict (more findings, more false positives)
- `3.5` - balanced (used by several contextual rules)
- `4.0` - permissive (fewer findings, fewer false positives)
- `4.5` - very permissive (raises the floor of any rule with an entropy threshold)

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

## Related pages

- [Configuration]({{ '/configuration/' | relative_url }}) for every section and key, discovery order and merge rules.
- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) for silencing one confirmed finding in the narrowest form.
- [CLI reference]({{ '/cli-reference/' | relative_url }}) for the flags that override configuration.
