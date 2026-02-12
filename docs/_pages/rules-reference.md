---
layout: default
title: Rules Reference
nav_order: 6
---

# Rules Reference

sekretbarilo is a high-performance secret scanner with **43 built-in detection rules** organized by precision tier. This reference describes each rule, the three-tier detection system, and how to write custom rules.

## Three-Tier Detection System

sekretbarilo organizes rules into three tiers based on their false positive risk. This tiered approach allows aggressive scanning while keeping false positives under control.

### Tier 1: Prefix-Based Rules (Very Low False Positives)

**Characteristics:**
- Match distinctive, service-specific prefixes (e.g., `AKIA`, `ghp_`, `sk-ant-`)
- No entropy threshold required
- No keyword context needed beyond the prefix itself
- Extremely low false positive rate

**Why they work:** Many services use unique prefixes that are virtually impossible to encounter by accident. When sekretbarilo sees `AKIA` followed by 16 alphanumeric characters, it's almost certainly an AWS access key.

**Stopword filtering:** Tier 1 rules only check for placeholder patterns like `XXXX...` to avoid flagging format examples. They skip word-based stopwords because tokens like `sk_test_` inherently contain "test" but are still real secrets.

**27 rules in this tier**

### Tier 2: Context-Aware Rules (Medium False Positives)

**Characteristics:**
- Require keyword context (e.g., `password=`, `postgres://`)
- Use entropy thresholds to validate randomness
- Apply full stopword filtering
- Password rules use strength heuristics instead of entropy

**Why they're needed:** Not all secrets have unique prefixes. Database passwords, API keys, and bearer tokens need additional validation through context keywords and entropy checks to distinguish them from regular strings.

**Password handling:** Rules like `generic-password-assignment` and `password-in-url` use a password strength heuristic that only flags strong passwords. Weak passwords like "password123" are intentionally allowed through to reduce noise.

**15 rules in this tier**

### Tier 3: Catch-All Rules (Highest False Positive Risk)

**Characteristics:**
- Generic patterns with high entropy requirements
- Broad keyword matching (`api_key`, `apikey`, etc.)
- Highest entropy threshold (4.0) to minimize false positives

**Why it exists:** The catch-all tier detects custom API keys that don't match any specific service pattern. It trades some false positives for comprehensive coverage.

**1 rule in this tier**

## Tier 1: Prefix-Based Rules

These rules detect secrets with distinctive service-specific prefixes:

| Rule ID | Description | Pattern Example | Minimum Length |
|---------|-------------|-----------------|----------------|
| `aws-access-key-id` | AWS access key ID | `AKIA` + 16 chars | 20 |
| `github-personal-access-token` | GitHub personal access token | `ghp_` + 36+ chars | 40+ |
| `github-oauth-token` | GitHub OAuth access token | `gho_` + 36+ chars | 40+ |
| `github-app-token` | GitHub app installation token | `ghs_` + 36+ chars | 40+ |
| `github-refresh-token` | GitHub refresh token | `ghr_` + 36+ chars | 40+ |
| `github-fine-grained-pat` | GitHub fine-grained PAT | `github_pat_` + 82+ chars | 93+ |
| `gitlab-personal-access-token` | GitLab personal access token | `glpat-` + 20+ chars | 26+ |
| `slack-bot-token` | Slack bot token | `xoxb-` + 24+ chars | 29+ |
| `slack-user-token` | Slack user token | `xoxp-` + 24+ chars | 29+ |
| `slack-app-token` | Slack app-level token | `xapp-` + 24+ chars | 29+ |
| `stripe-secret-key-live` | Stripe live secret key | `sk_live_` + 24+ chars | 32+ |
| `stripe-secret-key-test` | Stripe test secret key | `sk_test_` + 24+ chars | 32+ |
| `stripe-publishable-key-live` | Stripe live publishable key | `pk_live_` + 24+ chars | 32+ |
| `sendgrid-api-key` | SendGrid API key | `SG.` + 22+ `.` + 22+ chars | 47+ |
| `pem-private-key` | PEM private key block | `-----BEGIN...PRIVATE KEY-----` | 26+ |
| `jwt-token` | JWT token (3 base64 segments) | `eyJ...eyJ...` | 30+ |
| `digitalocean-personal-access-token` | DigitalOcean personal access token | `dop_v1_` + 64 hex chars | 71 |
| `digitalocean-oauth-token` | DigitalOcean OAuth token | `doo_v1_` + 64 hex chars | 71 |
| `digitalocean-refresh-token` | DigitalOcean refresh token | `dor_v1_` + 64 hex chars | 71 |
| `npm-access-token` | npm access token | `npm_` + 36+ chars | 40+ |
| `pypi-api-token` | PyPI API token | `pypi-` + 16+ chars | 21+ |
| `docker-hub-pat` | Docker Hub personal access token | `dckr_pat_` + 24+ chars | 33+ |
| `new-relic-api-key` | New Relic API key | `NRAK-` + 27 chars | 32 |
| `terraform-cloud-token` | Terraform Cloud/Enterprise token | 14 chars + `.atlasv1.` + 60+ chars | 83+ |
| `anthropic-api-key` | Anthropic API key | `sk-ant-` + 20+ chars | 27+ |
| `openai-api-key-legacy` | OpenAI API key (legacy format) | `sk-...T3BlbkFJ...` | 40+ |
| `openai-api-key` | OpenAI API key (project format) | `sk-proj-` + 20+ chars | 29+ |

### Built-in Allowlists

Some Tier 1 rules have built-in allowlists for common documentation examples:

- **aws-access-key-id:** Skips `AKIAIOSFODNN7EXAMPLE` (AWS documentation example)

## Tier 2: Context-Aware Rules

These rules require keyword context and apply additional validation:

| Rule ID | Description | Keywords | Entropy Threshold | Notes |
|---------|-------------|----------|-------------------|-------|
| `aws-secret-access-key` | AWS secret access key | `aws_secret`, `secret_access_key` | 3.5 | 40 base64 chars |
| `database-connection-string-postgres` | PostgreSQL connection with credentials | `postgres://`, `postgresql://` | None | Full stopword filter |
| `database-connection-string-mysql` | MySQL connection with credentials | `mysql://` | None | Full stopword filter |
| `database-connection-string-mongodb` | MongoDB connection with credentials | `mongodb://`, `mongodb+srv://` | None | Full stopword filter |
| `redis-connection-string` | Redis connection with password | `redis://` | None | Full stopword filter |
| `generic-password-assignment` | Password assignment in code | `password`, `passwd`, `pwd` | None | Strength heuristic |
| `generic-secret-assignment` | Secret assignment in code | `secret`, `secret_key`, `api_secret` | 3.5 | - |
| `password-in-url` | Password embedded in URL | `://` | None | Strength heuristic |
| `http-bearer-token` | HTTP bearer token | `bearer`, `authorization` | 3.5 | 20+ chars |
| `http-basic-auth` | HTTP basic auth header | `basic`, `authorization` | 3.0 | Base64 format |
| `webhook-url-with-token` | Slack webhook URL with token | `hooks.slack.com` | None | Full URL match |
| `azure-storage-account-key` | Azure storage account key | `accountkey` | None | 88 base64 chars |
| `cloudflare-api-key` | Cloudflare API key | `cloudflare`, `cf_api`, `cf-api` | 3.0 | 37 hex chars |
| `datadog-api-key` | Datadog API key | `datadog`, `dd_api`, `dd-api` | 3.0 | 32 hex chars |
| `heroku-api-key` | Heroku API key | `heroku` | 3.0 | 36 UUID format |

### Password Rules

Two rules use a special **password strength heuristic** instead of entropy:

- `generic-password-assignment`
- `password-in-url`

**How it works:** These rules only flag passwords that meet all of these criteria:
- At least 8 characters long
- Contains uppercase letters
- Contains lowercase letters
- Contains digits

This approach reduces false positives by allowing weak passwords like "password123" or "changeme" while catching real secrets like "MyS3cur3P@ssw0rd".

### Connection String Rules

Four rules extract credentials from connection strings:
- `database-connection-string-postgres`
- `database-connection-string-mysql`
- `database-connection-string-mongodb`
- `redis-connection-string`

These rules apply **full stopword filtering** to catch placeholder values like `postgres://user:example@localhost` but use **standard entropy checks** rather than the password strength heuristic.

## Tier 3: Catch-All

| Rule ID | Description | Keywords | Entropy Threshold |
|---------|-------------|----------|-------------------|
| `generic-api-key` | Generic API key assignment | `api_key`, `apikey`, `api-key`, `api_token`, `api-token` | 4.0 |

This rule has the highest entropy threshold (4.0) to minimize false positives while catching custom API keys that don't match any specific service pattern.

## False Positive Reduction Techniques

sekretbarilo uses multiple layers of filtering to reduce false positives while maintaining high detection accuracy:

### 1. Shannon Entropy Thresholds

**What it is:** Shannon entropy measures the randomness of a string. Real secrets typically have high entropy (3.0-4.0+), while placeholder text has low entropy.

**How it works:**
- Each rule can specify a minimum entropy threshold
- Secrets below the threshold are filtered out
- Documentation files get a +1.0 entropy bonus (they often contain example secrets)

**Example:**
- `"password123"` has entropy ~2.7 (would be filtered at 3.0 threshold)
- `"8f3a9b2c1d5e6f7a"` has entropy ~3.9 (would pass)

### 2. Stopwords

**Default stopwords:** sekretbarilo filters secrets containing these placeholder words:

`example`, `test`, `sample`, `placeholder`, `dummy`, `changeme`, `fake`, `mock`, `todo`, `fixme`, `xxx`, `lorem`, `default`, `replace_me`, `insert_here`, `your_`, `my_`, `<your`

**How it works:**
- Stopwords are matched at word boundaries (won't filter "attestation" when checking "test")
- Special case: `xxx` matches any run of 3+ identical X characters (e.g., `XXXX...`)
- Tier 1 rules only check for `xxx` placeholder patterns
- Tier 2+ rules apply full stopword filtering

**Why it matters:** Prevents flagging common documentation examples like:
```python
api_key = "your_key_here"
password = "changeme"
token = "replace_me_with_real_token"
```

### 3. Hash Detection

**What it detects:**
- SHA-1 hashes (40 hex chars)
- SHA-256 hashes (64 hex chars)
- MD5 hashes (32 hex chars)
- Git commit hashes (with context keywords: `commit`, `sha`, `hash`, `ref`)

**How it works:** If a captured secret matches a hash format, it's filtered out. Git commit hashes require additional context keywords to avoid false negatives.

**Example patterns filtered:**
```
commit abc123def456... # git commit hash
sha256: 4a5b6c7d... # file checksum
hash = "e3b0c44298..." # content hash
```

### 4. Variable Reference Detection

**What it detects:** Common environment variable reference patterns across multiple languages:

**Shell/Unix:**
- `$VAR`
- `${VAR}`
- `%VAR%` (Windows)

**Template engines:**
- `{{var}}`
- `{{ var }}`

**Programming languages:**
- JavaScript: `process.env.VAR`
- Python: `os.environ["VAR"]`, `os.environ.get("VAR")`, `os.getenv("VAR")`
- Java: `System.getenv("VAR")`
- Rust: `env::var("VAR")`, `std::env::var("VAR")`
- Go: `os.Getenv("VAR")`

**Example patterns filtered:**
```python
password = os.environ["DB_PASSWORD"]  # not a secret, just a reference
token = process.env.API_TOKEN  # filtered
api_key = $API_KEY  # filtered
```

### 5. Documentation Awareness

**What it does:** Files identified as documentation get a **+1.0 entropy bonus** added to all rule thresholds, making it less likely to flag example secrets in docs.

**Documentation files:**
- **Extensions:** `.md`, `.rst`, `.adoc`
- **Names:** Files starting with `readme`, `changelog`, `contributing`, `license` (case-insensitive)
- **Directories:** Files in `docs/`, `doc/`, `documentation/`, `wiki/`

**Example:** A rule with entropy threshold 3.5 becomes 4.5 for markdown files, allowing more lenient validation for example code blocks.

### 6. Path Allowlists

**Default skipped paths:**

**Binary files:**
`.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.ico`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.otf`, `.pdf`, `.exe`, `.dll`, `.so`, `.dylib`, `.zip`, `.gz`, `.tar`, `.bz2`, `.xz`, `.7z`, `.rar`, `.mp3`, `.mp4`, `.avi`, `.mov`, `.wav`, `.ogg`, `.webp`, `.webm`

**Generated files:**
`package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`, `pnpm-lock.yaml`, `composer.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`

**Generated extensions:**
`.min.js`, `.min.css`, `.js.map`, `.css.map`

**Vendor directories:**
`node_modules/`, `vendor/`, `.bundle/`, `bower_components/`, `__pycache__/`, `.git/`

**Config file:**
`.sekretbarilo.toml` (always skipped to prevent infinite recursion)

### 7. Password Strength Heuristics

**Applies to:** `generic-password-assignment`, `password-in-url`

**Requirements:** Only flags passwords that meet all of:
- Minimum 8 characters
- Contains uppercase letters
- Contains lowercase letters
- Contains digits

**Why it helps:** Weak passwords like "password", "changeme", "admin123" are filtered out, reducing false positives in test code and examples. Only strong passwords (likely real credentials) are flagged.

## Custom Rules

You can add project-specific detection rules by creating a `.sekretbarilo.toml` file in your project root.

### Basic Custom Rule

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
```

**Field descriptions:**

- **`id`** (required): Unique identifier for the rule. Use lowercase with hyphens.
- **`description`** (required): Human-readable description of what this rule detects.
- **`regex`** (required): Regular expression pattern. Use raw strings in TOML for backslashes.
- **`secret_group`** (required): Which capture group contains the secret (usually 1). Use 0 for the entire match.
- **`keywords`** (required): List of case-insensitive keywords that must appear for this rule to trigger. used for aho-corasick pre-filtering.

### Custom Rule with Entropy Threshold

```toml
[[rules]]
id = "custom-api-key"
description = "Company API key"
regex = "(?i)(?:company_api_key|company_token)\\s*[=:]\\s*['\"]([^'\"]{16,})['\"]"
secret_group = 1
keywords = ["company_api_key", "company_token"]
entropy_threshold = 3.5
```

**`entropy_threshold`** (optional): Minimum Shannon entropy for the captured secret. Typical values:
- `3.0` - moderate randomness
- `3.5` - good randomness (default for many Tier 2 rules)
- `4.0` - high randomness (catch-all rules)

### Custom Rule with Per-Rule Allowlist

```toml
[[rules]]
id = "custom-database-password"
description = "Database password in config"
regex = "(?i)db_password\\s*=\\s*['\"]([^'\"]{8,})['\"]"
secret_group = 1
keywords = ["db_password"]
entropy_threshold = 3.0

[rules.allowlist]
regexes = ["test_password_.*", "example.*"]
paths = ["test/.*", "^fixtures/"]
```

**Per-rule allowlist fields:**

- **`regexes`** (optional): List of regex patterns to match against the captured secret value. If any pattern matches, the finding is skipped.
- **`paths`** (optional): List of file path regex patterns. If the file path matches any pattern, this rule is skipped for that file. Patterns are automatically anchored at the start.

### Example: Custom JWT Detection

```toml
[[rules]]
id = "custom-jwt-in-header"
description = "JWT token in Authorization header"
regex = "(?i)authorization:\\s*bearer\\s+(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})"
secret_group = 1
keywords = ["authorization", "bearer"]

[rules.allowlist]
paths = ["test/fixtures/.*"]
```

### Example: Custom Connection String

```toml
[[rules]]
id = "custom-redis-url"
description = "Redis URL with password"
regex = "redis://(?:[^:]+):([^@\\s'\"]{6,})@"
secret_group = 1
keywords = ["redis://"]
entropy_threshold = 3.0

[rules.allowlist]
regexes = ["password", "changeme", "secret"]
```

### Example: Custom API Key with Multiple Prefixes

```toml
[[rules]]
id = "custom-service-key"
description = "Custom service API key"
regex = "((?:sk|pk|ak)_(?:live|test)_[A-Za-z0-9]{24,})"
secret_group = 1
keywords = ["sk_live_", "sk_test_", "pk_live_", "pk_test_", "ak_live_", "ak_test_"]
```

### Regex Tips

1. **Use capture groups:** The `secret_group` field extracts the secret from the specified capture group.
   ```toml
   regex = "api_key\\s*=\\s*['\"]([^'\"]+)['\"]"
   secret_group = 1  # captures just the value, not the quotes or assignment
   ```

2. **Case-insensitive matching:** Use `(?i)` prefix for case-insensitive patterns.
   ```toml
   regex = "(?i)password\\s*=\\s*([^\\s]+)"  # matches "password", "PASSWORD", "Password"
   ```

3. **Escape backslashes:** TOML requires escaping backslashes in strings.
   ```toml
   regex = "\\s*"  # matches whitespace
   regex = "\\."   # matches literal dot
   ```

4. **Use raw strings:** Alternatively, use TOML raw strings to avoid double-escaping.
   ```toml
   regex = '(MYCO_[A-Z0-9]{32})'  # single quotes = raw string
   ```

5. **Anchor patterns carefully:** Most patterns should NOT be anchored (`^` or `$`) unless you want to match entire lines.
   ```toml
   regex = "api_key: ([a-z0-9]+)"  # good - matches anywhere in line
   regex = "^api_key: ([a-z0-9]+)$"  # bad - only matches if entire line is exactly this
   ```

### Keywords Requirements

**Why keywords are required:** sekretbarilo uses Aho-Corasick keyword pre-filtering for performance. Only lines containing at least one keyword trigger regex evaluation.

**Best practices:**
- Include all distinctive parts of your pattern
- Use lowercase (matching is case-insensitive)
- Include prefix variations if your pattern has them
- Don't use common words that appear everywhere (e.g., "key", "token" alone)

**Good keywords:**
```toml
keywords = ["myco_", "company_api"]  # distinctive, unlikely to appear elsewhere
```

**Bad keywords:**
```toml
keywords = ["key"]  # too generic, will trigger on many unrelated lines
```

## Overriding Built-in Rules

You can override any built-in rule by defining a rule with the same `id` in your project config. This is useful when you need to adjust a rule's behavior for your specific use case.

### Example: Adjust AWS Secret Key Entropy

```toml
# override built-in aws-secret-access-key rule with higher entropy threshold
[[rules]]
id = "aws-secret-access-key"
description = "AWS secret access key (custom threshold)"
regex = "(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\\s*[=:]\\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
secret_group = 1
keywords = ["aws_secret", "secret_access_key"]
entropy_threshold = 4.0  # higher than default 3.5
```

### Example: Disable a Rule

To completely disable a built-in rule, override it with an unmatchable pattern:

```toml
[[rules]]
id = "generic-api-key"
description = "Disabled generic API key rule"
regex = "(?-u:^$a)"  # regex that never matches
secret_group = 1
keywords = ["__never_match__"]
```

**Better approach:** Use path allowlists or the `--no-defaults` flag instead of disabling individual rules.

## Configuration Hierarchy

Rules are merged in this order (later configs override earlier ones):

1. **Built-in default rules** (43 rules embedded in the binary)
2. **System config** (`/etc/sekretbarilo.toml`)
3. **User config** (`~/.config/sekretbarilo.toml`)
4. **Project config** (`.sekretbarilo.toml` in current directory and parent directories)
5. **CLI overrides** (`--config`, `--stopword`, `--entropy-threshold`, `--exclude-pattern`)

**Merging behavior:**
- Rules with the same `id` replace earlier definitions completely
- Rules with unique `id`s are appended to the rule list
- Allowlists and stopwords are cumulative (merged, not replaced)

### Skip Built-in Rules

To use only custom rules without any built-in defaults:

```sh
sekretbarilo scan --no-defaults --config my-rules.toml
```

## Rule Testing

When writing custom rules, test them thoroughly to ensure they catch real secrets without generating false positives.

### Test Your Rule

1. **Create a test file with sample secrets:**
   ```sh
   echo 'api_key = "MYCO_ABC123XYZ789..."' > test-secret.txt
   ```

2. **Create a config with your rule:**
   ```sh
   cat > test-rules.toml << 'EOF'
   [[rules]]
   id = "test-custom-rule"
   description = "Test rule"
   regex = "(MYCO_[A-Z0-9]{32})"
   secret_group = 1
   keywords = ["myco_"]
   EOF
   ```

3. **Scan with your rule:**
   ```sh
   # test custom rule alone
   sekretbarilo scan test-secret.txt --no-defaults --config test-rules.toml

   # test custom rule with built-in rules
   sekretbarilo scan test-secret.txt --config test-rules.toml
   ```

4. **Verify the finding:**
   - Rule ID should match your `id` field
   - Matched value should be the secret (not the surrounding context)
   - Line number and file path should be correct

### Common Issues

**Rule never triggers:**
- Check that keywords match what's actually in the file (case-insensitive)
- Verify the regex pattern actually matches your test input
- Use `--debug` flag (if available) to see which rules are evaluated

**Rule captures wrong value:**
- Check your `secret_group` number
- Verify your capture groups in the regex
- Test the regex in a tool like https://regex101.com

**Too many false positives:**
- Add entropy threshold if you haven't already
- Add stopwords to filter placeholder values
- Use per-rule path allowlists to skip test directories
- Consider requiring more specific keywords

**Entropy filtering too aggressive:**
- Lower the entropy threshold (typical range: 3.0-4.0)
- Remember documentation files get +1.0 entropy bonus automatically

## Next Steps

- **[Configuration Guide]({{ '/configuration/' | relative_url }})** - learn about global allowlists, stopwords, and output formats
- **[CLI Reference]({{ '/cli-reference/' | relative_url }})** - explore command options for scanning and auditing
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** - integrate with AI coding tools like Claude Code
