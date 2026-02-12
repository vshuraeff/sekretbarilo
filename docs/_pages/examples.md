---
layout: default
title: Examples
nav_order: 9
---

# Examples
{: .no_toc }

This page provides practical, real-world examples of using sekretbarilo in different scenarios. All examples are copy-paste friendly and ready to use.

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Basic Pre-Commit Workflow

The most common use case: protecting your commits from accidental secret leaks.

### Installing the hook

```sh
# navigate to your project
cd my-project

# install the pre-commit hook
sekretbarilo install pre-commit
```

Output:
```
[INFO] pre-commit hook installed at .git/hooks/pre-commit
```

### What happens when you commit a secret

```sh
# create a config file with an aws key
echo "AWS_KEY=AKIAIOSFODNN7EXAMPLE" > config.py

# try to commit it
git add config.py
git commit -m "add config"
```

sekretbarilo blocks the commit and shows:

```
[ERROR] secret detected in staged changes

  file: config.py
  line: 1
  rule: aws-access-key-id
  match: AK**************LE

commit blocked. 1 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

### Fixing the issue

```sh
# move the secret to environment variables
cat > config.py << 'EOF'
import os

AWS_KEY = os.environ.get("AWS_KEY")
if not AWS_KEY:
    raise ValueError("AWS_KEY environment variable is required")
EOF

# now the commit succeeds
git add config.py
git commit -m "add config"
```

Output:
```
[INFO] no secrets detected. commit allowed.
```

---

## Auditing a Repository

### Basic working tree audit

Scan all tracked files in your current working directory:

```sh
# scan the entire working tree
sekretbarilo audit
```

Example output (clean):
```
[AUDIT] no secrets found in working tree
```

Example output (secrets found):
```
[AUDIT] 2 secret(s) found in working tree

  file: src/config.rs
  line: 42
  rule: aws-access-key-id
  match: AK**************QA

  file: scripts/deploy.sh
  line: 15
  rule: generic-api-key
  match: sk********************xy
```

### Including ignored files

```sh
# scan including files matched by .gitignore
sekretbarilo audit --include-ignored
```

This is useful for scanning build artifacts, generated files, or other ignored content.

### Focusing on specific file types

```sh
# scan only python and javascript files
sekretbarilo audit \
  --include-pattern '\.py$' \
  --include-pattern '\.js$'

# scan only rust files, excluding tests
sekretbarilo audit \
  --include-pattern '\.rs$' \
  --exclude-pattern '^tests/'
```

### Excluding directories

```sh
# exclude test fixtures and vendor code
sekretbarilo audit \
  --exclude-pattern '^tests/fixtures/' \
  --exclude-pattern '^vendor/' \
  --exclude-pattern '^node_modules/'

# exclude multiple build directories
sekretbarilo audit \
  --exclude-pattern '^build/' \
  --exclude-pattern '^dist/' \
  --exclude-pattern '^target/'
```

---

## Auditing Git History

### Scanning all history

Scan every commit across all branches for secrets:

```sh
# full history scan (all branches, all time)
sekretbarilo audit --history
```

Example output:
```
[AUDIT] 3 secret(s) found in git history

  commit: abc1234567890abcdef1234567890abcdef12345 (Jane Dev <jane@company.com>, 2024-03-15T14:22:00+00:00)
    branches: main, feature/auth
    file: config.py
    line: 7
    rule: aws-access-key-id
    match: AK**************QA

  commit: def4567890123def4567890123def4567890123d (John Smith <john@company.com>, 2024-05-20T09:15:30+00:00)
    branches: main, develop
    file: scripts/setup.sh
    line: 23
    rule: github-personal-access-token
    match: gh**********************************AB

  commit: 789abc123def789abc123def789abc123def789a (Alice Johnson <alice@company.com>, 2024-08-10T16:45:00+00:00)
    branches: feature/api, develop
    file: src/api/client.js
    line: 102
    rule: generic-api-key
    match: sk********************yz
```

The output shows:
- **commit hash** - full sha-1 hash of the commit
- **author and email** - who committed the secret
- **timestamp** - when it was committed (iso 8601 format with timezone)
- **branches** - which branches contain this commit
- **file and line** - where in the file the secret was found
- **rule** - which detection rule matched
- **match** - partially redacted secret value

### Filtering by branch

```sh
# scan only commits reachable from main
sekretbarilo audit --history --branch main

# scan only commits in a feature branch
sekretbarilo audit --history --branch feature/new-api
```

### Filtering by date range

```sh
# scan commits since january 1st, 2024
sekretbarilo audit --history --since 2024-01-01

# scan commits from january to june 2024
sekretbarilo audit --history --since 2024-01-01 --until 2024-06-30

# scan recent commits (last month)
sekretbarilo audit --history --since 2024-11-01
```

### Combining filters

```sh
# scan main branch commits from the last quarter
sekretbarilo audit --history --branch main --since 2024-10-01

# scan a specific feature branch in a specific time window
sekretbarilo audit --history --branch feature/auth --since 2024-06-01 --until 2024-09-30
```

### Understanding history audit output

History audit findings include additional context compared to regular scans:

- **Author attribution**: see who introduced the secret (helps with remediation)
- **Timestamp**: understand when it was committed (assess exposure window)
- **Branch containment**: know which branches contain the secret (plan cleanup)
- **Deduplication**: if the same secret appears in multiple commits, only the earliest introducing commit is reported

---

## Setting Up Claude Code Protection

Prevent Claude Code from reading files that contain secrets.

### Step-by-step installation

```sh
# navigate to your project
cd my-project

# install the agent hook for claude code
sekretbarilo install agent-hook claude
```

Output:
```
[INFO] claude code hook installed at .claude/settings.json
[INFO] hook command: sekretbarilo check-file --stdin-json
[INFO] hook will scan files before claude code reads them
```

### Verifying installation

```sh
# check that everything is configured correctly
sekretbarilo doctor
```

Example output (healthy installation):
```
[INFO] sekretbarilo doctor

Git pre-commit hook (local):
  ✓ installed at .git/hooks/pre-commit
  ✓ executable
  ✓ sekretbarilo marker present

Claude code hook (local):
  ✓ installed at .claude/settings.json
  ✓ hook command: sekretbarilo check-file --stdin-json
  ✓ hook type: PreToolUse (Read tool)

Configuration:
  ✓ config loaded from .sekretbarilo.toml
  ✓ 43 built-in rules + 2 custom rules
  ✓ entropy threshold: 3.5

Binary:
  ✓ sekretbarilo found in PATH at /usr/local/bin/sekretbarilo
```

Example output (issues found):
```
[WARN] sekretbarilo doctor

Git pre-commit hook (local):
  ✗ not installed

Claude code hook (local):
  ✓ installed at .claude/settings.json
  ⚠ outdated command detected: sekretbarilo scan --stdin-json
  → run `sekretbarilo install agent-hook claude` to update

Configuration:
  ✓ config loaded from .sekretbarilo.toml
  ✓ 43 built-in rules

Binary:
  ✓ sekretbarilo found in PATH
```

### How it works

When Claude Code tries to read a file:

1. The agent hook intercepts the read request
2. sekretbarilo scans the file for secrets
3. If secrets are found, the read is blocked and Claude Code is notified
4. If no secrets are found, Claude Code reads the file normally

Example (Claude Code is blocked from reading a file with secrets):

```
[AGENT] secret(s) detected in src/config.rs

  line: 42
  rule: aws-access-key-id
  match: AK**************QA

file contains 1 secret(s). reading blocked to prevent secret exposure.
```

Claude Code will show an error message to the user and will not have access to the file contents.

### Global installation

Install the hook for all Claude Code projects:

```sh
# install globally (affects all projects)
sekretbarilo install agent-hook claude --global
```

This installs the hook in `~/.claude/settings.json` instead of `.claude/settings.json`.

---

## Configuration Examples

### Example 1: Minimal project config

A simple starting point for a new project:

```toml
# .sekretbarilo.toml

[allowlist]
# skip test fixtures (known safe test data)
paths = ["tests/fixtures/.*"]

# skip this specific test api key used in examples
stopwords = ["test-api-key-12345"]
```

### Example 2: Organization-wide config

Set defaults for all projects in your organization:

```toml
# ~/.config/sekretbarilo/sekretbarilo.toml

[settings]
# slightly higher threshold to reduce false positives
entropy_threshold = 3.5

[allowlist]
# skip vendor code and generated files (common across all projects)
paths = [
  "vendor/.*",
  "node_modules/.*",
  "third_party/.*",
  ".*\\.min\\.js$",
  ".*\\.map$",
]

# organization-wide safe placeholder values
stopwords = [
  "company-internal-placeholder",
  "acme-corp-example-token",
]
```

### Example 3: Custom detection rule for internal tokens

Detect company-specific token formats:

```toml
# .sekretbarilo.toml

[[rules]]
id = "acme-service-token"
description = "ACME Corp internal service token"
regex = "(ACME_[A-Za-z0-9]{40})"
secret_group = 1
keywords = ["acme_"]
entropy_threshold = 3.5

[rules.allowlist]
# skip known test tokens
regexes = [
  "ACME_EXAMPLE_.*",
  "ACME_TEST_.*",
]

# skip test files
paths = ["tests/.*", "spec/.*"]
```

### Example 4: Allowlisting a known false positive

Skip a specific value that looks like a secret but isn't:

```toml
# .sekretbarilo.toml

# skip the official aws example key from documentation
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]

# skip jwt tokens in documentation files
[[allowlist.rules]]
id = "jwt-token"
paths = ["docs/.*\\.md$", "README\\.md"]

# skip generic-api-key findings in test files
[[allowlist.rules]]
id = "generic-api-key"
paths = ["test/.*", "spec/.*", "fixtures/.*"]
```

### Example 5: CI/CD pipeline config

Use stricter settings in your ci/cd pipeline:

```toml
# ci-sekretbarilo.toml - used in CI with --config flag

[settings]
# stricter threshold for ci (fewer false positives)
entropy_threshold = 4.0

[allowlist]
# only allow safe test tokens in ci
stopwords = ["ci-test-token"]

[audit]
# scan everything in ci (no excludes)
exclude_patterns = []
# but skip ci-specific directories
exclude_patterns = ["^\.github/", "^scripts/"]
```

```sh
# in your ci pipeline script
sekretbarilo audit --config ci-sekretbarilo.toml
```

### Example 6: Merging multiple configs

Combine organization-wide rules with project-specific overrides:

```sh
# merge org-wide rules with project-specific settings
sekretbarilo scan --config /etc/sekretbarilo.toml --config .sekretbarilo.toml
```

**org-rules.toml** (organization-wide):
```toml
[settings]
entropy_threshold = 3.0

[[rules]]
id = "company-internal-token"
description = "Company internal service token"
regex = "(COMPANY_[A-Z0-9]{32})"
secret_group = 1
keywords = ["company_"]
```

**project-rules.toml** (project-specific):
```toml
[settings]
# override with stricter threshold for this project
entropy_threshold = 4.0

[allowlist]
# project-specific test data
paths = ["testdata/.*"]
```

Effective config:
- `entropy_threshold = 4.0` (project wins)
- company-internal-token rule is active
- testdata directory is skipped

### Example 7: Using only custom rules (no defaults)

Skip all built-in rules and use only your own:

```sh
# scan with only custom rules
sekretbarilo scan --no-defaults --config custom-only.toml
```

**custom-only.toml**:
```toml
# only detect internal company secrets (no aws, github, etc.)

[[rules]]
id = "company-api-key"
description = "Company API key"
regex = "(?i)api[-_]?key\\s*[=:]\\s*['\"]([A-Z0-9]{32})['\"]"
secret_group = 1
keywords = ["api_key", "api-key"]
entropy_threshold = 4.0

[[rules]]
id = "company-service-token"
description = "Company service token"
regex = "(SVC_[A-Za-z0-9]{40})"
secret_group = 1
keywords = ["svc_"]
entropy_threshold = 3.5
```

---

## CLI Override Examples

Use command-line flags to temporarily override config settings:

### Temporarily raise entropy threshold

```sh
# use a higher threshold for a one-off scan (fewer findings)
sekretbarilo scan --entropy-threshold 4.5
```

### Add a one-off allowlist path

```sh
# skip documentation directory just for this scan
sekretbarilo audit --allowlist-path 'docs/examples/.*'
```

### Add a one-off stopword

```sh
# ignore a specific value for this scan only
sekretbarilo scan --stopword known-safe-value-xyz
```

### Combine multiple overrides

```sh
# combine config file with multiple cli overrides
sekretbarilo audit \
  --config ci.toml \
  --stopword test-token \
  --stopword another-safe-value \
  --exclude-pattern '^fixtures/' \
  --exclude-pattern '^vendor/' \
  --entropy-threshold 4.0
```

### Override for a specific commit

```sh
# scan staged changes with custom settings
sekretbarilo scan \
  --stopword my-known-safe-value \
  --allowlist-path 'testdata/.*'

# if clean, commit
git commit -m "add feature"
```

---

## Doctor Diagnostics

The `doctor` command checks your sekretbarilo installation health.

### Running doctor

```sh
sekretbarilo doctor
```

### Example output: healthy installation

```
[INFO] sekretbarilo doctor

Git pre-commit hook (local):
  ✓ installed at .git/hooks/pre-commit
  ✓ executable
  ✓ sekretbarilo marker present

Git pre-commit hook (global):
  ✓ installed at ~/.git/hooks/pre-commit
  ✓ executable
  ✓ sekretbarilo marker present

Claude code hook (local):
  ✓ installed at .claude/settings.json
  ✓ hook command: sekretbarilo check-file --stdin-json
  ✓ hook type: PreToolUse (Read tool)

Claude code hook (global):
  ✓ installed at ~/.claude/settings.json
  ✓ hook command: sekretbarilo check-file --stdin-json
  ✓ hook type: PreToolUse (Read tool)

Configuration:
  ✓ config loaded from .sekretbarilo.toml
  ✓ config loaded from ~/.config/sekretbarilo/sekretbarilo.toml
  ✓ 43 built-in rules + 5 custom rules
  ✓ entropy threshold: 3.5
  ✓ 12 allowlist paths
  ✓ 3 stopwords (+ defaults)

Binary:
  ✓ sekretbarilo found in PATH at /usr/local/bin/sekretbarilo
```

### Example output: issues detected

```
[WARN] sekretbarilo doctor - issues detected

Git pre-commit hook (local):
  ✗ not installed
  → run `sekretbarilo install pre-commit` to install

Git pre-commit hook (global):
  ✓ installed at ~/.git/hooks/pre-commit
  ✓ executable

Claude code hook (local):
  ✓ installed at .claude/settings.json
  ⚠ outdated command detected: sekretbarilo scan --stdin-json
  → run `sekretbarilo install agent-hook claude` to update

Claude code hook (global):
  ✗ not installed
  → run `sekretbarilo install agent-hook claude --global` to install

Configuration:
  ✓ config loaded from .sekretbarilo.toml
  ⚠ config parse warning: unknown field 'invalid_key' in .sekretbarilo.toml
  ✓ 43 built-in rules + 1 custom rule
  ✗ rule 'custom-broken-rule' failed to compile: invalid regex pattern

Binary:
  ✓ sekretbarilo found in PATH
```

---

## Common Scenarios

### Scenario 1: New team member onboarding

When a new developer joins your team:

```sh
# step 1: clone the repository
git clone https://github.com/yourorg/yourproject.git
cd yourproject

# step 2: install sekretbarilo (if not already installed)
cargo install sekretbarilo

# step 3: install hooks (project already has .sekretbarilo.toml)
sekretbarilo install pre-commit
sekretbarilo install agent-hook claude  # if using claude code

# step 4: verify installation
sekretbarilo doctor

# step 5: audit the repository (optional, good first check)
sekretbarilo audit

# done - now protected from committing secrets
```

The project's `.sekretbarilo.toml` is already in the repository, so team members automatically get the same rules and allowlists.

### Scenario 2: Adding sekretbarilo to an existing project

When adding sekretbarilo to a project with existing history:

```sh
# step 1: navigate to project
cd existing-project

# step 2: audit first (don't install hooks yet)
sekretbarilo audit

# if secrets found, handle them:
# - rotate the secrets (change credentials)
# - remove from git history (git filter-repo or bfg-repo-cleaner)
# - add to .sekretbarilo.toml allowlist (if false positives)

# step 3: audit git history
sekretbarilo audit --history

# this shows all secrets across all commits
# you'll need to:
# - identify which secrets are still active (rotate them)
# - clean git history (advanced topic, see tools like git-filter-repo)

# step 4: create config file if needed
cat > .sekretbarilo.toml << 'EOF'
[allowlist]
# skip known safe test fixtures
paths = ["tests/fixtures/.*"]

# known safe example values
stopwords = ["example-api-key"]
EOF

# step 5: audit again to verify allowlists work
sekretbarilo audit

# step 6: install hooks once clean
sekretbarilo install pre-commit

# step 7: commit the config
git add .sekretbarilo.toml
git commit -m "add sekretbarilo config"

# step 8: document for team
echo "sekretbarilo is now active. Run 'sekretbarilo install pre-commit' after cloning." >> README.md
```

### Scenario 3: Handling false positives

When sekretbarilo flags something that isn't actually a secret:

```sh
# example: sekretbarilo flags a test jwt token in documentation
sekretbarilo audit
```

Output:
```
[AUDIT] 1 secret(s) found in working tree

  file: docs/authentication.md
  line: 42
  rule: jwt-token
  match: ey**************************************************Ab
```

**Option 1: Allowlist by path** (skip all jwt tokens in docs):

```toml
# .sekretbarilo.toml
[[allowlist.rules]]
id = "jwt-token"
paths = ["docs/.*"]
```

**Option 2: Allowlist by value** (skip this specific token):

```toml
# .sekretbarilo.toml
[[allowlist.rules]]
id = "jwt-token"
regexes = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\..*"]
```

**Option 3: Add as stopword** (skip any value containing this string):

```toml
# .sekretbarilo.toml
[allowlist]
stopwords = ["example-jwt-token"]
```

Test your fix:

```sh
# verify the allowlist works
sekretbarilo audit

# should now show clean
```

### Scenario 4: Bypassing for known safe values

Sometimes you legitimately need to commit something that looks like a secret (e.g., example code in documentation).

**Not recommended approach** (bypasses all checks):

```sh
# bypass hook entirely (dangerous - skips all validation)
git commit --no-verify
```

**Better approach** (allowlist the specific case):

```toml
# .sekretbarilo.toml
[[allowlist.rules]]
id = "aws-access-key-id"
# only skip this specific example key
regexes = ["AKIAIOSFODNN7EXAMPLE"]
```

Then commit normally:

```sh
git add docs/aws-example.md
git commit -m "add aws documentation example"
# sekretbarilo allows the commit (matches allowlist)
```

**Best approach** (use variable references in examples):

```python
# instead of hardcoding an example key
aws_key = "AKIAIOSFODNN7EXAMPLE"  # sekretbarilo will flag this

# use a variable reference (sekretbarilo skips these automatically)
aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
```

### Scenario 5: Scanning before a large refactor

Before making major changes:

```sh
# scan current state
sekretbarilo audit > audit-before.txt

# perform refactor
# ... make changes ...

# scan again
sekretbarilo audit > audit-after.txt

# compare results
diff audit-before.txt audit-after.txt

# ensure no new secrets were introduced
```

### Scenario 6: Integrating with CI/CD

Example GitHub Actions workflow:

```yaml
# .github/workflows/secrets-scan.yml
name: Secret Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # full history for --history scans

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install sekretbarilo
        run: cargo install --git https://github.com/vshuraeff/sekretbarilo

      - name: Scan working tree
        run: sekretbarilo audit

      - name: Scan git history (main branch only)
        if: github.ref == 'refs/heads/main'
        run: sekretbarilo audit --history --branch main --since 30.days.ago
```

Example GitLab CI:

```yaml
# .gitlab-ci.yml
secrets-scan:
  stage: test
  image: rust:latest
  before_script:
    - cargo install --git https://github.com/vshuraeff/sekretbarilo
  script:
    - sekretbarilo audit
    - sekretbarilo audit --history --branch $CI_COMMIT_BRANCH --since 30.days.ago
  only:
    - main
    - merge_requests
```

---

## Tips and Tricks

### Quickly scan a single file

```sh
# scan a specific file before committing
sekretbarilo check-file src/config.py

# if clean (exit code 0), safe to commit
```

### Test a new custom rule

```sh
# create a test config
cat > test-rule.toml << 'EOF'
[[rules]]
id = "test-custom-rule"
description = "Test rule"
regex = "(TEST_[A-Z0-9]{20})"
secret_group = 1
keywords = ["test_"]
EOF

# test it on your codebase
sekretbarilo audit --config test-rule.toml

# if it works well, merge into .sekretbarilo.toml
```

### Scan only staged changes

```sh
# scan only what you're about to commit
sekretbarilo scan

# this is what the pre-commit hook runs automatically
```

### Find which commits introduced secrets

```sh
# scan history with verbose output
sekretbarilo audit --history | grep -A 10 "commit:"

# shows full commit info including author and timestamp
```

### Check if binary is accessible

```sh
# verify sekretbarilo is in PATH
which sekretbarilo

# verify it runs
sekretbarilo --version

# comprehensive check
sekretbarilo doctor
```

### Temporarily disable the hook

```sh
# rename the hook (preserves it)
mv .git/hooks/pre-commit .git/hooks/pre-commit.disabled

# restore later
mv .git/hooks/pre-commit.disabled .git/hooks/pre-commit
```

Or use `--no-verify` for a single commit:

```sh
git commit --no-verify -m "commit message"
```

### Scan a different branch without switching

```sh
# audit a branch without checking it out
sekretbarilo audit --history --branch feature/experimental

# useful for reviewing feature branches
```

---

## See Also

- [Getting Started]({{ '/getting-started/' | relative_url }}) - quick setup guide
- [Configuration]({{ '/configuration/' | relative_url }}) - detailed configuration reference
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - complete command documentation
- [Agent Hooks]({{ '/agent-hooks/' | relative_url }}) - ai agent integration details
