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
[OK] created new pre-commit hook
```

### What happens when you commit a .env file

`.env` files are blocked unconditionally — sekretbarilo does not even read them, so this example needs no secret material at all:

```sh
# create a .env file (it does not matter what is in it)
echo "API_TOKEN=changeme" > .env

# try to commit it
git add -f .env
git commit -m "add env"
```

sekretbarilo blocks the commit and shows:

```
[ERROR] secret(s) detected in staged changes

  file: .env
  line: -
  rule: env-file-blocked
  match: (blocked file type)

commit blocked. 1 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

`line: -` and `match: (blocked file type)` are literal: the block is a policy decision about the filename, not a finding inside the file.

Renaming it to `.env.example` (or `.env.sample`, or `.env.template`) makes the commit pass — those three names are treated as documentation.

### What happens when you commit a key in source code

```sh
# a real-shaped aws access key ends up in a config file
git add config.py
git commit -m "add config"
```

```
[ERROR] secret(s) detected in staged changes

  file: config.py
  line: 1
  rule: aws-access-key-id
  match: AK****************ME

commit blocked. 1 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

The value is masked to its first and last two characters, so the last two of your output will differ from the transcript above.

**A note on `AKIAIOSFODNN7EXAMPLE`**: that specific string is the key AWS prints in its own documentation, and it ships allowlisted in the built-in `aws-access-key-id` rule. It will *not* block a commit. If you want to reproduce the block above, use a throwaway value of the same shape rather than the documentation key.

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

A clean `scan` prints nothing at all and exits 0 — silence is success. sekretbarilo only speaks up when it has something to block.

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
[AUDIT] audit complete. scanned 1 file(s), 0 secret(s) found.
```

Example output (secrets found):
```
[AUDIT] secret(s) detected in tracked files

  file: scripts/deploy.sh
  line: 1
  rule: github-personal-access-token
  match: gh**************************************AB

[AUDIT] audit complete. scanned 3 file(s), 1 secret(s) in 1 file(s).
```

Unlike `scan`, `audit` always prints a summary line, clean or not — it is a report, not a gate. It still exits 1 when it finds something.

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
[AUDIT] scanned 4/4 commits.
[AUDIT] resolving branches for 3 commit(s)...

[AUDIT] secret(s) detected in git history

  commit: 1e512f68 (Jane Dev <jane@example.com>, 2024-03-15T14:22:00Z)
    branches: feature/api, main
    file: config.py
    line: 1
    rule: github-personal-access-token
    match: gh**************************************AB

  commit: 7ff8ca52 (John Smith <john@example.com>, 2024-05-20T09:15:30Z)
    branches: feature/api, main
    file: scripts/setup.sh
    line: 1
    rule: gitlab-personal-access-token
    match: gl**********************ij

  commit: 6c2a6a9c (Alice Johnson <alice@example.com>, 2024-08-10T16:45:00Z)
    branches: feature/api
    file: src/api/client.js
    line: 1
    rule: slack-bot-token
    match: xo**************************************************Wx

[AUDIT] scanned 4 commit(s). 3 secret(s) found.
```

The output shows:
- **progress lines** - how many commits were scanned, and how many needed branch resolution
- **commit hash** - abbreviated commit hash
- **author and email** - who committed the secret
- **timestamp** - when it was committed (iso 8601)
- **branches** - which branches contain this commit
- **file and line** - where in the file the secret was found
- **rule** - which detection rule matched
- **match** - partially redacted secret value

Branch resolution runs only for commits that produced findings, which is why the second progress line counts 3 and not 4.

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

## Searching for Your Own Strings

`--search` and `--search-regex` add a second, independent pass to an audit. Use them when you know exactly what you are looking for — a rotated credential, an internal hostname, a vendor account id — and the built-in rules would not recognise it.

```sh
# find every occurrence of an internal hostname
sekretbarilo audit --search internal.example.com
```

The search pass runs *in addition to* the normal rule-based audit, and reports separately:

```
[AUDIT] secret(s) detected in tracked files

  file: config.py
  line: 1
  rule: github-personal-access-token
  match: gh**************************************AB

  file: scripts/setup.sh
  line: 1
  rule: gitlab-personal-access-token
  match: gl**********************ij

[AUDIT] audit complete. scanned 5 file(s), 2 secret(s) in 2 file(s).


[SEARCH] user-search match(es) found

  file: deploy/prod.yml
  line: 1
  pattern: internal.example.com
  match: endpoint: api.internal.example.com

  file: deploy/staging.yml
  line: 1
  pattern: internal.example.com
  match: endpoint: api.internal.example.com

[SEARCH] 2 match(es) in 2 file(s) across 5 scanned file(s).
```

With no matches, the pass still reports:

```
[SEARCH] scanned 5 file(s). 0 match(es).
```

Both flags are repeatable and can be mixed:

```sh
sekretbarilo audit \
  --search internal.example.com \
  --search-regex 'ACCT-[0-9]{8}'
```

Three things to know:

- **Search hits are not masked.** You asked for this exact string, so the full matching line is printed. Rule findings on the same run stay masked.
- **A search match alone makes the command exit 1**, even when the rule pass found nothing.
- **Audit only.** `scan --search` is rejected; the pass is meant for investigation, not for gating commits.

---

## Setting Up Claude Code Protection

The following examples use `block` mode, which prevents Claude Code from reading files that contain secrets. For output masking, use `sekretbarilo install agent-hook claude --mode redact` (Claude Code >= 2.1.121): successful `Bash`, text `Read`, and `Grep` results replace detected values with `[REDACTED]` while leaving files unchanged. See [redaction behavior and a synthetic smoke check]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}).

Without `--mode`, an install preserves the mode already configured in the selected settings file; a new installation uses `block`. Use `--mode block` explicitly when following these blocking examples after enabling redaction.

### Step-by-step installation

```sh
# navigate to your project
cd my-project

# install the agent hook for claude code
sekretbarilo install agent-hook claude
```

Output:
```
[OK] created claude code hook configuration
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

  file: config.rs
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

## Setting Up Codex CLI Protection

The Codex hook works in the other direction from the Claude hook: instead of checking a file the agent is about to *read*, it checks what the agent is about to *write* or *run*, before it happens.

### Step-by-step installation

```sh
cd my-project
sekretbarilo install agent-hook codex
```

Output:
```
[OK] created codex cli hook configuration
[WARN] IMPORTANT: Codex will silently skip this hook until you approve it.
       In the Codex TUI, run /hooks and approve the sekretbarilo hook.
       For non-interactive automation only, --dangerously-bypass-hook-trust bypasses this protection.
[INFO] detected Codex version: codex-cli 0.145.0
```

**Do not skip the approval step.** Codex ignores hooks it has not been asked to trust, and it does so silently — an unapproved hook looks exactly like a working one until a secret slips through. Run `/hooks` in the Codex TUI and approve the sekretbarilo entry.

### Global installation

```sh
sekretbarilo install agent-hook codex --global
```

This writes `$CODEX_HOME/hooks.json`, which is `~/.codex/hooks.json` unless `CODEX_HOME` is set.

### Installing everything at once

```sh
sekretbarilo install all           # pre-commit + claude + codex, in this project
sekretbarilo install all --global  # the same three, for every project
```

Output:
```
installing pre-commit hook...
[OK] created new pre-commit hook
installing claude code agent hook...
[OK] created claude code hook configuration
installing codex cli agent hook...
[OK] created codex cli hook configuration
[WARN] IMPORTANT: Codex will silently skip this hook until you approve it.
       In the Codex TUI, run /hooks and approve the sekretbarilo hook.
       For non-interactive automation only, --dangerously-bypass-hook-trust bypasses this protection.
[INFO] detected Codex version: codex-cli 0.145.0
```

### What it blocks

The hook matches two Codex tools, `apply_patch` and `Bash`.

When Codex tries to write a secret into a file, the patch is blocked before it lands:

```
[AGENT] Codex apply_patch blocked: secret(s) detected
  file: src/creds.py
  line: 1
  rule: github-personal-access-token
  match: gh**************************************AB
apply_patch action blocked to prevent secret exposure. total findings: 1.
```

When a secret appears in the shell command itself — for example an `echo` that appends a token to a file — the command is blocked and the finding is attributed to `<bash-command>`:

```
[AGENT] Codex Bash blocked: secret(s) detected
  file: <bash-command>
  line: 1
  rule: github-personal-access-token
  match: gh**************************************AB
Bash action blocked to prevent secret exposure. total findings: 1.
```

Codex sees the non-zero exit and does not run the tool call.

### Config trust on agent paths

An agent can write files, and one of the files it could write is `.sekretbarilo.toml`. So on the `check-file`, `check-codex`, and `redact-claude` paths only, an in-workspace config is honoured **only** when git says it is tracked and unmodified against `HEAD`. Otherwise the whole layer is dropped:

```
[WARN] ignoring untrusted in-workspace config: /home/user/project/.sekretbarilo.toml
```

`scan` and `audit` are unaffected — those are run by a human. See [Configuration]({{ '/configuration/' | relative_url }}) for the exact conditions.

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

# skip a specific throwaway key that appears in your own docs
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIA-YOUR-THROWAWAY-KEY-HERE"]

# skip jwt tokens in documentation files
[[allowlist.rules]]
id = "jwt-token"
paths = ["docs/.*\\.md$", "README\\.md"]

# skip generic-api-key findings in test files
[[allowlist.rules]]
id = "generic-api-key"
paths = ["test/.*", "spec/.*", "fixtures/.*"]
```

You do not need an entry for `AKIAIOSFODNN7EXAMPLE` — the key AWS uses in its own documentation already ships allowlisted in the built-in `aws-access-key-id` rule.

### Example 5: Enabling public key detection

By default, public keys (PEM, PGP, OpenSSH) are suppressed. Enable detection if your policy treats public keys as sensitive:

```toml
# .sekretbarilo.toml

[settings]
# report public keys as findings
detect_public_keys = true
```

Or enable via CLI for a one-off scan:

```sh
# scan staged changes including public keys
sekretbarilo scan --detect-public-keys

# audit working tree including public keys
sekretbarilo audit --detect-public-keys
```

This enables 3 additional rules: `pem-public-key`, `pgp-public-key-block`, and `openssh-public-key`.

### Example 6: CI/CD pipeline config

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
# skip ci-specific directories
exclude_patterns = ["^\\.github/", "^scripts/"]
```

Two TOML details that bite here: a key may appear only once per table (a second `exclude_patterns` is a parse error, not an override), and a backslash inside a basic string must be escaped — `"^\\.github/"`, not `"^\.github/"`. A config that fails to parse is reported and the command exits 2.

```sh
# in your ci pipeline script
sekretbarilo audit --config ci-sekretbarilo.toml
```

### Example 7: Merging multiple configs

Combine organization-wide rules with project-specific overrides:

```sh
# merge org-wide rules with project-specific settings
# --config skips hierarchical discovery entirely; only the listed files are loaded,
# left to right, with later files winning on scalars
sekretbarilo scan --config org-rules.toml --config project-rules.toml
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

### Example 8: Using only custom rules (no defaults)

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

Doctor prints five groups of checks. In the transcripts below, real absolute paths have been replaced with `/home/user/project` and `/home/user`; everything else is verbatim 0.7.x output.

### Example output: nothing installed yet

```
git pre-commit hook:
  [NOT INSTALLED] local pre-commit hook not found
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [NOT INSTALLED] local claude code hook not found
  [NOT INSTALLED] global claude code hook not found

codex cli agent hook:
  [NOT INSTALLED] local codex cli hook not found
  [NOT INSTALLED] global codex cli hook not found
  [OK] codex found in PATH (codex-cli 0.145.0)

configuration:
  [OK] no custom config files found (using defaults)
  [OK] 112 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

Exit code 0. `[NOT INSTALLED]` is informational — doctor tells you a hook is absent without treating absence as a failure. Only `[WARN]` and `[ERROR]` make it exit 1.

### Example output: issues detected

Here the hooks are installed locally, the Codex hook has not been approved, and the project has its own config adding one custom rule:

```
git pre-commit hook:
  [OK] local pre-commit hook installed
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [OK] local claude code hook installed (/home/user/project/.claude/settings.json)
  [NOT INSTALLED] global claude code hook not found

codex cli agent hook:
  [OK] local codex cli hook installed (/home/user/project/.codex/hooks.json)
  [WARN] local codex cli hook approval entry not found in /home/user/.codex/config.toml; codex silently skips unapproved hooks; approve it with /hooks in the Codex TUI
  [NOT INSTALLED] global codex cli hook not found
  [OK] codex found in PATH (codex-cli 0.145.0)

configuration:
  [OK] config file: /home/user/project/.sekretbarilo.toml
  [OK] 113 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

Exit code 1, because of the single `[WARN]`. Note the rule count is a total, not a split: 112 built-in plus the one rule defined in `.sekretbarilo.toml`.

### Example output: healthy installation

Everything installed locally and globally, and the Codex hook approved:

```
git pre-commit hook:
  [OK] local pre-commit hook installed
  [OK] global pre-commit hook installed

claude code agent hook:
  [OK] local claude code hook installed (/home/user/project/.claude/settings.json)
  [OK] global claude code hook installed (/home/user/.claude/settings.json)

codex cli agent hook:
  [OK] local codex cli hook installed (/home/user/project/.codex/hooks.json)
  [OK] local codex cli hook approval entry found in /home/user/.codex/config.toml (group 0, handler 0); codex re-checks its own trust hash at run time, so this is not proof the hook runs
  [OK] global codex cli hook installed (/home/user/.codex/hooks.json)
  [OK] global codex cli hook approval entry found in /home/user/.codex/config.toml (group 0, handler 0); codex re-checks its own trust hash at run time, so this is not proof the hook runs
  [OK] codex found in PATH (codex-cli 0.145.0)

configuration:
  [OK] no custom config files found (using defaults)
  [OK] 112 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

Exit code 0.

The Codex approval check is deliberately honest about its own limits: it confirms that an approval entry exists at the right position in Codex's `config.toml`, but it does not revalidate Codex's internal trust hash. An `[OK]` there means "approved at some point", not "guaranteed to run".

---

## Common Scenarios

### Scenario 1: New team member onboarding

When a new developer joins your team:

```sh
# step 1: clone the repository
git clone https://github.com/yourorg/yourproject.git
cd yourproject

# step 2: install sekretbarilo (if not already installed)
brew install vshuraeff/tap/sekretbarilo

# step 3: install hooks (project already has .sekretbarilo.toml)
sekretbarilo install all

# if you use Codex CLI, approve its hook now: run /hooks in the Codex TUI.
# an unapproved codex hook is silently ignored.

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
[AUDIT] secret(s) detected in tracked files

  file: docs/authentication.md
  line: 42
  rule: jwt-token
  match: ey**************************************************Ab

[AUDIT] audit complete. scanned 214 file(s), 1 secret(s) in 1 file(s).
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
# only skip the one example key that appears in our docs
regexes = ["AKIA-YOUR-THROWAWAY-KEY-HERE"]
```

Then commit normally:

```sh
git add docs/aws-example.md
git commit -m "add aws documentation example"
# sekretbarilo allows the commit (matches allowlist)
```

**Best approach** (use the vendor's own documentation key, or a variable reference):

```python
# a variable reference is never a finding — sekretbarilo skips these automatically
aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
```

Where an example genuinely needs a literal, prefer the value the vendor publishes in its own documentation. `AKIAIOSFODNN7EXAMPLE` is AWS's, and it is allowlisted in the built-in rule, so it needs no config at all.

### Scenario 5: Scanning before a large refactor

Before making major changes:

```sh
# scan current state
# note the 2>: all sekretbarilo output goes to stderr, so a plain > captures nothing
sekretbarilo audit 2> audit-before.txt

# perform refactor
# ... make changes ...

# scan again
sekretbarilo audit 2> audit-after.txt

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
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0  # full history for --history scans

      - name: Install Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
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

# check-file exits 0 (clean) or 2 (secrets found, or an error) — never 1
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
# redirect stderr into the pipe — that is where sekretbarilo writes
sekretbarilo audit --history 2>&1 | grep -A 10 "commit:"

# shows commit hash, author and timestamp for each finding
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
- [Rules Reference]({{ '/rules-reference/' | relative_url }}) - what each built-in rule detects
