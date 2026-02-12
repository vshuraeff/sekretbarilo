---
layout: default
title: Getting Started
nav_order: 1
---

# Getting Started

## What is sekretbarilo?

**sekretbarilo** (Esperanto for "secret keeper") is a high-performance secret scanner designed for git workflows and AI coding agents. Written in Rust, it protects your codebase by:

- **Preventing secret leaks** in git commits through pre-commit hooks
- **Auditing repositories** for existing secrets in commit history
- **Protecting AI agent file reads** by blocking access to files containing secrets

Whether you're working solo or in a team, sekretbarilo acts as an automated guard against accidentally committing API keys, passwords, tokens, and other sensitive data.

## Why you need it

Secrets in version control are a critical security risk:

- Once committed, secrets remain in git history even if removed later
- Public repositories expose secrets to the entire internet
- AI coding agents may inadvertently leak secrets when accessing files
- Automated scanning catches what manual code review misses

sekretbarilo provides multiple layers of defense:

1. **Pre-commit scanning** blocks secrets before they enter your repository
2. **History auditing** finds secrets already in your git history
3. **Agent hooks** prevent AI tools from reading files with secrets

## Quick 3-step setup

Get started with sekretbarilo in under a minute:

```sh
# step 1: install sekretbarilo
brew install vshuraeff/tap/sekretbarilo

# step 2: set up pre-commit hook in your project
cd your-project
sekretbarilo install pre-commit

# step 3: that's it - now every commit is scanned automatically
git add config.py
git commit -m "add config"
# sekretbarilo scans staged changes...
```

## What happens when a secret is detected

When sekretbarilo finds a secret in your staged changes, it blocks the commit and shows you exactly what was detected:

```
[ERROR] secret detected in staged changes

  file: config.py
  line: 3
  rule: aws-access-key-id
  match: AK**************QA

commit blocked. 1 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

The output includes:

- **file** - which file contains the secret
- **line** - exact line number for quick navigation
- **rule** - which detection rule matched (helps you understand what was found)
- **match** - partially redacted secret (enough to identify it, not enough to expose it)

You can then:

1. Remove the secret from the file
2. Move it to environment variables or a secure vault
3. Update the file and re-commit safely

## Typical workflow example

Here's what daily use looks like:

```sh
# working on your project
vim src/api_client.py
# (accidentally paste an API key)

# try to commit
git add src/api_client.py
git commit -m "add api client"

# sekretbarilo blocks the commit
# [ERROR] secret detected in staged changes
#   file: src/api_client.py
#   line: 12
#   rule: generic-api-key
#   match: sk_live_***************************

# fix the issue
vim src/api_client.py
# (move key to environment variable)

# commit successfully
git add src/api_client.py
git commit -m "add api client"
# [INFO] no secrets detected. commit allowed.
```

## Next steps

Now that you understand the basics:

- **[Installation]({{ '/installation/' | relative_url }})** - detailed installation guide including global hooks and AI agent integration
- **[CLI Reference]({{ '/cli-reference/' | relative_url }})** - complete command reference for scanning, auditing, and configuration
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** - protect AI coding tools like Claude Code from reading sensitive files
- **[Configuration]({{ '/configuration/' | relative_url }})** - customize detection rules, ignore patterns, and output formats

## Quick reference

Common commands you'll use:

```sh
# install pre-commit hook (local project)
sekretbarilo install pre-commit

# scan current directory
sekretbarilo scan

# audit git history
sekretbarilo audit

# check if a specific file contains secrets
sekretbarilo check-file path/to/file.py

# install hooks for claude code (ai agent protection)
sekretbarilo install agent-hook claude

# install all hooks at once
sekretbarilo install all
```

For help with any command:

```sh
sekretbarilo --help
sekretbarilo scan --help
sekretbarilo audit --help
```
