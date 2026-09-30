---
layout: default
title: Getting Started
nav_order: 1
---

# Getting Started

In this tutorial you install sekretbarilo, set up its pre-commit hook in a project, and see what happens when a commit carries a secret. What the tool is and why it exists are covered in [What sekretbarilo is for]({{ '/what-sekretbarilo-is-for/' | relative_url }}).

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
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** - block Claude Code file reads or mask secrets in tool results; protect Codex patches and shell commands
- **[Configuration]({{ '/configuration/' | relative_url }})** - customize detection rules, ignore patterns, and output formats
- **[Common commands]({{ '/common-commands/' | relative_url }})** - the commands you will use day to day, and where to get help
