---
title: Common commands
description: The handful of commands used day to day, and the help flags for everything else.
section: reference
---

## Everyday commands

Common commands you'll use:

```sh
# install pre-commit hook (local project)
sekretbarilo install pre-commit

# scan the staged diff
sekretbarilo scan

# audit the working tree (add --history to scan git history instead)
sekretbarilo audit

# check if a specific file contains secrets
sekretbarilo check-file path/to/file.py

# install hooks for claude code (ai agent protection)
sekretbarilo install agent-hook claude

# mask claude Bash/Read/Grep results (requires claude >= 2.1.121)
sekretbarilo install agent-hook claude --mode redact

# install all hooks at once
sekretbarilo install all
```

## Help

For help with any command:

```sh
sekretbarilo --help
sekretbarilo scan --help
sekretbarilo audit --help
```

Every command and flag is described in the [CLI reference]({{ '/cli-reference/' | relative_url }}).
