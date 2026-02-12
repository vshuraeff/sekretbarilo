---
layout: default
title: Home
---

# sekretbarilo

High-performance secret scanner for git workflows and AI coding agents. Catches API keys, credentials, and secrets in staged commits, working trees, full git history, and files read by AI agents — before they leak.

*sekretbarilo* means "secret keeper" in Esperanto.

## Why sekretbarilo?

- **Fast**: a typical commit scans in ~2.5 us, a 400-file diff in ~3.7 ms
- **43 built-in rules** organized by precision (prefix-based, context-aware, catch-all)
- **Low false positives**: Shannon entropy, stopwords, hash detection, variable reference detection
- **Pre-commit hook**: automatic scanning of staged changes on every commit
- **Working tree audit**: scan all tracked files for secrets
- **Git history audit**: scan every commit with deduplication and branch resolution
- **Agent hooks**: prevents AI coding agents (Claude Code) from reading files with secrets
- **Configurable**: hierarchical `.sekretbarilo.toml` for allowlists, custom rules, and overrides
- **Zero config needed**: works out of the box with sensible defaults

## Quick start

```sh
# install from source
cargo install --path .

# set up pre-commit hook
cd your-project
sekretbarilo install pre-commit

# every commit is now scanned automatically
```

When a secret is detected, the commit is blocked:

```
[ERROR] secret detected in staged changes

  file: config.py
  line: 3
  rule: aws-access-key-id
  match: AK**************QA

commit blocked. 1 secret(s) found.
use `git commit --no-verify` to bypass (not recommended).
```

## Protect AI agents too

```sh
# install claude code agent hook
sekretbarilo install agent-hook claude

# or install all hooks at once
sekretbarilo install all
```

When Claude Code tries to read a file containing secrets, the read is blocked before the agent sees the content.

## Documentation

| Page | Description |
|------|-------------|
| [Getting Started](getting-started/) | Introduction and quick setup |
| [Installation](installation/) | Detailed installation guide |
| [Configuration](configuration/) | Hierarchical config, allowlists, custom rules |
| [CLI Reference](cli-reference/) | Complete command and flag reference |
| [Agent Hooks](agent-hooks/) | Claude Code integration details |
| [Rules Reference](rules-reference/) | All 43 built-in rules and custom rule syntax |
| [Performance](performance/) | Benchmarks and optimization details |
| [Architecture](architecture/) | Internals and design decisions |
| [Examples](examples/) | Practical workflows and configuration examples |

## License

MIT
