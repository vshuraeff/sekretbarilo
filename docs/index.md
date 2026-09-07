---
layout: default
title: Home
---

# sekretbarilo

High-performance secret scanner for git workflows and AI coding agents. Catches API keys, credentials, and secrets in staged commits, working trees, full git history, files read by AI agents, and the patches and shell commands they write — before they leak.

*sekretbarilo* means "secret keeper" in Esperanto.

## Why sekretbarilo?

- **Fast**: a typical commit scans in ~2.5 µs, a 400-file diff in ~3.7 ms
- **112 built-in rules** organized by precision (prefix-based, context-aware, catch-all)
- **Low false positives**: Shannon entropy, stopwords, hash detection, variable reference detection
- **Pre-commit hook**: automatic scanning of staged changes on every commit
- **Working tree audit**: scan all tracked files for secrets
- **Git history audit**: scan every commit with deduplication and branch resolution
- **Agent hooks**: blocks Claude Code file reads or masks secrets in `Bash`, `Read`, and `Grep` results; blocks Codex CLI patches and shell commands carrying secrets
- **Configurable**: hierarchical `.sekretbarilo.toml` for allowlists, custom rules, and overrides
- **Zero config needed**: works out of the box with sensible defaults

## Quick start

```sh
# install via homebrew
brew install vshuraeff/tap/sekretbarilo

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

# install codex cli agent hook
sekretbarilo install agent-hook codex

# or install all hooks at once
sekretbarilo install all
```

New Claude installations use `block`: a file containing secrets is blocked before `Read`. To mask successful `Bash`, `Read`, and `Grep` text results instead, run `sekretbarilo install agent-hook claude --mode redact` (Claude Code >= 2.1.121). Source files are unchanged. Omitting `--mode` preserves the selected settings file's installed mode, including with `install all`. See [redaction coverage and limits](agent-hooks/#redact-mode-output-editor).

When Codex CLI tries to apply a patch or run a shell command that carries a secret, the tool call is blocked before it takes effect.

Codex only runs a hook once you approve it — run `/hooks` in the Codex TUI after installing, or it is skipped silently.

All agent hook modes ignore a `.sekretbarilo.toml` inside the repository until it is committed: an agent that can write files can otherwise write itself a permissive config. Redaction uses value exceptions, but ignores path exclusions and documentation relaxations. See [Configuration](configuration/#in-workspace-config-trust-agent-hooks-only).

## Documentation

| Page | Description |
|------|-------------|
| [Getting Started](getting-started/) | Introduction and quick setup |
| [Installation](installation/) | Detailed installation guide |
| [Configuration](configuration/) | Hierarchical config, allowlists, custom rules |
| [CLI Reference](cli-reference/) | Complete command and flag reference |
| [Agent Hooks](agent-hooks/) | Claude Code and Codex CLI integration details |
| [Rules Reference](rules-reference/) | All 112 built-in rules and custom rule syntax |
| [Performance](performance/) | Benchmarks and optimization details |
| [Architecture](architecture/) | Internals and design decisions |
| [Examples](examples/) | Practical workflows and configuration examples |

## License

MIT
