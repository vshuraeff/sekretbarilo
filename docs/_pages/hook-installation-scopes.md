---
title: Global and local hook installation
description: What a local and a global installation each change, when to choose which, which hook wins when both exist, and why re-running an install is safe.
section: explanation
---

Every sekretbarilo hook can be installed for one project or for every project under your account. The commands are in [Installation]({{ '/installation/' | relative_url }}); this page explains what each choice changes.

## Local installation

- Hooks are installed in the current project: `.git/hooks/` for pre-commit, `.claude/settings.json` for Claude Code, `.codex/hooks.json` for Codex CLI
- Only affects the current repository
- Requires running `sekretbarilo install` in each project

Use local installation when:
- You want project-specific hook behavior
- You're testing sekretbarilo before deploying globally
- Different projects need different configurations

## Global installation

- Hooks are installed in your home directory: `~/.config/git/hooks/` for pre-commit (via `core.hooksPath`), `~/.claude/settings.json` for Claude Code (or `$CLAUDE_CONFIG_DIR/settings.json` when that variable is set and non-empty), `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`) for Codex CLI
- Applies to all repositories automatically
- One-time setup for all projects

Use global installation when:
- You want consistent protection across all projects
- You work on multiple repositories
- You want new repositories to be protected automatically

## Precedence

When both global and local hooks exist:

1. **Pre-commit hooks**: the global one wins, and completely. `core.hooksPath` replaces `.git/hooks/` instead of layering with it, so once a global hook is installed, per-repository pre-commit hooks stop running everywhere. `sekretbarilo install pre-commit` without `--global` then writes to that same global file, because `git rev-parse --git-path hooks` resolves to it. Unset `core.hooksPath` if you want per-repository hooks back.
2. **Claude Code hooks**: sekretbarilo writes to whichever scope you choose and leaves the other alone; which files Claude Code loads and in what order is Claude Code's own settings behavior.
3. **Codex CLI hooks**: layers are additive — a global hook and a project hook both run

## Idempotent installation

sekretbarilo's install command is idempotent - safe to run multiple times:

```sh
# running this multiple times is safe
sekretbarilo install pre-commit
sekretbarilo install pre-commit
sekretbarilo install pre-commit

# no errors, hook is simply updated if needed
```

This means you can:
- Re-run installation to update hooks after upgrading sekretbarilo
- Include installation in setup scripts without worry
- Run install commands in CI/CD pipelines

What each agent-hook installer prints on a first install, a repeat install and an upgrade is listed under [Idempotent Installation]({{ '/agent-hooks/#idempotent-installation' | relative_url }}) in the agent hooks reference.

## Further reading

- [Installation]({{ '/installation/' | relative_url }}) for the install and uninstall commands of every hook.
- [How the agent hooks work]({{ '/how-agent-hooks-work/' | relative_url }}) for what the agent hooks guard and why.
- [Troubleshooting reference]({{ '/troubleshooting/' | relative_url }}) for a hook that does not run where you expect it.
