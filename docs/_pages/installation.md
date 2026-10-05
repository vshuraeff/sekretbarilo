---
layout: default
title: Installation
nav_order: 2
---

# Installation

This guide covers everything you need to install and configure sekretbarilo for your projects.

## Installing sekretbarilo

### Homebrew (recommended)

```sh
brew install vshuraeff/tap/sekretbarilo
```

Pre-built binaries for macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64). To update:

```sh
brew upgrade vshuraeff/tap/sekretbarilo
```

### GitHub Releases

Download pre-built binaries from the [releases page](https://github.com/vshuraeff/sekretbarilo/releases). Available targets:

- `aarch64-apple-darwin` (macOS Apple Silicon)
- `x86_64-apple-darwin` (macOS Intel)
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux ARM64)
- `.deb` packages for Debian/Ubuntu (amd64 + arm64)

### From source

If you have the Rust toolchain installed:

```sh
cd /path/to/sekretbarilo
cargo install --path .
```

This compiles and installs the `sekretbarilo` binary to your Cargo bin directory (typically `~/.cargo/bin`).

### Build from repository

Clone and build from scratch:

```sh
# clone the repository
git clone https://github.com/vshuraeff/sekretbarilo.git
cd sekretbarilo

# build release binary
cargo build --release

# binary is now at target/release/sekretbarilo
# optionally, install it to your path
cargo install --path .
```

### Verify installation

Confirm sekretbarilo is installed and accessible:

```sh
sekretbarilo --version
```

You should see the version number. You can also check the help output:

```sh
sekretbarilo --help
```

## Installing git hooks

sekretbarilo integrates with git through hooks. You can install hooks locally (per project) or globally (all repositories). What each choice changes, which hook wins when both exist, and why re-running an install is safe are explained in [Global and local hook installation]({{ '/hook-installation-scopes/' | relative_url }}).

### Pre-commit hooks

Pre-commit hooks scan staged changes before each commit, blocking commits that contain secrets.

#### Install locally (single project)

```sh
# navigate to your project
cd /path/to/your-project

# install pre-commit hook
sekretbarilo install pre-commit

# verify installation
ls -la .git/hooks/pre-commit
```

The hook is now active for this project only.

#### Install globally (all repositories)

```sh
# install globally for all git repositories
sekretbarilo install pre-commit --global

# verify installation
ls -la ~/.config/git/hooks/pre-commit
```

The global hook works through git's `core.hooksPath`. sekretbarilo writes the hook into the directory that `git config --global core.hooksPath` names, and sets that setting to `~/.config/git/hooks` when you have not configured one yourself.

That takes effect immediately, in every repository, with nothing to run afterwards — no `git init`, no template directory, no re-clone.

It also **replaces** per-repository hooks rather than layering with them. While `core.hooksPath` is set, git looks only there, so an existing `.git/hooks/pre-commit` in any repository stops running. If you need a repository to keep its own hooks, unset the global setting:

```sh
git config --global --unset core.hooksPath
```

### Agent hooks (AI coding tool protection)

Agent hooks can block Claude Code file reads or mask secrets in its tool results, block Codex CLI patches and shell commands containing secrets, and withhold Codex shell output that contains secrets. Each agent is installed separately.

> One thing to know before you tune them: a `.sekretbarilo.toml` inside the repository is honored by the agent hooks only once it is committed. An uncommitted config is ignored entirely, because an agent can write one. See [Configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }}).

#### Claude Code: install locally (single project)

```sh
# navigate to your project
cd /path/to/your-project

# install agent hooks for claude code
sekretbarilo install agent-hook claude

# verify installation
cat .claude/settings.json
```

This creates or modifies `./.claude/settings.json` in your project root. The hook only applies when Claude Code is run from this project.

For a new installation this selects `block`: sekretbarilo checks files before `Read` and blocks access if secrets are detected. Reinstallation without `--mode` preserves the mode already installed in the selected settings file.

#### Claude Code: install globally (all projects)

```sh
# install globally for all projects using claude code
sekretbarilo install agent-hook claude --global

# verify installation
cat ~/.claude/settings.json
```

This applies the hook to all projects where Claude Code runs under your user account.

#### Claude Code: choose output redaction

```sh
# inspect the installed claude version
claude --version

# mask successful Bash, Read, and Grep text results in this project
sekretbarilo install agent-hook claude --mode redact

# or select redaction globally
sekretbarilo install agent-hook claude --mode redact --global

# return this project to blocking reads
sekretbarilo install agent-hook claude --mode block

# target an explicit settings file instead of the local/global default
sekretbarilo install agent-hook claude --settings .claude/settings.local.json --mode redact
```

`redact` requires Claude Code >= 2.1.121. A missing, unknown, or older version prevents the installer from changing the previous Claude protection. The synchronous `PostToolUse` hook uses a 10-second timeout; it replaces detected values with `[REDACTED]` in memory and preserves source files and response structure.

Without `--mode`, installation preserves the mode already present in the selected settings file; a new installation uses `block`. `install all` follows the same rule and accepts `--mode block|redact` for its Claude step. `--mode` does not change Codex behavior.

Switching modes replaces only sekretbarilo's handlers in the selected file, atomically and without duplicates. Other hooks and their order are preserved. It does not switch hooks in another settings scope. A global blocking Read hook can still block a read before a local redaction hook gets any result, and the reverse scope combination has the same issue. Installation and `doctor` report this conflict; choose the intended mode explicitly in each affected scope. Read the [redaction coverage and limitations]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}) before relying on it.

**Targeting an explicit file.** `--settings <path>` installs into exactly that file instead of the local or global default, and is mutually exclusive with `--global`. A relative path resolves against the current directory of the invocation, not the repository root, and the flag works outside a git repository too; the file is created if absent, and existing content and other hooks are preserved exactly as with the default locations. Scope-conflict warnings from installation and `doctor` treat the explicit file as one more scope alongside local and global.

Writing into an arbitrary file does not register a new Claude Code profile by itself: Claude only loads a settings file when it is one of its standard locations, when Claude is launched with its own `--settings <path>` flag, or when the file is the `settings.json` of the profile directory named by `CLAUDE_CONFIG_DIR`. See the [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) and the [configuration directory docs](https://code.claude.com/docs/en/claude-directory). `sekretbarilo doctor --settings <path>` inspects the file's contents; it is not proof that a running Claude Code session has actually loaded it.

#### Codex CLI: install locally (single project)

```sh
# navigate to your project
cd /path/to/your-project

# install agent hooks for codex cli
sekretbarilo install agent-hook codex

# verify installation
cat .codex/hooks.json
```

This creates or modifies `.codex/hooks.json` in your repository root. The hook only applies when Codex CLI runs in this project.

Now when Codex CLI is about to apply a patch or run a shell command, sekretbarilo scans it first and blocks the tool call if secrets are detected.

#### Codex CLI: install globally (all projects)

```sh
# install globally for all projects using codex cli
sekretbarilo install agent-hook codex --global

# verify installation
cat ~/.codex/hooks.json
```

This writes `$CODEX_HOME/hooks.json` — `~/.codex/hooks.json` when `CODEX_HOME` is unset — and applies to every project where Codex CLI runs under your user account.

#### Codex CLI: approve the hook

Installing the Codex hook is only half the job. Codex will not run a newly installed hook until you approve it, and it skips an unapproved hook **silently** — no error and no warning at the point of use, so everything looks fine while nothing is being scanned.

Start Codex and approve both sekretbarilo hooks, the `PreToolUse` one and the `PostToolUse` one, from the TUI:

```
/hooks
```

sekretbarilo deliberately does not write the trust state for you: the trust hash is an internal Codex detail, and a security tool that grants itself trust defeats the purpose of the trust model. For non-interactive environments such as CI, Codex offers `--dangerously-bypass-hook-trust`, which skips the approval check for every hook in the session — use it only where you control the full hook configuration.

See [Agent Hooks]({{ '/agent-hooks/#hook-trust' | relative_url }}) for the details.

### Install all hooks at once

Install the pre-commit hook and every supported agent hook in one command:

```sh
# install locally (project pre-commit + project agent hooks)
sekretbarilo install all

# install globally (global pre-commit + global agent hooks)
sekretbarilo install all --global

# select claude redaction while installing the other hooks normally
sekretbarilo install all --mode redact
```

`install all` covers the pre-commit hook, the Claude Code hook, and the Codex CLI hook, in that order, reporting each one as it goes.

Only the Codex step is conditional. Codex is looked for on `PATH` and at `$CODEX_HOME` (default `~/.codex`); when neither is present the step is skipped with a `[SKIP]` line rather than failing:

```
installing codex cli agent hook...
[SKIP] codex cli not detected on this machine; skipping codex agent hook install
```

Omitted `--mode` preserves an existing Claude mode or uses `block` for a new install. In `block` mode, the Claude settings file can be installed even when Claude Code is absent. Selecting or preserving `redact` requires a known supported Claude version before the Claude settings can change.

Follow installation with `/hooks` in Codex to approve its hook.

## Uninstalling hooks

To remove sekretbarilo hooks, manually delete the hook files:

### Remove local pre-commit hook

```sh
cd /path/to/your-project
rm .git/hooks/pre-commit
```

### Remove global pre-commit hook

```sh
# the directory is whatever core.hooksPath names, ~/.config/git/hooks by default
rm "$(git config --global core.hooksPath)/pre-commit"

# optionally stop redirecting hooks altogether
git config --global --unset core.hooksPath
```

### Remove local agent hooks

Agent hooks live inside configuration files that may hold settings of your own, so remove the sekretbarilo entry rather than the file:

```sh
cd /path/to/your-project

# claude code: drop the Read matcher entry from hooks.PreToolUse
$EDITOR .claude/settings.json

# codex cli: drop the sekretbarilo PreToolUse and PostToolUse entries
$EDITOR .codex/hooks.json
```

### Remove global agent hooks

```sh
# claude code
$EDITOR ~/.claude/settings.json

# codex cli ($CODEX_HOME/hooks.json, by default the path below)
$EDITOR ~/.codex/hooks.json
```

Codex keeps its own approval record in the `[hooks.state]` table of the user-layer `config.toml`. A stale entry there is harmless once the hook itself is gone.

## Complete setup example

Here's a complete setup for a new development environment:

```sh
# step 1: install sekretbarilo
brew install vshuraeff/tap/sekretbarilo

# step 2: install global hooks for all projects
#         the pre-commit hook takes effect in every repository immediately
sekretbarilo install all --global

# step 3: verify installation
cd ~/projects/my-app
ls -la "$(git config --global core.hooksPath)/pre-commit"
sekretbarilo doctor

# step 4: approve the codex hook (inside the codex tui)
#   /hooks

# done - all current and future projects are protected
```

## Troubleshooting

The checks below cover installation problems. For an agent hook that is installed but misbehaves, see [Troubleshoot the agent hooks]({{ '/troubleshoot-agent-hooks/' | relative_url }}).

### Hook not running

If the pre-commit hook doesn't run when you commit:

```sh
# check if the hook file exists
ls -la .git/hooks/pre-commit

# check if it's executable
chmod +x .git/hooks/pre-commit

# check if git is skipping hooks (environment variable)
echo $GIT_HOOKS_DISABLED

# try a test commit
git commit --allow-empty -m "test commit"
```

### Permission denied

If you get permission errors:

```sh
# make the hook executable
chmod +x .git/hooks/pre-commit

# verify permissions
ls -la .git/hooks/pre-commit
# should show: -rwxr-xr-x
```

### Command not found

If `sekretbarilo` command is not found:

```sh
# ensure cargo bin is in your PATH
echo $PATH | grep cargo

# add to PATH if needed (add to ~/.bashrc or ~/.zshrc)
export PATH="$HOME/.cargo/bin:$PATH"

# reload shell configuration
source ~/.bashrc  # or source ~/.zshrc

# verify
which sekretbarilo
sekretbarilo --version
```

### Codex hook installed but never runs

If `sekretbarilo doctor` reports the Codex hook as installed but patches and commands are never scanned, the hook has almost certainly not been approved:

```sh
# 1. approve the hook from the codex tui
#    /hooks

# 2. confirm the file codex actually reads
cat .codex/hooks.json     # project-local
cat ~/.codex/hooks.json   # global ($CODEX_HOME/hooks.json)

# 3. check the codex version - verified on 0.145.0
codex --version

# 4. make sure codex can find the binary
which sekretbarilo
```

An unapproved hook is skipped without any message, which is why nothing appears in the Codex output. Codex has no command that validates a hooks file, so `sekretbarilo doctor` is the check to rely on. If you edited `hooks.json` by hand, also confirm the root object contains nothing but `hooks` and `description` — any other root key makes Codex discard that file's hooks silently.

### Global hooks not applying

If the global pre-commit hook doesn't run in a repository:

```sh
# 1. check where git is looking for hooks
git config --global core.hooksPath
# should show the directory sekretbarilo installed into, e.g. ~/.config/git/hooks

# 2. confirm the hook is there and executable
ls -la "$(git config --global core.hooksPath)/pre-commit"

# 3. confirm this repository resolves to the same directory
git rev-parse --git-path hooks

# 4. a local core.hooksPath overrides the global one
git config --local core.hooksPath
```

If step 1 prints nothing, the global install never set it — re-run `sekretbarilo install pre-commit --global`.

## Next steps

Now that sekretbarilo is installed:

- **[Getting Started]({{ '/getting-started/' | relative_url }})** - learn the basic workflow
- **[CLI Reference]({{ '/cli-reference/' | relative_url }})** - explore all available commands
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** - detailed agent hook configuration
- **[Configuration]({{ '/configuration/' | relative_url }})** - customize sekretbarilo for your needs
- **[Global and local hook installation]({{ '/hook-installation-scopes/' | relative_url }})** - what each scope changes and which hook wins
