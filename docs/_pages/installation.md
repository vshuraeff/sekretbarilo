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

sekretbarilo integrates with git through hooks. You can install hooks locally (per project) or globally (all repositories).

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

Agent hooks can block Claude Code file reads or mask secrets in its tool results, and block Codex CLI patches and shell commands containing secrets. Each agent is installed separately.

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

For a new installation this selects `block`: sekretbarilo checks files before `Read` and blocks access if secrets are detected. Reinstallation without `--mode` preserves the mode already installed in the selected settings file.

#### Claude Code: install globally (all projects)

```sh
# install globally for all projects using claude code
sekretbarilo install agent-hook claude --global

# verify installation
cat ~/.claude/settings.json
```

Global agent hooks protect all projects where Claude Code is used.

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

Mode changes affect only sekretbarilo handlers in the selected settings file. Other hooks are preserved. Installation and `doctor` warn if a blocking Read hook in the other local/global scope can prevent a result from reaching redaction. Set the intended mode explicitly in each affected scope. Read the [redaction coverage and limitations]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}) before relying on it.

`--settings <path>` installs into that exact file, mutually exclusive with `--global`; a relative path resolves against the current directory, not the repository root, and this works even outside a git repository. Writing into an arbitrary file does not by itself make Claude Code load it: Claude picks up a settings file only when it is one of its standard locations, when Claude is launched with its own `--settings <path>` flag, or when the file is the `settings.json` of the profile directory named by `CLAUDE_CONFIG_DIR`. See the [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) and the [configuration directory docs](https://code.claude.com/docs/en/claude-directory).

#### Codex CLI: install locally (single project)

```sh
# navigate to your project
cd /path/to/your-project

# install agent hooks for codex cli
sekretbarilo install agent-hook codex

# verify installation
cat .codex/hooks.json
```

Now when Codex CLI is about to apply a patch or run a shell command, sekretbarilo scans it first and blocks the tool call if secrets are detected.

#### Codex CLI: install globally (all projects)

```sh
# install globally for all projects using codex cli
sekretbarilo install agent-hook codex --global

# verify installation
cat ~/.codex/hooks.json
```

The global hook is written to `$CODEX_HOME/hooks.json`, which defaults to `~/.codex/hooks.json` when `CODEX_HOME` is unset.

#### Codex CLI: approve the hook

Installing the Codex hook is only half the job. Codex will not run a newly installed hook until you approve it, and it skips an unapproved hook **silently** — no error and no warning at the point of use, so everything looks fine while nothing is being scanned.

Start Codex and approve the hook from the TUI:

```
/hooks
```

sekretbarilo deliberately does not write the trust state for you: the trust hash is an internal Codex detail, and a security tool that grants itself trust defeats the purpose of the trust model. For non-interactive environments such as CI, Codex offers `--dangerously-bypass-hook-trust`, which skips the approval check for every hook in the session — use it only where you control the full hook configuration.

See [Agent Hooks]({{ '/agent-hooks/#hook-trust' | relative_url }}) for the details.

### Install all hooks at once

Install the pre-commit hook and every supported agent hook in one command:

```sh
# install all hooks locally
sekretbarilo install all

# install all hooks globally
sekretbarilo install all --global

# select claude redaction while installing the other hooks normally
sekretbarilo install all --mode redact
```

This covers the pre-commit hook, the Claude Code hook, and the Codex CLI hook. The Codex step is skipped with a `[SKIP]` line when `codex` is neither on `PATH` nor has a `$CODEX_HOME` directory. Omitted `--mode` preserves an existing Claude mode or uses `block` for a new install; selecting or preserving `redact` requires a supported Claude version. Follow installation with `/hooks` in Codex to approve its hook.

## Understanding global vs local installation

### Local installation

- Hooks are installed in the current project: `.git/hooks/` for pre-commit, `.claude/settings.json` for Claude Code, `.codex/hooks.json` for Codex CLI
- Only affects the current repository
- Requires running `sekretbarilo install` in each project

Use local installation when:
- You want project-specific hook behavior
- You're testing sekretbarilo before deploying globally
- Different projects need different configurations

### Global installation

- Hooks are installed in your home directory: `~/.config/git/hooks/` for pre-commit (via `core.hooksPath`), `~/.claude/settings.json` for Claude Code (or `$CLAUDE_CONFIG_DIR/settings.json` when that variable is set and non-empty), `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`) for Codex CLI
- Applies to all repositories automatically
- One-time setup for all projects

Use global installation when:
- You want consistent protection across all projects
- You work on multiple repositories
- You want new repositories to be protected automatically

### Precedence

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

# codex cli: drop the sekretbarilo PreToolUse entry
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
