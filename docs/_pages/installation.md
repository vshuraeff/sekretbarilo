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
ls -la ~/.git-templates/hooks/pre-commit
```

Global hooks apply to:
- All existing repositories that don't have local hooks
- All new repositories you clone or create

After installing globally, run this in existing repositories to pick up the global hooks:

```sh
cd /path/to/existing-repo
git init
```

### Agent hooks (AI coding tool protection)

Agent hooks protect AI coding tools like Claude Code from reading files that contain secrets.

#### Install locally (single project)

```sh
# navigate to your project
cd /path/to/your-project

# install agent hooks for claude code
sekretbarilo install agent-hook claude

# verify installation
cat .claude/settings.json
```

Now when Claude Code tries to read a file, sekretbarilo checks it first and blocks access if secrets are detected.

#### Install globally (all projects)

```sh
# install globally for all projects using claude code
sekretbarilo install agent-hook claude --global

# verify installation
cat ~/.claude/settings.json
```

Global agent hooks protect all projects where Claude Code is used.

### Install all hooks at once

Install both pre-commit and agent hooks in one command:

```sh
# install all hooks locally
sekretbarilo install all

# install all hooks globally
sekretbarilo install all --global
```

This is the recommended approach for complete protection.

## Understanding global vs local installation

### Local installation

- Hooks are installed in the current project's `.git/hooks/` or `.claude/hooks/` directory
- Only affects the current repository
- Requires running `sekretbarilo install` in each project
- Takes precedence over global hooks

Use local installation when:
- You want project-specific hook behavior
- You're testing sekretbarilo before deploying globally
- Different projects need different configurations

### Global installation

- Hooks are installed in `~/.git-templates/hooks/` or `~/.claude/hooks/`
- Applies to all repositories automatically
- One-time setup for all projects
- Overridden by local hooks if present

Use global installation when:
- You want consistent protection across all projects
- You work on multiple repositories
- You want new repositories to be protected automatically

### Precedence

When both global and local hooks exist:

1. **Pre-commit hooks**: local hooks override global hooks
2. **Agent hooks**: global hooks are checked first, then local hooks

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
rm ~/.git-templates/hooks/pre-commit
```

### Remove local agent hooks

```sh
cd /path/to/your-project
rm -rf .claude/hooks
```

### Remove global agent hooks

```sh
rm -rf ~/.claude/hooks
```

## Complete setup example

Here's a complete setup for a new development environment:

```sh
# step 1: install sekretbarilo
brew install vshuraeff/tap/sekretbarilo

# step 2: install global hooks for all projects
sekretbarilo install all --global

# step 3: apply global hooks to existing repositories
cd ~/projects/my-app
git init

cd ~/projects/another-project
git init

# step 4: verify installation
cd ~/projects/my-app
ls -la .git/hooks/pre-commit
ls -la .claude/hooks/check-file

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

### Global hooks not applying

If global hooks don't work in a repository:

```sh
# re-initialize git to pick up global hooks
cd /path/to/repo
git init

# check git config for template directory
git config --global init.templateDir
# should show: ~/.git-templates

# if not set, configure it
git config --global init.templateDir ~/.git-templates
```

## Next steps

Now that sekretbarilo is installed:

- **[Getting Started]({{ '/getting-started/' | relative_url }})** - learn the basic workflow
- **[CLI Reference]({{ '/cli-reference/' | relative_url }})** - explore all available commands
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** - detailed agent hook configuration
- **[Configuration]({{ '/configuration/' | relative_url }})** - customize sekretbarilo for your needs
