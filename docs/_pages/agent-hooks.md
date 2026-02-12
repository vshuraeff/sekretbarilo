---
layout: default
title: Agent Hooks
nav_order: 5
---

# Agent Hooks

## What Are Agent Hooks

AI coding agents like Claude Code interact with your codebase by reading files to understand context, answer questions, and make suggestions. This is a powerful feature, but it introduces a security risk: **if those files contain secrets, the agent could inadvertently expose them** in conversations, logs, or generated code snippets.

sekretbarilo's agent hooks solve this problem by integrating directly into the agent's file-read pipeline. When an AI agent attempts to read a file:

1. The agent triggers a sekretbarilo hook before reading the file
2. sekretbarilo scans the file for secrets
3. If secrets are found, the read is blocked and the agent receives an error
4. If the file is clean, the read proceeds normally

This creates a security boundary that prevents sensitive data from ever reaching the agent, protecting your credentials, API keys, and other secrets from accidental exposure.

## Claude Code Integration

Claude Code is an official CLI tool from Anthropic that brings Claude AI directly into your development workflow. sekretbarilo integrates with Claude Code through its hooks system:

**Hook Configuration:**
- **Hook type**: `PreToolUse` (triggered before the Read tool executes)
- **Tool matcher**: `Read` (applies to file read operations)
- **Command**: `sekretbarilo check-file --stdin-json`
- **Timeout**: 10 seconds
- **Status message**: "Scanning file for secrets..."

When Claude Code is about to read a file, it automatically calls sekretbarilo, sends the file path as JSON on stdin, and waits for the scan result. A clean file (exit code 0) allows the read to proceed; a blocked file (exit code 2) prevents Claude Code from accessing the content.

## Installation

Install agent hooks for Claude Code using the `install` command. You can install locally (per-project) or globally (for all projects).

### Project-Local Installation

Install in the current project's `.claude/settings.json`:

```sh
sekretbarilo install agent-hook claude
```

This creates or modifies `./.claude/settings.json` in your project root. The hook only applies when Claude Code is run from this project.

### Global Installation

Install in your user-level `~/.claude/settings.json`:

```sh
sekretbarilo install agent-hook claude --global
```

This applies the hook to all projects where Claude Code runs under your user account.

### Install All Hooks at Once

To install both pre-commit hooks and agent hooks in one command:

```sh
# install locally (project pre-commit + project agent hook)
sekretbarilo install all

# install globally (global pre-commit + global agent hook)
sekretbarilo install all --global
```

The `install all` command is the fastest way to set up complete protection for both git commits and AI agent file access.

## How It Works (Pipeline)

When Claude Code reads a file, sekretbarilo executes the following pipeline:

### 1. Hook Trigger

Claude Code is about to execute the `Read` tool to read a file. The `PreToolUse` hook fires, invoking:

```sh
sekretbarilo check-file --stdin-json
```

### 2. JSON Payload

Claude Code sends a JSON payload on stdin with the file path and optional working directory:

```json
{
  "tool_input": { "file_path": "path/to/file" },
  "cwd": "/optional/working/directory"
}
```

### 3. Path Resolution

sekretbarilo parses the JSON, extracts the file path, and resolves it:
- Absolute paths are converted to relative paths when possible (using `cwd` context)
- Relative paths are resolved against `cwd` or the current directory
- Path traversal attempts (e.g., `../../etc/passwd`) are rejected

### 4. Fast-Path Check: Binary Files, Vendor Dirs, Lock Files

Before scanning, sekretbarilo checks if the file is one that cannot contain readable secrets:

**Binary extensions** (images, executables, archives):
```
.png, .jpg, .jpeg, .gif, .bmp, .svg, .ico
.pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx
.exe, .dll, .so, .dylib, .o, .bin
.zip, .tar, .gz, .bz2, .7z, .rar
.mp3, .mp4, .avi, .mov, .wav
.woff, .woff2, .ttf, .eot
```

**Vendor directories** (dependencies, generated code):
```
node_modules/, vendor/, .bundle/, bower_components/
__pycache__/, .git/, .svn/, .hg/
```

**Lock files** (package manifests, checksums):
```
package-lock.json, yarn.lock, pnpm-lock.yaml
Cargo.lock, go.sum, Gemfile.lock, poetry.lock
composer.lock, Pipfile.lock
```

If the file matches any fast-path pattern, sekretbarilo returns exit code 0 immediately without reading the file. This avoids unnecessary scanning overhead for files that pose no secret risk.

### 5. .env File Blocking

Files matching the `.env` pattern are **always blocked unconditionally**, regardless of content:

**Blocked**:
```
.env
.env.local
.env.production
.env.development
.env.staging
.env.test
```

**Allowed (safe templates)**:
```
.env.example
.env.sample
.env.template
```

`.env` files almost always contain secrets (API keys, database passwords, tokens). Rather than scan them, sekretbarilo blocks them outright to prevent any possibility of exposure.

### 6. Full Scanning

If the file passes fast-path checks and isn't a `.env` file, sekretbarilo reads it and runs the full detection engine:
- Aho-corasick keyword pre-filter identifies candidate rules
- Regex matching extracts potential secrets
- Shannon entropy analysis filters low-randomness strings
- Hash detection skips known hash formats (SHA-1, SHA-256, MD5, git commits)
- Stopword filtering removes known-safe values like `example`, `test`, `placeholder`
- Variable reference detection skips patterns like `${VAR}`, `process.env.VAR`

### 7. Exit Code

sekretbarilo returns an exit code to Claude Code:

| Exit Code | Meaning | Claude Code Action |
|-----------|---------|-------------------|
| 0 | Clean (no secrets found, or file skipped via fast-path) | Allow read |
| 2 | Secrets found, or error (file not found, JSON parse error, config failure) | Block read |

Exit code 2 is used for both secrets and errors because **failing open would let secrets through**. Claude Code treats any non-zero exit as a block.

## Stdin JSON Payload

Claude Code sends a JSON payload on stdin when the hook is triggered. sekretbarilo parses this payload to extract the file path and working directory.

### Schema

```json
{
  "tool_input": { "file_path": "path/to/file" },
  "cwd": "/optional/working/directory"
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `tool_input.file_path` | Yes | Path to the file Claude Code wants to read (absolute or relative) |
| `cwd` | No | Working directory context (used to resolve relative paths and vendor dirs) |

### Example Payloads

**Absolute path with cwd**:
```json
{
  "tool_input": { "file_path": "/home/user/project/src/config.py" },
  "cwd": "/home/user/project"
}
```

**Relative path**:
```json
{
  "tool_input": { "file_path": "src/config.py" },
  "cwd": "/home/user/project"
}
```

**Absolute path without cwd**:
```json
{
  "tool_input": { "file_path": "/home/user/project/src/config.py" }
}
```

### Extra Fields

sekretbarilo tolerates extra fields in the JSON payload and ignores them. This ensures forward compatibility if Claude Code adds new fields in the future:

```json
{
  "session_id": "abc123",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": { "file_path": "src/config.py" },
  "cwd": "/home/user/project"
}
```

### Size Limit

stdin input is limited to **1 MB** to prevent unbounded memory consumption. This is more than sufficient for JSON payloads containing file paths.

## Fast-Path Skipping

Fast-path skipping is an optimization that allows certain files to pass through without scanning. These are files that **cannot contain readable secrets** or are not secret-relevant.

### Why Fast-Path Skipping Matters

- **Performance**: skipping binary files avoids reading megabytes of image/video data
- **Accuracy**: scanning binary content produces garbage matches (false positives)
- **Usability**: AI agents need to read lock files, images, and dependencies without friction

Fast-path decisions are made based on **file path patterns only**, before the file is read. This keeps the check extremely fast.

### Binary Files

Binary files cannot contain readable secrets in a form that matters for leakage:

```
.png, .jpg, .jpeg, .gif, .bmp, .svg, .ico, .webp
.pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .odt
.exe, .dll, .so, .dylib, .a, .o, .bin, .class
.zip, .tar, .gz, .bz2, .7z, .rar, .tgz, .xz
.mp3, .mp4, .avi, .mov, .wav, .flac, .mkv
.woff, .woff2, .ttf, .eot, .otf
.db, .sqlite, .sqlite3
.min.js, .min.css, .map
```

Even if a binary file somehow embeds a secret (e.g., an API key in image metadata), it's not accessible to the AI agent in a way that creates risk.

### Vendor Directories

Vendor directories contain third-party dependencies that are not part of your codebase:

```
node_modules/
vendor/
.bundle/
bower_components/
__pycache__/
.git/
.svn/
.hg/
```

These directories often contain thousands of files. Scanning them would:
- Slow down the agent significantly
- Produce false positives from test data in dependencies
- Block legitimate reads of library code

sekretbarilo skips these paths entirely.

### Lock Files

Lock files are package manifests and checksums, not source code:

```
package-lock.json
yarn.lock
pnpm-lock.yaml
Cargo.lock
go.sum
Gemfile.lock
poetry.lock
composer.lock
Pipfile.lock
```

Lock files are often large (thousands of lines) and contain cryptographic hashes that can trigger false positives. They never contain user secrets, so they're safe to skip.

### User-Configured Patterns

In addition to built-in patterns, sekretbarilo respects user-configured allowlists and audit exclude patterns from `.sekretbarilo.toml`:

```toml
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]

[audit]
exclude_patterns = ["^build/", "^dist/"]
```

These patterns are evaluated during the fast-path check, so you can customize which files are allowed through without scanning.

## .env File Blocking

`.env` files are a special case: they are **always blocked**, regardless of content.

### Why Block .env Files?

`.env` files are designed to store secrets. They typically contain:
- Database passwords
- API keys
- Service tokens
- Encryption keys
- OAuth secrets

Allowing an AI agent to read a `.env` file is almost always a mistake. Even if the file happens to be clean at the moment, it's likely to contain secrets in the future.

### Blocked Patterns

```
.env
.env.local
.env.production
.env.development
.env.staging
.env.test
.env.ci
```

Any file whose name matches these patterns is blocked with exit code 2.

### Allowed Template Files

Template files are **not** blocked, because they contain placeholder values:

```
.env.example
.env.sample
.env.template
```

These files are safe for AI agents to read because they document the expected structure without exposing real secrets.

### Output When Blocked

When sekretbarilo blocks a `.env` file, it writes a message to stderr:

```
[AGENT] .env file blocked: /home/user/project/.env
file likely contains environment secrets. reading blocked.
```

Claude Code will see this message and inform you that the file cannot be read.

## Output Format

When `check-file` detects secrets, it writes diagnostic output to **stderr** (not stdout) with an `[AGENT]` prefix. This ensures Claude Code can display the error to you.

### Clean File (Exit 0)

No output. The file is allowed through silently.

### Secrets Detected (Exit 2)

```
[AGENT] secret(s) detected in src/config.rs

  line: 42
  rule: aws-access-key-id
  match: AK**************QA

  line: 58
  rule: generic-api-key
  match: sk_live_************************

file contains 2 secret(s). reading blocked to prevent secret exposure.
```

### Output Fields

- **line**: line number where the secret was found
- **rule**: which detection rule matched (helps identify the secret type)
- **match**: partially redacted secret (first 2 and last 2 characters visible)

### .env File Blocked

```
[AGENT] .env file blocked: .env
file likely contains environment secrets. reading blocked.
```

### Error (Exit 2)

Errors (file not found, JSON parse failure, config load failure) also produce stderr output and exit with code 2:

```
[ERROR] failed to read /path/to/missing.py: No such file or directory
```

This fail-closed behavior ensures that errors don't accidentally allow secrets through.

## Using check-file Directly

The `check-file` command can be used standalone, outside of the Claude Code hook context. This is useful for testing, CI pipelines, or integrating with other tools.

### Scan a File by Path

```sh
sekretbarilo check-file src/config.rs
```

Exit code 0 = clean, exit code 2 = secrets found.

### Read File Path from Stdin JSON (Agent Hook Mode)

Simulate the Claude Code hook payload:

```sh
echo '{"tool_input":{"file_path":"src/config.rs"}}' | sekretbarilo check-file --stdin-json
```

This is the same mode used by the agent hook.

### Example: CI Pipeline

Run `check-file` on all source files in CI:

```sh
#!/bin/sh
# scan all python files for secrets

for file in $(find src -name '*.py'); do
  sekretbarilo check-file "$file"
  if [ $? -eq 2 ]; then
    echo "secret detected in $file"
    exit 1
  fi
done

echo "all files clean"
```

### Example: Pre-Read Script

Use `check-file` in a script before opening files in an editor:

```sh
#!/bin/sh
# check file before opening in vim

sekretbarilo check-file "$1"
if [ $? -eq 2 ]; then
  echo "file contains secrets. open anyway? (y/n)"
  read -r answer
  if [ "$answer" != "y" ]; then
    exit 1
  fi
fi

vim "$1"
```

## Configuration

The `check-file` command respects all hierarchical configuration from `.sekretbarilo.toml` files. This means you can customize detection behavior for agent hooks the same way you customize pre-commit scanning.

### Hierarchical Config Discovery

Config files are loaded in priority order (highest priority last):

1. `/etc/sekretbarilo.toml` (system-wide)
2. `~/.config/sekretbarilo/sekretbarilo.toml` (user-level)
3. `~/.sekretbarilo.toml` (home directory)
4. Parent directories from `$HOME` down to project root
5. `.sekretbarilo.toml` in project root (highest priority)

Settings are merged across all levels. Scalar values (like `entropy_threshold`) use the most local value; lists (like `allowlist.paths`) are concatenated.

### Allowlists

Allowlist patterns from config are applied during fast-path checks:

```toml
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]
stopwords = ["my-safe-token"]
```

Files matching `allowlist.paths` patterns are allowed through without scanning.

### Audit Exclude Patterns

Audit exclude patterns also apply to agent hooks:

```toml
[audit]
exclude_patterns = ["^build/", "^vendor/"]
```

Files matching these patterns are skipped.

### Custom Rules

Custom detection rules are loaded and applied:

```toml
[[rules]]
id = "internal-api-key"
description = "Internal service API key"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
```

### Entropy Threshold

Override the entropy threshold globally or per-rule:

```toml
[settings]
entropy_threshold = 4.0
```

### Example: Project-Specific Stopwords

Add project-specific stopwords to reduce false positives:

```toml
[allowlist]
stopwords = ["project-test-token", "known-safe-key"]
```

These stopwords apply to both pre-commit scanning and agent hooks.

## Idempotent Installation

Running `install agent-hook claude` multiple times is safe and idempotent. sekretbarilo detects existing hooks and skips installation if already present.

### First Install

```sh
$ sekretbarilo install agent-hook claude
created claude code hook configuration
```

Writes the hook to `.claude/settings.json`.

### Second Install (Already Installed)

```sh
$ sekretbarilo install agent-hook claude
sekretbarilo already installed in claude code hooks
```

No changes are made. The existing hook is preserved.

### Upgrade (Outdated Command Detected)

If an older version of sekretbarilo installed a hook with a different command format, the new installer updates it in place:

```sh
$ sekretbarilo install agent-hook claude
updated claude code hook configuration
```

The command is replaced with the current format (`sekretbarilo check-file --stdin-json`), and the timeout and status message are updated.

### Preserves Other Hooks

If `.claude/settings.json` already contains hooks for other tools (e.g., Write, Bash), sekretbarilo preserves them:

**Before**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write",
        "hooks": [{"type": "command", "command": "echo write hook"}]
      }
    ]
  }
}
```

**After**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write",
        "hooks": [{"type": "command", "command": "echo write hook"}]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-file --stdin-json",
            "timeout": 10,
            "statusMessage": "Scanning file for secrets..."
          }
        ]
      }
    ]
  }
}
```

The existing Write hook is untouched.

## Doctor Diagnostics

The `doctor` command checks the health of your sekretbarilo installation, including agent hooks. Use it to diagnose issues with hook configuration.

### Run Doctor

```sh
sekretbarilo doctor
```

### Sample Output

```
git pre-commit hook:
  [OK] local pre-commit hook installed
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [OK] local claude code hook installed (./.claude/settings.json)
  [NOT INSTALLED] global claude code hook not found

configuration:
  [OK] no custom config files found (using defaults)
  [OK] 43 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

### What Doctor Checks (Agent Hooks)

For both local (`./.claude/settings.json`) and global (`~/.claude/settings.json`):

1. **File exists**: settings.json is present
2. **Valid JSON**: file parses correctly
3. **hooks.PreToolUse array exists**: the hooks structure is present
4. **Read matcher entry exists**: there's a PreToolUse entry for the Read tool
5. **Command matches**: the command is `sekretbarilo check-file --stdin-json`
6. **Outdated command detection**: warns if an older sekretbarilo command is found

### Status Levels

| Status | Meaning |
|--------|---------|
| `[OK]` | Check passed |
| `[WARN]` | Non-critical issue (e.g., outdated command, non-executable hook) |
| `[ERROR]` | Critical issue (e.g., malformed JSON, config parse failure) |
| `[NOT INSTALLED]` | Hook not found (informational, not an error) |

### Exit Code

- **0**: all checks passed (or only NOT INSTALLED status, which is informational)
- **1**: one or more WARN or ERROR issues found

### Example: Outdated Hook Detected

```
claude code agent hook:
  [WARN] local claude code hook has outdated sekretbarilo command: sekretbarilo scan-file --old-flag
  [NOT INSTALLED] global claude code hook not found
```

Fix by running:

```sh
sekretbarilo install agent-hook claude
```

The installer will update the command in place.

## Codex CLI Note

**Codex CLI** is another AI coding agent tool. However, Codex CLI does not currently support a hooks system like Claude Code's `PreToolUse` hooks.

The `install agent-hook codex` subcommand is **reserved for future use**. It is recognized by the CLI but not yet implemented:

```sh
$ sekretbarilo install agent-hook codex
[ERROR] codex agent hook installation not yet supported
```

### Alternative: MCP Server Approach

An alternative integration approach under consideration is running sekretbarilo as an **MCP (Model Context Protocol) tool server**. This would allow any agent that supports MCP (including Codex CLI, if it adds MCP support) to call sekretbarilo as a tool.

If you need Codex CLI integration today, consider:
- Running `check-file` manually before Codex reads sensitive files
- Using a wrapper script that calls `check-file` before invoking Codex
- Opening an issue or PR to discuss MCP server implementation

## Practical Examples

### Example 1: Developer Installs Hook, Claude Code Tries to Read .env

**Setup**:

```sh
# install agent hook
sekretbarilo install agent-hook claude

# create .env file
echo 'DB_PASSWORD=supersecret123' > .env
```

**Claude Code session**:

```
User: Read the .env file and show me the database password

Claude Code: [attempts to read .env]
[AGENT] .env file blocked: .env
file likely contains environment secrets. reading blocked.

Claude Code: I was unable to read the .env file because it was blocked by sekretbarilo. This is a security measure to prevent exposing secrets. If you need to share configuration, consider reading .env.example instead, or tell me what specific non-secret information you need.
```

**Result**: The `.env` file is never exposed to Claude Code. The developer is informed that the file was blocked.

### Example 2: Claude Code Reads a Python File with AWS Key

**Setup**:

```sh
# install agent hook
sekretbarilo install agent-hook claude

# create file with secret
cat > src/config.py << 'EOF'
import os

aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = os.environ.get('AWS_SECRET_KEY')

def init_client():
    return boto3.client('s3', aws_access_key_id=aws_access_key)
EOF
```

**Claude Code session**:

```
User: Read src/config.py and explain how the AWS client is initialized

Claude Code: [attempts to read src/config.py]
[AGENT] secret(s) detected in src/config.py

  line: 3
  rule: aws-access-key-id
  match: AK**************YZ

file contains 1 secret(s). reading blocked to prevent secret exposure.

Claude Code: I was unable to read src/config.py because it contains an AWS access key. This is a security measure to prevent accidentally exposing the key. If you'd like help with this file, please remove the hardcoded key and use environment variables instead, then I'll be able to read it.
```

**Result**: The AWS key is never exposed. Claude Code provides actionable feedback (use environment variables).

### Example 3: Claude Code Reads a Normal Source File

**Setup**:

```sh
# install agent hook
sekretbarilo install agent-hook claude

# create clean file
cat > src/utils.py << 'EOF'
import json

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def save_config(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
EOF
```

**Claude Code session**:

```
User: Read src/utils.py and explain what it does

Claude Code: [attempts to read src/utils.py]
[sekretbarilo scans silently, exits 0, no output]

Claude Code: [reads file successfully]

This module provides two utility functions for working with JSON configuration files:

1. load_config(path): Reads a JSON file and returns the parsed data
2. save_config(path, data): Writes data to a JSON file with pretty-printing (2-space indent)

The functions use Python's built-in json module and file I/O.
```

**Result**: The file passes through transparently. Claude Code reads it normally and provides the requested explanation.

### Example 4: Claude Code Reads a Binary/Lock File (Fast-Path Skip)

**Setup**:

```sh
# install agent hook
sekretbarilo install agent-hook claude

# copy a real lock file (thousands of lines)
cp package-lock.json /tmp/test-lock.json
```

**Claude Code session**:

```
User: Read package-lock.json and tell me which version of react is installed

Claude Code: [attempts to read package-lock.json]
[sekretbarilo fast-path detects lock file, exits 0 immediately, no scanning]

Claude Code: [reads file successfully]

The project is using React version 18.2.0. It's listed as a direct dependency with the following details:
- Version: 18.2.0
- Resolved from: https://registry.npmjs.org/react/-/react-18.2.0.tgz
- Integrity: sha512-...
...
```

**Result**: The lock file is recognized during fast-path checks and allowed through without scanning. The read completes quickly with no overhead, and Claude Code can answer the question normally.

## Troubleshooting

### Hook Not Firing

**Symptom**: Claude Code reads files without triggering sekretbarilo.

**Check**:
1. Verify hook is installed: `sekretbarilo doctor`
2. Check `.claude/settings.json` exists and contains the hook
3. Ensure sekretbarilo binary is in PATH: `which sekretbarilo`
4. Test `check-file` manually: `sekretbarilo check-file path/to/file`

### Hook Fails with "command not found"

**Symptom**: Claude Code shows error: `sekretbarilo: command not found`.

**Fix**:
1. Add sekretbarilo to PATH: `export PATH="$HOME/.cargo/bin:$PATH"`
2. Or use absolute path in hook: edit `.claude/settings.json` and change command to `/full/path/to/sekretbarilo check-file --stdin-json`

### False Positives Blocking Clean Files

**Symptom**: sekretbarilo blocks a file that doesn't contain real secrets.

**Fix**:
1. Add the false positive value to stopwords in `.sekretbarilo.toml`:
   ```toml
   [allowlist]
   stopwords = ["known-safe-value"]
   ```
2. Or allowlist the file path:
   ```toml
   [allowlist]
   paths = ["path/to/false-positive-file.py"]
   ```

### Slow Hook Execution

**Symptom**: Claude Code shows "Scanning file for secrets..." for several seconds.

**Check**:
1. Verify fast-path patterns are working: binary files, vendor dirs, and lock files should skip instantly
2. Large source files (>10k lines) may take longer to scan
3. Check if custom rules have expensive regexes

**Fix**:
- Exclude large generated files in `.sekretbarilo.toml`:
  ```toml
  [audit]
  exclude_patterns = ["^build/", "^dist/"]
  ```

### Hook Installed but doctor Shows Outdated

**Symptom**: `sekretbarilo doctor` reports outdated command.

**Fix**:
Run the installer again to update the command:
```sh
sekretbarilo install agent-hook claude
```

This will detect the outdated command and replace it with the current format.

---

## Summary

Agent hooks provide a critical security layer for AI-assisted development:

- **Prevent secret exposure**: Block file reads before secrets reach the agent
- **Fast and unobtrusive**: Fast-path skipping ensures minimal overhead for binary files, dependencies, and lock files
- **Comprehensive coverage**: All detection rules, allowlists, and config apply to agent hooks
- **Easy installation**: One command installs the hook for Claude Code
- **Diagnostic support**: `doctor` command validates hook configuration

Install agent hooks today to protect your secrets from accidental exposure through AI coding agents:

```sh
# project-local
sekretbarilo install agent-hook claude

# global
sekretbarilo install agent-hook claude --global

# or install everything at once
sekretbarilo install all --global
```

For more information, see:
- [Getting Started]({{ '/getting-started/' | relative_url }}) - Overview and quick setup
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - Complete command reference
- [Configuration]({{ '/configuration/' | relative_url }}) - Customizing detection rules and allowlists
