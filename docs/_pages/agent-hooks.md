---
layout: default
title: Agent Hooks
nav_order: 5
---

# Agent Hooks

## What Are Agent Hooks

AI coding agents interact with your codebase in two directions: they **read** files to understand context, and they **write** patches and run shell commands to act on it. Both directions leak secrets. A file the agent reads can carry a credential into conversations, logs, and generated snippets; a patch or a shell command the agent writes can put a fresh credential into your repository.

sekretbarilo integrates into the agent's tool pipeline. Blocking hooks run before a tool call executes:

1. The agent triggers a sekretbarilo hook
2. sekretbarilo scans the file, the patch, or the command
3. If secrets are found, the tool call is blocked and the agent is told why
4. If it is clean, the tool call proceeds normally

| Agent / mode | Coverage | Event / tools | Hook command |
|--------------|----------|---------------|--------------|
| Claude Code `block` | blocks file reads | `PreToolUse` / `Read` | `<absolute-path-to-running-sekretbarilo> check-file --stdin-json` |
| Claude Code `redact` | masks successful text results | `PostToolUse` / `Bash`, `Read`, `Grep` | `<absolute-path-to-running-sekretbarilo> redact-claude --stdin-json` |
| Codex CLI | blocks patches and shell commands | `PreToolUse` / `apply_patch`, `Bash` | `sekretbarilo check-codex --stdin-json` |

In Claude `redact` mode, the tool executes normally and sekretbarilo edits its result in memory before it reaches the model. Coverage depends on the selected tools, detectors, and the hook runtime; see the limitations for each integration below.

## Claude Code Integration

Claude Code is an official CLI tool from Anthropic that brings Claude AI directly into your development workflow. sekretbarilo integrates with Claude Code through its hooks system:

### Block Mode

`block` is the default for a new installation. **Hook configuration:**

- **Hook type**: `PreToolUse` (triggered before the Read tool executes)
- **Tool matcher**: `Read` (applies to file read operations)
- **Command**: `<absolute-path-to-running-sekretbarilo> check-file --stdin-json`
- **Timeout**: 10 seconds
- **Status message**: "Scanning file for secrets..."

When Claude Code is about to read a file, it automatically calls sekretbarilo, sends the file path as JSON on stdin, and waits for the scan result. A clean file (exit code 0) allows the read to proceed; a blocked file (exit code 2) prevents Claude Code from accessing the content.

### Redact Mode: Output Editor

Install with `sekretbarilo install agent-hook claude --mode redact`. This mode requires Claude Code **2.1.121 or later**, which introduced replacement of built-in tool output through `hookSpecificOutput.updatedToolOutput`. The installer checks the installed version before modifying Claude settings; an unknown or unsupported version leaves the previous protection in place. See the [Claude hook contract](https://code.claude.com/docs/en/hooks#posttooluse-decision-control) and [2.1.121 release notes](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md#21121).

The hook is synchronous, runs on successful `PostToolUse` events, matches `^(Bash|Read|Grep)$`, and has a 10-second timeout. **Editor** means editing the returned text in memory. The tool runs normally and source files are unchanged; this mode does not edit files on disk or prevent a Bash command's side effects.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "^(Bash|Read|Grep)$",
        "hooks": [
          {
            "type": "command",
            "command": "<absolute-path-to-running-sekretbarilo> redact-claude --stdin-json",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The scanner processes supported text inside `tool_response`, using the [tool output schemas](https://code.claude.com/docs/en/agent-sdk/typescript#tool-output-types):

| Tool | Text scanned |
|------|--------------|
| `Bash` | `stdout`, `stderr`, and text content blocks |
| `Read` | Text-file content; images, PDFs, and notebooks are outside this version's scope |
| `Grep` | Returned content, result lines, and filename arrays across `content`, `files_with_matches`, and `count` modes; counters are preserved |

Only supported text fields change. The replacement preserves the original JSON structure, service fields, and unknown metadata, because Claude falls back to the original output when replacement validation fails. Unknown metadata is preserved, not scanned as arbitrary text.

For example, a Bash response containing `host = localhost`, a detected password assignment, and `port = 5432` becomes:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "updatedToolOutput": {
      "stdout": "host = localhost\npassword = \"[REDACTED]\"\nport = 5432\n",
      "stderr": "",
      "interrupted": false
    }
  }
}
```

The whole captured secret value becomes `[REDACTED]`; no prefix or suffix remains. Repeated findings are masked and overlapping ranges are merged. Surrounding text and UTF-8 are preserved, as are CR, LF, and CRLF line endings, including line breaks inside a multiline secret. PEM and PGP headers extend the masked range through the corresponding end marker. If the end marker is missing, masking covers the remainder of that text field. Public-key blocks receive the same treatment when `detect_public_keys` is enabled. With public-key detection disabled, an unterminated public-key header does not suppress scanning of the remaining output.

`redact` uses the current rules, custom capture groups, entropy thresholds, password heuristics, stopwords, and per-rule value exceptions through the trusted configuration loader. Path allowlists, audit path exclusions, and documentation relaxations do **not** apply to tool output. An `.env` file is scanned by its returned content, rather than blocked by its filename. This mode includes a bounded [generic high-entropy-value detector]({{ '/rules-reference/#tier-3-catch-all-rules' | relative_url }}) for long, high-entropy, non-whitespace values regardless of variable name; it does not search for every random-looking string.

Environment dumps and similar tool output also redact eligible high-entropy values regardless of the variable name. Some harmless high-entropy data, such as base64 blobs or checksums, may be redacted; use `[allowlist].stopwords` or a per-rule `[[allowlist.rules]]` `regexes` exception to suppress a specific case. An in-workspace `.sekretbarilo.toml` exception must be committed before hooks honor it; see [Config Inside the Repository Must Be Committed]({{ '/agent-hooks/#config-inside-the-repository-must-be-committed' | relative_url }}).

#### Output and Errors

`sekretbarilo redact-claude --stdin-json` requires the flag and reads the hook payload from stdin. A clean result exits 0 with no stdout. A masked result exits 0 with replacement JSON on stdout.

Input and the complete serialized hook response are each limited to **10 MiB (10,485,760 bytes)**. Parsing, configuration, scanning, and size errors return exit 0 with `continue: false` and a fixed safe `stopReason`. When the response structure is available and the fallback fits the limit, the error response also replaces all supported text with redacted text. Diagnostics never include original secret values. If stdout cannot accept the JSON, the command exits 1 with a fixed safe stderr message when that channel is writable. Closed output channels are handled without panicking, but a response that cannot be delivered cannot provide a masking guarantee.

Exit 2 is not a way to remove PostToolUse output: the tool has already executed. Stopping continuation is also not a substitute for a valid replacement when the original result exists.

#### Limits of This Version

- Only successful `PostToolUse` results from `Bash`, text `Read`, and `Grep` are supported. `PostToolUseFailure` does not offer this replacement contract.
- MCP tools, images, PDFs, notebooks, and results delivered through other tools are outside scope. There is no separate command to edit source files.
- Redaction does not remove original data from tool-side telemetry or other storage outside the model-facing replacement.
- A hook crash, timeout, failure to deliver output, or another hook replacing the same result can leave the original output exposed. These cases are outside the masking guarantee. Claude's fallback for an invalid replacement also matters; preserving response structure is required.
- Detection is rule-based and uses configured value exceptions. A secret not detected by those rules is not masked.
- Password assignments support double quotes, single quotes, backticks, and unquoted values. Unquoted captures end at whitespace or a syntax delimiter; escaped whitespace and delimiters remain part of the value. Quote values that contain literal delimiters. Existing password-strength and placeholder filters still apply.
- Ambiguous raw versus escaped quotes can mask adjacent text: a backslash before a possible closing single quote or backtick favors the longer escaped interpretation. Password assignments with multiline or mixed shell quoting are not parsed. See [password rules]({{ '/rules-reference/#tier-2-context-aware-rules' | relative_url }}) for detection boundaries.

These boundaries follow the [Claude hooks lifecycle and failure behavior](https://code.claude.com/docs/en/hooks).

#### Synthetic Smoke Check

Verified with the sekretbarilo 0.6.0 release build and Claude Code 2.1.261 on 2026-09-05: a synthetic AWS key and passwords without quotes and in double, single, and backtick quotes were masked in the model-visible results of Bash, text Read, and Grep content mode. The source file remained unchanged. Other result shapes and error cases are covered by the automated hook tests.

Use a disposable project and a synthetic credential that matches an enabled detector. Keep the synthetic value out of the prompt so the model cannot recover it from the request itself.

1. Check `claude --version`, install with `--mode redact`, and run `sekretbarilo doctor`. Resolve any local/global blocking-hook conflict.
2. Create a text fixture containing safe surrounding lines and the synthetic credential, and record its checksum outside Claude.
3. In a fresh Claude session, ask it to inspect the fixture separately with `Bash` (`cat`), `Read`, and `Grep` in content mode. Check that each tool was actually used and the model receives `[REDACTED]` with the safe lines intact.
4. Repeat with Bash output on stderr, Grep's file/count modes, repeated secrets, and a multiline key fixture. Inspect the actual tool results, not only the model's final paraphrase.
5. Compare the fixture checksum afterward. The file must be unchanged.

## Codex CLI Integration

Codex CLI is OpenAI's terminal coding agent. It has a hooks system of its own, and sekretbarilo integrates with it through a `PreToolUse` hook:

**Hook Configuration:**
- **Hook type**: `PreToolUse` (triggered before the matched tool executes)
- **Tool matcher**: `^(apply_patch|Bash)$` — the matcher is a regex, not a literal tool name
- **Command**: `sekretbarilo check-codex --stdin-json`
- **Timeout**: 10 seconds
- **Status message**: "Scanning tool input for secrets..."
- **Config file**: `hooks.json`, global or project-local (see [Where the Configuration Lives](#where-the-configuration-lives))

Where the Claude Code hook guards the read direction, the Codex hook guards the write direction: it inspects the changes the agent is about to apply and the shell commands it is about to run. You never invoke `check-codex` yourself — Codex calls it and sends the `PreToolUse` payload on stdin.

`--stdin-json` is **mandatory** for `check-codex`. The bare command has no other input to read, so it refuses rather than guessing:

```sh
$ sekretbarilo check-codex
[ERROR] check-codex reads its payload from stdin and requires --stdin-json
```

The command the installer writes already includes the flag, so an existing installation needs no change.

Two things about this integration are easy to get wrong, and both are covered below: **an installed hook does not run until you approve it** (see [Hook Trust](#hook-trust)), and the hook **cannot stop Codex from reading a file** (see [Limitations](#limitations)).

### What the Hook Covers

**`apply_patch`** — sekretbarilo parses the patch and scans the lines being **added**. Context lines and removed lines are parsed and then discarded, so deleting an existing secret never blocks the patch. Target paths that cannot hold a meaningful secret are skipped, using the same set `check-file` uses: binary extensions, vendor directories, lock files, generated files, and anything matching your configured path patterns.

A patch that only renames a file — `*** Update File:` followed by `*** Move to:` with no change lines — adds nothing, so it is accepted.

The `.env` policy is checked first, before any configuration is loaded. A patch writing to a `.env` file is blocked outright regardless of its content, and **no allowlist entry can override it** — the same rule the pre-commit hook and `check-file` enforce. For a move, it is enough that either the original path or the destination is a blocked `.env` name, so renaming a file *into* `.env` is blocked even though the patch itself carries no added lines. The safe templates `.env.example`, `.env.sample`, and `.env.template` remain allowed.

**`Bash`** — sekretbarilo scans the raw command string. This catches the usual ways a secret ends up on a command line:

```sh
# an exported credential
export AWS_SECRET_ACCESS_KEY=...

# a bearer token in a request header
curl -H "Authorization: Bearer ..." https://api.example.com/v1/status

# a heredoc writing secrets into a file
cat > config.yml << 'EOF'
api_key: ...
EOF
```

### Blocking

The hook blocks by exiting with code 2 and writing the reason to stderr. Codex surfaces that reason to the model, so the agent learns why the patch or command was refused and can correct itself instead of retrying blindly. Secret values in the reason are masked (first two and last two characters), exactly as in every other sekretbarilo output.

| Exit Code | Meaning | Codex Action |
|-----------|---------|--------------|
| 0 | no secrets in the patch or command | Allow the tool call |
| 2 | secrets found, `.env` target, or error | Block the tool call |

A secret block looks like this:

```
[AGENT] Codex apply_patch blocked: secret(s) detected
  file: config.py
  line: 1
  rule: aws-access-key-id
  match: AK****************FG
  file: config.py
  line: 2
  rule: aws-secret-access-key
  match: wJ************************************+a
apply_patch action blocked to prevent secret exposure. total findings: 2.
```

A `Bash` block has the same shape, with `Bash` in place of `apply_patch` and the pseudo-path `<bash-command>` instead of a file. A `.env` block is shorter, because no scanning took place:

```
[AGENT] Codex apply_patch blocked by .env policy
  file: .env
.env files may contain environment secrets; writing was blocked.
```

#### The Reason Is Capped at 20 Findings

A patch that adds a hundred credentials would otherwise produce a hundred-entry reason string, which is then injected into the model's context. Only the first 20 findings are rendered; the rest are summarized:

```
  ... (20 findings)
... and 5 more finding(s) omitted
apply_patch action blocked to prevent secret exposure. total findings: 25.
```

The cap affects the reason text only. The decision is still a block, and the `total findings:` count on the last line is the true total — that line is present on every secret block, capped or not.

#### Attacker-Controlled Strings Are Sanitized

The file paths and rule names in the reason come from the patch, which the agent wrote. They pass through the same control-character and bidirectional-override stripping the audit output uses before being printed. A path such as `spoof\u001b[2K\rname\u202e.rs` is reported as `spoof[2Kname.rs`: the escape, the carriage return, and the right-to-left override are gone.

This matters more here than elsewhere, because the reason has two audiences that both interpret escape sequences — the terminal it is printed to, and the model whose context it lands in. A rule name that can move the cursor is a rule name that can rewrite what the block appears to say.

#### Payload Size

The hook reads at most 10 MiB from stdin. An oversized `PreToolUse` payload is rejected and the tool call blocked, rather than scanned in part — the same fail-closed choice made everywhere else:

```
Codex hook payload truncated: input exceeds 10485760 bytes
```

Claude `block` mode (`check-file`) has a smaller 1 MB cap because it receives a file path. Claude `redact` mode limits both its input and serialized response to 10 MiB.

### Where the Configuration Lives

sekretbarilo writes the hook into a `hooks.json` file:

| Scope | Path |
|-------|------|
| Global (`--global`) | `$CODEX_HOME/hooks.json`, defaulting to `~/.codex/hooks.json` when `CODEX_HOME` is unset |
| Project-local (default) | `.codex/hooks.json` in the repository root |

Layers are **additive**: when a global hook and a project hook are both present, Codex runs both. This is different from pre-commit hooks, where a local hook overrides the global one.

This is what sekretbarilo writes:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(apply_patch|Bash)$",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-codex --stdin-json",
            "timeout": 10,
            "statusMessage": "Scanning tool input for secrets..."
          }
        ]
      }
    ]
  }
}
```

Points worth knowing if you ever hand-edit the file:

- The root object accepts exactly two keys, `hooks` and `description`, and **rejects anything else**. An unrecognised top-level key makes Codex drop that layer's hooks entirely — with only a log warning and nothing visible at the point of use. A typo at the root silently disarms every hook in that file.
- Event keys are PascalCase (`PreToolUse`).
- `timeout` is in **seconds**, and defaults to 600 when omitted.
- `statusMessage` is camelCase.
- `matcher` is a regex and is optional; omitting it matches every tool.
- It is standard JSON: no comments, no trailing commas.

Codex CLI `0.145.0` has no `hooks list` or `hooks validate` subcommand, so there is no way to ask Codex whether it accepted your file. It does have a `codex doctor`, but that diagnoses installation, config, auth, and runtime health — it does not look at `hooks.json`. `sekretbarilo doctor` is the check available.

Codex also accepts a second, equivalent representation of the same hooks — a `[hooks]` table in the `config.toml` of the same layer. sekretbarilo deliberately writes only `hooks.json` and never touches `config.toml`. If you already keep hooks in `config.toml`, expect to see a second hook definition appear in `hooks.json`; that is the sekretbarilo one. When both representations exist in a single layer, Codex loads both and prints a warning.

### Hook Trust

**Codex does not run a newly installed hook until you approve it.** An unapproved hook is skipped silently — no error, no warning at the point of use — so the installation looks complete while nothing is actually being scanned. This is the single most common reason for "I installed the hook and it never fires".

Approve the hook from the Codex TUI:

```
/hooks
```

sekretbarilo does not write the trust state for you, and this is deliberate:

- the trust hash is an internal, undocumented Codex implementation detail — writing it means guessing at a format that can change in any release;
- a security tool that grants itself trust defeats the purpose of the trust model. The approval has to come from a human.

Codex records the approval in a `[hooks.state]` table inside the `config.toml` of the user layer, keyed by source file path, event, and index.

For non-interactive environments where no one can answer a prompt — CI jobs, containers, automation — Codex offers `--dangerously-bypass-hook-trust`, which runs hooks without approval. It disables the trust check for *every* hook in that session, not just sekretbarilo's, so use it only where you fully control the hook configuration. Interactively, approve through `/hooks` instead.

### Version Requirements

The integration is verified against codex-cli `0.145.0`. Older releases may not deliver `PreToolUse` for `apply_patch`. If patches are being applied without ever reaching sekretbarilo, upgrade Codex CLI before debugging anything else.

### Limitations

The Codex hook is a narrower instrument than the Claude Code hook. Know what it does not do:

- **No read protection.** Codex's hook surface has no equivalent of Claude Code's `Read` tool, so there is no way to stop the agent from *reading* a file that contains a secret. This is an upstream capability gap, not a sekretbarilo choice.
- **The `Bash` check is textual.** The command string is scanned as text. sekretbarilo does not parse shell syntax, does not expand variables, and does not analyse redirect targets, so the check can be circumvented deliberately. Treat it as a guardrail against accidental leakage, not as a sandbox.
- **Write direction only.** Coverage is `apply_patch` and `Bash`. Nothing else Codex does is intercepted.

## Installation

Install agent hooks using the `install` command, one agent at a time. Each hook can be installed locally (per-project) or globally (for all projects).

### Project-Local Installation (Claude Code)

Install in the current project's `.claude/settings.json`:

```sh
sekretbarilo install agent-hook claude
```

This creates or modifies `./.claude/settings.json` in your project root. The hook only applies when Claude Code is run from this project.

### Global Installation (Claude Code)

Install in your user-level `~/.claude/settings.json`:

```sh
sekretbarilo install agent-hook claude --global
```

This applies the hook to all projects where Claude Code runs under your user account.

### Selecting and Switching Claude Modes

```sh
sekretbarilo install agent-hook claude --mode redact
sekretbarilo install agent-hook claude --mode block
sekretbarilo install agent-hook claude --mode redact --global
sekretbarilo install agent-hook claude --settings .claude/settings.local.json --mode redact
```

Without `--mode`, installation preserves the mode already present in the selected settings file; a new installation uses `block`. `install all` follows the same rule and accepts `--mode block|redact` for its Claude step. `--mode` does not change Codex behavior.

Switching modes replaces only sekretbarilo's handlers in the selected file, atomically and without duplicates. Other hooks and their order are preserved. It does not switch hooks in another settings scope. A global blocking Read hook can still block a read before a local redaction hook gets any result, and the reverse scope combination has the same issue. Installation and `doctor` report this conflict; choose the intended mode explicitly in each affected scope.

**Targeting an explicit file.** `--settings <path>` installs into exactly that file instead of the local or global default, and is mutually exclusive with `--global`. A relative path resolves against the current directory of the invocation, not the repository root, and the flag works outside a git repository too; the file is created if absent, and existing content and other hooks are preserved exactly as with the default locations. Scope-conflict warnings from installation and `doctor` treat the explicit file as one more scope alongside local and global.

Writing into an arbitrary file does not register a new Claude Code profile by itself: Claude only loads a settings file when it is one of its standard locations, when Claude is launched with its own `--settings <path>` flag, or when the file is the `settings.json` of the profile directory named by `CLAUDE_CONFIG_DIR`. See the [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) and the [configuration directory docs](https://code.claude.com/docs/en/claude-directory). `sekretbarilo doctor --settings <path>` inspects the file's contents; it is not proof that a running Claude Code session has actually loaded it.

### Project-Local Installation (Codex CLI)

Install in the current project's `.codex/hooks.json`:

```sh
sekretbarilo install agent-hook codex
```

This creates or modifies `.codex/hooks.json` in your repository root. The hook only applies when Codex CLI runs in this project.

### Global Installation (Codex CLI)

Install in your user-level Codex configuration directory:

```sh
sekretbarilo install agent-hook codex --global
```

This writes `$CODEX_HOME/hooks.json` — `~/.codex/hooks.json` when `CODEX_HOME` is unset — and applies to every project where Codex CLI runs under your user account.

> **Installing is not enough.** Codex will not run the hook until you approve it with `/hooks` in the Codex TUI, and it says nothing when it skips an unapproved hook. See [Hook Trust](#hook-trust).

### Install All Hooks at Once

To install the pre-commit hook and every supported agent hook in one command:

```sh
# install locally (project pre-commit + project agent hooks)
sekretbarilo install all

# install globally (global pre-commit + global agent hooks)
sekretbarilo install all --global
```

`install all` covers the pre-commit hook, the Claude Code hook, and the Codex CLI hook, in that order, reporting each one as it goes.

Only the Codex step is conditional. Codex is looked for on `PATH` and at `$CODEX_HOME` (default `~/.codex`); when neither is present the step is skipped rather than failing:

```
installing codex cli agent hook...
[SKIP] codex cli not detected on this machine; skipping codex agent hook install
```

In `block` mode, the Claude settings file can be installed even when Claude Code is absent. Selecting or preserving `redact` requires a known supported Claude version before the Claude settings can change.

Remember to approve the Codex hook afterwards with `/hooks`.

## How It Works (Claude Code Block Pipeline)

The following pipeline, path policies, and `check-file` examples describe Claude `block` mode. For tool-output masking, see [Redact Mode](#redact-mode-output-editor).

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
.png, .jpg, .jpeg, .gif, .bmp, .svg, .ico, .webp
.pdf
.exe, .dll, .so, .dylib
.zip, .tar, .gz, .bz2, .7z, .rar, .xz
.mp3, .mp4, .avi, .mov, .wav, .webm, .ogg
.woff, .woff2, .ttf, .eot, .otf
.min.js, .min.css
```

**Vendor directories** (dependencies, generated code):
```
node_modules/, vendor/, .bundle/, bower_components/
__pycache__/, .git/
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

Exit code 2 is used for both secrets and errors to block the `Read` call through `PreToolUse`.

## Stdin JSON Payload

In `block` mode, Claude Code sends a JSON payload on stdin when the hook is triggered. `check-file` parses this payload to extract the file path and working directory.

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

Fast-path skipping applies to `check-file` / Claude `block` mode and file-based scans, not `redact`. It allows files considered low-risk by the configured path policy to pass through without scanning.

### Why Fast-Path Skipping Matters

- **Performance**: skipping binary files avoids reading megabytes of image/video data
- **Accuracy**: scanning binary content produces garbage matches (false positives)
- **Usability**: AI agents need to read lock files, images, and dependencies without friction

Fast-path decisions are made based on **file path patterns only**, before the file is read. This keeps the check extremely fast.

### Binary Files

Binary files cannot contain readable secrets in a form that matters for leakage. The complete list:

```
images        .png, .jpg, .jpeg, .gif, .bmp, .svg, .ico, .webp
documents     .pdf
executables   .exe, .dll, .so, .dylib
archives      .zip, .tar, .gz, .bz2, .7z, .rar, .xz
media         .mp3, .mp4, .avi, .mov, .wav, .webm, .ogg
fonts         .woff, .woff2, .ttf, .eot, .otf
generated     .min.js, .min.css
```

Even if a binary file somehow embeds a secret (e.g., an API key in image metadata), it's not accessible to the AI agent in a way that creates risk.

Extensions outside this list are scanned, including ones that are usually binary — `.o`, `.class`, `.jar`, `.wasm`, `.db`, `.sqlite`, `.tgz`, `.docx`, `.flac`. Scanning a compressed or binary file is cheap and finds nothing, so the fast path stays deliberately short rather than trying to enumerate every binary format in existence. Add your own entries under `[allowlist] paths` if a particular format shows up often enough to matter.

### Vendor Directories

Vendor directories contain third-party dependencies that are not part of your codebase:

```
node_modules/
vendor/
.bundle/
bower_components/
__pycache__/
.git/
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
[AGENT] secret(s) detected in src/config.py

  file: src/config.py
  line: 1
  rule: aws-access-key-id
  match: AK****************FG

  file: src/config.py
  line: 2
  rule: stripe-secret-key-live
  match: sk*******************************ij

file contains 2 secret(s). reading blocked to prevent secret exposure.
```

### Output Fields

- **file**: path of the scanned file
- **line**: line number where the secret was found
- **rule**: which detection rule matched (helps identify the secret type)
- **match**: partially redacted secret (first 2 and last 2 characters visible)

One line can produce more than one finding when several rules match it — a Stripe key, for example, matches both the specific `stripe-secret-key-live` rule and the catch-all `generic-api-key`.

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

`check-file`, `check-codex`, and `redact-claude` load hierarchical configuration from `.sekretbarilo.toml` files through the trusted loader. Custom rules, stopwords, value exceptions, and entropy thresholds apply across the hooks. Path policy differs by command, as described below.

### Config Inside the Repository Must Be Committed

The agent hooks — and only the agent hooks — require a `.sekretbarilo.toml` **inside the git working tree** to be git-tracked and unmodified relative to `HEAD`. An untracked or dirty in-workspace config is dropped whole, with one line on stderr:

```
[WARN] ignoring untrusted in-workspace config: /home/user/project/.sekretbarilo.toml
```

The reason is the obvious attack: an agent that can write files can write a permissive config, and that patch carries no secret, so it passes. Requiring a commit puts a human between the agent and the rules the agent is checked against.

Layers above the repo root — a parent directory, `~/.sekretbarilo.toml`, the XDG user config, `/etc/sekretbarilo.toml` — are loaded normally, and `scan`/`audit` are not affected at all. If a value exception works under `sekretbarilo audit` but the hook still detects it, check whether the config is committed. Full detail in [Configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }}).

### Path Allowlists and Tool Text

**Path allowlists do not apply to Codex `Bash` command text or any Claude `redact` output.** `[allowlist] paths` and per-rule `paths` cannot suppress findings in those text modes. Stopwords, per-rule value regexes, entropy thresholds, and `detect_public_keys` still apply. Path allowlists work normally for `apply_patch` target paths and `check-file`. Redaction also ignores audit path exclusions and documentation-specific relaxations.

### Hierarchical Config Discovery

Config files are loaded in priority order (highest priority last):

1. `/etc/sekretbarilo.toml` (system-wide)
2. `~/.config/sekretbarilo/sekretbarilo.toml` (user-level)
3. `~/.sekretbarilo.toml` (home directory)
4. Parent directories from `$HOME` down to project root
5. `.sekretbarilo.toml` in project root (highest priority)

Settings are merged across all levels. Scalar values (like `entropy_threshold`) use the most local value; lists (like `allowlist.paths`) are concatenated.

### Allowlists

In `check-file` and Codex patch scanning, path allowlist patterns apply during fast-path checks:

```toml
[allowlist]
paths = ["test/fixtures/.*", "docs/examples/.*"]
stopwords = ["my-safe-token"]
```

Files matching `allowlist.paths` patterns are allowed through without scanning in those file-based modes. `redact` still scans their returned text.

### Audit Exclude Patterns

Audit exclude patterns also apply to file-based agent scanning, but not `redact`:

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

Running an `install agent-hook` command multiple times is safe. Both installers detect an existing hook and report one of three outcomes.

### First Install

```sh
$ sekretbarilo install agent-hook claude
[OK] created claude code hook configuration
```

Writes the hook to `.claude/settings.json`.

### Second Install (Already Installed)

```sh
$ sekretbarilo install agent-hook claude
[OK] sekretbarilo already installed in claude code hooks
```

No changes are made when the existing handler is current. Its mode is preserved when `--mode` is omitted.

### Upgrade (Outdated Command Detected)

If an older version of sekretbarilo installed a hook with a different command format, the new installer updates it in place:

```sh
$ sekretbarilo install agent-hook claude
[OK] updated claude code hook configuration
```

The installer writes the absolute path reported by the OS for the running executable, followed by `check-file --stdin-json` for `block` or `redact-claude --stdin-json` for `redact`, and quotes shell-sensitive paths. On macOS, an invocation through a symlink such as Homebrew's `/usr/local/bin/sekretbarilo` keeps that symlink path. On Linux, `current_exe` reports the resolved target, so Homebrew-on-Linux records a Cellar path; `brew upgrade` then breaks the hook when that target disappears, until `sekretbarilo install agent-hook claude` is rerun from the new binary. Doctor reports the old path as a missing target. If the executable path cannot be read or is not valid UTF-8, installation warns and falls back to the bare `sekretbarilo` command. Doctor warns for a bare command because Claude Code resolves it with its own `PATH`. For an absolute command, doctor checks filesystem metadata, requires a regular executable file, and compares its canonical identity with the running binary; it never executes the configured path and never claims its version. Redaction version validation happens before changing the file, and duplicate sekretbarilo handlers are removed without disturbing other handlers.

### The Codex Installer

The Codex installer has the same three outcomes, worded for its own target:

```sh
$ sekretbarilo install agent-hook codex
[OK] created codex cli hook configuration
[WARN] IMPORTANT: Codex will silently skip this hook until you approve it.
       In the Codex TUI, run /hooks and approve the sekretbarilo hook.
       For non-interactive automation only, --dangerously-bypass-hook-trust bypasses this protection.
[INFO] detected Codex version: codex-cli 0.145.0
```

Re-running it reports `[OK] sekretbarilo already installed in codex cli hooks`; finding an older command in `hooks.json` produces `[OK] updated codex cli hook configuration`. Existing hooks in the file are preserved either way, as with Claude Code — a `PreToolUse` group of your own stays where it is, and sekretbarilo's group is appended after it.

The trust reminder is printed on **every** run, including the already-installed one, because installing and approving are separate steps and only the first is something sekretbarilo can do (see [Hook Trust](#hook-trust)).

The last line reports what sekretbarilo could see of Codex itself. When the `codex` binary is not on `PATH`, it changes to a warning that the file was written but the tool was not found:

```
[NOTE] hook file was written to ./.codex/hooks.json, but Codex was not found on PATH
```

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
            "command": "<absolute-path-to-running-sekretbarilo> check-file --stdin-json",
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
  [NOT INSTALLED] local pre-commit hook not found
  [NOT INSTALLED] global pre-commit hook not found

claude code agent hook:
  [NOT INSTALLED] local claude code hook not found
  [NOT INSTALLED] global claude code hook not found

codex cli agent hook:
  [NOT INSTALLED] local codex cli hook not found
  [NOT INSTALLED] global codex cli hook not found
  [OK] codex found in PATH (codex-cli 0.145.0)

configuration:
  [OK] no custom config files found (using defaults)
  [OK] 113 rules loaded successfully
  [OK] rules compile successfully

sekretbarilo binary:
  [OK] sekretbarilo found in PATH
```

Five groups, each printed with the same status labels. The codex group carries an extra line for the `codex` binary itself, with its version when it can be read.

### What Doctor Checks (Claude Code Hook)

For both local (`./.claude/settings.json`) and global (`~/.claude/settings.json`):

1. **File exists**: settings.json is present
2. **Valid JSON**: file parses correctly
3. **Mode and event**: finds sekretbarilo handlers across events, including `PreToolUse` and `PostToolUse`
4. **Matcher and command**: checks `Read` / `check-file --stdin-json` for `block`, or `^(Bash|Read|Grep)$` / `redact-claude --stdin-json` for `redact`
5. **Hook settings**: checks the mode's configuration, including synchronous redaction and timeout
6. **Outdated command detection**: warns if an older sekretbarilo command is found
7. **Stale duplicate detection**: warns if a second, older sekretbarilo handler is left behind at another position in the file
8. **Scope conflict**: warns when a blocking Read hook in another scope can prevent a redaction hook from receiving the result
9. **Explicit scope (`--settings <path>`)**: when given, inspects that file as an additional scope next to local and global, deduplicated when it is the same file; the same mode, Claude Code redact-version, and scope-conflict checks apply, doctor never creates or edits the file, and a missing or malformed file is reported as an issue
10. **Bare hook binary command**: warns that Claude Code resolves the name under its own `PATH` and that reinstalling pins an absolute path; doctor does not resolve it under its own `PATH`
11. **Absolute hook binary command**: checks the path's filesystem metadata and executable bit, then canonicalizes it only to compare its identity with the running binary; doctor never executes the configured path and never reports a version for it

### What Doctor Checks (Codex CLI Hook)

For both local (`./.codex/hooks.json`) and global (`$CODEX_HOME/hooks.json`, by default `~/.codex/hooks.json`):

1. **File exists**: hooks.json is present
2. **Valid JSON**: file parses correctly
3. **PreToolUse entry exists**: the hooks structure is present under the `hooks` root key
4. **Matcher covers the tools**: the entry matches `apply_patch` and `Bash`
5. **Command matches**: the command is `sekretbarilo check-codex --stdin-json`
6. **Unrecognised root key**: warns if `hooks.json` has a top-level key other than `hooks` or `description`, which makes Codex discard that file's hooks entirely
7. **Approval entry**: looks for the `[hooks.state]` entry Codex writes when you approve the hook
8. **Codex on PATH**: reports the `codex` binary and its version

Doctor also reports, in the **configuration** group, any in-workspace `.sekretbarilo.toml` that is untracked or has uncommitted changes — the agent hooks ignore such a layer entirely. See [Config Inside the Repository Must Be Committed](#config-inside-the-repository-must-be-committed).

#### The Approval Check Is Positional

Codex keys its approval by source file, event, and **index** — `<path>:pre_tool_use:<group>:<handler>`. Doctor looks for the key matching the position sekretbarilo's hook actually occupies. That distinction matters on a machine that already has Codex hooks of its own: sekretbarilo's group is appended after them, so it sits at a non-zero group index and needs its **own** approval. Approving somebody else's hook, or approving ours before the indices shifted, does not count:

```
  [WARN] local codex cli hook: an approval entry exists in ~/.codex/config.toml but not for this hook's position (group 1, handler 0); codex silently skips unapproved hooks; the indices may have shifted; re-approve with /hooks in the Codex TUI
```

A found entry is reported as OK, with a caveat, because Codex re-checks its own trust hash at run time:

```
  [OK] local codex cli hook approval entry found in ~/.codex/config.toml (group 0, handler 0); codex re-checks its own trust hash at run time, so this is not proof the hook runs
```

Doctor reports whether the hook is *installed* and whether an approval entry *exists*. Whether Codex will actually run it stays Codex's decision, so confirm with `/hooks` in the Codex TUI. See [Hook Trust](#hook-trust). Codex CLI has no hook-validation subcommand of its own, which makes `doctor` the only mechanical check available on the sekretbarilo side.

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

## Practical Examples

The sessions below are illustrative: they show the sequence of events and how the agent reacts, not literal program output.

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

# create file with a real (not placeholder) aws key on line 3
cat > src/config.py << 'EOF'
import os

aws_access_key = "AKIA...."          # a live key id, not a documentation placeholder
aws_secret_key = os.environ.get('AWS_SECRET_KEY')

def init_client():
    return boto3.client('s3', aws_access_key_id=aws_access_key)
EOF
```

> The key has to be a real one for this example to work. `AKIAIOSFODNN7EXAMPLE`, the key from AWS's own documentation, is allowlisted by a built-in rule allowlist and passes through untouched.

**Claude Code session**:

```
User: Read src/config.py and explain how the AWS client is initialized

Claude Code: [attempts to read src/config.py]
[AGENT] secret(s) detected in src/config.py

  file: src/config.py
  line: 3
  rule: aws-access-key-id
  match: AK****************YZ

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

### Example 5: Codex CLI Tries to Write a Secret into .env

**Setup**:

```sh
# install and approve the codex hook
sekretbarilo install agent-hook codex
# then, inside codex: /hooks -> approve
```

**Codex session**:

```
User: Put my AWS credentials in .env so the deploy script can read them

Codex: [attempts apply_patch on .env]
[sekretbarilo blocks the patch: .env target, exit 2, reason on stderr]

Codex: I can't write to .env — sekretbarilo blocks patches targeting .env files
outright, because they are where credentials end up. If you want the deploy
script configured, I can add the variable names to .env.example and read the
values from your shell environment at deploy time instead.
```

**Result**: The credential never reaches the repository. Codex sees the reason, so it proposes a workable alternative instead of retrying the same patch.

### Example 6: Codex CLI Runs a Shell Command Containing a Token

**Setup**:

```sh
sekretbarilo install agent-hook codex --global
# then, inside codex: /hooks -> approve
```

**Codex session**:

```
User: Check whether the staging API is up, here's my token: sk_live_...

Codex: [attempts Bash: curl -H "Authorization: Bearer sk_live_..." https://staging.example.com/health]
[sekretbarilo blocks the command: secret in command string, exit 2, masked in the reason]

Codex: That request would put a live API token on the command line, where it
lands in shell history and process listings. sekretbarilo blocked it. Export the
token as an environment variable first and I'll reference it as
"$STAGING_TOKEN" in the request header.
```

**Result**: The token is not written into shell history or a process list. The value quoted back in the block reason is masked, so it is not re-exposed by the error itself.

### Example 7: Codex CLI Applies a Clean Patch

**Setup**:

```sh
sekretbarilo install agent-hook codex
# then, inside codex: /hooks -> approve
```

**Codex session**:

```
User: Add a retry wrapper around the HTTP client in src/client.py

Codex: [attempts apply_patch on src/client.py]
[sekretbarilo scans the added lines, finds nothing, exits 0]

Codex: [patch applied]

Added a retry wrapper with exponential backoff around the request call, retrying
on connection errors and 5xx responses up to three times.
```

**Result**: The patch passes through transparently. Ordinary edits carry no friction — only the lines being added are scanned, and clean lines produce no output at all.

## Troubleshooting

### Claude Code Hook Not Firing

**Symptom**: Claude Code reads files without triggering sekretbarilo.

These checks describe `block` mode. For `redact`, verify the synchronous `PostToolUse` handler, supported Claude version, and actual tool result using the [synthetic smoke check](#synthetic-smoke-check). Successful redaction lets the tool run; it does not block the call.

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
2. In `block` mode, you can instead allowlist the file path (`redact` ignores path exclusions):
   ```toml
   [allowlist]
   paths = ["path/to/false-positive-file.py"]
   ```
3. **Commit the config.** A `.sekretbarilo.toml` inside the repository is ignored by the agent hooks until it is git-tracked and clean, so an edit that has not been committed yet changes nothing. `sekretbarilo doctor` says so explicitly, and the hook prints `[WARN] ignoring untrusted in-workspace config: ...` on every run. See [Config Inside the Repository Must Be Committed](#config-inside-the-repository-must-be-committed).

### Slow Hook Execution

**Symptom**: Claude Code shows "Scanning file for secrets..." for several seconds.

The fast-path and exclusion advice below applies to `block` mode. Redaction scans supported output text regardless of its source path and uses a 10 MiB input/response limit.

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

### Codex CLI Hook Not Firing

**Symptom**: Codex applies patches and runs commands without triggering sekretbarilo, and nothing is reported anywhere.

**Check, in this order**:

1. **Approve the hook.** This is the usual cause. Run `/hooks` in the Codex TUI and approve the sekretbarilo entry. An unapproved hook is skipped without any message — see [Hook Trust](#hook-trust). If you already approved it once, approve it again: the approval is tied to the hook's position in the file, and adding or removing another hook shifts it.
2. **Verify it is installed**: `sekretbarilo doctor` reports the local and global codex groups, and tells you whether it can find an approval entry for the position your hook occupies. Codex itself has no `hooks list` or `hooks validate` command to cross-check with.
3. **Check the layer you expect**: project-local hooks live in `.codex/hooks.json` at the repository root, global ones in `$CODEX_HOME/hooks.json` (by default `~/.codex/hooks.json`). If you installed globally but run Codex somewhere with its own configuration, check both.
4. **Look for a stray root key** if you edited `hooks.json` by hand. Only `hooks` and `description` are accepted at the root; anything else makes Codex discard that file's hooks completely, with no visible error.
5. **Check the Codex version**: `codex --version`. The integration is verified on `0.145.0`; older releases may not deliver `PreToolUse` for `apply_patch`.
6. **Ensure the binary is in PATH**: `which sekretbarilo`. The hook command is resolved by Codex, in Codex's environment.

### Codex Warns About Duplicate Hook Definitions

**Symptom**: Codex prints a warning that hooks are defined in more than one place.

**Cause**: the same layer has both a `hooks.json` file and a `[hooks]` table in `config.toml`. Codex loads both representations and warns. sekretbarilo only ever writes `hooks.json`, so the `config.toml` definition is one you (or another tool) added.

**Fix**: keep your hooks in one representation. If you consolidate into `config.toml`, note that re-running `sekretbarilo install agent-hook codex` will write `hooks.json` again.

### Codex Blocks a Patch or Command You Know Is Safe

**Symptom**: a patch containing a fixture value, or a command containing a harmless-looking high-entropy string, is refused.

**Fix**: `check-codex` reads the same `.sekretbarilo.toml` hierarchy as every other command, so the same allowlist tools apply:

```toml
[allowlist]
stopwords = ["known-safe-value"]
paths = ["test/fixtures/.*"]
```

Commit the config afterwards — an uncommitted `.sekretbarilo.toml` inside the repository is ignored by `check-codex` entirely.

Three things that will not work, however hard you try:

- **An uncommitted in-workspace config.** The layer is dropped whole, and the hook says so on stderr. See [Config Inside the Repository Must Be Committed](#config-inside-the-repository-must-be-committed).
- **A path allowlist against a `Bash` block.** `paths` entries are ignored when scanning command text — use `stopwords` or a per-rule value regex instead. For `apply_patch`, `paths` works as usual against the patch target.
- **Anything against a `.env` block.** The `.env` check runs before configuration is even loaded, so no allowlist entry changes it. Write to `.env.example` instead, or set the value in your shell rather than through the agent.

---

## Summary

Agent hooks provide a critical security layer for AI-assisted development:

- **Claude modes**: Block file reads or mask detected secrets in successful Bash/Read/Grep text results
- **Prevent secret injection**: Block patches and shell commands that would write secrets through Codex CLI
- **File scanning fast paths**: Skip configured binary, dependency, and lock-file paths in `block` mode
- **Shared detectors**: Rules and value exceptions apply to all hook modes; redaction ignores path exclusions and documentation relaxations
- **Configuration the agent cannot rewrite**: an in-workspace `.sekretbarilo.toml` counts only once it is committed
- **Easy installation**: One command per agent, or `install all` for everything at once
- **Diagnostic support**: `doctor` command validates hook configuration for both agents

Install agent hooks today to protect your secrets from accidental exposure through AI coding agents:

```sh
# project-local
sekretbarilo install agent-hook claude
sekretbarilo install agent-hook codex

# global
sekretbarilo install agent-hook claude --global
sekretbarilo install agent-hook codex --global

# or install everything at once
sekretbarilo install all --global
```

Then approve the Codex hook with `/hooks` in the Codex TUI — until you do, Codex skips it silently.

For more information, see:
- [Getting Started]({{ '/getting-started/' | relative_url }}) - Overview and quick setup
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - Complete command reference
- [Configuration]({{ '/configuration/' | relative_url }}) - Customizing detection rules and allowlists
