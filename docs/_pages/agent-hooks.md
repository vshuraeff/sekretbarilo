---
layout: default
title: Agent Hooks
nav_order: 5
---

# Agent Hooks

This page is the reference for the agent hooks: what each hook intercepts, how it is configured, what it prints, its exit codes, and what `doctor` checks. Why the hooks are built this way, with illustrated sessions, is in [How the agent hooks work]({{ '/how-agent-hooks-work/' | relative_url }}). Installation steps are in [Installation]({{ '/installation/#agent-hooks-ai-coding-tool-protection' | relative_url }}), step-by-step fixes in [Troubleshoot the agent hooks]({{ '/troubleshoot-agent-hooks/' | relative_url }}), and running `check-file` by hand in [Scan a single file with check-file]({{ '/scan-a-file-with-check-file/' | relative_url }}).

## Supported Agents and Modes

| Agent / mode | Coverage | Event / tools | Hook command |
|--------------|----------|---------------|--------------|
| Claude Code `block` | blocks file reads | `PreToolUse` / `Read` | `<absolute-path-to-running-sekretbarilo> check-file --stdin-json` |
| Claude Code `redact` | masks successful text results | `PostToolUse` / `Bash`, `Read`, `Grep` | `<absolute-path-to-running-sekretbarilo> redact-claude --stdin-json` |
| Codex CLI | blocks patches and shell commands | `PreToolUse` / `apply_patch`, `Bash` | `sekretbarilo check-codex --stdin-json` |
| Codex CLI | withholds completed shell output that contains secrets | `PostToolUse` / `Bash` | `sekretbarilo check-codex --stdin-json` |

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

`redact` uses the current rules, custom capture groups, entropy thresholds, password heuristics, stopwords, and per-rule value exceptions through the trusted configuration loader. Path allowlists, audit path exclusions, and documentation relaxations do **not** apply to tool output. An `.env` file is scanned by its returned content, rather than blocked by its filename. From 0.9.0, this mode disables the keywordless heuristic rule by default. Prefix-less random tokens, such as bare `printenv` output, are not masked unless another enabled rule matches. Opt in through `[settings.rules]` with `"generic-high-entropy-value" = true` (or `[settings.rule_classes]` with `heuristic = true`) in a trusted configuration layer. Once enabled, it uses a bounded [generic high-entropy-value detector]({{ '/rules-reference/#heuristic-rules' | relative_url }}) for long, high-entropy, non-whitespace values regardless of variable name; it does not search for every random-looking string.

With the heuristic rule enabled, environment dumps and similar tool output also redact eligible high-entropy values regardless of the variable name. Some harmless high-entropy data, such as base64 blobs or checksums, may be redacted; use `[allowlist].stopwords` or a per-rule `[[allowlist.rules]]` `regexes` exception to suppress a specific case. An in-workspace `.sekretbarilo.toml` exception must be committed before hooks honor it; see [Config Inside the Repository Must Be Committed]({{ '/agent-hooks/#config-inside-the-repository-must-be-committed' | relative_url }}).

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
- Ambiguous raw versus escaped quotes can mask adjacent text: a backslash before a possible closing single quote or backtick favors the longer escaped interpretation. Password assignments with multiline or mixed shell quoting are not parsed. See [password rules]({{ '/rules-reference/#context-based-rules' | relative_url }}) for detection boundaries.

These boundaries follow the [Claude hooks lifecycle and failure behavior](https://code.claude.com/docs/en/hooks).

To confirm redaction end to end on your own machine, see [Verify redaction with a synthetic smoke check]({{ '/verify-redaction/' | relative_url }}).

## Codex CLI Integration

Codex CLI is OpenAI's terminal coding agent. It has a hooks system of its own, and sekretbarilo integrates with it through two hooks that run the same command:

**Hook Configuration:**
- **`PreToolUse`** (before the matched tool executes): matcher `^(apply_patch|Bash)$`, status message "Scanning tool input for secrets..."
- **`PostToolUse`** (after a `Bash` command has finished, before its output reaches the model): matcher `^Bash$`, status message "Scanning tool output for secrets..."
- **Command**: `sekretbarilo check-codex --stdin-json` for both; the matcher is a regex, not a literal tool name
- **Timeout**: 10 seconds
- **Config file**: `hooks.json`, global or project-local (see [Where the Configuration Lives](#where-the-configuration-lives))

The `PreToolUse` hook guards the write direction: it inspects the changes the agent is about to apply and the shell commands it is about to run. The `PostToolUse` hook guards the read direction. Codex has no Read tool and reads files through shell commands, so the output of a finished `Bash` call is where a secret would reach the model. You never invoke `check-codex` yourself — Codex calls it and sends the hook payload on stdin. The `PostToolUse` hook arrived in sekretbarilo 0.10.0.

`--stdin-json` is **mandatory** for `check-codex`. The bare command has no other input to read, so it refuses rather than guessing:

```sh
$ sekretbarilo check-codex
[ERROR] check-codex reads its payload from stdin and requires --stdin-json
```

The command the installer writes already includes the flag, so an existing installation needs no change.

Two things about this integration are easy to get wrong, and both are covered below: **an installed hook does not run until you approve it** (see [Hook Trust](#hook-trust)), and the output hook **only sees output from commands that have finished** (see [Limitations](#limitations)).

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

**`Bash` output** (`PostToolUse`) — when a `Bash` command finishes, Codex hands the hook the output it is about to give the model. sekretbarilo scans it with the detectors and trusted configuration layers that Claude [redact mode](#redact-mode-output-editor) uses. Clean output passes unchanged. If the output contains a secret, the hook exits 2 and Codex gives the model the hook's reason **instead of** the output. The reason says that sekretbarilo withheld the output and that the command already ran, and then shows the output with every detected value replaced by `[REDACTED]`:

```
[AGENT] sekretbarilo withheld this Bash output: 1 secret finding(s). The command already ran.
Output with secret values replaced by [REDACTED]:
APP_ENV=prod
GITHUB_TOKEN=[REDACTED]
```

Line breaks and tabs are kept, and other control and bidirectional characters are stripped, as in every block reason. The stripped text is redacted and scanned again as it will be shown, because removing a control character can join two halves of a value; if anything is still detected, the output is withheld whole with the masked findings list. An output that is still over 64 KiB after redaction is withheld whole, and the reason lists at most 20 masked findings (line, rule, masked value) in place of the text. A value that several rules detect is one finding, counted and listed once with its rule ids joined by commas. A payload whose `tool_response` is not a plain string, a configuration that cannot be loaded, and any other internal error also withhold the output. Codex itself would keep the original output on a hook failure, so sekretbarilo fails closed on its own side.

### Blocking

The hook blocks by exiting with code 2 and writing the reason to stderr. Codex surfaces that reason to the model, so the agent learns why the patch or command was refused and can correct itself instead of retrying blindly. Secret values in the reason are masked (first two and last two characters), exactly as in every other sekretbarilo output.

| Exit Code | Meaning | Codex Action |
|-----------|---------|--------------|
| 0 | no secrets in the patch, command or output | Allow the tool call, or pass the output through |
| 2 | secrets found, `.env` target, or error | Block the tool call (`PreToolUse`), or replace the output with the reason (`PostToolUse`) |

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

Why this matters more here than elsewhere is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-block-reasons-are-sanitized' | relative_url }}).

#### Payload Size

The hook reads at most 10 MiB from stdin. An oversized payload is rejected, blocking the tool call or withholding the output, rather than scanned in part — the same fail-closed choice made everywhere else:

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
    ],
    "PostToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "sekretbarilo check-codex --stdin-json",
            "timeout": 10,
            "statusMessage": "Scanning tool output for secrets..."
          }
        ]
      }
    ]
  }
}
```

The installer writes the absolute path of the running binary in place of the bare `sekretbarilo`, so Codex does not depend on its own `PATH`. Re-running the installer on an older installation that has only the `PreToolUse` group appends the `PostToolUse` group and leaves every existing group where it was.

Points worth knowing if you ever hand-edit the file:

- The root object accepts exactly two keys, `hooks` and `description`, and **rejects anything else**. An unrecognised top-level key makes Codex drop that layer's hooks entirely — with only a log warning and nothing visible at the point of use. A typo at the root silently disarms every hook in that file.
- Event keys are PascalCase (`PreToolUse`, `PostToolUse`).
- `timeout` is in **seconds**, and defaults to 600 when omitted.
- `statusMessage` is camelCase.
- `matcher` is a regex and is optional; omitting it matches every tool.
- It is standard JSON: no comments, no trailing commas.

Codex CLI `0.145.0` has no `hooks list` or `hooks validate` subcommand, so there is no way to ask Codex whether it accepted your file. It does have a `codex doctor`, but that diagnoses installation, config, auth, and runtime health — it does not look at `hooks.json`. `sekretbarilo doctor` is the check available.

Codex also accepts a second, equivalent representation of the same hooks — a `[hooks]` table in the `config.toml` of the same layer. sekretbarilo deliberately writes only `hooks.json` and never touches `config.toml`. If you already keep hooks in `config.toml`, expect to see a second hook definition appear in `hooks.json`; that is the sekretbarilo one. When both representations exist in a single layer, Codex loads both and prints a warning.

### Hook Trust

**Codex does not run a newly installed hook until you approve it.** An unapproved hook is skipped silently — no error, no warning at the point of use — so the installation looks complete while nothing is actually being scanned. This is the single most common reason for "I installed the hook and it never fires".

Approve the hooks from the Codex TUI. sekretbarilo installs two, the `PreToolUse` one and the `PostToolUse` one, and each needs its own approval:

```
/hooks
```

sekretbarilo does not write the trust state for you; why is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-sekretbarilo-does-not-approve-its-own-hook' | relative_url }}).

Codex records the approval in a `[hooks.state]` table inside the `config.toml` of the user layer, keyed by source file path, event, and index.

For non-interactive environments where no one can answer a prompt — CI jobs, containers, automation — Codex offers `--dangerously-bypass-hook-trust`, which runs hooks without approval. It disables the trust check for *every* hook in that session, not just sekretbarilo's, so use it only where you fully control the hook configuration. Interactively, approve through `/hooks` instead.

### Version Requirements

The `PreToolUse` hook is verified against codex-cli `0.145.0`, and the `PostToolUse` output hook against `0.159.3`. Older releases may not deliver `PreToolUse` for `apply_patch`, or `PostToolUse` for `Bash`. If patches are being applied, or secrets shown, without ever reaching sekretbarilo, upgrade Codex CLI before debugging anything else.

### Limitations

Know what the Codex hooks do not do:

- **Streaming output is not covered.** Codex runs `PostToolUse` only when a command has finished. Output it hands the model while a command is still running, including each intermediate `write_stdin` poll of an interactive or long-running process, never passes through the hook. A command that prints a secret and keeps running leaks that chunk.
- **Codex fails open.** If the output hook is not approved, times out, crashes, or prints something Codex cannot parse, Codex keeps the original output. sekretbarilo fails closed on every error it can see, but it cannot cover a hook that never ran.
- **Codex's local logs.** Replacing the result for the model does not remove the original output from Codex's own local session logs.
- **The command has already run.** The output hook hides output from the model; it does not undo the command or anything the command sent elsewhere.
- **The `Bash` checks are textual.** The command string and the output are scanned as text. sekretbarilo does not parse shell syntax, does not expand variables, and does not analyse redirect targets, so the checks can be circumvented deliberately. Treat them as a guardrail against accidental leakage, not as a sandbox.
- **`apply_patch` and `Bash` only.** Nothing else Codex does is intercepted, including MCP tool results.

## Claude Code Block Pipeline

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

Fast-path decisions are made based on **file path patterns only**, before the file is read. This keeps the check extremely fast. Why these files are skipped at all is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-some-files-are-never-scanned' | relative_url }}).

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

`.env` files are a special case: they are **always blocked**, regardless of content. Why they are never read is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-env-files-are-blocked-outright' | relative_url }}).

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

## Configuration

`check-file`, `check-codex`, and `redact-claude` load hierarchical configuration from `.sekretbarilo.toml` files through the trusted loader. Custom rules, stopwords, value exceptions, and entropy thresholds apply across the hooks. Path policy differs by command, as described below.

### Config Inside the Repository Must Be Committed

The agent hooks — and only the agent hooks — require a `.sekretbarilo.toml` **inside the git working tree** to be git-tracked and unmodified relative to `HEAD`. An untracked or dirty in-workspace config is dropped whole, with one line on stderr:

```
[WARN] ignoring untrusted in-workspace config: /home/user/project/.sekretbarilo.toml
```

The reason for the rule is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-in-workspace-config-must-be-committed' | relative_url }}).

A `.sekretbarilo.toml` that is a symlink inside the working tree is dropped the same way even when committed, because git vouches for the link text and not for the file it points to. Outside a git repository the workspace is the working directory, and a layer there is always dropped.

Layers above the repo root — a parent directory, `~/.sekretbarilo.toml` — are loaded normally. The XDG user config and `/etc/sekretbarilo.toml` are loaded wherever the working directory is, `$HOME` included. `scan`/`audit` are not affected at all. If a value exception works under `sekretbarilo audit` but the hook still detects it, check whether the config is committed and is not a symlink. Full detail in [Configuration]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }}).

`check-codex` finds the configuration from the payload's `cwd` for both events. A `cwd` that is empty, relative, or not a directory blocks the tool call, or withholds its output, with a scanner setup error, rather than falling back to the process directory, whose layers belong to another workspace. A `cwd` that no longer exists, such as a worktree a command removed, is resolved to its nearest existing parent, as in Claude redact mode. Only an absent `cwd` uses the process directory.

### Path Allowlists and Tool Text

**Path allowlists do not apply to Codex `Bash` command text, Codex `Bash` output, or any Claude `redact` output.** `[allowlist] paths` and per-rule `paths` cannot suppress findings in those text modes. Stopwords, per-rule value regexes, entropy thresholds, and `detect_public_keys` still apply. Path allowlists work normally for `apply_patch` target paths and `check-file`. Redaction also ignores audit path exclusions and documentation-specific relaxations.

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
[WARN] IMPORTANT: Codex will silently skip these hooks until you approve them.
       In the Codex TUI, run /hooks and approve both sekretbarilo hooks (PreToolUse and PostToolUse).
       For non-interactive automation only, --dangerously-bypass-hook-trust bypasses this protection.
[INFO] detected Codex version: codex-cli 0.159.3
```

Re-running it reports `[OK] sekretbarilo already installed in codex cli hooks` when both hooks are present; finding an older command in `hooks.json`, or an installation from before 0.10.0 without the `PostToolUse` hook, produces `[OK] updated codex cli hook configuration`. Existing hooks in the file are preserved either way, as with Claude Code — a `PreToolUse` or `PostToolUse` group of your own stays where it is, and sekretbarilo's group is appended after it.

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
6. **Output hook**: the same command under `PostToolUse` with the matcher `^Bash$`, reported as `codex cli output hook`; a missing one is a warning to re-run the installer, because without it `Bash` output reaches the model unscanned
7. **Unrecognised root key**: warns if `hooks.json` has a top-level key other than `hooks` or `description`, which makes Codex discard that file's hooks entirely
8. **Approval entries**: looks for the `[hooks.state]` entry Codex writes when you approve each hook
9. **Codex on PATH**: reports the `codex` binary and its version

Doctor also reports, in the **configuration** group, any in-workspace `.sekretbarilo.toml` that is untracked or has uncommitted changes — the agent hooks ignore such a layer entirely. See [Config Inside the Repository Must Be Committed](#config-inside-the-repository-must-be-committed).

#### The Approval Check Is Positional

Codex keys its approval by source file, event, and **index** — `<path>:pre_tool_use:<group>:<handler>` for the input hook and `<path>:post_tool_use:<group>:<handler>` for the output hook, so approving one never approves the other. Doctor looks for the key matching the position sekretbarilo's hook actually occupies. That distinction matters on a machine that already has Codex hooks of its own: sekretbarilo's group is appended after them, so it sits at a non-zero group index and needs its **own** approval. Approving somebody else's hook, or approving ours before the indices shifted, does not count:

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

---

## See Also

- [Getting Started]({{ '/getting-started/' | relative_url }}) - Overview and quick setup
- [Installation]({{ '/installation/#agent-hooks-ai-coding-tool-protection' | relative_url }}) - Installing each hook, choosing a Claude mode, approving the Codex hook
- [How the agent hooks work]({{ '/how-agent-hooks-work/' | relative_url }}) - Why the hooks are built this way, with illustrated sessions
- [Troubleshoot the agent hooks]({{ '/troubleshoot-agent-hooks/' | relative_url }}) - Step-by-step fixes for a hook that misbehaves
- [Verify redaction with a synthetic smoke check]({{ '/verify-redaction/' | relative_url }}) - End-to-end check of `redact` mode
- [Scan a single file with check-file]({{ '/scan-a-file-with-check-file/' | relative_url }}) - Running `check-file` outside the hook
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - Complete command reference
- [Configuration]({{ '/configuration/' | relative_url }}) - Customizing detection rules and allowlists
