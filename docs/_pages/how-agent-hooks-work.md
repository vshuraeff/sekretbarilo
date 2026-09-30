---
title: How the agent hooks work
description: Why the hooks guard both the read and the write direction, why configuration inside the repository must be committed, why some files are never scanned and .env files never read, and what a session looks like with the hooks in place.
section: explanation
---

## Two directions of leakage

AI coding agents interact with your codebase in two directions: they **read** files to understand context, and they **write** patches and run shell commands to act on it. Both directions leak secrets. A file the agent reads can carry a credential into conversations, logs, and generated snippets; a patch or a shell command the agent writes can put a fresh credential into your repository.

sekretbarilo integrates into the agent's tool pipeline. Blocking hooks run before a tool call executes:

1. The agent triggers a sekretbarilo hook
2. sekretbarilo scans the file, the patch, or the command
3. If secrets are found, the tool call is blocked and the agent is told why
4. If it is clean, the tool call proceeds normally

Which hook covers which direction, on which tool and in which mode, is listed in the [Agent hooks reference]({{ '/agent-hooks/#supported-agents-and-modes' | relative_url }}).

## Why in-workspace config must be committed

The agent hooks honour a `.sekretbarilo.toml` inside the git working tree only when it is git-tracked and unmodified relative to `HEAD`; the exact rule is in the [Configuration reference]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }}).

An agent hook is the one place where the thing being scanned can also rewrite the scanner's configuration. An agent asked to add a feature can write a permissive `.sekretbarilo.toml` first — that patch carries no secret, so it passes the check cleanly — and every check after it is neutered. Two tool calls, no warning, protection gone.

Requiring the config to be committed moves that step in front of a human: changing what the hooks enforce becomes a reviewable commit rather than a silent side effect of an agent turn.

### Why the Whole Layer

The rule drops the layer entirely, not just its allowlists. A `[[rules]]` entry whose `id` collides with a built-in rule **replaces** that rule (see [Merge Strategy]({{ '/configuration/#merge-strategy' | relative_url }})), so an overlay shipping its own `id = "aws-access-key-id"` with a regex that matches nothing would disable AWS key detection while looking like an ordinary rule addition. Honoring "only the safe parts" of an untrusted layer is not possible when any part of it can disarm a built-in rule.

## Why sekretbarilo does not approve its own hook

Codex does not run a newly installed hook until a human approves it with `/hooks` (see [Hook Trust]({{ '/agent-hooks/#hook-trust' | relative_url }})). sekretbarilo does not write the trust state for you, and this is deliberate:

- the trust hash is an internal, undocumented Codex implementation detail — writing it means guessing at a format that can change in any release;
- a security tool that grants itself trust defeats the purpose of the trust model. The approval has to come from a human.

## Why some files are never scanned

In `block` mode and file-based scans, binary files, vendor directories and lock files are passed through by path without being read (the lists are under [Fast-Path Skipping]({{ '/agent-hooks/#fast-path-skipping' | relative_url }})). That matters for three reasons:

- **Performance**: skipping binary files avoids reading megabytes of image/video data
- **Accuracy**: scanning binary content produces garbage matches (false positives)
- **Usability**: AI agents need to read lock files, images, and dependencies without friction

Even if a binary file somehow embeds a secret (e.g., an API key in image metadata), it's not accessible to the AI agent in a way that creates risk.

Vendor directories often contain thousands of files. Scanning them would:
- Slow down the agent significantly
- Produce false positives from test data in dependencies
- Block legitimate reads of library code

Lock files are often large (thousands of lines) and contain cryptographic hashes that can trigger false positives. They never contain user secrets, so they're safe to skip.

## Why `.env` files are blocked outright

`.env` files are designed to store secrets. They typically contain:
- Database passwords
- API keys
- Service tokens
- Encryption keys
- OAuth secrets

Allowing an AI agent to read a `.env` file is almost always a mistake. Even if the file happens to be clean at the moment, it's likely to contain secrets in the future.

The blocked and allowed names are listed under [.env File Blocking]({{ '/agent-hooks/#env-file-blocking' | relative_url }}).

## Why block reasons are sanitized

The file paths and rule names in a Codex block reason come from the patch, which the agent wrote, and are stripped of control characters and bidirectional overrides before they are printed (see [Blocking]({{ '/agent-hooks/#attacker-controlled-strings-are-sanitized' | relative_url }})).

This matters more here than elsewhere, because the reason has two audiences that both interpret escape sequences — the terminal it is printed to, and the model whose context it lands in. A rule name that can move the cursor is a rule name that can rewrite what the block appears to say.

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

# create file with an aws-shaped key id on line 3 (AKIA plus 16 random uppercase letters and digits)
cat > src/config.py << 'EOF'
import os

aws_access_key = "AKIA...."          # replace the dots with 16 random characters
aws_secret_key = os.environ.get('AWS_SECRET_KEY')

def init_client():
    return boto3.client('s3', aws_access_key_id=aws_access_key)
EOF
```

> The key only has to match the detector's shape; a generated fake works, and no real credential is needed. `AKIAIOSFODNN7EXAMPLE`, the key from AWS's own documentation, is allowlisted by a built-in rule allowlist and passes through untouched.

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

## Summary

Agent hooks provide a critical security layer for AI-assisted development:

- **Claude modes**: Block file reads or mask detected secrets in successful Bash/Read/Grep text results
- **Prevent secret injection**: Block patches and shell commands that would write secrets through Codex CLI
- **File scanning fast paths**: Skip configured binary, dependency, and lock-file paths in `block` mode
- **Shared detectors**: Rules and value exceptions apply to all hook modes; redaction ignores path exclusions and documentation relaxations
- **Configuration the agent cannot rewrite**: an in-workspace `.sekretbarilo.toml` counts only once it is committed
- **Easy installation**: One command per agent, or `install all` for everything at once
- **Diagnostic support**: `doctor` command validates hook configuration for both agents

## Further reading

- [Agent hooks]({{ '/agent-hooks/' | relative_url }}) for the full contract of each hook, its limits, output and exit codes.
- [Installation]({{ '/installation/#agent-hooks-ai-coding-tool-protection' | relative_url }}) for installing the hooks, choosing a Claude mode and approving the Codex hook.
- [Redact secrets in Claude Code tool output]({{ '/protect-an-ai-agent/' | relative_url }}) for a hands-on walk through redaction.
- [How secret detection works]({{ '/how-detection-works/' | relative_url }}) for the rules behind every hook decision.
