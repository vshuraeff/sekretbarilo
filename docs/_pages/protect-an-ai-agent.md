---
title: Redact secrets in Claude Code tool output
description: Install the Claude Code hook in redact mode and watch it mask a real value in a disposable repository.
section: tutorial
---

## What we are going to do

In this tutorial we install the sekretbarilo hook for Claude Code in `redact` mode, put a value into a throwaway repository, and watch the scanner replace that value with `[REDACTED]` before it ever reaches the model. At the end we delete everything we made.

Redaction masks the text a tool returns; the file on disk is never touched. The other mode, `block`, refuses the read instead. We use `redact` here because its result is visible in one command.

## Before you begin

- sekretbarilo installed and on your `PATH` (`sekretbarilo --version`).
- Claude Code 2.1.121 or later, which is what introduced the output-replacement contract the hook uses.
- `openssl` and `jq`, both present on a stock macOS and on most Linux distributions.

## Step 1: create a disposable repository

We work in a repository we can throw away, so nothing here touches a project you care about.

```sh
mkdir /tmp/redact-demo && cd /tmp/redact-demo
git init
```

Git reports `Initialized empty Git repository in /tmp/redact-demo/.git/`.

## Step 2: install the hook in redact mode

```sh
sekretbarilo install agent-hook claude --mode redact
```

The command answers:

```
[OK] created claude code hook configuration
```

It wrote `.claude/settings.json` in this directory, which is one of the standard places Claude Code loads settings from. A fresh install without `--mode` would have selected `block`; we asked for `redact` explicitly.

Look at what it installed:

```sh
jq '.hooks.PostToolUse[0]' .claude/settings.json
```

```json
{
  "matcher": "^(Bash|Read|Grep)$",
  "hooks": [
    {
      "type": "command",
      "command": "/usr/local/bin/sekretbarilo redact-claude --stdin-json",
      "statusMessage": "Redacting tool output secrets...",
      "timeout": 10
    }
  ]
}
```

Notice the matcher. Redaction runs after `Bash`, `Read` and `Grep` return, not before them. The command is written as an absolute path, so it keeps working whatever `PATH` Claude Code is started with.

## Step 3: create a value worth hiding

The documentation never contains a detectable value, so we generate our own. Thirty random bytes in base64 give a forty-character string, which clears both gates the catch-all rule applies: at least twenty bytes, and Shannon entropy of at least 4.0 bits per byte.

```sh
openssl rand -base64 30 | sed 's/.*/api_key = "&"/' > config.txt
```

## Step 4: confirm the scanner sees it

```sh
sekretbarilo check-file config.txt
```

```
[AGENT] secret(s) detected in config.txt

  file: config.txt
  line: 1
  rule: generic-high-entropy-value
  match: zI************************************/8

  file: config.txt
  line: 1
  rule: generic-api-key
  match: zI************************************/8

file contains 2 secret(s). reading blocked to prevent secret exposure.
```

Two rules matched the same value: the catch-all entropy rule, which ignores the name on the left of the `=`, and the generic API-key rule, which was drawn in by the name `api_key`.

The `match` line is how sekretbarilo reports a finding: first two characters, last two characters, asterisks in between. Enough to recognise which value it was, not enough to reconstruct it. Your own characters will differ from the ones above.

{: .note }
`check-file` exits 2 both when it finds something and when it fails. That is deliberate, so a hook that cannot scan blocks rather than waves the file through.

## Step 5: watch the redaction itself

The hook is fed a JSON payload of a finished tool call and answers with the text Claude should see instead. We can hand it the same payload by hand. Here we pretend a `Bash` command printed the file:

```sh
jq -Rs '{hook_event_name:"PostToolUse",tool_name:"Bash",tool_response:{stdout:.,stderr:"",interrupted:false}}' config.txt \
  | sekretbarilo redact-claude --stdin-json
```

```json
{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"interrupted":false,"stderr":"","stdout":"api_key = \"[REDACTED]\"\n"}}}
```

That is the whole mechanism. The assignment survives, the quotes survive, the value is gone. Here the replacement is `[REDACTED]` rather than the masked shape of step 4: a finding is reported to you, so it keeps two characters at each end for recognition, while a redacted result is aimed at the model and keeps nothing.

## Step 6: see it in a Claude session

Start Claude Code in this directory and ask it to read `config.txt`. The tool call runs normally, and what comes back to the model carries `[REDACTED]` where the value was, while the file on disk is unchanged.

Keep the value out of your prompt. If you paste it in, the model already has it and no hook can take it back.

{: .warning }
Redaction is not a guarantee. A hook that crashes, times out, or fails to deliver its answer leaves the original result exposed, and results from MCP tools, images, PDFs and notebooks are outside its scope.

## Step 7: clean up

```sh
cd /tmp && rm -rf /tmp/redact-demo
```

That removes the repository, the fixture and the hook we installed, since all three lived inside it. Your global Claude settings were never touched.

## What we did

We installed an output-editing hook, produced a value that the catch-all entropy rule detects, saw it reported in masked form, and saw it replaced in a tool result. Nothing we ran modified a file's contents.

## Next steps

- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) when the scanner flags something you know is safe.
- [How secret detection works]({{ '/how-detection-works/' | relative_url }}) for the rules and gates behind those two findings.
- [Agent hooks]({{ '/agent-hooks/' | relative_url }}) for the full contract, its limits, and the Codex CLI hook, which guards the writing direction instead of the reading one.
- [Troubleshooting reference]({{ '/troubleshooting/' | relative_url }}) if the hook stays silent.
