---
title: Verify redaction with a synthetic smoke check
description: Confirm on your own machine that the Claude Code redact hook masks a synthetic credential in Bash, Read and Grep results while the file on disk stays unchanged.
section: how-to
---

## Before you start

Verified with the sekretbarilo 0.6.0 release build and Claude Code 2.1.261 on 2026-09-05: a synthetic AWS key and passwords without quotes and in double, single, and backtick quotes were masked in the model-visible results of Bash, text Read, and Grep content mode. The source file remained unchanged. Other result shapes and error cases are covered by the automated hook tests.

Use a disposable project and a synthetic credential that matches an enabled detector. In 0.9.0, bare random tokens require explicit `generic-high-entropy-value` opt-in; a signature credential or a named `api_key` assignment tests the default configuration. Keep the synthetic value out of the prompt so the model cannot recover it from the request itself.

## Steps

1. Check `claude --version`, install with `--mode redact`, and run `sekretbarilo doctor`. Resolve any local/global blocking-hook conflict.
2. Create a text fixture containing safe surrounding lines and the synthetic credential, and record its checksum outside Claude.
3. In a fresh Claude session, ask it to inspect the fixture separately with `Bash` (`cat`), `Read`, and `Grep` in content mode. Check that each tool was actually used and the model receives `[REDACTED]` with the safe lines intact.
4. Repeat with Bash output on stderr, Grep's file/count modes, repeated secrets, and a multiline key fixture. Inspect the actual tool results, not only the model's final paraphrase.
5. Compare the fixture checksum afterward. The file must be unchanged.

## Related pages

- [Redact Mode: Output Editor]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}) for what the hook scans, its output contract and its limits.
- [Redact secrets in Claude Code tool output]({{ '/protect-an-ai-agent/' | relative_url }}) for a guided first run of the same hook.
- [Troubleshoot the agent hooks]({{ '/troubleshoot-agent-hooks/' | relative_url }}) if the hook stays silent.
