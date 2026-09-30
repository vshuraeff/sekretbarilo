---
title: Troubleshoot the agent hooks
description: Work through the checks for a Claude Code or Codex CLI hook that never fires, blocks something safe, runs slowly, reports an outdated command, or ignores your configuration.
section: how-to
---

Each section starts from a symptom and walks through the checks in order. For a one-line lookup of symptom, cause and fix across every surface, see the [Troubleshooting reference]({{ '/troubleshooting/' | relative_url }}).

## A random value is not masked

In 0.9.0, `generic-high-entropy-value` is off by default. If a bare random token
has no recognizable credential signature or named credential context, an active
hook can correctly leave it unchanged. Run `sekretbarilo doctor` to inspect
effective class states and rule overrides. To include these values, opt in with
`[settings.rules]` and `"generic-high-entropy-value" = true` in a trusted config
layer. Neither `exemption_layer = false` nor `source_posture = "all"` enables it.
Then repeat the synthetic check; do not expose a real credential to diagnose it.

## Claude Code Hook Not Firing

**Symptom**: Claude Code reads files without triggering sekretbarilo.

These checks describe `block` mode. For `redact`, verify the synchronous `PostToolUse` handler, supported Claude version, and actual tool result using the [synthetic smoke check]({{ '/verify-redaction/' | relative_url }}). Successful redaction lets the tool run; it does not block the call.

**Check**:
1. Verify hook is installed: `sekretbarilo doctor`
2. Check `.claude/settings.json` exists and contains the hook
3. Ensure sekretbarilo binary is in PATH: `which sekretbarilo`
4. Test `check-file` manually: `sekretbarilo check-file path/to/file`

## Hook Fails with "command not found"

**Symptom**: Claude Code shows error: `sekretbarilo: command not found`.

**Fix**:
1. Add sekretbarilo to PATH: `export PATH="$HOME/.cargo/bin:$PATH"`
2. Or use absolute path in hook: edit `.claude/settings.json` and change command to `/full/path/to/sekretbarilo check-file --stdin-json`

## False Positives Blocking Clean Files

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
3. **Commit the config.** A `.sekretbarilo.toml` inside the repository is ignored by the agent hooks until it is git-tracked and clean, so an edit that has not been committed yet changes nothing. `sekretbarilo doctor` says so explicitly, and the hook prints `[WARN] ignoring untrusted in-workspace config: ...` on every run. See [Config Inside the Repository Must Be Committed]({{ '/agent-hooks/#config-inside-the-repository-must-be-committed' | relative_url }}).

## Slow Hook Execution

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

## Hook Installed but doctor Shows Outdated

**Symptom**: `sekretbarilo doctor` reports outdated command.

**Fix**:
Run the installer again to update the command:
```sh
sekretbarilo install agent-hook claude
```

This will detect the outdated command and replace it with the current format.

## Codex CLI Hook Not Firing

**Symptom**: Codex applies patches and runs commands without triggering sekretbarilo, and nothing is reported anywhere.

**Check, in this order**:

1. **Approve the hook.** This is the usual cause. Run `/hooks` in the Codex TUI and approve the sekretbarilo entry. An unapproved hook is skipped without any message — see [Hook Trust]({{ '/agent-hooks/#hook-trust' | relative_url }}). If you already approved it once, approve it again: the approval is tied to the hook's position in the file, and adding or removing another hook shifts it.
2. **Verify it is installed**: `sekretbarilo doctor` reports the local and global codex groups, and tells you whether it can find an approval entry for the position your hook occupies. Codex itself has no `hooks list` or `hooks validate` command to cross-check with.
3. **Check the layer you expect**: project-local hooks live in `.codex/hooks.json` at the repository root, global ones in `$CODEX_HOME/hooks.json` (by default `~/.codex/hooks.json`). If you installed globally but run Codex somewhere with its own configuration, check both.
4. **Look for a stray root key** if you edited `hooks.json` by hand. Only `hooks` and `description` are accepted at the root; anything else makes Codex discard that file's hooks completely, with no visible error.
5. **Check the Codex version**: `codex --version`. The integration is verified on `0.145.0`; older releases may not deliver `PreToolUse` for `apply_patch`.
6. **Ensure the binary is in PATH**: `which sekretbarilo`. The hook command is resolved by Codex, in Codex's environment.

## Codex Warns About Duplicate Hook Definitions

**Symptom**: Codex prints a warning that hooks are defined in more than one place.

**Cause**: the same layer has both a `hooks.json` file and a `[hooks]` table in `config.toml`. Codex loads both representations and warns. sekretbarilo only ever writes `hooks.json`, so the `config.toml` definition is one you (or another tool) added.

**Fix**: keep your hooks in one representation. If you consolidate into `config.toml`, note that re-running `sekretbarilo install agent-hook codex` will write `hooks.json` again.

## Codex Blocks a Patch or Command You Know Is Safe

**Symptom**: a patch containing a fixture value, or a command containing a harmless-looking high-entropy string, is refused.

**Fix**: `check-codex` reads the same `.sekretbarilo.toml` hierarchy as every other command, so the same allowlist tools apply:

```toml
[allowlist]
stopwords = ["known-safe-value"]
paths = ["test/fixtures/.*"]
```

Commit the config afterwards — an uncommitted `.sekretbarilo.toml` inside the repository is ignored by `check-codex` entirely.

Three things that will not work, however hard you try:

- **An uncommitted in-workspace config.** The layer is dropped whole, and the hook says so on stderr. See [Config Inside the Repository Must Be Committed]({{ '/agent-hooks/#config-inside-the-repository-must-be-committed' | relative_url }}).
- **A path allowlist against a `Bash` block.** `paths` entries are ignored when scanning command text — use `stopwords` or a per-rule value regex instead. For `apply_patch`, `paths` works as usual against the patch target.
- **Anything against a `.env` block.** The `.env` check runs before configuration is even loaded, so no allowlist entry changes it. Write to `.env.example` instead, or set the value in your shell rather than through the agent.

## The Hook Ignores Your In-Workspace Config

**Symptom**: an allowlist entry works under `sekretbarilo audit`, but the agent hook still blocks or masks the same value.

The agent hooks honour a `.sekretbarilo.toml` inside the git working tree only when it is git-tracked and unmodified relative to `HEAD` (see [In-Workspace Config Trust]({{ '/configuration/#in-workspace-config-trust-agent-hooks-only' | relative_url }})).

Commit the config:

```sh
git add .sekretbarilo.toml
git commit -m "add sekretbarilo config"
```

A tracked file with uncommitted edits is untrusted too, so committing changes to it is part of the same workflow. `sekretbarilo doctor` reports any in-workspace config the hooks will ignore:

```
  [WARN] /home/user/project/.sekretbarilo.toml is untracked or has uncommitted changes; the check-file/check-codex agent hooks ignore this config layer entirely until it is committed
```

If your allowlist works when you run `sekretbarilo audit` by hand but the agent hook still blocks the same file, this is almost always why.

## Related pages

- [Agent hooks]({{ '/agent-hooks/' | relative_url }}) for what each hook covers, its output and its exit codes.
- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) for writing the narrowest entry that silences one finding.
- [Troubleshooting reference]({{ '/troubleshooting/' | relative_url }}) for the symptom tables of every surface.
