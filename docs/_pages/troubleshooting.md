---
title: Troubleshooting reference
description: Symptoms, causes, fixes and the confirming command, grouped by the surface they occur on.
section: reference
---

## Using this page

Find the symptom in the group for the surface it appears on. `sekretbarilo doctor` covers every group at once and exits 0 when all checks pass, 1 when any warning or error was reported.

## Pre-commit hook

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| Commits are never scanned | Hook file absent | `sekretbarilo install pre-commit` | `ls -la .git/hooks/pre-commit` |
| Hook exists, nothing runs | Hook not executable | `chmod +x .git/hooks/pre-commit` | `ls -la .git/hooks/pre-commit` |
| Local hook stopped running after a global install | `core.hooksPath` replaces `.git/hooks` entirely | `git config --global --unset core.hooksPath`, or install into the global directory | `git rev-parse --git-path hooks` |
| Global hook does not apply in one repository | Repository-local `core.hooksPath` overrides it | Unset the local value | `git config --local core.hooksPath` |
| Global install did not take effect anywhere | `core.hooksPath` was never set | `sekretbarilo install pre-commit --global` | `git config --global core.hooksPath` |
| A commit is blocked by a fixture value | Detector matched test data | Add an allowlist entry | `sekretbarilo scan` |

## Claude Code hook

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| Files are read without scanning | Hook not installed in the scope Claude loads | `sekretbarilo install agent-hook claude` | `sekretbarilo doctor` |
| `sekretbarilo: command not found` in the hook | Bare command resolved under Claude's own `PATH` | Re-run the installer, which pins an absolute path | `sekretbarilo doctor` |
| doctor reports an outdated command | Settings written by an older release | `sekretbarilo install agent-hook claude` | `sekretbarilo doctor` |
| `--mode redact` refuses to install | Claude Code older than 2.1.121, or its version unreadable | Upgrade Claude Code; the previous protection is left in place | `claude --version` |
| Redaction installed, output still unmasked | A blocking `Read` hook in the other scope intercepts first | Set the intended mode explicitly in each scope | `sekretbarilo doctor` |
| A clean file is blocked | Detector matched a safe value | Allowlist the value, or the path in `block` mode | `sekretbarilo check-file <path>` |
| Path allowlist ignored in redact mode | Redaction applies no path exclusions by design | Use a per-rule value regex instead | `sekretbarilo check-file <path>` |
| Scanning takes seconds | Large file, or an expensive custom rule | Exclude generated directories under `[audit]` | `sekretbarilo check-file <path>` |

## Codex CLI hook

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| Patches and commands are never scanned, silently | Hook installed but not approved | Approve it with `/hooks` in the Codex TUI | `sekretbarilo doctor` |
| Approved once, still skipped | Approval is keyed to the hook's position, and indices shifted | Approve again with `/hooks` | `sekretbarilo doctor` |
| Whole file's hooks ignored | `hooks.json` has a root key other than `hooks` or `description` | Remove the extra root key | `sekretbarilo doctor` |
| Codex warns about duplicate hook definitions | The same layer defines hooks in `hooks.json` and in `config.toml` | Keep one representation | `cat .codex/hooks.json` |
| Hook installed in the wrong layer | Project and global layers are separate files | Check both locations | `cat .codex/hooks.json` and `cat "${CODEX_HOME:-$HOME/.codex}/hooks.json"` |
| A safe patch is refused | Detector matched a fixture value | Allowlist the value; `paths` does not apply to `Bash` command text | `sekretbarilo doctor` |
| A `.env` write is refused | The `.env` check precedes configuration loading | Write to `.env.example`, or set the value in your shell | — |

## Configuration

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| Allowlist works for `scan`, not for the hooks | In-workspace config untracked or modified against `HEAD` | Commit `.sekretbarilo.toml` | `sekretbarilo doctor` |
| `[WARN] ignoring untrusted in-workspace config` on stderr | The same trust rule; the layer is dropped whole | Commit the file | `git status .sekretbarilo.toml` |
| A rule stopped firing after adding config | A `[[rules]]` entry reused a built-in `id` and replaced it | Rename the custom rule | `sekretbarilo doctor` |
| Redaction returns `continue: false` | Trusted configuration failed to parse | Fix the TOML syntax | `sekretbarilo doctor` |
| A stopword has no effect | Stopwords reach only rules carrying an entropy threshold | Use a per-rule `regexes` entry | `sekretbarilo scan` |
| Public keys reported as findings | `detect_public_keys` enabled | Remove the setting or the `--detect-public-keys` flag | `sekretbarilo audit` |
| Every value under a key is still flagged | `keys` applies to `generic-high-entropy-value` only | Add a per-rule entry for the other rule | `sekretbarilo scan` |
| A high-entropy value is no longer reported | A structural exemption step suppressed it | Set `exemption_layer = false` under `[settings]` if the shape is genuinely a secret | `sekretbarilo audit --trace-exemptions` |
| Findings named `exempt:syntax`, `exempt:url` and the like | `--trace-exemptions` is on; the decisions are reported as findings and count towards the exit code | Drop the flag outside diagnosis | `sekretbarilo audit` |

## Binary and PATH

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| `sekretbarilo: command not found` | Install directory not on `PATH` | Add it to `PATH` in your shell profile | `which sekretbarilo` |
| An old version runs | Another copy shadows the current one earlier in `PATH` | Remove the stale copy | `which -a sekretbarilo` and `sekretbarilo --version` |
| doctor reports a hook binary mismatch | The configured path is a different build from the running one | Re-run the installer to pin the current path | `sekretbarilo doctor` |
| doctor reports a hook binary that is not executable | Executable bit lost, or the path no longer exists | Re-run the installer | `sekretbarilo doctor` |

## Related pages

- [Agent hooks]({{ '/agent-hooks/' | relative_url }}) for what each hook covers and its limits.
- [Configuration]({{ '/configuration/' | relative_url }}) for discovery, trust and merge rules.
- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) for the suppression procedure.
