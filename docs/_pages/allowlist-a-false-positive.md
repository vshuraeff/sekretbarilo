---
title: Allowlist a confirmed false positive
description: Silence one finding you have confirmed is safe, in the narrowest form and at the right configuration layer.
section: how-to
---

## Before you start

Confirm the finding is genuinely a false positive by reading the file and the line it names. An unexplained credential-shaped value is not a false positive; a documentation placeholder, a test fixture, or a checksum is. An allowlist entry is permanent until someone removes it, so it is worth the minute.

## 1. Read the finding

Every finding names the rule that matched and shows the value masked:

```
  file: src/session.rs
  line: 42
  rule: generic-high-entropy-value
  match: xx********************************7f
```

You need two things from it: the **rule id**, which the entry must name exactly, and enough of the value to write a pattern for it. Take the value from the file, not from the masked output — the asterisks are not recoverable.

## 2. Choose the layer

Configuration is discovered hierarchically and merged, so put the entry where its reach matches the fact:

| The value is safe... | Put the entry in |
| --- | --- |
| in this repository only | `.sekretbarilo.toml` at the repository root |
| across several repositories under one directory | `.sekretbarilo.toml` in that parent directory |
| everywhere you work | `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` |

Lists merge across layers rather than replacing each other, so a project entry adds to the user-level ones instead of overriding them.

## 3. Write the narrowest entry that works

A `[[allowlist.rules]]` block names one rule and suppresses findings for it alone. Three keys select what is matched, and they can be combined.

**An exact value.** `regexes` is matched against the captured value, not the whole line. Anchor it, and escape regex metacharacters — base64 values contain `+` and `/`:

```toml
[[allowlist.rules]]
id = "generic-api-key"
regexes = ["^the-exact-value-here$"]
```

**A path.** Use this when a whole directory holds fixtures rather than credentials:

```toml
[[allowlist.rules]]
id = "generic-api-key"
paths = ["tests/fixtures/.*"]
```

**An assignment key.** Only `generic-high-entropy-value` accepts `keys`, and it is the one mechanism that sees the name on the left of the assignment. Matching is case-sensitive and covers the whole key; `*` and `?` are the wildcards:

```toml
[[allowlist.rules]]
id = "generic-high-entropy-value"
keys = ["SSH_AUTH_SOCK", "GHOSTTY_*"]
```

{: .note }
A `keys` list on any other rule is a configuration error, and a wildcard-only pattern such as `*` is rejected as well, because it would match every key.

Prefer a value regex to a path, and a path to anything broader. Global `[allowlist].stopwords` reach only the rules that carry an entropy threshold, so they are a blunt instrument for this job.

## 4. Re-run the scan

```sh
sekretbarilo scan          # staged changes
sekretbarilo audit         # the whole working tree
```

Check that the finding you targeted is gone and the others are still there. Two rules often match the same value, and each needs its own entry: silencing `generic-high-entropy-value` on an `api_key` assignment leaves `generic-api-key` reporting the same characters.

For an agent hook, re-run the command the hook runs:

```sh
sekretbarilo check-file path/to/file
```

Exit 0 means clean. Exit 2 means the finding, or another one, is still there.

## Troubleshooting

**The allowlist works for `scan` but the agent hook still fires.** A `.sekretbarilo.toml` inside the working tree is honoured by `check-file`, `check-codex` and `redact-claude` only when it is git-tracked and unmodified against `HEAD`. Otherwise the whole layer is dropped, and the hook says so on stderr:

```
[WARN] ignoring untrusted in-workspace config: /path/to/project/.sekretbarilo.toml
```

Commit the file, edits included, and it is honoured again. `sekretbarilo doctor` reports any in-workspace config the hooks are ignoring.

**A path entry has no effect in redact mode.** Redaction deliberately ignores every path exclusion, because the text it inspects is a tool result rather than a file. Use a value regex there.

**Nothing suppresses a `.env` block.** The `.env` check runs before configuration is loaded, so no entry reaches it. Write to `.env.example` instead.

For the full syntax of every section, see [Configuration]({{ '/configuration/' | relative_url }}); for what each rule matches, the [Rules reference]({{ '/rules-reference/' | relative_url }}).
