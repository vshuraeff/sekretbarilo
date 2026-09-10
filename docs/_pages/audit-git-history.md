---
title: Audit Git history for secrets
description: Scan every commit in a repository for secrets, narrow the scan by branch or date, and decide what to do with what you find.
section: how-to
---

## Before you start

Run this in a full clone. History mode reads commits directly and never checks anything out, so it is safe on a dirty working tree, but a shallow clone only has the commits it fetched.

A first run over a long history is slow compared with a working-tree scan. Narrow it with the filters below when you are iterating.

## 1. Scan the whole history

```sh
sekretbarilo audit --history
```

This walks every commit reachable from any ref, scans the lines each commit adds, and reports findings with the commit, author and date they came from. Identical findings are collapsed: same rule, same file, same value is reported once, with the branches containing it resolved for the surviving finding.

Without `--history`, `audit` scans the tracked files of the working tree instead, which answers a different question — what is in the repository now, rather than what has ever been in it.

## 2. Narrow the scan

Each of these requires `--history`; used alone they are refused with `branch filter requires --history` or `date filter requires --history`.

| Flag | Effect |
| --- | --- |
| `--branch <name>` | only commits reachable from `refs/heads/<name>`, instead of every ref |
| `--since <date>` | only commits after the date |
| `--until <date>` | only commits before the date |

```sh
sekretbarilo audit --history --branch master
sekretbarilo audit --history --since 2024-01-01 --until 2024-12-31
sekretbarilo audit --history --since '30 days ago'
```

`--branch` names a local branch. A name containing `..`, or starting with `/` or `-`, is rejected, and a branch that does not exist is an error rather than an empty result. Dates are handed to Git, so any format `git rev-list` accepts works, absolute or relative.

The path filters work in both modes:

```sh
sekretbarilo audit --history --exclude-pattern '^vendor/' --include-pattern '\.rs$'
```

## 3. Search for text as well

`--search` and `--search-regex` add a pass of your own alongside the rules. Both are repeatable, both work with or without `--history`, and neither is available on `scan`.

```sh
sekretbarilo audit --history --search 'internal.example.com'
sekretbarilo audit --history --search-regex 'TOKEN_[A-Z]+'
```

Literal patterns have their metacharacters escaped, so `api.key` matches only `api.key`. Regex patterns are case-sensitive; prefix `(?i)` to change that. Matches appear in a separate `[SEARCH]` block, are reported unmasked, and skip the allowlists and stopwords entirely — this pass looks for text you named rather than for secrets.

## 4. Act on what you find

Treat every confirmed finding as disclosed. A secret in history has been on every clone and every fetch that ever touched that commit.

1. **Rotate the credential first.** This is the step that actually removes the exposure, and it is the only one that does not depend on anyone else's clone.
2. **Remove it from the current code**, so a fresh commit does not reintroduce it.
3. **Then decide about rewriting history.** Rewriting is disruptive, invalidates every existing clone, and does not reach forks, caches, or anything that already mirrored the repository. It is out of scope here; see the [GitHub guidance on removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) if you go that way.
4. **Allowlist the ones that are not real.** Fixtures and documentation placeholders belong in an allowlist, not in a rewrite — see [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | nothing found |
| 1 | a secret or a `--search` match was found |
| 2 | error: bad configuration, a Git failure, an invalid branch or date |

A search match and a secret share exit code 1, so in a pipeline that treats a non-zero status as failure, run the two passes separately if you need to tell them apart.

Full flag descriptions are in the [CLI reference]({{ '/cli-reference/' | relative_url }}).
