---
title: Configuration reference
description: Every section and key of .sekretbarilo.toml, the discovery order and merge rules, the agent-hook trust rule for in-workspace config, and how configuration is validated.
section: reference
---

sekretbarilo uses hierarchical `.sekretbarilo.toml` configuration files to customize scanning behavior, add allowlists, define custom detection rules, and configure audit options. Configuration is entirely optional - the tool works out of the box with sensible defaults.

This page is the reference for every section and key. Ready-made configurations and practical advice are in [Write a configuration file]({{ '/write-a-configuration-file/' | relative_url }}).

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Hierarchical Config Discovery

When you run `sekretbarilo`, it searches for configuration files in multiple locations and merges them together. This allows you to set organization-wide defaults at the user or system level and override them per-project.

### Discovery Order

Config files are searched in this order (lowest to highest priority):

| Priority | Location | Description |
|----------|----------|-------------|
| 1 (lowest) | `/etc/sekretbarilo.toml` | System-wide defaults (all users) |
| 2 | `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` | User-level defaults (falls back to `~/.config/sekretbarilo/sekretbarilo.toml` if `XDG_CONFIG_HOME` is not set, empty or relative) |
| 3 | `~/.sekretbarilo.toml` | Home directory config (legacy location) |
| 4..N | Parent directories from `$HOME` down to current directory | Hierarchical project configs (walks from home down to repo root) |
| N+1 (highest) | `.sekretbarilo.toml` in current directory | Project-specific config (highest priority) |

All found config files are loaded and merged automatically. This hierarchy allows you to define:
- Organization-wide rules and allowlists in `/etc/sekretbarilo.toml` or `~/.config/sekretbarilo/sekretbarilo.toml`
- Per-organization or per-team overrides in intermediate directories (e.g., `~/work/.sekretbarilo.toml`)
- Project-specific rules and allowlists in `.sekretbarilo.toml` at the repo root

### Example Directory Structure

```
/etc/sekretbarilo.toml                         # priority 1 (system-wide)
~/.config/sekretbarilo/sekretbarilo.toml       # priority 2 (user-level)
~/.sekretbarilo.toml                           # priority 3 (legacy home)
~/work/acme/.sekretbarilo.toml                 # priority 4 (org-level)
~/work/acme/project-x/.sekretbarilo.toml       # priority 5 (project-level, highest)
```

When running `sekretbarilo` from `~/work/acme/project-x/`, all five configs will be loaded and merged in priority order.

---

## In-Workspace Config Trust (Agent Hooks Only)

The agent hooks — `check-file`, `check-codex`, and `redact-claude` — apply one extra rule on top of the discovery above:

> A `.sekretbarilo.toml` located **inside the git working tree** is honored only when it is **git-tracked and unmodified relative to `HEAD`**. Otherwise the entire layer is dropped.
>
> Unmodified means byte for byte: the file must equal its blob at `HEAD`, so `git update-index --assume-unchanged`, `--skip-worktree` or a replace ref does not hide an edit, and a checkout that differs from the blob through an `eol` or filter conversion counts as modified.

Outside a git repository the workspace is the hook's working directory, and a `.sekretbarilo.toml` there is always dropped, because nothing vouches for it.

A layer reached through a symlink inside the workspace is dropped even when the symlink is committed. Git records only the link text, so a clean `git status` says nothing about the file the link points to, which may sit anywhere the agent can write. The test uses the path where discovery found the layer, not its resolved target. A symlink outside the workspace that points into it is judged by its target, which must then be committed. A working directory reached through a symlink that one repository holds and that leads into another repository drops every layer inside that other repository, because its commits vouch for nothing in the workspace holding the link. A layer outside that other repository but inside the one holding the link, such as a layer above a nested repository the link leads into, must be committed unmodified in the repository holding the link. `sekretbarilo doctor` reports symlinked layers along with untracked and modified ones, using the hooks' own judgment.

When a layer is dropped, the hook writes one line to stderr and carries on with the remaining layers:

```
[WARN] ignoring untrusted in-workspace config: /home/user/project/.sekretbarilo.toml
```

A dropped layer is never read, so a malformed untracked or modified config only produces that warning. A layer the hooks do trust — a committed in-workspace config or any layer in the table below — is read and parsed strictly: if it cannot be read, is not UTF-8 or does not parse, `check-file` exits 2 and `check-codex` blocks the tool call, each with a fixed reason that quotes nothing from the file. The hook does not fall back to the remaining layers, because the broken layer may carry the switches and allowlists the scan depends on.

`scan` and `audit` are **not** affected. They load an in-workspace config the moment it exists on disk, tracked or not. The rule exists only where an AI agent is on the other side of the scan.

Why the rule exists, and why it drops the whole layer rather than only its allowlists, is explained in [How the agent hooks work]({{ '/how-agent-hooks-work/#why-in-workspace-config-must-be-committed' | relative_url }}).

### What Is and Is Not Subject to the Rule

| Layer | Subject to the trust check |
|-------|---------------------------|
| `.sekretbarilo.toml` at the repo root | Yes |
| `.sekretbarilo.toml` in any subdirectory of the working tree | Yes |
| `.sekretbarilo.toml` symlink inside the working tree, committed or not | Always dropped |
| `.sekretbarilo.toml` in a parent directory above the repo root | No |
| `~/.sekretbarilo.toml` | Only when `$HOME` is the workspace itself: a dotfiles repository at `$HOME`, or `$HOME` as the working directory outside git |
| `$XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml` (or `~/.config/sekretbarilo/sekretbarilo.toml`) | No, wherever the working directory is |
| `/etc/sekretbarilo.toml` | No, wherever the working directory is |

The layers outside the working tree are outside the agent's reach in the same session, so they are loaded normally.

The user and system configs are trusted even when the workspace contains them, symlinked or not, because they are your configuration rather than the project's. Two setups put them inside: running the agent with `$HOME` as its working directory outside git, and a dotfiles repository checked out at `$HOME`. In the dotfiles case an uncommitted edit to `~/.config/sekretbarilo/sekretbarilo.toml` takes effect in the hooks, as it does from any other directory. The exemption needs the location to come from an absolute `HOME` or `XDG_CONFIG_HOME`; a user config path derived without one is checked like a project layer.

To make the hooks honour an in-workspace config, commit it; the steps and the `doctor` warning are in [Troubleshoot the agent hooks]({{ '/troubleshoot-agent-hooks/#the-hook-ignores-your-in-workspace-config' | relative_url }}).

### Redaction Policy

`redact-claude` uses the trusted layers' detection rules, entropy thresholds, password heuristics, public-key setting, stopwords, and per-rule value regexes. It ignores all path exclusions and documentation relaxations, including global/per-rule path allowlists and audit exclusion patterns. `.env` output is scanned by content instead of rejected by filename. These differences apply only to output redaction; existing file-scanning policies are unchanged.

An invalid trusted config is an error: redaction returns `continue: false` with a fixed safe reason and, when the response structure is available and fits the limit, masks all supported text. It does not silently continue with defaults after a config parse failure. See [Agent Hooks]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}).

---

## Merge Strategy

sekretbarilo merges all discovered config files using the following rules:

### Scalars

**Highest priority wins.** The most local (closest to current directory) config value takes precedence.

Example: if `entropy_threshold` is set to `3.0` in the user config and `4.5` in the project config, the effective value is `4.5`.

### Rule switches

`settings.rule_classes` and `settings.rules` merge per key with nearer-layer
precedence. A missing key inherits; an explicit `false` can be reversed by a
nearer `true` for that key. After both maps merge, rule-id switches override
class switches. See [Rule switches](#settingsrule_classes-and-settingsrules)
for defaults and examples.

### Lists

**Concatenated and deduplicated.** All list entries from all config levels are combined, with duplicates removed.

Example: if user config has `paths = ["vendor/.*"]` and project config has `paths = ["test/.*"]`, the effective list is `["vendor/.*", "test/.*"]`.

### Rules

**Merged by `id`.** If the same rule `id` appears at multiple levels, the most local (highest priority) definition wins. Rules with unique IDs from all levels are combined.

Example:
- User config defines `aws-access-key-id` rule with `entropy_threshold = 3.0`
- Project config defines `aws-access-key-id` rule with `entropy_threshold = 4.0` (overrides)
- Project config also defines `custom-internal-token` rule (appends)
- Effective ruleset: `aws-access-key-id` with threshold `4.0` + `custom-internal-token` + all other rules from user config

### Example: Multi-Level Merge

**System config** (`/etc/sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 3.0

[allowlist]
stopwords = ["company-safe-token"]
paths = ["vendor/.*"]
```

**User config** (`~/.config/sekretbarilo/sekretbarilo.toml`):
```toml
[allowlist]
paths = ["node_modules/.*"]
stopwords = ["my-test-token"]
```

**Project config** (`.sekretbarilo.toml`):
```toml
[settings]
entropy_threshold = 4.0

[allowlist]
stopwords = ["project-specific-token"]
paths = ["test/.*"]
```

**Effective merged config:**
```toml
# entropy_threshold = 4.0 (project wins, highest priority)

# allowlist.stopwords = [
#   "company-safe-token",     # from system
#   "my-test-token",          # from user
#   "project-specific-token", # from project
# ]

# allowlist.paths = [
#   "vendor/.*",              # from system
#   "node_modules/.*",        # from user
#   "test/.*",                # from project
# ]
```

---

## Config Sections

A `.sekretbarilo.toml` file can contain the following sections:

### `[settings.rule_classes]` and `[settings.rules]`

From 0.9.0, detection rules have a `class` describing their primary evidence:

| Rule class | Evidence | Default |
|------------|----------|---------|
| `signature` | Recognizable credential format, marker, or provider-specific structure | Enabled |
| `contextual` | Credential-naming key, authentication header, or credential-bearing URL | Enabled |
| `heuristic` | Generic value shape and entropy without credential-specific context | Disabled |

`generic-high-entropy-value` is the only built-in heuristic rule. `generic-api-key`,
`generic-secret-assignment` and `generic-token-assignment` are contextual and stay
enabled; they also read an unquoted value under a name that is or ends in a
credential key, wherever an assignment can start on a line (`API_KEY=…`,
`HF_TOKEN=…`, `docker run -e DJANGO_SECRET_KEY=… img`, `cmd; API_KEY=…`,
`token: …`, see the
[Rules Reference]({{ '/rules-reference/#generic-credential-assignments' | relative_url }})).
The three public-key rules are signature rules but also require
`detect_public_keys = true`.

```toml
[settings.rule_classes]
signature = true
contextual = true
heuristic = false

[settings.rules]
# opt in to keywordless high-entropy detection
"generic-high-entropy-value" = true
```

Each table merges by key across configuration layers: a nearer layer replaces a
boolean for the same class or rule id, including replacing `false` with `true`.
Missing keys preserve the earlier value; built-in defaults apply after merging.
An explicit rule-id switch wins over its class switch, even when the rule switch
comes from an ancestor and the class switch from a nearer layer. To reverse that
exception, set the same rule id in the nearer layer. Unknown classes and unknown
rule ids are configuration errors; custom ids are checked after definitions merge.

Use `false` under `[settings.rules]` to disable an individual rule. These switches
do not replace `[[rules]]` definitions, bypass allowlists or filters, or turn on
public-key detection. They apply to scan, audit, check-file, check-codex and
redact-claude. Disabled rules are excluded before scanning.

With the defaults, `redact-claude` no longer masks prefix-less random tokens such
as bare `printenv` values unless an enabled signature or contextual rule matches.
A value under a credential-named variable (`API_KEY=…`, `SECRET_KEY=…`,
`GITHUB_TOKEN=…`, `AWS_SESSION_TOKEN=…`, also inside a command such as
`env API_KEY=… cmd`) is such a match and stays masked; a value under any other name
is not. Enable the heuristic class or the individual rule to restore that coverage.

`sekretbarilo doctor` reports class states, explicit rule overrides and
enabled/total counts. A disabled class can contain an explicitly enabled rule.
It also notes when the heuristic-only settings below have no effect because
`generic-high-entropy-value` is disabled.

### `[settings]`

Global settings that affect scanning behavior.

```toml
[settings]
# minimum shannon entropy for rules with entropy thresholds (default: none, uses per-rule thresholds)
# valid range: 0.0 - 8.0 (typical values: 3.0 - 4.5)
# lower values = more sensitive (more potential secrets detected)
# higher values = less sensitive (fewer false positives)
entropy_threshold = 3.5

# report public keys (PEM, PGP, OpenSSH) as findings (default: false)
# when false, public key material is suppressed to reduce noise
detect_public_keys = false

# structural exemptions for the heuristic rule generic-high-entropy-value (default: true)
# applies only when the rule is enabled; affects no other rule
exemption_layer = true

# where generic-high-entropy-value looks inside a source file: "literals" or "all"
# unset means "literals" while exemption_layer is on, "all" while it is off
source_posture = "literals"

# skip generic-high-entropy-value on test paths (default: true, and only while the layer is on)
heuristic_skip_test_paths = true
```

`exemption_layer`, `source_posture`, and `heuristic_skip_test_paths` affect only
an enabled `generic-high-entropy-value`; none enables that rule. The old
`tier3_skip_test_paths` spelling remains a deprecated input alias. Both spellings
in the same file are an error. Across layers, either spelling updates the same
setting with ordinary nearer-layer precedence.

**Notes:**
- `entropy_threshold` is optional. If not set, each rule uses its own built-in threshold (if any).
- A global threshold is a floor for rules that declare an entropy threshold: it can raise, never lower, their threshold. It does not add an entropy check to a rule without one.
- Rule class does not determine whether entropy or stopword checks apply; some signature rules also declare thresholds.
- Use this to tune sensitivity globally without modifying individual rules.
- `exemption_layer` is scoped to `generic-high-entropy-value` and is on by default. See [The exemption layer](#the-exemption-layer) below.
- `source_posture` is scoped to the same rule. In `literals` posture a candidate in a source file counts only inside a string-literal body. The covered languages are Rust and Go, where each literal body is also a candidate of its own, and from 0.9.0 C and C++, Python, JavaScript and TypeScript (JSX and TSX included) and Swift, where a complete-source parse filters the findings. See [The source posture](#the-source-posture) below.
- `heuristic_skip_test_paths` turns off that one rule in test paths — under `test/`, `tests/`, `__tests__/`, `testdata/`, `fixtures/`, `benches/`, a `*_tests/` or `*-tests/` directory, an XCTest target such as `Tests/` or `FooTests/`, or a dotted .NET test project such as `Foo.Tests/` or `Foo.UnitTests/` (`spec/` and `specs/` are deliberately not directory segments); in `*_test.*`, `test_*.py`, `*_spec.rb`, `*Tests.swift`, `*Test.swift`, `conftest.py` and a JS/TS-family `*.test.<ext>`/`*.spec.<ext>` file, decided by the file's LAST extension (`js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts`, `cts`) — and inside a Rust `#[cfg(test)] mod name { }` region. Signature and contextual rules keep running there.
- `detect_public_keys` enables 3 gated rules (`pem-public-key`, `pgp-public-key-block`, `openssh-public-key`). When disabled (default), lines inside public key blocks are also suppressed to avoid false positives from base64 content. Can be overridden with `--detect-public-keys` CLI flag.

### The exemption layer

`generic-high-entropy-value` is the opt-in heuristic rule. When enabled, it can
produce false positives from non-secret high-entropy data. The exemption layer suppresses the shapes that are structurally not
credentials — import lines, markdown links, paths and globs, pinned digests, credential-free URLs,
source expressions and word-structured values — by testing the bytes of the value, never its
assignment key. It also collects quoted call-argument bodies so that a token passed to a function is
a candidate at all.

```toml
[settings]
exemption_layer = false
```

For an enabled rule, turning the layer off disables these mechanisms: the fourteen exemption steps, the
call-argument collector and the exact-length hex bypass are disabled together. Two things stay on
regardless, because they sit outside the switch: the path-shape check that runs before the layer,
and the `keys` entries of `[[allowlist.rules]]`, which are applied after it. The 20-byte minimum
length and the 4.0 entropy threshold are the same in both modes.

Disabling `exemption_layer` does not revert independent rule changes in 0.7.0; `password-in-url`
continues to report non-placeholder literal URL passwords regardless of strength. Restoring the
complete 0.6.3 detector behaviour requires the 0.6.3 release, not this switch.

### The source posture

A file whose extension names a supported language is scanned in `literals` posture for
`generic-high-entropy-value` alone, and bare code and comments produce nothing from this rule. Two
mechanisms find the literal bodies:

- `.rs` and `.go` use a literal tracker. A candidate is kept only when it lies inside a
  string-literal body, and every literal body on the line is a candidate of its own. The tracker
  reads each language's delimiters and escapes rather than parsing it, and an unknown lexical
  state — after a gap in a diff whose file could not be read, or in a history audit — is scanned in
  full posture rather than guessed at.
- From 0.9.0, C and C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.hh`, `.hpp`, `.hxx`, `.C`), Python (`.py`,
  `.pyi`), JavaScript and TypeScript (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.tsx`)
  and Swift (`.swift`) are parsed with pinned Tree-sitter grammars. The parse runs only on the
  exact complete file — the staged blob on `scan`, the file itself on `audit` and `check-file` —
  and adds no candidates: a finding of the full posture is dropped only when it lies outside every
  literal body the parse proved, so a value that starts at a prefix or operator before the opening
  quote is kept. A parse error, a literal form the adapter does not map, a missing complete file or
  an exhausted size or time budget keeps the whole file in full posture. Ambiguous `.h` headers
  stay in full posture.

Shell, configuration and data formats, markdown, extensionless files and unknown extensions are
unaffected.

```toml
[settings]
source_posture = "all"
```

Unset, the posture follows `exemption_layer`, so turning the layer off alone still yields exactly
the candidate set of the previous release with the layer off. An explicit value wins in both
directions. "Source files" in the table below means the covered languages; for the parsed
languages, literal bodies narrow the full-posture findings rather than adding candidates.

| `source_posture` | `exemption_layer` | Effect on source files |
| --- | --- | --- |
| unset | `true` | literals posture, literal bodies as candidates |
| unset | `false` | full posture; exemption steps and the call-argument collector off |
| `"literals"` | `true` | literals posture |
| `"literals"` | `false` | literal candidates and the posture stay on; the structural exemption steps and the hex bypass are off, while the length and ASCII gate, the path check, variable-reference detection, the allowlists and the stopwords keep running |
| `"all"` | `true` | the 0.7.0 default, with the call-argument collector |
| `"all"` | `false` | the layer off entirely |

`heuristic_skip_test_paths` is separate and on by default: a test path skips this one rule. A path is a
test path when a directory segment is exactly `test`, `tests`, `__tests__`, `testdata`, `fixtures`
or `benches`, ends in `_tests` or `-tests`, is an XCTest target name — `Tests` itself, or a CamelCase
`Tests` suffix after a letter or digit, as in `FooTests` or `FooUITests` — or is a dotted .NET test
project name: a non-empty prefix, a `.`, then a run of ASCII alphanumeric characters ending in
`Tests`, as in `Foo.Tests` or `Foo.UnitTests`. `spec` and `specs` are deliberately not directory
segments, because a bare `spec/` directory is also a common production specification/schema package
name. The file name matches when it is `*_test.*`, `test_*.py`, `*_spec.rb`, `*Tests.swift`,
`*Test.swift`, `conftest.py`, or a JS/TS-family `*.test.<ext>` or `*.spec.<ext>` name decided by the
file's LAST extension (`js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts` or `cts`, so `x.spec.d.ts` still
matches via the final `.ts`, while `config.test.env` and `api.spec.json` do not). A path carrying a
literal `..` segment anywhere is never a test path. The segment names are case-sensitive, so
`latest`, `contests`, `Testimonials` and `Foo_Tests` stay ordinary directories, and `testing` is
deliberately not a test segment, because it usually holds shipped test helpers rather than tests. A
Rust `#[cfg(test)] mod name { }` region is treated the same way, recognised by the literal tracker on
the exact attribute applied to a `mod` item — `cfg(all(test, ...))`, the attribute on a `fn`, a
`use` or an `impl`, and other languages are gaps — and only in `literals` posture, so
`source_posture = "all"` does not get it while the directory skip applies under any posture. The
skip applies only while `exemption_layer` is on.

The reasoning, what the posture forfeits and what it recovers, is in
[ADR 0003](../adr/0003-tier3-source-posture.md).

`--trace-exemptions` also prints, once per run and on stderr only, a
`[TRACE] rule:disabled <id> class=<class> reason=<default|class|rule override>` line per
rule the switches turn off and a `[TRACE] rule:gated <id> ... reason=detect_public_keys` line per
public-key rule held back by `detect_public_keys`. These lines are not findings and do not change
the exit status. A disabled rule has no candidate to exempt. For an enabled heuristic rule, the flag reports every exemption decision as a pseudo-finding of its own, named
`exempt:` plus the step that suppressed the value: `file`, `import`, `markdown`, `path`, `relpath`,
`mktemp`, `pin`, `url`, `regex`, `syntax`, `wordshape`, `digest`, plus `exempt:code` for a candidate outside every literal body in a
source file and `exempt:testpath` for the test-path skip. It answers the question of which gate
stopped a value, and an absent decision says the value never reached that gate.

```
  file: src/config/discovery.rs
  line: 118
  rule: exempt:path
  match: cr*****ml
```

The flag exists on the CLI only, so the hook surfaces (`check-file`, `check-codex`, `redact-claude`)
never see those pseudo-findings. While it is on they do count as findings for the `scan` and `audit`
exit codes, so a comparison run of `scripts/corpus-audit.sh` is made without it and the flag is
added to a separate run. See [Testing False Positives]({{ '/testing-false-positives/' | relative_url }})
and [ADR 0002](../adr/0002-tier3-exemption-layer.md).

### `[allowlist]`

Global allowlists that skip findings based on file path or secret value.

```toml
[allowlist]
# file path patterns to skip (regex, matched against full relative path)
paths = [
  "test/fixtures/.*",           # skip all files in test/fixtures/
  "docs/examples/.*",            # skip documentation examples
  "vendor/.*",                   # skip vendored dependencies
  ".*\\.min\\.js$",              # skip minified javascript
]

# additional stopwords (findings containing these strings are skipped)
# these are merged with the built-in default stopwords
stopwords = [
  "my-project-specific-safe-token",
  "known-test-api-key-12345",
  "company-safe-prefix",
]
```

**Default stopwords** (always active, even if not listed):
- `example`, `test`, `sample`, `placeholder`, `dummy`, `changeme`, `fake`, `mock`, `todo`, `fixme`, `xxx`, `lorem`, `default`, `replace_me`, `insert_here`, `your_`, `my_`

Word-based stopwords are consulted only by the rules that carry an `entropy_threshold` (34 of the 114 built-in rules at the time of writing; `grep -c '^entropy_threshold' src/config/rules.toml` gives the current count). The other rules still reject the built-in placeholder examples, but ignore stopwords otherwise: a string matching `AKIA` plus sixteen key characters is an AWS key whatever else it contains.

The split follows the entropy threshold, not the rule class. `mailchimp-api-key`, `facebook-access-token`, `dropbox-api-token` and `launchdarkly-sdk-key` are signature rules that do carry a threshold, so stopwords reach them. `airtable-api-key`, `twilio-api-key`, `azure-storage-account-key`, `password-in-url`, `webhook-url-with-token` and `generic-password-assignment` match case-insensitively but carry no threshold, so word-based stopwords do not apply to them. Password rules reject stopword values separately, and not the same way: `generic-password-assignment`
requires the value to also clear the password-strength heuristic, while `password-in-url` instead
checks the value against a fixed placeholder list (`is_url_password_placeholder` in
`src/scanner/password.rs`) plus the user's own stopwords, so a weak but non-placeholder URL
password is still reported.

To allowlist a value a stopword cannot reach, use a per-rule `regexes` entry (see [`[[allowlist.rules]]`](#allowlistrules)).

**Default allowlisted paths** (built-in, automatically skipped):
- Binary files: `.png`, `.jpg`, `.gif`, `.pdf`, `.exe`, `.dll`, `.zip`, `.gz`, `.tar`, `.mp3`, `.mp4`, etc.
- Generated files: `.min.js`, `.min.css`
- Lock files: `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`, `pnpm-lock.yaml`, etc.
- Vendor directories: `node_modules/`, `vendor/`, `.bundle/`, `bower_components/`, `__pycache__/`, `.git/`

The complete lists are in [Agent Hooks]({{ '/agent-hooks/#fast-path-skipping' | relative_url }}).

### `[[allowlist.rules]]`

Per-rule allowlist overrides. These allow you to skip findings for specific rules based on value pattern or file path.

```toml
# skip a known safe AWS key value
# (this particular one, from AWS's own docs, is already allowlisted by a
#  built-in rule allowlist - it is shown here for the syntax)
[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = []

# skip generic-api-key findings in test files
[[allowlist.rules]]
id = "generic-api-key"
regexes = []
paths = ["test/.*", "spec/.*"]

# skip specific known-safe JWT token value
[[allowlist.rules]]
id = "jwt-token"
regexes = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\..*"]  # example jwt header
paths = []

# combine value and path allowlists
[[allowlist.rules]]
id = "github-personal-access-token"
regexes = ["ghp_[0-9a-zA-Z]{36}"]                          # skip tokens matching this pattern
paths = ["fixtures/github/.*", "testdata/.*"]              # skip findings in these paths

# skip generic high-entropy values assigned to known-safe environment keys
[[allowlist.rules]]
id = "generic-high-entropy-value"
keys = ["TMPDIR", "SSH_AUTH_SOCK", "GHOSTTY_*"]
```

**Notes:**
- `id` must match an existing rule ID (built-in or custom).
- `regexes` are matched against the captured secret value (not the whole line).
- `paths` are matched against the file path.
- `keys` applies only to `generic-high-entropy-value`; using a non-empty `keys` list for any other rule is a configuration error.
- `keys` use case-sensitive whole-key matching: `*` matches zero or more characters, `?` matches exactly one character, and every other character is literal. A pattern needs at least one literal character, so a wildcard-only pattern (e.g. `*`, `**`, `?`) that would match every key is a configuration error, as is an empty pattern. For quoted assignment keys, matching removes one surrounding pair of matching single or double quotes.
- Per-rule `regexes` still see only the captured value. For `generic-high-entropy-value`, `keys` is the one allowlist mechanism that sees the assignment key.
- Both `regexes` and `paths` can be empty (use only one or both); `keys` can be omitted or empty to preserve the default behavior.
- Per-rule allowlists from config files are **merged** with allowlists defined in the rule itself (from `rules.toml`).

Allowlisting a key is intentionally narrow but does exempt any opaque or random-looking value assigned to that key from `generic-high-entropy-value`, including a URL-shaped value. It does not disable any other rule, so named-secret rules can still report values under an allowlisted key.

### `[audit]`

Audit-specific configuration (only affects `sekretbarilo audit` command).

```toml
[audit]
# include untracked ignored files in audit (default: false)
# when true, files matched by .gitignore are also scanned
include_ignored = false

# additional patterns to exclude from audit (regex, matched against file path)
# these are merged with the global allowlist.paths
exclude_patterns = [
  "^vendor/",
  "^build/",
  "^dist/",
  "^target/",
]

# patterns to force-include during audit (regex, matched against file path)
# these override exclude_patterns (if a file matches both, it's included)
include_patterns = [
  "\\.rs$",      # force-include all rust files
  "\\.toml$",    # force-include all toml files
]
```

**Notes:**
- `include_ignored = true` includes files matched by `.gitignore` (useful for scanning generated files, build artifacts, etc.).
- `exclude_patterns` is useful for skipping large directories that don't contain sensitive data.
- `include_patterns` takes precedence over `exclude_patterns`.
- Patterns are matched using regex (not glob).

### `[[rules]]`

Custom detection rules. These are merged with the 114 built-in rule definitions (110 enabled by default).

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
```

**Required fields:**
- `id` - unique identifier for the rule (used for allowlist overrides and merging)
- `description` - human-readable description (shown in findings)
- `regex` - regex pattern to match secrets (must have at least one capture group)
- `secret_group` - which capture group contains the secret (1-indexed, typically `1`)
- `keywords` - list of lowercase keywords for aho-corasick pre-filter (improves performance by only running regex on matching lines)

**Optional fields:**

```toml
[[rules]]
id = "custom-high-entropy-token"
description = "Custom high-entropy token"
regex = "(?i)custom[-_]?token\\s*[=:]\\s*['\"]([^'\"]{20,})['\"]"
secret_group = 1
keywords = ["custom_token", "custom-token"]
entropy_threshold = 4.0    # require minimum shannon entropy of 4.0 for this rule

[rules.allowlist]
regexes = ["CUSTOM_SAFE_TOKEN_.*"]   # skip values matching this pattern
paths = ["test/.*"]                   # skip findings in test files
```

- `class` - `signature`, `contextual`, or `heuristic`. If omitted, a replacement of a built-in id inherits its class; a new custom id defaults to `contextual`. There is no `enabled` field on a definition: use `[settings.rules]`.
- `entropy_threshold` - minimum Shannon entropy for the captured secret (0.0 - 8.0). The global setting can raise this floor; a rule without a threshold does not gain an entropy check.
- `secret_groups` - alternative capture group indices, checked in order when `secret_group` did not participate in the match. Defaults to `[]`; for example, `[2, 3, 4]` supports regex alternatives for different quoting forms. If no configured group participates, the full match is used, preserving existing custom-rule behavior.
- `payload_group` - a nonzero capture group index selecting the payload without its provider prefix. An index missing from the regex is a configuration error.
- `min_payload_entropy` - minimum Shannon entropy of that payload (0.0 - 8.0). Requires `payload_group`.
- `reject_hex_payload` - reject a payload made entirely of hex digits. Defaults to `false`. Requires `payload_group`.
- The two payload checks apply only to a match in which `payload_group` participates. A match through a regex branch without that group is reported without them, so place the payload group inside every alternative the checks should cover.
- `allowlist.regexes` - value patterns to skip (merged with `[[allowlist.rules]]` overrides)
- `allowlist.paths` - file path patterns to skip (merged with `[[allowlist.rules]]` overrides)

---

## Skipping Hierarchical Discovery

By default, sekretbarilo discovers and merges all config files in the hierarchy. To skip this behavior and use only explicit config files:

```sh
# use only this config file (no auto-discovery)
sekretbarilo scan --config my-config.toml

# merge multiple explicit config files (order matters: last wins for scalars)
sekretbarilo scan --config base.toml --config overrides.toml
```

When `--config` is provided, hierarchical discovery is completely skipped. Only the specified file(s) are loaded and merged.

---

## CLI Overrides

You can override config settings via command-line flags (these take precedence over all config files):

```sh
# override global entropy threshold
sekretbarilo scan --entropy-threshold 4.5

# add stopwords
sekretbarilo scan --stopword my-known-safe-token --stopword another-safe-value

# add allowlist paths
sekretbarilo audit --allowlist-path "^vendor/" --allowlist-path "^build/"

# combine config file with cli overrides
sekretbarilo scan --config .sekretbarilo.toml --stopword test-override
```

**Available CLI flags:**
- `--config <path>` - explicit config file (repeatable, skips auto-discovery)
- `--no-defaults` - skip built-in rules (use only custom rules from config)
- `--entropy-threshold <n>` - override global entropy threshold
- `--stopword <word>` - add a stopword (repeatable)
- `--allowlist-path <pattern>` - add a path pattern to allowlist (repeatable)
- `--exclude-pattern <pattern>` - add an audit exclude pattern (repeatable, audit only)
- `--include-pattern <pattern>` - add an audit include pattern (repeatable, audit only)
- `--detect-public-keys` - report public keys as findings (default: suppressed)

See the [CLI Reference]({{ '/cli-reference/' | relative_url }}) for a complete list of available flags.

---

## Config Validation

sekretbarilo validates config files at load time:

- **Missing files:** If a discovered config file doesn't exist, it's silently skipped (no error).
- **Empty files:** Empty config files are silently skipped.
- **Parse errors:** Invalid TOML syntax, a wrong value type, an unknown class under `[settings.rule_classes]` or both skip-test-path spellings in one file are fatal (exit 2). The message names the file, line and column and a fixed category; it never quotes the file's contents. A file that is not valid UTF-8 is a parse error too (`invalid UTF-8 encoding`), for a discovered file and for `--config` alike. A discovered file that cannot be read at all (permissions, I/O) is still skipped with a warning.
- **Unknown rule ids:** An id under `[settings.rules]` that names no built-in or custom rule is fatal, with or without `--no-defaults`.
- **Invalid regex:** Invalid regex patterns in rules or allowlists cause an error (fatal). An allowlist error is reported as a fixed category (`an allowlist path, stopword, regex or key pattern is invalid`), never with the pattern itself.
- **Nothing staged:** `scan` loads and validates the configuration before it looks at the staged diff, so a configuration error, an unknown rule id or a missing `--config` file exits 2 even when nothing is staged, and `--trace-exemptions` still prints its rule-switch lines.
- **Agent hooks:** `check-file` and `check-codex` fail closed (exit 2 and a blocked tool call) on a trusted layer that cannot be read, is not UTF-8 or does not parse, and on an allowlist that does not compile; their reasons are fixed categories without config content. Untrusted in-workspace layers are ignored without being read, as described in [In-Workspace Config Trust](#in-workspace-config-trust-agent-hooks-only). `redact-claude` keeps its own protocol, described under [Redaction Policy](#redaction-policy).
- **Missing required fields:** Rules without required fields (`id`, `description`, `regex`, `secret_group`, `keywords`) cause an error (fatal).

**Example validation error:**
```
[ERROR] failed to compile rules: invalid regex in rule 'custom-token' (see: sekretbarilo help config)
```

`sekretbarilo help config` prints the full configuration reference and `sekretbarilo help rules` the resolved state of every rule. How to check a file before relying on it is in [Write a configuration file]({{ '/write-a-configuration-file/#validate-the-configuration' | relative_url }}).

---

## See Also

- [Getting Started]({{ '/getting-started/' | relative_url }}) - installation and quick start
- [Write a configuration file]({{ '/write-a-configuration-file/' | relative_url }}) - ready-made configurations, tips and best practices
- [CLI Reference]({{ '/cli-reference/' | relative_url }}) - complete list of command-line flags
- [Agent Hooks]({{ '/agent-hooks/' | relative_url }}) - how config applies to the Claude Code and Codex CLI hooks
- [How the agent hooks work]({{ '/how-agent-hooks-work/' | relative_url }}) - why an in-workspace config must be committed
- [Rules Reference]({{ '/rules-reference/' | relative_url }}) - default detection rules
