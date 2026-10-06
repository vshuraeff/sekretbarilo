---
layout: default
title: Architecture
nav_order: 8
---

# Architecture & Internals

sekretbarilo is a high-performance secret scanner written in Rust. This page explains how it works internally, from the ground up.

## Project Structure

```
src/
  main.rs           - cli entry point, hand-rolled command parsing
  lib.rs            - library exports
  agent/
    mod.rs          - check-file command, path resolution, stdin json parsing
    claude.rs       - claude code hook installation (settings.json)
    codex.rs        - check-codex command, codex cli hook installation
    apply_patch.rs  - extraction of added lines from codex apply_patch payloads
    hooks_json.rs   - shared reader/writer for claude and codex hook json
  audit/
    mod.rs          - working tree scanning
    history.rs      - git history scanning with branch resolution
    search.rs       - user-search pass (--search / --search-regex)
  config/
    mod.rs          - config loading and merging
    allowlist.rs    - allowlist compilation
    discovery.rs    - hierarchical config file discovery
    merge.rs        - config merge logic
    rules.toml      - 114 built-in rule definitions with explicit classes
  diff/
    mod.rs          - git diff retrieval
    parser.rs       - unified diff parser
  doctor/mod.rs     - diagnostic health checks
  hook/mod.rs       - git pre-commit hook installation
  output/
    mod.rs          - finding reports
    masking.rs      - secret value masking
  scanner/
    engine.rs       - main scanning pipeline
    rules.rs        - rule compilation
    entropy.rs      - shannon entropy calculation
    literals.rs     - per-language string-literal tracker (source posture)
    hash_detect.rs  - hash detection (sha-1, sha-256, md5)
    password.rs     - password strength heuristics
    pubkey.rs       - public key block detection and tracking
fuzz/fuzz_targets/
  literals.rs       - literal tracker against arbitrary bytes
```

## Rule selection

Configuration resolves `signature`, `contextual`, and `heuristic` class switches
by key, then applies explicit rule-id overrides. Signature and contextual classes
default to enabled; heuristic defaults to disabled. Disabled rules are excluded
before scanning, including agent-hook and redaction surfaces. The public-key gate
remains independent. Classes do not replace the existing context, entropy or
stopword filters. `doctor` reports effective class states, rule exceptions and
enabled/total counts; `--trace-exemptions` reports `rule:disabled` once per disabled
rule with its id, class and disabling reason.

The parts of the pipeline below scoped to `generic-high-entropy-value` apply only
when it has been enabled. Its exemption, posture and test-path settings do not enable it.

## Scanning Pipeline (Core Engine)

The scanner processes files through a multi-stage pipeline optimized for speed and accuracy:

### 1. Git Diff Retrieval
```bash
git diff --cached --unified=0 --diff-filter=d
```
- retrieves only staged changes
- `--unified=0` minimizes context (we only scan added lines)
- `--diff-filter=d` excludes deleted files (no scanning needed)

### 2. Unified Diff Parsing
- splits diff into `DiffFile` structs with metadata:
  - `path`: file path
  - `is_new`, `is_deleted`, `is_renamed`, `is_binary`: file status flags
  - `added_lines`: vector of `AddedLine` structs with `line_number` and `content`
- handles multi-file diffs, multiple hunks per file, and edge cases:
  - binary files (via `Binary files ... differ` marker)
  - renames (extracts final path from `+++ b/` header)
  - root commits (with `--root` flag)

### 3. .env File Blocking
- immediate, unconditional block for `.env`, `.env.local`, `.env.production`
- excludes `.env.example`, `.env.sample`, `.env.template` (safe examples)
- prevents accidental exposure before scanning
- reported as rule `env-file-blocked` with `line: -` and `match: (blocked file type)` — the file is never read

### 4. Global Path Allowlist Check
pre-filters files to skip scanning:
- **binary extensions**: `.png`, `.jpg`, `.exe`, `.so`, `.woff2`, etc.
- **vendor directories**: `node_modules/`, `vendor/`, `.venv/`, etc.
- **generated files**: `package-lock.json`, `Cargo.lock`, minified `.min.js`
- **documentation**: `README.md`, `docs/`, `*.rst` (with entropy bonus)

### 5. Public Key Block Suppression
- tracks multi-line PEM/PGP public key blocks via `PubKeyBlockTracker`
- when `detect_public_keys` is disabled (default), lines inside public key blocks are skipped entirely
- prevents base64 content in public keys from triggering token rules (e.g., `EAA` → `facebook-access-token`)
- also detects single-line OpenSSH public keys (`ssh-rsa AAAA...`, etc.)
- gated rules (`pem-public-key`, `pgp-public-key-block`, `openssh-public-key`) are skipped unless enabled

### 6. Aho-Corasick Keyword Pre-filter
- single-pass scan across all rules' keywords simultaneously
- case-insensitive matching via aho-corasick automaton
- builds a bitset of "candidate rules" whose keywords matched
- drastically reduces regex evaluations: a line that matches no keyword never reaches a regex

**Example**: Line contains "akia" → activates `aws-access-key-id` rule

### 7. Regex Evaluation
- only evaluates regexes for rules whose keywords matched
- uses `regex::bytes` crate for binary-safe matching
- extracts full matches or capture groups via `secret_group` field
- handles multiple matches per line (iterates `captures_iter`)

**Example**: `(AKIA[A-Z0-9]{16})` matches `AKIAIOSFODNN7EXAMPLE`

### 8. Secret Extraction

- if `secret_group > 0`, extracts capture group value
- if `secret_group == 0`, uses full match
- skips empty matches

**Exemption layer** (rule `generic-high-entropy-value` only, `[settings] exemption_layer`, default on). The extracted value passes a sequence of structural predicates over its bytes; the first one that matches suppresses the finding. The assignment key is consulted by the pin and digest steps alone:

1. **file** — ignore files (`.gitignore`, `.dockerignore`, `.npmignore`, `.prettierignore`, `.eslintignore`, `.gitattributes`, `.helmignore`) and `CODEOWNERS` disable this rule alone; every other rule still runs on them
2. **import** — the surrounding line is an import or include statement
3. **markdown** — a wrapper is retargeted to the value it holds and evaluation continues on that inner value, a call-literal body included; only an inner value shorter than 20 bytes ends here. The wrappers are a markdown link `[label](target)`; an autolink `<scheme://...>`, including one whose closing `>` the value grammar consumed, with no `<` or `>` in its target; a one-item quoted flow sequence of a URL, `['https://...']`; and a markup element on one line or the part of one the line holds, anchored at both ends: the text after one or more open tags and before the matching close tag (`<string>text</string>`), the text between a leading `>` and a close tag when a formatter broke the open tag across lines (`>text</code`), or a URL with its scheme before a complete close tag when the element opened on the line before (`https://host/path</loc>`). Tag names are lowercase and shorter than 20 bytes, only a close tag at the end of the value may lack its `>`, and every further text run is shorter than 20 bytes and enclosed by an element of its own, so no byte that could hold a credential is left out of the evaluation
4. **path** — the value is path-shaped: rooted, at least two separators, no separator-free run of 20 bytes or more, and a wordy leaf. An extension never makes a leaf wordy: trailing dot parts of up to five alphanumerics or of letters only, of any length, are set aside while a stem remains, so `<opaque>.credentials` is reported while `secrets.production` is not; a leaf of two to four short lowercase words that each carry a vowel (`oh-my-pi`) counts as wordy. In a JSON pointer (`#/…`) a segment may open with a schema keyword's `$` (`#/$defs/name`) when that segment is one word, and a separator-free run of 20 bytes or more vetoes only when it is not word-structured; a pointer carrying such a keyword also passes the balance and chunk checks below. The step also claims a path rooted at, or carrying, a variable reference — `$HOME/…`, `${WORKSPACE}/…`, `${NAME:-default}/…`, `${NAME%.*}.ext`, `$(NAME)/…`, `{name}/…`, `%NAME%\…` — for every capture kind, keyed or not. Every literal piece, every piece of a reference name and of a default or pattern must read as a word or a number of at most four digits, and one rule then weighs the whole value: at least two words of four or more letters, and no fewer of them than short words outside the short-word vocabulary plus runs of digits after the first, where a reference whose name carries no short word outside the vocabulary (`HOME`, `STATE_DIR`) counts as one long word. No segment may be cut into short groups — four or more letter words of at most five letters in a row, carrying 14 letters or more, with vocabulary words passed over and the reference syntax ending a run. The reference reader follows the shell's parameter expansion: a subscript (`[@]`, `[*]`, `[n]`, `[$i]`), a `#` length or a `!` indirection, the default, alternative and error operators (`${NAME:?message}`), the pattern removals, substitutions (`/`, `//`, `/#`, `/%`) and case changes, an offset, nested defaults, `$(command)`, `$((arithmetic))` and `$[…]` with balanced brackets, `$$` and the other special and positional parameters (never `$2y$10$…`, whose `$2` runs into a letter), and an escaped `\$` or a `\"…\"` wrapper. The glob bytes `*` and `?` and the list joins `|` and `:` separate pieces, so `$HOME/Library/Caches/*.log`, `$HOME/.cargo/bin:$PATH` and `$HOME/Library/Caches|backups` are read too, and the leaf of every list item must be wordy, a reference or a bare glob. A default, pattern, replacement, message or counter is written in uniform case (each letter run lowercase, capitalized or all capitals); a list, a glob, an escaped path and references alone in coherent case, camel case of three-letter humps included; at most one distinct piece sets digits beside letter words of at most five letters; references with no separator between them need one word longer than five letters; and a run of 20 bytes or more between separators, joins, globs and reference syntax must read as words on its own: a file name whose parts are numbers or words closed by at most one number, in lowercase or camel case (`x86_64-unknown-linux-gnu`, `com.apple.WebKit.WebContent`), or an identifier. A module path rooted at a host (`github.com/owner/repo/pkg`, `golang.org/x/sys/unix`, `gopkg.in/yaml.v3`) passes a stricter rule instead: every part a word or a short number in coherent case, or a single letter or `vN` version; at most one mixed part; the words outweigh the short pieces; no chunk run, `/` included; and a wordy leaf. A scheme-less URL (`//host/…`) passes the rooted rule only when its authority carries no userinfo and every part after the host reads as a word in coherent case, a number or an abbreviation of at most five letters, with at most one mixed part, the words outweighing the short pieces, and no long run that fails the file-name reading; groups of four or five letters keep the rooted reading there, as a url slug of short words does. So `X="$VAR/<opaque>"`, an opaque token under a host, and short random chunks in a component, a name, a default, a pattern, a replacement, a subscript or a list item stay reported
5. **relpath** — for a bare capture standing alone on its line, a relative path: not rooted, no `://`, ASCII alphanumerics and `/`, `.`, `-`, `_` only, at least two `/`, no empty segment, a wordy leaf, exactly one non-leaf identifier segment (alphanumeric, with a digit or mixed case, shorter than 20 bytes) and the remaining segments, rejoined with `/`, word-structured. It covers a printed branch name such as `task/<16-character id>/integrator/lead` and runs on every surface, the redact hook's pathless text included. A bare dated file name counts as well, keyed or not: a `YYYY-MM-DD-` date, then parts that are word pieces, at most one of them mixed, words outweighing the short pieces, no chunk run, the file-name reading of the path step and a wordy leaf (`2026-09-10-docs-site-redesign.md`). For a keyed unquoted, double- or single-quoted capture it takes a relative path of words instead, reading a usage placeholder of fewer than 20 bytes as the words it holds (`Tests/<Class>/<method>`) and setting aside git's exclude magic before a pathspec (`:!docs/drafts.md`) and an English possessive after the leaf (`notes.md's`): not rooted, a `/` and no empty segment, every part between `/`, `.`, `-`, `_`, `+` and `:` a word, a number of at most eight digits, or the one letter-and-digit part of at most eight bytes the value may carry (one run of digits, each run of letters lowercase, capitalized or all capitals), at least two words of four or more letters and no fewer of them than shorter words, at most one vowel-less four-letter word such as `html`, no segment cut into short groups, and a wordy leaf read before any `:` suffix (`model: vendor/name-5-large:medium`, `where: dir/Type+Extension.swift:function`)
6. **mktemp** — under the same gating as relpath, a bare capture standing alone on its line with no assignment key: a `./`-prefixed single leaf whose stem is dash-joined lowercase words of three to nineteen bytes and whose suffix is exactly six alphanumerics, the shape `mktemp` prints, with stem and suffix together shorter than 20 bytes
7. **pin** — a reference pinned behind `@`, as a workflow `uses:` line writes it, gated on the exact key `uses`: a 40-hex commit digest, a docker image at a sha-256 digest, or a version tag `vN`, `vN.N` or `vN.N.N` (numbers of up to four digits, optionally on one lowercase branch word such as `release/v1`). Behind a tag, every owner, repository and path segment must be a name: words, numbers of up to ten digits and lowercase alphanumerics of up to five bytes, joined by `.`, `-` or `_`
8. **url** — a URL with no credential in any component. A URL-shaped value can leave the layer only through this step, so the regex, syntax, wordshape, symbols and template steps below are skipped for one. A path segment or fragment that is a slug (words and short numbers joined by `-`, `_` or `.`, at least half of its letter pieces words of four or more letters) carries no credential. A markdown link chain that the value grammar split inside a label or badge (`label](url)](target`) passes only when at least one target is an absolute URL, every target is a credential-free URL or a relative file reference (a path of file names holding a word of four or more letters, no query and at most a slug fragment), and any label tail is a name shorter than 20 bytes. A value with no scheme passes only as an email address or `user@host` destination whose local part and host labels are words
9. **regex** — for the whole value of a quoted, bracketed or call-literal capture, and for an unquoted or bare capture delimited as a regex literal (`/body/flags`, the body alone) or passed as the pattern of a regex-taking command or option (`grep`, `egrep`, `rg`, `sed`, `awk`, `--regexp`, `--extended-regexp`, `--perl-regexp`, or a short-option cluster carrying `E` or `P` before its key), on every surface, the redact hook's pathless text included. A value is exempt when it carries two distinct construct kinds from a closed list — a bracket class holding a range, an escape, a POSIX class name or a leading `^`; a quantifier standing directly after a class, a group or an escape; a backslash escape from a fixed set; a group opener — and a counted bracket class is among them, so a quantifier alone never satisfies the minimum although it counts as one of the two kinds. Any contiguous run of 20 bytes or more of `[A-Za-z0-9_-]` outside those constructs disqualifies the value and keeps it a candidate, traced as `exempt:regex`
10. **syntax** — for unquoted and bare captures, a complete source expression covering the flagged range (`src/scanner/syntax.rs`). An expression is a balanced group after an identifier, a member chain, a `#macro(`, `@Attribute(` or `#[attribute]` head, a `$0` closure parameter, a Go slice, array or map type, or a call left open at the line end; a member chain without a group needs two or more segments that read as words, with at most one opaque segment of eight bytes or fewer, and a lone type name counts only when marked `?` or `!`. A capture that closes a group it did not open is read from that group's opener on the same line. An inner token of 20 bytes or more vetoes the span when its entropy reaches 4.0 or its length is exactly 32, 40 or 64 hex digits, so an expression can never cover a credential; an identifier whose pieces read as words and a grouped numeric literal of at most 16 digits do not veto, and a quoted body inside the span vetoes word by word around its interpolation holes
11. **wordshape** — words, camel case or snake case rather than an opaque run, bounded against chunked secrets: a word of four bytes or more counts only with a vowel (`y` included) and no run of more than four consonants, three quarters of those long words must pass, and near-uniform long-word lengths allow no failing word at all. Camel case is judged per separator-delimited segment, so one separator between two camel-case segments (`hookSpecificOutput.hookEventName`) counts like a camel-case value of four or more long words, unless its words are cut into short groups as above. A camel-case identifier may open with a hungarian `k`, with a framework class prefix from a closed list (`NS`, `CF`, `CGS`, `AX`, `UI`, `OS` and the other platform prefixes) or a short-word acronym (`URL`, `DNS`), may carry short-word acronyms inside (`sourceDNSRecordType`) and may close on one run of at most four digits; behind such a prefix three long words suffice (`NSCameraUsageDescription`), and every one of these widened forms is refused when its words are cut into short groups. The step also recognizes three value shapes whose every variable position is either shorter than 20 bytes or judged by the identifier rule above: a search pattern of alternation groups, anchors and POSIX classes whose literal runs are words (`(^|/)(target|node_modules)$`; each run must pass as an item of a plain alternation, and the runs together need three long words and no run of short groups); an environment entry, an upper-snake name and a number of at most four digits or a flag (`GOFLAGS=-mod=readonly`, `NODE_EXTRA_MEMORY_LIMIT_MB=4096`); and a key chord, modifier keys from a closed list, a short key and an action the identifier rule reads (`super+shift+t=toggle_quick_terminal`). A bare word after an environment name (`NAME=always`), a comma list and a chord with no modifier stay reported
12. **symbols** — a lookup table of punctuation, such as a delimiter set tested with `contains`: a backslash escape or a byte is one element, no element repeats, no two unescaped letters or digits stand side by side, and at most one element in eight is one. A character set spelled out as a string (`abc…xyz0123456789-_.`) stays reported: its bytes are the dummy token test suites carry
13. **template** — a format template with at least one placeholder: brace fields, printf conversions (a currency sign before one included, `$%(price).2f`), `${name}` substitutions and interpolation holes (`\(expr)`, `\#(expr)`, `#{expr}`, `${expr}`, `($name.field)`) whose expressions are identifiers, member accesses and calls of words; or a string body whose escapes are its only structure (`\"feature-flag-rollout\"\nenabled`), words joined by separators, `=` and `,`, whose lines of 20 bytes or more are word-structured as they stand. The literal text, read with every placeholder, hole and escape as a separator, must carry no opaque payload and no run of short groups, so a token cut into chunks and joined by placeholders stays reported
14. **digest** — the last step before the hex bypass, gated on an assignment key separated from its value by a `:` (for a quoted value, a `:` or `=` before the opening quote). Under a `digest`, `checksum` or `x-checksum-<algorithm>` key: an exact-length hex digest of 32, 40 or 64 digits, optionally carrying its own `md5`, `sha1`, `sha-1`, `sha256` or `sha-256` prefix before a `:` or `=`, whose length agrees with the algorithm named on either side. Under the go.sum `h1` label: a standard base64 sha-256 of exactly 44 bytes, `=` padding included. Under an `integrity`, `hash`, `digest` or `checksum` key: a subresource-integrity value `sha256-`, `sha384-` or `sha512-` followed by standard base64 of exactly 44, 64 or 88 bytes

With the layer enabled, a bounded lexical pass also collects quoted call-argument bodies once per logical line, independently of the regex capture cursor. Ordinary single/double quotes and Rust raw/byte delimiters feed exact body ranges into the shared generic entropy evaluator, with no key and no import or syntax exemption; a markdown link body is retargeted to its target. Redaction preserves surrounding delimiters and other arguments. Body-level path, pin, URL, regex and wordshape exemptions retain their recall costs; a regex body whose only structure is `|`-separated words carries none of the regex step's evidence and may become a finding. The collector does not join multiline call fragments or support Python-specific literal forms or Go backticks; a complete literal in an unfinished same-line call is still collected. Keyless call bodies receive no assignment hex bypass, so hex bodies below the ordinary entropy threshold remain undetected. Disabling the layer disables collection as well as exemptions.

**Source posture** (`[settings] source_posture`, unset means `literals` while the layer is on and `all` while it is off). A file whose extension names a tracker language — `.rs` and `.go` (`language_for_path` in `src/scanner/literals.rs`) — is scanned in literals posture for this rule: a candidate survives only when its range lies inside a string-literal body, and every literal body on the line is a candidate of its own, evaluated like a call-argument body with no key, no import or syntax step and no hex bypass. A candidate outside every body is suppressed with the label `exempt:code`. A regex candidate whose normalised range equals a body owns it and keeps its key, so the `keys` allowlist and the quoted-assignment hex bypass still apply there. The tracker is a per-language delimiter and escape table carried across lines, not a parser, and unknown lexical state never narrows a scan: on `scan` the staged blob supplies the state of the added lines, and where no context exists (history audit, a path outside the working tree, an unreadable blob) the lines after the gap are scanned in full posture. Shell, configuration and data formats, markdown, extensionless and unknown extensions keep the posture of the previous release. From 0.9.0 the C/C++, Python, JavaScript/TypeScript (JSX and TSX included) and Swift families, which 0.8.0 deferred to full posture, are covered by a complete-source parser instead of the tracker (`supports_path` and `analyze` in `src/scanner/source_literals.rs`, pinned Tree-sitter grammars): it runs only on the exact complete blob and passes no literal candidates to the evaluator. A `generic-high-entropy-value` finding disjoint from every proved literal body is dropped as `exempt:code`, one inside a single string body stands, and one that straddles a body and a string prefix, an interpolation hole or a delimiter is traced `exempt:clip` and replaced by the body segments it touches, each evaluated again as a keyless literal body; a segment of a regex literal (`/.../flags`) reaches the regex step that way. A parse error or recovered parse, an unmapped literal form (in Swift, regex literals and a comment inside a literal among them), a missing complete blob or an exhausted size, node or time budget keeps the whole file in full posture ([parser notes](../adr/0003-parser-posture-implementation.md)).

**Test paths** (`[settings] heuristic_skip_test_paths`, default on, active only while the layer is on). A path with a directory segment `test`, `tests`, `__tests__`, `testdata`, `fixtures` or `benches`, a segment ending in `_tests` or `-tests`, an XCTest target segment (`Tests`, or a CamelCase `Tests` suffix after a letter or digit, as in `FooTests` or `FooUITests`), or a dotted .NET test project segment (a non-empty prefix, a `.`, then a run of ASCII alphanumeric characters ending in `Tests`, as in `Foo.Tests` or `Foo.UnitTests`) — `spec` and `specs` are deliberately not directory segments, since a bare `spec/` directory is also a common production specification/schema package name — or a file name matching `*_test.*`, `test_*.py`, `*_spec.rb`, `*Tests.swift`, `*Test.swift`, `conftest.py`, or a JS/TS-family `*.test.<ext>` or `*.spec.<ext>` name decided by the file's LAST extension (`js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts`, `cts`, so `x.spec.d.ts` still matches via the final `.ts`), skips this rule alone with the label `exempt:testpath` (`is_test_path` and `generic_rule_skip` in `src/config/allowlist.rs`); a path carrying a literal `..` segment anywhere is never a test path; signature and contextual rules still run there. A Rust `#[cfg(test)] mod name { }` region counts the same way, under the same label and the same setting: the literal tracker recognises it in code state on the exact attribute `cfg(test)` applied to a `mod` item, so `cfg(all(test, ...))`, the attribute on a `fn`, a `use` or an `impl`, and other languages are gaps, and the recognition is active in literals posture only — `source_posture = "all"` does not get it, while the directory skip applies under any posture.

The layer changes which values are considered, never the gates they are measured against: the 20-byte minimum and the 4.0 threshold are unchanged, and signature and contextual rules never enter it. The path-shape check that runs before the layer, and the user entropy-key allowlist that runs after it, are both independent of the switch.

**Hex bypass**: a hex value of 32 through 128 digits (optionally `0x`-prefixed) assigned under a key that is not `*_id`, `*_hash` or `address`-shaped skips the Shannon gate of step 14 and is emitted if it clears every other gate. This is the one place the layer makes the rule stricter. It applies to double-quoted, single-quoted, bracketed and unquoted captures, never to bare lines or call bodies, and requires both that the value's own assignment carry no hash context (step 12) and that the value reach 2.0 bits of entropy over the 16-symbol hex alphabet.

**Rationale and residuals**: [ADR 0002](../adr/0002-tier3-exemption-layer.md) for the layer, [ADR 0003](../adr/0003-tier3-source-posture.md) for the source posture and the test-path skip.

### 9. Per-Rule Allowlist Check
each rule can define:
- **value regexes**: patterns to match against extracted secret (e.g., `AKIAIOSFODNN7EXAMPLE`)
- **path patterns**: file path regexes to skip (e.g., `test/.*`)
- **key patterns**: assignment-key wildcard patterns to skip (e.g., `TMPDIR`, `GHOSTTY_*`); applies only to `generic-high-entropy-value` matches

### 10. Variable Reference Detection
skips values that are template variables, not real secrets:
- `$VAR`, `${VAR}`, `%VAR%` (shell variables)
- `process.env.VAR` (node.js)
- `os.environ['VAR']` (python)
- `ENV['VAR']` (ruby)

### 11. Stopword Filtering
rules with `entropy_threshold` check for common safe words:
- built-in: `test`, `example`, `fake`, `placeholder`, `changeme`, `dummy`, `mock`
- user-configurable via `[allowlist] stopwords = [...]`
- **rules without an entropy threshold** only check placeholder patterns (`XXXX...`, `****...`) to allow tokens like `sk_test_` that inherently contain "test"
- **`password-in-url`** is neither: it checks the value against a fixed placeholder list
  (`is_url_password_placeholder` in `src/scanner/password.rs` — exact matches like `password`,
  `changeme`, `example`, `test`, `<PASSWORD>`-shaped brackets, `xxx...`/`***...` runs, and
  `your`/`my` plus a password word) plus the user's own `[allowlist] stopwords`, not the built-in
  stopword list above

### 12. Hash Detection
prevents false positives on git commit hashes and checksums:
- **full-length hashes**: 32 (md5), 40 (sha-1), 64 (sha-256) hex chars
- **abbreviated hashes**: 7-12 hex chars
- requires context keywords on the same line: `commit`, `sha`, `hash`, `checksum`, `digest`, `integrity`
- uses word-boundary matching to avoid false matches (`hash` inside `HashMap`)

**Example**: `sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` → skipped

This hash context keeps precedence over the hex bypass of step 8: a hex value whose own assignment carries a hash context word is a hash, not a secret. For `generic-high-entropy-value` the word is looked for in the stretch of the line that assignment owns, from the end of the previous value to the start of the next key, so `sha256=<digest> api_key=<hex>` still reports the second value.

### 13. Password Strength Heuristics
for `generic-password-assignment` only:
- **weak passwords allowed**: `password`, `admin`, `123456`, `changeme`
- **strong passwords blocked**: complex passwords with high entropy + character classes
- scoring:
  - shannon entropy (0-5)
  - character class bonus (uppercase + lowercase + digits + special ≥ 3 → +1.0, all 4 → +2.0)
  - length bonus (≥12 chars → +0.5, ≥20 chars → +1.0)
  - dictionary penalty (-4.0)
  - short-value penalty (< 6 chars → -2.0)
  - score is clamped at 0.0; threshold: 6.0

**Rationale**: `password=test` is a placeholder, while a long random value that mixes character classes scores past the threshold and is reported as a real secret

`password-in-url` does not use this heuristic. It captures any length of password (no minimum) and
is filtered at step 11 instead, by `is_url_password_placeholder` (`src/scanner/password.rs`) plus
the user's own stopwords, so a weak but non-placeholder URL password is still reported.

### 14. Shannon Entropy Evaluation
for rules with `entropy_threshold` set:
- calculates shannon entropy over all 256 byte values
- min length: 20 characters (shorter strings skip entropy check)
- documentation file bonus: +1.0 to threshold (raises bar for false positives in docs)
- global override: `--entropy-threshold` or `[settings] entropy_threshold = 3.5` sets a floor

**Formula**: `H = -Σ(p_i * log2(p_i))` where `p_i` is frequency of byte `i`

**Example**: `aaaaaaaaaaaaaaaaaaaaaaaa` → entropy ≈ 0.0 (blocked), `aB3dEf7hIj1kLmN0pQrStUvWxYz` → entropy ≈ 4.2 (allowed)

**Hex bypass**: a value admitted by the hex bypass of step 8 skips this gate and nothing else; the allowlists, variable-reference detection and stopwords still apply to it.

**Baseline**: the measured entropy of short random passwords, and why the 20-character and 4.0 gates are left unchanged, are recorded in [ADR 0001](../adr/0001-entropy-baseline-8-char-password.md).

### 15. Output with Masking
- diagnostic secret values masked: `AK**************FG` (first 2 + last 2 chars)
- short values (≤5 chars): fully masked with one `x` per character (`abc` → `xxx`)
- prefixes: `[ERROR]` (scan), `[AUDIT]` (audit), `[AGENT]` (check-file / check-codex), `[SEARCH]` (user-search pass)

`redact-claude` uses full `[REDACTED]` replacement instead of diagnostic prefix/suffix masking.

---

## Audit Pipeline

### Working Tree Mode (`sekretbarilo audit`)

1. **enumerate tracked files**: `git ls-files -z` (nul-delimited for safe filenames)
2. **optional: include ignored files**: `git ls-files -z --others --ignored --exclude-standard`
3. **apply exclude/include patterns**: filter via regex (from `[audit]` section)
4. **read files in parallel**: rayon thread pool, converts to synthetic `DiffFile` structs
5. **feed through scanner engine**: same pipeline as scan mode
6. **report findings**: grouped by file, with masked values

**Optimizations**:
- parallel file reads via rayon (4+ files)
- binary detection: checks first 8KB for null bytes
- error handling: read failures reported but don't stop scanning

### Git History Mode (`sekretbarilo audit --history`)

1. **list commits**: `git rev-list --all --format=%H%n%an%n%ae%n%aI%n%at`
   - optional filters: `--branch`, `--since`, `--until`
   - parses: hash, author, email, date, timestamp (unix)

2. **identify root commits**: `git rev-list --max-parents=0 --all`
   - required for correct scanning (root commits need `--root` flag)

3. **extract per-commit diffs**: `git diff-tree -p --no-commit-id -r --unified=0 --diff-filter=d -m <hash>`
   - `-m` splits merge commits into individual diffs per parent (catches secrets in conflict resolution)
   - `--root` for root commits

4. **parallel commit processing**: rayon parallelizes commit scanning
   - progress reporting every 50 commits
   - error count tracked atomically

5. **deduplication**: same secret + same file + same rule = keep earliest commit by timestamp
   - key: `(file, rule_id, matched_value)` → earliest `HistoryFinding`
   - sorts by timestamp, then commit hash, then file, then line

6. **branch resolution**: `git branch --contains <hash> --format=%(refname:short)`
   - only queries commits with findings (not all commits)
   - parallel resolution via rayon
   - best-effort: failures warned but don't stop reporting

7. **report findings**: grouped by commit, shows author email + branches
   - sanitizes output: strips control chars and bidi overrides (prevents terminal injection)
   - commit hashes are abbreviated in the report

### User-Search Pass (`--search` / `--search-regex`)

an additive pass that runs alongside the rule-based audit, never instead of it:

1. **compile patterns**: `--search` literals and `--search-regex` patterns (both repeatable)
2. **reuse the same file set**: whatever the audit pass enumerated, after exclude/include filtering
3. **report separately**: matches are printed under `[SEARCH]` with a trailing count line
4. **unmasked**: search hits show the matched text verbatim — the user asked for this exact string

audit-only by design: the flags are rejected on `scan`. a search match alone is enough to make the
command exit 1, even when the rule-based pass found nothing.

---

## Check-File Pipeline (Claude Code Agent Hook)

Triggered by claude code when reading a file via the `Read` tool.

### Input Modes
1. **stdin json** (`--stdin-json`): reads hook payload from stdin
   ```json
   {
     "tool_input": {"file_path": "/path/to/file.rs"},
     "cwd": "/project/root"
   }
   ```
2. **direct path**: `sekretbarilo check-file src/config.rs`

### Pipeline

1. **parse stdin json payload** (if `--stdin-json`):
   - reads up to 1 MB from stdin (prevents unbounded memory)
   - extracts `file_path` and optional `cwd`

2. **resolve file path**:
   - absolute paths: computes relative path from `cwd` for better vendor/pattern detection
   - relative paths: validates against path traversal (blocks `../../etc/passwd`)
   - returns `(relative_path, base_dir)`

3. **validate base directory**: checks `base_dir.is_dir()`

4. **.env blocking**: unconditional block for `.env` files (same policy as scan)

5. **fast-path rejection (default allowlist only)**:
   - uses hardcoded patterns (binary, vendor, lock files)
   - skips config loading for obvious skips (performance optimization)

6. **load hierarchical config (trusted loader)**:
   - discovers configs from `base_dir` up to home directory
   - merges all found configs
   - a `.sekretbarilo.toml` **inside the git working tree** is honoured only when it is git-tracked
     and unmodified against `HEAD`; otherwise the whole layer is dropped with
     `[WARN] ignoring untrusted in-workspace config: <path>`
   - this trust check applies to the agent-hook paths only (`check-file`, `check-codex`, `redact-claude`) — `scan`
     and `audit` load in-workspace configs unconditionally. see
     [Configuration]({{ '/configuration/' | relative_url }}) for the full rules

7. **full fast-path rejection (with user config)**:
   - applies user-defined allowlist paths
   - applies audit exclude patterns

8. **read file**:
   - converts to synthetic `DiffFile` (all lines treated as "added")
   - binary detection: first 8KB null byte check
   - error handling: read errors block (fail closed)

9. **compile scanner**: builds `CompiledScanner` from merged rules

10. **scan**: runs through scanner engine (same pipeline as scan mode)

11. **report findings** (to stderr):
    ```
    [AGENT] secret(s) detected in /path/to/file.rs

      file: file.rs
      line: 42
      rule: aws-access-key-id
      match: AK**************FG

    file contains 1 secret(s). reading blocked to prevent secret exposure.
    ```

12. **exit code**:
    - `0` = clean (claude reads file)
    - `2` = secrets found or error (claude blocks read)

**Key Design**: fail closed. errors (read failure, config error) exit 2 to prevent exposing secrets.

---

## Redact-Claude Pipeline (Claude Code PostToolUse)

`sekretbarilo redact-claude --stdin-json` receives the successful tool result, after execution. It is an in-memory output editor: it does not read or modify the source file to redact it.

1. **bounded input**: read at most 10 MiB and parse the PostToolUse payload.
2. **select text fields**: Bash stdout/stderr and text blocks, text-file Read content, and Grep content/result lines and filename arrays. Preserve the complete response structure, counters, and unknown metadata.
3. **trusted configuration**: load the existing trusted layers; use rules, entropy, password heuristics, and value exceptions without path exclusions or documentation relaxations.
4. **exact ranges**: the shared scanner exposes captured byte ranges through `scan_text`, while the existing `scan` / `Finding` interface remains intact. Extend key-block ranges, merge overlaps, and apply the pure `redact_text` function, preserving UTF-8 and CR/LF.
5. **bounded replacement**: return exit 0 with `hookSpecificOutput.updatedToolOutput`, or no stdout when clean. Limit the complete serialized response to 10 MiB.
6. **errors**: return `continue: false` and a fixed safe reason, plus a replacement hiding every supported text field when its structure is available and the fallback fits. Use fallible stdout/stderr writes; failed stdout delivery exits 1 with a safe stderr diagnostic if possible. A PostToolUse exit 2 cannot remove existing output.

For supported formats, installation/version requirements, and failure/telemetry limitations, see [Agent Hooks]({{ '/agent-hooks/#redact-mode-output-editor' | relative_url }}).

---

## Check-Codex Pipeline (Codex CLI Agent Hook)

Triggered by the Codex CLI at two points. On `PreToolUse`, before it runs a tool, `check-codex`
inspects what the agent is about to write, so a secret is caught before it reaches the working tree.
On `PostToolUse`, after a `Bash` command has finished, it scans the output Codex is about to hand the
model with the agent text surface (`scan_text`/`redact_text`, the `redact-claude` trust and cwd
rules), and on a finding exits 2 so Codex replaces the output with the reason, which carries the
redacted output or, above 64 KiB, masked findings only.

The hook is registered with matcher `^(apply_patch|Bash)$` under `PreToolUse` and `^Bash$` under
`PostToolUse`, and both run `sekretbarilo check-codex --stdin-json`. The command is internal: it only
reads a hook payload from stdin, and refuses to run without `--stdin-json`.

### Payload

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "apply_patch",
  "tool_input": {"command": "*** Begin Patch\n..."},
  "cwd": "/project/root"
}
```

a payload that does not match this schema is rejected with
`Codex hook payload schema mismatch: <detail>` and exit 2 — fail closed, same as `check-file`.

### Pipeline

1. **parse payload**: 10 MiB stdin limit
2. **extract scannable text**, by tool:
   - `apply_patch`: parses the patch envelope and takes only the added lines, keeping the target
     path so findings are attributed to the file the agent is creating or editing
   - `Bash`: scans the command string itself, attributed to the synthetic path `<bash-command>`
3. **load config** through the same trusted loader as `check-file` (see step 6 above)
4. **scan** through the shared scanner engine
5. **report findings** (to stderr):
   ```
   [AGENT] Codex apply_patch blocked: secret(s) detected
     file: src/creds.py
     line: 1
     rule: github-personal-access-token
     match: gh**************************************AB
   apply_patch action blocked to prevent secret exposure. total findings: 1.
   ```
6. **exit code**:
   - `0` = clean (codex runs the tool)
   - `2` = secrets found or error (codex blocks the tool call)

**Codex-specific caveat**: Codex silently skips hooks it has not been asked to trust. Installing the
hook is not enough — it must also be approved with `/hooks` in the Codex TUI, and `doctor` reports
the approval entry separately from the installation itself.

---

## Configuration System

### Hierarchical Discovery

searches for `.sekretbarilo.toml` in order (lowest → highest priority):

1. `/etc/sekretbarilo/sekretbarilo.toml` (system-wide)
2. `~/.config/sekretbarilo/sekretbarilo.toml` (user)
3. `.sekretbarilo.toml` in each directory from repo root → home

**merge strategy**:
- **scalars**: highest priority wins (e.g., `entropy_threshold`)
- **lists**: concatenated + deduplicated (e.g., `stopwords`, `paths`)
- **rules**: same `id` overrides, new `id` appends

**trust**: on the agent-hook paths (`check-file`, `check-codex`, `redact-claude`) an in-workspace config layer is
dropped unless it is git-tracked and clean against `HEAD` — an agent that writes its own
`.sekretbarilo.toml` cannot allowlist its way past the scanner. `scan` and `audit` are unaffected.
[Configuration]({{ '/configuration/' | relative_url }}) documents the exact conditions.

### TOML Format

```toml
[settings]
entropy_threshold = 3.5

[allowlist]
paths = ["test/.*", "vendor/.*"]
stopwords = ["my-project-safe-token"]

[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
paths = ["test/.*"]

# key patterns apply only to generic-high-entropy-value assignment matches
[[allowlist.rules]]
id = "generic-high-entropy-value"
keys = ["TMPDIR", "GHOSTTY_*"]

[audit]
include_ignored = true
exclude_patterns = ["^build/", "^dist/"]
include_patterns = ["\\.rs$"]

[[rules]]
id = "custom-token"
description = "Custom API token"
regex = "(CUSTOM_[A-Z]{10})"
secret_group = 1
keywords = ["custom_"]
entropy_threshold = 3.5
```

### Rule Compilation

1. **load default rules**: embedded `config/rules.toml` (112 rules)
2. **merge user rules**: overrides by `id`, appends new rules
3. **compile regexes**: `regex::bytes::RegexBuilder` with 1 MB size limit
4. **build aho-corasick automaton**: all keywords (case-insensitive, deduplicated)
5. **map keywords → rules**: `keyword_to_rules[pattern_idx] = [rule_idx, ...]`

**Result**: `CompiledScanner` struct with `automaton`, `keyword_to_rules`, `rules`

---

## Hook Installation

### Pre-Commit Hook

**local**: `.git/hooks/pre-commit`
```bash
sekretbarilo install pre-commit
```

**global**: `~/.config/git/hooks/pre-commit` + `git config --global core.hooksPath`
```bash
sekretbarilo install pre-commit --global
```

**generated script**:
```sh
#!/bin/sh

# sekretbarilo pre-commit hook
# resolve the sekretbarilo binary
SEKRETBARILO_BIN=""
if command -v sekretbarilo >/dev/null 2>&1; then
    SEKRETBARILO_BIN="sekretbarilo"
elif [ -x "$HOME/.cargo/bin/sekretbarilo" ]; then
    SEKRETBARILO_BIN="$HOME/.cargo/bin/sekretbarilo"
fi

if [ -n "$SEKRETBARILO_BIN" ]; then
    "$SEKRETBARILO_BIN" scan
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
        exit 1
    elif [ $exit_code -ne 0 ]; then
        echo "[ERROR] sekretbarilo exited with code $exit_code" >&2
        exit $exit_code
    fi
else
    echo "[WARN] sekretbarilo not found in PATH or ~/.cargo/bin/, skipping secret scan" >&2
    echo "[WARN] install with: cargo install sekretbarilo" >&2
fi
# end sekretbarilo
```

**features**:
- POSIX-compatible (no bashisms)
- idempotent: detects existing installation via marker comment
- appends to existing hooks (inserts before trailing `exit`)
- graceful degradation: warns if binary not found but doesn't fail
- sets executable permission (`chmod +x`)

### Agent Hook (Claude Code)

**local**: `.claude/settings.json`
```bash
sekretbarilo install agent-hook claude
```

**global**: `~/.claude/settings.json`
```bash
sekretbarilo install agent-hook claude --global
```

`--mode block|redact` selects the Claude mode. Omitting it preserves the selected file's installed mode, defaulting to `block` for a new installation. Redaction requires Claude Code >= 2.1.121 before any change to Claude settings; it installs synchronous `PostToolUse` / `^(Bash|Read|Grep)$` with a 10-second timeout.

The installer records the absolute path reported by the OS for the running executable and quotes shell-sensitive paths; it warns and uses the bare `sekretbarilo` name only when the path lookup fails or is not valid UTF-8. On macOS, an invocation through a symlink such as Homebrew's `/usr/local/bin/sekretbarilo` keeps that path. On Linux, `current_exe` reports the resolved target, so Homebrew-on-Linux records a Cellar path; when `brew upgrade` removes that target, the hook remains broken until installation is rerun from the new binary, and doctor reports the old path as missing. Doctor checks an absolute configured path's filesystem metadata, executable bit, and canonical identity relative to the running binary. It never executes a binary selected by Claude settings and does not report a version for it; a bare name receives a warning because Claude Code resolves it under its own `PATH`.

**settings.json structure (`block`)**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "<absolute-path-to-running-sekretbarilo> check-file --stdin-json",
            "statusMessage": "Scanning file for secrets...",
            "timeout": 10,
            "type": "command"
          }
        ],
        "matcher": "Read"
      }
    ]
  }
}
```

**features**:
- reads/creates `.claude/settings.json` or `~/.claude/settings.json`
- idempotent: detects entries across events, updates the selected or preserved mode, removes duplicate sekretbarilo handlers
- preserves existing settings and other hook matchers
- preserves other handler/group order; reports local/global blocking-Read conflicts with redaction
- atomic write: temp file + rename (prevents corruption)

### Agent Hook (Codex CLI)

**local**: `.codex/hooks.json`
```bash
sekretbarilo install agent-hook codex
```

**global**: `$CODEX_HOME/hooks.json`, defaulting to `~/.codex/hooks.json`
```bash
sekretbarilo install agent-hook codex --global
```

**hooks.json structure**:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "sekretbarilo check-codex --stdin-json",
            "statusMessage": "Scanning tool input for secrets...",
            "timeout": 10,
            "type": "command"
          }
        ],
        "matcher": "^(apply_patch|Bash)$"
      }
    ]
  }
}
```

**features**:
- shares its json reader/writer with the claude installer (`agent/hooks_json.rs`), so idempotency,
  preservation of unrelated entries and atomic writes behave identically
- reports the detected Codex version when `codex` is on `PATH`
- warns, on every install, that Codex ignores unapproved hooks until you run `/hooks` in its TUI

### Install All

```bash
sekretbarilo install all           # pre-commit + claude + codex, locally
sekretbarilo install all --global  # the same three, globally
```

runs the three installers in sequence and prints each one's result. accepts `--mode block|redact` for Claude with the same preservation/default/version policy as the standalone installer.

---

## Doctor

`sekretbarilo doctor` runs five groups of checks and prints each result with a status label:

| Group | Checks |
|-------|--------|
| `git pre-commit hook` | local and global hook present, carries the sekretbarilo marker |
| `claude code agent hook` | local and global `settings.json` entries, command metadata, and canonical identity relative to the running binary; the configured binary is never executed |
| `codex cli agent hook` | local and global `hooks.json` entries, the matching approval entry in Codex's `config.toml`, and whether `codex` is on `PATH` |
| `configuration` | which config files were discovered, whether an in-workspace layer is untrusted, rule count, rule compilation |
| `sekretbarilo binary` | binary reachable on `PATH` |

status labels are `[OK]`, `[WARN]`, `[ERROR]` and `[NOT INSTALLED]`. only `[WARN]` and `[ERROR]`
count as issues: doctor exits 1 if any check is an issue, 0 otherwise. a missing hook is
`[NOT INSTALLED]`, which is informational and does not by itself fail the command.

the codex approval check is deliberately weaker than the others. it looks for a positional entry
under `[hooks.state]` in Codex's `config.toml` and does not validate Codex's own trust hash, so an
`[OK]` there means "an approval entry exists", not "the hook will definitely run". it can never
produce a false `[OK]` for a *missing* approval, only an over-optimistic one for a stale hash.

---

## Output & Masking

### Masking Strategy

diagnostic secret values masked before display:

| Length | Display |
|--------|---------|
| 1-5 chars | `xxx` — one `x` per character, length preserved, value fully hidden |
| 6+ chars | `AB**********YZ` (first 2 + last 2) |

**rationale**: prevents accidental exposure in logs/screenshots while allowing identification

### Output Prefixes

- `[ERROR]`: scan command findings (blocks commit), and fatal errors on any command
- `[AUDIT]`: audit command findings and progress (informational)
- `[AGENT]`: check-file findings (blocks read) and check-codex findings (blocks the tool call or withholds Bash output)
- `[SEARCH]`: user-search pass results — **not** masked
- `[OK]` / `[WARN]` / `[NOT INSTALLED]` / `[INFO]`: install and doctor status lines

diagnostics go to stderr. `redact-claude` writes replacement/stop JSON to stdout, using full `[REDACTED]` values and preserving the response structure.

### Terminal Safety

history mode sanitizes all displayed fields:
- strips control characters (`\x00-\x1f`, `\x7f`)
- strips bidi overrides (`\u{202A}-\u{202E}`)
- prevents terminal injection via malicious git author/email/branch/file names

---

## Design Decisions

### Fail Closed
errors exit 2 (block) rather than 0 (allow):
- config parse errors → block
- file read errors → block
- rule compilation errors → block

**rationale**: better to over-block than expose secrets

### No Network
everything runs locally:
- no telemetry
- no remote rule updates
- no API calls

**rationale**: privacy, security, offline support

### POSIX Hooks
generated hooks use only POSIX shell features:
- `[ ]` not `[[ ]]`
- `command -v` not `which`
- `"$VAR"` quoting everywhere

**rationale**: works on all shells (sh, bash, zsh, dash)

### Graceful Degradation
hooks warn but don't fail if binary not found:
```
[WARN] sekretbarilo not found in PATH or ~/.cargo/bin/, skipping secret scan
```

**rationale**: doesn't break workflows if binary is temporarily missing

### Trusted Config on Agent Paths
`check-file`, `check-codex`, and `redact-claude` drop an in-workspace `.sekretbarilo.toml` unless git says it is
tracked and unmodified:
```
[WARN] ignoring untrusted in-workspace config: /project/root/.sekretbarilo.toml
```

**rationale**: the agent being scanned can write files in the workspace. if an untracked config
counted, an agent could allowlist itself past the hook it is supposed to be constrained by.
`scan` and `audit` are run by a human and keep the unconditional behaviour.

### Stdin Limit
`check-file` limits stdin to 1 MB:
```rust
std::io::stdin().take(1_048_576).read_to_string(&mut input)
```

`check-codex` and `redact-claude` cap input at 10 MiB. Redaction also caps its serialized hook response at 10 MiB.

**rationale**: prevents unbounded memory consumption from malicious payloads

### Regex Size Limit
all regexes compiled with 1 MB limit:
```rust
RegexBuilder::new(&pattern).size_limit(1 << 20).build()
```

**rationale**: prevents ReDoS (regular expression denial of service)

### Parallel Processing
uses rayon for parallel file/commit processing:
- threshold: 4+ files/commits
- automatic work-stealing
- respects available CPU cores

**rationale**: 10-100x speedup on large repos

### Binary-Safe Scanning
uses `regex::bytes` and `Vec<u8>` everywhere:
- handles non-UTF-8 files
- no allocation for UTF-8 conversion

**rationale**: supports all file encodings

---

## Performance Characteristics

### Scan Mode (Staged Changes)

per-invocation wall clock, measured on macOS 15.7 / Intel Core i9-9900K @ 3.60GHz, 50 invocations
of `sekretbarilo scan` against a one-file staged diff:

| Component | Cost |
|-----------|------|
| process spawn (`--version` as a floor) | ~13 ms |
| `git diff --cached` subprocess | ~10 ms |
| rule compilation (112 rules, delta vs `--no-defaults`) | ~11 ms |
| **whole `sekretbarilo scan` invocation** | **~53 ms** |

the in-process scan itself is microseconds ([Performance]({{ '/performance/' | relative_url }}));
essentially all of the wall clock is fixed startup cost, so it does not grow with commit size until
the diff is very large. these figures are hardware- and OS-dependent — treat them as a shape, not a
guarantee.

**bottleneck**: fixed startup, not scanning. regex evaluation is the scanning-side cost, mitigated
by the aho-corasick pre-filter.

### Audit and History Modes

no published figures. both are dominated by I/O and by `git` subprocesses rather than by the
scanner, so they track repository size, filesystem speed and core count more than anything
sekretbarilo controls. measure on your own repository:

```sh
time sekretbarilo audit
time sekretbarilo audit --history
```

**audit bottleneck**: file I/O, mitigated by parallel reads.
**history bottleneck**: `git diff-tree` execution, mitigated by parallel commit processing and by
resolving branches only for commits that produced findings.

### Optimization Techniques
1. **aho-corasick pre-filter**: most lines match no keyword at all and never reach a regex
2. **rayon parallelism**: audit and history work scales with available cores
3. **binary-safe bytes**: no UTF-8 conversion overhead
4. **reusable bitsets**: avoids per-line allocations
5. **early termination**: skips binary/vendor/lock files immediately

---

## Testing Strategy

### Unit Tests
- scanner engine: keyword matching, regex extraction, entropy calculation
- diff parser: edge cases (binary, renames, root commits, multiple hunks)
- config merging: scalar override, list concatenation, rule merging
- allowlist compilation: path patterns, stopwords, per-rule allowlists

### Integration Tests
one file per area under `tests/`:
- default rules: all 112 rules compile and detect known secrets
- false positives: a corpus that must stay clean
- hook installation: idempotency, appending, preservation of existing hooks
- claude agent hook: JSON parsing, path resolution, fast-path rejection
- codex agent hook: payload schema, `apply_patch` and `Bash` extraction, config trust
- doctor: each check group, and the exit code it produces
- audit, history and the user-search pass
- public key suppression, config merge precedence, CLI flag overrides
- hook panic safety: a panic must not turn into a silent allow

git-dependent tests build temp repos with `tempfile` and are serialized with `serial_test`, since
they mutate global git state.

---

## Security Considerations

### Threat Model
**in-scope**:
- accidental secret commits (developer error)
- copy-paste from documentation (example secrets)
- weak passwords in config files

- an AI agent writing a secret into the working tree, before the write lands (`check-codex`)
- an AI agent reading a file that already contains one (`check-file`)
- detected secrets in successful Claude Bash/Read/Grep text results (`redact-claude`)

**out-of-scope**:
- intentional malicious commits (insider threat)
- encrypted/obfuscated secrets
- secrets obfuscated or split so that no detector matches them; redaction handles matched multiline captures and PEM/PGP blocks

### Attack Surface
1. **malicious config files**: TOML parsing uses `serde_toml` (memory-safe)
2. **malicious git payloads**: binary-safe parsing, control char stripping
3. **ReDoS via user regexes**: 1 MB size limit enforced
4. **path traversal**: canonicalization + prefix check in check-file mode
5. **terminal injection**: sanitizes author/email/branch/file names before display
6. **agent-authored config**: an in-workspace config layer is ignored on the agent-hook paths
   unless git-tracked and clean
7. **hostile hook payloads**: bounded stdin and strict schemas; blocking hooks exit 2 on parse failure, while redaction returns stop JSON and a fully masked fallback when possible

### Sandboxing
agent hook mode:
- `check-file` reads only the target file (no directory traversal); `check-codex` reads no file at
  all, only the payload the agent is about to act on or the output Codex is about to show it
- no network access
- no temp file creation
- read-only access to config files

---

## Future Work

### Performance
- incremental scanning (cache results per file hash)
- rule priority ordering (check high-confidence rules first)
- streaming diff parsing (avoid buffering full diffs)

### Features
- custom entropy models per rule (hex-only, base64-only)
- machine learning-based false positive reduction
- integration with secret management systems (vault, 1password)

### Accuracy
- context-aware scanning (understand variable assignments)
- cross-file analysis (detect secrets split across imports)
- semantic analysis (distinguish API keys from UUIDs)
