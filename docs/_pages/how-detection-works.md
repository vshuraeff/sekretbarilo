---
title: How secret detection works
description: How rule classes select detection evidence, what entropy can and cannot decide, and where the design accepts noise or blindness on purpose.
section: explanation
---

## The problem with one rule

A secret has no intrinsic marker. `AKIA` followed by sixteen key characters is an AWS access key and almost nothing else, but a forty-character base64 string might be a session token, a build checksum, or a public key fingerprint, and no amount of pattern matching separates them with certainty. Detection is therefore not one question but two: recognising credentials whose shape is known, and guessing about values whose shape is not.

sekretbarilo separates these signals into three rule classes. Classes select
which detectors run; they do not replace each detector's existing filters.

## Three rule classes

**Signature rules match recognizable credential formats.** A provider-specific
prefix, suffix or structural marker supplies the evidence. Some of these rules
also require entropy checks. There are 75 definitions, including three public-key
rules that require the independent `detect_public_keys` opt-in.

**Contextual rules need credential context.** A key such as `password` or `api_key`,
an authentication header or a credential-bearing URL identifies what the value
means. The 37 contextual rules include `generic-api-key`,
`generic-secret-assignment` and `generic-token-assignment`; all three remain
enabled by default. Besides a quoted value, they read an unquoted value under a
name that is or ends in a credential key such as `API_KEY`, `SECRET` or `TOKEN`,
wherever an assignment can start on a line: `HF_TOKEN=value`,
`export DJANGO_SECRET_KEY=value`, `docker run -e STRIPE_API_KEY=value img`,
`cmd; API_KEY=value`, a Compose item `- API_KEY=value`, or YAML `token: value` at
the start of a line. An `env` dump or a shell command carrying a credential-named
variable is therefore still masked without the heuristic rule, while a value that
reads as code or words (`settings.SECRET_KEY`, `SecretStr`) is not reported. A
name after `.` or `-`, a dotted property name and a quoted assignment
(`-e "API_KEY=value"`) are not read this way, and a JSON pair
(`"api_key": "value"`) is read by neither form; the
[Rules Reference]({{ '/rules-reference/#generic-credential-assignments' | relative_url }})
lists the exact forms. Password rules use strength checks, and other rules may use
entropy thresholds.

**The heuristic rule is an opt-in fallback.** `generic-high-entropy-value` judges
value shape and entropy without a credential-specific signature or key. In 0.9.0
it is disabled by default because that broad coverage also reports harmless
checksums, base64 blobs and identifiers. Prefix-less random tokens are therefore
not covered by default unless another enabled rule matches their context, such as
one of the credential keys above; a bare value, or one under an unrelated name,
is not.

Enable it with `[settings.rules]` and `"generic-high-entropy-value" = true`, or
enable its class with `[settings.rule_classes]` and `heuristic = true`. This also
controls `redact-claude`: a bare random value in `printenv` output is no longer
masked by the fallback without opt-in. Rule-id switches override class switches;
each table merges by key across configuration layers.

The remaining discussion of keywordless entropy and structural exemptions
describes this rule when enabled. Neither `exemption_layer` nor `source_posture`
turns a disabled rule back on.

## Why the pre-filter comes first

Evaluating every enabled regex against every line of every file would be slow enough to change how people use the tool, and a pre-commit hook that people disable protects nothing.

So the keywords of every rule are compiled into a single Aho-Corasick automaton, case-insensitive, and each line is passed through it once. That pass reports which keywords occur, and only the rules owning those keywords have their regex evaluated. A line with no keyword at all costs one automaton pass and nothing more, which is the common case in source code. The work is proportional to the interesting lines rather than to the file.

Enabled rules with no keywords, including the heuristic rule, sit outside that shortcut by construction: there is nothing to pre-filter on, so their cost is paid on every candidate value.

## What entropy decides, and what it cannot

Candidate values are scored with Shannon entropy over byte frequencies, in bits per byte, with no normalisation for length or alphabet. `generic-high-entropy-value` requires at least twenty bytes and at least 4.0 bits per byte.

Entropy in bits per byte is bounded by the logarithm of the value's length, so short values are penalised by arithmetic rather than by policy: an eight-character value cannot score above 3.0 however random it is, because it has at most eight distinct bytes to distribute. Nothing under sixteen bytes can reach 4.0 at all. The gate sits at twenty rather than sixteen by judgement, and it short-circuits before entropy is computed, so a shorter value is never scored.

[ADR 0001](https://github.com/vshuraeff/sekretbarilo/blob/master/docs/adr/0001-entropy-baseline-8-char-password.md) measured what that costs. Across ten thousand generated passwords per length, a genuinely random twenty-character password scores below 4.0 about a third of the time and is therefore missed, while at thirty-two characters the miss rate is one in ten thousand. Detection of short credentials is not merely imperfect; it is structurally out of reach for this metric.

Lowering the gate would not fix it. At eight characters entropy cannot distinguish a random password from an ordinary English word: `document` and `security` are eight distinct letters each and score exactly 3.0, the same as a random password at its ceiling. A lower gate would need a second signal — a dictionary, or keyword context — before it could be proposed. The threshold is where it is because the alternative is worse, not because it is good.

## Suppression, and who is exempt from it

Several filters exist to keep the false-positive rate tolerable: the built-in stopword list, hash and checksum recognition for SHA-1, SHA-256, MD5 and Git object ids, variable-reference detection for the shapes that mean "this is not the value, it is a lookup", template-expression handling for the templating languages, an entropy bonus for documentation files, and path allowlists for binaries, lock files and vendor directories.

`generic-high-entropy-value` bypasses most of them: the default stopwords, the hash suppression, the template handling and the documentation bonus all step aside for it. Of the filters above, only explicitly configured stopwords and per-rule value exceptions apply, together with the `keys` allowlist that is unique to this rule. This follows from what the rule is for — a suppression heuristic that a caller can trip by naming a variable well is not a safety property — and it is why that rule, more than any other, is the one people end up allowlisting.

What does apply to it, and to no other rule, is a layer of structural exemptions that reads the value rather than its name.

The redaction hook narrows the set further. It applies the detection rules and value exceptions but no path exclusion at all, because what it inspects is a tool result rather than a file, and a path is not a property the returned text carries.

## The exemption layer

The keywordless rule runs a sequence of predicates over the bytes of the candidate value, switched by `[settings] exemption_layer` and on by default. Fourteen steps, evaluated in order, and the first that matches suppresses the finding: **file** (an ignore file or `CODEOWNERS` disables this rule alone there), **import**, **markdown** (a wrapper — a link, an autolink, a one-item quoted list of a URL, or a markup element on one line such as `<string>...</string>` — is retargeted to the value it holds and evaluation continues on that; a markup element is read through only when it is anchored at both ends by well-formed, nested lowercase tags and any other text beside the value is shorter than 20 bytes and inside an element of its own), **path** (in practice rarely the step that fires: an earlier, unconditional path-shape check outside this layer already exempts most path-shaped values before the trace even starts; it is the step that claims a path rooted at or carrying a variable reference, `$HOME/…`, `${WORKSPACE}/…`, `$(NAME)/…`, keyed or not, along with the shell's parameter expansions — `${NAME/#\~/$HOME}`, `${list[@]}`, `${NAME:?message}`, `$((…))` — globs and `|` or `:` lists of such paths, as long as every literal piece and every reference name, default, pattern and replacement reads as a word or a short number and no run long enough to be a credential fails to read as a file name or an identifier on its own; the rooted-path check before the layer holds a module path rooted at a host, such as `github.com/owner/repo`, and a scheme-less `//host/…` URL to every part after the host reading as a word, a number or a short abbreviation), **relpath** (a bare capture standing alone on its line that reads as a relative path — at least two slashes, a wordy leaf and exactly one short identifier segment among otherwise word-structured ones, the shape of a printed branch name — or a bare dated file name such as `2026-09-10-release-notes.md`, or a keyed value that is a relative path of words carrying at most one letter-and-digit part of up to eight bytes, usage placeholders such as `<Class>` read as the words they hold), **mktemp** (the same bare keyless capture, a `./`-prefixed leaf of dash-joined lowercase words and a six-character suffix, the shape `mktemp` prints), **pin** (a commit digest or a version tag such as `v4` or `release/v1` pinned behind a reference, a tag only when every segment of that reference is a name of words and short numbers), **url** (no credential in any component; a path segment or fragment that is a slug of words and short numbers carries none, a badge chain the value grammar split needs an absolute URL among its targets and every target to pass, and a value with no scheme passes only as an email address or `user@host` of words), **regex** (a quoted, bracketed or call-literal value, a `/body/flags` literal or the pattern handed to `grep -E` and its kin, carrying two distinct regular-expression constructs, one of them a counted bracket class, on every surface), **syntax** (a complete source expression covering the flagged range — a call, index, macro or attribute group, a member chain whose segments read as words, a type name marked `?` or `!`, the enclosing group a capture closes, or a call left open at the line end — with no opaque token anywhere inside it), **wordshape** (words, camel case or snake case rather than an opaque run, a platform symbol such as `NSCameraUsageDescription`, a search pattern whose alternatives are words, an environment entry such as `GOFLAGS=-mod=readonly` or a key chord such as `super+shift+t=toggle_quick_terminal`), **symbols** (a lookup table of punctuation, such as a set of delimiters), **template** (a format string or an interpolated string whose placeholders and holes stand between words, or a string body whose escapes are its only structure), **digest** (an exact-length hex digest under a `digest`, `checksum` or `x-checksum-<algorithm>` key, a go.sum `h1:` hash of exactly 44 base64 bytes, or a subresource-integrity `sha256-`, `sha384-` or `sha512-` value of exact encoded length under an `integrity`, `hash`, `digest` or `checksum` key). Only the pin and digest steps consult the assignment key, pin to gate itself to the exact key `uses` and digest to those checksum and integrity labels — the other twelve look at the value alone. So the argument of the previous section mostly still holds: naming a variable well does not silence any step except those two narrow, key-specific cases.

The layer changes which values are considered, never the gates they are measured against. Twenty bytes and 4.0 bits per byte are the same in both modes, and signature and contextual rules never enter it.

Two parts of it move in the other direction. Quoted call-argument bodies are collected as candidates as well, so a token handed to a function is examined at all; and an exact-length hex value of 32, 40 or 64 digits, assigned under a key that is not id-, hash- or address-shaped, skips the entropy gate — the one place the layer makes the rule stricter rather than quieter, and it still defers to a hash context word in its own assignment, so a digest assigned earlier on the same line does not turn the next value into a hash.

The rule's grammar reads a few forms as source code reads them rather than as bytes. A string prefix (`r"…"`, `b'…'`, `f"…"`, `u8"…"`, `L"…"`) or a Swift raw string (`#"…"#`) leaves the value as the body alone in a source file, while an environment-style line keeps the whole word a shell would read (`VALUE=b"x"rest`); on a Python file a Python f-string or t-string is literal text around `{…}` holes, each piece judged on its own and the reading traced as `exempt:hole`, but only when every hole is an expression of names, and on every other surface the braces are data; a shell `&&` ends the value before it; and a name the grammar would otherwise read as a key — the scope before `::`, a POSIX class such as `[:space:]`, the letter of an escape such as `\n:` — is not one, while the text after it is still read. Every one of these readings keeps the whole value when the text it would call code reads as a token cut into short groups. A URL whose scheme was taken for a key is judged whole, from the scheme.

A credential a program carries is normally assigned as a string literal, while an opaque run of bytes outside every literal is usually an identifier, a constant expression or comment text. That difference in position is one the rule can read, and it is the one the exemption layer could not. So a file whose extension names a supported language is scanned in a posture of its own: a candidate counts only when it sits inside a string-literal body. In Rust and Go every literal body on the line is also a candidate in its own right, judged like a call argument with no assignment key behind it. From 0.9.0 C and C++, Python, the JavaScript and TypeScript family and Swift are covered too, through a parse of the complete file that adds no candidate: it removes a finding lying outside every literal body, and cuts a finding that runs from a body into an interpolation hole, a string prefix or a delimiter down to the literal text it covers, each piece judged again on its own. Bare code and comments yield nothing from this rule, which is where the dotted call openers, the split expressions and the constant tables that survived the exemption layer were coming from. Shell, configuration and data formats, markdown and anything without a recognised extension are unchanged.

For Rust and Go the recogniser is a table of each language's literal delimiters and escape rules, not a parser; the other languages use pinned Tree-sitter grammars. Neither narrows a scan on a guess: where the lexical state is unknown — after a gap in a diff whose file could not be read, in a history audit, in a file that does not parse cleanly or uses a literal form the adapter does not map — the lines are scanned in full. Further labels appear in the trace for this: `exempt:code`, a candidate outside every literal body in a source file, `exempt:clip`, a finding cut down to the literal text it covers, and `exempt:testpath`, the rule standing down on a test path — under `test`, `tests`, `__tests__`, `testdata`, `fixtures`, `benches`, an XCTest target such as `FooTests` or a dotted .NET test project such as `Foo.Tests` (`spec`/`specs` are deliberately not directory segments, since they also name production specification packages), or in a file such as `*_test.*`, `test_*.py`, `*_spec.rb` or a JS/TS `*.test.js`/`*.spec.ts`-style name (the full list is in [Configuration]({{ '/configuration/' | relative_url }})) — where signature and contextual rules still run. Each has a setting of its own — `source_posture` and `heuristic_skip_test_paths` — and the reasoning, what it forfeits and what it recovers, is in [ADR 0003](https://github.com/{{ site.repository }}/blob/master/docs/adr/0003-tier3-source-posture.md).

`--trace-exemptions`, accepted on `scan` and `audit` and on no hook surface, reports each decision as a pseudo-finding named `exempt:` plus the step that made it:

```
  file: Cargo.toml
  line: 37
  rule: exempt:syntax
  match: [p******************b]
```

A trace line marks a successful suppression only: it is emitted when a step's predicate matches and the value is dropped right there. Its absence proves nothing about whether a step was reached — it only means no step suppressed the value, and that includes a value dropped before the traced layer runs at all, such as by the unconditional path-shape check the **path** step's own note above describes. While the flag is on, those pseudo-findings count towards the exit code, so a before-and-after comparison is measured without it.

Turning the layer off affects only the enabled heuristic rule; it does not enable that rule or revert later independent detection changes. The reasoning, the measured effect and the shapes it still misses are in [ADR 0002](https://github.com/{{ site.repository }}/blob/master/docs/adr/0002-tier3-exemption-layer.md).

## Two decisions that look arbitrary

**Findings show two characters at each end.** Enough to recognise which value was found, in a file with several, and to match it against the credential you are looking at. Not enough to reconstruct it from a log or a screen recording. Values shorter than six characters are replaced entirely, since two-plus-two of a five-character string is most of it. Redaction for an agent takes the opposite decision and keeps nothing, because its reader is a model that does not need to recognise anything.

**`.env` files are blocked without being read.** The check runs on the filename, before any configuration is loaded, and nothing in an allowlist can override it. That is unusual for a rule-based scanner, and it is on purpose: a file whose entire reason for existing is to hold credentials does not need its contents inspected, and the check must not depend on configuration an agent could have written. Templates named `.env.example`, `.env.sample` and `.env.template` are the exception, since their purpose is to be committed.

## What this design does not do

It does not find secrets it has no rule for, and no scanner does. It does not distinguish a live credential from a revoked one. It does not reach short credentials, for the reasons above. It reports checksums as findings from time to time and expects you to allowlist them.

What it does offer is a predictable failure direction: when the scanner is unsure, it reports. Every stage of it — the fail-closed exit codes of the agent hooks, the whole-layer rejection of untrusted configuration, the unconditional `.env` block — resolves ambiguity towards the noisy answer rather than the quiet one, on the grounds that a false positive costs a minute and a missed credential costs a rotation.

## Further reading

- [Rules reference]({{ '/rules-reference/' | relative_url }}) for every rule, its class and its threshold.
- [Architecture]({{ '/architecture/' | relative_url }}) for the scan pipeline stage by stage.
- [Performance]({{ '/performance/' | relative_url }}) for what the pre-filter buys in measured terms.
- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) for acting on the noise this design accepts.
- [Testing False Positives]({{ '/testing-false-positives/' | relative_url }}) for the fixture corpus that holds the exemption layer to its measured behaviour.
