# ADR 0002: an exemption layer for the tier-3 entropy rule

## 0.9.0 rule-class amendment

`generic-high-entropy-value` now belongs to the `heuristic` rule class, disabled
by default. The rule behavior and historical measurements below assume it is
enabled. Opt in with `[settings.rules]` and `"generic-high-entropy-value" = true`
or `[settings.rule_classes]` and `heuristic = true`. The signature and contextual
classes remain enabled; `generic-api-key` and `generic-token-assignment` are
contextual, despite their historical tier-3 grouping.

`heuristic_skip_test_paths` is the current name of `tier3_skip_test_paths`; the
old spelling is a deprecated input alias, and using both in one file is an error.
It, `exemption_layer`, and `source_posture` still affect only the enabled
`generic-high-entropy-value` rule. They do not turn it on. Earlier “tier” wording,
test names, source identifiers and links below are retained as historical evidence;
they do not define the current class switches. ADR filenames remain stable.


- status: accepted
- date: 2026-09-10
- scope: the exemption layer and its `[settings] exemption_layer` switch are scoped to rule
  `generic-high-entropy-value` only. `generic-password-assignment` gains a named `password_key`
  capture group in this release, used only to exempt the shell variables `PWD` and `OLDPWD`; it
  narrows that rule and is unrelated to the layer. `password-in-url` is widened independently of
  the layer in this same release (backlog 9zToqTHzJ5QKE8Xl, authorised by the user's G0 decisions
  of 2026-09-10) and is not governed by the switch: see "the switch and the trace flag" below.

## context

`generic-high-entropy-value` is the keywordless catch-all of tier 3. It fires on any whitespace-free
ASCII run of at least `MIN_ENTROPY_LENGTH` bytes whose Shannon entropy reaches 4.0, wherever that
run appears: an assignment value, a bare quoted line, a bracketed value. It carries no keyword
pre-filter, so every line of every scanned file reaches its regex.

The corpus study behind 0.7.0 audited 16 local repositories with the 0.6.3 binary. It produced
52,537 findings and not one of them was a confirmed secret. 99.58% came from this single rule. The
findings were not random: they fell into a small number of recognisable shapes, each of which is a
structural property of the value rather than a property of its name. Source expressions
(`CompiledAllowlist::from_config(&config, &rules).unwrap()`), dotted identifiers, CSS selectors,
paths and globs, URLs without a credential, markdown links, import lines, pinned action references,
recorded checksums and generated constant tables account for effectively all of them.

Those shapes are long and byte-diverse, so entropy alone cannot separate them from a credential. A
scanner whose catch-all rule is wrong 52,537 times in a row is switched off, which loses tier 1 and
tier 2 with it. The question was how to suppress the shapes without lowering recall on real opaque
tokens.

## decision

An exemption layer runs inside the candidate evaluation of `src/scanner/engine.rs`, scoped by rule
id to `generic-high-entropy-value` and switchable by `[settings] exemption_layer` (default true).
The layer is a sequence of structural predicates over the captured value; the first one that matches
suppresses the finding. Each predicate is a pure function of bytes, except the `pin` and `digest`
steps, which are gated on the assignment key of the capture.

The steps run in this order, all of them inside the `exemption_layer` guard:

1. **file** - `generic_rule_skip` in `src/config/allowlist.rs`. Ignore files
   (`.gitignore`, `.dockerignore`, `.npmignore`, `.prettierignore`, `.eslintignore`,
   `.gitattributes`, `.helmignore`) and `CODEOWNERS` disable this rule alone; every other rule still
   runs on them.
2. **import** - `is_import_line` over the surrounding line. Skipped for call-literal candidates.
3. **markdown** - `unwrap_markdown_target` in `src/scanner/urlshape.rs`. This step retargets rather
   than exempts: the range is narrowed to the link target and evaluation continues on the inner
   value, and only a target shorter than `MIN_ENTROPY_LENGTH` ends here. It applies to call
   literals as well (amendment 2026-09-26).
4. **path** - `entropy::is_path_shaped` over the possibly retargeted value, or
   `entropy::is_reference_rooted`: a path rooted at, or carrying, a variable reference (`$NAME`,
   `${NAME}`, `${NAME:-default}` and the other default and pattern operators, `$(NAME)`, `{name}`,
   `%NAME%`), for every capture kind. Every literal piece between `/ \ . - _`, every piece of a
   reference name and every piece of a default or pattern must read as a word or a number of at
   most four digits (`wordshape::wordlike_piece`, admitting one vowel-less four-letter word such as
   `html` per value); together their words must outweigh the short pieces: at least two words of
   four or more letters, and no fewer of them than short words outside the short-word vocabulary
   plus runs of digits after the first (`PieceWords::outweigh_short_pieces`). A reference whose
   name carries no short word outside the vocabulary (`HOME`, `STATE_DIR`, `run_id`) counts as one
   long word in place of its pieces. No segment may be cut into short groups (`wordshape::is_chunked`:
   four or more letter words of at most five letters in a row, carrying 14 letters or more, with
   the reference syntax ending a run), and the leaf must be wordy. A JSON pointer that carries a
   schema keyword (`#/$defs/name`) passes the same balance and chunk checks, and its `$` opens a
   segment of one word.
5. **relpath** - for bare captures standing alone on their line only. A value is exempt when it is
   a relative path: not rooted, no `://`, bytes limited to ASCII alphanumerics and `/`, `.`, `-`,
   `_`, at least two `/`, no empty segment, a wordy leaf, exactly one non-leaf identifier segment
   (alphanumeric, carrying a digit or mixed case, shorter than 20 bytes) and the remaining segments,
   rejoined with `/`, word-structured by the same check the `wordshape` step uses. The shape
   it covers is a printed branch name such as `task/<16-character id>/integrator/lead`, which carries no `./`
   prefix and so reaches the layer where a prefixed relative path does not. It runs on every
   surface, the pathless text surface of the redact hook included. A keyed unquoted, double- or
   single-quoted capture takes `entropy::is_keyed_relative_path` instead: not rooted, a `/` and no
   empty segment, every part between `/ . - _ + :` a word piece, a number of at most eight digits,
   or the one letter-and-digit part of at most eight bytes the value may carry (one run of digits,
   each run of letters lowercase, capitalized or all capitals), at least two words of four or more
   letters and no fewer of them than words of one to three letters, at most one vowel-less
   four-letter word, no segment cut into short groups (`wordshape::is_chunked`), and a wordy leaf
   read before any `:` suffix.
6. **mktemp** - `entropy::is_mktemp_path`, under the same gating as relpath: a bare capture standing
   alone on its line, with no assignment key. A value is exempt when it is a `./`-prefixed single
   leaf whose stem is dash-joined lowercase words of three to nineteen bytes each and whose suffix
   is exactly six alphanumerics, the shape `mktemp` prints, with stem and suffix together shorter
   than `MIN_ENTROPY_LENGTH` so that the separators cannot hide an eligible opaque payload.
7. **shell-path** - retired 2026-09-26: the path step's reference predicate claims every value it
   exempted, and the numbering of the steps after it is kept so the amendments below still read.
8. **pin** - `is_pinned_action_ref`: a digest pinned behind a reference, as a workflow `uses:` line
   writes it. Gated on the exact assignment key `uses`.
9. **url** - `is_credential_free_url`: a URL none of whose components carries a credential. A
   URL-shaped value can leave the layer through this predicate and through no other: the regex,
   syntax and wordshape steps below are skipped when `is_url_shaped` holds.
10. **regex** - for the whole value of a quoted, bracketed or call-literal capture, and for an
   unquoted or bare capture that is delimited as a regex literal (`/body/flags`, where the body
   alone is read) or is the pattern argument of a regex-taking command or option (the word before
   its key is `grep`, `egrep`, `rg`, `sed` or `awk`, `--regexp`, `--extended-regexp` or
   `--perl-regexp`, or a short-option cluster carrying `E` or `P`), on every surface, the pathless
   text surface of the redact hook included (amendment 2026-09-26). A value is exempt when it carries two
   distinct construct kinds from a closed list - a bracket class holding a range, an escape, a POSIX
   class name or a leading `^`; a quantifier standing directly after a class, a group or an escape;
   a backslash escape from a fixed set; a group opener - and a counted bracket class is among them,
   so a quantifier alone never satisfies the minimum although it counts as one of the two kinds.
   Any contiguous run of 20 bytes or more of `[A-Za-z0-9_-]` outside those constructs disqualifies
   the value and keeps it a candidate.
11. **syntax** - `expression_span` in `src/scanner/syntax.rs`, for unquoted and bare captures only. A
   complete source expression that covers the flagged range is exempt. The recognizer refuses to
   cover a credential: an inner token of at least 20 bytes vetoes the span when its Shannon entropy
   reaches 4.0 or its length is exactly 32, 40 or 64 hex digits.
12. **wordshape** - `is_word_structured` in `src/scanner/wordshape.rs`: values whose structure is
   words, camel case or snake case rather than an opaque run. The predicate is bounded against
   chunked secrets: a word of four bytes or more counts as word-like only when it carries a vowel
   (`y` included) and no run of more than four consonants, at least three quarters of those long
   words must be word-like, and when their lengths are near-uniform (a spread of at most one byte)
   a single failing word is enough to refuse the exemption. It also recognizes the widened camel
   forms, search patterns, environment entries and key chords of the 2026-09-26 value-shape
   amendment. Two literal-shape steps follow it and share its number, so that the amendments
   below still read, both skipped when `is_url_shaped` holds:
   - **symbols** - `is_symbol_table` in `src/scanner/litshape.rs`: a lookup table of punctuation in
     which no element repeats, no two unescaped letters or digits are adjacent and at most one
     element in eight is one.
   - **template** - `is_format_template` in `src/scanner/litshape.rs`: a format template with at
     least one placeholder (brace fields, printf conversions, `${name}` substitutions and
     interpolation holes) whose literal segments carry no opaque payload, or a string body whose
     escapes are its only structure; the literal text holds no run of short groups.
13. **digest** - `is_digest_record` in `src/scanner/hash_detect.rs`, the last step before the hex
   bypass. Gated on an assignment key separated from its value by a `:` (for a quoted value, a `:`
   or `=` before the opening quote, amendment 2026-09-26), and on that key being `digest`,
   `checksum` or `x-checksum-<algorithm>`. The value is exempt when it is an exact-length
   hex digest, 32, 40 or 64 digits, optionally carrying its own `md5`, `sha1`, `sha-1`, `sha256` or
   `sha-256` prefix before a `:` or `=`, whose length agrees with the algorithm named on either side.

Two properties bound the layer:

- `MIN_ENTROPY_LENGTH` stays 20 bytes and `entropy_threshold` stays 4.0 for this rule. The layer
  changes which values are considered, never the gate they are measured against, so the baseline of
  ADR 0001 continues to hold.
- The layer is keyed on the rule id, so a prefixed key on an exempted line is still a finding from
  any other rule. `generic-password-assignment` is unaffected by the layer, except for the
  `PWD`/`OLDPWD` key exemption noted in the scope line above. `password-in-url` is widened
  independently of the layer, in this same release: see "the switch and the trace flag" below.

### the hex bypass

The layer makes the rule stricter in exactly one place. An exact-length hex value (32, 40 or 64
digits, optionally `0x`-prefixed) assigned under a key that is not `*_id`, `*_hash` or
`address`-shaped is a hex policy candidate (`is_hex_policy_candidate` in
`src/scanner/hash_detect.rs`). Such a value skips the Shannon gate at the end of the pipeline and is
emitted if it clears everything else. This recovers real hex credentials that fall below 4.0 bits
per byte purely because their alphabet has 16 symbols.

The bypass applies to double-quoted, single-quoted, bracketed and unquoted captures, and to neither
bare lines nor call literals, both of which have no key. It carries two guards:

- the 0.6.x hash-context exemption keeps precedence: a hex value whose assignment carries a hash
  context word is a hash, not a secret. Since the amendment of 2026-09-26 the word is looked for in
  the stretch of the line that assignment owns rather than in the whole line;
- a floor of 2.0 bits of hex-symbol entropy over the 16-symbol alphabet excludes repeated-pattern
  and low-diversity values. 3.0 was rejected: of 1e6 uniformly random 32-hex values, 112 fall below
  3.0 and none below 2.0, while the calibration minima observed at 32, 40 and 64 digits are 2.80,
  3.00 and 3.31.

A bypass value skips the Shannon gate and nothing else. The user entropy-key allowlist, the per-rule
allowlist, variable-reference detection and the user stopwords all still apply to it.

### recall additions

Three changes widen detection rather than narrowing it:

- `0x`-prefixed 32- and 40-digit hex values became hex policy candidates.
- Opaque string literals passed as call arguments became tier-3 candidates. A bounded lexical pass
  (`src/scanner/calllit.rs`) collects quoted argument bodies once per logical line, independently of
  the regex capture cursor, and feeds their exact ranges to the same evaluator. These candidates
  skip the import and syntax steps, get no key allowance and no hex bypass, and keep the path, pin,
  url, regex and wordshape steps at their documented cost.
- `.terraform.lock.hcl` joined the generated-file list, which skips the file for every rule.

### the switch and the trace flag

`[settings] exemption_layer = false` restores the 0.6.x behaviour of this rule: every step
above, the call-literal collector and the hex bypass are all disabled together. Two things are not
part of the switch and stay on either way: the unconditional path-shape check that precedes the
layer, and the user entropy-key allowlist, which is applied after it.

Disabling `exemption_layer` does not revert independent rule changes in 0.7.0; `password-in-url`
continues to report non-placeholder literal URL passwords regardless of strength. Restoring the
complete 0.6.3 detector behaviour requires the 0.6.3 release, not this switch.

`--trace-exemptions` reports each decision as a pseudo-finding named `exempt:<step>` over the range
the step suppressed. It is a CLI flag only, so hook surfaces never see those pseudo-findings, and
they count as findings for the `scan` and `audit` exit codes while it is on.

## alternatives considered

- **name-based exemptions: trust a value because its key looks safe.** Rejected. A key is written by
  the same person who wrote the value, so it is evidence about intent and not about content, and a
  credential under a benign key would be silently exempt everywhere. The user allowlist already
  offers key patterns for the cases where a project wants to make that trade deliberately, and it is
  the project's decision rather than a default. Every predicate in the layer is therefore a function
  of the value bytes alone.
- **raise `entropy_threshold` above 4.0.** Rejected. The shapes the corpus produced are not
  low-entropy: dotted identifiers and source expressions score well above 4.0 because they are byte
  diverse. A threshold high enough to silence them silences real tokens first, and ADR 0001 already
  measured that any single threshold is implicitly length-dependent.
- **a regex alternative to the call-literal collector.** Rejected. The rule's regex advances a
  single capture cursor along the line, so an argument body reached by that cursor is consumed
  together with the assignment context around it and a second body on the same line is skipped
  entirely. Independent per-line collection is what gives call arguments exact, order-preserving
  ranges; a regex cannot produce them without a second pass, which is what the collector is.
- **the callee name as evidence that a literal is a pattern.** Rejected for the regex step. The
  true-positive corpus requires `re.compile("<opaque>")` to fire, so trusting the callee would
  exempt an opaque token because of the function it is passed to, which is evidence about intent
  rather than about content.
- **scope the regex step to call literals only.** Rejected. Under the ownership rule of ADR 0003 a
  quoted assignment is owned by its regex candidate, so a pattern written as an assignment would
  never reach a body evaluation and would stay a finding.
- **treat `|` alternation as evidence.** Rejected. A list of alternatives is a word list, which is
  what the `wordshape` step exists to judge; accepting it here would exempt any `|`-joined run of
  opaque chunks. It remains the known gap recorded in the residuals below.
- **suppress the rule in whole file classes.** Rejected as too coarse. The layer's file step is
  deliberately limited to ignore files and `CODEOWNERS`, where an opaque run is a pattern rather
  than a value.

## consequences

The corpus measurement after the layer shows roughly 70 percent of the tier-3 findings suppressed
with no real secret lost among them. The tier-3 rule remains the noisiest rule in the set; it is now
noisy in a bounded number of shapes, each of which has a fixture.

The `password-in-url` widening is measured separately, on the same corpus: 3 findings under 0.6.3
become 18 under 0.7.0. Weak literal credentials in URLs (documentation, compose files, fixtures) now
produce findings and may block a commit or be redacted; the remedy is a narrow explicit allowlist
entry for a verified example, never a global exception.

Accepted residuals, each of them measured rather than assumed:

- **multiline call fragments.** The collector keeps no state across lines, so an argument whose
  literal is split over two lines is not collected.
- **hex bodies in call arguments.** A call body has no key, so the hex bypass cannot apply. A 40-hex
  body below 4.0 bits is not reported.
- **Python raw and byte string prefixes, and Go backtick literals.** Out of scope for the collector;
  their bodies are not collected.
- **word alternations in regex bodies.** The regex step reads constructs, not alternation, so a
  pattern whose only structure is `|`-separated words carries none of the evidence it asks for and
  remains a finding. Four of the thirteen regex bodies measured in this repository are of that
  shape; a word list is a `wordshape` matter and is left to that step.
- **base64-standard and printable tokens inside URLs and expressions.** The url and syntax steps can
  cover a token embedded in a URL or an expression. This cost is accepted and report-only: the
  fixtures record it, no gate was changed for it.
- **crypto test vectors.** The hex bypass stays on over them; the resulting noise is handled by
  repository allowlists rather than by weakening the bypass.
- **the `hook_payload` fuzz target** is deferred, because the hook parsers read from stdin and the
  target would have to reimplement that boundary rather than exercise it.

ADR 0003 resolves the multiline call fragments and the Go backtick and Python-prefixed string
residuals above for source files, by reading their bodies with a per-language literal tracker.

The `check-codex` relative-path allowlist defect found during this round is fixed in this release.

## amendments

- 2026-09-19: the **relpath** step joined the layer at position 5, between path and mktemp, with the
  conditions recorded in the step list above. Its accepted cost is one opaque segment shorter than
  20 bytes inside an otherwise wordy keyless relative path, which is no longer reported - the same
  recall a `./` prefix already gave up. A bare file name, a path with two identifier segments and a
  value carrying an assignment key are deliberately outside it.
- 2026-09-19: the **mktemp** and **shell-path** steps joined the layer at positions 6 and 7, between
  relpath and pin, and the **digest** step at position 13, after wordshape and before the hex
  bypass, each with the conditions recorded in the step list above. Their accepted cost is that a
  keyless `mktemp`-shaped leaf, a keyless `$<NAME>_DIR/<wordy path>` value and an exact-length hex
  digest under a `digest`, `checksum` or `x-checksum-<algorithm>` key are no longer reported by
  tier 3.
- 2026-09-20: the **regex** step joined the layer at position 10, between url and syntax, with the
  evidence rule and the opaque-run disqualifier recorded in the step list above. The measurement
  behind it: thirteen regex-body locations remained in this repository after ADR 0003, of which the
  step closes nine, the other four being the word alternations listed under the residuals. The
  counted class is required because a quantifier alone was too weak: with a quantifier allowed to
  satisfy the minimum, 0.37 percent of random 40-byte printable-ASCII values were exempt, and
  requiring a class brought that to 0.055 percent, with zero exemptions across base62, base64 and
  hex values of 20 to 64 bytes. The cost is measured in the Monte-Carlo grid: the step misses 3 of
  2000 samples on each of two quoted 64-byte printable-ASCII families and none on any
  opaque-alphabet family, and the test allows at most 0.5 percent per printable cell and zero on
  every other family. Its accepted cost is that a secret shaped like a regular expression is not
  reported by tier 3; tier 1 and tier 2 are untouched by it, as by every other step.
- 2026-09-19: the **wordshape** step was bounded against chunked secrets, as its entry above now
  records. A value whose long words are near-uniform in length no longer buys the exemption with a
  minority of unpronounceable chunks.
- 2026-09-26: structural path shapes (0.9.0). The **path** step claims a path rooted at or carrying
  a variable reference through `entropy::is_reference_rooted`, for keyed and keyless values of every
  capture kind, and the `_DIR`-only **shell-path** step is retired into it; its separator-attack
  pins stay green because every literal piece must read as a word, while the three pins that
  asserted a keyed or single-quoted `$STATE_DIR/diagnostic.log` is reported by tier 3 now assert it
  is exempt; behind a `secret` or `password` key the tier-2 assignment rules still report it. Two
  format-template fixtures whose `${name}` placeholders sit in a path of words moved to the
  variable-path class, since the path step now claims them before the template step.
  JSON pointers admit a schema keyword's `$` at the start of a segment (`#/$defs/name`), and in a
  pointer a separator-free run of 20 bytes or more vetoes only when it is not word-structured. The
  **relpath** step extends to keyed unquoted, double- and single-quoted captures with
  `entropy::is_keyed_relative_path`; a mixed part longer than eight bytes keeps the value reported,
  so `token = task/<16-byte id>/integrator/lead` still is. Its cost on random values of 20 to 64
  bytes at 4.0 bits or more, two million samples per alphabet: 19 base64 values (about 0.001
  percent), 24 values over base64 plus `. - _ :`, and 168 over lowercase letters, digits and
  `/ . - _` (about 0.009 percent), against the 0.1 percent the Monte-Carlo test allows the
  wordshape step. The **wordshape** step judges camel case
  per separator-delimited segment, so one separator between two camel-case segments counts like a
  camel-only value. The leaf check sets aside a trailing dot part of letters only at any length, not
  just of up to five alphanumerics, so `.credentials`, `.keystore` or `.production` no longer makes
  an opaque stem wordy (a tightening: such paths are reported again), and it accepts a leaf of short
  lowercase words that each carry a vowel (`oh-my-pi`). Accepted cost: a wordy path behind a
  reference or a key, a keyed relative path with one short id, and a dotted camel-case field path
  are no longer reported by tier 3. Measured on an eight-repository local corpus with an empty
  config: tier 3 went from 2146 to 1922 findings, none added and no other rule changed; the
  variable-path class fell from 199 to 67, relative paths from 32 to 13, and 60 member chains of two
  camel-case segments left with the dotted camel case. The rest of those classes are shell
  substitutions, globs and `:`-joined path lists, which are not paths of words.
- 2026-09-26: chunked payloads in the structural path shapes. Review of the entry above found that
  the reference predicate bounded only vowel-less words: 36 random lowercase letters cut into twelve
  chunks by `_` passed it as a component (`$VAR/<chunks>`), a default (`${VAR:-<chunks>}/…`) and a
  name (`${<chunks>}/…`), all reported at base. Three rules close it, each judging the whole value:
  - Balance. The words of every literal piece, name, default and pattern together must outweigh
    the short pieces: at least two words of four or more letters, and no fewer of them than short
    words outside the short-word vocabulary plus runs of digits after the first
    (`PieceWords::outweigh_short_pieces`). A reference whose name carries no short word outside
    the vocabulary (`HOME`, `STATE_DIR`, `run_id`) counts as one long word in place of its pieces;
    any other name adds its words as they are, so a name of short random chunks counts against the
    value. A JSON pointer carrying a schema keyword passes the same balance, and its `$` must open
    a segment of one word.
  - Chunk runs. Four or more letter words of at most five letters in a row inside one segment,
    carrying 14 letters or more, read as a value cut into short groups (`wordshape::is_chunked`):
    those are the fewest groups and letters a 20-byte value cut every two to five letters by
    one-byte separators carries. Vocabulary words are passed over (`com.apple.dock.plist`), and
    `/`, `\` and, in a reference path, the reference syntax end a run
    (`${XDG_CACHE_HOME:-$HOME/.cache}`). The rule rejects in the reference, keyed relative path and
    keyword-pointer predicates and in the one-separator camel-case form of the wordshape step; the
    zero-separator camel form keeps its base rule.
  - A leaf of short lowercase words (`oh-my-pi`) is wordy with two to four of them, under the 20
    bytes an opaque value needs.

  Measured with an attack grid through `scan_text`, counting the exemptions of the step that owns
  each predicate. Payloads were 20 to 64 bytes at 4.0 bits or more, cut into chunks of two to five
  letters, fixed or drawn per chunk, by one separator among `_ - . / + :`. The alphabets were random
  lowercase, random mixed case and consonant-vowel alternation, placed as a component, a reference
  name in each form, a default, a pattern, a leaf and a suffix; 1000 samples per cell. Before, then
  after this amendment:
  - reference predicate, three-letter chunks: 100 to 0 percent for both lowercase and
    consonant-vowel. Four- and five-letter lowercase: about 9 to 1.3 percent. Mixed chunk widths,
    lowercase: 27 to 2.2 percent. Consonant-vowel four- and five-letter: 100 to 13 percent. Mixed
    case: at most 3.8 to at most 0.05 percent;
  - keyed relative path: four- and five-letter lowercase about 8 to 1.2 percent, consonant-vowel
    100 to 17 percent, three-letter chunks 0 before and after;
  - keyword pointer: between 65 and 100 percent before, 0 after, for every alphabet;
  - one-separator camel case: consonant-vowel four- and five-letter chunks 96 and 98 percent
    before, random ones 2 and 8 percent, 0 after, as at base;
  - short-word leaf behind a reference or a key: 100 to 0 percent.

  Every residual is a sample cut by `/`. `tests/pathshape_chunking_tests.rs` runs the grid on the
  predicates themselves. Outside `/` it finds 0 exemptions in 100 000 samples per chunk width for
  random lowercase and mixed case, and in 25 000 per width for consonant-vowel; 100 000 per width
  were measured once, also 0. Accepted gap: a payload cut by `/` into chunks of four or five
  letters reads as a path of short directory names (`$HOME/.local/share/nvim/site`), and its
  rooted twin is exempt at base. Of such samples about 9 percent of random lowercase, under 0.3
  percent of mixed case and every consonant-vowel one stay exempt; the test prints these counts
  and checks that each exempted sample is reported once its `/` become `_`. The rooted path, the
  extension set-aside and a pointer without a keyword keep their base behavior, which exempts a
  chunked leaf of any alphabet. A keyed value that the relpath step now reports can still be
  exempted by the wordshape step, as at base (consonant-vowel four- and five-letter chunks, about
  83 percent). Corpus, same eight repositories and empty config, row by row: all 224 removals of
  the entry above hold, no removed row returns, and no row is added against base. This run counts
  2147 and 1923 findings where the entry above counted 2146 and 1922; the extra row is in base and
  head alike.

  The digit-bearing repair keeps digit runs from resetting the chunk counter and retains their
  count when a reference name is collapsed to one word. Otherwise eight short pronounceable
  groups with a digit in each could bypass the guard in a reference, default, or keyword pointer.
  The generated regression varies two to five letters, one to four digits, and digit position;
  it checks every supported non-slash position/separator combination and detection/redaction for
  payloads that are detected bare. The letter-only Monte Carlo counts above pool positions and
  separators within each alphabet/width; they are not a per-position or per-separator bound.
- 2026-09-26: value grammar and step scope. The false-positive classes below were fixed where they
  arise, in the rule's value grammar and in the scope of four steps, with no value, key or file
  name singled out:
  - **String prefixes and raw strings.** The quoted alternatives accept a Python prefix (one or two
    of `r b u f t`) and a C/C++ prefix (`L u U u8` and the `R` raw forms), and a Swift raw string
    `#"..."#`, any number of `#`, captures its body in a new group `entropy_raw` judged as a
    double-quoted value. Before, the prefix letter opened an unquoted value that the first-quote
    cut reduced to that letter, so the body was no candidate at all, which is the "Python raw and
    byte string prefixes" residual above for assignments, while the hole and delimiter bytes around
    it made the prefixed-string class. This widens detection: the agent surface of the corpus gains
    20 rows, all opaque test values in Rust raw and byte strings of this repository.
  - **f-string and t-string holes.** A double- or single-quoted body behind a prefix carrying `f`
    or `t` is read as literal text around `{...}` holes: `{{` and `}}` are literal braces, a hole
    ends at its matching `}` with brackets of every kind nested inside it, and a quoted string
    inside a hole is literal text of its own. Each literal run and each such string is evaluated
    as a keyless literal body, and the whole value is traced `exempt:hole`. A body with no hole, an
    unclosed hole or quoted string, a lone `}`, a body holding whitespace and a body under 20 bytes
    are judged whole, as before. Recall risk: a credential cut by a hole into pieces shorter than
    20 bytes is not reported, and a hex secret in an f-string gets no hex bypass.
  - **`&` terminators.** An unquoted value also ends before a trailing run of `&` followed by
    whitespace or the end of the line, and before a shell `&&` list operator followed by a command
    word and whitespace, `;` or the end, so `TOKEN=<hex40>&&echo done` reports exactly the 40
    bytes. An `&` inside a value stays data (`a=1&b=2`). Recall risk: a value whose own tail is
    `&&word` is cut there; none of the six encodings below contains `&`.
  - **Misread keys.** A key the grammar misread is no candidate, and the scan resumes right after
    its separator, so the text behind it is still read: the name before a `::` scope separator
    (`std::env`, `Acquire::Check-Valid-Until`), the name of a POSIX bracket class (`[:space:]`),
    and a one-letter key behind an odd run of backslashes, the letter of an escape (`\n: `). An
    escape letter joined to a longer key (`\ntoken=`) keeps that key, and an even run of
    backslashes is a literal backslash. Recall risk: a keyless value right after `\n: ` is no
    longer read as the value of `n`; `name::value` and `[:name:]` are no supported assignment form.
  - **Scheme re-anchor.** A URI scheme read as a key splits `https://host/...` into the key `https`
    and the value `//host/...`. When that split value would be reported (20 bytes or more, graphic,
    not path-shaped, not reference-rooted while the layer is on, past the entropy gate), the
    candidate becomes the whole URL from its scheme, without a key, and the url steps judge the
    complete URL, which the entropy gate does not measure again. A split value one of those checks
    drops keeps that outcome, so the re-anchor only narrows what is reported and never retargets a
    candidate to a `//` value. Known gap: a split value the path check drops, such as
    `//host/<opaque>/<wordy leaf>`, stays silently exempt as at base.
  - **Regex step scope.** Step 10 above: unquoted and bare captures reach it through the delimited
    form or a regex command, and the file-path gate is gone. The gate kept the step off the redact
    hook's pathless text because that text cannot say whether a value is source code, but the
    predicate reads the value bytes alone and its cost does not depend on the surface (no
    exemption on the opaque alphabets in the 1e5-sample property test or in the grids below),
    while keeping it off left every pattern in tool output redacted, a 0.8.0 residual. Recall
    risk: a regex-shaped secret handed to `grep -E` or written between slashes, the accepted cost
    of step 10 itself.
  - **Hash context per assignment.** The hash-context word that withholds the hex bypass is looked
    for from the end of the previous candidate's value to the start of the next candidate's key,
    so `sha256=<digest> api_key=<hex40>` reports the second value. This tightens rather than
    exempts; its cost is a finding where one line assigns a hash and then an exact-length hex value
    under a key that names no hash (none on the corpus).
  - **Quoted digest records.** Step 13 accepts a quoted value whose key is separated by `:` or `=`
    before the opening quote (`"integrity": "..."`, `checksum = "<hex64>"` in a lock file). Recall
    risk: a secret under the exact key `digest`, `checksum` or `x-checksum-<algorithm>` written as
    a quoted exact-length hex value. Its hash context already withheld the hex bypass, so it was
    reported only at 4.0 bits or more, which random hex almost never reaches. A non-hex value under
    those keys and a hex value under any other key stay reported.
  - **Markdown targets in call literals.** Step 3 retargets a call-literal body too, so
    `render("[docs](<url>)")` is judged by its target.
  - **Bracket captures stay out of the syntax step.** Measured first: of 2155 corpus files, five
    bracket captures clear the gates, and the expression recognizer covers four of them, Swift
    array types of a generic (`[Type<Arg>]`), all on the pathless surface and none on the audit
    surface, where the parser posture already drops them. Four rows do not justify a new exemption
    path and its recall guard; they remain a known gap.

  Recall guards: `tests/posture_clip_tests.rs` pins each change and runs three Monte-Carlo grids
  of 104,000 samples, tokens of 20 to 64 bytes from base62, base64, base64url, hex, base32 and
  lowercase base36. Each grid holds a form to a control that lacks the feature under test and fails
  on any token the control reports and the form loses. The grammar grid has ten forms (the three
  misread keys, `&&`, a digest assignment before the value, a markdown target in a call, a quoted
  value under a digest key where a digest-shaped token is exempt by design, an f-string) and loses
  none of 81,641 reportable tokens; the regex grid (a TypeScript regex literal, `/token/i`,
  `grep -E` and `rg` patterns) finds none of 79,774 regex-shaped and loses none; the interpolation
  grid is recorded in ADR 0003. True-positive twins are in `same-line-resumption.txt` and
  `raw-strings.txt`; the false-positive classes `scope-resolution.txt` and `escaped-key.txt` hold
  only shapes that fire on the base release.

  Corpus, same eight repositories and empty configuration. The audit surface is recorded in the
  ADR 0003 amendment of this date. The pathless agent surface (the redact scan over the same files)
  goes from 3466 to 2895 findings, tier 3 from 3270 to 2699: 628 rows removed and 57 added, 37 of
  them respans and 20 the new rows of the first item. Removed: 274 scope separators, 184 rows of
  this repository's own source (Rust `::` paths, patterns in `rules.toml` and the docs, markdown
  links in call literals), 63 regex literals, 38 expressions split at `::`, 20 prefixed strings,
  19 split URLs and 30 others. One of the others is the crafted `checksum = "<hex32>"` value in
  `tests/env_entropy_redaction_tests.rs`, now a digest record; the env-text contract that test
  asserts, an unquoted `CHECKSUM=` value, is unchanged.
- 2026-09-26: value shapes of the wordshape and template steps. The residual tier-3 findings left
  after the structural path shapes held value shapes the layer did not read: platform symbols,
  search patterns, environment entries and key chords, interpolated strings, escaped string
  bodies and spelled-out character sets. Every position a token could fill in a new
  shape is either shorter than `MIN_ENTROPY_LENGTH` or handed to a judgement that existed before,
  so a token that fills it is exempted no more often than in that earlier form.
  - **wordshape**, camel case. A separator-free identifier may open with a hungarian `k` and with
    a leading acronym: a framework class prefix from the closed `FRAMEWORK_PREFIXES` list (`NS`,
    `UI`, `CF`, `CG`, `CGS`, `AX`, `OS` and the other platform prefixes), a short-word acronym
    (`URL`, `DNS`), or both run together (`NSURL`). Inside it only short-word acronyms stand
    (`sourceDNSRecordType`), and one run of at most four digits may close it. Behind a leading
    acronym three long words suffice (`NSCameraUsageDescription`). Every widened form is refused
    when a run of short groups crosses its humps; a plain camel identifier keeps its base
    judgement, since the guard on it reported two real identifiers of the agent corpus again
    (`libcPosixSpawnFileActionsAddopen`). The prefix list is a vocabulary of platform
    naming, as the short-word vocabulary and `MODIFIER_KEYS` are, not a list of observed values,
    and it is closed because an open one was measured to cost recall: with any two to five
    capitals allowed to open an identifier, random base64 values of 20 bytes gained one exemption
    in 1e5 and random mixed-case letters one and three at 20 and 24 bytes; with the list, every
    credential cell of the standalone grid equals the base.
  - **wordshape**, pieces. `wordlike_piece` reads a vowel-poor compound, a vowel-less vocabulary
    word of three letters at either end of a word that passes the vowel rule (`launchctl`,
    `dstblock`), and `ctl` joined the short-word vocabulary. The path and relpath steps read pieces
    the same way and claim seven more paths of words through it on the audit surface.
  - **wordshape**, search patterns (`is_word_pattern`): `(…)` and `(?:…)` groups of `|`
    alternatives, top-level `|`, the anchors `^`, `$` and `\b`, POSIX classes with an optional
    quantifier, escaped `.`, `-` and `/`, literal runs of word bytes, and a shell case pattern
    closed by `)`, with no nesting and no empty alternative. Every literal run passes the judgement
    a plain alternation gives its item (`is_short_item_structured` below 20 bytes, the identifier
    rule from there on), so a pattern is exempted no more often than the plain alternation of its
    runs, and a token that fills one run is judged as it is alone. The runs must also read as
    words, at least three of four or more letters that outweigh the short pieces, with no run of
    short groups. This closes part of the word-alternation residual above.
  - **wordshape**, entries and chords (`is_word_entry`). An environment entry `NAME=value`: a name
    of at least four capitals, digits and `_` opening with a capital, either one word below 20
    bytes or a snake name the identifier rule accepts, and a value that is a number of at most four
    digits or a flag of lowercase words of at most eight bytes (`GOFLAGS=-mod=readonly`). A key
    chord `modifier+…+key=action`: modifiers from the closed `MODIFIER_KEYS` list, a key of at most
    twelve bytes and an action the identifier rule accepts. Neither a snake name nor an action may
    carry a run of short groups. A bare word after an environment name stays reported, because a
    string literal holding `NAME=<eight letters>` is a whole candidate and a random lowercase word
    reads as a word about half the time; comma lists, flag lists and chords with no modifier head
    stay reported, because random lowercase letters cut by `,`, `+` and `=` read as the same words.
  - **wordshape**, the chunk guard of every new shape is `is_chunked_with_digits`: `is_chunked`
    with each run of at most five digits counted as a group, and with the two-letter vocabulary
    words counted as groups too, since about one pair of random letters in seventeen is one and a
    payload cut every two letters would otherwise hide enough groups. `is_chunked` is unchanged.
  - **template**: interpolation holes, Swift `\(expr)` and `\#(expr)`, Ruby `#{expr}`,
    JavaScript `${expr}` and nushell `($name.field)`, whose expression is an identifier of words,
    `$name` or a number of at most four digits, with member accesses, calls whose arguments are
    such expressions and forced unwraps; a currency sign before a conversion (`$%(price).2f`); and
    a string body whose only structure is its escapes (`is_escaped_text`): at least one quote or
    control escape, words joined by separators, `=` and `,`, at least three long words that
    outweigh the short pieces, every short word in the vocabulary, and every line between two
    escapes of 20 bytes or more word-structured as it stands. The literal text of either form,
    read with every placeholder, hole and escape as a separator, carries no run of short groups.
    That guard also closes a base weakness: the template step exempted every lowercase payload cut
    into chunks of two or three letters, and every consonant-vowel payload, when the chunks were
    joined by `{}`, `%s` or `${name}` (20 000 of 20 000 per cell), and up to 11 percent of the
    other lowercase widths; it now exempts none in any of the 260 template and escape cells.
  - Rejected: reverse domain names with short labels outside the vocabulary
    (`com.apple.security.cs.allow-jit`). A rule admitting one whole short label after a top-level
    label exempted random dotted lowercase tokens in `com.apple.<token>` 2306 times in 1e5 more
    than in `lib.apple.<token>`, and no corpus row depended on it. They stay reported.
  - Rejected: a spelled-out character set in the **symbols** step (`abc…xyz0123456789-_.`, a
    base64 alphabet), which would have claimed four rows of the corpus on the audit surface and
    six on the agent surface. Its bytes
    are the dummy token test suites carry, and `d2_exemption_layer_preserves_base_detections` in
    `tests/property_tests.rs` keeps every window of the alphabet `a..zA..Z0..9-_` a detection the
    layer must not remove; a window aligned on the runs (`0123456789-_abc…xyz`) is such a set, so
    no rule over the bytes can tell the two apart. They stay reported.

  Measured by `tests/valueshape_tests.rs`, 1e5 random tokens of 20 to 64 bytes per position and
  alphabet. The credential alphabets (base62, base64, base64url, hex, base32, lowercase base36) are
  never exempted in a position the shape judges itself, and never beyond the reference form where
  the position hands the token to an earlier judgement. That is the bound, rather than no
  exemption at all, because the identifier rule alone already exempts about one random credential
  in 1e5 (one base64 value of 24 bytes in the standalone grid at base, and, in one sampling, one
  base64url token filling a pattern item, which the plain alternation of the same items exempted
  as well); a position answers for what it adds. The camel positions draw 1e5 tokens without a
  separator byte, since a separator sends the value down the identifier rule's separator path,
  which is unchanged. The shape alphabets: hole expressions 2 in 1e5, escaped bodies 54, 61 and 8,
  the `NS` and `kAX` prefixes 51 and 46 over camel-case letters, all below the 100 the test
  allows; closing digits,
  literal text beside holes and conversions, entry names, chord actions and pattern items 0 beyond
  their reference. The chunking attack, 20 000 payloads per position, chunk alphabet (lowercase,
  mixed case, consonant-vowel, letters with a digit run) and width (two to five, fixed or mixed),
  joined by every byte each shape accepts between its items: no exemption in any cell. The
  standalone grid of the three predicates, 1e5 per cell: every credential cell equals the base, and
  the shape alphabets gain at most 54 in 1e5 (wordshape over lowercase with `_ - | ( )`), 50
  (wordshape over pattern bytes) and 45 (template over lowercase with escapes).

  Corpus, the eight repositories and empty config of the entries above. Diff and audit surface:
  tier 3 from 471 to 421 findings, none added and no other rule changed; interpolated strings 55
  to 28, variable paths 58 to 52, delimited word lists 16 to 12, format placeholders 3 to 0, single
  identifiers 4 to 1, open groups at the end of a line 6 to 4, regex literals 40 to 38, relative
  paths 12 to 11 and two unclassified rows. Agent surface (`scan_text`): tier 3 from 3270 to 2937,
  none added; interpolated strings 406 to 150, open groups at the end of a line 299 to 255,
  variable paths 71 to 65, escaped quote bodies 31 to 26, escaped field records 14 to 10, and 18
  rows across eight other classes. Every removed row is a template, an identifier, a path of
  words, a pattern or an entry.

  Accepted cost: an opaque value in one of these shapes, at the rates above. Known gaps, each noted
  in its fixture: a hole the capture cuts open (`\(controller.handle(for:`), an escaped record with
  a short piece outside the vocabulary, a pattern with fewer than three long words or with four
  short alternatives in a row, a comma or flag list, a bare word after an environment name, a
  chord with no modifier head or with a two-word action, a reverse domain name with a short label
  outside the vocabulary, and a spelled-out character set.
- 2026-09-26: residual reference shapes. The path and relpath steps read the rest of the shell,
  module and dated shapes that stayed reported after the two entries above; every rule is
  structural, none names a value, a key or a file.
  - Parameter expansion. The reference reader follows the shell grammar: a subscript (`[@]`, `[*]`,
    `[n]`, `[$i]`), a `#` length and a `!` indirection, the default, alternative and error
    operators (`${NAME:?message}`), the pattern removals, substitutions (`/`, `//`, `/#`, `/%`)
    and case changes, an offset, defaults nested up to four deep, `$(command)`, `$((arithmetic))`
    and RouterOS `$[…]` with balanced brackets, bracket expressions (`[[:space:]]`, `[$'\n\t']`),
    `$$` and the other special and positional parameters, which must not run into a letter, a
    digit or `_` (`$2y$10$…` stays a bcrypt hash), and an escaped `\$` or a `\"…\"` wrapper.
  - Joins and globs. `*` and `?` and the list joins `|` and `:` separate pieces, a `~` may open a
    list item, and the leaf of every list item must be wordy, a reference, a bare glob or a glob
    after vocabulary words (`com.*`). The glob bytes and joins do not end a chunk run.
  - Case. A default, pattern, replacement, message or counter (a subscript, an offset, an
    arithmetic name) is written in uniform case: each letter run lowercase, capitalized or all
    capitals. A list, a glob, an escaped path and references alone are written in coherent case,
    which also admits camel case whose humps have three letters or more (`JetBrains*`). References
    with no separator between them count each name word by word, need one word longer than five
    letters, and their names must be coherent.
  - Mixed pieces. At most one distinct piece, compared case-insensitively (`VST3` and `.vst3` are
    one), may set digits beside letter words of at most five letters, so chunks that each carry a
    digit run stay reported.
  - Long runs. A run of 20 bytes or more of letters, digits and `. - _ +`, between separators,
    joins, globs and reference syntax, must read as words on its own: a file name, whose parts are
    joined one at a time and are numbers or words closed by at most one number, in lowercase or in
    camel case of three-letter humps with an acronym of at most five capitals opening a hump
    (`x86_64-unknown-linux-gnu`, `com.apple.WebKit.WebContent`, `com.apple.UIKitSystem`); or an
    identifier (`wordshape::is_word_structured`). The rule applies inside names, operands and list
    items alike, since the syntax around them vouches for nothing there.
  - Host-rooted module paths (`github.com/owner/repo/pkg`, `gopkg.in/yaml.v3`) are judged by
    `is_path_shaped`, before the layer, as `#/$defs` pointers are: lowercase host labels and a TLD of
    two to six letters, then every part a word piece or short number in coherent case or a single
    letter or `vN` version, at most one mixed part, the words outweighing the short pieces, no chunk
    run with `/` included, the long-run rule, and a wordy leaf with a trailing `vN` segment and a
    closing number (`http2`) set aside.
  - Scheme-less urls. The rooted path rule read `//host/<token>` as a path. It now also requires
    an authority without userinfo and every part after the host a word piece in coherent case, a
    number or an abbreviation of at most five letters counted as a short word, at most one mixed
    part, the words outweighing the short pieces, and the long-run rule. Base exempted random
    base64url under a host 7.5 percent of the time (17 percent a segment deep) and base64 1.1
    percent (7.8); both are now 0 in 100 000 samples.
  - Keyed relative paths read a usage placeholder of under 20 bytes as the words it holds
    (`Tests/<Class>/<method>`) and set aside git's exclude magic before a pathspec (`:!`, `:^`)
    and an English possessive after the leaf (`notes.md's`). A dated file name, `YYYY-MM-DD-` then
    word pieces with at most one mixed part, outweighing words, no chunk run, the long-run rule and
    a wordy leaf, is exempt keyed or alone on its line (`2026-09-10-release-notes.md`).

  Recall, measured on the predicates with 100 000 samples per position and alphabet, tokens of 20
  to 64 bytes at 4.0 bits or more; hex never reaches 4.0 bits, so the pooled test draws it at any
  entropy, 100 000 samples over all positions:
  - base62, base64, base64url, hex, base32 and lowercase base36 in every new position (defaults,
    messages, patterns, replacements, names, subscripts, nested defaults, command, arithmetic and
    RouterOS bodies, glob leaves and middles, list items and leads, `:` lists, escaped paths,
    positional defaults, placeholders, dated tails): 0, except base64 whose `/` cuts it into
    directory names in a literal component (`${TMPDIR:-/tmp}/<a>/<b>_$$.log`, 4 per 100 000), the
    component rule's own rate at base (`$HOME/<token>/settings.log`, 10 per 100 000 before and
    after). Where base read those positions at all it exempted up to 6 per 100 000 (defaults) and
    now does not.
  - The recognizer's own alphabet, lowercase letters, digits and `. - _`, reads as words at most
    19 times in 100 000 (0.019 percent) in any reference position, 26 in a module path and 17 under
    a scheme-less host; base exempted 149 in a default and 152 in a component. The same alphabet
    with capitals: at most 1 per 100 000 in a new position.
  - Chunks of two to five letters joined by `_ - . + : |`, lowercase, mixed case, consonant-vowel
    and with digit runs: 0 in every new position (`tests/pathshape_chunking_tests.rs`), where base
    exempted chunks with digits 0.28 percent of the time in a default and 0.30 in a component. Under a
    scheme-less host, mixed-case and digit-bearing chunks are 0, two- and three-letter ones 0, while
    groups of four or five letters keep the rooted path's reading (lowercase 15 to 21 percent,
    consonant-vowel 41 to 46 percent, base 46 to 50): a url slug of short words
    (`/blob/main/docs/when-to-use-this`) is such a run to `wordshape::is_chunked`, and the rows
    that check would flip are real urls. The test prints those samples apart as the url slug gap.
  - The rooted path rule is unchanged, and it is not the "every segment wordy" rule the scheme-less
    guard adds: `/srv/<token>` exempts chunks of four or five letters about 46 percent of the time,
    base64url 7.6 and base64 1.1 percent, at base and after. Adding the chunk check there flips the
    committed fixture `./vendor/cache/widget-runtime-1.4.2-linux-aarch64.tar.gz` (`linux`, `aarch`,
    `tar`, `gz` are four short groups), so it needs its own change.

  Corpus, the same eight repositories and empty config: tier 3 went from 471 to 382 findings in the
  audit, none added and no other rule changed; variable paths 58 to 17, shell expansions 37 to
  17, module paths 15 to 0, relative paths 12 to 5, interpolated strings 55 to 51. On the agent
  surface, `redact_text` over 2155 files of the same repositories, tier 3 went from 3270 to 3161:
  variable paths 71 to 27, shell expansions 44 to 23, module paths 23 to 0, relative paths 30 to 23.
  The one row added there is a test's `//user:password@host:port/db`, a credential in a
  scheme-less authority, reported by design. Accepted cost: a secret written as words of a file
  name or as camel case in a list, glob or long run, and a module path or scheme-less url of words,
  are not reported by tier 3. Residuals: an expansion the capture cuts short (at a space in
  `$(command arg)` or `${VAR:?a message}`, before a stripped `]}` or `)`, or with a prose `)`
  after it), a vowel-poor leaf, references alone whose words are all chunk-sized
  (`${raw_path/#\~/$HOME}`), a camel-case operand (`${bundle_id%.appExtension}`), zsh nested
  expansions, a list of vocabulary globs cut into short groups, and a dated name of short words.
- 2026-09-26: the **syntax** step reads more of the source grammar it already stood for. A `#name`
  or `@Name` head and a `#[` or `#![` attribute apply to the group after them, a `$0` closure
  parameter and a `.0` tuple field count as members, a Go type assertion `.(T)` is a group after the
  dot, generic arguments leave their type the callee of the next group, and a Go slice, array or map
  type heads a composite literal or conversion. Without any group, a member chain of two or more
  segments joined by `.`, `?.`, `::` or `->` is complete when every segment reads as words - camel
  and snake pieces that are known short words or pronounceable, cased words of three to nineteen
  letters, at most two digit runs of up to four digits, no more than two pieces shorter than four
  letters per longer piece, an all-capitals word only inside a constant name, and without an
  underscore or an inner capital a single word under twelve bytes, digits included - with at most
  one segment of eight bytes or fewer that does not; one such name alone is complete only when
  marked `?` or `!`. A capture that closes
  a group it did not open is read from that group's opener on the same line, found by a
  quote-aware pass that resets at a quote still open before the capture. The veto changes in three
  places only: an identifier that reads as words by that measure no longer vetoes, a numeric
  literal of at most 16 digits grouped by `_` no longer vetoes, and a quoted body inside the span
  vetoes word by word around its interpolation holes and whitespace instead of as one run. The
  exact 32, 40 and 64 hex-digit veto is unchanged. A chain ending where the scan window ends is not
  complete. Measured over the agent surface of eight repositories, the step now removes 1080 of the
  1291 rows in the macro, member-chain, enclosing-group, open-group, type, other-expression and
  long-identifier classes, and adds none; on the working-tree audit of the same repositories the
  rule reports 50 fewer findings, 42 of them in those classes (61 to 19), and no new one.
  The guard is `tests/syntax_montecarlo_tests.rs`: random tokens of 20 to 64 bytes drawn from
  base62, base64, base64url, hex, base32, lowercase base36 and the identifier alphabet the
  recognizer reads, placed in each of 26 positions of the new readings, 100,000 per position,
  gave no covering span, and the text surface claimed none of 54,600 as `exempt:syntax`. Lowercase-letter tokens, the most
  word-like alphabet, were covered 2 times in 650,000 (0.0003 percent), both as a dotted split into
  two pronounceable halves, against a ceiling of 0.1 percent. The accepted cost is that a
  credential written as a dotted chain whose pieces all read as words, or whose one opaque piece
  is eight bytes or shorter, a word-shaped type name marked `?` or `!`, a grouped 64-bit literal,
  or a credential split by spaces into pieces under 20 bytes inside a quoted argument, is not
  reported by tier 3 when it sits in such an expression. A JWT and any value with an opaque segment
  longer than eight bytes keep the veto. The residuals are recorded as `# known gap:` lines in
  `swift-macro.txt`, `member-chain.txt` and `type-expression.txt`: a macro call left open after a
  bare argument, an acronym inside a lower-case segment, a bracketed type after a `key:` (a
  bracket capture, which never reaches this step), and a C type whose last snake-case word is a
  single letter.
- 2026-09-26: the **markdown**, **pin**, **url** and **digest** steps read four more kinds of
  syntax around a value. Their positions in the order are unchanged, and each entry above keeps its
  gate; what follows extends it.
  - **markdown** also reads through an autolink whose closing `>` the value grammar consumed (the
    target of any autolink now holds no `<` or `>`), a one-item quoted flow sequence of a URL with
    its scheme, and a markup element on one line, anchored at both ends: the text after one or more
    open tags and before the matching close tag, the text between a leading `>` and a close tag
    after a formatter broke the open tag across lines, or a URL with its scheme before a complete
    close tag. Tag names are lowercase and shorter than 20 bytes, only a close tag ending the value
    may lack its `>`, and every later text run is shorter than 20 bytes and enclosed by an element
    of its own. Accepted cost: an element text shorter than 20 bytes ends at this step, as a link
    target of that length always did; no other byte of the capture leaves the evaluation.
  - **pin** also accepts a version tag, `vN`, `vN.N` or `vN.N.N` with numbers of up to four
    digits, optionally on one lowercase branch word (`release/v1`), when every owner, repository
    and path segment of the reference is a name of words, numbers of up to ten digits and lowercase
    alphanumerics of up to five bytes. Accepted cost: none on the value, which is a tag; an opaque
    owner or repository keeps the line a finding.
  - **url** treats a path segment or fragment that is a slug as credential free (words and numbers
    joined by `-`, `_` or `.`, at least half of its letter pieces words of four or more letters,
    at most twelve digits); reads a markdown link chain the value grammar split inside a badge
    (`label](url)](target`) only when one target is an absolute URL, every target is free - a
    relative target being a path of file names holding a word of four or more letters, with no
    query and at most a slug fragment - and a label tail is a name shorter than 20 bytes; and
    accepts a value with no scheme only as an email address or `user@host` whose local part and
    host labels are words and whose last label is alphabetic. Accepted cost: a lowercase
    word-shaped value in a path segment, a fragment or an email local part.
  - **digest** also accepts, after its `:` gate, a go.sum `h1:` hash of exactly 44 bytes of
    standard base64 with its padding, and a subresource-integrity value `sha256-`, `sha384-` or
    `sha512-` followed by standard base64 of exactly 44, 64 or 88 bytes under an `integrity`,
    `hash`, `digest` or `checksum` key. Accepted cost: a standard-base64 value of exactly that
    length under exactly those labels; `sha384-` has no padding at its length, so any 64-byte
    standard-base64 body there is a digest by construction. With the quoted-digest gate of the
    value-grammar entry above, a quoted integrity value (`"integrity": "sha512-..."` in a JSON lock
    file) reaches the step as well and is held to the same exact encoded length.

  Measured with random tokens of 20 to 64 bytes: at every new position (the email local part and
  host label, a chain's relative target and label tail, a form-list field, a slug, a tag
  reference's owner, repository, path, tag and branch word), 2e4 tokens from each of base62,
  base64, base64url, hex and base32 plus 1e5 printable-ASCII tokens gave 0 exemptions (the
  form-list field excludes printable, whose `#` and `&` end the query where the older fragment and
  field checks accept its short pieces), and 1e5 tokens per encoding alphabet in each digest label
  gave 0 exemptions off the exact encoded length. The markup, flow and autolink
  readers returned either exactly the wrapped text or nothing, and at the engine 2000 tokens per
  alphabet, printable and letters included, lost no finding inside any of eight wrappers that the
  same engine without the layer reported. The `tier3_montecarlo_tests` harness reports 0 markdown
  and 0 unattributed misses on every generator. Printable-ASCII was the discriminating alphabet: a
  first version guarded only by the encoding alphabets let a token carrying `<`, `](` or a quote
  lose its finding through an unanchored element reading and a short relative chain target, which
  that harness caught and the anchoring above removed. Word-shaped alphabets pass at a measurable
  rate, as they do for the wordshape step: over 1e5 strings of lowercase letters and `-`, a slug
  1.87 percent and the wordshape step 0.73 percent, and a URL path segment 2.18 percent against
  0.73 percent before; over lowercase letters, `.` and `@`, an email address 0.53 percent. None of
  these alphabets is a credential format, and the 0.1 percent a recognizer of words would be held
  to is not met by the wordshape step either.
- 2026-09-26: review repair of the five entries above. A full-range review put a token INSIDE the
  positions the new readers treat as structure (a hole, an escape, a member, a reference or tag
  name) and found values the base release reported that the readers above had exempted. Every
  reader now judges the value it claims as a whole: the digit-aware chunk guard
  (`wordshape::is_chunked_with_digits`) sees every alphanumeric byte of the value, the bytes
  inside holes, escapes and names included, and unknown lexical state keeps the whole candidate.
  The acceptance test of the repair is per generated sample: the findings of this release must be
  a superset of the base release's on the same line, in every position the entries above added,
  on the pathless text and on the file surfaces. The five parts follow, each with its rule, its
  measured rates and its accepted cost.
  - **Interpolation holes and string prefixes keep the tokens inside them.** The tier-3 value
    readers narrow the captured shell word only where the bytes and the surface prove the narrower
    reading. A Python f-string or t-string body is read around its `{...}` holes only on a Python
    file, and only when every hole is one expression of names (member access, call, subscript, an
    optional `!r`/`!s`/`!a`) whose text is code of words and the whole body is not a run of short
    groups. A hole holding a quoted string, an escape, a format spec or an opaque run keeps the
    body whole. On the pathless surface, shell, dotenv and files of unknown language `f"{...}"` is
    literal data. A language string prefix (`r b u f t`, `L u U u8 R`, a Swift `#"..."#`) no
    longer ends a capture in the grammar: the `entropy_raw` group of the value-grammar entry is
    withdrawn. An env-style value stays the whole word a shell reads (`VALUE=b"x"<word>`). The body
    of a prefixed string is read on its own only for an assignment that is not env-style, or when
    the string closes the value on a tracked or parser-supported source file and its body opens no
    brace the reader cannot prove to be a hole. Every heuristic reader that takes text for code (a
    hole expression, a misread `::`, POSIX-class or escape key, the command word after `&&`) meets
    the aggregate chunk guard over all its alphanumeric bytes, and a run of letters and digits,
    joined or not by `+ / _ -`, that clears the rule's entropy threshold must be word-structured as
    a whole. Under the parser posture, literal pieces that none report alone but that together read
    as a chunked token keep the finding whole. The parser reads a format specification as a
    literal body, which Python hands to `__format__` verbatim, and the hole's expression in front
    of it as code, so a token cut into groups by `:` puts its first group in that expression: a
    hole whose specification, nested replacement fields left out, is not Python's format
    mini-language (`[[fill]align][sign][z][#][0][width][grouping][.precision][type]`), and whose
    text reads as a run of short groups with nested fields breaking the run, stands whole. A
    mini-language specification behind an attribute chain of short words (`{self.base.name:>12}`,
    `{node.hash:016x}`) stays clipped. Measured: 1e5 random tokens (six alphabets, 20-64 bytes) in
    each of 22 positions and 2e4 chunked tokens in each of 17 separator cells, on the pathless and
    file surfaces, lose 0 against the same token standing alone; a 2e3-sample-per-cell survey
    against the base release finds no reportable loss on the pathless, shell, dotenv, text, C++ and
    unparsed-Python surfaces. Costs: an escape-key line with four short words
    (`Build(v${MAJOR}.${MINOR}.${PATCH})`) and scope paths whose members read as a run of short
    groups (`CStr::from_bytes_with_nul(...)`, `std::io::stdin().take(1_000_000)...`) are reported
    again. The parser posture's accepted cost: a token standing after the closing quote as Python
    code, a separate expression behind `,` or `;` (`VALUE=b"x",<token>`, about 76 percent of
    reportable tokens in the survey) or an operand behind a `+`, `-` or `/` that opens it (about 1
    percent or less), is code to the parser and is dropped where the base release reported the
    whole shell word; a bytes literal holding braces, `b"{<token>}"`, is judged by the template
    step the way the base release judged `"{<token>}"` (212 of 1,560 reportable tokens on parsed
    Python).
  - **Grouped identifiers inside template holes.** A value that holds a token the base template
    grammar did not read — an interpolation hole (`\(…)`, `\#(…)`, `#{…}`, `${expr}`, `($…)`) or a
    currency sign before a conversion (`$%(…)`) — is judged by the chunk guard over the whole
    value, with hole expressions and placeholder names in place, as well as over its literal text.
    One hole expression holds at most one word of one to three letters outside the short-word
    vocabulary, the syntax step's bound. A value made only of base placeholders keeps its names out
    of the guard. Capital runs opening a placeholder or hole name come only from the
    framework-prefix list, and POSIX class names only from the POSIX set. A chord's key is read
    with its action, and an entry's name with its flag. The vowel-poor compound reading of the
    value-shape entry is withdrawn: a payload placed inside it lost its finding. Before this repair
    the layer exempted a token cut into short identifiers inside a hole: 565,347 of 1,425,312 base
    findings were lost in 2.25 million generated samples; now 0 in 1,125 cells, and 0 beyond the
    payload alone. Credential tokens cut at any width into hole members lose 21 of 960,000 to the
    template step. Letter-only members of six or more letters that pass the vowel rule read as
    words (1,874 of 40,000 lost), and so do such members closed by one to three digits, which
    base32 and base36 tokens cut into members reach at about 2 in 100,000, while the same words as plain text are exempted by the base word
    step at 13-15 percent (6-11 letters). Positions shorter than 20 bytes lose by construction, the
    currency name at the rate of the base `%(name)` conversion (434 against 435 of 2,000). Corpus:
    8 rows the base release reported return, all false positives (paths to `…ctl` binaries and one
    `\(d.rawValue)`-shaped hole).
  - **Escaped bytes in references.** The reference reader consumed a backslash and the byte after
    it without counting that byte in a bracket expression or a quoted string, and backslashes cut
    the run checks, so a token escaped before every byte inside `${NAME%[…]}` read as syntax (base
    766 of 1000 generated cases reported, the reviewed tip none). An escaped letter or digit in a
    pattern, a bracket expression, a single-quoted or an ANSI-C quoted string is now a piece of the
    value; only the nine control escapes of ANSI-C quoting (`\n`, `\t`, `\r`, `\a`, `\b`, `\e`,
    `\E`, `\f`, `\v`) count neither way, under 3.2 bits a byte. A value with a backslash is also
    judged as the shell reads it: an escape before every byte leaves one run for the long-run
    rule, and an escaped separator (`\-`, `\.`, `\_`, `\:`, `\|`, `\+`) continues a run of short
    groups. A bare backslash separates directories, ending a run as `/` does, only outside any
    reference in a value written as a Windows path is: plain references (`$NAME`, `${NAME}`,
    `$(NAME)`, `{name}`, `%NAME%`) and literal pieces (`%APPDATA%\Tool\settings.json`); inside an
    operand, a pattern, a bracket or quoted string, and anywhere in a value with an expansion
    operator, a subscript, a length or an indirection, a special or positional parameter, a
    command, arithmetic, a glob, a list, an escaped dollar or escaped quotes, it is an escape and
    the chunk guard reads the groups on both sides of it as one run. Bracket ranges run up within
    one class (`a-z`, `A-F`, `0-9`), at most six per value. A positional digit (`$1`) and a
    positional run (`${10}`) are numbers of the value. A scheme-less url holds no backslash.
    References alone whose name is a dotted member chain (`${item.name}`, `{self.root}`) carry no
    path and are left to the template step; optional chaining (`${item?.name}`) and a command that
    opens on a member access (`$(item.name)`) are not read as references; a dotted name inside a
    path keeps its earlier reading (`${ctx.workspace}/${ctx.name}.lock`). Measured against the
    base release over 46 positions: no token cell and no chunk cell loses a sample to the path or
    relpath step except those cut by `/` or `\/`; a bare `\` between chunks is claimed only in a
    path of plain references, on the same samples as base; the reviewer's probe reports 766 of
    1000, as base. The engine cells lose 0 in 100,000 tokens per alphabet and writing; member
    chains, 20,000 per kind and operator, are claimed 0 times alone, beside another reference, in
    a default, in a command or with optional chaining. Accepted cost: a Windows path inside an
    operand, or in a value with any shell syntax, with four or more directory names of at most
    five letters in a row is reported. Residual, the directory ambiguity this ADR already accepts
    for `/`: chunks cut by `/` or `\/` in an operand, a pattern, a command, a list or a glob read as
    a path of short directory names (consonant-vowel groups up to 744 of 771 in a message, lowercase
    up to 278 of 1000, `\/` up to 395 of 396).
  - **Aggregate chunk protection for URL reference names.** The url readers judged names piece by
    piece: a tag-pinned action's owner, repository and path, a badge chain's relative target and
    label tail, a url path slug and fragment, an email or `user@host` address, markup tag names and
    texts, and a form-encoded list. Each reader now also judges the whole name. A tag-pinned
    reference reads owner, repository, path and release-branch word as one name, whose words of
    four or more letters are at least half as many as its other letter pieces and digit runs, not
    cut into short groups across `/`. A relative badge target is judged by its leaf, so a word in a
    directory above no longer vouches for an opaque leaf, and by its whole path. A label tail must
    not be cut into short groups, and tail and relative targets together must not be a run of
    letter groups. A slug or an email address must not be a run of short letter groups, and an
    address's words must outweigh its short pieces. A markup value whose tag names and texts
    together are chunked is evaluated whole, and later element texts are dropped only while they,
    with a returned text short enough to be dropped, stay below the tier-3 minimum. A form list
    holds at most one short letter-digit mix. Digest records keep their exact-length check.
    Measured at the engine: 1e5 tokens per reader from the six alphabets and 2e4 chunked tokens per
    reader and chunk kind, in 26 positions over 8 readers, lose 0 where the same token alone is
    reported, with scan and redaction twins. Residual: a label tail of 19 single-case letters that
    reads as a word, with the rest of the token in a short absolute-url segment (12 per 20,000
    base32, 2 per 20,000 base36), and rarely a tail of digit-bearing groups (1 of 1,000 in one
    generated cell). Autolink and one-item flow-list wrappers stay transparent: a payload they
    wrap is lost only where the same URL standing bare is not reported either. Cost: an action whose owner and repository run four or more words
    of at most five letters together (`acme-rust-lang/setup-rust-toolchain@v1`) is reported, as it
    was before the version-tag reader, and so is a sitemap entry whose url text is shorter than 20
    bytes and is followed by date and priority texts. Commit-digest pins are unaffected.
  - **Widened syntax readings judge the value they claim.** The readings the syntax entry added
    (`#name`, `@Name`, `#[` and `#![` heads, `$N` closure parameters, `.N` tuple fields, go `.(T)`
    assertions and type heads, open calls whose callee follows `>` or `!`, a quote ending a
    complete expression, bare member chains and marked type names, and the enclosing call of a
    value that closes groups it did not open) exempt a span, or the part of an enclosing span the
    value holds, only when that region reads as words: no run of short groups crosses it; its
    terms (identifier segments joined by `.`, `::` or `->`) hold only numbers of at most 16
    digits, word-structured segments, segments of at most three bytes and once per region an
    opaque segment of at most eight bytes; a one-word member under 20 bytes counts as a word only
    beside a structured member of the same term; and a term or region of 20 bytes or more has
    words that outweigh its short pieces. In the token veto a macro, attribute or parameter sigil
    counts toward the token's length and entropy, and the relaxation for identifiers made of words
    excludes tokens cut into short groups. A quoted body with interpolation holes vetoes when its
    joined text holds an opaque 20-byte token or the whole body is cut into short groups. Spans
    read by the plain grammar are unchanged. Measured: 0 exemptions in 14 payload-inside-position
    cells of 100,000, 52 chunk cells of 20,000 and 52 long-member cells of 20,000; the word-shaped
    lowercase rate is 0 of 650,000 (it was 2); against the base release, 0 losses in 1,136,000
    random-token samples and 0 syntax losses in 2,982,000 chunked samples. Recall risk: the words
    test has no dictionary, so pronounceable pseudo-word identifiers inside a widened position are
    exempt (9,459 of 28,400 generated samples that the base release reported, 2,520 of them
    reported when standing alone), payloads under 20 bytes that `/`, `+` or `-` split can read as
    words (8 of 113,600), and chunked payloads as arguments of a plain call stay exempt as in the
    base release. Corpus: 4 findings the base release reported return (documentation code spans).

## how to verify

- `cargo test --test tier3_exemption_tests` covers the steps in order and their retargeted ranges
  (`syntax_forms_and_adjacent_secrets`, `markdown_targets`, `pinned_action_references`,
  `urls_keep_credential_spans`, `word_structured_targets`), the hex bypass and its floor
  (`exact_length_hex_assignments`, `hex_floor_boundaries_and_capture_kinds`,
  `hex_floor_calibration`), the switch (`exemption_switch_restores_plain_entropy_gate`), the trace
  flag (`trace_url_exemption_is_opt_in`), the call-literal policy
  (`call_literal_policy_is_body_scoped_and_switchable`, `call_literals_have_exact_independent_ranges`)
  and the structural path shapes (`structural_path_shapes_are_exempt_and_traced`,
  `structural_path_shapes_keep_opaque_components_reported`,
  `shell_directory_separator_attacks_are_redacted`); the unit contracts `path_shape_contract`,
  `reference_rooted_contract`, `keyed_relative_path_contract`,
  `keyed_path_words_and_dated_names_contract`, `host_path_contract`, `scheme_less_url_contract`,
  `long_runs_read_as_file_names_or_identifiers` and `case_and_mixed_piece_contract` in
  `src/scanner/entropy.rs` pin the predicates themselves.
- `cargo test --test pathshape_chunking_tests -- --nocapture` runs the chunked-payload attack grid
  against the reference and expansion, keyed relative path, module path, scheme-less url, dated
  name, keyword-pointer and one-separator camel-case predicates, fails on any exemption outside
  the `/` gap and the url slug gap, prints the gap counts, and checks the reviewer's shapes end to
  end through `scan_text` and `redact_text`.
- `cargo test --test reference_montecarlo_tests -- --nocapture` places random base62, base64,
  base64url, hex, base32 and base36 tokens in every expansion, list, glob, module, url,
  placeholder and dated position, fails on any exemption outside the base64 `/` gap, and holds the
  recognizer's own alphabet under 0.1 percent.
- `cargo test --test tier3_montecarlo_tests` prints the recall and cost grid per generator, length
  and line form, and fails on a regression against the base rule.
- `cargo test --test posture_clip_tests -- --nocapture` pins the value grammar and the step scope
  of the 2026-09-26 amendment and prints its three recall grids.
- `cargo test --test valueshape_tests -- --nocapture` fills every new position of the value shapes
  with random tokens and with chunked payloads, prints the per-cell counts and fails outside the
  bounds of the 2026-09-26 value-shape amendment; it also checks that the `word-list` fixture
  reaches its step on both surfaces.
- `cargo test --test fixture_corpus_tests` walks `tests/fixtures/false_positives` and
  `tests/fixtures/true_positives`. The `# known gap:` and `# known cost:` comments in those files
  name the residuals above at the line where each is visible.
- `cargo test --test property_tests` and the five `fuzz/fuzz_targets` cover the predicates and the
  parsers against arbitrary input.
- `sekretbarilo audit --trace-exemptions` on a real tree reports which step suppressed which value.
  For the regex step specifically: a pattern body reports `exempt:regex` over its own range, while
  the same body carrying a contiguous run of 20 bytes or more of `[A-Za-z0-9_-]` outside its
  constructs stays a finding.
- `scripts/corpus-audit.sh` runs a before/after comparison over a list of repositories and prints
  the per-rule delta.

### Follow-up recall repair (2026-09-27)

The widened regex reading retains character-class contents in its aggregate chunk check.
Previously it discarded the entire class, so dot-separated opaque groups inside a negated or
range-prefixed class escaped detection on pathless text and unquoted delimited captures. Class
syntax still separates groups; its payload bytes now participate in the same check as surrounding
literal text. The existing source-file exemption for parsed regex literals is unchanged.

Template-hole identifiers use the existing word-unit rule for every underscore-separated
component, including numbers. Numeric components therefore have the same four-digit limit as
other numeric operands. The former unlimited numeric branch admitted repeated long digit groups
that reset the aggregate chunk detector. Regression coverage checks widths 4, 5, 6, 8 and 12 with
generated values through detection and redaction, and preserves a normal numbered identifier.

2026-09-27, numeric lists and escaped regex bytes. A second review measured two more losses against
the base release, and both readings now count the bytes they had set aside. The widened syntax
readings set numbers aside: `,` and `;` end the chunk run, a literal of up to 16 digits passed as a
number, and the words test weighed no number, so a list of decimal groups or of `0x` bytes under a
two-word `@Name(` or `#[name(` head read as structure. A widened region now keeps its opaque
content within the rule's minimum length: its numbers as written and its one opaque segment of at
most eight bytes, each with one byte for the joint after it, and the digit runs of its words span
at most `MIN_ENTROPY_LENGTH` bytes together. A numeric list long enough to be a value keeps the
finding, while an alignment, a bound or one ungrouped number of up to 16 digits keeps the reading. In
the token guard of the regex step, an escape outside a bracket class cut the base64 run and dropped
its byte from the chunk check, so a token escaped before every second byte read as pattern syntax.
An escape now writes its byte unless that byte is one of the eight class letters that
`regexshape::is_regex_escape` reads (`\b \B \d \D \w \W \s \S`): an escaped base64 byte, `\/` and
`\+` included, continues the run; an escaped letter or digit is a piece of its own in the chunk
check; and a class escape ends the run while its letter opens the next one, as before. Measured
against the base release with 2e4 samples in each of 172 cells, on the pathless text and on a
`.java` file: decimal lists lost 0.97-0.999 of the base findings under `#[name(` (0.60-0.97 keyed)
and 0.31-0.94 under `@Name(` (0.11-0.80 keyed), 16-byte `0x` lists about 0.05, and payloads
escaped before every second byte 0.19-0.28 (base62), 0.055-0.20 (base36) and 0.004 (hex), in all
521,023 samples in 43 cells; now 0 in every cell, and no finding is gained. The generated guards
lost 23,345 of 75,128 and 1,931 of 37,507 samples that the gates without the layer report, and now
lose none: `numeric_lists_inside_widened_heads_stay_reported` in `syntax_montecarlo_tests.rs`, 60
cells of 2,000 with decimal and `0x` lists of 20 to 64 bytes and four token alphabets under three
heads, and `escaped_regex_payloads_keep_detection_and_redaction_montecarlo` in
`posture_clip_tests.rs`, 24 cells of 2,000 with base62, base64, base36 and hex tokens escaped
before every second or third byte in three forms. Recall risk: numbers and one short opaque segment
that together span fewer than 20 bytes stay exempt under a two-word head, as any payload shorter
than a value does. A token escaped before every second byte and cut by class escapes is held by
the chunk check alone. A control escape such as `\n` or `\t` now counts as a letter of the value,
so a pattern dense in them is reported more often, not less. Corpus: the working-tree audit and the
agent surface of the same eight repositories are unchanged against the base tree (358 and 1,476
findings).

## references

- the layer and its step order in `src/scanner/engine.rs`; the predicates in
  `src/scanner/syntax.rs`, `wordshape.rs`, `urlshape.rs`, `calllit.rs` and `hash_detect.rs`.
- rule `generic-high-entropy-value` in `src/config/rules.toml`.
- `exemption_layer` in `src/config/mod.rs` and `src/config/allowlist.rs`; `--trace-exemptions` in
  `src/main.rs`.
- ADR 0001 for the entropy baseline and the two gates this layer leaves unchanged.
- pipeline step "Secret Extraction" in `docs/_pages/architecture.md`; the corpus and the fixture
  conventions in `docs/_pages/testing-false-positives.md`.
