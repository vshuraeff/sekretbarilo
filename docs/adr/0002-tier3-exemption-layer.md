# ADR 0002: an exemption layer for the tier-3 entropy rule

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
suppresses the finding. Each predicate is a pure function of bytes, and none of them consults the
assignment key.

The steps run in this order, all of them inside the `exemption_layer` guard:

1. **file** - `is_generic_rule_skipped_path` in `src/config/allowlist.rs`. Ignore files
   (`.gitignore`, `.dockerignore`, `.npmignore`, `.prettierignore`, `.eslintignore`,
   `.gitattributes`, `.helmignore`) and `CODEOWNERS` disable this rule alone; every other rule still
   runs on them.
2. **import** - `is_import_line` over the surrounding line. Skipped for call-literal candidates.
3. **markdown** - `unwrap_markdown_target` in `src/scanner/urlshape.rs`. This step retargets rather
   than exempts: the range is narrowed to the link target and evaluation continues on the inner
   value, and only a target shorter than `MIN_ENTROPY_LENGTH` ends here. Skipped for call literals.
4. **path** - `entropy::is_path_shaped` over the possibly retargeted value.
5. **pin** - `is_pinned_action_ref`: a digest pinned behind a reference, as a workflow `uses:` line
   writes it.
6. **url** - `is_credential_free_url`: a URL none of whose components carries a credential. A
   URL-shaped value can leave the layer through this predicate and through no other, so the two
   shape predicates below are skipped when `is_url_shaped` holds.
7. **syntax** - `expression_span` in `src/scanner/syntax.rs`, for unquoted and bare captures only. A
   complete source expression that covers the flagged range is exempt. The recognizer refuses to
   cover a credential: an inner token of at least 20 bytes vetoes the span when its Shannon entropy
   reaches 4.0 or its length is exactly 32, 40 or 64 hex digits.
8. **wordshape** - `is_word_structured` in `src/scanner/wordshape.rs`: values whose structure is
   words, camel case or snake case rather than an opaque run.

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

- the 0.6.x line-level hash-context exemption keeps precedence: a hex value on a line carrying a
  hash context word is a hash, not a secret;
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
  url and wordshape steps at their documented cost.
- `.terraform.lock.hcl` joined the generated-file list, which skips the file for every rule.

### the switch and the trace flag

`[settings] exemption_layer = false` restores the 0.6.x behaviour of this rule: the eight steps
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
- **dense regex literals in calls.** A regex body can clear the entropy gate, and a call body skips
  the syntax step, so such a literal is a finding unless a repository allowlists it.
- **base64-standard and printable tokens inside URLs and expressions.** The url and syntax steps can
  cover a token embedded in a URL or an expression. This cost is accepted and report-only: the
  fixtures record it, no gate was changed for it.
- **crypto test vectors.** The hex bypass stays on over them; the resulting noise is handled by
  repository allowlists rather than by weakening the bypass.
- **the `hook_payload` fuzz target** is deferred, because the hook parsers read from stdin and the
  target would have to reimplement that boundary rather than exercise it.

The `check-codex` relative-path allowlist defect found during this round is fixed in this release.

## how to verify

- `cargo test --test tier3_exemption_tests` covers the steps in order and their retargeted ranges
  (`syntax_forms_and_adjacent_secrets`, `markdown_targets`, `pinned_action_references`,
  `urls_keep_credential_spans`, `word_structured_targets`), the hex bypass and its floor
  (`exact_length_hex_assignments`, `hex_floor_boundaries_and_capture_kinds`,
  `hex_floor_calibration`), the switch (`exemption_switch_restores_plain_entropy_gate`), the trace
  flag (`trace_url_exemption_is_opt_in`) and the call-literal policy
  (`call_literal_policy_is_body_scoped_and_switchable`, `call_literals_have_exact_independent_ranges`).
- `cargo test --test tier3_montecarlo_tests` prints the recall and cost grid per generator, length
  and line form, and fails on a regression against the base rule.
- `cargo test --test fixture_corpus_tests` walks `tests/fixtures/false_positives` and
  `tests/fixtures/true_positives`. The `# known gap:` and `# known cost:` comments in those files
  name the residuals above at the line where each is visible.
- `cargo test --test property_tests` and the five `fuzz/fuzz_targets` cover the predicates and the
  parsers against arbitrary input.
- `sekretbarilo audit --trace-exemptions` on a real tree reports which step suppressed which value.
- `scripts/corpus-audit.sh` runs a before/after comparison over a list of repositories and prints
  the per-rule delta.

## references

- the layer and its step order in `src/scanner/engine.rs`; the predicates in
  `src/scanner/syntax.rs`, `wordshape.rs`, `urlshape.rs`, `calllit.rs` and `hash_detect.rs`.
- rule `generic-high-entropy-value` in `src/config/rules.toml`.
- `exemption_layer` in `src/config/mod.rs` and `src/config/allowlist.rs`; `--trace-exemptions` in
  `src/main.rs`.
- ADR 0001 for the entropy baseline and the two gates this layer leaves unchanged.
- pipeline step "Secret Extraction" in `docs/_pages/architecture.md`; the corpus and the fixture
  conventions in `docs/_pages/testing-false-positives.md`.
