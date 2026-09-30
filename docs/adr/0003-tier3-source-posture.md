# ADR 0003: a source-file posture for the tier-3 entropy rule

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


- status: accepted, amended 2026-09-20 and 2026-09-26
- date: 2026-09-15
- scope: the source posture, its `[settings] source_posture` switch and the test-path skip behind
  `[settings] tier3_skip_test_paths` are scoped to rule `generic-high-entropy-value` only. Tier 1 and
  tier 2 rules are untouched by both, as are the 20-byte minimum length and the 4.0 entropy
  threshold of ADR 0001. The `redact-claude` surface inspects a tool result rather than a file and
  carries no path, so neither the posture nor the test-path skip applies there.

## context

ADR 0002 suppressed the shapes the 0.6.3 corpus produced by testing the bytes of the value. The
audits that followed on 0.7.0 measured what it left behind: 285 residual findings in this repository,
265 of them in `.rs` files, against 9 in a Go and shell repository and 1 in a Python one. Only about
a third of the residuals were shorter than 32 bytes, so a length gate would not have reached them.

The residuals are concentrated in source files rather than spread across the corpus, and they are the
shapes a byte predicate cannot settle: a dotted call opener that the syntax step did not cover, a
fragment of an expression split over two lines, a constant table. They are not low-entropy and they
are not word-structured; what separates them from a credential is where they sit in the file, which
the layer had no way to read.

The two populations of a source file differ in that position. A credential a program carries is
normally assigned as a string literal, while an opaque run outside every literal is usually an
identifier, a constant expression or comment text. The question this ADR answers is whether the rule
may trade the second population for quiet on the first.

## decision

A file whose extension names a supported language is scanned in **literals posture** for this one
rule. As accepted, that set was `.rs`, `.go`, `.py`, `.pyi`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`,
`.tsx`, `.mts`, `.cts`, `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp` and `.hxx` (`language_for_path` in
`src/scanner/literals.rs`); the amendment of 2026-09-20 below reduces it to `.rs` and `.go` for
0.8.0. In that posture:

- a tier-3 candidate is kept only when its captured range lies inside a string-literal body of that
  language; a candidate outside every body is suppressed, with the trace label `exempt:code`;
- every literal body on the line is a candidate of its own, evaluated like a call-argument body: no
  assignment key, no import step, no syntax step and no hex bypass;
- bare code and comments therefore never yield a tier-3 finding.

Shell, configuration and data formats, markdown, extensionless files and unknown extensions keep the
0.7.0 posture unchanged, as do the Python, JavaScript/TypeScript and C/C++ families under the
amendment below.

The recognizer is not a parser. It is a per-language table of literal delimiters and escape rules
driving a line tracker (`src/scanner/literals.rs`), which carries the open-literal state from one
line to the next. Unknown lexical state never narrows a scan. On the pre-commit `scan` surface only
the added lines of a diff are available, so the scanner reads the staged blob of a source-class file
to establish the state of those lines; where no context exists — a history audit, a path outside the
working directory, a blob that could not be read — the lines after the gap are scanned in full
posture rather than guessed at. `audit` and `check-file` hold the whole file and always have context.

**Ownership between the regex and the bodies.** A regex candidate whose normalized range equals a
literal body owns that body: it is evaluated once, with its assignment key, and its disposition
stands, so an allowlisted `keys` entry stays suppressed and the quoted-assignment hex bypass keeps
working. A body no regex candidate owns is evaluated as a body candidate under the rules above.

**The switch.** `[settings] source_posture = "literals" | "all"`. Unset, it is `literals` while
`exemption_layer` is on and `all` while it is off, so `exemption_layer = false` alone still yields
exactly the candidate set of the previous release with the layer off. An explicit value wins in both
directions:

| `source_posture` | `exemption_layer` | effect on source files |
| --- | --- | --- |
| unset | on | literals posture, literal bodies as candidates |
| unset | off | full posture, exemption steps and the call-literal collector off |
| `literals` | on | literals posture |
| `literals` | off | literal candidate generation and the posture stay on; the structural exemption layer and the hex bypass are off, while the remaining filters keep running: the length and ASCII gate, the path check, variable-reference detection, the allowlists and the stopwords |
| `all` | on | the 0.7.0 default, with the call-literal collector |
| `all` | off | the layer off entirely |

**Test paths.** A path with a directory segment `tests`, `fixtures`, `testdata` or `benches`, or a
file name containing `_test.`, skips this rule alone (`is_test_path` and `generic_rule_skip` in
`src/config/allowlist.rs`), with the trace label `exempt:testpath`. Tier 1 and tier 2 still run
there, so a real AWS key in a fixture is still reported. `[settings] tier3_skip_test_paths = false`
disables the skip, and it is active only while the exemption layer is on.

Since 2026-09-20 a Rust `#[cfg(test)] mod name { }` region counts as a test path for this rule as
well, with the same `exempt:testpath` label and the same `tier3_skip_test_paths` switch. The region
is recognised by the literal tracker while it is in code state, on the exact attribute `cfg(test)`
applied to a `mod` item only: `cfg(all(test, ...))`, the same attribute on a `fn`, a `use` or an
`impl`, and every other language are documented gaps. The recognition rides on the tracker, so it is
active in literals posture only and `source_posture = "all"` does not get it, unlike the directory
skip, which applies under any posture. Unknown lexical state still never narrows a scan: where no
context exists, the lines after the gap are scanned in full posture and no region is assumed.

Since 2026-09-26 the test-path predicate recognises the common layouts of other ecosystems as well,
under the same label and the same switch. The directory segments are `test`, `tests`, `__tests__`,
`testdata`, `fixtures` and `benches`, matched exactly and case-sensitively, a segment ending in
`_tests` or `-tests`, an XCTest target segment (`Tests` itself, or a CamelCase `Tests` suffix after
an ASCII letter or digit, as in `FooTests` or `FooUITests`), and a dotted .NET test project segment:
a non-empty prefix, a `.`, then a run of ASCII alphanumeric characters ending in `Tests`, as in
`Foo.Tests` or `Foo.UnitTests`. `spec` and `specs` are deliberately not directory segments, because a
bare `spec/` directory is also a common production specification/schema package name — a
corpus measurement found 9 real-code findings lost to it in one repository. The file names are
`*_test.*`, `test_*.py`, `*_spec.rb`, `*Tests.swift`, `*Test.swift`, `conftest.py`, and a JS/TS-family
`*.test.<ext>` or `*.spec.<ext>` name decided by the file's LAST extension (`js`, `jsx`, `mjs`, `cjs`,
`ts`, `tsx`, `mts` or `cts`, so `x.spec.d.ts` still matches via the final `.ts`, while
`config.test.env` and `api.spec.json` do not). A path carrying a literal `..` segment anywhere is
never a test path, regardless of any other segment. Lookalikes stay ordinary paths — `latest`,
`contests`, `attestation`, `Testimonials`, `specification`, `spectrum`, `protest.rs`, `inspect.py`,
`spec/x.rb`, `Foo_Tests/` — and `testing` is deliberately not a test segment, because it usually
holds shipped test-support code rather than tests. A baseline audit of an eight-repository corpus
had put 57% of the remaining tier-3 findings in test-shaped paths the narrower predicate missed,
most of them XCTest targets. Tier 1 and tier 2 are unchanged there.

One predicate is widened with the posture: a `#/`-rooted JSON pointer is path-shaped, with the
opaque-run veto for segments of 20 bytes or more kept as it is.

## alternatives considered

- **parse the languages.** Rejected. A parser per language is a dependency and a maintenance surface
  out of proportion to one rule, and it would have to be right on incomplete files, on a diff
  fragment and on dialects. The tracker needs only delimiters and escapes, and its failure mode is
  bounded by the rule below it.
- **raise the length floor or the entropy threshold, or require key context.** Deferred by the user
  rather than rejected on the merits. The measurement above is why it would not have worked here: two
  thirds of the residuals are 32 bytes or longer, and the shapes are byte-diverse.
- **make `exemption_layer = false` imply literals posture.** Rejected. The switch documented in ADR
  0002 means "the previous release's candidate set", and a user turning the layer off to compare two
  versions must get that set and not a new one. The posture has its own switch for the same reason.
- **bodies only, dropping the regex candidates in source files.** Rejected: it is simpler, and it
  loses the `keys` allowlist and the hex bypass, both of which depend on an assignment key that a
  body does not have.
- **guess the lexical state after a diff gap.** Rejected. A guess that a line sits outside a literal
  suppresses a real credential silently, which is the one failure direction this scanner does not
  take. No context means full posture.
- **a glob crate for the test-path rule.** Rejected as a dependency for a segment comparison.
- **let a `#[cfg(test)]` region run to the end of the file.** Rejected. Production code written
  after a test module would then drop out of the rule silently, which is the failure direction this
  scanner does not take. The region ends where its `mod` block does.
- **run the tracker under `source_posture = "all"` to get the region there too.** Rejected. `all`
  means the candidate set of the release before the posture, and the region recognition is a
  property of the tracker that posture turns on.

## consequences

This is an intentional scope decision about where the keywordless rule looks, not a claim that every
residual it suppresses is code, and not a claim that a credential can live only in a string.

Forfeited in source files:

- an opaque value outside every literal — an unquoted hex constant, a token pasted into a comment —
  is no longer reported;
- the hex bypass for unquoted assignments, which has no literal body to attach to;
- in a test path the rule is off by design, so a fixture token is reported by tier 1 or tier 2 or not
  at all.

Gained: literals in return positions, match arms, arrays and multi-line calls, which the rule's
single regex capture cursor never reached, are candidates now. That closes the multi-line call
fragment and the Go backtick residuals of ADR 0002 for the languages the posture covers, because the
tracker reads the language's own delimiters rather than a fixed quote set. The Python-prefixed
string residual stays open in 0.8.0, since Python is deferred by the amendment below.

The residual population is mixed rather than empty: a dense regex body written inside a literal
leaves through the **regex** step of ADR 0002, while a body whose only structure is `|`-separated
words remains one, as `tests/fixtures/false_positives/regex-literal.txt` records.

The measurement behind the `#[cfg(test)]` region: of the 109 residual tier-3 findings left under
`src/` of this repository, 99 lay inside such a module. Forfeited with them is an opaque literal
written in a Rust unit test, which tier 1 and tier 2 still report.

## how to verify

- `cargo test --test literals_tests` covers the per-language delimiter and escape table, the
  continuation of an open literal across lines and the reset after a gap.
- `cargo test --test source_posture_engine_tests` covers the posture, the two settings and their
  defaults, the ownership rule between regex candidates and bodies, and the two trace labels.
- `cargo test --test fixture_corpus_tests` walks the corpus under the path matrix described in
  `docs/_pages/testing-false-positives.md`.
- the `literals` fuzz target under `fuzz/fuzz_targets` exercises the tracker against arbitrary bytes.
- an old-versus-new audit replay over the same repositories, with `scripts/corpus-audit.sh` and its
  `--diff` mode, measures the change the way the 0.7.0 round was measured.

## amendment 2026-09-20: literals posture ships for Rust and Go only

0.8.0 narrows the decision above to `.rs` and `.go`. A file with one of the extensions `.py`, `.pyi`,
`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`, `.c`, `.h`, `.cc`, `.cpp`, `.cxx`,
`.hpp` or `.hxx` selects no tracker and is scanned in full posture — the 0.7.0 behaviour for that
file — and an explicit `source_posture = "literals"` does not change that. There is no setting that
re-enables those families.

The reason is the invariant, not the residual measurement. Review found that the
JavaScript/TypeScript, C/C++ and Python trackers could report a *known* lexical state over the wrong
set of literal bodies: a regex literal read as division after a postfix operator, on a continuation
line or after a control header's closing parenthesis; a backslash-newline splice, including CRLF
input reaching the history surface; and a PEP 701 f-string replacement field. Each of those is a
state the tracker carries into the next line, so recovering from an unknown state per line is not
safe in these families: a wrong guess does not end with the line that made it, and it fails in the
direction this scanner does not take — a real credential silently outside a body. The conservative
narrowing tried instead left the posture inert after an ordinary multi-line C macro or after the
first Python f-string, which buys the invariant at the price of the feature. Enumerating further
punctuation shapes does not establish the invariant either. The lexers for these three families stay
in the tree as dormant, experimental code; they are not claimed to be correct and they are not on any
scanning path in 0.8.0.

Consequences: Python, JavaScript/TypeScript and C/C++ files get no tier-3 relief in 0.8.0, and their
recall is unchanged against 0.7.0 — a tier-3 finding in bare code there is expected rather than a
regression, and the tools against it are a `[[allowlist.rules]]` entry and `tier3_skip_test_paths`,
which is independent of posture and still applies to every language. The `exempt:code` label appears
for Rust and Go only. Rust and Go keep everything the decision above describes; the
`#[cfg(test)] mod` region rule stays Rust-only.

Re-enabling a family needs three things: a bounded lexical subset that rejects the constructs it does
not support and falls back to full posture before guessing at them, rather than one that guesses;
engine-level parity tests against full posture over those constructs, so a body set that differs is
caught by a test and not by a review; and a review of that subset against this ADR's invariant.

## amendment 2026-09-26: the parser posture clips a straddling finding

The parser families (C/C++, Python, JavaScript/TypeScript and Swift, through
`src/scanner/source_literals.rs`) used to keep every tier-3 finding whose range intersected a proved
literal body and drop only a finding disjoint from all of them. A finding that began at a string
prefix, an interpolation hole or a regex delimiter and ran into the body was therefore kept whole:
`"\(name)<text>"`, `` `token=${name}<text>` ``, `R"(<text>)"` and `/<pattern>/i` were reported with
the hole or delimiter bytes inside the value, and an interpolation of words beside a hole was a
finding at all only because of those bytes.

A surviving `generic-high-entropy-value` finding is now compared with the proved bodies on its line:

- disjoint from every body: dropped and traced `exempt:code`, as before;
- inside a single string body: it stands as evaluated, its key and hex bypass included;
- otherwise, when it touches several bodies or covers bytes outside the one body it touches: it is
  traced `exempt:clip` over its original range, and each part of it that lies inside a body is
  evaluated again as a keyless literal body, the path a call-argument body takes (no key, no import
  or syntax step, no hex bypass). A segment is reported on its own merits or not at all, and the
  hole, prefix or delimiter bytes never reach a value.

The adapter also records which bodies are regular-expression literals (`analyze_with_kinds` and
`ParsedLine::body_kind`, a string, regex or generic body), so a segment inside `/.../flags` reaches
the regex step as a literal body even when the finding was exactly that body. The engine reads the
parsed lines once per file and applies the clip to this rule alone; tier 1 and tier 2 findings and
the Rust and Go tracker are untouched.

A Python f-string or t-string is read around its `{...}` holes by the value grammar itself, on a
Python file only and only when every hole is an expression of names (ADR 0002, amendments of the
same date), so the clip finds those segments already inside bodies and the trace for the reading is
`exempt:hole`. A hole whose format specification is not Python's mini-language and whose text reads
as a token cut into short groups stands whole, as does any clip whose literal pieces together read
as a chunked token. The Rust and Go tracker, whose
languages have no such string, keeps its own body check for that text.

Recall. The clip only narrows a finding to text the parser proves literal, and each segment faces
the gates any literal body faces. What it gives up:

- a credential split by an interpolation hole into pieces that are each shorter than 20 bytes, or
  each below 4.0 bits, is no longer reported; it was reported whole before. Interpolation joins
  runtime values, so such a string holds no complete literal credential;
- a hex value below 4.0 bits clipped out of a straddle has no key and no hex bypass. The straddle
  was never a hex policy candidate either, since the hole bytes are not hex, so nothing reported
  before is lost here;
- the clip acts on surviving findings only: a straddle whose whole value is dropped by a gate is
  not rescued. That is unchanged from the intersect policy.

Measured by `interpolation_hole_recall_montecarlo` in `tests/posture_clip_tests.rs`: 104,000
samples per dialect (Swift `\(...)`, Swift raw `\#(...)`, TypeScript `${...}`, Python f-string
`{...}` and a C++ raw string's delimiters), a random token of 20 to 64 bytes from base62, base64,
base64url, hex, base32 or lowercase base36 before or after a random hole of a name, a member access
or a call. Of the tokens a call-literal control reports (about 78 percent, the rest falling below
the entropy gate), none is lost: the audit surface reports each exactly, without hole bytes, and
the pathless surface covers each. `regex_body_recall_montecarlo` puts 104,000 tokens in a
TypeScript regex literal: none is regex-shaped and none is lost.

Corpus, eight repositories with an empty configuration (`scripts/corpus-audit.sh`, base against
head): the audit surface goes from 669 to 607 findings, tier 3 from 471 to 409, 99 rows removed and
37 added. Every added row is a respan of a removed row on the same line: 17 URLs now reported from
their scheme (ADR 0002 amendment), 15 regex bodies clipped out of their delimiters that the regex
step does not yet read as patterns, three opaque identifiers inside URLs now reported with the
scheme, and two rows whose values changed span on lines that keep a finding. The removals by class:
29 interpolated strings, 25 regex literals, 17 split URLs, 13 prefixed strings, three escaped keys,
three scope separators and nine others, among them the three URL identifiers respanned above.

`tests/parser_posture_tests.rs` pins the contract: a straddling full-posture finding yields exactly
one `exempt:clip` and exactly the generated body when the body alone passes the gates, a finding
inside a body is retained exactly, a disjoint one yields exactly one `exempt:code`, and each of the
four branches is exercised at least a hundred times.

## references

- the tracker and its language table in `src/scanner/literals.rs`, which also recognises the
  `#[cfg(test)]` module region; the posture and the candidate ownership in `src/scanner/engine.rs`.
- `source_posture` and `tier3_skip_test_paths` in `src/config/mod.rs`; `effective_source_posture`,
  `generic_rule_skip` and `is_test_path` in `src/config/allowlist.rs`.
- ADR 0002 for the exemption layer this posture sits in front of, and its residual list.
- ADR 0001 for the entropy baseline, which is unchanged.
- pipeline step "Secret Extraction" in `docs/_pages/architecture.md`; the settings in
  `docs/_pages/configuration.md`.
