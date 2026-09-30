# Complete-source parser implementation notes

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


This amendment draft implements the agreed parser choice for ADR 0003. The integrator owns reconciliation with the main ADR.

The new `scanner::source_literals` module analyzes the exact complete source blob. Its crate interface consists of `supports_path` and `analyze`; the engine now calls `analyze_with_kinds`, which also marks each body as a string, a regular-expression literal or a generic literal (`ParsedLine::body_kind`). No complete blob means full scanning. The engine checks every added line against that blob and rejects duplicate or out-of-range line identities before installing any narrowed lines. Rust and Go keep their streaming tracker and conservative latch; added-only CRLF input now strips the terminal CR before feeding that tracker.

For the new parser families, spans filter the findings emitted by the unchanged `source_posture = "all"` detector. The parser does not add candidates. This distinction is intentional: Rust/Go historically enumerate every literal body as an extra candidate, but reusing that policy introduced additional import, regex, docstring and character-table findings on the measured corpus. The parser families therefore pass no literal metadata into the shared candidate evaluator, then retain every emitted tier-3 finding whose byte range intersects a proved body. A finding can start at a prefix or operator before the opening delimiter and still contain the opaque body; it must remain. Only findings disjoint from every body are dropped, including call-collector findings in comments. This conservative boundary can retain benign delimiter-straddling templates. Superseded by the ADR 0003 amendment of 2026-09-26: a straddling finding is now clipped to the body segments it touches, each evaluated again as a literal body, and traced `exempt:clip`. Every removed baseline finding receives its exact `exempt:code` trace; existing non-code trace decisions and tier-1/2 findings remain unchanged. A language registered through this module, the Swift adapter included, automatically follows this filtering policy. Complete AST body coverage and the detector's candidate coverage are separate guarantees: a body missing from the full scanner's candidates is not introduced by posture filtering.

Pinned dependencies are Tree-sitter 0.27.0 (0.26.11 until 0.9.0 moved to 0.27.0, whose `Node::child_count` returns `u32`), C 0.24.2, C++ 0.23.4, Python 0.25.0, JavaScript 0.25.0, TypeScript/TSX 0.23.2 and Swift 0.7.3. All concrete nodes, including anonymous and missing tokens, are visited. Parsing and traversal share a 100 ms cooperative deadline, a 4 MiB input ceiling and a one-million-node ceiling. Any parse error, missing token, invalid UTF-8, NUL, bare CR, uncertain span, unsupported form or exhausted budget retains full scanning for the whole file. The wall-clock deadline is conservative but timing-dependent: the same file can retain more findings under load when its budget expires. LF and CRLF retain their original byte offsets; JavaScript Unicode line separators are handled without rewriting source.

C and C++ retain full scanning for files containing any splice (including trailing space, tab, CR, form feed or vertical tab) or trigraph marker. Supported raw strings keep their original body ranges. Single-line opaque macro arguments and system include names retain full scanning on their own line; raw-string or block-comment openers inside opaque macro arguments cannot establish a safe outgoing boundary and force full scanning. Ordinary grammar-recognized multiline comments are safe. Ambiguous `.h` headers remain fully scanned; `.C` selects C++ explicitly. No delimiter-free C floor is activated because the parser family passes its implementation gates.

Python supports ordinary, raw, bytes, Unicode, triple-quoted, f- and t-string forms. Non-UTF-8 encoding declarations retain full scanning. Interpolation expressions are excluded from outer text, while their nested literal bodies and format-specification text remain candidates. JavaScript, TypeScript and TSX preserve ordinary strings, template text, nested literals, regex patterns, JSX attributes and JSX text, including adjacent character references. TypeScript template literal types use their separate substitution nodes. A literal body includes its escapes as one range rather than splitting at escape tokens.

## Swift

Swift (`.swift`, any case) uses `tree-sitter-swift` 0.7.3 (MIT; its build script compiles only the vendored `parser.c` and `scanner.c` through `cc`, with no network access). The adapter maps single-line, multi-line (`"""`), raw (`#"..."#`, any number of `#`) and multi-line raw literals. `\(...)` and `\#(...)` interpolations are holes in the outer body, and a literal nested inside one is a body of its own. A raw string closed on its opening row is single-line even after `#"""`, as swiftc reads it. `#warning`, `#error` and `#sourceLocation` lines are one grammar token, so the whole line after `#` is kept as a body; a `"""` there falls back, since a multi-line literal could leave the line.

The grammar accepts some text that swiftc lexes differently. Each of these keeps the whole file in full posture:
- a comment node inside a literal, because the external scanner reads `/*` inside a string as a comment;
- a regex literal (`/.../`, `#/.../#`), which the adapter does not map, and a `#` directly before `/`;
- an operator holding a slash that is not left-bound but is right-bound by swiftc's rules (a line starting with `/b/` after a statement, or `a /b/ c`), which swiftc re-lexes as a bare regex while the grammar parses division;
- a single-line literal over several rows, a multi-line opener that does not end its line, and a multi-line closer that does not start its own line;
- a raw closer preceded by `\` and the delimiter's `#` run, which swiftc reads as an escaped quote while the scanner closes the string there;
- any child of a literal other than its text, escape, delimiter and interpolation tokens, and any gap between those tokens that is not whitespace.

A tree-sitter error recovery can leave only a zero-width ordinary leaf that carries the error cost, with no ERROR or MISSING node for the walk to find; with tree-sitter-swift, `x as? T ?? y` is one such shape. For Swift, a root that reports `has_error` therefore rejects the file before the walk. The check covers Swift only, the scope of this change: the other grammars were checked on R0 (681 parser-family files, none with an erroneous tree outside Swift), not proven immune. Among the R0 corpus's 505 Swift files, 14 fall back this way or on a plain parse error, none on the other rules above. Parsing the largest file (134 KB) takes 35 to 53 ms of the 100 ms budget on the Intel host in a release build, and the whole Swift set about 1.7 to 1.9 s single-threaded.

On R0 with an empty configuration (`scripts/corpus-audit.sh`, 6e05a1d against the Swift head), Swift `generic-high-entropy-value` findings fall from 1,762 to 434. All 1,328 removals carry an exact `exempt:code` identity, no finding is added, other rules and other languages are unchanged, and the repository fingerprints are identical before and after the runs. An `audit` of that repository takes 0.43 s instead of 0.25 s (median of seven pairs) with a peak RSS of about 144 MB instead of 130 MB. `redact-claude` builds no parser; its median on a small payload is 38 ms for both binaries.

## Adding a language

Add the dialect and its extensions in `Dialect`/`dialect`, then its pinned grammar in the `language` match inside `analyze_bounded`. Add language-specific preflight checks and concrete literal-node adapters in that same module. Reuse `segmented_body` to exclude interpolation nodes and `project` to validate, join adjacent text segments, and map absolute byte spans to physical lines. Do not change the engine dispatch or Rust/Go tracker to add a language. A tree-sitter recovery can leave an erroneous tree with no ERROR or MISSING node in it, so check the new grammar for such trees; Swift's root `has_error` check is the one addition it needed outside its own adapter.

The test helper `append_body` records expected spans while constructing source; `assert_oracle` compares the entire resulting per-line span set and requires every ordinary generated line to be known. New adapters can use these helpers without changing them. Extend the language cases in `tests/parser_posture_tests.rs` for explicit-all parity, exact `exempt:code` traces, Monte Carlo recall and unsupported-input fallback. Pathless text/redaction and synthetic shell paths have a thread-local construction counter proving they create no parser. Resource and encoding rejection controls live alongside the adapter tests.

## Host binary growth

Measured release builds on the Intel macOS host use the unchanged release profile. The exact base binary was 2,743,912 bytes.

| Increment | Binary bytes | Incremental bytes |
| --- | ---: | ---: |
| C and C++ | 6,768,148 | 4,024,236 |
| Python | 7,235,348 | 467,200 |
| JavaScript including JSX | 7,657,492 | 422,144 |
| TypeScript and TSX | 10,520,940 | 2,863,448 |

These staged measurements precede final formatting and adapter cleanup and are not the final artifact size. The shared cap is 12 MiB above the base artifact; the final result reports the final artifact size against that cap. Final cross-target builds, corpus measurements, and release-candidate validation belong to integration.

Swift was measured with one toolchain (rustup stable 1.98.1, no extra flags) for all three trees on the same host:

| Tree | Binary bytes | Growth over the root base |
| --- | ---: | ---: |
| Root base 5ea5525 | 2,747,800 | 0 |
| Parser families, 6e05a1d | 10,610,720 | 7,862,920 |
| Parser families and Swift | 14,272,896 | 11,525,096 |

Swift adds 3,662,176 bytes. The total growth is 10.99 MiB, 1,057,816 bytes under the 12 MiB cap; against the 2,743,912-byte base recorded above it is 11,528,984 bytes. The `aarch64-unknown-linux-gnu` build of the same head (`cargo zigbuild`, `-C target-feature=+neon` as in the release workflow) succeeds at 14,394,944 bytes.
