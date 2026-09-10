---
layout: default
title: Testing False Positives
nav_order: 10
---

# Testing False Positives

A scanner that cries wolf is switched off. The corpus study behind 0.7.0 audited 16 local
repositories and produced 52,537 findings with not one confirmed secret among them; 99.58% of them
came from the single keywordless rule `generic-high-entropy-value`, and they fell into a small
number of recognisable shapes.

Those shapes are now committed as a fixture corpus that the test suite checks on every run, so a
detection change that revives one of them fails a test instead of reaching a user.

## The corpus

```
tests/fixtures/false_positives/*.txt   shapes that must produce no finding
tests/fixtures/true_positives/*.txt    shapes that must produce one
tests/fixture_corpus_tests.rs          the test that walks both directories
```

Every file name is a class of the taxonomy: `generated-constant-table`, `dotted-identifier`,
`url-no-credential`, `code-expression`, `path-glob`, `lockfile-hash-line-shapes`,
`documented-test-fixture-shapes`, `regex-literal`, `commit-sha-pin`, `placeholder-example`,
`env-var-name`, `css-selector`, `markdown-link`, `import-line`, `checksum-record`.

One shape per line. A blank line is ignored, and so is a comment, which is a `#` followed by a
space or a tab — `#include <sys/socket.h>` and `#widget-settings-panel` stay shapes. Leading
whitespace is part of the shape, because an indented line matches different alternatives of the
tier-3 rule than a bare one.

Every line is scanned twice, once through the diff surface (`scan`, under the path
`src/fixture.rs`, which no path allowlist covers) and once through the agent surface
(`redact_text`), because a shape that is quiet in a commit and masked in a `Read` result is still a
false positive.

## No opaque literal lives in the repository

An opaque value is written as a placeholder that the test expands from a deterministic generator:

| Placeholder | Expands to |
|-------------|------------|
| `{S32}` `{S36}` `{S40}` | alternating A-Z / a-z with a digit at every fifth index |
| `{HEX32}` `{HEX40}` `{HEX64}` | lower-case hex from a seeded xorshift64* |
| `{B64_44}` | a 44-character base64 body ending in `=` |
| `{UUID}` | a dashed 8-4-4-4-12 identifier |

A brace group that is not one of these, such as `${TOKEN}` or `{{ secrets.API_TOKEN }}`, is
ordinary fixture text and is left alone. A group that looks like a placeholder but is unknown, say
`{S12}`, fails the corpus meta-test rather than passing through as literal text.

A false positive needs no placeholder, because a false positive is by definition not an opaque
token. The exceptions are the shapes whose safety comes from their surroundings rather than from
their content: a pinned commit sha, a recorded checksum or etag, and a generated identifier such as
a tenant `{UUID}` in an environment file.

## Expected findings

A true-positive line is `<rule id>`, a tab, then the line:

```
generic-high-entropy-value	token = "{S40}"
password-in-url	https://widget-ci:{S32}@artifacts.example.internal/repository/releases/
```

The test asserts a finding of that rule whose reported span covers the expanded value, and that
`redact_text` masks it. The rule id must be one that `src/config/rules.toml` defines.

One of those files records behaviour rather than secrets: `lockfile-digests.txt` holds the
`sha256-` integrity digests that the layer still reports. They are not credentials, and if the
exemption layer ever learns that prefix, the deliberate move is to take those lines out of
`true_positives/` and put them in `false_positives/lockfile-hash-line-shapes.txt`.

## Running it

```sh
cargo test --test fixture_corpus_tests
```

A failure names the file, the line number and the line, and for a false positive it also prints
which rule fired over which byte range.

## Adding a fixture from a real false positive

1. Reproduce it. `sekretbarilo audit --trace-exemptions` reports the exemption decisions as
   findings of their own (`exempt:path`, `exempt:url`, `exempt:syntax`), so an absent decision
   tells you which gate the value never reached. Feed the value to `sekretbarilo entropy` on
   stdin to see its length gate, Shannon entropy and path shape.
2. Write the shape synthetically. Invent the host, the identifiers and the paths
   (`example.internal`, `acme`, `widget`) and reproduce only the shape. Nothing is copied out of
   the repository where you found it.
3. Add the line to the file of its class, or create a file named after a new class.
4. Run the test. If the line is quiet, the corpus has grown a regression guard.
5. If the line still fires, it is a gap, not a fixture. Record it as a `# known gap:` comment in
   that file, naming the shape and what the layer misses, and add the line once the gap is closed.

## Measuring a whole corpus

`scripts/corpus-audit.sh` runs an audit over a list of local repositories and writes the numbers a
tuning round compares:

```sh
scripts/corpus-audit.sh target/debug/sekretbarilo repos.txt out/before
scripts/corpus-audit.sh target/debug/sekretbarilo repos.txt out/after
scripts/corpus-audit.sh --diff out/before out/after
```

Both runs of a comparison are plain, because `--trace-exemptions` reports every exemption decision
as a finding of its own and those pseudo-rules would then show up as a gain. Add it to a single run
of its own when the question is which gate stopped a value:

```sh
scripts/corpus-audit.sh target/debug/sekretbarilo repos.txt out/traced --trace-exemptions
```

`repos.txt` lists one repository path per line. Each run writes `summary.tsv` (repo, exit code,
findings, files scanned), `findings.tsv` (repo, file, line, rule, masked match), `per-rule.tsv`
and the unparsed output under `raw/`. The `--diff` mode prints the per-rule delta between two runs,
smallest delta first, so a change that removes a class of false positives is visible as one line.

## Never commit a real token

Not in a fixture, not in a test, not in a comment that documents one. Generate it, or write a
placeholder the test expands. The only literals the corpus carries are the two documented fake AWS
keys the suite has always used: the `...EXAMPLE` one, which the default rules allowlist, and the
`...ABCDEFG` one, which stands in for a tier-1 finding.
