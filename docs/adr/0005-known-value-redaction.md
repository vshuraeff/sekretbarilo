# ADR 0005: reject persistent known-value redaction for now

- status: rejected
- date: 2026-11-01
- scope: user-registered values stored as a hash plus shape for `redact-claude`;
  design only, with no new command, configuration, storage or detector behavior

## decision

Do not build the proposed persistent known-value registry in this release. Exact
matching has value, but an unkeyed hash is an offline guessing oracle for a weak
value, and shape matching does not solve candidate discovery for arbitrary output.
A keyed alternative is feasible; it adds a secret lifecycle and a new bounded
matching pass whose operational cost has not been measured here. We require the
reopening evidence below before taking on that state and protection contract.

This rejects the present feature, not the possibility of exact redaction. It does
not turn on `generic-high-entropy-value`, weaken existing detectors, or describe
hash-only storage as safe to publish.

## value and threat model

At base `2c2f0ae`, `generic-high-entropy-value` is a heuristic rule, disabled by
default. Signature and contextual rules still catch their respective formats and
assignments. A registered value could add coverage when a tool prints a prefixless
token without a credential name, including a short value missed by the generic
rule. It could do so without classifying every unfamiliar string as a secret.
Registration would cover only the registered bytes: rotation, an unregistered
credential and an encoded representation remain separate problems.

The intended protection is against accidental disclosure in the model-facing
text fields of successful tool results. It does not undo tool execution, modify
source files, erase earlier transcripts or prevent network exfiltration. An agent
or attacker able to execute arbitrary commands as the user can read that user's
files, invoke a matcher as a guessing oracle or disable the hook. This feature
would not create a security boundary against that capability.

There are nevertheless two additional risks to account for: an accidentally
shared registry or backup can disclose information without sharing the original
secret store, and hostile output can force expensive candidate searches. These
risks exist even when a local account compromise is outside the threat model.

ADR 0004 treats known-value redaction as additive recall work, outside its FP
reduction phases. This decision retains its no-network-candidate and per-surface
measurement invariants. The survey ADR was read on `task/fp-research`; it is not
present at the source base used for this decision.

## what hash plus shape actually provides

The checked [redacted-cli 1.1.0 architecture][redacted] describes registration from
selected `.env` values, storing a name, SHA-256, byte length and optional shape.
Its learned pass first replaces shape-regex matches, then separately hashes
candidates obtained from character runs, assignment separators and punctuation
peeling. Thus its shape is also a generalized detector, not merely a prefilter
that proves equality. Its candidate grammar is not an exhaustive substring
search. We do not infer equivalent recall or performance for sekretbarilo from
this design description; no comparative benchmark was run.

An unsalted SHA-256 digest permits testing guesses without the original value.
A public salt prevents reuse of a precomputed table across salts, but does not
prevent guessing a particular weak value. Length, literal prefix and character
shape further constrain guesses. Minimum length and measured Shannon entropy do
not establish that a value was generated randomly. Replacing SHA-256 with another
fast unkeyed digest does not change this privacy issue. [OWASP's password-storage
guidance][password-storage] explains the fast-hash and salt distinction; applying
it to this registry is our threat-model inference.

A slow password KDF would raise guessing cost, but the hook would pay that cost
for every candidate, with potentially many candidates per output. Per-record salts
would also prevent sharing one candidate digest across all records. That is the
wrong default computation for an adversarial output scanner.

If reopened, choose full-length HMAC-SHA-256 over a versioned domain tag and exact
value bytes, using a random local 256-bit key. [HMAC][hmac] supplies keyed digest
comparison; privacy against a registry-only leak depends on keeping its key
separate. This is not password-storage hardening against theft of both key and
registry. The registry remains sensitive, including its length and shape metadata.
No plaintext prefixes, source paths, environment names or value-derived labels
belong in records; an opaque local record id suffices. Key loss or rotation
requires re-registering values, since the old digest cannot produce the new one.

## candidate discovery and its bound

A digest cannot locate its input in text. Checking only a whole whitespace token
misses a value embedded in punctuation or another token; stopping at the first
match can miss a second registered value in the same run. Generic rule matches
cannot supply the only candidates, because the feature is meant to catch values
those rules miss.

The reference algorithm for a reopening experiment is explicit: for each
registered byte length, slide that length over every possible start in each
supported decoded text field; consider only UTF-8 character boundaries. A coarse
alphabet category derived at registration may reject an impossible window, but
must contain every byte of its registered value. It stores no literal prefix and
never causes redaction by shape alone. Compute one keyed digest for each surviving
window and look it up among records of that length. Keep every matching range,
including overlaps. Match original field bytes before any replacement.

For field size `N` and `D` distinct lengths this entails at most `N * D` windows.
If the lengths sum to `S`, directly hashing every window costs `O(N * S)` bytes,
not `O(N)` merely because the registry is small. Shape checking itself must be
accounted for; checking each byte of each window adds similar cost unless rolling
category counts are used. Adversarial repeated text can defeat a coarse prefilter.
For illustration, a 10 MiB field and lengths 16 through 47 bytes
already imply roughly 335 million windows and 9.8 GiB of candidate bytes
when all pass. These are analytical bounds, not measured timings.

A viable implementation must cap registry bytes, records, distinct lengths,
value length, candidate work, hashed bytes and retained ranges across the entire
hook invocation, not separately per field. The existing 10 MiB payload bound is
not a CPU budget. Registration must reject unsupported values rather than silently
truncate them. If a budget is exhausted, withhold supported output through the
existing failure path; never return an incompletely scanned result as clean.
Concrete limits belong to the measured prototype gate, not to guessed defaults
in this ADR. A faster tokenizer is acceptable only with an explicit narrower
coverage contract and tests for every boundary it excludes.

Only exact bytes in the already-decoded hook fields are covered. No case folding,
Unicode normalization, nested JSON decoding, URL decoding, base64 expansion or
cross-field reconstruction is implied. Those transformations need separate
bounded designs and source-range mapping before they can add coverage.

## registration and storage trust

No configuration layer may register values under this rejected decision. If
reopened, registration must be an explicit local user operation receiving one
selected value over a protected input channel. Do not accept secret values in
argv, chat, logs or committed configuration. Do not crawl `.env` files, import
the ambient environment, learn from hook output or fetch from a secret manager
automatically. A later importer must let the user select entries without exposing
their contents, and handle its source format without evaluating it as code.

The future registry would live at `$XDG_STATE_HOME/sekretbarilo/known-values.v1`,
falling back to `$HOME/.local/state/sekretbarilo/known-values.v1`; roots must be
absolute, user-controlled and outside the workspace. It must never be discovered
by walking the workspace. Its HMAC key would live in a separate user-controlled
secret store, outside registry exports and backups.
Choose and verify the supported platform storage mechanism before implementation;
placing the key beside the registry does not satisfy registry-only leak protection.

System, parent-directory, project and committed repository TOML layers must not
add records, redirect storage, replace the key or disable this explicit protection.
Existing tracked-and-unchanged hook config trust is not authorization to maintain
a private credential registry. Even a user config layer should contain only the
explicit enablement setting, not values or digests. The private store requires
owner-only access and bounded, validated, atomic updates. A configured but
missing, corrupt, unreadable or mismatched registry/key must stop protected output;
absence before opt-in leaves current behavior unchanged. Failures must not print
paths, record contents or candidate snippets.

## interaction with existing surfaces

The first possible integration is additive on `redact-claude`'s currently visited
`Bash`, text `Read` and `Grep` fields. It must combine exact-match byte ranges with
existing scanner ranges, then perform one overlap merge and full `[REDACTED]`
replacement while preserving CR/LF and response structure. Existing detector
allowlists, entropy thresholds, public-key suppression and rule-class switches
must not cancel an explicit registration. Removing a registration is the explicit
way to stop its coverage; ordinary detectors still run afterwards.

There is no automatic extension to `scan`, `audit`, history, `check-file` or Codex
PreToolUse through a shared scanner helper. Codex PostToolUse is a separate gate:
it currently handles a Bash string using a deny/reason contract, not Claude's
replacement envelope. Any later adoption must preserve that contract and state
its streaming and host fail-open limitations. Unknown metadata fields and non-text
Read variants do not become covered merely because this registry exists.

## evidence required to reopen

1. Demonstrate incremental recall on synthetic prefixless values and representative
   private output samples, without persisting candidates. Separate registered
   exact-byte coverage from unregistered and encoded-value gaps.
2. Settle and test the protected registration and separate key-storage mechanism
   on supported platforms, including restart, backup, rotation, deletion, corrupt
   state and unavailable-store behavior. Test registry-only disclosure separately
   from possession of both registry and key; do not claim protection against the
   latter or against local execution access.
3. Prototype bounded candidate discovery with generated values. Compare every
   matched span against an exhaustive exact-byte oracle, including adjacent and
   overlapping values, punctuation, Unicode boundaries, multiple fields and long
   repeated runs. Freeze resource limits and a latency target before the holdout
   run; report memory, candidate count, hashed bytes, p95 latency and how often
   ordinary output is withheld by the budget.
4. Before shipping, pass the normal deterministic gate, per-finding recall
   comparison and hook-envelope/failure tests. Verify no original bytes survive
   in supported fields on failure and no secret enters diagnostics. Obtain an
   independent security/design review of the complete implementation and a
   separate live contract check for each enabled host surface.

Until that evidence supports an amended decision, the existing opt-in heuristic
and signature/contextual rules remain the available coverage. This ADR makes no
new completeness claim for them.

## checked sources

Local source at `2c2f0ae`: `src/config/rules.toml`, `src/agent/redact.rs`,
`src/agent/codex.rs`, `src/config/discovery.rs` and `src/scanner/text.rs`.
External sources below were read on 2026-11-01; the redacted-cli reference pins the
version resolved by its then-current `latest` page. Privacy and cost conclusions
above are design analysis, not results from a shipped prototype.

[redacted]: https://docs.rs/crate/redacted-cli/1.1.0/source/docs/ARCHITECTURE.md
[password-storage]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[hmac]: https://www.rfc-editor.org/rfc/rfc2104.html
