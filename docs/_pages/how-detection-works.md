---
title: How secret detection works
description: Why detection is split into three tiers, what entropy can and cannot decide, and where the design accepts noise or blindness on purpose.
section: explanation
---

## The problem with one rule

A secret has no intrinsic marker. `AKIA` followed by sixteen key characters is an AWS access key and almost nothing else, but a forty-character base64 string might be a session token, a build checksum, or a public key fingerprint, and no amount of pattern matching separates them with certainty. Detection is therefore not one question but two: recognising credentials whose shape is known, and guessing about values whose shape is not.

Trying to answer both with one mechanism produces either a scanner that misses everything unbranded, or one that flags every hash in the repository. sekretbarilo splits the problem into three tiers of decreasing certainty and gives each its own tolerance for noise.

## Three tiers

**Tier 1 rules match a distinctive prefix.** Seventy-five of them, each tied to one service. They need no surrounding context and no entropy check, because the prefix already carries the meaning. Their false-positive rate is close to zero, so they get the benefit of the doubt: a string matching `AKIA` plus sixteen key characters is treated as an AWS key whatever else is on the line, and the general stopword list does not reach them. Only a placeholder shape such as a run of `XXXX` is filtered.

**Tier 2 rules need context.** Thirty-two of them, keyed to a nearby word — `password=`, `postgres://`, `api_secret` — and usually gated by an entropy threshold as well. Here the keyword carries some of the evidence and the value carries the rest, so full stopword filtering applies. The password rules replace entropy with a strength heuristic, since a password's randomness is not what makes it a password.

**Tier 3 rules match the value alone.** Three of them, at the highest threshold. Two are still keyword-oriented, covering names such as `api_key` and `auth_token`. The third, `generic-high-entropy-value`, has no keywords at all: it judges a value by its shape and its entropy and ignores the name it is assigned to.

That last rule is where the design accepts noise deliberately. It has no exemption for `PATH`, `LS_COLORS`, `TERM_SESSION_ID` or any other familiar name, because a name-based exemption list is exactly what an attacker, or a careless variable name, would slip through. What it does have is an exemption layer that judges the value's own bytes, described below. The cost that remains is that checksums, base64 blobs and cache keys are sometimes reported. The judgement is that a scanner which explains one extra finding is better than one that misses a token because it was assigned to a name nobody thought of.

## Why the pre-filter comes first

Evaluating a hundred and ten regexes against every line of every file would be slow enough to change how people use the tool, and a pre-commit hook that people disable protects nothing.

So the keywords of every rule are compiled into a single Aho-Corasick automaton, case-insensitive, and each line is passed through it once. That pass reports which keywords occur, and only the rules owning those keywords have their regex evaluated. A line with no keyword at all costs one automaton pass and nothing more, which is the common case in source code. The work is proportional to the interesting lines rather than to the file.

Rules with no keywords, tier 3's entropy rule among them, sit outside that shortcut by construction: there is nothing to pre-filter on, so their cost is paid on every candidate value.

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

The keywordless rule runs a sequence of predicates over the bytes of the candidate value, switched by `[settings] exemption_layer` and on by default. Eight steps, evaluated in order, and the first that matches suppresses the finding: **file** (an ignore file or `CODEOWNERS` disables this rule alone there), **import**, **markdown** (a link is retargeted to its target and evaluation continues on that), **path**, **pin** (a digest pinned behind a reference), **url** (no credential in any component), **syntax** (a complete source expression covering the flagged range), **wordshape** (words, camel case or snake case rather than an opaque run). None of them consults the assignment key, so the argument of the previous section still holds: naming a variable well does not silence anything.

The layer changes which values are considered, never the gates they are measured against. Twenty bytes and 4.0 bits per byte are the same in both modes, and tier 1 and tier 2 rules never enter it.

Two parts of it move in the other direction. Quoted call-argument bodies are collected as candidates as well, so a token handed to a function is examined at all; and an exact-length hex value of 32, 40 or 64 digits, assigned under a key that is not id-, hash- or address-shaped, skips the entropy gate — the one place the layer makes the rule stricter rather than quieter, and it still defers to a hash context word on the line.

`--trace-exemptions`, accepted on `scan` and `audit` and on no hook surface, reports each decision as a pseudo-finding named `exempt:` plus the step that made it:

```
  file: src/config/discovery.rs
  line: 118
  rule: exempt:path
  match: cr*****ml
```

An absent decision says the value never reached that gate. While the flag is on, those pseudo-findings count towards the exit code, so a before-and-after comparison is measured without it.

Turning the layer off restores the 0.6.x behaviour of this one rule, and of nothing else. The reasoning, the measured effect and the shapes it still misses are in [ADR 0002](https://github.com/{{ site.repository }}/blob/master/docs/adr/0002-tier3-exemption-layer.md).

## Two decisions that look arbitrary

**Findings show two characters at each end.** Enough to recognise which value was found, in a file with several, and to match it against the credential you are looking at. Not enough to reconstruct it from a log or a screen recording. Values shorter than six characters are replaced entirely, since two-plus-two of a five-character string is most of it. Redaction for an agent takes the opposite decision and keeps nothing, because its reader is a model that does not need to recognise anything.

**`.env` files are blocked without being read.** The check runs on the filename, before any configuration is loaded, and nothing in an allowlist can override it. That is unusual for a rule-based scanner, and it is on purpose: a file whose entire reason for existing is to hold credentials does not need its contents inspected, and the check must not depend on configuration an agent could have written. Templates named `.env.example`, `.env.sample` and `.env.template` are the exception, since their purpose is to be committed.

## What this design does not do

It does not find secrets it has no rule for, and no scanner does. It does not distinguish a live credential from a revoked one. It does not reach short credentials, for the reasons above. It reports checksums as findings from time to time and expects you to allowlist them.

What it does offer is a predictable failure direction: when the scanner is unsure, it reports. Every stage of it — the fail-closed exit codes of the agent hooks, the whole-layer rejection of untrusted configuration, the unconditional `.env` block — resolves ambiguity towards the noisy answer rather than the quiet one, on the grounds that a false positive costs a minute and a missed credential costs a rotation.

## Further reading

- [Rules reference]({{ '/rules-reference/' | relative_url }}) for every rule, its tier and its threshold.
- [Architecture]({{ '/architecture/' | relative_url }}) for the scan pipeline stage by stage.
- [Performance]({{ '/performance/' | relative_url }}) for what the pre-filter buys in measured terms.
- [Allowlist a confirmed false positive]({{ '/allowlist-a-false-positive/' | relative_url }}) for acting on the noise this design accepts.
- [Testing False Positives]({{ '/testing-false-positives/' | relative_url }}) for the fixture corpus that holds the exemption layer to its measured behaviour.
