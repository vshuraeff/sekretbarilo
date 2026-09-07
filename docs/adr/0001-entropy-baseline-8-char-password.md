# ADR 0001: entropy baseline for 8-character passwords

- status: accepted
- date: 2026-09-05
- scope: reference figures for entropy-gated detection; no rule or gate is changed

## context

The scanner scores candidate values with Shannon entropy over 256 byte bins, in bits per byte,
without length normalisation (`shannon_entropy` in `src/scanner/entropy.rs`). Two gates decide
whether an entropy-gated rule can fire at all:

- `MIN_ENTROPY_LENGTH = 20` bytes in `src/scanner/entropy.rs`. For rule `generic-high-entropy-value`
  the `is_entropy_value` guard in `src/scanner/engine.rs` skips shorter values before entropy is
  computed at all. The other rules carrying `entropy_threshold` take the opposite path through
  `passes_entropy_check`, which admits values shorter than the minimum without an entropy check;
- `entropy_threshold = 4.0` on rule `generic-high-entropy-value` in `src/config/rules.toml`.

Both numbers were chosen by judgement. Nothing recorded what the entropy of a short human-scale
password actually is, so there was no reference point for arguing about either gate. The question
put was narrow: what are the mean and the p99 empirical entropy of an 8-character password drawn
from mixed-case letters and digits?

### method

9999 samples per generator per length, two generators: pwgen 2.08 in secure mode (`-s`, captured
from a non-TTY) and a uniform draw from the 62-symbol alphabet A-Z, a-z, 0-9 backed by the OS
CSPRNG. Entropy computed with the scanner's own formula, 256 byte counts summed as `-p*log2(p)`,
bits per byte. Quantiles by nearest rank. The script is `measure_entropy.py`, kept outside the
repository together with its aggregate JSON output, which is the record for every figure below.

One property of the metric governs the whole result: for a value of length n <= 62 the maximum
attainable empirical entropy is log2(n), reached when every character is distinct, not log2(62).
An 8-character value cannot score above 3.0 bits/byte whatever alphabet it is drawn from.

## decision

The 8-character, 62-symbol password is adopted as the reference population for "minimum detectable
password", and its measured entropy is recorded here as the baseline for future threshold work.

| statistic | pwgen 2.08 `-s` | uniform 62-symbol draw |
| --- | --- | --- |
| samples | 9999 | 9999 |
| mean | 2.898164 | 2.890903 |
| median | 3.000000 | 3.000000 |
| p1 | 2.405639 | 2.405639 |
| p5 | 2.750000 | 2.500000 |
| p99 | 3.000000 | 3.000000 |
| min / max | 2.000000 / 3.000000 | 2.000000 / 3.000000 |
| ceiling, log2(8) | 3.000000 | 3.000000 |
| at the ceiling | 64.77% (6476) | 62.97% (6296) |
| strictly below p99 | 35.23% (3523) | 37.03% (3703) |

The uniform draw agrees with the analytic expectation for that same population, 2.889329, which is
the cross-check that both the sampling and the formula are sound.

This ADR records a baseline and nothing else. The runtime gates are unchanged: `MIN_ENTROPY_LENGTH`
stays 20 bytes and `entropy_threshold` for `generic-high-entropy-value` stays 4.0. An 8-character
value remains ineligible for the rule, because the length gate short-circuits before the threshold
is consulted, and this ADR does not make it eligible.

## consequences

Empirical entropy by length, pwgen 2.08 `-s`, 9999 samples per length:

| length (bytes) | mean | p1 | p99 | ceiling, log2(n) | below 4.0 |
| --- | --- | --- | --- | --- | --- |
| 8 | 2.898164 | 2.405639 | 3.000000 | 3.000000 | 100% |
| 12 | 3.417287 | 3.022055 | 3.584963 | 3.584963 | 100% |
| 16 | 3.769376 | 3.327820 | 4.000000 | 4.000000 | 87.82% |
| 20 | 4.035305 | 3.646439 | 4.321928 | 4.321928 | 34.34% |
| 32 | 4.546529 | 4.202820 | 4.812500 | 5.000000 | 0.01% |

- At the shortest eligible length the current threshold misses a measurable share of genuinely
  random passwords: 34.34% of 20-byte pwgen values score below 4.0 and so never produce a finding,
  against 0.01% at 32 bytes. That recall cost is now measured rather than assumed.
- p99 of the 8-character population equals the ceiling exactly and is degenerate as a statistic:
  64.77% of the samples already sit at 3.0, so the 99th percentile says only that the ceiling is
  reachable. Used as an accept-threshold it would reject the 35.23% of samples below it.
- Because the metric is bits per byte, any single threshold is implicitly length-dependent: the same
  4.0 that 20-byte values barely clear is trivial at 32 bytes. Threshold work that is not per-length
  will re-derive this asymmetry by accident.

## deferred

Lowering or length-scaling the gates so that short passwords become detectable is a product decision
and is deliberately not taken here. Its false-positive cost is measurable and large: at this length
entropy cannot separate a random password from an ordinary English word. `document` and `security`
are each 8 distinct letters and therefore score exactly 3.0 bits/byte, the same value as a random
8-character password at the ceiling. A lower gate would have to be paired with another signal -
dictionary, keyword context, the existing password heuristics - before it could be proposed. Note
that lowering `MIN_ENTROPY_LENGTH` would widen detection for `generic-high-entropy-value` but would
newly subject short matches of the other entropy-threshold rules to filtering they currently bypass.

## alternatives considered

- **adopt p99 (3.000) as a detection threshold for short values.** Rejected. p99 is an upper-tail
  statistic; as an accept-threshold it rejects roughly 35% of the very population it came from, and
  here it coincides with the ceiling, so it is a bound rather than a threshold.
- **calibrate per length on the lower tail (p1).** Not adopted; recorded as future work. p1 is the
  recall-oriented statistic - 2.405639 at 8 bytes, 3.646439 at 20 - and a per-length curve fitted to
  it would keep a stated share of random passwords detectable. It needs its own false-positive
  measurement against real source text first, which this measurement does not provide.
- **measure nothing and leave the gates unexplained.** Rejected: the next person asking why 4.0
  would have to repeat the experiment.

## references

- `shannon_entropy` and `MIN_ENTROPY_LENGTH` in `src/scanner/entropy.rs`; the `is_entropy_value`
  length gate in `src/scanner/engine.rs`.
- rule `generic-high-entropy-value` and its `entropy_threshold = 4.0` in `src/config/rules.toml`.
- pipeline step "Shannon Entropy Evaluation" in `docs/_pages/architecture.md`.
- measurement of 2026-09-05: `measure_entropy.py` and its aggregate JSON output, kept outside the
  repository; pwgen 2.08; 9999 samples per generator and length.
