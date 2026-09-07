---
layout: default
title: Performance
nav_order: 7
---

# Performance

sekretbarilo is a high-performance secret scanner written in Rust, designed to be fast enough for pre-commit hooks and AI agent workflows without slowing down developers.

## Performance Philosophy

Pre-commit hooks must be **imperceptible** or developers bypass them. sekretbarilo is architected to scan typical commits in microseconds, making it completely invisible in normal workflows.

- **Pre-commit hooks must be fast**: developers will skip hooks that add noticeable delay
- **Designed to be imperceptible**: the scan itself is microseconds; process startup dominates
- **Parallelized for large operations**: audit mode leverages all CPU cores with rayon
- **Early exit paths**: binary files, vendor directories, and lock files are filtered before scanning

## Benchmark Environment

Every figure on this page was measured with `cargo bench` (criterion) on macOS 15.7, Intel Core i9-9900K @ 3.60GHz, against the 112 built-in rules. Absolute numbers move with hardware, OS and rule count — the ratios are the durable part.

## Scan Mode Benchmarks

Scan mode is the core operation used by pre-commit hooks and agent hooks. These measure the in-process scan only, excluding process startup and `git diff` (see [End-to-End Latency](#end-to-end-latency) below):

| Scenario | Scale | Time |
|----------|-------|------|
| Empty diff | 0 lines | ~44 ns |
| Typical commit | 1 file, 10 lines | ~3.2 µs |
| Medium commit | 10 files, 500 lines | ~183 µs |
| With secrets | 10 files | ~230 µs |
| Large commit | 100 files, 5000 lines | ~765 µs |
| Very large commit | 400 files, 40000 lines | ~4.4 ms |

### What This Means

- **Typical workflow**: scanning a 1-10 file commit takes microseconds to a fraction of a millisecond
- **Large refactors**: even 100-file commits scan in under 1 millisecond
- **Massive changes**: 400-file diffs (40,000 lines) still scan in under 5 milliseconds
- **Secret detection**: finding and reporting actual secrets adds roughly 50 microseconds over the same clean diff

## End-to-End Latency

The benchmarks above are the scan itself. What a developer waits for is a whole process: spawn, config discovery, rule compilation, a `git diff` subprocess, then the scan. Measured as 50 sequential invocations of `sekretbarilo scan` against a one-file staged diff, on the machine described above:

| Component | Per invocation |
|-----------|----------------|
| Process spawn (`sekretbarilo --version` as a floor) | ~13 ms |
| `git diff --cached` subprocess | ~10 ms |
| Rule compilation (delta between `scan` and `scan --no-defaults`) | ~11 ms |
| **Whole `sekretbarilo scan` invocation** | **~53 ms** |

Two things follow. First, the ~50 ms is essentially fixed: it barely moves with commit size, because the size-dependent part is the microsecond-scale scan. Second, optimizing the scanner further would be pointless for pre-commit use — startup and `git` already account for almost all of it.

Process spawn cost in particular is OS-dependent and can be noticeably higher on macOS than on Linux for a locally built, unsigned binary.

## Diff Parsing Performance

Diff parsing extracts added lines from git diff output before scanning. This is a separate pipeline stage:

| Scale | Time |
|-------|------|
| 1 file, 10 lines | ~1.3 µs |
| 10 files, 50 lines each | ~39 µs |
| 100 files, 50 lines each | ~459 µs |

Parsing overhead is minimal compared to scanning, since the Aho-Corasick and regex stages dominate computation.

## Keyword Matching Performance

sekretbarilo uses Aho-Corasick automaton for keyword pre-filtering instead of naive string matching:

| Method | Time | Ratio |
|--------|------|-------|
| Aho-Corasick | ~100 µs | 1x (baseline) |
| Naive contains | ~12.4 ms | ~125x slower |

**Why this matters**: the naive approach checks every keyword against every line (O(keywords × lines)). Aho-Corasick builds a finite automaton that matches all keywords in a single pass (O(lines)).

With 112 built-in rules and hundreds of total keywords, this optimization is critical. Without it, scan performance would degrade from microseconds to milliseconds — and the gap widens with every rule added, since the naive cost grows with rule count while the automaton's does not.

## Key Optimizations

sekretbarilo achieves microsecond-scale scanning through several architectural optimizations:

### 1. Aho-Corasick Automaton

**What**: single-pass keyword matching across all 112 rules simultaneously

**Why**: instead of checking each rule's keywords against every line (O(rules × keywords × lines)), Aho-Corasick builds a finite automaton that matches all keywords in one pass (O(lines))

**Impact**: ~125x faster than the naive `contains()` approach

The automaton is compiled once at startup and reused across all files and lines.

### 2. Lazy Regex Evaluation

**What**: only rules whose keywords matched in the Aho-Corasick pass have their regexes evaluated

**Why**: most lines match zero keywords, so most regex checks are skipped entirely

**Impact**: a line matching no keyword never reaches a regex at all. Scanning 100 keyword-free lines costs ~8.6 µs — under 90 ns per line — because the work stops at the automaton.

This is a critical filter: regex matching is expensive relative to an automaton step, and in ordinary source code the overwhelming majority of lines contain nothing that looks like a credential keyword.

### 3. One-Time Compilation

**What**: regex patterns and Aho-Corasick automaton are compiled once at startup

**Why**: compilation is expensive; reuse amortizes the cost across all files and lines

**Impact**: avoids per-file or per-line recompilation overhead

For pre-commit hooks, the process lifetime is short (a single commit), so compilation is paid once and never amortized across runs — it is the ~11 ms line in the end-to-end table above. Compiling per file or per line instead would multiply that cost by the number of files.

### 4. Byte-Level Processing

**What**: works with `&[u8]` byte slices instead of `&str`

**Why**: avoids UTF-8 validation overhead on every line

**Impact**: no UTF-8 validation pass, and no allocation to convert a line before matching it

Secret patterns are ASCII-only (API keys, tokens), and diff output is byte-oriented. Byte slices let the scanner skip validation and work directly with raw bytes — which also means files that are not valid UTF-8 scan correctly instead of being skipped.

### 5. Parallel Processing (rayon)

**What**: audit mode processes files and commits in parallel across all CPU cores

**Why**: modern CPUs have 4-16+ cores; serial processing leaves them idle

**Impact**: work scales with available cores. Audit and history are I/O- and subprocess-bound rather than CPU-bound, so the real speedup lands below the core count — measure on your own repository rather than assuming a multiplier.

Parallel processing triggers when:
- **Scan mode**: 4+ files in a diff (`PARALLEL_FILE_THRESHOLD` in `src/scanner/engine.rs`)
- **Audit mode**: all files processed in parallel
- **History audit**: all commits processed in parallel

### 6. Early Exit Paths

**What**: binary files, allowlisted paths, vendor directories, and lock files are skipped before any scanning

**Why**: scanning binary or generated files wastes CPU cycles and produces false positives

**Impact**: skipped files are never read from disk, so they cost a path-pattern check (~1.1 µs) instead of a read plus a scan

Early exit filters (applied before keyword matching):
- Binary files (`.png`, `.jpg`, `.wasm`, etc.)
- Vendor directories (`node_modules/`, `vendor/`, `.venv/`)
- Lock files (`package-lock.json`, `Cargo.lock`, `poetry.lock`)
- Generated files (minified JS, source maps)

### 7. Branch Resolution Optimization

**What**: in history audit, branch resolution (`git branch --contains`) is only run for commits that actually have findings

**Why**: `git branch --contains` is expensive (O(branches × commits)); most commits have no findings

**Impact**: one `git branch --contains` subprocess per *finding-bearing* commit instead of one per commit — on a clean repository, none at all

This optimization is critical for large repositories with many branches. Without it, history audit would spend most of its time resolving branches for clean commits.

### 8. Deduplication

**What**: history audit deduplicates findings — same secret in same file keeps only the earliest introducing commit

**Why**: a secret introduced in commit A and present in commits B, C, D only needs to be reported once

**Impact**: a secret that survived N commits is reported once, not N times — which also removes N-1 branch-resolution subprocesses

Deduplication uses a hash map keyed by `(file_path, rule_id, matched_value)`. Only the earliest commit (by timestamp) is retained.

## Running Benchmarks

sekretbarilo uses [criterion](https://github.com/bheisler/criterion.rs) for statistical benchmarking with warmup, iterations, and confidence intervals.

```sh
cargo bench
```

Benchmark suite includes:
- **Scan performance**: empty, small, medium, large, very large diffs
- **Scan with secrets**: detection path overhead
- **Diff parsing**: parsing speed at different scales
- **Keyword matching**: Aho-Corasick vs naive comparison
- **Entropy calculation**: Shannon entropy on different string lengths
- **Prefilter**: cost of 100 lines that match no keyword at all
- **Path allowlist**: regex matching overhead

Criterion runs each benchmark multiple times, applies statistical analysis, and reports mean, median, and standard deviation. Results are saved to `target/criterion/` with HTML reports.

## Performance in Practice

### Pre-commit Hook

**Scenario**: developer commits 1-10 files with 10-500 lines changed

**Time**: ~50 ms of process, of which microseconds are scanning

**Experience**: not noticeable next to `git commit`'s own work

The installed hook does not pipe anything in — it invokes the binary, which runs `git diff` itself:
```sh
sekretbarilo scan
```

Where that ~50 ms goes is broken down in [End-to-End Latency](#end-to-end-latency). The practical consequence: commit latency is flat. A 1-file commit and a 100-file commit cost about the same, because the part that varies with commit size is under a millisecond.

### Working Tree Audit

**Scenario**: scan all tracked files in a repository

Audit mode enumerates tracked files with `git ls-files`, reads them in parallel with rayon, and feeds them through the same scanner engine:
```sh
sekretbarilo audit
```

Bottlenecks, in order:
- File I/O (reading from disk)
- Regex evaluation (for lines with keyword matches)
- Entropy calculation (for tier 2+ rules)

Runtime tracks file count, file sizes, filesystem speed and core count. No figure is published here because none of those are properties of sekretbarilo — time it on the repository you care about:
```sh
time sekretbarilo audit
```

### History Audit

**Scenario**: scan every commit in git history

```sh
sekretbarilo audit --history
```

This is the slowest mode by a wide margin, and the cost is mostly `git`: one `diff-tree` subprocess per commit, parallelized across cores. Progress is reported as commits are consumed.

Performance factors:
- **Commit count**: the dominant term — one `git diff-tree` per commit
- **Deduplication**: a long-lived secret is reported once, not once per commit that contains it
- **Branch resolution**: one extra subprocess per finding-bearing commit, none for clean ones
- **CPU cores**: commits are processed in parallel

On a large repository this can run for a long time. Narrow it with `--branch`, `--since` and `--until` rather than waiting out a full scan.

### Agent Hook Performance

**Scenario**: an AI agent is about to read a file (`check-file`) or write one (`check-codex`); sekretbarilo runs first

**Time**: dominated by the same fixed startup as `scan` — tens of milliseconds per tool call

**Experience**: not noticeable against model latency, which is orders of magnitude larger

`check-file` includes fast-path optimizations that apply before the file is read:
- **Binary files**: detected and skipped on the extension alone
- **Vendor directories**: skipped via path pattern matching
- **Lock files**: skipped via filename patterns
- **Full scan**: same performance as scan mode for individual files

Fast-path filters (applied before reading file content):
- `.png`, `.jpg`, `.gif`, `.wasm`, `.so`, etc. → skip
- `node_modules/`, `vendor/`, `.venv/`, `target/` → skip
- `package-lock.json`, `Cargo.lock`, `go.sum` → skip

`check-codex` never reads a file at all. It scans the tool payload the agent is about to execute — the added lines of an `apply_patch`, or a `Bash` command string — so its scanning cost is proportional to that payload, which is small.

**Timeout**: both hooks are installed with a 10-second timeout, far above what either needs.

## Performance Tuning

### Entropy Thresholds

Raising the entropy threshold (e.g. 4.0 instead of 3.5) reduces false positives. It does not meaningfully change scan time: the same number of entropy calculations run either way, only their verdict changes.

**Recommendation**: use default thresholds (3.5 for most rules) unless you have specific false positive issues.

### Custom Rules

Adding custom rules increases keyword matching and regex evaluation overhead. Keep keyword lists focused and regex patterns efficient.

**Impact**: each additional rule adds:
- Keywords to Aho-Corasick automaton (minimal overhead)
- Regex evaluation for matching lines (measurable overhead if keywords are common)

### Parallel Thresholds

The `PARALLEL_FILE_THRESHOLD` constant (default: 4 files) controls when rayon parallel processing activates. Lower values increase parallelism but add thread spawn overhead.

**Default**: 4 files (optimal for most workflows)
**Tuning**: modify `src/scanner/engine.rs` constant and recompile

## Comparison to Other Tools

No cross-tool benchmarks are published here. Comparing secret scanners fairly requires running them over the same corpus with comparable rule sets on the same machine, and numbers quoted without that setup are not meaningful.

What is structural rather than measured:

- **Compiled, no runtime**: sekretbarilo is a single native binary with no interpreter or VM to start, which matters most for the short-lived, once-per-commit invocations a pre-commit hook makes.
- **Keyword pre-filter**: rules are gated behind one Aho-Corasick pass, so adding rules costs automaton states rather than another regex over every line.
- **Parallel by default**: audit and history work is spread across cores without configuration.

If you need a comparison for a decision, benchmark the candidates on your own repository.

## Future Optimizations

Potential areas for further performance improvements:

1. **SIMD acceleration**: use SIMD instructions for entropy calculation and byte matching
2. **Memory-mapped files**: avoid read() syscalls for large files
3. **Incremental scanning**: cache results for unchanged files (audit mode)

None of these are priorities. The scan itself is already microseconds; the wall clock a developer feels is process startup and `git` subprocesses, which no amount of scanner optimization would touch.
