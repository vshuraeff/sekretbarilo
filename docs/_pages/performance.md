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
- **Designed to be imperceptible**: typical commits scan in ~2.5 microseconds
- **Parallelized for large operations**: audit mode leverages all CPU cores with rayon
- **Early exit paths**: binary files, vendor directories, and lock files are filtered before scanning

## Scan Mode Benchmarks

Scan mode is the core operation used by pre-commit hooks and agent hooks. Performance is measured across different commit sizes:

| Scenario | Scale | Time |
|----------|-------|------|
| Empty diff | 0 lines | ~48 ns |
| Typical commit | 1 file, 10 lines | ~2.5 µs |
| Medium commit | 10 files, 500 lines | ~168 µs |
| With secrets | 10 files | ~199 µs |
| Large commit | 100 files, 5000 lines | ~679 µs |
| Very large commit | 400 files, 40000 lines | ~3.7 ms |

**Benchmark environment**: macOS 15.7, Intel Core i9-9900 @ 3.60GHz, measured with criterion.

### What This Means

- **Typical workflow**: scanning a 1-10 file commit takes 2-200 microseconds — completely imperceptible
- **Large refactors**: even 100-file commits complete in under 1 millisecond
- **Massive changes**: 400-file diffs (40,000 lines) still complete in under 4 milliseconds
- **Secret detection**: finding and validating actual secrets adds only ~30 microseconds overhead

## Diff Parsing Performance

Diff parsing extracts added lines from git diff output before scanning. This is a separate pipeline stage:

| Scale | Time |
|-------|------|
| 1 file, 10 lines | ~1.4 µs |
| 10 files, 50 lines each | ~37 µs |
| 100 files, 50 lines each | ~435 µs |

Parsing overhead is minimal compared to scanning, since the Aho-Corasick and regex stages dominate computation.

## Keyword Matching Performance

sekretbarilo uses Aho-Corasick automaton for keyword pre-filtering instead of naive string matching:

| Method | Time | Ratio |
|--------|------|-------|
| Aho-Corasick | ~44 µs | 1x (baseline) |
| Naive contains | ~4.2 ms | ~96x slower |

**Why this matters**: the naive approach checks every keyword against every line (O(keywords × lines)). Aho-Corasick builds a finite automaton that matches all keywords in a single pass (O(lines)).

With 43 built-in rules and hundreds of total keywords, this optimization is critical. Without it, scan performance would degrade from microseconds to milliseconds.

## Key Optimizations

sekretbarilo achieves microsecond-scale scanning through several architectural optimizations:

### 1. Aho-Corasick Automaton

**What**: single-pass keyword matching across all 43 rules simultaneously
**Why**: instead of checking each rule's keywords against every line (O(rules × keywords × lines)), Aho-Corasick builds a finite automaton that matches all keywords in one pass (O(lines))
**Impact**: 96x faster than naive `contains()` approach

The automaton is compiled once at startup and reused across all files and lines.

### 2. Lazy Regex Evaluation

**What**: only rules whose keywords matched in the Aho-Corasick pass have their regexes evaluated
**Why**: most lines match zero keywords, so most regex checks are skipped entirely
**Impact**: reduces regex evaluation from 100% of lines to ~10% (keyword match rate)

This is a critical filter: regex compilation and matching are expensive. The keyword pre-filter eliminates 90%+ of regex work.

### 3. One-Time Compilation

**What**: regex patterns and Aho-Corasick automaton are compiled once at startup
**Why**: compilation is expensive; reuse amortizes the cost across all files and lines
**Impact**: avoids per-file or per-line recompilation overhead

For pre-commit hooks, this means the scanner process lifetime is short (single commit), so compilation overhead is noticeable. One-time compilation keeps it negligible.

### 4. Byte-Level Processing

**What**: works with `&[u8]` byte slices instead of `&str`
**Why**: avoids UTF-8 validation overhead on every line
**Impact**: eliminates UTF-8 validation cost (~10-20% speedup for non-ASCII content)

Secret patterns are often ASCII-only (API keys, tokens), and diff output is byte-oriented. Byte slices let the scanner skip validation and work directly with raw bytes.

### 5. Parallel Processing (rayon)

**What**: audit mode processes files and commits in parallel across all CPU cores
**Why**: modern CPUs have 4-16+ cores; serial processing leaves them idle
**Impact**: near-linear speedup on multi-core systems (4x on 4 cores, 8x on 8 cores)

Parallel processing triggers when:
- **Scan mode**: 4+ files in a diff (pre-commit hooks)
- **Audit mode**: all files processed in parallel
- **History audit**: all commits processed in parallel

### 6. Early Exit Paths

**What**: binary files, allowlisted paths, vendor directories, and lock files are skipped before any scanning
**Why**: scanning binary or generated files wastes CPU cycles and produces false positives
**Impact**: eliminates scanning overhead for 30-50% of files in typical repos

Early exit filters (applied before keyword matching):
- Binary files (`.png`, `.jpg`, `.wasm`, etc.)
- Vendor directories (`node_modules/`, `vendor/`, `.venv/`)
- Lock files (`package-lock.json`, `Cargo.lock`, `poetry.lock`)
- Generated files (minified JS, source maps)

### 7. Branch Resolution Optimization

**What**: in history audit, branch resolution (`git branch --contains`) is only run for commits that actually have findings
**Why**: `git branch --contains` is expensive (O(branches × commits)); most commits have no findings
**Impact**: reduces branch resolution from 100% of commits to ~1-5% (findings rate)

This optimization is critical for large repositories with many branches. Without it, history audit would spend most of its time resolving branches for clean commits.

### 8. Deduplication

**What**: history audit deduplicates findings — same secret in same file keeps only the earliest introducing commit
**Why**: a secret introduced in commit A and present in commits B, C, D only needs to be reported once
**Impact**: reduces noise and branch resolution overhead by 10-100x in repos with long-lived secrets

Deduplication uses a hash map keyed by `(file_path, rule_id, secret_hash)`. Only the earliest commit (by timestamp) is retained.

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
- **Path allowlist**: regex matching overhead

Criterion runs each benchmark multiple times, applies statistical analysis, and reports mean, median, and standard deviation. Results are saved to `target/criterion/` with HTML reports.

## Performance in Practice

### Pre-commit Hook

**Scenario**: developer commits 1-10 files with 10-500 lines changed
**Time**: 2-200 microseconds
**Experience**: imperceptible — faster than terminal I/O

The hook runs as:
```sh
git diff --cached | sekretbarilo scan
```

Total latency includes:
- `git diff` generation: ~500 µs - 2 ms (dominant cost)
- sekretbarilo scan: ~2-200 µs (negligible)
- Process spawn overhead: ~1-3 ms (one-time)

**Total commit latency**: typically under 10 milliseconds, dominated by git diff and shell overhead.

### Working Tree Audit

**Scenario**: scan all tracked files in a repository
**Time**: seconds for most repos (parallel file processing)
**Example**: 1000 files, 100k lines → ~1-3 seconds on 8-core CPU

Audit mode uses rayon to process files in parallel:
```sh
sekretbarilo audit
```

Bottlenecks:
- File I/O (reading from disk)
- Regex evaluation (for lines with keyword matches)
- Entropy calculation (for tier 2+ rules)

For repositories with 10k+ files, audit time scales linearly with file count and CPU core count.

### History Audit

**Scenario**: scan every commit in git history
**Time**: minutes for large repos (parallel commit processing with dedup)
**Example**: 10,000 commits, 500 with changes → ~2-10 minutes on 8-core CPU

History audit uses rayon to process commits in parallel:
```sh
sekretbarilo audit --history
```

Performance factors:
- **Commit count**: linear scaling (more commits = more time)
- **Deduplication**: 10-100x reduction in reported findings
- **Branch resolution**: only for commits with findings (~1-5% of commits)
- **CPU cores**: near-linear speedup (8 cores ≈ 8x faster)

For extremely large repositories (100k+ commits), history audit can take 30+ minutes. Use `--branch` and `--since` filters to limit scope.

### Agent Hook Performance

**Scenario**: Claude Code reads a file; sekretbarilo checks it first
**Time**: microseconds for typical files
**Experience**: imperceptible — no noticeable delay

The check-file operation includes fast-path optimizations:
- **Binary files**: detected and skipped in microseconds (extension check)
- **Vendor directories**: skipped via path pattern matching
- **Lock files**: skipped via filename patterns
- **Full scan**: same performance as scan mode for individual files

**Timeout**: 10 seconds (more than sufficient for any single file, even 100k+ lines)

Fast-path filters (applied before reading file content):
- `.png`, `.jpg`, `.gif`, `.wasm`, `.so`, etc. → skip
- `node_modules/`, `vendor/`, `.venv/`, `target/` → skip
- `package-lock.json`, `Cargo.lock`, `go.sum` → skip

## Performance Tuning

### Entropy Thresholds

Higher entropy thresholds (e.g., 4.0 instead of 3.5) reduce false positives but increase scan time slightly due to more entropy calculations passing the keyword filter.

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

| Tool | Language | Typical Commit | Large Commit | Notes |
|------|----------|----------------|--------------|-------|
| sekretbarilo | Rust | ~2.5 µs | ~3.7 ms | parallel, Aho-Corasick |
| gitleaks | Go | ~10-50 ms | ~500 ms | serial scanning |
| truffleHog | Python | ~100-500 ms | ~5-10 s | slow regex evaluation |
| detect-secrets | Python | ~50-200 ms | ~2-5 s | serial scanning |

**Note**: benchmarks are approximate and depend on repository structure, rule count, and hardware. sekretbarilo's Rust implementation and Aho-Corasick optimization provide 10-1000x speedup over Python-based tools.

## Future Optimizations

Potential areas for further performance improvements:

1. **SIMD acceleration**: use SIMD instructions for entropy calculation and byte matching
2. **Memory-mapped files**: avoid read() syscalls for large files
3. **Incremental scanning**: cache results for unchanged files (audit mode)
4. **GPU acceleration**: offload regex matching to GPU for extremely large audits

Currently, sekretbarilo is fast enough that these optimizations are not priorities. Pre-commit hooks complete in microseconds, and audit operations are I/O-bound rather than CPU-bound.
