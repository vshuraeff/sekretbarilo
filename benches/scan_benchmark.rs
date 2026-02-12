use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use aho_corasick::AhoCorasick;
use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{parse_diff, AddedLine, DiffFile};
use sekretbarilo::scanner::engine::scan;
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

// -- helpers for generating synthetic diffs --

fn make_file(path: &str, lines: Vec<(usize, &[u8])>) -> DiffFile {
    DiffFile {
        path: path.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: lines
            .into_iter()
            .map(|(num, content)| AddedLine {
                line_number: num,
                content: content.to_vec(),
            })
            .collect(),
    }
}

fn generate_diff_bytes(num_files: usize, lines_per_file: usize) -> Vec<u8> {
    let mut diff = Vec::new();
    for i in 0..num_files {
        let filename = format!("src/file_{}.rs", i);
        diff.extend_from_slice(format!("diff --git a/{f} b/{f}\n", f = filename).as_bytes());
        diff.extend_from_slice(format!("--- a/{f}\n", f = filename).as_bytes());
        diff.extend_from_slice(format!("+++ b/{f}\n", f = filename).as_bytes());
        diff.extend_from_slice(format!("@@ -0,0 +1,{} @@\n", lines_per_file).as_bytes());
        for j in 0..lines_per_file {
            let line = match j % 5 {
                0 => format!("+let key_{j} = \"some_value_{j}\";\n"),
                1 => format!("+// comment line {j}\n"),
                2 => format!("+let config = load_config(\"{j}\");\n"),
                3 => format!("+println!(\"debug: {{}}\", value_{j});\n"),
                _ => format!("+let x_{j} = {j} * 2;\n"),
            };
            diff.extend_from_slice(line.as_bytes());
        }
    }
    diff
}

fn generate_files_with_secrets(num_files: usize, lines_per_file: usize) -> Vec<DiffFile> {
    (0..num_files)
        .map(|i| {
            let filename = format!("src/file_{}.rs", i);
            let lines: Vec<(usize, Vec<u8>)> = (1..=lines_per_file)
                .map(|j| {
                    let content = match j % 10 {
                        0 => format!("let key = \"AKIAIOSFODNN7ABCDE{:02}\"", i),
                        1 => format!(
                            "token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}bcdefghij\"",
                            (b'a' + (i as u8 % 26)) as char
                        ),
                        _ => format!("let x_{} = {} * 2;", j, j),
                    };
                    (j, content.into_bytes())
                })
                .collect();
            DiffFile {
                path: filename,
                is_new: false,
                is_deleted: false,
                is_renamed: false,
                is_binary: false,
                added_lines: lines
                    .into_iter()
                    .map(|(num, content)| AddedLine {
                        line_number: num,
                        content,
                    })
                    .collect(),
            }
        })
        .collect()
}

// -- benchmark: empty scan (baseline overhead) --

fn bench_empty_scan(c: &mut Criterion) {
    let scanner = compile_rules(&[]).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();

    c.bench_function("scan_empty_diff", |b| {
        b.iter(|| {
            let files = parse_diff(b"");
            scan(&files, &scanner, &allowlist)
        })
    });
}

// -- benchmark: small diff (1 file, 10 lines) --

fn bench_small_diff(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    let diff_bytes = generate_diff_bytes(1, 10);

    c.bench_function("scan_small_1file_10lines", |b| {
        b.iter(|| {
            let files = parse_diff(&diff_bytes);
            scan(&files, &scanner, &allowlist)
        })
    });
}

// -- benchmark: medium diff (10 files, 500 total lines) --

fn bench_medium_diff(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    let diff_bytes = generate_diff_bytes(10, 50);

    c.bench_function("scan_medium_10files_500lines", |b| {
        b.iter(|| {
            let files = parse_diff(&diff_bytes);
            scan(&files, &scanner, &allowlist)
        })
    });
}

// -- benchmark: large diff (100 files, 5000 lines) --

fn bench_large_diff(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    let diff_bytes = generate_diff_bytes(100, 50);

    c.bench_function("scan_large_100files_5000lines", |b| {
        b.iter(|| {
            let files = parse_diff(&diff_bytes);
            scan(&files, &scanner, &allowlist)
        })
    });
}

// -- benchmark: very large diff (1MB+ payload) --

fn bench_very_large_diff(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    // ~400 files x 100 lines = 40000 lines, generates a 1MB+ payload
    let diff_bytes = generate_diff_bytes(400, 100);
    assert!(
        diff_bytes.len() > 1_000_000,
        "very large diff should be 1MB+, got {} bytes",
        diff_bytes.len()
    );

    c.bench_function("scan_very_large_400files_40000lines", |b| {
        b.iter(|| {
            let files = parse_diff(&diff_bytes);
            scan(&files, &scanner, &allowlist)
        })
    });
}

// -- benchmark: scan with actual secrets (measures detection path) --

fn bench_scan_with_secrets(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();
    let files = generate_files_with_secrets(10, 50);

    c.bench_function("scan_with_secrets_10files", |b| {
        b.iter(|| scan(&files, &scanner, &allowlist))
    });
}

// -- benchmark: entropy calculation on various sizes --

fn bench_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");

    let short = b"aB3dEf7hIj1kLmN0pQr";
    let medium = b"aB3dEf7hIj1kLmN0pQrStUvWxYz0123456789ABCDEFGHIJKL";
    let long_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

    group.bench_with_input(
        BenchmarkId::new("short", 20),
        short.as_slice(),
        |b, data| b.iter(|| shannon_entropy(data)),
    );
    group.bench_with_input(
        BenchmarkId::new("medium", 50),
        medium.as_slice(),
        |b, data| b.iter(|| shannon_entropy(data)),
    );
    group.bench_with_input(
        BenchmarkId::new("long", 1000),
        long_data.as_slice(),
        |b, data| b.iter(|| shannon_entropy(data)),
    );

    group.finish();
}

// -- benchmark: aho-corasick pre-filter effectiveness --
// measures the cost of keyword pre-filtering vs lines that match nothing

fn bench_aho_corasick_prefilter(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();

    // file with no keywords matching any rule (should be very fast)
    let no_match_file = make_file(
        "clean.rs",
        (1..=100)
            .map(|i| (i, format!("let x_{} = {} * 2;", i, i)))
            .map(|(i, s)| (i, s.into_bytes()))
            .collect::<Vec<_>>()
            .iter()
            .map(|(i, s)| (*i, s.as_slice()))
            .collect(),
    );

    c.bench_function("prefilter_no_keywords_100lines", |b| {
        b.iter(|| scan(std::slice::from_ref(&no_match_file), &scanner, &allowlist))
    });
}

// -- benchmark: aho-corasick vs naive keyword matching --
// compares the aho-corasick automaton approach against naive str::contains per keyword

fn bench_aho_corasick_vs_naive(c: &mut Criterion) {
    let rules = load_default_rules().unwrap();
    // collect all unique keywords from all rules
    let keywords: Vec<String> = {
        let mut kws = Vec::new();
        for rule in &rules {
            for kw in &rule.keywords {
                let lower = kw.to_lowercase();
                if !kws.contains(&lower) {
                    kws.push(lower);
                }
            }
        }
        kws
    };

    let automaton = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&keywords)
        .unwrap();

    // generate test lines: mix of matching and non-matching
    let lines: Vec<Vec<u8>> = (0..1000)
        .map(|i| {
            match i % 10 {
                // ~10% of lines contain a keyword that might match
                0 => format!("let aws_key = \"AKIAIOSFODNN7ABCDEFG{:03}\";", i).into_bytes(),
                1 => format!("const token = \"ghp_abcdef{:04}\";", i).into_bytes(),
                2 => format!("password = \"s3cret_value_{:03}\";", i).into_bytes(),
                _ => format!("let x_{i} = compute_value({i}) + offset;").into_bytes(),
            }
        })
        .collect();

    let mut group = c.benchmark_group("keyword_matching");

    group.bench_function("aho_corasick", |b| {
        b.iter(|| {
            let mut match_count = 0usize;
            for line in &lines {
                if automaton.find(line).is_some() {
                    match_count += 1;
                }
            }
            match_count
        })
    });

    group.bench_function("naive_contains", |b| {
        b.iter(|| {
            let mut match_count = 0usize;
            for line in &lines {
                let line_lower: Vec<u8> = line.iter().map(|&b| b.to_ascii_lowercase()).collect();
                for kw in &keywords {
                    if line_lower.windows(kw.len()).any(|w| w == kw.as_bytes()) {
                        match_count += 1;
                        break;
                    }
                }
            }
            match_count
        })
    });

    group.finish();
}

// -- benchmark: diff parsing only --

fn bench_diff_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_parsing");

    let small = generate_diff_bytes(1, 10);
    let medium = generate_diff_bytes(10, 50);
    let large = generate_diff_bytes(100, 50);

    group.bench_with_input(BenchmarkId::new("small", "1x10"), &small, |b, diff| {
        b.iter(|| parse_diff(diff))
    });
    group.bench_with_input(BenchmarkId::new("medium", "10x50"), &medium, |b, diff| {
        b.iter(|| parse_diff(diff))
    });
    group.bench_with_input(BenchmarkId::new("large", "100x50"), &large, |b, diff| {
        b.iter(|| parse_diff(diff))
    });

    group.finish();
}

// -- benchmark: path allowlist checking --

fn bench_path_allowlist(c: &mut Criterion) {
    let allowlist = CompiledAllowlist::default_allowlist().unwrap();

    let paths = vec![
        "src/main.rs",
        "node_modules/lodash/index.js",
        "image.png",
        "package-lock.json",
        "src/deep/nested/module/config.rs",
    ];

    c.bench_function("path_allowlist_check", |b| {
        b.iter(|| {
            for path in &paths {
                let _ = allowlist.is_path_skipped(path);
            }
        })
    });
}

criterion_group!(
    benches,
    bench_empty_scan,
    bench_small_diff,
    bench_medium_diff,
    bench_large_diff,
    bench_very_large_diff,
    bench_scan_with_secrets,
    bench_entropy,
    bench_aho_corasick_prefilter,
    bench_aho_corasick_vs_naive,
    bench_diff_parsing,
    bench_path_allowlist,
);
criterion_main!(benches);
