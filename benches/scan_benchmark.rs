use criterion::{criterion_group, criterion_main, Criterion};

fn bench_empty_scan(c: &mut Criterion) {
    // compile an empty rule set for baseline measurement
    let scanner = sekretbarilo::scanner::rules::compile_rules(&[]).unwrap();
    let allowlist = sekretbarilo::config::allowlist::CompiledAllowlist::default_allowlist().unwrap();

    c.bench_function("empty_scan", |b| {
        b.iter(|| {
            let files = sekretbarilo::diff::parser::parse_diff(b"");
            sekretbarilo::scanner::engine::scan(&files, &scanner, &allowlist)
        })
    });
}

criterion_group!(benches, bench_empty_scan);
criterion_main!(benches);
