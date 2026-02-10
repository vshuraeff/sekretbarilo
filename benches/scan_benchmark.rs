use criterion::{criterion_group, criterion_main, Criterion};

fn bench_empty_scan(c: &mut Criterion) {
    c.bench_function("empty_scan", |b| {
        b.iter(|| {
            let files = sekretbarilo::diff::parser::parse_diff(b"");
            sekretbarilo::scanner::engine::scan(&files)
        })
    });
}

criterion_group!(benches, bench_empty_scan);
criterion_main!(benches);
