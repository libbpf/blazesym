mod dwarf;
mod gsym;
mod normalize;
mod symbolize;

use std::time::Duration;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;


fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("main");
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(5));
    group.confidence_level(0.98);
    group.significance_level(0.02);
    dwarf::benchmark(&mut group);
    gsym::benchmark(&mut group);
    normalize::benchmark(&mut group);
    symbolize::benchmark(&mut group);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
