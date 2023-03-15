mod dwarf;
mod gsym;

use std::time::Duration;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;


fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("dwarf");
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(5));
    group.confidence_level(0.98);
    group.significance_level(0.02);
    group.bench_function(stringify!(dwarf::lookup_end_to_end), |b| {
        b.iter(dwarf::lookup_end_to_end)
    });
    group.bench_function(stringify!(dwarf::symbolize_end_to_end), |b| {
        b.iter(dwarf::symbolize_end_to_end)
    });
    group.bench_function(stringify!(gsym::symbolize_end_to_end), |b| {
        b.iter(gsym::symbolize_end_to_end)
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
