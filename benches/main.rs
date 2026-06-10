//! Benchmarks for `blazesym`.

#![allow(missing_docs)]

macro_rules! bench_fn {
    ($group:expr, $bench_fn:ident) => {
        $group.bench_function(crate::bench_fn_name(stringify!($bench_fn)), |b| {
            b.iter($bench_fn)
        });
    };
}

macro_rules! bench_sub_fn {
    ($group:expr, $bench_fn:ident) => {
        $group.bench_function(crate::bench_fn_name(stringify!($bench_fn)), $bench_fn);
    };
}


mod inspect;
mod normalize;
mod symbolize;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::measurement::Measurement;
use criterion::Criterion;


const BENCH_NAME_WIDTH: usize = 56;


fn bench_fn_name(name: &str) -> String {
    format!("{name:<BENCH_NAME_WIDTH$}")
}


fn benchmark<M>(c: &mut Criterion<M>)
where
    M: Measurement,
{
    let mut group = c.benchmark_group("main");
    group.confidence_level(0.98);
    group.significance_level(0.02);
    inspect::benchmark(&mut group);
    normalize::benchmark(&mut group);
    symbolize::benchmark(&mut group);
}

criterion_group!(
    name = benches;
    config = blazesym_dev::criterion_config();
    targets = benchmark
);
criterion_main!(benches);
