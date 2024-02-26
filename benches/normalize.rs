#![allow(clippy::fn_to_numeric_cast)]

use std::hint::black_box;

use blazesym::normalize::Normalizer;
use blazesym::Addr;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


fn normalize_process_impl(normalizer: &Normalizer) {
    let mut addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        normalize_process as Addr,
        Normalizer::normalize_user_addrs_sorted as Addr,
    ];
    let () = addrs.sort();

    let normalized = normalizer
        .normalize_user_addrs_sorted(black_box(0.into()), black_box(addrs.as_slice()))
        .unwrap();
    assert_eq!(normalized.meta.len(), 2);
    assert_eq!(normalized.outputs.len(), 5);
}


/// Normalize addresses in the current process, and read build IDs as part of
/// the normalization.
fn normalize_process() {
    let normalizer = Normalizer::builder().enable_build_ids(true).build();
    normalize_process_impl(&normalizer)
}

/// Normalize addresses in the current process, but don't read build IDs.
fn normalize_process_no_build_ids() {
    let normalizer = Normalizer::builder().enable_build_ids(false).build();
    normalize_process_impl(&normalizer)
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_fn!(group, normalize_process);
    bench_fn!(group, normalize_process_no_build_ids);
}
