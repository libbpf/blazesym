#![allow(clippy::fn_to_numeric_cast)]

use std::hint::black_box;

use blazesym::normalize::Normalizer;
use blazesym::Addr;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


fn normalize_process_impl(read_build_ids: bool) {
    let mut addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        normalize_process as Addr,
        Normalizer::normalize_user_addrs_sorted as Addr,
    ];
    let () = addrs.sort();

    let normalizer = Normalizer::builder()
        .enable_build_ids(read_build_ids)
        .build();
    let normalized = normalizer
        .normalize_user_addrs_sorted(black_box(0.into()), black_box(addrs.as_slice()))
        .unwrap();
    assert_eq!(normalized.meta.len(), 2);
    assert_eq!(normalized.outputs.len(), 5);
}


/// Normalize addresses in the current process, and read build IDs as part of
/// the normalization.
fn normalize_process() {
    normalize_process_impl(true)
}

/// Normalize addresses in the current process, but don't read build IDs.
fn normalize_process_no_build_ids() {
    normalize_process_impl(false)
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_fn!(group, normalize_process);
    bench_fn!(group, normalize_process_no_build_ids);
}
