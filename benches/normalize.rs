#![allow(clippy::fn_to_numeric_cast)]

use std::hint::black_box;

use blazesym::normalize::Normalizer;
use blazesym::Addr;

use criterion::measurement::Measurement;
use criterion::Bencher;
use criterion::BenchmarkGroup;


fn normalize_process_impl<M>(normalizer: &Normalizer, b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let mut addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        normalize_process::<M> as Addr,
        Normalizer::normalize_user_addrs_sorted as Addr,
    ];
    let () = addrs.sort();

    let () = b.iter(|| {
        let normalized = normalizer
            .normalize_user_addrs_sorted(black_box(0.into()), black_box(addrs.as_slice()))
            .unwrap();
        assert_eq!(normalized.meta.len(), 2);
        assert_eq!(normalized.outputs.len(), 5);
    });
}


/// Normalize addresses in the current process, and read build IDs as part of
/// the normalization.
fn normalize_process<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder().enable_build_ids(true).build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, but don't read build IDs.
fn normalize_process_no_build_ids<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder().enable_build_ids(false).build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, read and parse the
/// `/proc/self/maps` file only once, and don't read build IDs.
fn normalize_process_no_build_ids_cached<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_maps_caching(true)
        .enable_build_ids(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_sub_fn!(group, normalize_process);
    bench_sub_fn!(group, normalize_process_no_build_ids);
    bench_sub_fn!(group, normalize_process_no_build_ids_cached);
}
