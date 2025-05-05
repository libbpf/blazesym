use std::hint::black_box;

use blazesym::normalize::NormalizeOpts;
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
        libc::atexit as Addr,
        libc::chdir as Addr,
        libc::fopen as Addr,
        normalize_process_impl::<M> as Addr,
        Normalizer::normalize_user_addrs as Addr,
    ];
    let () = addrs.sort();
    let opts = NormalizeOpts {
        sorted_addrs: true,
        ..Default::default()
    };

    let () = b.iter(|| {
        let normalized = normalizer
            .normalize_user_addrs_opts(
                black_box(0.into()),
                black_box(addrs.as_slice()),
                black_box(&opts),
            )
            .unwrap();
        assert_eq!(normalized.meta.len(), 2);
        assert_eq!(normalized.outputs.len(), 5);
    });
}


/// Normalize addresses in the current process, and read build IDs as part of
/// the normalization.
fn normalize_process_uncached_build_ids_uncached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_build_ids(true)
        .enable_build_id_caching(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_uncached_build_ids_cached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_vma_caching(true)
        .enable_build_ids(true)
        .enable_build_id_caching(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_cached_build_ids_uncached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_build_ids(true)
        .enable_build_id_caching(true)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_cached_build_ids_cached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_vma_caching(true)
        .enable_build_ids(true)
        .enable_build_id_caching(true)
        .build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, but don't read build IDs.
fn normalize_process_no_build_ids_uncached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder().enable_build_ids(false).build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, read and parse the
/// `/proc/self/maps` file only once, and don't read build IDs.
fn normalize_process_no_build_ids_cached_vmas_maps<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_vma_caching(true)
        .enable_build_ids(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_uncached_build_ids_uncached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_build_ids(true)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_uncached_build_ids_cached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_vma_caching(true)
        .enable_build_ids(true)
        .enable_build_id_caching(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_cached_build_ids_uncached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_build_ids(true)
        .enable_build_id_caching(true)
        .build();
    normalize_process_impl(&normalizer, b)
}

fn normalize_process_cached_build_ids_cached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_vma_caching(true)
        .enable_build_ids(true)
        .enable_build_id_caching(true)
        .build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, but don't read build IDs.
fn normalize_process_no_build_ids_uncached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_build_ids(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

/// Normalize addresses in the current process, read and parse the
/// `/proc/self/maps` file only once, and don't read build IDs.
fn normalize_process_no_build_ids_cached_vmas_ioctl<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let normalizer = Normalizer::builder()
        .enable_procmap_query(true)
        .enable_vma_caching(true)
        .enable_build_ids(false)
        .build();
    normalize_process_impl(&normalizer, b)
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_sub_fn!(
        group,
        normalize_process_uncached_build_ids_uncached_vmas_maps
    );
    bench_sub_fn!(group, normalize_process_uncached_build_ids_cached_vmas_maps);
    bench_sub_fn!(group, normalize_process_cached_build_ids_uncached_vmas_maps);
    bench_sub_fn!(group, normalize_process_cached_build_ids_cached_vmas_maps);
    bench_sub_fn!(group, normalize_process_no_build_ids_uncached_vmas_maps);
    bench_sub_fn!(group, normalize_process_no_build_ids_cached_vmas_maps);

    if cfg!(has_procmap_query_ioctl) {
        bench_sub_fn!(
            group,
            normalize_process_uncached_build_ids_uncached_vmas_ioctl
        );
        bench_sub_fn!(
            group,
            normalize_process_uncached_build_ids_cached_vmas_ioctl
        );
        bench_sub_fn!(
            group,
            normalize_process_cached_build_ids_uncached_vmas_ioctl
        );
        bench_sub_fn!(group, normalize_process_cached_build_ids_cached_vmas_ioctl);
        bench_sub_fn!(group, normalize_process_no_build_ids_uncached_vmas_ioctl);
        bench_sub_fn!(group, normalize_process_no_build_ids_cached_vmas_ioctl);
    }
}
