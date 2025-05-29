use std::hint::black_box;
use std::ptr;

use blazesym::Addr;

use blazesym_c::blaze_normalize_opts;
use blazesym_c::blaze_normalize_user_addrs_opts;
use blazesym_c::blaze_normalizer_free;
use blazesym_c::blaze_normalizer_new_opts;
use blazesym_c::blaze_normalizer_opts;
use blazesym_c::blaze_user_output_free;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


fn normalize_process_impl(read_build_ids: bool) {
    let mut addrs = [
        libc::atexit as Addr,
        libc::chdir as Addr,
        libc::fopen as Addr,
        blaze_normalizer_new_opts as Addr,
        blaze_normalize_user_addrs_opts as Addr,
    ];
    let () = addrs.sort();

    let opts = blaze_normalizer_opts {
        build_ids: read_build_ids,
        ..Default::default()
    };
    let normalizer = unsafe { blaze_normalizer_new_opts(&opts) };
    assert_ne!(normalizer, ptr::null_mut());

    let opts = blaze_normalize_opts {
        sorted_addrs: true,
        ..Default::default()
    };
    let pid = 0;
    let result = unsafe {
        blaze_normalize_user_addrs_opts(
            normalizer,
            black_box(pid),
            black_box(addrs.as_slice().as_ptr()),
            black_box(addrs.len()),
            black_box(&opts),
        )
    };
    assert_ne!(result, ptr::null_mut());

    let normalized = unsafe { &*result };
    assert_eq!(normalized.meta_cnt, 2);
    assert_eq!(normalized.output_cnt, 5);

    let () = unsafe { blaze_user_output_free(result) };
    let () = unsafe { blaze_normalizer_free(normalizer) };
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
