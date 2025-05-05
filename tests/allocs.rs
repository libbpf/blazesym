//! Investigate allocation behavior of certain code paths.

#![allow(clippy::incompatible_msrv)]
#![cfg_attr(not(linux), allow(dead_code, unused_imports))]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::backtrace::Backtrace;
use std::backtrace::BacktraceStatus;
use std::cell::Cell;
use std::hint::black_box;
use std::thread_local;

use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::Addr;

use stats_alloc::Region;
use stats_alloc::StatsAlloc;

#[global_allocator]
static GLOBAL: StatsAlloc<TracingAlloc> = StatsAlloc::new(TracingAlloc);

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static TRACING: Cell<bool> = const { Cell::new(false) };
}


/// An allocator that prints a backtrace for each allocation being made.
struct TracingAlloc;

unsafe impl GlobalAlloc for TracingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            // Capturing a backtrace will allocate itself. Prevent infinite
            // recursion with a flag.
            if ENABLED.get() && !TRACING.with(|tracing| tracing.replace(true)) {
                let bt = Backtrace::capture();
                if let BacktraceStatus::Captured = bt.status() {
                    println!("{layout:?}:\n{bt}");
                }
                let () = TRACING.with(|tracing| tracing.set(false));
            }
            System.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
    }
}


/// Normalize addresses in the current process and print allocation
/// statistics.
#[cfg(linux)]
#[test]
fn normalize_process() {
    let region = Region::new(&GLOBAL);

    let () = ENABLED.set(true);
    {
        let normalizer = Normalizer::builder().build();
        let mut addrs = [
            libc::atexit as Addr,
            libc::chdir as Addr,
            libc::fopen as Addr,
            normalize_process as Addr,
            Normalizer::normalize_user_addrs as Addr,
        ];
        let () = addrs.sort();

        let opts = NormalizeOpts {
            sorted_addrs: true,
            ..Default::default()
        };
        let normalized = normalizer
            .normalize_user_addrs_opts(
                black_box(0.into()),
                black_box(addrs.as_slice()),
                black_box(&opts),
            )
            .unwrap();
        assert_eq!(normalized.meta.len(), 2);
        assert_eq!(normalized.outputs.len(), 5);
    }
    let () = ENABLED.set(false);

    // We can't make many assumptions about the allocations here,
    // because a lot of it is system dependent. E.g., more entries in
    // `/proc/<pid>/maps` likely means more allocations. Even the order
    // may have an influence, to the point that ASLR could change
    // results.
    let stats = region.change();
    println!("Stats: {stats:#?}");
}
