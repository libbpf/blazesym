#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::backtrace::Backtrace;
use std::backtrace::BacktraceStatus;
use std::cell::Cell;
use std::hint::black_box;
use std::thread_local;

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

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}


/// Normalize addresses in the current process and print allocation
/// statistics.
#[test]
fn normalize_process() {
    let region = Region::new(&GLOBAL);

    let () = ENABLED.set(true);
    {
        let normalizer = Normalizer::builder().build();
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
    let () = ENABLED.set(false);

    // We can't make many assumptions about the allocations here,
    // because a lot of it is system dependent. E.g., more entries in
    // `/proc/<pid>/maps` likely means more allocations. Even the order
    // may have an influence, to the point that ASLR could change
    // results.
    let stats = region.change();
    println!("Stats: {stats:#?}");
}
