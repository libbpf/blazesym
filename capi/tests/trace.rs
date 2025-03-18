//! Test capturing of trace information.
//!
//! Modifies global state; keep in separate test binary.

use std::ffi::c_char;
use std::ffi::CStr;
use std::sync::Mutex;

use blazesym::Addr;
use blazesym_c::blaze_err;
use blazesym_c::blaze_err_last;
use blazesym_c::blaze_symbolize_process_abs_addrs;
use blazesym_c::blaze_symbolize_src_process;
use blazesym_c::blaze_symbolizer_free;
use blazesym_c::blaze_symbolizer_new;
use blazesym_c::blaze_syms_free;
use blazesym_c::blaze_trace;
use blazesym_c::blaze_trace_lvl::*;


/// Check that we retrieve callbacks for traces being emitted.
#[test]
fn trace_callbacks() {
    static TRACES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    extern "C" fn trace_cb(msg: *const c_char) {
        let msg = unsafe { CStr::from_ptr(msg) };
        let msg = msg.to_string_lossy().to_string();
        let mut traces = TRACES.lock().unwrap();
        let () = traces.push(msg);
    }

    let () = blaze_trace(BLAZE_LVL_TRACE, trace_cb);
    assert_eq!(blaze_err_last(), blaze_err::OK);

    // Symbolize something, which should emit traces.
    {
        let process_src = blaze_symbolize_src_process {
            pid: 0,
            ..Default::default()
        };
        let symbolizer = blaze_symbolizer_new();
        let addrs = [0x0 as Addr];
        let result = unsafe {
            blaze_symbolize_process_abs_addrs(symbolizer, &process_src, addrs.as_ptr(), addrs.len())
        };
        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    let traces = TRACES.lock().unwrap();
    assert!(traces.len() > 0, "{traces:?}");

    let () = blaze_trace(BLAZE_LVL_TRACE, trace_cb);
    assert_eq!(blaze_err_last(), blaze_err::ALREADY_EXISTS);
}
