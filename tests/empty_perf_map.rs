#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::fs::remove_file;
use std::fs::File;
use std::process;

use scopeguard::defer;

use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;


/// Make sure that we do not fail symbolization when an empty perf
/// map is present.
#[test]
fn symbolize_with_empty_perf_map() {
    let heap = vec![0; 4096];
    let path = format!("/tmp/perf-{}.map", process::id());
    let _file = File::options()
        .create_new(true)
        .write(true)
        .read(true)
        .open(&path)
        .unwrap();
    defer!({
        let _result = remove_file(&path);
    });

    let src = Source::Process(Process::new(Pid::Slf));
    // We attempt symbolization of an address inside the heap, whose
    // corresponding proc maps entry is likely "unnamed". That
    // should trigger the perf map symbolization path, and the perf
    // map that we created above is empty.
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, Input::AbsAddr(heap.as_slice().as_ptr() as Addr))
        .unwrap();
    assert!(matches!(result, Symbolized::Unknown(..)));
}
