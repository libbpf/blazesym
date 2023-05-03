use blazesym::c_api;
use blazesym::symbolize::cfg;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Symbolize addresses in the current process.
fn symbolize_process() {
    let src = Source::Process(cfg::Process { pid: Pid::Slf });
    let addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        symbolize_process as Addr,
        c_api::blaze_inspector_free as Addr,
    ];

    let symbolizer = Symbolizer::new().unwrap();
    let results = symbolizer.symbolize(&src, &addrs).unwrap();
    assert_eq!(results.len(), addrs.len());
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    group.bench_function(stringify!(symbolize::symbolize_process), |b| {
        b.iter(symbolize_process)
    });
}
