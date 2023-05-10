use std::path::Path;

use blazesym::c_api;
use blazesym::symbolize::Elf;
use blazesym::symbolize::Gsym;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Symbolize addresses in the current process.
fn symbolize_process() {
    let src = Source::Process(Process::new(Pid::Slf));
    let addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        symbolize_process as Addr,
        c_api::blaze_inspector_free as Addr,
    ];

    let symbolizer = Symbolizer::new();
    let results = symbolizer.symbolize(&src, &addrs).unwrap();
    assert_eq!(results.len(), addrs.len());
}

/// Symbolize an address in a DWARF file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_dwarf() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let src = Source::Elf(Elf::new(dwarf_vmlinux));
    let symbolizer = Symbolizer::new();

    let results = symbolizer
        .symbolize(&src, &[0xffffffff8110ecb0])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "abort_creds");
}

/// Symbolize an address in a GSYM file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_gsym() {
    let gsym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.gsym");
    let src = Source::Gsym(Gsym::new(gsym_vmlinux));
    let symbolizer = Symbolizer::new();

    let results = symbolizer
        .symbolize(&src, &[0xffffffff8110ecb0])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "abort_creds");
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    group.bench_function(stringify!(symbolize::symbolize_process), |b| {
        b.iter(symbolize_process)
    });
    if cfg!(feature = "generate-bench-files") {
        group.bench_function(stringify!(symbolize::symbolize_dwarf), |b| {
            b.iter(symbolize_dwarf)
        });
        group.bench_function(stringify!(symbolize::symbolize_gsym), |b| {
            b.iter(symbolize_gsym)
        });
    }
}
