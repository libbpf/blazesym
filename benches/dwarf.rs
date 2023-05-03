use std::path::Path;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::symbolize::SymbolizerFeature;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Symbolize an address, end-to-end, i.e., including all necessary setup.
fn symbolize_end_to_end() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let features = [
        SymbolizerFeature::DebugInfoSymbols(true),
        SymbolizerFeature::LineNumberInfo(true),
    ];
    let src = Source::Elf(Elf {
        file_name: dwarf_vmlinux,
        base_address: 0,
    });
    let symbolizer = Symbolizer::with_opts(&features).unwrap();

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

/// Lookup an address, end-to-end, i.e., including all necessary setup.
fn lookup_end_to_end() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let features = [
        SymbolizerFeature::DebugInfoSymbols(true),
        SymbolizerFeature::LineNumberInfo(true),
    ];
    let src = Source::Elf(Elf {
        file_name: dwarf_vmlinux,
        base_address: 0,
    });

    let symbolizer = Symbolizer::with_opts(&features).unwrap();
    let results = symbolizer
        .find_addrs(&src, &["abort_creds"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.address, 0xffffffff8110ecb0);
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    if cfg!(feature = "generate-bench-files") {
        group.bench_function(stringify!(dwarf::lookup_end_to_end), |b| {
            b.iter(lookup_end_to_end)
        });
        group.bench_function(stringify!(dwarf::symbolize_end_to_end), |b| {
            b.iter(symbolize_end_to_end)
        });
    }
}
