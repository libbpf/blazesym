use std::path::Path;

use blazesym::symbolize::cfg;
use blazesym::symbolize::SymbolSrcCfg;
use blazesym::symbolize::Symbolizer;
use blazesym::symbolize::SymbolizerFeature;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Symbolize an address, end-to-end, i.e., including all necessary setup.
fn symbolize_end_to_end() {
    let gsym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.gsym");
    let features = [
        SymbolizerFeature::DebugInfoSymbols(true),
        SymbolizerFeature::LineNumberInfo(true),
    ];
    let cfg = SymbolSrcCfg::Gsym(cfg::Gsym {
        file_name: gsym_vmlinux,
        base_address: 0,
    });
    let symbolizer = Symbolizer::with_opts(&features).unwrap();

    let results = symbolizer
        .symbolize(&cfg, &[0xffffffff8110ecb0])
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
    if cfg!(feature = "generate-bench-files") {
        group.bench_function(stringify!(gsym::symbolize_end_to_end), |b| {
            b.iter(symbolize_end_to_end)
        });
    }
}
