use std::path::Path;

use blazesym::BlazeSymbolizer;
use blazesym::SymbolSrcCfg;
use blazesym::SymbolizerFeature;


/// Symbolize an address, end-to-end, i.e., including all necessary setup.
pub fn symbolize_end_to_end() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let features = [
        SymbolizerFeature::DebugInfoSymbols(true),
        SymbolizerFeature::LineNumberInfo(true),
    ];
    let sources = [SymbolSrcCfg::Elf {
        file_name: dwarf_vmlinux,
        base_address: 0,
    }];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();

    let results = symbolizer
        .symbolize(&sources, &[0xffffffff8110ecb0])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "abort_creds");
}

/// Lookup an address, end-to-end, i.e., including all necessary setup.
pub fn lookup_end_to_end() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let features = [
        SymbolizerFeature::DebugInfoSymbols(true),
        SymbolizerFeature::LineNumberInfo(true),
    ];
    let sources = [SymbolSrcCfg::Elf {
        file_name: dwarf_vmlinux,
        base_address: 0,
    }];

    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
    let results = symbolizer
        .find_addresses(&sources, &["abort_creds"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.address, 0xffffffff8110ecb0);
}
