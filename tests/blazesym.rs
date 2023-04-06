use std::io::ErrorKind;
use std::path::Path;

use blazesym::cfg;
use blazesym::BlazeSymbolizer;
use blazesym::SymbolSrcCfg;
use blazesym::SymbolizerFeature;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        SymbolSrcCfg::Gsym(cfg::Gsym {
            file_name: non_existent.to_path_buf(),
            base_address: 0,
        }),
        SymbolSrcCfg::Elf(cfg::Elf {
            file_name: non_existent.to_path_buf(),
            base_address: 0,
        }),
    ];
    let symbolizer = BlazeSymbolizer::new().unwrap();

    for src in srcs {
        let err = symbolizer
            .symbolize([src].as_slice(), &[0x2000100])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can correctly symbolize an address using GSYM.
#[test]
fn symbolize_gsym() {
    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test.gsym");

    let features = vec![SymbolizerFeature::LineNumberInfo(true)];
    let srcs = vec![SymbolSrcCfg::Gsym(cfg::Gsym {
        file_name: test_gsym,
        base_address: 0,
    })];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();

    let results = symbolizer
        .symbolize(&srcs, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can symbolize an address using DWARF.
#[test]
fn symbolize_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let features = [
        SymbolizerFeature::LineNumberInfo(true),
        SymbolizerFeature::DebugInfoSymbols(true),
    ];
    let srcs = [SymbolSrcCfg::Elf(cfg::Elf {
        file_name: test_dwarf,
        base_address: 0,
    })];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
    let results = symbolizer
        .symbolize(&srcs, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can look up an address using DWARF.
#[test]
fn lookup_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let features = [
        SymbolizerFeature::LineNumberInfo(true),
        SymbolizerFeature::DebugInfoSymbols(true),
    ];
    let srcs = [SymbolSrcCfg::Elf(cfg::Elf {
        file_name: test_dwarf,
        base_address: 0,
    })];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
    let results = symbolizer
        .find_addresses(&srcs, &["factorial"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.address, 0x2000100);
}

/// Check that we cannot lookup a symbol from DWARF information when the debug
/// info feature is turned off.
#[test]
fn lookup_dwarf_no_debug_info() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let features = [
        SymbolizerFeature::LineNumberInfo(true),
        SymbolizerFeature::DebugInfoSymbols(false),
    ];
    let srcs = [SymbolSrcCfg::Elf(cfg::Elf {
        file_name: test_dwarf,
        base_address: 0,
    })];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
    let results = symbolizer
        .find_addresses(&srcs, &["factorial"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 0);
}
