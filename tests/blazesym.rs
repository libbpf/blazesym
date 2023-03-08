use std::path::Path;

use blazesym::BlazeSymbolizer;
use blazesym::SymbolSrcCfg;
use blazesym::SymbolizerFeature;


/// Check that we can correctly symbolize an address using GSYM.
#[test]
fn symbolize_gsym() {
    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test.gsym");

    let features = vec![SymbolizerFeature::LineNumberInfo(true)];
    let srcs = vec![SymbolSrcCfg::Gsym {
        file_name: test_gsym,
        base_address: 0,
    }];
    let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();

    let results = symbolizer
        .symbolize(&srcs, &[0x2000100])
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}
