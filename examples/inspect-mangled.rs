//! An example illustrating how to look up a (mangled) symbol (and its
//! meta data) based on its expected demangled name.

use std::ops::ControlFlow;
use std::path::Path;

use anyhow::Result;

use blazesym::inspect::source::Elf;
use blazesym::inspect::source::Source;
use blazesym::inspect::Inspector;
use blazesym::inspect::SymInfo;

use rustc_demangle::demangle;


const TEST_FN: &str = "test::test_function";


fn find_test_function(
    sym: &SymInfo<'_>,
    test_fn: &mut Option<SymInfo<'static>>,
) -> ControlFlow<()> {
    let name = format!("{:#}", demangle(&sym.name));
    if name == TEST_FN {
        let _none = test_fn.replace(sym.to_owned());
        ControlFlow::Break(())
    } else {
        ControlFlow::Continue(())
    }
}

fn main() -> Result<()> {
    let so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let inspector = Inspector::new();
    let src = Source::from(Elf::new(so));

    // We can't really use `Inspector::lookup` here, because we only
    // know the demangled but not the mangled name. But the mangled name
    // is what is what `Inspector::lookup` uses in the case of an ELF
    // source. To look up symbol information based on the demangled
    // name, we roll our own search based on the `Inspector::for_each`
    // facility.
    let mut test_fn_out = None;
    let () = inspector
        .for_each(&src, |sym| find_test_function(sym, &mut test_fn_out))
        .unwrap();
    let test_fn = test_fn_out.unwrap_or_else(|| panic!("failed to find `{TEST_FN}` symbol"));
    println!("successfully looked up mangled symbol with demangled name `{TEST_FN}`:\n{test_fn:?}");
    Ok(())
}
