use std::collections::HashMap;
use std::env;
use std::fs::read as read_file;
use std::ops::ControlFlow;
use std::ops::Deref as _;
use std::path::Path;
use std::str;

use blazesym::inspect::source::Breakpad;
use blazesym::inspect::source::Elf;
use blazesym::inspect::source::Source;
use blazesym::inspect::Inspector;
use blazesym::inspect::SymInfo;
use blazesym::symbolize;
use blazesym::SymType;

use test_log::test;


/// Check that we can look up an address.
#[test]
fn inspect_elf() {
    fn test(src: Source, no_vars: bool) {
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["factorial", "a_variable"])
            .unwrap();
        assert_eq!(results.len(), 2);

        let result = &results[0];
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].addr, 0x2000100);
        assert_eq!(result[0].sym_type, SymType::Function);
        assert_ne!(result[0].file_offset, None);
        assert_eq!(
            result[0].obj_file_name.as_deref().unwrap(),
            src.path().unwrap()
        );

        let result = &results[1];
        if no_vars {
            assert!(result.is_empty(), "{result:#x?}");
        } else {
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].addr, 0x4001100);
            assert_eq!(result[0].sym_type, SymType::Variable);
            assert_ne!(result[0].file_offset, None);
            assert_eq!(
                result[0].obj_file_name.as_deref().unwrap(),
                src.path().unwrap()
            );
        }
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
    let src = Source::Elf(Elf::new(test_dwarf));
    // Our `DwarfResolver` type does not currently support look up of
    // variables.
    let no_vars = true;
    let () = test(src, no_vars);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.bin");
    for debug_syms in [true, false] {
        let mut elf = Elf::new(&test_elf);
        elf.debug_syms = debug_syms;
        let src = Source::Elf(elf);
        let () = test(src, false);
    }

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let mut elf = Elf::new(test_elf);
    assert!(elf.debug_syms);
    elf.debug_syms = false;
    let src = Source::Elf(elf);
    let () = test(src, false);
}


/// Check that we can look up a symbol by name in a Breakpad file.
#[test]
fn inspect_breakpad() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let breakpad = Breakpad::new(path);
    let src = Source::from(breakpad);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["factorial"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let sym = &results[0];
    assert_eq!(sym.name, "factorial");
    assert_eq!(sym.addr, 0x100);
    assert_eq!(sym.sym_type, SymType::Function);
    assert_eq!(sym.file_offset, None);
    assert_eq!(sym.obj_file_name, None);
}


/// Make sure that we can look up a dynamic symbol in an ELF file.
#[test]
fn inspect_elf_dynamic_symbol() {
    #[track_caller]
    fn test(bin: &str) {
        let bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(bin);

        let src = Source::Elf(Elf::new(&bin));
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["the_answer"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let src = symbolize::source::Source::Elf(symbolize::source::Elf::new(&bin));
        let symbolizer = symbolize::Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(results[0].addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, results[0].addr);
    }

    test("libtest-so.so");
    test("libtest-so-stripped.so");
    test("libtest-so-partly-stripped.so");
}

/// Make sure that we can look up an indirect in an ELF file.
#[test]
fn inspect_elf_indirect_function() {
    let bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");

    let src = Source::Elf(Elf::new(&bin));
    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["indirect_func"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let src = symbolize::source::Source::Elf(symbolize::source::Elf::new(&bin));
    let symbolizer = symbolize::Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(results[0].addr))
        .unwrap()
        .into_sym()
        .unwrap();

    // Both functions may legitimately have the same address.
    assert!(["indirect_func", "resolve_indirect_func"].contains(&result.name.deref()));
    assert_eq!(result.addr, results[0].addr);
}


/// Read four bytes at the given `offset` in the file identified by `path`.
fn read_4bytes_at(path: &Path, offset: u64) -> [u8; 4] {
    let offset = offset as usize;
    let content = read_file(path).unwrap();
    let slice = &content[offset..offset + 4];
    <[u8; 4]>::try_from(slice).unwrap()
}


/// Check that we can correctly retrieve the file offset in an ELF file.
#[test]
fn inspect_elf_file_offset() {
    fn test(file: &str) {
        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(file);
        let elf = Elf::new(test_elf);
        let src = Source::Elf(elf);

        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["dummy"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_ne!(result.file_offset, None);
        let bytes = read_4bytes_at(src.path().unwrap(), result.file_offset.unwrap());
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
    }

    for file in [
        "test-stable-addrs-no-dwarf.bin",
        "test-stable-addrs-stripped-with-link.bin",
    ] {
        let () = test(file);
    }
}


/// Check that we can iterate over all symbols in a symbolization source.
#[test]
fn inspect_elf_dwarf_breakpad_all_symbols() {
    fn test(src: &Source) {
        let breakpad = matches!(src, Source::Breakpad(..));
        let dwarf = matches!(
            src,
            Source::Elf(Elf {
                debug_syms: true,
                ..
            })
        );
        let inspector = Inspector::new();
        let mut syms = HashMap::<String, SymInfo>::new();
        let () = inspector
            .for_each(src, |sym| {
                let _inserted = syms.insert(sym.name.to_string(), sym.to_owned());
                ControlFlow::Continue(())
            })
            .unwrap();

        // Breakpad and DWARF don't contain any or any reasonable information
        // for some symbols.
        if !breakpad {
            let sym = syms.get("main").unwrap();
            assert_eq!(sym.sym_type, SymType::Function);
        }

        let sym = syms.get("factorial").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("factorial_wrapper").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("factorial_inline_test").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        if !breakpad && !dwarf {
            let sym = syms.get("indirect_func").unwrap();
            assert_eq!(sym.sym_type, SymType::Function);
        }

        let sym = syms.get("my_indirect_func").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        let sym = syms.get("resolve_indirect_func").unwrap();
        assert_eq!(sym.sym_type, SymType::Function);

        if !breakpad && !dwarf {
            let sym = syms.get("a_variable").unwrap();
            assert_eq!(sym.sym_type, SymType::Variable);
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let mut elf = Elf::new(path);
    elf.debug_syms = false;
    let src = Source::Elf(elf);
    test(&src);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
    let elf = Elf::new(path);
    let src = Source::Elf(elf);
    test(&src);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let breakpad = Breakpad::new(path);
    let src = Source::Breakpad(breakpad);
    test(&src);
}


/// Check that early stopping of symbol iteration works as expected.
#[test]
fn inspect_elf_dwarf_breakpad_early_iter_stop() {
    fn test(src: &Source) {
        let mut i = 0;
        let inspector = Inspector::new();
        let () = inspector
            .for_each(src, |_sym| {
                if i == 0 {
                    i += 1;
                    ControlFlow::Break(())
                } else {
                    panic!()
                }
            })
            .unwrap();
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let mut elf = Elf::new(path);
    elf.debug_syms = false;
    let src = Source::Elf(elf);
    test(&src);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
    let elf = Elf::new(path);
    let src = Source::Elf(elf);
    test(&src);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs.sym");
    let breakpad = Breakpad::new(path);
    let src = Source::Breakpad(breakpad);
    test(&src);
}


/// Make sure that the `debug_syms` flag is honored.
#[test]
fn inspect_debug_syms_flag() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-no-dwarf.bin");
    let mut elf = Elf::new(path);
    elf.debug_syms = true;
    let src = Source::Elf(elf);
    let inspector = Inspector::new();
    // There aren't any debug symbols in the source (although there are ELF
    // symbols).
    let () = inspector.for_each(&src, |_sym| panic!()).unwrap();

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
    let mut elf = Elf::new(path);
    elf.debug_syms = false;
    let src = Source::Elf(elf);
    // There aren't any ELF symbols in the source (although there are DWARF
    // symbols).
    let () = inspector.for_each(&src, |_sym| panic!()).unwrap();
}


/// Check that we can iterate over all symbols in an ELF file, without
/// encountering duplicates caused by dynamic/static symbol overlap.
#[test]
fn inspect_elf_all_symbols_without_duplicates() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let mut elf = Elf::new(path);
    elf.debug_syms = false;
    let src = Source::Elf(elf);

    let inspector = Inspector::new();
    let mut syms = Vec::<String>::new();
    let () = inspector
        .for_each(&src, |sym| {
            let () = syms.push(sym.name.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();

    assert_eq!(syms.iter().filter(|name| *name == "the_answer").count(), 1);
}
