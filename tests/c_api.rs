#![allow(clippy::let_and_return, clippy::let_unit_value)]

use std::ffi::CStr;
use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::path::Path;
use std::slice;

use blazesym::blazesym_feature;
use blazesym::blazesym_feature_name;
use blazesym::blazesym_feature_params;
use blazesym::blazesym_find_addresses;
use blazesym::blazesym_free;
use blazesym::blazesym_new;
use blazesym::blazesym_new_opts;
use blazesym::blazesym_result_free;
use blazesym::blazesym_src_type;
use blazesym::blazesym_ssc_elf;
use blazesym::blazesym_ssc_gsym;
use blazesym::blazesym_ssc_params;
use blazesym::blazesym_sym_src_cfg;
use blazesym::blazesym_symbolize;
use blazesym::blazesym_syms_list_free;


/// Make sure that we can create and free a symbolizer instance.
#[test]
fn symbolizer_creation() {
    let symbolizer = unsafe { blazesym_new() };
    let () = unsafe { blazesym_free(symbolizer) };
}


/// Make sure that we can create and free a symbolizer instance with the
/// provided features.
#[test]
fn symbolizer_creation_with_features() {
    let features = [
        blazesym_feature {
            feature: blazesym_feature_name::BLAZESYM_LINE_NUMBER_INFO,
            params: blazesym_feature_params { enable: true },
        },
        blazesym_feature {
            feature: blazesym_feature_name::BLAZESYM_DEBUG_INFO_SYMBOLS,
            params: blazesym_feature_params { enable: true },
        },
    ];
    let symbolizer = unsafe { blazesym_new_opts(features.as_ptr(), features.len()) };
    let () = unsafe { blazesym_free(symbolizer) };
}


/// Make sure that we can symbolize an address.
#[test]
fn symbolize_from_file() {
    fn test(cfg: blazesym_sym_src_cfg) {
        let symbolizer = unsafe { blazesym_new() };
        let srcs = [cfg];
        let addrs = [0x2000100];
        let result = unsafe {
            blazesym_symbolize(
                symbolizer,
                srcs.as_ptr(),
                srcs.len(),
                addrs.as_ptr(),
                addrs.len(),
            )
        };

        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.size, 1);
        let entries = unsafe { slice::from_raw_parts(result.entries.as_ptr(), result.size) };
        let entry = &entries[0];
        assert_eq!(entry.size, 1);

        let syms = unsafe { slice::from_raw_parts(entry.syms, entry.size) };
        let sym = &syms[0];
        assert_eq!(
            unsafe { CStr::from_ptr(sym.symbol) },
            CStr::from_bytes_with_nul(b"factorial\0").unwrap()
        );

        let () = unsafe { blazesym_result_free(result) };
        let () = unsafe { blazesym_free(symbolizer) };
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let test_dwarf_c = CString::new(test_dwarf.to_str().unwrap()).unwrap();

    let elf_src = ManuallyDrop::new(blazesym_ssc_elf {
        file_name: test_dwarf_c.as_ptr(),
        base_address: 0,
    });
    let cfg = blazesym_sym_src_cfg {
        src_type: blazesym_src_type::BLAZESYM_SRC_T_ELF,
        params: blazesym_ssc_params { elf: elf_src },
    };
    test(cfg);

    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test.gsym");
    let test_gsym_c = CString::new(test_gsym.to_str().unwrap()).unwrap();
    let gsym_src = ManuallyDrop::new(blazesym_ssc_gsym {
        file_name: test_gsym_c.as_ptr(),
        base_address: 0,
    });
    let cfg = blazesym_sym_src_cfg {
        src_type: blazesym_src_type::BLAZESYM_SRC_T_GSYM,
        params: blazesym_ssc_params { gsym: gsym_src },
    };
    test(cfg);
}


/// Make sure that we can lookup a function's address using DWARF information.
#[test]
fn lookup_dwarf() {
    let features = [
        blazesym_feature {
            feature: blazesym_feature_name::BLAZESYM_LINE_NUMBER_INFO,
            params: blazesym_feature_params { enable: true },
        },
        blazesym_feature {
            feature: blazesym_feature_name::BLAZESYM_DEBUG_INFO_SYMBOLS,
            params: blazesym_feature_params { enable: true },
        },
    ];
    let symbolizer = unsafe { blazesym_new_opts(features.as_ptr(), features.len()) };

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let test_dwarf_c = CString::new(test_dwarf.to_str().unwrap()).unwrap();

    let elf_src = ManuallyDrop::new(blazesym_ssc_elf {
        file_name: test_dwarf_c.as_ptr(),
        base_address: 0,
    });
    let srcs = [blazesym_sym_src_cfg {
        src_type: blazesym_src_type::BLAZESYM_SRC_T_ELF,
        params: blazesym_ssc_params { elf: elf_src },
    }];

    let factorial = CString::new("factorial").unwrap();
    let names = [factorial.as_ptr()];

    let result = unsafe {
        blazesym_find_addresses(
            symbolizer,
            srcs.as_ptr(),
            srcs.len(),
            names.as_ptr(),
            names.len(),
        )
    };
    let sym_infos = unsafe { slice::from_raw_parts(result, names.len()) };
    let sym_info = unsafe { &*sym_infos[0] };
    assert_eq!(
        unsafe { CStr::from_ptr(sym_info.name) },
        CStr::from_bytes_with_nul(b"factorial\0").unwrap()
    );
    assert_eq!(sym_info.address, 0x2000100);

    let () = unsafe { blazesym_syms_list_free(result) };
    let () = unsafe { blazesym_free(symbolizer) };
}
