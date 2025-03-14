use std::ffi::OsString;
use std::mem::transmute;
use std::path::Path;

use crate::elf::ElfParser;
use crate::inspect;
use crate::zip;
use crate::Addr;
use crate::Mmap;
use crate::SymType;


/// Find the `the_answer` function inside the provided `mmap`, which is
/// expected to be the memory mapped `libtest-so.so`.
///
/// This function returns the symbol information of the function along
/// with it's absolute address in the memory mapped region.
#[allow(clippy::missing_transmute_annotations)]
pub fn find_the_answer_fn(mmap: &Mmap) -> (inspect::SymInfo<'static>, Addr) {
    // Look up the address of the `the_answer` function inside of the shared
    // object.
    let elf_parser = ElfParser::from_mmap(mmap.clone(), Some(OsString::from("libtest-so.so")));
    let opts = inspect::FindAddrOpts {
        file_offset: true,
        sym_type: SymType::Function,
    };
    let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
    // There is only one symbol with this address in there.
    assert_eq!(syms.len(), 1);
    let sym = syms.first().unwrap();

    let the_answer_addr = unsafe { mmap.as_ptr().add(sym.addr as usize) };
    // Now just double check that everything worked out and the function
    // is actually where it was meant to be.
    let the_answer_fn = unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
    let answer = the_answer_fn();
    assert_eq!(answer, 42);

    (sym.to_owned(), the_answer_addr as Addr)
}

/// Find the `the_answer` function inside the provided `mmap`, which is
/// expected to be the memory mapped zip archive.
pub fn find_the_answer_fn_in_zip(mmap: &Mmap) -> (inspect::SymInfo<'static>, Addr) {
    let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
    let so = archive
        .entries()
        .find_map(|entry| {
            let entry = entry.unwrap();
            (entry.path == Path::new("libtest-so.so")).then_some(entry)
        })
        .unwrap();

    let elf_mmap = mmap
        .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
        .unwrap();

    let (sym, the_answer_addr) = find_the_answer_fn(&elf_mmap);
    (sym, the_answer_addr)
}
