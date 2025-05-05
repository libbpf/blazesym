use std::ffi::OsString;
use std::mem::transmute;
#[cfg(linux)]
use std::ops::ControlFlow;
use std::path::Path;
#[cfg(linux)]
use std::slice;

use crate::elf::ElfParser;
use crate::inspect;
#[cfg(linux)]
use crate::inspect::FindAddrOpts;
#[cfg(linux)]
use crate::inspect::SymInfo;
#[cfg(linux)]
use crate::vdso::find_vdso;
#[cfg(linux)]
use crate::vdso::find_vdso_maps;
use crate::zip;
use crate::Addr;
use crate::Mmap;
use crate::Pid;
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

/// Find the address of the `gettimeofday` function in the given
/// process.
#[cfg(linux)]
pub fn find_gettimeofday_in_process(pid: Pid) -> Addr {
    let vdso_range = find_vdso().unwrap().unwrap();
    let data = vdso_range.start as *const u8;
    let len = vdso_range.end.saturating_sub(vdso_range.start);
    let mem = unsafe { slice::from_raw_parts(data, len as _) };
    let parser = ElfParser::from_mem(mem);
    let opts = FindAddrOpts {
        sym_type: SymType::Function,
        file_offset: false,
    };

    let remote_vdso_range = find_vdso_maps(pid).unwrap().unwrap();

    let mut found = None;
    let () = parser
        .for_each(&opts, &mut |sym: &SymInfo<'_>| {
            if sym.name.contains("gettimeofday") {
                found = Some(remote_vdso_range.start + sym.addr);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();

    found.expect("`gettimeofday` function not found")
}
