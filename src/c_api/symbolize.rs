use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::mem;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use crate::log::error;
use crate::log::warn;
use crate::symbolize::Elf;
use crate::symbolize::Gsym;
use crate::symbolize::Kernel;
use crate::symbolize::Process;
use crate::symbolize::Source;
use crate::symbolize::SymbolizedResult;
use crate::symbolize::Symbolizer;
use crate::util::slice_from_user_array;
use crate::Addr;


/// The parameters to load symbols and debug information from an ELF.
///
/// Describes the path and address of an ELF file loaded in a
/// process.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_elf {
    /// The path to the ELF file.
    ///
    /// The referenced file may be an executable or shared object. For example,
    /// passing "/bin/sh" will load symbols and debug information from `sh` and
    /// passing "/lib/libc.so.xxx" will load symbols and debug information from
    /// libc.
    pub path: *const c_char,
}

impl From<&blaze_symbolize_src_elf> for Elf {
    fn from(elf: &blaze_symbolize_src_elf) -> Self {
        let blaze_symbolize_src_elf { path } = elf;
        Self {
            path: unsafe { from_cstr(*path) },
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a kernel.
///
/// Use a kernel image and a snapshot of its kallsyms as a source of symbols and
/// debug information.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct blaze_symbolize_src_kernel {
    /// The path of a copy of kallsyms.
    ///
    /// It can be `"/proc/kallsyms"` for the running kernel on the
    /// device.  However, you can make copies for later.  In that situation,
    /// you should give the path of a copy.
    /// Passing a `NULL`, by default, will result in `"/proc/kallsyms"`.
    pub kallsyms: *const c_char,
    /// The path of a kernel image.
    ///
    /// The path of a kernel image should be, for instance,
    /// `"/boot/vmlinux-xxxx"`.  For a `NULL` value, it will locate the
    /// kernel image of the running kernel in `"/boot/"` or
    /// `"/usr/lib/debug/boot/"`.
    pub kernel_image: *const c_char,
}

impl From<&blaze_symbolize_src_kernel> for Kernel {
    fn from(kernel: &blaze_symbolize_src_kernel) -> Self {
        let blaze_symbolize_src_kernel {
            kallsyms,
            kernel_image,
        } = kernel;
        Self {
            kallsyms: (!kallsyms.is_null()).then(|| unsafe { from_cstr(*kallsyms) }),
            kernel_image: (!kernel_image.is_null()).then(|| unsafe { from_cstr(*kernel_image) }),
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a process.
///
/// Load all ELF files in a process as the sources of symbols and debug
/// information.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_process {
    /// It is the PID of a process to symbolize.
    ///
    /// blazesym will parse `/proc/<pid>/maps` and load all the object
    /// files.
    pub pid: u32,
}

impl From<&blaze_symbolize_src_process> for Process {
    fn from(process: &blaze_symbolize_src_process) -> Self {
        let blaze_symbolize_src_process { pid } = process;
        Self {
            pid: (*pid).into(),
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a gsym file.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_gsym {
    /// The path to a gsym file.
    pub path: *const c_char,
}

impl From<&blaze_symbolize_src_gsym> for Gsym {
    fn from(gsym: &blaze_symbolize_src_gsym) -> Self {
        let blaze_symbolize_src_gsym { path } = gsym;
        Self {
            path: unsafe { from_cstr(*path) },
            _non_exhaustive: (),
        }
    }
}


/// A placeholder symbolizer for C API.
///
/// It is returned by [`blaze_symbolizer_new`] and should be free by
/// [`blaze_symbolizer_free`].
pub type blaze_symbolizer = Symbolizer;


/// The result of symbolization of an address.
///
/// A `blaze_sym` is the information of a symbol found for an
/// address. One address may result in several symbols.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_sym {
    /// The symbol name is where the given address should belong to.
    pub symbol: *const c_char,
    /// The address (i.e.,the first byte) is where the symbol is located.
    ///
    /// The address is already relocated to the address space of
    /// the process.
    pub addr: Addr,
    /// The path of the source file defining the symbol.
    pub path: *const c_char,
    /// The line number on which the symbol was to be found in the source code.
    pub line: usize,
    pub column: usize,
}

/// `blaze_entry` is the output of symbolization for an address for C API.
///
/// Every address has an `blaze_entry` in
/// [`blaze_result::entries`] to collect symbols found.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_entry {
    /// The number of symbols found for an address.
    pub size: usize,
    /// All symbols found.
    ///
    /// `syms` is an array of [`blaze_sym`] in the size `size`.
    pub syms: *const blaze_sym,
}

/// `blaze_result` is the result of symbolization for C API.
///
/// Instances of [`blaze_result`] are returned by any of the `blaze_symbolize_*`
/// variants. They should be freed by calling [`blaze_result_free`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_result {
    /// The number of addresses being symbolized.
    pub size: usize,
    /// The entries for addresses.
    ///
    /// Symbolization occurs based on the order of addresses.
    /// Therefore, every address must have an entry here on the same
    /// order.
    pub entries: [blaze_entry; 0],
}

/// Create a `PathBuf` from a pointer of C string
///
/// # Safety
/// The provided `cstr` should be terminated with a NUL byte.
unsafe fn from_cstr(cstr: *const c_char) -> PathBuf {
    Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(cstr) }.to_bytes(),
    ))
    .to_path_buf()
}


/// Options for configuring `blaze_symbolizer` objects.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolizer_opts {
    /// Whether to enable usage of debug symbols.
    pub debug_syms: bool,
    /// Whether to attempt to gather source code location information.
    ///
    /// This setting implies `debug_syms` (and forces it to `true`).
    pub src_location: bool,
}


/// Create an instance of a symbolizer.
#[no_mangle]
pub extern "C" fn blaze_symbolizer_new() -> *mut blaze_symbolizer {
    let symbolizer = Symbolizer::new();
    let symbolizer_box = Box::new(symbolizer);
    Box::into_raw(symbolizer_box)
}

/// Create an instance of a symbolizer with configurable options.
///
/// # Safety
/// `opts` needs to be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolizer_new_opts(
    opts: *const blaze_symbolizer_opts,
) -> *mut blaze_symbolizer {
    // SAFETY: The caller ensures that the pointer is valid.
    let opts = unsafe { &*opts };
    let blaze_symbolizer_opts {
        debug_syms,
        src_location,
    } = opts;

    let symbolizer = Symbolizer::builder()
        .enable_debug_syms(*debug_syms)
        .enable_src_location(*src_location)
        .build();
    let symbolizer_box = Box::new(symbolizer);
    Box::into_raw(symbolizer_box)
}

/// Free an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// The pointer must have been returned by [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`].
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolizer_free(symbolizer: *mut blaze_symbolizer) {
    if !symbolizer.is_null() {
        drop(unsafe { Box::from_raw(symbolizer) });
    }
}

/// Convert [`SymbolizedResult`] objects to [`blaze_result`] ones.
///
/// # Safety
///
/// The returned pointer should be freed by [`blaze_result_free`].
unsafe fn convert_symbolizedresults_to_c(
    results: Vec<Vec<SymbolizedResult>>,
) -> *const blaze_result {
    // Allocate a buffer to contain a blaze_result, all
    // blaze_sym, and C strings of symbol and path.
    let strtab_size = results.iter().flatten().fold(0, |acc, result| {
        acc + result.symbol.len() + result.path.as_os_str().len() + 2
    });
    let all_csym_size = results.iter().flatten().count();
    let buf_size = strtab_size
        + mem::size_of::<blaze_result>()
        + mem::size_of::<blaze_entry>() * results.len()
        + mem::size_of::<blaze_sym>() * all_csym_size;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null()
    }

    // prepend an u64 to keep the size of the buffer.
    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };

    let result_ptr = raw_buf as *mut blaze_result;
    let mut entry_last = unsafe { &mut (*result_ptr).entries as *mut blaze_entry };
    let mut csym_last = unsafe {
        raw_buf.add(mem::size_of::<blaze_result>() + mem::size_of::<blaze_entry>() * results.len())
    } as *mut blaze_sym;
    let mut cstr_last = unsafe {
        raw_buf.add(
            mem::size_of::<blaze_result>()
                + mem::size_of::<blaze_entry>() * results.len()
                + mem::size_of::<blaze_sym>() * all_csym_size,
        )
    } as *mut c_char;

    let mut make_cstr = |src: &OsStr| {
        let cstr = cstr_last;
        unsafe { ptr::copy(src.as_bytes().as_ptr(), cstr as *mut u8, src.len()) };
        unsafe { *cstr.add(src.len()) = 0 };
        cstr_last = unsafe { cstr_last.add(src.len() + 1) };

        cstr
    };

    unsafe { (*result_ptr).size = results.len() };

    // Convert all `SymbolizedResult`s to `blaze_entry`s and `blazesym_sym`s.
    for entry in results {
        unsafe { (*entry_last).size = entry.len() };
        unsafe { (*entry_last).syms = csym_last };
        entry_last = unsafe { entry_last.add(1) };

        for r in entry {
            let symbol_ptr = make_cstr(OsStr::new(&r.symbol));

            let path_ptr = make_cstr(r.path.as_os_str());

            let csym_ref = unsafe { &mut *csym_last };
            csym_ref.symbol = symbol_ptr;
            csym_ref.addr = r.addr;
            csym_ref.path = path_ptr;
            csym_ref.line = r.line;
            csym_ref.column = r.column;

            csym_last = unsafe { csym_last.add(1) };
        }
    }

    result_ptr
}

unsafe fn blaze_symbolize_impl(
    symbolizer: *mut blaze_symbolizer,
    src: Source,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blaze_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let addrs = unsafe { slice_from_user_array(addrs, addr_cnt) };

    let result = symbolizer.symbolize(&src, addrs);

    match result {
        Ok(results) if results.is_empty() => {
            warn!("empty result while request for {addr_cnt}");
            ptr::null()
        }
        Ok(results) => unsafe { convert_symbolizedresults_to_c(results) },
        Err(_err) => {
            error!("failed to symbolize {addr_cnt} addresses: {_err}");
            ptr::null()
        }
    }
}


/// Symbolize addresses of a process.
///
/// Return an array of [`blaze_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blaze_result_free`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blaze_symbolize_src_process`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_process(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_process,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blaze_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Process::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize kernel addresses.
///
/// Return an array of [`blaze_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blaze_result_free`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blaze_symbolize_src_kernel`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_kernel(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_kernel,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blaze_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Kernel::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize addresses in an ELF file.
///
/// Return an array of [`blaze_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blaze_result_free`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blaze_symbolize_src_elf`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_elf(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_elf,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blaze_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Elf::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize addresses in a Gsym file.
///
/// Return an array of [`blaze_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blaze_result_free`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blaze_symbolize_src_gsym`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_gsym(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_gsym,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blaze_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Gsym::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Free an array returned by any of the `blaze_symbolize_*` variants.
///
/// # Safety
/// The pointer must have been returned by any of the `blaze_symbolize_*`
/// variants.
#[no_mangle]
pub unsafe extern "C" fn blaze_result_free(results: *const blaze_result) {
    if results.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (results as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can convert an [`Unknown`] into a
    /// [`blaze_user_addr_meta_unknown`] and back.
    #[test]
    fn kernel_conversion() {
        let kernel = blaze_symbolize_src_kernel {
            kallsyms: ptr::null(),
            kernel_image: ptr::null(),
        };
        let kernel = Kernel::from(&kernel);
        assert_eq!(kernel.kallsyms, None);
        assert_eq!(kernel.kernel_image, None);

        let kernel = blaze_symbolize_src_kernel {
            kallsyms: b"/proc/kallsyms\0" as *const _ as *const c_char,
            kernel_image: b"/boot/image\0" as *const _ as *const c_char,
        };
        let kernel = Kernel::from(&kernel);
        assert_eq!(kernel.kallsyms, Some(PathBuf::from("/proc/kallsyms")));
        assert_eq!(kernel.kernel_image, Some(PathBuf::from("/boot/image")));
    }
}
