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
pub struct blazesym_ssc_elf {
    /// The path to the ELF file.
    ///
    /// The referenced file may be an executable or shared object. For example,
    /// passing "/bin/sh" will load symbols and debug information from `sh` and
    /// passing "/lib/libc.so.xxx" will load symbols and debug information from
    /// libc.
    pub path: *const c_char,
    /// The base address is where the file's executable segment(s) is loaded.
    ///
    /// It should be the address
    /// in the process mapping to the executable segment's first byte.
    /// For example, in /proc/&lt;pid&gt;/maps
    ///
    /// ```text
    ///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    ///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
    /// ```
    ///
    /// It reveals that the executable segment of libc-2.28.so was
    /// loaded at 0x7fe1b2dc4000.  This base address is used to
    /// translate an address in the segment to the corresponding
    /// address in the ELF file.
    ///
    /// A loader would load an executable segment with the permission of `x`
    /// (executable).  For example, the first block is with the
    /// permission of `r-xp`.
    pub base_address: Addr,
}

impl From<&blazesym_ssc_elf> for Elf {
    fn from(elf: &blazesym_ssc_elf) -> Self {
        let blazesym_ssc_elf { path, base_address } = elf;
        Self {
            path: unsafe { from_cstr(*path) },
            base_address: *base_address,
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a kernel.
///
/// Use a kernel image and a snapshot of its kallsyms as a source of symbols and
/// debug information.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_ssc_kernel {
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

impl From<&blazesym_ssc_kernel> for Kernel {
    fn from(kernel: &blazesym_ssc_kernel) -> Self {
        let blazesym_ssc_kernel {
            kallsyms,
            kernel_image,
        } = kernel;
        Self {
            kallsyms: (kallsyms.is_null()).then(|| unsafe { from_cstr(*kallsyms) }),
            kernel_image: (kernel_image.is_null()).then(|| unsafe { from_cstr(*kernel_image) }),
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
pub struct blazesym_ssc_process {
    /// It is the PID of a process to symbolize.
    ///
    /// BlazeSym will parse `/proc/<pid>/maps` and load all the object
    /// files.
    pub pid: u32,
}

impl From<&blazesym_ssc_process> for Process {
    fn from(process: &blazesym_ssc_process) -> Self {
        let blazesym_ssc_process { pid } = process;
        Self {
            pid: (*pid).into(),
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a gsym file.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_ssc_gsym {
    /// The path to a gsym file.
    pub path: *const c_char,
    /// The base address is where the file's executable segment(s) is loaded.
    pub base_address: Addr,
}

impl From<&blazesym_ssc_gsym> for Gsym {
    fn from(gsym: &blazesym_ssc_gsym) -> Self {
        let blazesym_ssc_gsym { path, base_address } = gsym;
        Self {
            path: unsafe { from_cstr(*path) },
            base_address: *base_address,
            _non_exhaustive: (),
        }
    }
}


/// A placeholder symbolizer for C API.
///
/// It is returned by [`blaze_symbolizer_new`] and should be free by
/// [`blaze_symbolizer_free`].
pub type blaze_symbolizer = Symbolizer;

/// The result of symbolization of an address for C API.
///
/// A `blazesym_csym` is the information of a symbol found for an
/// address.  One address may result in several symbols.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_csym {
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

/// `blazesym_entry` is the output of symbolization for an address for C API.
///
/// Every address has an `blazesym_entry` in
/// [`blazesym_result::entries`] to collect symbols found by BlazeSym.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_entry {
    /// The number of symbols found for an address.
    pub size: usize,
    /// All symbols found.
    ///
    /// `syms` is an array of blazesym_csym in the size `size`.
    pub syms: *const blazesym_csym,
}

/// `blazesym_result` is the result of symbolization for C API.
///
/// The instances of blazesym_result are returned by any of the
/// `blaze_symbolize_*` variants. They should be freed by calling
/// [`blazesym_result_free`].
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_result {
    /// The number of addresses being symbolized.
    pub size: usize,
    /// The entries for addresses.
    ///
    /// Symbolization occurs based on the order of addresses.
    /// Therefore, every address must have an entry here on the same
    /// order.
    pub entries: [blazesym_entry; 0],
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

/// Convert SymbolizedResults to blazesym_results.
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
unsafe fn convert_symbolizedresults_to_c(
    results: Vec<Vec<SymbolizedResult>>,
) -> *const blazesym_result {
    // Allocate a buffer to contain a blazesym_result, all
    // blazesym_csym, and C strings of symbol and path.
    let strtab_size = results.iter().flatten().fold(0, |acc, result| {
        acc + result.symbol.len() + result.path.as_os_str().len() + 2
    });
    let all_csym_size = results.iter().flatten().count();
    let buf_size = strtab_size
        + mem::size_of::<blazesym_result>()
        + mem::size_of::<blazesym_entry>() * results.len()
        + mem::size_of::<blazesym_csym>() * all_csym_size;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null()
    }

    // prepend an u64 to keep the size of the buffer.
    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };

    let result_ptr = raw_buf as *mut blazesym_result;
    let mut entry_last = unsafe { &mut (*result_ptr).entries as *mut blazesym_entry };
    let mut csym_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>() + mem::size_of::<blazesym_entry>() * results.len(),
        )
    } as *mut blazesym_csym;
    let mut cstr_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>()
                + mem::size_of::<blazesym_entry>() * results.len()
                + mem::size_of::<blazesym_csym>() * all_csym_size,
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

    // Convert all SymbolizedResults to blazesym_entrys and blazesym_csyms
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
) -> *const blazesym_result {
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
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blazesym_result_free()`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blazesym_ssc_process`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_process(
    symbolizer: *mut blaze_symbolizer,
    src: *const blazesym_ssc_process,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blazesym_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Process::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize kernel addresses.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blazesym_result_free()`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blazesym_ssc_kernel`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_kernel(
    symbolizer: *mut blaze_symbolizer,
    src: *const blazesym_ssc_kernel,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blazesym_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Kernel::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize addresses in an ELF file.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blazesym_result_free()`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blazesym_ssc_elf`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_elf(
    symbolizer: *mut blaze_symbolizer,
    src: *const blazesym_ssc_elf,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blazesym_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::from(Elf::from(unsafe { &*src }));
    unsafe { blaze_symbolize_impl(symbolizer, src, addrs, addr_cnt) }
}


/// Symbolize addresses in a Gsym file.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses. The caller should free the returned array by
/// calling [`blazesym_result_free()`].
///
/// # Safety
/// `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`]. `src` must point to a valid
/// [`blazesym_ssc_gsym`] object. `addrs` must represent an array of
/// `addr_cnt` objects.
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_gsym(
    symbolizer: *mut blaze_symbolizer,
    src: *const blazesym_ssc_gsym,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blazesym_result {
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
pub unsafe extern "C" fn blazesym_result_free(results: *const blazesym_result) {
    if results.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (results as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}
