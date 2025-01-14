use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::mem;
use std::ops::Deref as _;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use blazesym::symbolize::CodeInfo;
use blazesym::symbolize::Elf;
use blazesym::symbolize::GsymData;
use blazesym::symbolize::GsymFile;
use blazesym::symbolize::InlinedFn;
use blazesym::symbolize::Input;
use blazesym::symbolize::Kernel;
use blazesym::symbolize::Process;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;

use crate::blaze_err;
#[cfg(doc)]
use crate::blaze_err_last;
use crate::set_last_err;
use crate::util::slice_from_aligned_user_array;
use crate::util::slice_from_user_array;


/// The parameters to load symbols and debug information from an ELF.
///
/// Describes the path and address of an ELF file loaded in a
/// process.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_elf {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// The path to the ELF file.
    ///
    /// The referenced file may be an executable or shared object. For example,
    /// passing "/bin/sh" will load symbols and debug information from `sh` and
    /// passing "/lib/libc.so.xxx" will load symbols and debug information from
    /// libc.
    pub path: *const c_char,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    pub debug_syms: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 7],
}

impl Default for blaze_symbolize_src_elf {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            path: ptr::null(),
            debug_syms: false,
            reserved: [0; 7],
        }
    }
}

impl From<blaze_symbolize_src_elf> for Elf {
    fn from(elf: blaze_symbolize_src_elf) -> Self {
        let blaze_symbolize_src_elf {
            type_size: _,
            path,
            debug_syms,
            reserved: _,
        } = elf;
        Self {
            path: unsafe { from_cstr(path) },
            debug_syms,
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
pub struct blaze_symbolize_src_kernel {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
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
    /// Whether or not to consult debug symbols from `kernel_image`
    /// to satisfy the request (if present).
    pub debug_syms: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 7],
}

impl Default for blaze_symbolize_src_kernel {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            kallsyms: ptr::null(),
            kernel_image: ptr::null(),
            debug_syms: false,
            reserved: [0; 7],
        }
    }
}

impl From<blaze_symbolize_src_kernel> for Kernel {
    fn from(kernel: blaze_symbolize_src_kernel) -> Self {
        let blaze_symbolize_src_kernel {
            type_size: _,
            kallsyms,
            kernel_image,
            debug_syms,
            reserved: _,
        } = kernel;
        Self {
            kallsyms: (!kallsyms.is_null()).then(|| unsafe { from_cstr(kallsyms) }),
            kernel_image: (!kernel_image.is_null()).then(|| unsafe { from_cstr(kernel_image) }),
            debug_syms,
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
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// It is the PID of a process to symbolize.
    ///
    /// blazesym will parse `/proc/<pid>/maps` and load all the object
    /// files.
    pub pid: u32,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    pub debug_syms: bool,
    /// Whether to incorporate a process' perf map file into the symbolization
    /// procedure.
    pub perf_map: bool,
    /// Whether to work with `/proc/<pid>/map_files/` entries or with
    /// symbolic paths mentioned in `/proc/<pid>/maps` instead.
    /// `map_files` usage is generally strongly encouraged, as symbolic
    /// path usage is unlikely to work reliably in mount namespace
    /// contexts or when files have been deleted from the file system.
    /// However, by using symbolic paths the need for requiring the
    /// `SYS_ADMIN` capability is eliminated.
    pub map_files: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 1],
}

impl Default for blaze_symbolize_src_process {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            pid: 0,
            debug_syms: false,
            perf_map: false,
            map_files: false,
            reserved: [0; 1],
        }
    }
}

impl From<blaze_symbolize_src_process> for Process {
    fn from(process: blaze_symbolize_src_process) -> Self {
        let blaze_symbolize_src_process {
            type_size: _,
            pid,
            debug_syms,
            perf_map,
            map_files,
            reserved: _,
        } = process;
        Self {
            pid: pid.into(),
            debug_syms,
            perf_map,
            map_files,
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from "raw" Gsym data.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_gsym_data {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// The Gsym data.
    pub data: *const u8,
    /// The size of the Gsym data.
    pub data_len: usize,
    /// Unused member indicating the last field.
    pub reserved: (),
}

impl Default for blaze_symbolize_src_gsym_data {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            data: ptr::null(),
            data_len: 0,
            reserved: (),
        }
    }
}

impl From<blaze_symbolize_src_gsym_data> for GsymData<'_> {
    fn from(gsym: blaze_symbolize_src_gsym_data) -> Self {
        let blaze_symbolize_src_gsym_data {
            type_size: _,
            data,
            data_len,
            reserved: (),
        } = gsym;
        Self {
            data: unsafe { slice_from_aligned_user_array(data, data_len) },
            _non_exhaustive: (),
        }
    }
}


/// The parameters to load symbols and debug information from a Gsym file.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_src_gsym_file {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// The path to a gsym file.
    pub path: *const c_char,
    /// Unused member indicating the last field.
    pub reserved: (),
}

impl Default for blaze_symbolize_src_gsym_file {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            path: ptr::null(),
            reserved: (),
        }
    }
}

impl From<blaze_symbolize_src_gsym_file> for GsymFile {
    fn from(gsym: blaze_symbolize_src_gsym_file) -> Self {
        let blaze_symbolize_src_gsym_file {
            type_size: _,
            path,
            reserved: (),
        } = gsym;
        Self {
            path: unsafe { from_cstr(path) },
            _non_exhaustive: (),
        }
    }
}


/// C ABI compatible version of [`blazesym::symbolize::Symbolizer`].
///
/// It is returned by [`blaze_symbolizer_new`] and should be free by
/// [`blaze_symbolizer_free`].
pub type blaze_symbolizer = Symbolizer;


/// The reason why symbolization failed.
///
/// The reason is generally only meant as a hint. Reasons reported may
/// change over time and, hence, should not be relied upon for the
/// correctness of the application.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum blaze_symbolize_reason {
    /// Symbolization was successful.
    BLAZE_SYMBOLIZE_REASON_SUCCESS = 0,
    /// The absolute address was not found in the corresponding process'
    /// virtual memory map.
    BLAZE_SYMBOLIZE_REASON_UNMAPPED,
    /// The file offset does not map to a valid piece of code/data.
    BLAZE_SYMBOLIZE_REASON_INVALID_FILE_OFFSET,
    /// The `/proc/<pid>/maps` entry corresponding to the address does
    /// not have a component (file system path, object, ...) associated
    /// with it.
    BLAZE_SYMBOLIZE_REASON_MISSING_COMPONENT,
    /// The symbolization source has no or no relevant symbols.
    BLAZE_SYMBOLIZE_REASON_MISSING_SYMS,
    /// The address could not be found in the symbolization source.
    BLAZE_SYMBOLIZE_REASON_UNKNOWN_ADDR,
    /// The address belonged to an entity that is currently unsupported.
    BLAZE_SYMBOLIZE_REASON_UNSUPPORTED,
}

impl From<Reason> for blaze_symbolize_reason {
    fn from(reason: Reason) -> Self {
        use blaze_symbolize_reason::*;

        match reason {
            Reason::Unmapped => BLAZE_SYMBOLIZE_REASON_UNMAPPED,
            Reason::InvalidFileOffset => BLAZE_SYMBOLIZE_REASON_INVALID_FILE_OFFSET,
            Reason::MissingComponent => BLAZE_SYMBOLIZE_REASON_MISSING_COMPONENT,
            Reason::MissingSyms => BLAZE_SYMBOLIZE_REASON_MISSING_SYMS,
            Reason::Unsupported => BLAZE_SYMBOLIZE_REASON_UNSUPPORTED,
            Reason::UnknownAddr => BLAZE_SYMBOLIZE_REASON_UNKNOWN_ADDR,
            _ => unreachable!(),
        }
    }
}


/// Retrieve a textual representation of the reason of a symbolization
/// failure.
#[no_mangle]
pub extern "C" fn blaze_symbolize_reason_str(err: blaze_symbolize_reason) -> *const c_char {
    use blaze_symbolize_reason::*;

    match err as i32 {
        e if e == BLAZE_SYMBOLIZE_REASON_SUCCESS as i32 => b"success\0".as_ptr().cast(),
        e if e == BLAZE_SYMBOLIZE_REASON_UNMAPPED as i32 => {
            Reason::Unmapped.as_bytes().as_ptr().cast()
        }
        e if e == BLAZE_SYMBOLIZE_REASON_INVALID_FILE_OFFSET as i32 => {
            Reason::InvalidFileOffset.as_bytes().as_ptr().cast()
        }
        e if e == BLAZE_SYMBOLIZE_REASON_MISSING_COMPONENT as i32 => {
            Reason::MissingComponent.as_bytes().as_ptr().cast()
        }
        e if e == BLAZE_SYMBOLIZE_REASON_MISSING_SYMS as i32 => {
            Reason::MissingSyms.as_bytes().as_ptr().cast()
        }
        e if e == BLAZE_SYMBOLIZE_REASON_UNKNOWN_ADDR as i32 => {
            Reason::UnknownAddr.as_bytes().as_ptr().cast()
        }
        e if e == BLAZE_SYMBOLIZE_REASON_UNSUPPORTED as i32 => {
            Reason::Unsupported.as_bytes().as_ptr().cast()
        }
        _ => b"unknown reason\0".as_ptr().cast(),
    }
}


/// Source code location information for a symbol or inlined function.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_code_info {
    /// The directory in which the source file resides.
    ///
    /// This attribute is optional and may be NULL.
    pub dir: *const c_char,
    /// The file that defines the symbol.
    ///
    /// This attribute is optional and may be NULL.
    pub file: *const c_char,
    /// The line number on which the symbol is located in the source
    /// code.
    pub line: u32,
    /// The column number of the symbolized instruction in the source
    /// code.
    pub column: u16,
    /// Unused member available for future expansion.
    pub reserved: [u8; 10],
}


/// Data about an inlined function call.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolize_inlined_fn {
    /// The symbol name of the inlined function.
    pub name: *const c_char,
    /// Source code location information for the inlined function.
    pub code_info: blaze_symbolize_code_info,
    /// Unused member available for future expansion.
    pub reserved: [u8; 8],
}


/// The result of symbolization of an address.
///
/// A `blaze_sym` is the information of a symbol found for an
/// address.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_sym {
    /// The symbol name is where the given address should belong to.
    ///
    /// If an address could not be symbolized, this member will be NULL.
    /// Check the `reason` member for additional information pertaining
    /// the failure.
    pub name: *const c_char,
    /// The address at which the symbol is located (i.e., its "start").
    ///
    /// This is the "normalized" address of the symbol, as present in
    /// the file (and reported by tools such as `readelf(1)`,
    /// `llvm-gsymutil`, or similar).
    pub addr: Addr,
    /// The byte offset of the address that got symbolized from the
    /// start of the symbol (i.e., from `addr`).
    ///
    /// E.g., when symbolizing address 0x1337 of a function that starts at
    /// 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
    /// member is especially useful in contexts when input addresses are not
    /// already normalized, such as when symbolizing an address in a process
    /// context (which may have been relocated and/or have layout randomizations
    /// applied).
    pub offset: usize,
    /// The size of the symbol.
    ///
    /// If the symbol's size is not available, this member will be `-1`.
    /// Note that some symbol sources may not distinguish between
    /// "unknown" size and `0`. In that case the size will be reported
    /// as `0` here as well.
    pub size: isize,
    /// Source code location information for the symbol.
    pub code_info: blaze_symbolize_code_info,
    /// The number of symbolized inlined function calls present.
    pub inlined_cnt: usize,
    /// An array of `inlined_cnt` symbolized inlined function calls.
    pub inlined: *const blaze_symbolize_inlined_fn,
    /// On error (i.e., if `name` is NULL), a reason trying to explain
    /// why symbolization failed.
    pub reason: blaze_symbolize_reason,
    /// Unused member available for future expansion.
    pub reserved: [u8; 7],
}

/// `blaze_syms` is the result of symbolization of a list of addresses.
///
/// Instances of [`blaze_syms`] are returned by any of the `blaze_symbolize_*`
/// variants. They should be freed by calling [`blaze_syms_free`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_syms {
    /// The number of symbols being reported.
    pub cnt: usize,
    /// The symbols corresponding to input addresses.
    ///
    /// Symbolization happens based on the ordering of (input) addresses.
    /// Therefore, every input address has an associated symbol.
    pub syms: [blaze_sym; 0],
}

/// Create a `PathBuf` from a pointer of C string
///
/// # Safety
/// The provided `cstr` should be terminated with a NUL byte.
pub(crate) unsafe fn from_cstr(cstr: *const c_char) -> PathBuf {
    Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(cstr) }.to_bytes(),
    ))
    .to_path_buf()
}


/// Options for configuring [`blaze_symbolizer`] objects.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_symbolizer_opts {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// Array of debug directories to search for split debug information.
    ///
    /// These directories will be consulted (in given order) when resolving
    /// debug links in binaries. By default and when this member is NULL,
    /// `/usr/lib/debug` and `/lib/debug/` will be searched. Setting an array
    /// here will overwrite these defaults, so make sure to include these
    /// directories as desired.
    ///
    /// Note that the directory containing a symbolization source is always an
    /// implicit candidate target directory of the highest precedence.
    pub debug_dirs: *const *const c_char,
    /// The number of array elements in `debug_dirs`.
    pub debug_dirs_len: usize,
    /// Whether or not to automatically reload file system based
    /// symbolization sources that were updated since the last
    /// symbolization operation.
    pub auto_reload: bool,
    /// Whether to attempt to gather source code location information.
    ///
    /// This setting implies `debug_syms` (and forces it to `true`).
    pub code_info: bool,
    /// Whether to report inlined functions as part of symbolization.
    pub inlined_fns: bool,
    /// Whether or not to transparently demangle symbols.
    ///
    /// Demangling happens on a best-effort basis. Currently supported
    /// languages are Rust and C++ and the flag will have no effect if
    /// the underlying language does not mangle symbols (such as C).
    pub demangle: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 4],
}

impl Default for blaze_symbolizer_opts {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            debug_dirs: ptr::null(),
            debug_dirs_len: 0,
            auto_reload: false,
            code_info: false,
            inlined_fns: false,
            demangle: false,
            reserved: [0; 4],
        }
    }
}


/// Create an instance of a symbolizer.
///
/// C ABI compatible version of [`blazesym::symbolize::Symbolizer::new()`].
/// Please refer to its documentation for the default configuration in use.
///
/// On success, the function creates a new [`blaze_symbolizer`] object
/// and returns it. The resulting object should be released using
/// [`blaze_symbolizer_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
#[no_mangle]
pub extern "C" fn blaze_symbolizer_new() -> *mut blaze_symbolizer {
    let symbolizer = Symbolizer::new();
    let symbolizer_box = Box::new(symbolizer);
    let () = set_last_err(blaze_err::BLAZE_ERR_OK);
    Box::into_raw(symbolizer_box)
}

/// Create an instance of a symbolizer with configurable options.
///
/// On success, the function creates a new [`blaze_symbolizer`] object
/// and returns it. The resulting object should be released using
/// [`blaze_symbolizer_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `opts` needs to point to a valid [`blaze_symbolizer_opts`] object
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolizer_new_opts(
    opts: *const blaze_symbolizer_opts,
) -> *mut blaze_symbolizer {
    if !input_zeroed!(opts, blaze_symbolizer_opts) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null_mut()
    }
    let opts = input_sanitize!(opts, blaze_symbolizer_opts);

    let blaze_symbolizer_opts {
        type_size: _,
        debug_dirs,
        debug_dirs_len: _debug_dirs_len,
        auto_reload,
        code_info,
        inlined_fns,
        demangle,
        reserved: _,
    } = opts;

    let builder = Symbolizer::builder()
        .enable_auto_reload(auto_reload)
        .enable_code_info(code_info)
        .enable_inlined_fns(inlined_fns)
        .enable_demangling(demangle);

    let builder = if debug_dirs.is_null() {
        builder
    } else {
        #[cfg(feature = "dwarf")]
        {
            // SAFETY: The caller ensures that the pointer is valid and the count
            //         matches.
            let slice = unsafe { slice_from_user_array(debug_dirs, _debug_dirs_len) };
            let iter = slice.iter().map(|cstr| {
                Path::new(OsStr::from_bytes(
                    // SAFETY: The caller ensures that valid C strings are
                    //         provided.
                    unsafe { CStr::from_ptr(cstr.cast()) }.to_bytes(),
                ))
            });

            builder.set_debug_dirs(Some(iter))
        }

        #[cfg(not(feature = "dwarf"))]
        {
            builder
        }
    };

    let symbolizer = builder.build();
    let symbolizer_box = Box::new(symbolizer);
    let () = set_last_err(blaze_err::BLAZE_ERR_OK);
    Box::into_raw(symbolizer_box)
}

/// Free an instance of blazesym a symbolizer for C API.
///
/// # Safety
/// The pointer must have been returned by [`blaze_symbolizer_new`] or
/// [`blaze_symbolizer_new_opts`].
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolizer_free(symbolizer: *mut blaze_symbolizer) {
    if !symbolizer.is_null() {
        drop(unsafe { Box::from_raw(symbolizer) });
    }
}

fn code_info_strtab_size(code_info: &Option<CodeInfo>) -> usize {
    code_info
        .as_ref()
        .and_then(|info| info.dir.as_ref().map(|d| d.as_os_str().len() + 1))
        .unwrap_or(0)
        + code_info
            .as_ref()
            .map(|info| info.file.len() + 1)
            .unwrap_or(0)
}

fn inlined_fn_strtab_size(inlined_fn: &InlinedFn) -> usize {
    inlined_fn.name.len() + 1 + code_info_strtab_size(&inlined_fn.code_info)
}

fn sym_strtab_size(sym: &Sym) -> usize {
    sym.name.len()
        + 1
        + code_info_strtab_size(&sym.code_info)
        + sym
            .inlined
            .iter()
            .map(inlined_fn_strtab_size)
            .sum::<usize>()
}

fn convert_code_info(
    code_info_in: &Option<CodeInfo>,
    code_info_out: &mut blaze_symbolize_code_info,
    mut make_cstr: impl FnMut(&OsStr) -> *mut c_char,
) {
    code_info_out.dir = code_info_in
        .as_ref()
        .and_then(|info| info.dir.as_ref().map(|d| make_cstr(d.as_os_str())))
        .unwrap_or_else(ptr::null_mut);
    code_info_out.file = code_info_in
        .as_ref()
        .map(|info| make_cstr(&info.file))
        .unwrap_or_else(ptr::null_mut);
    code_info_out.line = code_info_in
        .as_ref()
        .and_then(|info| info.line)
        .unwrap_or(0);
    code_info_out.column = code_info_in
        .as_ref()
        .and_then(|info| info.column)
        .unwrap_or(0);
}

/// Convert [`Sym`] objects to [`blaze_syms`] ones.
///
/// The returned pointer should be released using [`blaze_syms_free`] once
/// usage concluded.
fn convert_symbolizedresults_to_c(results: Vec<Symbolized>) -> *const blaze_syms {
    // Allocate a buffer to contain a blaze_syms, all
    // blaze_sym, and C strings of symbol and path.
    let (strtab_size, inlined_fn_cnt) = results.iter().fold((0, 0), |acc, sym| match sym {
        Symbolized::Sym(sym) => (acc.0 + sym_strtab_size(sym), acc.1 + sym.inlined.len()),
        Symbolized::Unknown(..) => acc,
    });

    let buf_size = mem::size_of::<u64>()
        + strtab_size
        + mem::size_of::<blaze_syms>()
        + mem::size_of::<blaze_sym>() * results.len()
        + mem::size_of::<blaze_symbolize_inlined_fn>() * inlined_fn_cnt;
    let raw_buf_with_sz = unsafe { alloc(Layout::from_size_align(buf_size, 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null()
    }

    // prepend an u64 to keep the size of the buffer.
    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };

    let syms_ptr = raw_buf as *mut blaze_syms;
    let mut syms_last = unsafe { (*syms_ptr).syms.as_mut_slice().as_mut_ptr() };
    let mut inlined_last = unsafe {
        raw_buf.add(mem::size_of::<blaze_syms>() + mem::size_of::<blaze_sym>() * results.len())
    } as *mut blaze_symbolize_inlined_fn;
    let mut cstr_last = unsafe {
        raw_buf.add(
            mem::size_of::<blaze_syms>()
                + mem::size_of::<blaze_sym>() * results.len()
                + mem::size_of::<blaze_symbolize_inlined_fn>() * inlined_fn_cnt,
        )
    } as *mut c_char;

    let mut make_cstr = |src: &OsStr| {
        let cstr = cstr_last;
        unsafe { ptr::copy_nonoverlapping(src.as_bytes().as_ptr(), cstr as *mut u8, src.len()) };
        unsafe { *cstr.add(src.len()) = 0 };
        cstr_last = unsafe { cstr_last.add(src.len() + 1) };

        cstr
    };

    unsafe { (*syms_ptr).cnt = results.len() };

    // Convert all `Sym`s to `blazesym_sym`s.
    for sym in results {
        match sym {
            Symbolized::Sym(sym) => {
                let sym_ref = unsafe { &mut *syms_last };
                let name_ptr = make_cstr(OsStr::new(sym.name.as_ref()));

                sym_ref.name = name_ptr;
                sym_ref.addr = sym.addr;
                sym_ref.offset = sym.offset;
                sym_ref.size = sym
                    .size
                    .map(|size| isize::try_from(size).unwrap_or(isize::MAX))
                    .unwrap_or(-1);
                convert_code_info(&sym.code_info, &mut sym_ref.code_info, &mut make_cstr);
                sym_ref.inlined_cnt = sym.inlined.len();
                sym_ref.inlined = inlined_last;
                sym_ref.reason = blaze_symbolize_reason::BLAZE_SYMBOLIZE_REASON_SUCCESS;

                for inlined in sym.inlined.iter() {
                    let inlined_ref = unsafe { &mut *inlined_last };

                    let name_ptr = make_cstr(OsStr::new(inlined.name.as_ref()));
                    inlined_ref.name = name_ptr;
                    convert_code_info(
                        &inlined.code_info,
                        &mut inlined_ref.code_info,
                        &mut make_cstr,
                    );

                    inlined_last = unsafe { inlined_last.add(1) };
                }
            }
            Symbolized::Unknown(reason) => {
                // Unknown symbols/addresses are just represented with all
                // fields set to zero (except for reason).
                // SAFETY: `syms_last` is pointing to a writable and properly
                //         aligned `blaze_sym` object.
                let () = unsafe { syms_last.write_bytes(0, 1) };
                let sym_ref = unsafe { &mut *syms_last };
                sym_ref.reason = reason.into();
            }
        }

        syms_last = unsafe { syms_last.add(1) };
    }

    syms_ptr
}

unsafe fn blaze_symbolize_impl(
    symbolizer: *mut blaze_symbolizer,
    src: Source<'_>,
    inputs: Input<*const u64>,
    input_cnt: usize,
) -> *const blaze_syms {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let addrs = unsafe { slice_from_user_array(*inputs.as_inner_ref(), input_cnt) };

    let input = match inputs {
        Input::AbsAddr(..) => Input::AbsAddr(addrs.deref()),
        Input::VirtOffset(..) => Input::VirtOffset(addrs.deref()),
        Input::FileOffset(..) => Input::FileOffset(addrs.deref()),
    };

    let result = symbolizer.symbolize(&src, input);
    match result {
        Ok(results) if results.is_empty() => {
            let () = set_last_err(blaze_err::BLAZE_ERR_OK);
            ptr::null()
        }
        Ok(results) => {
            let result = convert_symbolizedresults_to_c(results);
            if result.is_null() {
                let () = set_last_err(blaze_err::BLAZE_ERR_OUT_OF_MEMORY);
            } else {
                let () = set_last_err(blaze_err::BLAZE_ERR_OK);
            }
            result
        }
        Err(err) => {
            let () = set_last_err(err.kind().into());
            ptr::null_mut()
        }
    }
}


/// Symbolize a list of process absolute addresses.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `abs_addr_cnt` [`blaze_sym`] objects. The returned object
/// should be released using [`blaze_syms_free`] once it is no longer
/// needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_process`] object
/// - `abs_addrs` point to an array of `abs_addr_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_process_abs_addrs(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_process,
    abs_addrs: *const Addr,
    abs_addr_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_process) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_process);
    let src = Source::from(Process::from(src));

    unsafe { blaze_symbolize_impl(symbolizer, src, Input::AbsAddr(abs_addrs), abs_addr_cnt) }
}


/// Symbolize a list of kernel absolute addresses.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `abs_addr_cnt` [`blaze_sym`] objects. The returned object
/// should be released using [`blaze_syms_free`] once it is no longer
/// needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_kernel`] object
/// - `abs_addrs` point to an array of `abs_addr_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_kernel_abs_addrs(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_kernel,
    abs_addrs: *const Addr,
    abs_addr_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_kernel) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_kernel);
    let src = Source::from(Kernel::from(src));

    unsafe { blaze_symbolize_impl(symbolizer, src, Input::AbsAddr(abs_addrs), abs_addr_cnt) }
}


/// Symbolize virtual offsets in an ELF file.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `virt_offset_cnt` [`blaze_sym`] objects. The returned
/// object should be released using [`blaze_syms_free`] once it is no
/// longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_elf`] object
/// - `virt_offsets` point to an array of `virt_offset_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_elf_virt_offsets(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_elf,
    virt_offsets: *const Addr,
    virt_offset_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_elf) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_elf);
    let src = Source::from(Elf::from(src));

    unsafe {
        blaze_symbolize_impl(
            symbolizer,
            src,
            Input::VirtOffset(virt_offsets),
            virt_offset_cnt,
        )
    }
}

/// Symbolize file offsets in an ELF file.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `file_offset_cnt` [`blaze_sym`] objects. The returned
/// object should be released using [`blaze_syms_free`] once it is no
/// longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_elf`] object
/// - `file_offsets` point to an array of `file_offset_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_elf_file_offsets(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_elf,
    file_offsets: *const Addr,
    file_offset_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_elf) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_elf);
    let src = Source::from(Elf::from(src));

    unsafe {
        blaze_symbolize_impl(
            symbolizer,
            src,
            Input::FileOffset(file_offsets),
            file_offset_cnt,
        )
    }
}


/// Symbolize virtual offsets using "raw" Gsym data.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `virt_offset_cnt` [`blaze_sym`] objects. The returned
/// object should be released using [`blaze_syms_free`] once it is no
/// longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_gsym_data`] object
/// - `virt_offsets` point to an array of `virt_offset_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_gsym_data_virt_offsets(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_gsym_data,
    virt_offsets: *const Addr,
    virt_offset_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_gsym_data) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_gsym_data);
    let src = Source::from(GsymData::from(src));
    unsafe {
        blaze_symbolize_impl(
            symbolizer,
            src,
            Input::VirtOffset(virt_offsets),
            virt_offset_cnt,
        )
    }
}


/// Symbolize virtual offsets in a Gsym file.
///
/// On success, the function returns a [`blaze_syms`] containing an
/// array of `virt_offset_cnt` [`blaze_sym`] objects. The returned
/// object should be released using [`blaze_syms_free`] once it is no
/// longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `symbolizer` needs to point to a valid [`blaze_symbolizer`] object
/// - `src` needs to point to a valid [`blaze_symbolize_src_gsym_file`] object
/// - `virt_offsets` point to an array of `virt_offset_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_symbolize_gsym_file_virt_offsets(
    symbolizer: *mut blaze_symbolizer,
    src: *const blaze_symbolize_src_gsym_file,
    virt_offsets: *const Addr,
    virt_offset_cnt: usize,
) -> *const blaze_syms {
    if !input_zeroed!(src, blaze_symbolize_src_gsym_file) {
        let () = set_last_err(blaze_err::BLAZE_ERR_INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_symbolize_src_gsym_file);
    let src = Source::from(GsymFile::from(src));

    unsafe {
        blaze_symbolize_impl(
            symbolizer,
            src,
            Input::VirtOffset(virt_offsets),
            virt_offset_cnt,
        )
    }
}


/// Free an array returned by any of the `blaze_symbolize_*` variants.
///
/// # Safety
/// The pointer must have been returned by any of the `blaze_symbolize_*`
/// variants.
#[no_mangle]
pub unsafe extern "C" fn blaze_syms_free(syms: *const blaze_syms) {
    if syms.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize;
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::fs::copy;
    use std::fs::read as read_file;
    use std::hint::black_box;
    use std::io::Error;
    use std::os::unix::ffi::OsStringExt as _;
    use std::slice;

    use blazesym::inspect;
    use blazesym::normalize;
    use blazesym::symbolize::Reason;
    use blazesym::Pid;

    use tempfile::tempdir;

    use test_tag::tag;

    use crate::blaze_err_last;


    /// Check that various types have expected sizes.
    #[tag(miri)]
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn type_sizes() {
        assert_eq!(mem::size_of::<blaze_symbolize_src_elf>(), 24);
        assert_eq!(mem::size_of::<blaze_symbolize_src_kernel>(), 32);
        assert_eq!(mem::size_of::<blaze_symbolize_src_process>(), 16);
        assert_eq!(mem::size_of::<blaze_symbolize_src_gsym_data>(), 24);
        assert_eq!(mem::size_of::<blaze_symbolize_src_gsym_file>(), 16);
        assert_eq!(mem::size_of::<blaze_symbolizer_opts>(), 32);
        assert_eq!(mem::size_of::<blaze_symbolize_code_info>(), 32);
        assert_eq!(mem::size_of::<blaze_symbolize_inlined_fn>(), 48);
        assert_eq!(mem::size_of::<blaze_sym>(), 88);
    }

    /// Exercise the `Debug` representation of various types.
    #[tag(miri)]
    #[test]
    fn debug_repr() {
        let elf = blaze_symbolize_src_elf {
            type_size: 24,
            ..Default::default()
        };
        assert_eq!(
            format!("{elf:?}"),
            "blaze_symbolize_src_elf { type_size: 24, path: 0x0, debug_syms: false, reserved: [0, 0, 0, 0, 0, 0, 0] }"
        );

        let kernel = blaze_symbolize_src_kernel {
            type_size: 32,
            debug_syms: true,
            ..Default::default()
        };
        assert_eq!(
            format!("{kernel:?}"),
            "blaze_symbolize_src_kernel { type_size: 32, kallsyms: 0x0, kernel_image: 0x0, debug_syms: true, reserved: [0, 0, 0, 0, 0, 0, 0] }"
        );

        let process = blaze_symbolize_src_process {
            type_size: 16,
            pid: 1337,
            debug_syms: true,
            ..Default::default()
        };
        assert_eq!(
            format!("{process:?}"),
            "blaze_symbolize_src_process { type_size: 16, pid: 1337, debug_syms: true, perf_map: false, map_files: false, reserved: [0] }"
        );

        let gsym_data = blaze_symbolize_src_gsym_data {
            type_size: 24,
            data: ptr::null(),
            data_len: 0,
            reserved: (),
        };
        assert_eq!(
            format!("{gsym_data:?}"),
            "blaze_symbolize_src_gsym_data { type_size: 24, data: 0x0, data_len: 0, reserved: () }"
        );

        let gsym_file = blaze_symbolize_src_gsym_file {
            type_size: 16,
            path: ptr::null(),
            reserved: (),
        };
        assert_eq!(
            format!("{gsym_file:?}"),
            "blaze_symbolize_src_gsym_file { type_size: 16, path: 0x0, reserved: () }"
        );

        let sym = blaze_sym {
            name: ptr::null(),
            addr: 0x1337,
            offset: 24,
            size: 16,
            code_info: blaze_symbolize_code_info {
                dir: ptr::null(),
                file: ptr::null(),
                line: 42,
                column: 1,
                reserved: [0u8; 10],
            },
            inlined_cnt: 0,
            inlined: ptr::null(),
            reason: blaze_symbolize_reason::BLAZE_SYMBOLIZE_REASON_UNSUPPORTED,
            reserved: [0u8; 7],
        };
        assert_eq!(
            format!("{sym:?}"),
            "blaze_sym { name: 0x0, addr: 4919, offset: 24, size: 16, code_info: blaze_symbolize_code_info { dir: 0x0, file: 0x0, line: 42, column: 1, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, inlined_cnt: 0, inlined: 0x0, reason: BLAZE_SYMBOLIZE_REASON_UNSUPPORTED, reserved: [0, 0, 0, 0, 0, 0, 0] }"
        );

        let inlined = blaze_symbolize_inlined_fn {
            name: ptr::null(),
            code_info: blaze_symbolize_code_info {
                dir: ptr::null(),
                file: ptr::null(),
                line: 42,
                column: 1,
                reserved: [0u8; 10],
            },
            reserved: [0u8; 8],
        };
        assert_eq!(
            format!("{inlined:?}"),
            "blaze_symbolize_inlined_fn { name: 0x0, code_info: blaze_symbolize_code_info { dir: 0x0, file: 0x0, line: 42, column: 1, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, reserved: [0, 0, 0, 0, 0, 0, 0, 0] }"
        );

        let syms = blaze_syms { cnt: 0, syms: [] };
        assert_eq!(format!("{syms:?}"), "blaze_syms { cnt: 0, syms: [] }");

        let opts = blaze_symbolizer_opts {
            type_size: 16,
            demangle: true,
            ..Default::default()
        };
        assert_eq!(
            format!("{opts:?}"),
            "blaze_symbolizer_opts { type_size: 16, debug_dirs: 0x0, debug_dirs_len: 0, auto_reload: false, code_info: false, inlined_fns: false, demangle: true, reserved: [0, 0, 0, 0] }"
        );
    }

    /// Make sure that we can stringify symbolization reasons as expected.
    #[tag(miri)]
    #[test]
    fn reason_stringification() {
        use blaze_symbolize_reason::*;

        let data = [
            (Reason::Unmapped, BLAZE_SYMBOLIZE_REASON_UNMAPPED),
            (
                Reason::InvalidFileOffset,
                BLAZE_SYMBOLIZE_REASON_INVALID_FILE_OFFSET,
            ),
            (
                Reason::MissingComponent,
                BLAZE_SYMBOLIZE_REASON_MISSING_COMPONENT,
            ),
            (Reason::MissingSyms, BLAZE_SYMBOLIZE_REASON_MISSING_SYMS),
            (Reason::Unsupported, BLAZE_SYMBOLIZE_REASON_UNSUPPORTED),
            (Reason::UnknownAddr, BLAZE_SYMBOLIZE_REASON_UNKNOWN_ADDR),
        ];

        for (reason, expected) in data {
            assert_eq!(blaze_symbolize_reason::from(reason), expected);
            let cstr = unsafe { CStr::from_ptr(blaze_symbolize_reason_str(expected)) };
            let expected = CStr::from_bytes_with_nul(reason.as_bytes()).unwrap();
            assert_eq!(cstr, expected);
        }
    }


    /// Check that we can convert a [`blaze_symbolize_src_kernel`]
    /// reference into a [`Kernel`].
    #[tag(miri)]
    #[test]
    fn kernel_conversion() {
        let kernel = blaze_symbolize_src_kernel::default();
        let kernel = Kernel::from(kernel);
        assert_eq!(kernel.kallsyms, None);
        assert_eq!(kernel.kernel_image, None);

        let kernel = blaze_symbolize_src_kernel {
            kallsyms: b"/proc/kallsyms\0" as *const _ as *const c_char,
            kernel_image: b"/boot/image\0" as *const _ as *const c_char,
            debug_syms: false,
            ..Default::default()
        };

        let kernel = Kernel::from(kernel);
        assert_eq!(kernel.kallsyms, Some(PathBuf::from("/proc/kallsyms")));
        assert_eq!(kernel.kernel_image, Some(PathBuf::from("/boot/image")));
    }

    /// Test the Rust to C symbol conversion.
    #[tag(miri)]
    #[test]
    fn symbol_conversion() {
        fn touch<X: Clone>(x: &X) {
            let x = x.clone();
            let _x = black_box(x);
        }

        fn touch_cstr(s: *const c_char) {
            if !s.is_null() {
                let s = unsafe { CStr::from_ptr(s) }.to_bytes();
                let _x = black_box(s);
            }
        }

        fn touch_code_info(code_info: &blaze_symbolize_code_info) {
            let blaze_symbolize_code_info {
                dir,
                file,
                line,
                column,
                reserved: _,
            } = code_info;

            let _x = touch_cstr(*dir);
            let _x = touch_cstr(*file);
            let _x = touch(line);
            let _x = touch(column);
        }

        /// Touch all "members" of a [`blaze_syms`].
        fn touch_syms(syms: *const blaze_syms) {
            let syms = unsafe { &*syms };
            for i in 0..syms.cnt {
                let sym = unsafe { &*syms.syms.as_slice().as_ptr().add(i) };
                let blaze_sym {
                    name,
                    addr,
                    offset,
                    size,
                    code_info,
                    inlined_cnt,
                    inlined,
                    reason,
                    reserved: _,
                } = sym;

                let () = touch_cstr(*name);
                let _x = touch(addr);
                let _x = touch(offset);
                let _x = touch(size);
                let () = touch_code_info(code_info);

                for j in 0..*inlined_cnt {
                    let inlined_fn = unsafe { &*inlined.add(j) };
                    let blaze_symbolize_inlined_fn {
                        name,
                        code_info,
                        reserved: _,
                    } = inlined_fn;
                    let () = touch_cstr(*name);
                    let () = touch_code_info(code_info);
                }
                let () = touch(reason);
            }
        }

        // Empty list of symbols.
        let results = vec![];
        let syms = convert_symbolizedresults_to_c(results);
        assert!(!syms.is_null());

        let () = touch_syms(syms);
        let () = unsafe { blaze_syms_free(syms) };

        // A single symbol with inlined function information.
        let results = vec![Symbolized::Sym(Sym {
            name: "test".into(),
            addr: 0x1337,
            offset: 0x1338,
            size: Some(42),
            code_info: Some(CodeInfo {
                dir: None,
                file: OsStr::new("a-file").into(),
                line: Some(42),
                column: Some(43),
                _non_exhaustive: (),
            }),
            inlined: vec![InlinedFn {
                name: "inlined_fn".into(),
                code_info: Some(CodeInfo {
                    dir: Some(Path::new("/some/dir").into()),
                    file: OsStr::new("another-file").into(),
                    line: Some(42),
                    column: Some(43),
                    _non_exhaustive: (),
                }),
                _non_exhaustive: (),
            }]
            .into_boxed_slice(),
            _non_exhaustive: (),
        })];
        let syms = convert_symbolizedresults_to_c(results);
        assert!(!syms.is_null());
        let () = touch_syms(syms);
        let () = unsafe { blaze_syms_free(syms) };

        // One symbol and some unsymbolized values.
        let results = vec![
            Symbolized::Unknown(Reason::UnknownAddr),
            Symbolized::Sym(Sym {
                name: "test".into(),
                addr: 0x1337,
                offset: 0x1338,
                size: None,
                code_info: None,
                inlined: vec![InlinedFn {
                    name: "inlined_fn".into(),
                    code_info: None,
                    _non_exhaustive: (),
                }]
                .into_boxed_slice(),
                _non_exhaustive: (),
            }),
            Symbolized::Unknown(Reason::InvalidFileOffset),
        ];
        let syms = convert_symbolizedresults_to_c(results);
        assert!(!syms.is_null());
        let () = touch_syms(syms);
        let () = unsafe { blaze_syms_free(syms) };
    }

    /// Make sure that we can create and free a symbolizer instance.
    #[tag(miri)]
    #[test]
    fn symbolizer_creation() {
        let symbolizer = blaze_symbolizer_new();
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Make sure that we can create and free a symbolizer instance with the
    /// provided options.
    #[tag(miri)]
    #[test]
    fn symbolizer_creation_with_opts() {
        let opts = blaze_symbolizer_opts {
            demangle: true,
            ..Default::default()
        };

        let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Make sure that we can symbolize an address using ELF, DWARF, and
    /// GSYM.
    #[test]
    fn symbolize_elf_dwarf_gsym() {
        fn test<F>(symbolize: F, has_code_info: bool)
        where
            F: FnOnce(*mut blaze_symbolizer, *const Addr, usize) -> *const blaze_syms,
        {
            let symbolizer = blaze_symbolizer_new();
            let addrs = [0x2000100];
            let result = symbolize(symbolizer, addrs.as_ptr(), addrs.len());

            assert!(!result.is_null());

            let result = unsafe { &*result };
            assert_eq!(result.cnt, 1);
            let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
            let sym = &syms[0];
            assert_eq!(
                unsafe { CStr::from_ptr(sym.name) },
                CStr::from_bytes_with_nul(b"factorial\0").unwrap()
            );
            assert_eq!(
                sym.reason,
                blaze_symbolize_reason::BLAZE_SYMBOLIZE_REASON_SUCCESS
            );
            assert_eq!(sym.addr, 0x2000100);
            assert_eq!(sym.offset, 0);
            assert!(sym.size > 0);

            if has_code_info {
                assert!(!sym.code_info.dir.is_null());
                assert!(!sym.code_info.file.is_null());
                assert_eq!(
                    unsafe { CStr::from_ptr(sym.code_info.file) },
                    CStr::from_bytes_with_nul(b"test-stable-addrs.c\0").unwrap()
                );
                assert_eq!(sym.code_info.line, 10);
            } else {
                assert!(sym.code_info.dir.is_null());
                assert!(sym.code_info.file.is_null());
                assert_eq!(sym.code_info.line, 0);
            }

            let () = unsafe { blaze_syms_free(result) };
            let () = unsafe { blaze_symbolizer_free(symbolizer) };
        }

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
            debug_syms: true,
            ..Default::default()
        };

        let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
            blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs, addr_cnt)
        };
        test(symbolize, false);

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-stripped-elf-with-dwarf.bin");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
            debug_syms: true,
            ..Default::default()
        };

        let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
            blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs, addr_cnt)
        };
        test(symbolize, true);

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs.gsym");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let gsym_src = blaze_symbolize_src_gsym_file {
            path: path_c.as_ptr(),
            ..Default::default()
        };

        let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
            blaze_symbolize_gsym_file_virt_offsets(symbolizer, &gsym_src, addrs, addr_cnt)
        };
        test(symbolize, true);

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs.gsym");
        let data = read_file(path).unwrap();
        let gsym_src = blaze_symbolize_src_gsym_data {
            data: data.as_ptr(),
            data_len: data.len(),
            ..Default::default()
        };

        let symbolize = |symbolizer, addrs, addr_cnt| unsafe {
            blaze_symbolize_gsym_data_virt_offsets(symbolizer, &gsym_src, addrs, addr_cnt)
        };
        test(symbolize, true);
    }


    /// Check that we can symbolize a file offset in an ELF file.
    #[test]
    fn symbolize_elf_file_offset() {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("libtest-so.so")
            .canonicalize()
            .unwrap();
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = normalize::Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs(Pid::Slf, [the_answer_addr as Addr].as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        assert_eq!(meta.as_elf().unwrap().path, test_so);

        let symbolizer = blaze_symbolizer_new();
        let elf_src = blaze_symbolize_src_elf {
            path: so_cstr.as_ptr(),
            ..Default::default()
        };
        let offsets = [output.0];
        let result = unsafe {
            blaze_symbolize_elf_file_offsets(
                symbolizer,
                &elf_src,
                offsets.as_slice().as_ptr(),
                offsets.len(),
            )
        };
        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);

        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        assert!(!sym.name.is_null());
        assert!(sym.size > 0);
        assert_eq!(
            unsafe { CStr::from_ptr(sym.name) },
            CStr::from_bytes_with_nul(b"the_answer\0").unwrap()
        );

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Symbolize an address inside a DWARF file, with and without
    /// auto-demangling enabled.
    #[test]
    fn symbolize_dwarf_demangle() {
        fn test(path: &Path, addr: Addr) -> Result<(), ()> {
            let opts = blaze_symbolizer_opts {
                code_info: true,
                inlined_fns: true,
                ..Default::default()
            };

            let path_c = CString::new(path.to_str().unwrap()).unwrap();
            let elf_src = blaze_symbolize_src_elf {
                path: path_c.as_ptr(),
                debug_syms: true,
                ..Default::default()
            };

            let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
            let addrs = [addr];
            let result = unsafe {
                blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
            };
            assert!(!result.is_null());

            let result = unsafe { &*result };
            assert_eq!(result.cnt, 1);
            let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
            let sym = &syms[0];
            let name = unsafe { CStr::from_ptr(sym.name) };
            assert!(
                name.to_str().unwrap().contains("test13test_function"),
                "{:?}",
                name
            );

            if sym.inlined_cnt == 0 {
                let () = unsafe { blaze_syms_free(result) };
                let () = unsafe { blaze_symbolizer_free(symbolizer) };
                return Err(())
            }

            assert_eq!(sym.inlined_cnt, 1);
            let name = unsafe { CStr::from_ptr((*sym.inlined).name) };
            assert!(
                name.to_str().unwrap().contains("test12inlined_call"),
                "{:?}",
                name
            );

            let () = unsafe { blaze_syms_free(result) };
            let () = unsafe { blaze_symbolizer_free(symbolizer) };

            // Do it again, this time with demangling enabled.
            let opts = blaze_symbolizer_opts {
                code_info: true,
                inlined_fns: true,
                demangle: true,
                ..Default::default()
            };

            let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };
            let addrs = [addr];
            let result = unsafe {
                blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
            };
            assert!(!result.is_null());

            let result = unsafe { &*result };
            assert_eq!(result.cnt, 1);
            let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
            let sym = &syms[0];
            assert_eq!(
                unsafe { CStr::from_ptr(sym.name) },
                CStr::from_bytes_with_nul(b"test::test_function\0").unwrap()
            );

            assert_eq!(sym.inlined_cnt, 1);
            assert_eq!(
                unsafe { CStr::from_ptr((*sym.inlined).name) },
                CStr::from_bytes_with_nul(b"test::inlined_call\0").unwrap()
            );

            let () = unsafe { blaze_syms_free(result) };
            let () = unsafe { blaze_symbolizer_free(symbolizer) };
            Ok(())
        }

        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-rs.bin");
        let elf = inspect::Elf::new(&test_dwarf);
        let src = inspect::Source::Elf(elf);

        let inspector = inspect::Inspector::new();
        let results = inspector
            .lookup(&src, &["_RNvCs69hjMPjVIJK_4test13test_function"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert!(!results.is_empty());

        let addr = results[0].addr;
        let src = Source::Elf(Elf::new(&test_dwarf));
        let symbolizer = Symbolizer::builder().enable_demangling(false).build();
        let result = symbolizer
            .symbolize_single(&src, Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        let addr = result.addr;
        let size = result.size.unwrap() as u64;
        for inst_addr in addr..addr + size {
            if test(&test_dwarf, inst_addr).is_ok() {
                return
            }
        }

        panic!("failed to find inlined function call");
    }

    /// Make sure that we can symbolize an address in a process.
    #[test]
    fn symbolize_in_process() {
        let process_src = blaze_symbolize_src_process {
            pid: 0,
            debug_syms: true,
            perf_map: true,
            ..Default::default()
        };

        let symbolizer = blaze_symbolizer_new();
        let addrs = [blaze_symbolizer_new as Addr];
        let result = unsafe {
            blaze_symbolize_process_abs_addrs(symbolizer, &process_src, addrs.as_ptr(), addrs.len())
        };

        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        assert_eq!(
            unsafe { CStr::from_ptr(sym.name) },
            CStr::from_bytes_with_nul(b"blaze_symbolizer_new\0").unwrap()
        );

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Make sure that we can symbolize an address in the kernel via
    /// kallsyms.
    #[test]
    fn symbolize_in_kernel() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("kallsyms");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let src = blaze_symbolize_src_kernel {
            kallsyms: path_c.as_ptr(),
            ..Default::default()
        };

        let symbolizer = blaze_symbolizer_new();
        let addrs = [0xc080a470];
        let result = unsafe {
            blaze_symbolize_kernel_abs_addrs(symbolizer, &src, addrs.as_ptr(), addrs.len())
        };

        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        assert_eq!(
            unsafe { CStr::from_ptr(sym.name) },
            CStr::from_bytes_with_nul(b"init_task\0").unwrap()
        );

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Check that we report the expected error when attempting to
    /// symbolize data using a non-existent source.
    #[test]
    fn symbolize_elf_non_existent() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("does-not-actually-exist.bin");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
            debug_syms: true,
            ..Default::default()
        };

        let symbolizer = blaze_symbolizer_new();
        let addrs = [blaze_symbolizer_new as Addr];
        let result = unsafe {
            blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
        };
        assert!(result.is_null());
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_NOT_FOUND);

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Check that we can handle no configured debug directories.
    #[test]
    fn symbolize_no_debug_dirs() {
        let dir = tempdir().unwrap();
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-stripped-with-link.bin");
        let dst = dir.path().join("test-stable-addrs-stripped-with-link.bin");
        let _count = copy(path, &dst).unwrap();

        let debug_dirs = [];
        let opts = blaze_symbolizer_opts {
            debug_dirs: debug_dirs.as_ptr(),
            debug_dirs_len: debug_dirs.len(),
            code_info: true,
            inlined_fns: true,
            demangle: true,
            ..Default::default()
        };
        let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };

        let path_c = CString::new(dst.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
            debug_syms: true,
            ..Default::default()
        };
        let addrs = [0x2000100];
        let result = unsafe {
            blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
        };
        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        // Shouldn't have symbolized because the debug link target cannot be
        // found.
        assert_eq!(sym.name, ptr::null());
        assert_eq!(
            sym.reason,
            blaze_symbolize_reason::BLAZE_SYMBOLIZE_REASON_MISSING_SYMS
        );

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }

    /// Make sure that debug directories are configurable.
    #[test]
    fn symbolize_configurable_debug_dirs() {
        let debug_dir1 = tempdir().unwrap();
        let debug_dir1_c = CString::new(debug_dir1.path().to_str().unwrap()).unwrap();
        let debug_dir2 = tempdir().unwrap();
        let debug_dir2_c = CString::new(debug_dir2.path().to_str().unwrap()).unwrap();

        let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-dwarf-only.dbg");
        let dst = debug_dir2.path().join("test-stable-addrs-dwarf-only.dbg");
        let _count = copy(src, dst).unwrap();

        let debug_dirs = [debug_dir1_c.as_ptr(), debug_dir2_c.as_ptr()];
        let opts = blaze_symbolizer_opts {
            debug_dirs: debug_dirs.as_ptr(),
            debug_dirs_len: debug_dirs.len(),
            code_info: true,
            inlined_fns: true,
            demangle: true,
            ..Default::default()
        };
        let symbolizer = unsafe { blaze_symbolizer_new_opts(&opts) };

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-stripped-with-link.bin");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();
        let elf_src = blaze_symbolize_src_elf {
            path: path_c.as_ptr(),
            debug_syms: true,
            ..Default::default()
        };
        let addrs = [0x2000100];
        let result = unsafe {
            blaze_symbolize_elf_virt_offsets(symbolizer, &elf_src, addrs.as_ptr(), addrs.len())
        };
        assert!(!result.is_null());

        let result = unsafe { &*result };
        assert_eq!(result.cnt, 1);
        let syms = unsafe { slice::from_raw_parts(result.syms.as_ptr(), result.cnt) };
        let sym = &syms[0];
        let name = unsafe { CStr::from_ptr(sym.name) };
        assert_eq!(name.to_str().unwrap(), "factorial");

        let () = unsafe { blaze_syms_free(result) };
        let () = unsafe { blaze_symbolizer_free(symbolizer) };
    }
}
