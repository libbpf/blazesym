use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::ptr;
use std::ptr::NonNull;
use std::slice;

use crate::cfg;
use crate::log::error;
use crate::log::warn;
use crate::Addr;
use crate::BlazeSymbolizer;
use crate::FindAddrFeature;
use crate::SymbolInfo;
use crate::SymbolSrcCfg;
use crate::SymbolType;
use crate::SymbolizedResult;
use crate::SymbolizerFeature;


/// "Safely" create a slice from a user provided array.
unsafe fn slice_from_user_array<'t, T>(items: *const T, num_items: usize) -> &'t [T] {
    let items = if items.is_null() {
        // `slice::from_raw_parts` requires a properly aligned non-NULL pointer.
        // Craft one.
        NonNull::dangling().as_ptr()
    } else {
        items
    };
    unsafe { slice::from_raw_parts(items, num_items) }
}

/// Types of symbol sources and debug information for C API.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
#[derive(Debug)]
pub enum blazesym_src_type {
    /// Symbols and debug information from an ELF file.
    BLAZESYM_SRC_T_ELF,
    /// Symbols and debug information from a kernel image and its kallsyms.
    BLAZESYM_SRC_T_KERNEL,
    /// Symbols and debug information from a process, including loaded object files.
    BLAZESYM_SRC_T_PROCESS,
    /// Symbols and debug information from a gsym file.
    BLAZESYM_SRC_T_GSYM,
}

/// The parameters to load symbols and debug information from an ELF.
///
/// Describes the path and address of an ELF file loaded in a
/// process.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_ssc_elf {
    /// The file name of an ELF file.
    ///
    /// It can be an executable or shared object.
    /// For example, passing "/bin/sh" will load symbols and debug information from `sh`.
    /// Whereas passing "/lib/libc.so.xxx" will load symbols and debug information from the libc.
    pub file_name: *const c_char,
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

/// The parameters to load symbols and debug information from a gsym file.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_ssc_gsym {
    /// The file name of a gsym file.
    pub file_name: *const c_char,
    /// The base address is where the file's executable segment(s) is loaded.
    pub base_address: Addr,
}

/// Parameters of a symbol source.
#[repr(C)]
pub union blazesym_ssc_params {
    /// The variant for [`blazesym_src_type::BLAZESYM_SRC_T_ELF`].
    pub elf: mem::ManuallyDrop<blazesym_ssc_elf>,
    /// The variant for [`blazesym_src_type::BLAZESYM_SRC_T_KERNEL`].
    pub kernel: mem::ManuallyDrop<blazesym_ssc_kernel>,
    /// The variant for [`blazesym_src_type::BLAZESYM_SRC_T_PROCESS`].
    pub process: mem::ManuallyDrop<blazesym_ssc_process>,
    /// The variant for [`blazesym_src_type::BLAZESYM_SRC_T_GSYM`].
    pub gsym: mem::ManuallyDrop<blazesym_ssc_gsym>,
}

impl Debug for blazesym_ssc_params {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blazesym_ssc_params)).finish()
    }
}


/// Description of a source of symbols and debug information for C API.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_sym_src_cfg {
    /// A type of symbol source.
    pub src_type: blazesym_src_type,
    pub params: blazesym_ssc_params,
}

impl From<&blazesym_sym_src_cfg> for SymbolSrcCfg {
    fn from(cfg: &blazesym_sym_src_cfg) -> Self {
        match cfg.src_type {
            blazesym_src_type::BLAZESYM_SRC_T_ELF => {
                // SAFETY: `elf` is the union variant used for `BLAZESYM_SRC_T_ELF`.
                let elf = unsafe { &cfg.params.elf };
                SymbolSrcCfg::Elf(cfg::Elf {
                    file_name: unsafe { from_cstr(elf.file_name) },
                    base_address: elf.base_address,
                })
            }
            blazesym_src_type::BLAZESYM_SRC_T_KERNEL => {
                // SAFETY: `kernel` is the union variant used for `BLAZESYM_SRC_T_KERNEL`.
                let kernel = unsafe { &cfg.params.kernel };
                let kallsyms = kernel.kallsyms;
                let kernel_image = kernel.kernel_image;
                SymbolSrcCfg::Kernel(cfg::Kernel {
                    kallsyms: if !kallsyms.is_null() {
                        Some(unsafe { from_cstr(kallsyms) })
                    } else {
                        None
                    },
                    kernel_image: if !kernel_image.is_null() {
                        Some(unsafe { from_cstr(kernel_image) })
                    } else {
                        None
                    },
                })
            }
            blazesym_src_type::BLAZESYM_SRC_T_PROCESS => {
                // SAFETY: `process` is the union variant used for `BLAZESYM_SRC_T_PROCESS`.
                let pid = unsafe { cfg.params.process.pid };
                SymbolSrcCfg::Process(cfg::Process {
                    pid: if pid > 0 { Some(pid) } else { None },
                })
            }
            blazesym_src_type::BLAZESYM_SRC_T_GSYM => {
                // SAFETY: `gsym` is the union variant used for `BLAZESYM_SRC_T_GSYM`.
                let gsym = unsafe { &cfg.params.gsym };
                SymbolSrcCfg::Gsym(cfg::Gsym {
                    file_name: unsafe { from_cstr(gsym.file_name) },
                    base_address: gsym.base_address,
                })
            }
        }
    }
}


/// Names of the BlazeSym features.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
#[derive(Debug)]
pub enum blazesym_feature_name {
    /// Enable or disable returning line numbers of addresses.
    ///
    /// Users should set `blazesym_feature.params.enable` to enable or
    /// disable the feature.
    BLAZESYM_LINE_NUMBER_INFO,
    /// Enable or disable loading symbols from DWARF.
    ///
    /// Users should set `blazesym_feature.params.enable` to enable or
    /// disable the feature. This feature is disabled by default.
    BLAZESYM_DEBUG_INFO_SYMBOLS,
}

#[repr(C)]
pub union blazesym_feature_params {
    pub enable: bool,
}

impl Debug for blazesym_feature_params {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blazesym_feature_params))
            // SAFETY: There is only one variant.
            .field("enable", &unsafe { self.enable })
            .finish()
    }
}

/// Setting of the blazesym features.
///
/// Contain parameters to enable, disable, or customize a feature.
#[repr(C)]
#[derive(Debug)]
pub struct blazesym_feature {
    pub feature: blazesym_feature_name,
    pub params: blazesym_feature_params,
}

/// A placeholder symbolizer for C API.
///
/// It is returned by [`blazesym_new()`] and should be free by
/// [`blazesym_free()`].
#[allow(non_camel_case_types)]
type blazesym = BlazeSymbolizer;

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
    pub start_address: Addr,
    /// The path of the source code defines the symbol.
    pub path: *const c_char,
    /// The instruction of the address is in the line number of the source code.
    pub line_no: usize,
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
/// The instances of blazesym_result are returned from
/// [`blazesym_symbolize()`].  They should be free by calling
/// [`blazesym_result_free()`].
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
///
/// C string should be terminated with a null byte.
unsafe fn from_cstr(cstr: *const c_char) -> PathBuf {
    PathBuf::from(unsafe { CStr::from_ptr(cstr) }.to_str().unwrap())
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_new() -> *mut blazesym {
    let symbolizer = match BlazeSymbolizer::new() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let symbolizer_box = Box::new(symbolizer);
    Box::into_raw(symbolizer_box)
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_new_opts(
    features: *const blazesym_feature,
    nfeatures: usize,
) -> *mut blazesym {
    // SAFETY: The caller needs to ensure that `features` is a valid pointer and
    //         that it points to `nfeatures` elements.
    let features_v = unsafe { slice_from_user_array(features, nfeatures) };
    let features_r = features_v
        .iter()
        .map(|x| -> SymbolizerFeature {
            match x.feature {
                blazesym_feature_name::BLAZESYM_LINE_NUMBER_INFO => {
                    SymbolizerFeature::LineNumberInfo(unsafe { x.params.enable })
                }
                blazesym_feature_name::BLAZESYM_DEBUG_INFO_SYMBOLS => {
                    SymbolizerFeature::DebugInfoSymbols(unsafe { x.params.enable })
                }
            }
        })
        .collect::<Vec<_>>();

    let symbolizer = match BlazeSymbolizer::new_opt(&features_r) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let symbolizer_box = Box::new(symbolizer);
    Box::into_raw(symbolizer_box)
}

/// Free an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_new()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_free(symbolizer: *mut blazesym) {
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
        acc + result.symbol.len() + result.path.len() + 2
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

    let mut make_cstr = |src: &str| {
        let cstr = cstr_last;
        unsafe { ptr::copy(src.as_ptr(), cstr as *mut u8, src.len()) };
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
            let symbol_ptr = make_cstr(&r.symbol);

            let path_ptr = make_cstr(&r.path);

            let csym_ref = unsafe { &mut *csym_last };
            csym_ref.symbol = symbol_ptr;
            csym_ref.start_address = r.start_address;
            csym_ref.path = path_ptr;
            csym_ref.line_no = r.line_no;
            csym_ref.column = r.column;

            csym_last = unsafe { csym_last.add(1) };
        }
    }

    result_ptr
}

/// Symbolize addresses with the sources of symbols and debug info.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses.  The caller should free the returned
/// array by calling [`blazesym_result_free()`].
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_symbolize(
    symbolizer: *mut blazesym,
    sym_srcs: *const blazesym_sym_src_cfg,
    sym_srcs_len: usize,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *const blazesym_result {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let sym_srcs = unsafe { slice_from_user_array(sym_srcs, sym_srcs_len) };
    let sym_srcs = sym_srcs.iter().map(SymbolSrcCfg::from).collect::<Vec<_>>();
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let addresses = unsafe { slice_from_user_array(addrs, addr_cnt) };

    let result = symbolizer.symbolize(&sym_srcs, addresses);

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

/// Free an array returned by blazesym_symbolize.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_symbolize()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_result_free(results: *const blazesym_result) {
    if results.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (results as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

#[repr(C)]
#[derive(Debug)]
pub struct blazesym_sym_info {
    pub name: *const c_char,
    pub address: Addr,
    pub size: usize,
    pub file_offset: u64,
    pub obj_file_name: *const c_char,
    pub sym_type: blazesym_sym_type,
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_addresses() to a C array.
fn convert_syms_list_to_c(syms_list: Vec<Vec<SymbolInfo>>) -> *const *const blazesym_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.obj_file_name.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = ((mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        % mem::size_of::<u64>())
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * sym_cnt;
    let buf_size = array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blazesym_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut c_char;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } in syms
        {
            let name_ptr = str_ptr.cast();
            unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
                let obj_fname_ptr = str_ptr;
                unsafe { ptr::copy_nonoverlapping(fname.as_ptr().cast(), str_ptr, fname.len()) };
                str_ptr = unsafe { str_ptr.add(fname.len()) };
                unsafe { *str_ptr = 0 };
                str_ptr = unsafe { str_ptr.add(1) };
                obj_fname_ptr
            } else {
                ptr::null()
            };

            unsafe {
                (*sym_ptr) = blazesym_sym_info {
                    name: name_ptr,
                    address,
                    size,
                    sym_type: match sym_type {
                        SymbolType::Function => blazesym_sym_type::BLAZESYM_SYM_T_FUNC,
                        SymbolType::Variable => blazesym_sym_type::BLAZESYM_SYM_T_VAR,
                        SymbolType::Unknown => blazesym_sym_type::BLAZESYM_SYM_T_UNKNOWN,
                    },
                    file_offset,
                    obj_file_name,
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: ptr::null(),
                address: 0,
                size: 0,
                sym_type: blazesym_sym_type::BLAZESYM_SYM_T_UNKNOWN,
                file_offset: 0,
                obj_file_name: ptr::null(),
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blazesym_sym_info
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_address_regex() to a C array.
fn convert_syms_to_c(syms: Vec<SymbolInfo>) -> *const blazesym_sym_info {
    let mut str_buf_sz = 0;

    for sym in &syms {
        str_buf_sz += sym.name.len() + 1;
        if let Some(fname) = sym.obj_file_name.as_ref() {
            str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
        }
    }

    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * (syms.len() + 1);
    let buf_size = sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut sym_ptr = raw_buf as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(sym_buf_sz) } as *mut c_char;

    for sym in syms {
        let SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } = sym;
        let name_ptr = str_ptr as *const c_char;
        unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), str_ptr, name.len()) };
        str_ptr = unsafe { str_ptr.add(name.len()) };
        unsafe { *str_ptr = 0 };
        str_ptr = unsafe { str_ptr.add(1) };
        let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
            let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
            let obj_fname_ptr = str_ptr;
            unsafe { ptr::copy_nonoverlapping(fname.as_ptr().cast(), str_ptr, fname.len()) };
            str_ptr = unsafe { str_ptr.add(fname.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            obj_fname_ptr
        } else {
            ptr::null()
        };

        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: name_ptr,
                address,
                size,
                sym_type: match sym_type {
                    SymbolType::Function => blazesym_sym_type::BLAZESYM_SYM_T_FUNC,
                    SymbolType::Variable => blazesym_sym_type::BLAZESYM_SYM_T_VAR,
                    SymbolType::Unknown => blazesym_sym_type::BLAZESYM_SYM_T_UNKNOWN,
                },
                file_offset,
                obj_file_name,
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };
    }
    unsafe {
        (*sym_ptr) = blazesym_sym_info {
            name: ptr::null(),
            address: 0,
            size: 0,
            sym_type: blazesym_sym_type::BLAZESYM_SYM_T_UNKNOWN,
            file_offset: 0,
            obj_file_name: ptr::null(),
        }
    };

    raw_buf as *const blazesym_sym_info
}

/// The types of symbols.
///
/// This type is used to choice what type of symbols you like to find
/// and indicate the types of symbols found.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
#[derive(Copy, Clone, Debug)]
pub enum blazesym_sym_type {
    /// You want to find a symbol of any type.
    BLAZESYM_SYM_T_UNKNOWN,
    /// The returned symbol is a function, or you want to find a function.
    BLAZESYM_SYM_T_FUNC,
    /// The returned symbol is a variable, or you want to find a variable.
    BLAZESYM_SYM_T_VAR,
}

/// Feature names of looking up addresses of symbols.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
#[derive(Debug)]
pub enum blazesym_faf_type {
    /// Return the offset in the file. (enable)
    BLAZESYM_FAF_T_OFFSET_IN_FILE,
    /// Return the file name of the shared object. (enable)
    BLAZESYM_FAF_T_OBJ_FILE_NAME,
    /// Return symbols having the given type. (sym_type)
    BLAZESYM_FAF_T_SYMBOL_TYPE,
}

/// The parameter parts of `blazesym_faddr_feature`.
#[repr(C)]
pub union blazesym_faf_param {
    enable: bool,
    sym_type: blazesym_sym_type,
}

impl Debug for blazesym_faf_param {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blazesym_faf_param)).finish()
    }
}


/// Switches and settings of features of looking up addresses of
/// symbols.
///
/// See [`FindAddrFeature`] for details.
#[repr(C)]
pub struct blazesym_faddr_feature {
    ftype: blazesym_faf_type,
    param: blazesym_faf_param,
}

impl Debug for blazesym_faddr_feature {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blazesym_faddr_feature))
            .field("ftype", &self.ftype)
            .finish()
    }
}

impl From<&blazesym_faddr_feature> for FindAddrFeature {
    fn from(feature: &blazesym_faddr_feature) -> Self {
        match feature.ftype {
            blazesym_faf_type::BLAZESYM_FAF_T_SYMBOL_TYPE => {
                // SAFETY: `sym_type` is the union variant used for `BLAZESYM_FAF_T_SYMBOL_TYPE`.
                match unsafe { feature.param.sym_type } {
                    blazesym_sym_type::BLAZESYM_SYM_T_UNKNOWN => {
                        FindAddrFeature::SymbolType(SymbolType::Unknown)
                    }
                    blazesym_sym_type::BLAZESYM_SYM_T_FUNC => {
                        FindAddrFeature::SymbolType(SymbolType::Function)
                    }
                    blazesym_sym_type::BLAZESYM_SYM_T_VAR => {
                        FindAddrFeature::SymbolType(SymbolType::Variable)
                    }
                }
            }
            blazesym_faf_type::BLAZESYM_FAF_T_OFFSET_IN_FILE => {
                // SAFETY: `enable` is the union variant used for `BLAZESYM_FAF_T_OFFSET_IN_FILE`.
                FindAddrFeature::OffsetInFile(unsafe { feature.param.enable })
            }
            blazesym_faf_type::BLAZESYM_FAF_T_OBJ_FILE_NAME => {
                // SAFETY: `enable` is the union variant used for `BLAZESYM_FAF_T_OBJ_FILE_NAME`.
                FindAddrFeature::ObjFileName(unsafe { feature.param.enable })
            }
        }
    }
}


/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// It works the same as [`blazesym_find_address_regex()`] with
/// additional controls on features.
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const blazesym_sym_src_cfg,
    sym_srcs_len: usize,
    pattern: *const c_char,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const blazesym_sym_info {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let sym_srcs = unsafe { slice_from_user_array(sym_srcs, sym_srcs_len) };
    let sym_srcs = sym_srcs.iter().map(SymbolSrcCfg::from).collect::<Vec<_>>();

    let pattern = unsafe { CStr::from_ptr(pattern) };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let features = unsafe { slice_from_user_array(features, num_features) };
    let features = features
        .iter()
        .map(FindAddrFeature::from)
        .collect::<Vec<_>>();
    let syms = symbolizer.find_address_regex_opt(&sym_srcs, pattern.to_str().unwrap(), &features);

    if syms.is_none() {
        return ptr::null_mut()
    }

    convert_syms_to_c(syms.unwrap())
}

/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex(
    symbolizer: *mut blazesym,
    sym_srcs: *const blazesym_sym_src_cfg,
    sym_srcs_len: usize,
    pattern: *const c_char,
) -> *const blazesym_sym_info {
    unsafe {
        blazesym_find_address_regex_opt(symbolizer, sym_srcs, sym_srcs_len, pattern, ptr::null(), 0)
    }
}

/// Free an array returned by blazesym_find_addr_regex() or
/// blazesym_find_addr_regex_opt().
///
/// # Safety
///
/// The `syms` pointer should have been allocated by one of the
/// `blazesym_find_address*` variants.
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_free(syms: *const blazesym_sym_info) {
    if syms.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

/// Find the addresses of a list of symbols.
///
/// Return an array with the same size as the input names. The caller should
/// free the returned array by calling [`blazesym_syms_list_free()`].
///
/// Every name in the input name list may have more than one address.
/// The respective entry in the returned array is an array containing
/// all addresses and ended with a null (0x0).
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_list_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const blazesym_sym_src_cfg,
    sym_srcs_len: usize,
    names: *const *const c_char,
    name_cnt: usize,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const *const blazesym_sym_info {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let sym_srcs = unsafe { slice_from_user_array(sym_srcs, sym_srcs_len) };
    let sym_srcs = sym_srcs.iter().map(SymbolSrcCfg::from).collect::<Vec<_>>();
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let names = unsafe { slice_from_user_array(names, name_cnt) };
    let names = names
        .iter()
        .map(|&p| {
            // SAFETY: The caller ensures that the pointer is valid.
            unsafe { CStr::from_ptr(p) }.to_str().unwrap()
        })
        .collect::<Vec<_>>();
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let features = unsafe { slice_from_user_array(features, num_features) };
    let features = features
        .iter()
        .map(FindAddrFeature::from)
        .collect::<Vec<_>>();

    let result = symbolizer.find_addresses_opt(&sym_srcs, &names, &features);
    match result {
        Ok(syms) => convert_syms_list_to_c(syms),
        Err(_err) => {
            // TODO: Errors should probably be surfaced.
            #[cfg(debug_assertions)]
            eprintln!("failed to find {name_cnt} symbols: {_err}");
            ptr::null()
        }
    }
}

/// Find addresses of a symbol name.
///
/// A symbol may have multiple addressses.
///
/// # Safety
///
/// The returned data should be free by [`blazesym_syms_list_free()`].
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses(
    symbolizer: *mut blazesym,
    sym_srcs: *const blazesym_sym_src_cfg,
    sym_srcs_len: usize,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blazesym_sym_info {
    unsafe {
        blazesym_find_addresses_opt(
            symbolizer,
            sym_srcs,
            sym_srcs_len,
            names,
            name_cnt,
            ptr::null(),
            0,
        )
    }
}

/// Free an array returned by [`blazesym_find_addresses`].
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_find_addresses`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_list_free(syms_list: *const *const blazesym_sym_info) {
    if syms_list.is_null() {
        return
    }

    let raw_buf_with_sz =
        unsafe { (syms_list as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}
