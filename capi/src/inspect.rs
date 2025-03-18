use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Debug;
use std::mem;
use std::mem::ManuallyDrop;
use std::ops::Deref as _;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::ptr;

#[cfg(doc)]
use blazesym::inspect;
use blazesym::inspect::source::Elf;
use blazesym::inspect::source::Source;
use blazesym::inspect::Inspector;
use blazesym::inspect::SymInfo;
use blazesym::Addr;
use blazesym::SymType;

use crate::blaze_err;
#[cfg(doc)]
use crate::blaze_err_last;
use crate::from_cstr;
use crate::set_last_err;
use crate::util::slice_from_user_array;


/// C ABI compatible version of [`blazesym::inspect::Inspector`].
pub type blaze_inspector = Inspector;


/// An object representing an ELF inspection source.
///
/// C ABI compatible version of [`inspect::source::Elf`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_inspect_elf_src {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// The path to the ELF file. This member is always present.
    pub path: *const c_char,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    pub debug_syms: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 23],
}

impl Default for blaze_inspect_elf_src {
    fn default() -> Self {
        Self {
            type_size: mem::size_of::<Self>(),
            path: ptr::null(),
            debug_syms: false,
            reserved: [0; 23],
        }
    }
}

#[cfg_attr(not(test), allow(unused))]
impl blaze_inspect_elf_src {
    fn from(other: Elf) -> ManuallyDrop<Self> {
        let Elf {
            path,
            debug_syms,
            _non_exhaustive: (),
        } = other;

        let slf = Self {
            path: CString::new(path.into_os_string().into_vec())
                .expect("encountered path with NUL bytes")
                .into_raw(),
            debug_syms,
            ..Default::default()
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        let Self {
            type_size: _,
            path,
            debug_syms,
            reserved: _,
        } = self;

        let _elf = Elf {
            path: PathBuf::from(OsString::from_vec(
                unsafe { CString::from_raw(path as *mut _) }.into_bytes(),
            )),
            debug_syms,
            _non_exhaustive: (),
        };
    }
}

impl From<blaze_inspect_elf_src> for Elf {
    fn from(other: blaze_inspect_elf_src) -> Self {
        let blaze_inspect_elf_src {
            type_size: _,
            path,
            debug_syms,
            reserved: _,
        } = other;

        Self {
            path: unsafe { from_cstr(path) },
            debug_syms,
            _non_exhaustive: (),
        }
    }
}


/// The type of a symbol.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct blaze_sym_type(u8);

impl blaze_sym_type {
    /// The symbol type is unspecified or unknown.
    ///
    /// In input contexts this variant can be used to encompass all
    /// other variants (functions and variables), whereas in output
    /// contexts it means that the type is not known.
    pub const UNDEF: blaze_sym_type = blaze_sym_type(0);
    /// The symbol is a function.
    pub const FUNC: blaze_sym_type = blaze_sym_type(1);
    /// The symbol is a variable.
    pub const VAR: blaze_sym_type = blaze_sym_type(2);
}

impl From<SymType> for blaze_sym_type {
    fn from(other: SymType) -> Self {
        match other {
            SymType::Undefined => blaze_sym_type::UNDEF,
            SymType::Function => blaze_sym_type::FUNC,
            SymType::Variable => blaze_sym_type::VAR,
            _ => unreachable!(),
        }
    }
}


/// Information about a looked up symbol.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_sym_info {
    /// See [`inspect::SymInfo::name`].
    pub name: *const c_char,
    /// See [`inspect::SymInfo::addr`].
    pub addr: Addr,
    /// See [`inspect::SymInfo::size`].
    ///
    /// If the symbol's size is not available, this member will be `-1`.
    /// Note that some symbol sources may not distinguish between
    /// "unknown" size and `0`. In that case the size will be reported
    /// as `0` here as well.
    pub size: isize,
    /// See [`inspect::SymInfo::file_offset`].
    pub file_offset: u64,
    /// See [`inspect::SymInfo::module`].
    pub module: *const c_char,
    /// See [`inspect::SymInfo::sym_type`].
    pub sym_type: blaze_sym_type,
    /// Unused member available for future expansion.
    pub reserved: [u8; 23],
}


/// Convert [`SymInfo`] objects as returned by
/// [`Symbolizer::find_addrs`] to a C array.
fn convert_syms_list_to_c(syms_list: Vec<Vec<SymInfo>>) -> *const *const blaze_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.module.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname.deref()).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = (mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        / mem::size_of::<u64>()
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blaze_sym_info>() * sym_cnt;
    let buf_size = mem::size_of::<u64>() + array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz = unsafe { alloc(Layout::from_size_align(buf_size, 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null()
    }

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blaze_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blaze_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut c_char;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymInfo {
            name,
            addr,
            size,
            sym_type,
            file_offset,
            module,
        } in syms
        {
            let name_ptr = str_ptr.cast();
            unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let module = if let Some(fname) = module.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname.deref()).as_bytes();
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
                (*sym_ptr) = blaze_sym_info {
                    name: name_ptr,
                    addr,
                    size: size
                        .map(|size| isize::try_from(size).unwrap_or(isize::MAX))
                        .unwrap_or(-1),
                    sym_type: sym_type.into(),
                    file_offset: file_offset.unwrap_or(0),
                    module,
                    reserved: [0; 23],
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blaze_sym_info {
                name: ptr::null(),
                addr: 0,
                size: 0,
                sym_type: blaze_sym_type::UNDEF,
                file_offset: 0,
                module: ptr::null(),
                reserved: [0; 23],
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blaze_sym_info
}


/// Lookup symbol information in an ELF file.
///
/// On success, returns an array with `name_cnt` elements. Each such element, in
/// turn, is NULL terminated array comprised of each symbol found. The returned
/// object should be released using [`blaze_inspect_syms_free`] once it is no
/// longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `inspector` needs to point to an initialized [`blaze_inspector`] object
/// - `src` needs to point to an initialized [`blaze_inspect_syms_elf`] object
/// - `names` needs to be a valid pointer to `name_cnt` NUL terminated strings
#[no_mangle]
pub unsafe extern "C" fn blaze_inspect_syms_elf(
    inspector: *const blaze_inspector,
    src: *const blaze_inspect_elf_src,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blaze_sym_info {
    if !input_zeroed!(src, blaze_inspect_elf_src) {
        let () = set_last_err(blaze_err::INVALID_INPUT);
        return ptr::null()
    }
    let src = input_sanitize!(src, blaze_inspect_elf_src);

    // SAFETY: The caller ensures that the pointer is valid.
    let inspector = unsafe { &*inspector };
    // SAFETY: The caller ensures that the pointer is valid.
    let src = Source::Elf(Elf::from(src));
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
    let result = inspector.lookup(&src, &names);
    match result {
        Ok(syms) => {
            let result = convert_syms_list_to_c(syms);
            if result.is_null() {
                let () = set_last_err(blaze_err::OUT_OF_MEMORY);
            } else {
                let () = set_last_err(blaze_err::OK);
            }
            result
        }
        Err(err) => {
            let () = set_last_err(err.kind().into());
            ptr::null()
        }
    }
}


/// Free an array returned by [`blaze_inspect_syms_elf`].
///
/// # Safety
///
/// The pointer must be returned by [`blaze_inspect_syms_elf`].
#[no_mangle]
pub unsafe extern "C" fn blaze_inspect_syms_free(syms: *const *const blaze_sym_info) {
    if syms.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize;
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}


/// Create an instance of a blazesym inspector.
///
/// C ABI compatible version of [`blazesym::inspect::Inspector::new()`].
/// Please refer to its documentation for the default configuration in
/// use.
///
/// On success, the function creates a new [`blaze_inspector`] object
/// and returns it. The resulting object should be released using
/// [`blaze_inspector_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
#[no_mangle]
pub extern "C" fn blaze_inspector_new() -> *mut blaze_inspector {
    let inspector = Inspector::new();
    let inspector_box = Box::new(inspector);
    let () = set_last_err(blaze_err::OK);
    Box::into_raw(inspector_box)
}


/// Free a blazesym inspector.
///
/// Release resources associated with a inspector as created by
/// [`blaze_inspector_new`], for example.
///
/// # Safety
/// The provided inspector should have been created by
/// [`blaze_inspector_new`].
#[no_mangle]
pub unsafe extern "C" fn blaze_inspector_free(inspector: *mut blaze_inspector) {
    if !inspector.is_null() {
        // SAFETY: The caller needs to ensure that `inspector` is a
        //         valid pointer.
        drop(unsafe { Box::from_raw(inspector) });
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::MaybeUninit;
    use std::path::Path;
    use std::ptr::addr_of;
    use std::slice;

    use test_log::test;
    use test_tag::tag;

    use crate::blaze_err_last;


    /// Check that various types have expected sizes.
    #[tag(miri)]
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn type_sizes() {
        assert_eq!(mem::size_of::<blaze_inspect_elf_src>(), 40);
        assert_eq!(mem::size_of::<blaze_sym_info>(), 64);
    }

    /// Exercise the `Debug` representation of various types.
    #[tag(miri)]
    #[test]
    fn debug_repr() {
        let elf = blaze_inspect_elf_src {
            type_size: 24,
            path: ptr::null(),
            debug_syms: true,
            reserved: [0; 23],
        };
        assert_eq!(
            format!("{elf:?}"),
            "blaze_inspect_elf_src { type_size: 24, path: 0x0, debug_syms: true, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }"
        );

        let info = blaze_sym_info {
            name: ptr::null(),
            addr: 42,
            size: 1337,
            file_offset: 31,
            module: ptr::null(),
            sym_type: blaze_sym_type::VAR,
            reserved: [0; 23],
        };
        assert_eq!(
            format!("{info:?}"),
            "blaze_sym_info { name: 0x0, addr: 42, size: 1337, file_offset: 31, module: 0x0, sym_type: blaze_sym_type(2), reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }"
        );
    }

    /// Test that we can correctly validate zeroed "extensions" of a
    /// struct.
    #[tag(miri)]
    #[test]
    fn elf_src_validity() {
        #[repr(C)]
        struct elf_src_with_ext {
            type_size: usize,
            _path: *const c_char,
            debug_syms: bool,
            reserved: [u8; 23],
            foobar: bool,
            reserved2: [u8; 7],
        }

        assert!(mem::size_of::<blaze_inspect_elf_src>() < mem::size_of::<elf_src_with_ext>());

        let mut src = MaybeUninit::<elf_src_with_ext>::uninit();
        let () = unsafe {
            ptr::write_bytes(
                src.as_mut_ptr().cast::<u8>(),
                0,
                mem::size_of::<elf_src_with_ext>(),
            )
        };

        let mut src = unsafe { src.assume_init() };
        src.type_size = mem::size_of::<elf_src_with_ext>();
        src.debug_syms = true;

        let src_ptr = addr_of!(src).cast::<blaze_inspect_elf_src>();
        assert!(input_zeroed!(src_ptr, blaze_inspect_elf_src));

        src.reserved[0] = 1;
        let src_ptr = addr_of!(src).cast::<blaze_inspect_elf_src>();
        assert!(!input_zeroed!(src_ptr, blaze_inspect_elf_src));
        src.reserved[0] = 0;

        src.type_size = mem::size_of::<usize>() - 1;
        let src_ptr = addr_of!(src).cast::<blaze_inspect_elf_src>();
        assert!(!input_zeroed!(src_ptr, blaze_inspect_elf_src));
        src.type_size = mem::size_of::<elf_src_with_ext>();

        src.foobar = true;
        let src_ptr = addr_of!(src).cast::<blaze_inspect_elf_src>();
        assert!(!input_zeroed!(src_ptr, blaze_inspect_elf_src));
    }

    /// Check that we can properly convert a "syms list" into the corresponding
    /// C representation.
    #[tag(miri)]
    #[test]
    fn syms_list_conversion() {
        fn test(syms: Vec<Vec<SymInfo>>) {
            let copy = syms.clone();
            let ptr = convert_syms_list_to_c(syms);
            assert!(!ptr.is_null());

            for (i, list) in copy.into_iter().enumerate() {
                for (j, sym) in list.into_iter().enumerate() {
                    let c_sym = unsafe { &(*(*ptr.add(i)).add(j)) };
                    assert_eq!(
                        unsafe { CStr::from_ptr(c_sym.name) }.to_bytes(),
                        CString::new(sym.name.deref()).unwrap().to_bytes()
                    );
                    assert_eq!(c_sym.addr, sym.addr);
                    assert_eq!(
                        c_sym.size,
                        sym.size
                            .map(|size| isize::try_from(size).unwrap_or(isize::MAX))
                            .unwrap_or(-1)
                    );
                    assert_eq!(c_sym.sym_type, blaze_sym_type::from(sym.sym_type));
                    assert_eq!(Some(c_sym.file_offset), sym.file_offset);
                    assert_eq!(
                        unsafe { CStr::from_ptr(c_sym.module) }.to_bytes(),
                        CString::new(sym.module.as_deref().unwrap().to_os_string().into_vec())
                            .unwrap()
                            .to_bytes()
                    );
                }
            }

            let () = unsafe { blaze_inspect_syms_free(ptr) };
        }

        // Test conversion of no symbols.
        let syms = vec![];
        test(syms);

        // Test conversion with a single symbol.
        let syms = vec![vec![SymInfo {
            name: "sym1".into(),
            addr: 0xdeadbeef,
            size: Some(42),
            sym_type: SymType::Function,
            file_offset: Some(1337),
            module: Some(OsStr::new("/tmp/foobar.so").into()),
        }]];
        test(syms);

        // Test conversion of two symbols in one result.
        let syms = vec![vec![
            SymInfo {
                name: "sym1".into(),
                addr: 0xdeadbeef,
                size: Some(42),
                sym_type: SymType::Function,
                file_offset: Some(1337),
                module: Some(OsStr::new("/tmp/foobar.so").into()),
            },
            SymInfo {
                name: "sym2".into(),
                addr: 0xdeadbeef + 52,
                size: Some(45),
                sym_type: SymType::Undefined,
                file_offset: Some(1338),
                module: Some(OsStr::new("other.so").into()),
            },
        ]];
        test(syms);

        // Test conversion of two symbols spread over two results.
        let syms = vec![
            vec![SymInfo {
                name: "sym1".into(),
                addr: 0xdeadbeef,
                size: Some(42),
                sym_type: SymType::Function,
                file_offset: Some(1337),
                module: Some(OsStr::new("/tmp/foobar.so").into()),
            }],
            vec![SymInfo {
                name: "sym2".into(),
                addr: 0xdeadbeef + 52,
                size: Some(45),
                sym_type: SymType::Undefined,
                file_offset: Some(1338),
                module: Some(OsStr::new("other.so").into()),
            }],
        ];
        test(syms);

        // Test conversion of a `SymInfo` vector with many elements.
        let sym = SymInfo {
            name: "sym1".into(),
            addr: 0xdeadbeef,
            size: Some(42),
            sym_type: SymType::Function,
            file_offset: Some(1337),
            module: Some(OsStr::new("/tmp/foobar.so").into()),
        };
        let syms = vec![(0..200).map(|_| sym.clone()).collect()];
        test(syms);

        // Test conversion of many `SymInfo` vectors.
        let syms = (0..200).map(|_| vec![sym.clone()]).collect();
        test(syms);
    }

    /// Make sure that we can create and free an inspector instance.
    #[tag(miri)]
    #[test]
    fn inspector_creation() {
        let inspector = blaze_inspector_new();
        let () = unsafe { blaze_inspector_free(inspector) };
    }

    /// Check that `blaze_inspect_syms_elf` fails if the input source
    /// does not have reserved fields set to zero.
    #[test]
    fn non_zero_reserved() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs.bin");

        let mut src = blaze_inspect_elf_src::from(Elf::new(path));
        src.reserved[1] = 1;

        let factorial = CString::new("factorial").unwrap();
        let names = [factorial.as_ptr()];
        let inspector = blaze_inspector_new();

        let result =
            unsafe { blaze_inspect_syms_elf(inspector, &*src, names.as_ptr(), names.len()) };
        let () = unsafe { ManuallyDrop::into_inner(src).free() };
        assert_eq!(result, ptr::null());
        assert_eq!(blaze_err_last(), blaze_err::INVALID_INPUT);

        let () = unsafe { blaze_inspector_free(inspector) };
    }

    /// Check that we see the expected error being reported when a source file
    /// does not exist.
    #[test]
    fn non_present_file() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("does-not-exist");

        let src = blaze_inspect_elf_src::from(Elf::new(path));
        let factorial = CString::new("factorial").unwrap();
        let names = [factorial.as_ptr()];
        let inspector = blaze_inspector_new();

        let result =
            unsafe { blaze_inspect_syms_elf(inspector, &*src, names.as_ptr(), names.len()) };
        let () = unsafe { ManuallyDrop::into_inner(src).free() };
        assert_eq!(result, ptr::null());
        assert_eq!(blaze_err_last(), blaze_err::NOT_FOUND);

        let () = unsafe { blaze_inspector_free(inspector) };
    }

    /// Make sure that we can lookup a function's address using DWARF
    /// information.
    #[test]
    fn lookup_dwarf() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test-stable-addrs-stripped-elf-with-dwarf.bin");

        let src = blaze_inspect_elf_src::from(Elf::new(test_dwarf));
        let factorial = CString::new("factorial").unwrap();
        let names = [factorial.as_ptr()];

        let inspector = blaze_inspector_new();
        let result =
            unsafe { blaze_inspect_syms_elf(inspector, &*src, names.as_ptr(), names.len()) };
        let () = unsafe { ManuallyDrop::into_inner(src).free() };
        assert!(!result.is_null());

        let sym_infos = unsafe { slice::from_raw_parts(result, names.len()) };
        let sym_info = unsafe { &*sym_infos[0] };
        assert_eq!(
            unsafe { CStr::from_ptr(sym_info.name) },
            CStr::from_bytes_with_nul(b"factorial\0").unwrap()
        );
        assert_eq!(sym_info.addr, 0x2000200);

        let () = unsafe { blaze_inspect_syms_free(result) };
        let () = unsafe { blaze_inspector_free(inspector) };
    }
}
