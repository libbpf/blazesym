use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::borrow::Cow;
use std::ffi::CString;
use std::ffi::OsString;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::mem::size_of;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::ptr;
use std::slice;

use blazesym::normalize::Apk;
use blazesym::normalize::Elf;
use blazesym::normalize::NormalizeOpts;
use blazesym::normalize::Normalizer;
use blazesym::normalize::Reason;
use blazesym::normalize::Unknown;
use blazesym::normalize::UserMeta;
use blazesym::normalize::UserOutput;
use blazesym::symbolize::Sym;
use blazesym::Addr;

use crate::blaze_err;
#[cfg(doc)]
use crate::blaze_err_last;
use crate::blaze_sym;
use crate::blaze_symbolize_inlined_fn;
use crate::convert_sym;
use crate::set_last_err;
use crate::util::slice_from_user_array;
use crate::util::DynSize as _;


/// C ABI compatible version of [`blazesym::normalize::Normalizer`].
pub type blaze_normalizer = Normalizer;


/// Options for configuring [`blaze_normalizer`] objects.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalizer_opts {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// Whether or not to use the `PROCMAP_QUERY` ioctl instead of
    /// parsing `/proc/<pid>/maps` for getting available VMA ranges.
    ///
    /// Refer to
    /// [`blaze_supports_procmap_query`][crate::helper::blaze_supports_procmap_query]
    /// as a way to check whether your system supports this
    /// functionality.
    ///
    /// # Notes
    ///
    /// Support for this ioctl is only present in very recent kernels
    /// (likely: 6.11+). See <https://lwn.net/Articles/979931/> for
    /// details.
    ///
    /// Furthermore, the ioctl will also be used for retrieving build
    /// IDs (if enabled). Build ID reading logic in the kernel is known
    /// to be incomplete, with a fix slated to be included only with
    /// 6.12.
    pub use_procmap_query: bool,
    /// Whether or not to cache `/proc/<pid>/maps` contents.
    ///
    /// Setting this flag to `true` is not generally recommended, because it
    /// could result in addresses corresponding to mappings added after caching
    /// may not be normalized successfully, as there is no reasonable way of
    /// detecting staleness.
    pub cache_vmas: bool,
    /// Whether to read and report build IDs as part of the normalization
    /// process.
    ///
    /// Note that build ID read failures will be swallowed without
    /// failing the normalization operation.
    pub build_ids: bool,
    /// Whether or not to cache build IDs. This flag only has an effect
    /// if build ID reading is enabled in the first place.
    pub cache_build_ids: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 20],
}

impl Default for blaze_normalizer_opts {
    fn default() -> Self {
        Self {
            type_size: size_of::<Self>(),
            use_procmap_query: false,
            cache_vmas: false,
            build_ids: false,
            cache_build_ids: false,
            reserved: [0; 20],
        }
    }
}


/// Options influencing the address normalization process.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalize_opts {
    /// The size of this object's type.
    ///
    /// Make sure to initialize it to `sizeof(<type>)`. This member is used to
    /// ensure compatibility in the presence of member additions.
    pub type_size: usize,
    /// Whether or not addresses are sorted (in ascending order) already.
    ///
    /// Normalization always happens on sorted addresses and if the addresses
    /// are sorted already, the library does not need to sort and later restore
    /// original ordering, speeding up the normalization process.
    pub sorted_addrs: bool,
    /// Whether to report `/proc/<pid>/map_files/` entry paths or work
    /// with symbolic paths mentioned in `/proc/<pid>/maps` instead.
    ///
    /// Relying on `map_files` may make sense in cases where
    /// symbolization happens on the local system and the reported paths
    /// can be worked with directly. In most other cases where one wants
    /// to attach meaning to symbolic paths on a remote system (e.g., by
    /// using them for file look up) symbolic paths are probably the
    /// better choice.
    pub map_files: bool,
    /// Normalize addresses inside APKs to the contained ELF file and
    /// report a regular [`blaze_user_meta_kind::ELF`] meta data entry
    /// instead of an [`blaze_user_meta_kind::APK`] one. As a result,
    /// the reported file offset will also be relative to the contained
    /// ELF file and not to the APK itself.
    pub apk_to_elf: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 21],
}

impl Default for blaze_normalize_opts {
    fn default() -> Self {
        Self {
            type_size: size_of::<Self>(),
            sorted_addrs: false,
            map_files: false,
            apk_to_elf: false,
            reserved: [0; 21],
        }
    }
}

impl From<blaze_normalize_opts> for NormalizeOpts {
    fn from(opts: blaze_normalize_opts) -> Self {
        let blaze_normalize_opts {
            type_size: _,
            sorted_addrs,
            map_files,
            apk_to_elf,
            reserved: _,
        } = opts;
        Self {
            sorted_addrs,
            map_files,
            apk_to_elf,
            _non_exhaustive: (),
        }
    }
}


/// Create an instance of a blazesym normalizer in the default
/// configuration.
///
/// C ABI compatible version of [`blazesym::normalize::Normalizer::new()`].
/// Please refer to its documentation for the default configuration in use.
///
/// On success, the function creates a new [`blaze_normalizer`] object and
/// returns it. The resulting object should be released using
/// [`blaze_normalizer_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
#[no_mangle]
pub extern "C" fn blaze_normalizer_new() -> *mut blaze_normalizer {
    let normalizer = Normalizer::new();
    let normalizer_box = Box::new(normalizer);
    let () = set_last_err(blaze_err::OK);
    Box::into_raw(normalizer_box)
}


/// Create an instance of a blazesym normalizer.
///
/// On success, the function creates a new [`blaze_normalizer`] object and
/// returns it. The resulting object should be released using
/// [`blaze_normalizer_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `opts` needs to point to a valid [`blaze_normalizer_opts`] object
#[no_mangle]
pub unsafe extern "C" fn blaze_normalizer_new_opts(
    opts: *const blaze_normalizer_opts,
) -> *mut blaze_normalizer {
    if !input_zeroed!(opts, blaze_normalizer_opts) {
        let () = set_last_err(blaze_err::INVALID_INPUT);
        return ptr::null_mut()
    }
    let opts = input_sanitize!(opts, blaze_normalizer_opts);

    let blaze_normalizer_opts {
        type_size: _,
        use_procmap_query,
        cache_vmas,
        build_ids,
        cache_build_ids,
        reserved: _,
    } = opts;

    let normalizer = Normalizer::builder()
        .enable_procmap_query(use_procmap_query)
        .enable_vma_caching(cache_vmas)
        .enable_build_ids(build_ids)
        .enable_build_id_caching(cache_build_ids)
        .build();
    let normalizer_box = Box::new(normalizer);
    let () = set_last_err(blaze_err::OK);
    Box::into_raw(normalizer_box)
}


/// Free a blazesym normalizer.
///
/// Release resources associated with a normalizer as created by
/// [`blaze_normalizer_new`], for example.
///
/// # Safety
/// The provided normalizer should have been created by
/// [`blaze_normalizer_new`].
#[no_mangle]
pub unsafe extern "C" fn blaze_normalizer_free(normalizer: *mut blaze_normalizer) {
    if !normalizer.is_null() {
        // SAFETY: The caller needs to ensure that `normalizer` is a
        //         valid pointer.
        drop(unsafe { Box::from_raw(normalizer) });
    }
}


/// A file offset or non-normalized address along with an index into the
/// associated [`blaze_user_meta`] array (such as
/// [`blaze_normalized_user_output::metas`]).
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalized_output {
    /// The file offset or non-normalized address.
    pub output: u64,
    /// The index into the associated [`blaze_user_meta`] array.
    pub meta_idx: usize,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 16],
}

impl From<(u64, usize)> for blaze_normalized_output {
    fn from((output, meta_idx): (u64, usize)) -> Self {
        Self {
            output,
            meta_idx,
            reserved: [0; 16],
        }
    }
}


/// The valid variant kind in [`blaze_user_meta`].
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct blaze_user_meta_kind(u8);

impl blaze_user_meta_kind {
    /// [`blaze_user_meta_variant::unknown`] is valid.
    pub const UNKNOWN: blaze_user_meta_kind = blaze_user_meta_kind(0);
    /// [`blaze_user_meta_variant::apk`] is valid.
    pub const APK: blaze_user_meta_kind = blaze_user_meta_kind(1);
    /// [`blaze_user_meta_variant::elf`] is valid.
    pub const ELF: blaze_user_meta_kind = blaze_user_meta_kind(2);
    /// [`blaze_user_meta_variant::sym`] is valid.
    pub const SYM: blaze_user_meta_kind = blaze_user_meta_kind(3);

    // TODO: Remove the following constants with the 0.2 release
    /// Deprecated; use `BLAZE_USER_META_KIND_UNKNOWN`.
    #[deprecated]
    pub const BLAZE_USER_META_UNKNOWN: blaze_user_meta_kind = blaze_user_meta_kind(0);
    /// Deprecated; use `BLAZE_USER_META_KIND_APK`.
    #[deprecated]
    pub const BLAZE_USER_META_APK: blaze_user_meta_kind = blaze_user_meta_kind(1);
    /// Deprecated; use `BLAZE_USER_META_KIND_ELF`.
    #[deprecated]
    pub const BLAZE_USER_META_ELF: blaze_user_meta_kind = blaze_user_meta_kind(2);
}


/// C compatible version of [`Apk`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_apk {
    /// The canonical absolute path to the APK, including its name.
    /// This member is always present.
    pub path: *mut c_char,
    /// Unused member available for future expansion.
    pub reserved: [u8; 16],
}

impl blaze_user_meta_apk {
    fn from(other: Apk) -> ManuallyDrop<Self> {
        let Apk {
            path,
            _non_exhaustive: (),
        } = other;

        let slf = Self {
            path: CString::new(path.into_os_string().into_vec())
                .expect("encountered path with NUL bytes")
                .into_raw(),
            reserved: [0; 16],
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        let Self { path, reserved: _ } = self;

        let _apk = Apk {
            path: PathBuf::from(OsString::from_vec(
                unsafe { CString::from_raw(path) }.into_bytes(),
            )),
            _non_exhaustive: (),
        };
    }
}


/// C compatible version of [`Elf`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_elf {
    /// Ordinarily, the canonical absolute path to the ELF file,
    /// including its name. In case of an ELF file contained inside an
    /// APK (see [`blaze_normalize_opts::apk_to_elf`]) this will be an
    /// Android style path of the form `<apk>!<elf-in-apk>`. E.g.,
    /// `/root/test.apk!/lib/libc.so`.
    ///
    /// This member is always present.
    pub path: *mut c_char,
    /// The length of the build ID, in bytes.
    pub build_id_len: usize,
    /// The optional build ID of the ELF file, if found and readable.
    pub build_id: *mut u8,
    /// Unused member available for future expansion.
    pub reserved: [u8; 16],
}

impl blaze_user_meta_elf {
    fn from(other: Elf) -> ManuallyDrop<Self> {
        let Elf {
            path,
            build_id,
            _non_exhaustive: (),
        } = other;

        let slf = Self {
            path: CString::new(path.into_os_string().into_vec())
                .expect("encountered path with NUL bytes")
                .into_raw(),
            build_id_len: build_id
                .as_ref()
                .map(|build_id| build_id.len())
                .unwrap_or(0),
            build_id: build_id
                .map(|build_id| {
                    // SAFETY: We know the pointer is valid because it
                    //         came from a `Box`.
                    unsafe {
                        Box::into_raw(build_id.to_vec().into_boxed_slice())
                            .as_mut()
                            .unwrap()
                            .as_mut_ptr()
                    }
                })
                .unwrap_or_else(ptr::null_mut),
            reserved: [0; 16],
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        let blaze_user_meta_elf {
            path,
            build_id_len,
            build_id,
            reserved: _,
        } = self;

        let _elf = Elf {
            path: PathBuf::from(OsString::from_vec(
                unsafe { CString::from_raw(path) }.into_bytes(),
            )),
            build_id: (!build_id.is_null()).then(|| unsafe {
                Cow::Owned(
                    Box::<[u8]>::from_raw(slice::from_raw_parts_mut(build_id, build_id_len))
                        .into_vec(),
                )
            }),
            _non_exhaustive: (),
        };
    }
}


/// Readily symbolized information for an address.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_sym {
    /// The symbol data.
    pub sym: *const blaze_sym,
    /// Unused member available for future expansion.
    pub reserved: [u8; 16],
}

impl blaze_user_meta_sym {
    fn from(sym: Sym) -> ManuallyDrop<Self> {
        let strtab_size = sym.c_str_size();
        let buf_size = mem::size_of::<u64>()
            + mem::size_of::<blaze_sym>()
            + sym.inlined.len() * mem::size_of::<blaze_symbolize_inlined_fn>()
            + strtab_size;
        let buf = unsafe { alloc(Layout::from_size_align(buf_size, 8).unwrap()) };
        // TODO: Should ideally report runtime error, but we already
        //       use panic-on-OOM functions elsewhere, so they'd all
        //       need to be adjusted.
        assert!(!buf.is_null());

        // Prepend a `u64` to store the size of the buffer.
        unsafe { *(buf as *mut u64) = buf_size as u64 };

        let sym_buf = unsafe { buf.add(mem::size_of::<u64>()) }.cast::<blaze_sym>();
        let mut inlined_last = unsafe { sym_buf.add(1) }.cast::<blaze_symbolize_inlined_fn>();
        let mut cstr_last = unsafe { inlined_last.add(sym.inlined.len()) }.cast::<c_char>();
        let sym_ref = unsafe { &mut *sym_buf };
        let () = convert_sym(&sym, sym_ref, &mut inlined_last, &mut cstr_last);

        let slf = Self {
            sym: sym_buf,
            reserved: [0; 16],
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        let blaze_user_meta_sym { sym, reserved: _ } = self;

        let buf = unsafe { sym.byte_sub(mem::size_of::<u64>()).cast::<u8>().cast_mut() };
        let size = unsafe { *(buf as *mut u64) } as usize;
        let () = unsafe { dealloc(buf, Layout::from_size_align(size, 8).unwrap()) };
    }
}


/// The reason why normalization failed.
///
/// The reason is generally only meant as a hint. Reasons reported may change
/// over time and, hence, should not be relied upon for the correctness of the
/// application.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct blaze_normalize_reason(u8);

impl blaze_normalize_reason {
    /// The absolute address was not found in the corresponding process' virtual
    /// memory map.
    pub const UNMAPPED: blaze_normalize_reason = blaze_normalize_reason(0);
    /// The `/proc/<pid>/maps` entry corresponding to the address does not have
    /// a component (file system path, object, ...) associated with it.
    pub const MISSING_COMPONENT: blaze_normalize_reason = blaze_normalize_reason(1);
    /// The address belonged to an entity that is currently unsupported.
    pub const UNSUPPORTED: blaze_normalize_reason = blaze_normalize_reason(2);
}

impl From<Reason> for blaze_normalize_reason {
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::Unmapped => blaze_normalize_reason::UNMAPPED,
            Reason::MissingComponent => blaze_normalize_reason::MISSING_COMPONENT,
            Reason::Unsupported => blaze_normalize_reason::UNSUPPORTED,
            _ => unreachable!(),
        }
    }
}


/// Retrieve a textual representation of the reason of a normalization failure.
#[no_mangle]
pub extern "C" fn blaze_normalize_reason_str(err: blaze_normalize_reason) -> *const c_char {
    match err {
        blaze_normalize_reason::UNMAPPED => Reason::Unmapped.as_bytes().as_ptr().cast(),
        blaze_normalize_reason::MISSING_COMPONENT => {
            Reason::MissingComponent.as_bytes().as_ptr().cast()
        }
        blaze_normalize_reason::UNSUPPORTED => Reason::Unsupported.as_bytes().as_ptr().cast(),
        _ => b"unknown reason\0".as_ptr().cast(),
    }
}


/// C compatible version of [`Unknown`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_unknown {
    /// The reason why normalization failed.
    ///
    /// The provided reason is a best guess, hinting at what ultimately
    /// prevented the normalization from being successful.
    pub reason: blaze_normalize_reason,
    /// Unused member available for future expansion.
    pub reserved: [u8; 15],
}

impl blaze_user_meta_unknown {
    fn from(other: Unknown) -> ManuallyDrop<Self> {
        let Unknown {
            reason,
            _non_exhaustive: (),
        } = other;

        let slf = Self {
            reason: reason.into(),
            reserved: [0; 15],
        };
        ManuallyDrop::new(slf)
    }

    fn free(self) {
        let blaze_user_meta_unknown {
            reason: _,
            reserved: _,
        } = self;
    }
}


/// The actual variant data in [`blaze_user_meta`].
#[repr(C)]
pub union blaze_user_meta_variant {
    /// Valid on [`blaze_user_meta_kind::APK`].
    pub apk: ManuallyDrop<blaze_user_meta_apk>,
    /// Valid on [`blaze_user_meta_kind::ELF`].
    pub elf: ManuallyDrop<blaze_user_meta_elf>,
    /// Valid on [`blaze_user_meta_kind::SYM`].
    pub sym: ManuallyDrop<blaze_user_meta_sym>,
    /// Valid on [`blaze_user_meta_kind::UNKNOWN`].
    pub unknown: ManuallyDrop<blaze_user_meta_unknown>,
}

impl Debug for blaze_user_meta_variant {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blaze_user_meta_variant)).finish()
    }
}


/// C ABI compatible version of [`UserMeta`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta {
    /// The variant kind that is present.
    pub kind: blaze_user_meta_kind,
    /// Currently unused bytes.
    pub unused: [u8; 7],
    /// The actual variant with its data.
    pub variant: blaze_user_meta_variant,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 16],
}

impl blaze_user_meta {
    fn from(other: UserMeta) -> ManuallyDrop<Self> {
        let slf = match other {
            UserMeta::Apk(apk) => Self {
                kind: blaze_user_meta_kind::APK,
                unused: [0; 7],
                variant: blaze_user_meta_variant {
                    apk: blaze_user_meta_apk::from(apk),
                },
                reserved: [0; 16],
            },
            UserMeta::Elf(elf) => Self {
                kind: blaze_user_meta_kind::ELF,
                unused: [0; 7],
                variant: blaze_user_meta_variant {
                    elf: blaze_user_meta_elf::from(elf),
                },
                reserved: [0; 16],
            },
            UserMeta::Sym(sym) => Self {
                kind: blaze_user_meta_kind::SYM,
                unused: [0; 7],
                variant: blaze_user_meta_variant {
                    sym: blaze_user_meta_sym::from(sym),
                },
                reserved: [0; 16],
            },
            UserMeta::Unknown(unknown) => Self {
                kind: blaze_user_meta_kind::UNKNOWN,
                unused: [0; 7],
                variant: blaze_user_meta_variant {
                    unknown: blaze_user_meta_unknown::from(unknown),
                },
                reserved: [0; 16],
            },
            _ => unreachable!(),
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        match self.kind {
            blaze_user_meta_kind::APK => unsafe {
                ManuallyDrop::into_inner(self.variant.apk).free()
            },
            blaze_user_meta_kind::ELF => unsafe {
                ManuallyDrop::into_inner(self.variant.elf).free()
            },
            blaze_user_meta_kind::SYM => unsafe {
                ManuallyDrop::into_inner(self.variant.sym).free()
            },
            blaze_user_meta_kind::UNKNOWN => {
                ManuallyDrop::into_inner(unsafe { self.variant.unknown }).free()
            }
            _ => {
                debug_assert!(false)
            }
        }
    }
}


/// An object representing normalized user addresses.
///
/// C ABI compatible version of [`UserOutput`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalized_user_output {
    /// The number of [`blaze_user_meta`] objects present in `metas`.
    pub meta_cnt: usize,
    /// An array of `meta_cnt` objects.
    pub metas: *mut blaze_user_meta,
    /// The number of [`blaze_normalized_output`] objects present in `outputs`.
    pub output_cnt: usize,
    /// An array of `output_cnt` objects.
    pub outputs: *mut blaze_normalized_output,
    /// Unused member available for future expansion.
    pub reserved: [u8; 16],
}

impl blaze_normalized_user_output {
    fn from(other: UserOutput) -> ManuallyDrop<Self> {
        let slf = Self {
            meta_cnt: other.meta.len(),
            metas: unsafe {
                Box::into_raw(
                    other
                        .meta
                        .into_iter()
                        .map(blaze_user_meta::from)
                        .map(ManuallyDrop::into_inner)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
                .as_mut()
                .unwrap()
                .as_mut_ptr()
            },
            output_cnt: other.outputs.len(),
            outputs: unsafe {
                Box::into_raw(
                    other
                        .outputs
                        .into_iter()
                        .map(blaze_normalized_output::from)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
                .as_mut()
                .unwrap()
                .as_mut_ptr()
            },
            reserved: [0; 16],
        };
        ManuallyDrop::new(slf)
    }
}


unsafe fn blaze_normalize_user_addrs_impl(
    normalizer: *const blaze_normalizer,
    pid: u32,
    addrs: *const Addr,
    addr_cnt: usize,
    opts: &NormalizeOpts,
) -> *mut blaze_normalized_user_output {
    // SAFETY: The caller needs to ensure that `normalizer` is a valid
    //         pointer.
    let normalizer = unsafe { &*normalizer };
    // SAFETY: The caller needs to ensure that `addrs` is a valid pointer and
    //         that it points to `addr_cnt` elements.
    let addrs = unsafe { slice_from_user_array(addrs, addr_cnt) };
    let result = normalizer.normalize_user_addrs_opts(pid.into(), &addrs, opts);
    match result {
        Ok(output) => {
            let output_box = Box::new(ManuallyDrop::into_inner(
                blaze_normalized_user_output::from(output),
            ));
            let () = set_last_err(blaze_err::OK);
            Box::into_raw(output_box)
        }
        Err(err) => {
            let () = set_last_err(err.kind().into());
            ptr::null_mut()
        }
    }
}


/// Normalize a list of user space addresses.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs`].
///
/// `pid` should describe the PID of the process to which the addresses
/// belongs. It may be `0` if they belong to the calling process.
///
/// On success, the function creates a new [`blaze_normalized_user_output`]
/// object and returns it. The resulting object should be released using
/// [`blaze_user_output_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `addrs` needs to be a valid pointer to `addr_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs(
    normalizer: *const blaze_normalizer,
    pid: u32,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *mut blaze_normalized_user_output {
    let opts = NormalizeOpts::default();

    unsafe { blaze_normalize_user_addrs_impl(normalizer, pid, addrs, addr_cnt, &opts) }
}


/// Normalize a list of user space addresses.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs_opts`].
///
/// `pid` should describe the PID of the process to which the addresses
/// belongs. It may be `0` if they belong to the calling process.
///
/// `opts` should point to a valid [`blaze_normalize_opts`] object.
///
/// On success, the function creates a new [`blaze_normalized_user_output`]
/// object and returns it. The resulting object should be released using
/// [`blaze_user_output_free`] once it is no longer needed.
///
/// On error, the function returns `NULL` and sets the thread's last error to
/// indicate the problem encountered. Use [`blaze_err_last`] to retrieve this
/// error.
///
/// # Safety
/// - `addrs` needs to be a valid pointer to `addr_cnt` addresses
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs_opts(
    normalizer: *const blaze_normalizer,
    pid: u32,
    addrs: *const Addr,
    addr_cnt: usize,
    opts: *const blaze_normalize_opts,
) -> *mut blaze_normalized_user_output {
    if !input_zeroed!(opts, blaze_normalize_opts) {
        let () = set_last_err(blaze_err::INVALID_INPUT);
        return ptr::null_mut()
    }
    let opts = input_sanitize!(opts, blaze_normalize_opts);
    let opts = NormalizeOpts::from(opts);

    unsafe { blaze_normalize_user_addrs_impl(normalizer, pid, addrs, addr_cnt, &opts) }
}


/// Free an object as returned by [`blaze_normalize_user_addrs`] or
/// [`blaze_normalize_user_addrs_opts`].
///
/// # Safety
/// The provided object should have been created by
/// [`blaze_normalize_user_addrs`] or
/// [`blaze_normalize_user_addrs_opts`].
#[no_mangle]
pub unsafe extern "C" fn blaze_user_output_free(output: *mut blaze_normalized_user_output) {
    if output.is_null() {
        return
    }

    // SAFETY: The caller should make sure that `output` was created by one of
    //         our blessed functions.
    let user_output = unsafe { Box::from_raw(output) };
    let addr_metas = unsafe {
        Box::<[blaze_user_meta]>::from_raw(slice::from_raw_parts_mut(
            user_output.metas,
            user_output.meta_cnt,
        ))
    }
    .into_vec();
    let _norm_addrs = unsafe {
        Box::<[blaze_normalized_output]>::from_raw(slice::from_raw_parts_mut(
            user_output.outputs,
            user_output.output_cnt,
        ))
    }
    .into_vec();

    for addr_meta in addr_metas {
        let () = unsafe { addr_meta.free() };
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CStr;
    use std::io;
    use std::path::Path;

    use blazesym::helper::read_elf_build_id;
    use blazesym::Mmap;
    use blazesym::__private::find_the_answer_fn;
    use blazesym::__private::zip;

    use test_tag::tag;

    use crate::blaze_err_last;


    /// Check that various types have expected sizes.
    #[tag(miri)]
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn type_sizes() {
        assert_eq!(size_of::<blaze_normalizer_opts>(), 32);
        assert_eq!(size_of::<blaze_normalize_opts>(), 32);
        assert_eq!(size_of::<blaze_user_meta_apk>(), 24);
        assert_eq!(size_of::<blaze_user_meta_elf>(), 40);
        assert_eq!(size_of::<blaze_user_meta_sym>(), 24);
        assert_eq!(size_of::<blaze_user_meta_unknown>(), 16);
    }

    /// Exercise the `Debug` representation of various types.
    #[tag(miri)]
    #[test]
    fn debug_repr() {
        let output = blaze_normalized_output {
            output: 0x1337,
            meta_idx: 1,
            reserved: [0; 16],
        };
        assert_eq!(
            format!("{output:?}"),
            "blaze_normalized_output { output: 4919, meta_idx: 1, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }"
        );

        let meta_kind = blaze_user_meta_kind::APK;
        assert_eq!(format!("{meta_kind:?}"), "blaze_user_meta_kind(1)");

        let apk = blaze_user_meta_apk {
            path: ptr::null_mut(),
            reserved: [0; 16],
        };
        assert_eq!(
            format!("{apk:?}"),
            "blaze_user_meta_apk { path: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let elf = blaze_user_meta_elf {
            path: ptr::null_mut(),
            build_id_len: 0,
            build_id: ptr::null_mut(),
            reserved: [0; 16],
        };
        assert_eq!(
            format!("{elf:?}"),
            "blaze_user_meta_elf { path: 0x0, build_id_len: 0, build_id: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let unknown = blaze_user_meta_unknown {
            reason: blaze_normalize_reason::UNMAPPED,
            reserved: [0; 15],
        };
        assert_eq!(
            format!("{unknown:?}"),
            "blaze_user_meta_unknown { reason: blaze_normalize_reason(0), reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let meta = blaze_user_meta {
            kind: blaze_user_meta_kind::UNKNOWN,
            unused: [0; 7],
            variant: blaze_user_meta_variant {
                unknown: ManuallyDrop::new(blaze_user_meta_unknown {
                    reason: blaze_normalize_reason::UNMAPPED,
                    reserved: [0; 15],
                }),
            },
            reserved: [0; 16],
        };
        assert_eq!(
            format!("{meta:?}"),
            "blaze_user_meta { kind: blaze_user_meta_kind(0), unused: [0, 0, 0, 0, 0, 0, 0], variant: blaze_user_meta_variant, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let normalized = blaze_normalized_user_output {
            meta_cnt: 0,
            metas: ptr::null_mut(),
            output_cnt: 0,
            outputs: ptr::null_mut(),
            reserved: [0; 16],
        };
        assert_eq!(
            format!("{normalized:?}"),
            "blaze_normalized_user_output { meta_cnt: 0, metas: 0x0, output_cnt: 0, outputs: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }",
        );
    }

    /// Make sure that we can stringify normalization reasons as expected.
    #[tag(miri)]
    #[test]
    fn reason_stringification() {
        let data = [
            (Reason::Unmapped, blaze_normalize_reason::UNMAPPED),
            (
                Reason::MissingComponent,
                blaze_normalize_reason::MISSING_COMPONENT,
            ),
            (Reason::Unsupported, blaze_normalize_reason::UNSUPPORTED),
        ];

        for (reason, expected) in data {
            assert_eq!(blaze_normalize_reason::from(reason), expected);
            let cstr = unsafe { CStr::from_ptr(blaze_normalize_reason_str(expected)) };
            let expected = CStr::from_bytes_with_nul(reason.as_bytes()).unwrap();
            assert_eq!(cstr, expected);
        }
    }

    /// Check that we can convert an [`Unknown`] into a
    /// [`blaze_user_meta_unknown`] and back.
    #[tag(miri)]
    #[test]
    fn unknown_conversion() {
        let unknown = Unknown {
            reason: Reason::Unsupported,
            _non_exhaustive: (),
        };

        let unknown_c = blaze_user_meta_unknown::from(unknown.clone());
        let () = ManuallyDrop::into_inner(unknown_c).free();

        let meta = UserMeta::Unknown(unknown);
        let meta_c = blaze_user_meta::from(meta);
        let () = unsafe { ManuallyDrop::into_inner(meta_c).free() };
    }

    /// Check that we can convert an [`Apk`] into a [`blaze_user_meta_apk`] and
    /// back.
    #[tag(miri)]
    #[test]
    fn apk_conversion() {
        let apk = Apk {
            path: PathBuf::from("/tmp/archive.apk"),
            _non_exhaustive: (),
        };

        let apk_c = blaze_user_meta_apk::from(apk.clone());
        let () = unsafe { ManuallyDrop::into_inner(apk_c).free() };

        let meta = UserMeta::Apk(apk);
        let meta_c = blaze_user_meta::from(meta);
        let () = unsafe { ManuallyDrop::into_inner(meta_c).free() };
    }

    /// Check that we can convert an [`Elf`] into a [`blaze_user_meta_elf`]
    /// and back.
    #[tag(miri)]
    #[test]
    fn elf_conversion() {
        let elf = Elf {
            path: PathBuf::from("/tmp/file.so"),
            build_id: Some(Cow::Borrowed(&[0x01, 0x02, 0x03, 0x04])),
            _non_exhaustive: (),
        };

        let elf_c = blaze_user_meta_elf::from(elf.clone());
        let () = unsafe { ManuallyDrop::into_inner(elf_c).free() };

        let meta = UserMeta::Elf(elf);
        let meta_c = blaze_user_meta::from(meta);
        let () = unsafe { ManuallyDrop::into_inner(meta_c).free() };
    }

    /// Make sure that we can create and free a normalizer instance.
    #[tag(miri)]
    #[test]
    fn normalizer_creation() {
        let normalizer = blaze_normalizer_new();
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can normalize user space addresses.
    #[test]
    fn normalize_user_addrs() {
        fn test(normalizer: *const blaze_normalizer) {
            let addrs = [
                0x0,
                libc::atexit as Addr,
                libc::chdir as Addr,
                libc::fopen as Addr,
                elf_conversion as Addr,
                normalize_user_addrs as Addr,
            ];

            let result = unsafe {
                blaze_normalize_user_addrs(normalizer, 0, addrs.as_slice().as_ptr(), addrs.len())
            };
            assert_ne!(result, ptr::null_mut());

            let normalized = unsafe { &*result };
            assert_eq!(normalized.meta_cnt, 3);
            assert_eq!(normalized.output_cnt, 6);

            let meta = unsafe { normalized.metas.read() };
            assert_eq!(meta.kind, blaze_user_meta_kind::UNKNOWN);
            assert_eq!(
                unsafe { meta.variant.unknown.reason },
                blaze_normalize_reason::UNMAPPED
            );

            let () = unsafe { blaze_user_output_free(result) };
        }

        let normalizer = blaze_normalizer_new();
        assert_ne!(normalizer, ptr::null_mut());
        test(normalizer);
        let () = unsafe { blaze_normalizer_free(normalizer) };

        let opts = blaze_normalizer_opts {
            cache_vmas: true,
            ..Default::default()
        };
        let normalizer = unsafe { blaze_normalizer_new_opts(&opts) };
        assert_ne!(normalizer, ptr::null_mut());
        test(normalizer);
        test(normalizer);
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    fn test_normalize_user_addrs_sorted(use_procmap_query: bool) {
        let mut addrs = [
            libc::atexit as Addr,
            libc::chdir as Addr,
            libc::fopen as Addr,
            elf_conversion as Addr,
            normalize_user_addrs as Addr,
        ];
        let () = addrs.sort();

        let opts = blaze_normalizer_opts {
            use_procmap_query,
            ..Default::default()
        };
        let normalizer = unsafe { blaze_normalizer_new_opts(&opts) };
        assert_ne!(normalizer, ptr::null_mut());

        let opts = blaze_normalize_opts {
            sorted_addrs: true,
            ..Default::default()
        };
        let result = unsafe {
            blaze_normalize_user_addrs_opts(
                normalizer,
                0,
                addrs.as_slice().as_ptr(),
                addrs.len(),
                &opts,
            )
        };
        assert_ne!(result, ptr::null_mut());

        let normalized = unsafe { &*result };
        assert_eq!(normalized.meta_cnt, 2);
        assert_eq!(normalized.output_cnt, 5);

        let () = unsafe { blaze_user_output_free(result) };
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can normalize sorted user space addresses.
    #[test]
    fn normalize_user_addrs_sorted_proc_maps() {
        test_normalize_user_addrs_sorted(false)
    }

    /// Check that we can normalize sorted user space addresses using
    /// the `PROCMAP_QUERY` ioctl.
    #[test]
    #[ignore = "test requires PROCMAP_QUERY ioctl kernel support"]
    fn normalize_user_addrs_sorted_ioctl() {
        test_normalize_user_addrs_sorted(true)
    }

    /// Check that we fail normalizing unsorted addresses with a function that
    /// requires them to be sorted.
    #[test]
    fn normalize_user_addrs_unsorted_failure() {
        let mut addrs = [
            libc::atexit as Addr,
            libc::chdir as Addr,
            libc::fopen as Addr,
            elf_conversion as Addr,
            normalize_user_addrs as Addr,
        ];
        let () = addrs.sort_by(|addr1, addr2| addr1.cmp(addr2).reverse());

        let normalizer = blaze_normalizer_new();
        assert_ne!(normalizer, ptr::null_mut());

        let opts = blaze_normalize_opts {
            sorted_addrs: true,
            ..Default::default()
        };
        let result = unsafe {
            blaze_normalize_user_addrs_opts(
                normalizer,
                0,
                addrs.as_slice().as_ptr(),
                addrs.len(),
                &opts,
            )
        };
        assert_eq!(result, ptr::null_mut());
        assert_eq!(blaze_err_last(), blaze_err::INVALID_INPUT);

        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can enable/disable the reading of build IDs.
    #[test]
    #[cfg_attr(
        not(target_pointer_width = "64"),
        ignore = "loads 64 bit shared object"
    )]
    fn normalize_build_id_reading() {
        fn test(read_build_ids: bool) {
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

            let opts = blaze_normalizer_opts {
                build_ids: read_build_ids,
                ..Default::default()
            };

            let normalizer = unsafe { blaze_normalizer_new_opts(&opts) };
            assert!(!normalizer.is_null());

            let opts = blaze_normalize_opts {
                sorted_addrs: true,
                ..Default::default()
            };
            let addrs = [the_answer_addr as Addr];
            let result = unsafe {
                blaze_normalize_user_addrs_opts(
                    normalizer,
                    0,
                    addrs.as_slice().as_ptr(),
                    addrs.len(),
                    &opts,
                )
            };
            assert!(!result.is_null());

            let normalized = unsafe { &*result };
            assert_eq!(normalized.meta_cnt, 1);
            assert_eq!(normalized.output_cnt, 1);

            let rc = unsafe { libc::dlclose(handle) };
            assert_eq!(rc, 0, "{}", io::Error::last_os_error());

            let output = unsafe { &*normalized.outputs.add(0) };
            let meta = unsafe { &*normalized.metas.add(output.meta_idx) };
            assert_eq!(meta.kind, blaze_user_meta_kind::ELF);

            let elf = unsafe { &meta.variant.elf };

            assert!(!elf.path.is_null());
            let path = unsafe { CStr::from_ptr(elf.path) };
            assert_eq!(path, so_cstr.as_ref());

            if read_build_ids {
                let expected = read_elf_build_id(&test_so).unwrap().unwrap();
                let build_id = unsafe { slice_from_user_array(elf.build_id, elf.build_id_len) };
                assert_eq!(build_id, expected.as_ref());
            } else {
                assert!(elf.build_id.is_null());
            }

            let () = unsafe { blaze_user_output_free(result) };
            let () = unsafe { blaze_normalizer_free(normalizer) };
        }

        test(true);
        test(false);
    }

    /// Check that we can normalize addresses in our own shared object inside a
    /// zip archive.
    #[test]
    fn normalize_custom_so_in_zip() {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("test.zip");
        let so_name = "libtest-so.so";

        let mmap = Mmap::builder().exec().open(&test_zip).unwrap();
        let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
        let so = archive
            .entries()
            .find_map(|entry| {
                let entry = entry.unwrap();
                (entry.path == Path::new(so_name)).then_some(entry)
            })
            .unwrap();

        let elf_mmap = mmap
            .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
            .unwrap();
        let (_sym, the_answer_addr) = find_the_answer_fn(&elf_mmap);

        let normalizer = blaze_normalizer_new();
        assert!(!normalizer.is_null());

        let addrs = [the_answer_addr];
        let opts = blaze_normalize_opts {
            apk_to_elf: true,
            ..Default::default()
        };
        let result = unsafe {
            blaze_normalize_user_addrs_opts(
                normalizer,
                0,
                addrs.as_slice().as_ptr(),
                addrs.len(),
                &opts,
            )
        };
        assert_ne!(result, ptr::null_mut());

        let normalized = unsafe { &*result };
        assert_eq!(normalized.meta_cnt, 1);
        assert_eq!(normalized.output_cnt, 1);

        let output = unsafe { &*normalized.outputs.add(0) };
        let meta = unsafe { &*normalized.metas.add(output.meta_idx) };
        assert_eq!(meta.kind, blaze_user_meta_kind::ELF);

        let elf = unsafe { &meta.variant.elf };
        let path = unsafe { CStr::from_ptr(elf.path) };
        assert!(path.to_str().unwrap().ends_with(so_name), "{path:?}");

        let () = unsafe { blaze_user_output_free(result) };
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Make sure that we can normalize addresses in a vDSO in the current
    /// process.
    #[cfg(linux)]
    // 32 bit system may not have vDSO.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn normalize_local_vdso_address() {
        use libc::gettimeofday;

        let addrs = [normalize_local_vdso_address as Addr, gettimeofday as Addr];
        let normalizer = blaze_normalizer_new();
        assert!(!normalizer.is_null());

        let result = unsafe {
            blaze_normalize_user_addrs(normalizer, 0, addrs.as_slice().as_ptr(), addrs.len())
        };
        assert_ne!(result, ptr::null_mut());

        let normalized = unsafe { &*result };
        assert_eq!(normalized.meta_cnt, 2);
        assert_eq!(normalized.output_cnt, 2);

        let output = unsafe { &*normalized.outputs.add(1) };
        let meta = unsafe { &*normalized.metas.add(output.meta_idx) };
        assert_eq!(meta.kind, blaze_user_meta_kind::SYM);

        let sym = unsafe { &*meta.variant.sym.sym };
        let name = unsafe { CStr::from_ptr(sym.name) };
        assert!(name.to_str().unwrap().ends_with("gettimeofday"), "{name:?}");

        let () = unsafe { blaze_user_output_free(result) };
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }
}
