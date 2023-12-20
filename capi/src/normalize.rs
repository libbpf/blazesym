use std::ffi::CString;
use std::ffi::OsString;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem::size_of;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::ptr;
use std::slice;

use blazesym::normalize::Apk;
use blazesym::normalize::Elf;
use blazesym::normalize::Normalizer;
use blazesym::normalize::Unknown;
use blazesym::normalize::UserMeta;
use blazesym::normalize::UserOutput;
use blazesym::Addr;

use crate::slice_from_user_array;


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
    /// Whether to read and report build IDs as part of the normalization
    /// process.
    pub build_ids: bool,
    /// Unused member available for future expansion. Must be initialized
    /// to zero.
    pub reserved: [u8; 7],
}

impl Default for blaze_normalizer_opts {
    fn default() -> Self {
        Self {
            type_size: size_of::<Self>(),
            build_ids: false,
            reserved: [0; 7],
        }
    }
}


/// Create an instance of a blazesym normalizer.
///
/// The returned pointer should be released using [`blaze_normalizer_free`] once
/// it is no longer needed.
#[no_mangle]
pub extern "C" fn blaze_normalizer_new() -> *mut blaze_normalizer {
    let normalizer = Normalizer::new();
    let normalizer_box = Box::new(normalizer);
    Box::into_raw(normalizer_box)
}


/// Create an instance of a blazesym normalizer.
///
/// The returned pointer should be released using [`blaze_normalizer_free`] once
/// it is no longer needed.
///
/// # Safety
/// The provided pointer needs to point to a valid [`blaze_normalizer_opts`]
/// instance.
#[no_mangle]
pub unsafe extern "C" fn blaze_normalizer_new_opts(
    opts: *const blaze_normalizer_opts,
) -> *mut blaze_normalizer {
    if !input_zeroed!(opts, blaze_normalizer_opts) {
        return ptr::null_mut()
    }
    let opts = input_sanitize!(opts, blaze_normalizer_opts);

    let blaze_normalizer_opts {
        type_size: _,
        build_ids,
        reserved: _,
    } = opts;

    let normalizer = Normalizer::builder().enable_build_ids(build_ids).build();
    let normalizer_box = Box::new(normalizer);
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
}

impl From<(u64, usize)> for blaze_normalized_output {
    fn from((output, meta_idx): (u64, usize)) -> Self {
        Self { output, meta_idx }
    }
}


/// The valid variant kind in [`blaze_user_meta`].
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum blaze_user_meta_kind {
    /// [`blaze_user_meta_variant::unknown`] is valid.
    BLAZE_USER_META_UNKNOWN,
    /// [`blaze_user_meta_variant::apk`] is valid.
    BLAZE_USER_META_APK,
    /// [`blaze_user_meta_variant::elf`] is valid.
    BLAZE_USER_META_ELF,
}


/// C compatible version of [`Apk`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_apk {
    /// The canonical absolute path to the APK, including its name.
    /// This member is always present.
    pub path: *mut c_char,
    /// Unused member available for future expansion.
    pub reserved: [u8; 8],
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
            reserved: [0u8; 8],
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
    /// The path to the ELF file. This member is always present.
    pub path: *mut c_char,
    /// The length of the build ID, in bytes.
    pub build_id_len: usize,
    /// The optional build ID of the ELF file, if found.
    pub build_id: *mut u8,
    /// Unused member available for future expansion.
    pub reserved: [u8; 8],
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
                        Box::into_raw(build_id.into_boxed_slice())
                            .as_mut()
                            .unwrap()
                            .as_mut_ptr()
                    }
                })
                .unwrap_or_else(ptr::null_mut),
            reserved: [0u8; 8],
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
                Box::<[u8]>::from_raw(slice::from_raw_parts_mut(build_id, build_id_len)).into_vec()
            }),
            _non_exhaustive: (),
        };
    }
}


/// C compatible version of [`Unknown`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_meta_unknown {
    /// Unused member available for future expansion.
    pub reserved: [u8; 8],
}

impl blaze_user_meta_unknown {
    fn from(other: Unknown) -> ManuallyDrop<Self> {
        let Unknown {
            _non_exhaustive: (),
        } = other;

        let slf = Self { reserved: [0u8; 8] };
        ManuallyDrop::new(slf)
    }

    fn free(self) {
        let blaze_user_meta_unknown { reserved: _ } = self;
    }
}


/// The actual variant data in [`blaze_user_meta`].
#[repr(C)]
pub union blaze_user_meta_variant {
    /// Valid on [`blaze_user_meta_kind::BLAZE_USER_META_APK`].
    pub apk: ManuallyDrop<blaze_user_meta_apk>,
    /// Valid on [`blaze_user_meta_kind::BLAZE_USER_META_ELF`].
    pub elf: ManuallyDrop<blaze_user_meta_elf>,
    /// Valid on [`blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN`].
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
    /// The actual variant with its data.
    pub variant: blaze_user_meta_variant,
}

impl blaze_user_meta {
    fn from(other: UserMeta) -> ManuallyDrop<Self> {
        let slf = match other {
            UserMeta::Apk(apk) => Self {
                kind: blaze_user_meta_kind::BLAZE_USER_META_APK,
                variant: blaze_user_meta_variant {
                    apk: blaze_user_meta_apk::from(apk),
                },
            },
            UserMeta::Elf(elf) => Self {
                kind: blaze_user_meta_kind::BLAZE_USER_META_ELF,
                variant: blaze_user_meta_variant {
                    elf: blaze_user_meta_elf::from(elf),
                },
            },
            UserMeta::Unknown(unknown) => Self {
                kind: blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN,
                variant: blaze_user_meta_variant {
                    unknown: blaze_user_meta_unknown::from(unknown),
                },
            },
            _ => unreachable!(),
        };
        ManuallyDrop::new(slf)
    }

    unsafe fn free(self) {
        match self.kind {
            blaze_user_meta_kind::BLAZE_USER_META_APK => unsafe {
                ManuallyDrop::into_inner(self.variant.apk).free()
            },
            blaze_user_meta_kind::BLAZE_USER_META_ELF => unsafe {
                ManuallyDrop::into_inner(self.variant.elf).free()
            },
            blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN => {
                ManuallyDrop::into_inner(unsafe { self.variant.unknown }).free()
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
    pub reserved: [u8; 8],
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
            reserved: [0u8; 8],
        };
        ManuallyDrop::new(slf)
    }
}


/// Normalize a list of user space addresses.
///
/// Contrary to [`blaze_normalize_user_addrs_sorted`] the provided
/// `addrs` array does not have to be sorted, but otherwise the
/// functions behave identically. If you happen to know that `addrs` is
/// sorted, using [`blaze_normalize_user_addrs_sorted`] instead will
/// result in slightly faster normalization.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs`].
/// Returns `NULL` on error. The resulting object should be freed using
/// [`blaze_user_output_free`].
///
/// # Safety
/// Callers need to pass in a valid `addrs` pointer, pointing to memory of
/// `addr_cnt` addresses.
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs(
    normalizer: *const blaze_normalizer,
    pid: u32,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *mut blaze_normalized_user_output {
    // SAFETY: The caller needs to ensure that `normalizer` is a valid
    //         pointer.
    let normalizer = unsafe { &*normalizer };
    // SAFETY: The caller needs to ensure that `addrs` is a valid pointer and
    //         that it points to `addr_cnt` elements.
    let addrs = unsafe { slice_from_user_array(addrs, addr_cnt) };
    let result = normalizer.normalize_user_addrs(pid.into(), addrs);
    match result {
        Ok(addrs) => Box::into_raw(Box::new(ManuallyDrop::into_inner(
            blaze_normalized_user_output::from(addrs),
        ))),
        Err(_err) => ptr::null_mut(),
    }
}


/// Normalize a list of user space addresses.
///
/// The `addrs` array has to be sorted in ascending order. By providing
/// a pre-sorted array the library does not have to sort internally,
/// which will result in quicker normalization. If you don't have sorted
/// addresses, use [`blaze_normalize_user_addrs`] instead.
///
/// `pid` should describe the PID of the process to which the addresses
/// belongs. It may be `0` if they belong to the calling process.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs_sorted`].
/// Returns `NULL` on error. The resulting object should be freed using
/// [`blaze_user_output_free`].
///
/// # Safety
/// Callers need to pass in a valid `addrs` pointer, pointing to memory of
/// `addr_cnt` addresses.
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs_sorted(
    normalizer: *const blaze_normalizer,
    pid: u32,
    addrs: *const Addr,
    addr_cnt: usize,
) -> *mut blaze_normalized_user_output {
    // SAFETY: The caller needs to ensure that `normalizer` is a valid
    //         pointer.
    let normalizer = unsafe { &*normalizer };
    // SAFETY: The caller needs to ensure that `addrs` is a valid pointer and
    //         that it points to `addr_cnt` elements.
    let addrs = unsafe { slice_from_user_array(addrs, addr_cnt) };
    let result = normalizer.normalize_user_addrs_sorted(pid.into(), addrs);
    match result {
        Ok(addrs) => Box::into_raw(Box::new(ManuallyDrop::into_inner(
            blaze_normalized_user_output::from(addrs),
        ))),
        Err(_err) => ptr::null_mut(),
    }
}

/// Free an object as returned by [`blaze_normalize_user_addrs`] or
/// [`blaze_normalize_user_addrs_sorted`].
///
/// # Safety
/// The provided object should have been created by
/// [`blaze_normalize_user_addrs`] or [`blaze_normalize_user_addrs_sorted`].
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


    /// Check that various types have expected sizes.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn type_sizes() {
        assert_eq!(size_of::<blaze_normalizer_opts>(), 16);
        assert_eq!(size_of::<blaze_user_meta_apk>(), 16);
        assert_eq!(size_of::<blaze_user_meta_elf>(), 32);
        assert_eq!(size_of::<blaze_user_meta_unknown>(), 8);
    }

    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let output = blaze_normalized_output {
            output: 0x1337,
            meta_idx: 1,
        };
        assert_eq!(
            format!("{output:?}"),
            "blaze_normalized_output { output: 4919, meta_idx: 1 }"
        );

        let meta_kind = blaze_user_meta_kind::BLAZE_USER_META_APK;
        assert_eq!(format!("{meta_kind:?}"), "BLAZE_USER_META_APK");

        let apk = blaze_user_meta_apk {
            path: ptr::null_mut(),
            reserved: [0u8; 8],
        };
        assert_eq!(
            format!("{apk:?}"),
            "blaze_user_meta_apk { path: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let elf = blaze_user_meta_elf {
            path: ptr::null_mut(),
            build_id_len: 0,
            build_id: ptr::null_mut(),
            reserved: [0u8; 8],
        };
        assert_eq!(
            format!("{elf:?}"),
            "blaze_user_meta_elf { path: 0x0, build_id_len: 0, build_id: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let unknown = blaze_user_meta_unknown { reserved: [0u8; 8] };
        assert_eq!(
            format!("{unknown:?}"),
            "blaze_user_meta_unknown { reserved: [0, 0, 0, 0, 0, 0, 0, 0] }",
        );

        let meta = blaze_user_meta {
            kind: blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN,
            variant: blaze_user_meta_variant {
                unknown: ManuallyDrop::new(blaze_user_meta_unknown { reserved: [0u8; 8] }),
            },
        };
        assert_eq!(
            format!("{meta:?}"),
            "blaze_user_meta { kind: BLAZE_USER_META_UNKNOWN, variant: blaze_user_meta_variant }",
        );

        let user_addrs = blaze_normalized_user_output {
            meta_cnt: 0,
            metas: ptr::null_mut(),
            output_cnt: 0,
            outputs: ptr::null_mut(),
            reserved: [0u8; 8],
        };
        assert_eq!(
            format!("{user_addrs:?}"),
            "blaze_normalized_user_output { meta_cnt: 0, metas: 0x0, output_cnt: 0, outputs: 0x0, reserved: [0, 0, 0, 0, 0, 0, 0, 0] }",
        );
    }

    /// Check that we can convert an [`Unknown`] into a
    /// [`blaze_user_meta_unknown`] and back.
    #[test]
    fn unknown_conversion() {
        let unknown = Unknown {
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
    #[test]
    fn elf_conversion() {
        let elf = Elf {
            path: PathBuf::from("/tmp/file.so"),
            build_id: Some(vec![0x01, 0x02, 0x03, 0x04]),
            _non_exhaustive: (),
        };

        let elf_c = blaze_user_meta_elf::from(elf.clone());
        let () = unsafe { ManuallyDrop::into_inner(elf_c).free() };

        let meta = UserMeta::Elf(elf);
        let meta_c = blaze_user_meta::from(meta);
        let () = unsafe { ManuallyDrop::into_inner(meta_c).free() };
    }

    /// Make sure that we can create and free a normalizer instance.
    #[test]
    fn normalizer_creation() {
        let normalizer = blaze_normalizer_new();
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can normalize user space addresses.
    #[test]
    fn normalize_user_addrs() {
        let addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
            elf_conversion as Addr,
            normalize_user_addrs as Addr,
        ];

        let normalizer = blaze_normalizer_new();
        assert_ne!(normalizer, ptr::null_mut());

        let result = unsafe {
            blaze_normalize_user_addrs(normalizer, 0, addrs.as_slice().as_ptr(), addrs.len())
        };
        assert_ne!(result, ptr::null_mut());

        let user_addrs = unsafe { &*result };
        assert_eq!(user_addrs.meta_cnt, 2);
        assert_eq!(user_addrs.output_cnt, 5);

        let () = unsafe { blaze_user_output_free(result) };
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can normalize sorted user space addresses.
    #[test]
    fn normalize_user_addrs_sorted() {
        let mut addrs = [
            libc::__errno_location as Addr,
            libc::dlopen as Addr,
            libc::fopen as Addr,
            elf_conversion as Addr,
            normalize_user_addrs as Addr,
        ];
        let () = addrs.sort();

        let normalizer = blaze_normalizer_new();
        assert_ne!(normalizer, ptr::null_mut());

        let result = unsafe {
            blaze_normalize_user_addrs_sorted(normalizer, 0, addrs.as_slice().as_ptr(), addrs.len())
        };
        assert_ne!(result, ptr::null_mut());

        let user_addrs = unsafe { &*result };
        assert_eq!(user_addrs.meta_cnt, 2);
        assert_eq!(user_addrs.output_cnt, 5);

        let () = unsafe { blaze_user_output_free(result) };
        let () = unsafe { blaze_normalizer_free(normalizer) };
    }

    /// Check that we can enable/disable the reading of build IDs.
    #[test]
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

            let addrs = [the_answer_addr as Addr];
            let result = unsafe {
                blaze_normalize_user_addrs_sorted(
                    normalizer,
                    0,
                    addrs.as_slice().as_ptr(),
                    addrs.len(),
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
            assert_eq!(meta.kind, blaze_user_meta_kind::BLAZE_USER_META_ELF);

            let elf = unsafe { &meta.variant.elf };

            assert!(!elf.path.is_null());
            let path = unsafe { CStr::from_ptr(elf.path) };
            assert_eq!(path, so_cstr.as_ref());

            if read_build_ids {
                let expected = read_elf_build_id(&test_so).unwrap().unwrap();
                let build_id = unsafe { slice_from_user_array(elf.build_id, elf.build_id_len) };
                assert_eq!(build_id, &expected);
            } else {
                assert!(elf.build_id.is_null());
            }

            let () = unsafe { blaze_user_output_free(result) };
            let () = unsafe { blaze_normalizer_free(normalizer) };
        }

        test(true);
        test(false);
    }
}
