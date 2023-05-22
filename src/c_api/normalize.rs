use std::ffi::CString;
use std::ffi::OsString;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::ptr;
use std::slice;

use crate::log::error;
use crate::normalize::Binary;
use crate::normalize::NormalizedUserAddrs;
use crate::normalize::Normalizer;
use crate::normalize::Unknown;
use crate::normalize::UserAddrMeta;
use crate::util::slice_from_user_array;
use crate::Addr;


/// Create an instance of a blazesym normalizer.
///
/// The returned pointer should be released using
/// [`blaze_normalizer_free`] once it is no longer needed.
#[no_mangle]
pub extern "C" fn blaze_normalizer_new() -> *mut Normalizer {
    let normalizer = Normalizer::new();
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
pub unsafe extern "C" fn blaze_normalizer_free(normalizer: *mut Normalizer) {
    if !normalizer.is_null() {
        // SAFETY: The caller needs to ensure that `normalizer` is a
        //         valid pointer.
        drop(unsafe { Box::from_raw(normalizer) });
    }
}


/// A normalized address along with an index into the associated
/// [`blaze_user_addr_meta`] array (such as
/// [`blaze_normalized_user_addrs::metas`]).
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalized_addr {
    /// The normalized address.
    pub addr: Addr,
    /// The index into the associated [`blaze_user_addr_meta`] array.
    pub meta_idx: usize,
}

impl From<(Addr, usize)> for blaze_normalized_addr {
    fn from((addr, meta_idx): (Addr, usize)) -> Self {
        Self { addr, meta_idx }
    }
}


/// The valid variant kind in [`blaze_user_addr_meta`].
#[repr(C)]
#[derive(Debug)]
pub enum blaze_user_addr_meta_kind {
    /// [`blaze_user_addr_meta_variant::unknown`] is valid.
    BLAZE_USER_ADDR_UNKNOWN,
    /// [`blaze_user_addr_meta_variant::binary`] is valid.
    BLAZE_USER_ADDR_BINARY,
}


/// C compatible version of [`Binary`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_addr_meta_binary {
    /// The path to the binary. This member is always present.
    path: *mut c_char,
    /// The length of the build ID, in bytes.
    build_id_len: usize,
    /// The optional build ID of the binary, if found.
    build_id: *mut u8,
}

impl From<Binary> for blaze_user_addr_meta_binary {
    fn from(other: Binary) -> Self {
        let Binary {
            path,
            build_id,
            _non_exhaustive: (),
        } = other;
        Self {
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
        }
    }
}

impl From<blaze_user_addr_meta_binary> for Binary {
    fn from(other: blaze_user_addr_meta_binary) -> Self {
        let blaze_user_addr_meta_binary {
            path,
            build_id_len,
            build_id,
        } = other;

        Binary {
            path: PathBuf::from(OsString::from_vec(
                unsafe { CString::from_raw(path) }.into_bytes(),
            )),
            build_id: (!build_id.is_null()).then(|| unsafe {
                Box::<[u8]>::from_raw(slice::from_raw_parts_mut(build_id, build_id_len)).into_vec()
            }),
            _non_exhaustive: (),
        }
    }
}


/// C compatible version of [`Unknown`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_addr_meta_unknown {
    __unused: u8,
}

impl From<Unknown> for blaze_user_addr_meta_unknown {
    fn from(other: Unknown) -> Self {
        let Unknown {
            _non_exhaustive: (),
        } = other;
        Self { __unused: 0 }
    }
}

impl From<blaze_user_addr_meta_unknown> for Unknown {
    fn from(other: blaze_user_addr_meta_unknown) -> Self {
        let blaze_user_addr_meta_unknown { __unused } = other;
        Unknown {
            _non_exhaustive: (),
        }
    }
}


/// The actual variant data in [`blaze_user_addr_meta`].
#[repr(C)]
pub union blaze_user_addr_meta_variant {
    /// Valid on [`blaze_user_addr_meta_kind::BLAZE_USER_ADDR_BINARY`].
    pub binary: ManuallyDrop<blaze_user_addr_meta_binary>,
    /// Valid on [`blaze_user_addr_meta_kind::BLAZE_USER_ADDR_UNKNOWN`].
    pub unknown: ManuallyDrop<blaze_user_addr_meta_unknown>,
}

impl Debug for blaze_user_addr_meta_variant {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct(stringify!(blaze_user_addr_meta_variant))
            .finish()
    }
}


/// C ABI compatible version of [`UserAddrMeta`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_user_addr_meta {
    /// The variant kind that is present.
    kind: blaze_user_addr_meta_kind,
    /// The actual variant with its data.
    variant: blaze_user_addr_meta_variant,
}

impl From<UserAddrMeta> for blaze_user_addr_meta {
    fn from(other: UserAddrMeta) -> Self {
        match other {
            UserAddrMeta::Binary(binary) => Self {
                kind: blaze_user_addr_meta_kind::BLAZE_USER_ADDR_BINARY,
                variant: blaze_user_addr_meta_variant {
                    binary: ManuallyDrop::new(blaze_user_addr_meta_binary::from(binary)),
                },
            },
            UserAddrMeta::Unknown(unknown) => Self {
                kind: blaze_user_addr_meta_kind::BLAZE_USER_ADDR_UNKNOWN,
                variant: blaze_user_addr_meta_variant {
                    unknown: ManuallyDrop::new(blaze_user_addr_meta_unknown::from(unknown)),
                },
            },
        }
    }
}


/// An object representing normalized user addresses.
///
/// C ABI compatible version of [`NormalizedUserAddrs`].
#[repr(C)]
#[derive(Debug)]
pub struct blaze_normalized_user_addrs {
    /// The number of [`blaze_user_addr_meta`] objects present in `metas`.
    pub meta_count: usize,
    /// An array of `meta_count` objects.
    pub metas: *mut blaze_user_addr_meta,
    /// The number of [`blaze_normalized_addr`] objects present in `addrs`.
    pub addr_count: usize,
    /// An array of `addr_count` objects.
    pub addrs: *mut blaze_normalized_addr,
}

impl From<NormalizedUserAddrs> for blaze_normalized_user_addrs {
    fn from(other: NormalizedUserAddrs) -> Self {
        Self {
            meta_count: other.meta.len(),
            metas: unsafe {
                Box::into_raw(
                    other
                        .meta
                        .into_iter()
                        .map(blaze_user_addr_meta::from)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
                .as_mut()
                .unwrap()
                .as_mut_ptr()
            },
            addr_count: other.addrs.len(),
            addrs: unsafe {
                Box::into_raw(
                    other
                        .addrs
                        .into_iter()
                        .map(blaze_normalized_addr::from)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
                .as_mut()
                .unwrap()
                .as_mut_ptr()
            },
        }
    }
}


/// Normalize a list of user space addresses.
///
/// The `addrs` array has to be sorted in ascending order. `pid` should
/// describe the PID of the process to which the addresses belong. It
/// may be `0` if they belong to the calling process.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs`].
/// Returns `NULL` on error. The resulting object should be freed using
/// [`blaze_user_addrs_free`].
///
/// # Safety
/// Callers need to pass in a valid `addrs` pointer, pointing to memory of
/// `addr_count` addresses.
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs(
    normalizer: *const Normalizer,
    addrs: *const Addr,
    addr_count: usize,
    pid: u32,
) -> *mut blaze_normalized_user_addrs {
    // SAFETY: The caller needs to ensure that `normalizer` is a valid
    //         pointer.
    let normalizer = unsafe { &*normalizer };
    // SAFETY: The caller needs to ensure that `addrs` is a valid pointer and
    //         that it points to `addr_count` elements.
    let addrs = unsafe { slice_from_user_array(addrs, addr_count) };
    let result = normalizer.normalize_user_addrs(addrs, pid.into());
    match result {
        Ok(addrs) => Box::into_raw(Box::new(blaze_normalized_user_addrs::from(addrs))),
        Err(err) => {
            error!("failed to normalize user addresses: {err}");
            ptr::null_mut()
        }
    }
}


/// Normalize a list of user space addresses.
///
/// `pid` should describe the PID of the process to which the addresses belong.
/// It may be `0` if they belong to the calling process.
///
/// C ABI compatible version of [`Normalizer::normalize_user_addrs_sorted`].
/// Returns `NULL` on error. The resulting object should be freed using
/// [`blaze_user_addrs_free`].
///
/// # Safety
/// Callers need to pass in a valid `addrs` pointer, pointing to memory of
/// `addr_count` addresses.
#[no_mangle]
pub unsafe extern "C" fn blaze_normalize_user_addrs_sorted(
    normalizer: *const Normalizer,
    addrs: *const Addr,
    addr_count: usize,
    pid: u32,
) -> *mut blaze_normalized_user_addrs {
    // SAFETY: The caller needs to ensure that `normalizer` is a valid
    //         pointer.
    let normalizer = unsafe { &*normalizer };
    // SAFETY: The caller needs to ensure that `addrs` is a valid pointer and
    //         that it points to `addr_count` elements.
    let addrs = unsafe { slice_from_user_array(addrs, addr_count) };
    let result = normalizer.normalize_user_addrs_sorted(addrs, pid.into());
    match result {
        Ok(addrs) => Box::into_raw(Box::new(blaze_normalized_user_addrs::from(addrs))),
        Err(err) => {
            error!("failed to normalize user addresses: {err}");
            ptr::null_mut()
        }
    }
}

/// Free an object as returned by [`blaze_normalized_user_addrs`] or
/// [`blaze_normalize_user_addrs_sorted`].
///
/// # Safety
/// The provided object should have been created by
/// [`blaze_normalized_user_addrs`] or
/// [`blaze_normalize_user_addrs_sorted`].
#[no_mangle]
pub unsafe extern "C" fn blaze_user_addrs_free(addrs: *mut blaze_normalized_user_addrs) {
    if addrs.is_null() {
        return
    }

    // SAFETY: The caller should make sure that `addrs` was created by
    //         `blaze_normalize_user_addrs_sorted`.
    let user_addrs = unsafe { Box::from_raw(addrs) };
    let addr_metas = unsafe {
        Box::<[blaze_user_addr_meta]>::from_raw(slice::from_raw_parts_mut(
            user_addrs.metas,
            user_addrs.meta_count,
        ))
    }
    .into_vec();
    let _norm_addrs = unsafe {
        Box::<[blaze_normalized_addr]>::from_raw(slice::from_raw_parts_mut(
            user_addrs.addrs,
            user_addrs.addr_count,
        ))
    }
    .into_vec();

    for addr_meta in addr_metas {
        match addr_meta.kind {
            blaze_user_addr_meta_kind::BLAZE_USER_ADDR_BINARY => {
                let _binary = Binary::from(ManuallyDrop::into_inner(unsafe {
                    addr_meta.variant.binary
                }));
            }
            blaze_user_addr_meta_kind::BLAZE_USER_ADDR_UNKNOWN => {
                let _unknown = Unknown::from(ManuallyDrop::into_inner(unsafe {
                    addr_meta.variant.unknown
                }));
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can convert an [`Unknown`] into a
    /// [`blaze_user_addr_meta_unknown`] and back.
    #[test]
    fn unknown_convesion() {
        let unknown = Unknown {
            _non_exhaustive: (),
        };

        let unknown_new = Unknown::from(blaze_user_addr_meta_unknown::from(unknown.clone()));
        assert_eq!(unknown_new, unknown);
    }

    /// Check that we correctly format the debug representation of a
    /// [`blaze_user_addr_meta_variant`].
    #[test]
    fn debug_meta_variant() {
        let unknown = blaze_user_addr_meta_unknown { __unused: 0 };
        let variant = blaze_user_addr_meta_variant {
            unknown: ManuallyDrop::new(unknown),
        };
        assert_eq!(format!("{variant:?}"), "blaze_user_addr_meta_variant");
    }
}
