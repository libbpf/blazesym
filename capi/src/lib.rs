//! C API bindings for the library.
//!
//! # Compatibility
//! The library aims to provide forward compatibility with newer
//! versions and backward compatibility with older ones. To make that
//! happen, relevant types that are being passed to the library contain
//! the `type_size` member that is to be set to the type's size. The
//! `BLAZE_INPUT` macro can be used for convenient initialization:
//! ```c
#![doc = include_str!("../examples/input-struct-init.c")]
//! ```

#![allow(
    clippy::collapsible_if,
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::manual_non_exhaustive
)]
#![deny(unsafe_op_in_unsafe_fn)]


macro_rules! input_zeroed {
    ($container_ptr:ident, $container_ty:ty) => {{
        // Each input type's first member is a `usize`.
        let user_size = unsafe { $container_ptr.cast::<usize>().read() };
        if user_size < std::mem::size_of_val(&user_size) {
            false
        } else {
            let effective_size = memoffset::offset_of!($container_ty, reserved);
            unsafe {
                crate::is_mem_zero(
                    $container_ptr.cast::<u8>().add(effective_size),
                    user_size.saturating_sub(effective_size),
                )
            }
        }
    }};
}


macro_rules! input_sanitize {
    ($container_ptr:ident, $container_ty:ty) => {
        unsafe {
            let user_type_size = (*$container_ptr).type_size;
            if (user_type_size < std::mem::size_of::<$container_ty>()) {
                let mut obj = std::mem::MaybeUninit::<$container_ty>::uninit();
                let buf = obj.as_mut_ptr().cast::<u8>();
                // Copy user data over local copy.
                let () =
                    std::ptr::copy_nonoverlapping($container_ptr.cast::<u8>(), buf, user_type_size);

                let () = std::ptr::write_bytes(
                    buf.add(user_type_size),
                    0,
                    std::mem::size_of::<$container_ty>() - user_type_size,
                );
                obj.assume_init()
            } else {
                $container_ptr.read()
            }
        }
    };
}


#[allow(non_camel_case_types)]
mod inspect;
#[allow(non_camel_case_types)]
mod normalize;
#[allow(non_camel_case_types)]
mod symbolize;

use std::ptr::NonNull;
use std::slice;

pub use inspect::*;
pub use normalize::*;
pub use symbolize::*;


/// Check whether the given piece of memory is zeroed out.
///
/// # Safety
/// The caller needs to make sure that `mem` points to `len` (or more) bytes of
/// valid memory.
pub(crate) unsafe fn is_mem_zero(mut mem: *const u8, mut len: usize) -> bool {
    while len > 0 {
        if unsafe { mem.read() } != 0 {
            return false
        }
        mem = unsafe { mem.add(1) };
        len -= 1;
    }
    true
}


/// "Safely" create a slice from a user provided array.
pub(crate) unsafe fn slice_from_user_array<'t, T>(items: *const T, num_items: usize) -> &'t [T] {
    let items = if items.is_null() {
        // `slice::from_raw_parts` requires a properly aligned non-NULL pointer.
        // Craft one.
        NonNull::dangling().as_ptr()
    } else {
        items
    };
    unsafe { slice::from_raw_parts(items, num_items) }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;


    /// Check that `is_mem_zero` works as it should.
    #[test]
    fn mem_zeroed_checking() {
        let mut bytes = [0u8; 64];
        assert!(
            unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) },
            "{bytes:#x?}"
        );

        bytes[bytes.len() / 2] = 42;
        assert!(
            !unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) },
            "{bytes:#x?}"
        );
    }

    /// Test the `slice_from_user_array` helper in the presence of various
    /// inputs.
    #[test]
    fn slice_creation() {
        let slice = unsafe { slice_from_user_array::<u64>(ptr::null(), 0) };
        assert_eq!(slice, &[]);

        let array = [];
        let slice = unsafe { slice_from_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[]);

        let array = [42u64, 1337];
        let slice = unsafe { slice_from_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[42, 1337]);
    }
}
