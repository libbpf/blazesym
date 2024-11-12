//! C API bindings for [`blazesym`]. Please refer to its documentation
//! for a high level overview of the functionality provided.
//!
//! # Error handling
//! Fallible functions generally return a `NULL` pointer. To provide
//! users with a better idea of what went wrong, they additionally set a
//! thread local last [error code][blaze_err]. This error indicates what
//! kind of issue caused the operation to fail.
//! A call to a fallible function always overwrites this error code. As
//! such, please make sure to check the error before making an
//! additional API call into the library.
//!
//! # Thread-Safety
//! The library does not perform any synchronization of concurrent
//! accesses to the same object. However, state is strictly kept at the
//! object level (no shared global state), meaning that while concurrent
//! accesses to the *same* object (e.g., multiple
//! [`blaze_symbolize_process_abs_addrs`] calls on the same
//! [`blaze_symbolizer`] instance) from multiple threads necessitates
//! serialization at the call site, it is fine to issue requests to
//! different objects from multiple threads.
//!
//! # Compatibility
//! The library aims to provide forward compatibility with newer
//! versions and backward compatibility with older ones. To make that
//! happen, relevant types that are being passed to the library contain
//! the `type_size` member that is to be set to the type's size, e.g.:
//! ```c
#![doc = include_str!("../examples/input-struct-init.c")]
//! ```

#![allow(
    non_camel_case_types,
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
                crate::util::is_mem_zero(
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


mod error;
mod helper;
mod inspect;
mod normalize;
mod symbolize;
mod trace;
mod util;

pub use error::*;
pub use helper::*;
pub use inspect::*;
pub use normalize::*;
pub use symbolize::*;
pub use trace::*;
