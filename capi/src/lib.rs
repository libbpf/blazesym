//! C API bindings for the library.

#![allow(
    clippy::collapsible_if,
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]
#![deny(unsafe_op_in_unsafe_fn)]


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
