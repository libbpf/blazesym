use std::borrow::Cow;
use std::mem::align_of;
use std::ptr::NonNull;
use std::slice;


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

/// "Safely" create a slice from an aligned user provided array.
pub(crate) unsafe fn slice_from_aligned_user_array<'t, T>(
    items: *const T,
    num_items: usize,
) -> &'t [T] {
    let items = if items.is_null() {
        // `slice::from_raw_parts` requires a properly aligned non-NULL pointer.
        // Craft one.
        NonNull::dangling().as_ptr()
    } else {
        items
    };
    unsafe { slice::from_raw_parts(items, num_items) }
}

/// "Safely" create a slice from a user provided array.
pub(crate) unsafe fn slice_from_user_array<'t, T>(items: *const T, num_items: usize) -> Cow<'t, [T]>
where
    T: Clone,
{
    #[cold]
    fn safely_copy_to_allocated_slow<T>(items: *const T, num_items: usize) -> Vec<T>
    where
        T: Clone,
    {
        if items.is_null() {
            Vec::new()
        } else {
            let mut src = items;
            let mut buffer = Vec::<T>::with_capacity(num_items);
            let mut dst = buffer.as_mut_ptr();

            for _ in 0..num_items {
                let () = unsafe { dst.write(src.read_unaligned()) };
                src = unsafe { src.add(1) };
                dst = unsafe { dst.add(1) };
            }
            let () = unsafe { buffer.set_len(num_items) };
            buffer
        }
    }

    if items.align_offset(align_of::<T>()) == 0 {
        let slice = unsafe { slice_from_aligned_user_array(items, num_items) };
        Cow::Borrowed(slice)
    } else {
        let vec = safely_copy_to_allocated_slow(items, num_items);
        Cow::Owned(vec)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ops::Deref as _;
    use std::ptr;

    use test_tag::tag;


    /// Check that `is_mem_zero` works as it should.
    #[tag(miri)]
    #[test]
    fn mem_zeroed_checking() {
        let mut bytes = [0u8; 64];
        let zero = unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) };
        assert!(zero, "{bytes:#x?}");

        bytes[bytes.len() / 2] = 42;
        let zero = unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) };
        assert!(!zero, "{bytes:#x?}");
    }

    /// Test the `slice_from_aligned_user_array` helper in the presence of
    /// various inputs.
    #[tag(miri)]
    #[test]
    fn slice_creation() {
        let slice = unsafe { slice_from_aligned_user_array::<u64>(ptr::null(), 0) };
        assert_eq!(slice, &[]);

        let array = [];
        let slice =
            unsafe { slice_from_aligned_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[]);

        let array = [42u64, 1337];
        let slice =
            unsafe { slice_from_aligned_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[42, 1337]);
    }

    /// Make sure that we can create a slice from a potentially unaligned C
    /// array of values.
    #[tag(miri)]
    #[test]
    fn unaligned_slice_creation() {
        let slice = unsafe { slice_from_user_array(ptr::null::<u64>(), 0) };
        assert_eq!(slice.deref(), &[]);

        let mut buffer = [0u64; 8];
        let ptr = unsafe { buffer.as_mut_ptr().byte_add(3) };

        let slice = unsafe { slice_from_user_array(ptr, buffer.len() - 1) };
        assert!(matches!(slice, Cow::Owned(..)), "{slice:?}");
        assert_eq!(slice.len(), buffer.len() - 1);

        let slice = unsafe { slice_from_user_array(buffer.as_ptr(), buffer.len()) };
        assert!(matches!(slice, Cow::Borrowed(..)), "{slice:?}");
        assert_eq!(slice.len(), buffer.len());
    }
}
