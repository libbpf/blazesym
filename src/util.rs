use std::cmp::Ordering;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::iter;
use std::mem::align_of;
use std::mem::size_of;
use std::mem::MaybeUninit;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::slice;
#[cfg(not(unix))]
use std::str::from_utf8;

use crate::Addr;


#[cfg(feature = "tracing")]
pub(crate) struct Hexify<'addrs>(pub &'addrs [Addr]);

#[cfg(feature = "tracing")]
impl Debug for Hexify<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut lst = f.debug_list();
        for addr in self.0 {
            let _lst = lst.entry(&format_args!("{addr:#x}"));
        }
        lst.finish()
    }
}


/// A type providing a derive for `Debug` for types that
/// otherwise don't.
#[repr(transparent)]
pub(crate) struct Dbg<T>(pub T)
where
    T: ?Sized;

impl<T> Debug for Dbg<T>
where
    T: ?Sized,
{
    #[inline]
    fn fmt(&self, fmt: &mut Formatter<'_>) -> FmtResult {
        write!(fmt, "{:?}", &self.0 as *const T)
    }
}


#[derive(Clone, Debug)]
pub(crate) enum Either<A, B> {
    A(A),
    B(B),
}

impl<A, B, T> Iterator for Either<A, B>
where
    A: Iterator<Item = T>,
    B: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::A(a) => a.next(),
            Self::B(b) => b.next(),
        }
    }
}

impl<A, B, T> ExactSizeIterator for Either<A, B>
where
    A: ExactSizeIterator<Item = T>,
    B: ExactSizeIterator<Item = T>,
{
}


/// Split a byte slice at the first byte for which `check` returns
/// `true`.
///
/// # Notes
/// The byte at which the split happens is not included in either of the
/// returned sliced.
pub(crate) fn split_bytes<F>(bytes: &[u8], mut check: F) -> Option<(&[u8], &[u8])>
where
    F: FnMut(u8) -> bool,
{
    let (idx, _) = bytes.iter().enumerate().find(|(_idx, b)| check(**b))?;
    let (left, right) = bytes.split_at(idx);
    Some((left, &right[1..]))
}

// TODO: This is a copy of unstable `trim_ascii_start` from std. Once
//       stabilized, we should remove this functionality in favor of the std
//       version.
#[inline]
pub(crate) fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

// TODO: This is a copy of unstable `trim_ascii_end` from std. Once stabilized,
//       we should remove this functionality in favor of the std version.
#[inline]
pub(crate) fn trim_ascii_end(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

// TODO: This is a copy of unstable `trim_ascii` from std. Once stabilized,
//       we should remove this functionality in favor of the std version.
#[inline]
pub(crate) fn trim_ascii(bytes: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(bytes))
}

/// Splits the slice on the first element that matches the specified predicate.
// TODO: This is a copy of unstable `<[u8]>::split_once` from std. Once
//       stabilized, we should remove this functionality in favor of the std
//       version.
#[inline]
pub(crate) fn split_once<F>(bytes: &[u8], pred: F) -> Option<(&[u8], &[u8])>
where
    F: FnMut(&u8) -> bool,
{
    let index = bytes.iter().position(pred)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

/// Converts an ascii character to digit
fn ascii_to_hexdigit(character: u8) -> Option<u64> {
    match character {
        b'0' => Some(0),
        b'1' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'a' | b'A' => Some(10),
        b'b' | b'B' => Some(11),
        b'c' | b'C' => Some(12),
        b'd' | b'D' => Some(13),
        b'e' | b'E' => Some(14),
        b'f' | b'F' => Some(15),
        _ => None,
    }
}

pub(crate) fn from_radix_16(text: &[u8]) -> Option<u64> {
    let mut index = 0;
    let mut number = 0;
    while index != text.len() {
        if let Some(digit) = ascii_to_hexdigit(text[index]) {
            number *= 16;
            number += digit;
            index += 1;
        } else {
            return None
        }
    }
    Some(number)
}

/// Convert a byte slice into a [`Path`].
#[cfg(unix)]
#[inline]
pub(crate) fn bytes_to_os_str(bytes: &[u8]) -> io::Result<&OsStr> {
    Ok(OsStr::from_bytes(bytes))
}

/// Convert a byte slice into a [`PathBuf`].
#[cfg(not(unix))]
#[inline]
pub(crate) fn bytes_to_os_str(bytes: &[u8]) -> io::Result<&OsStr> {
    Ok(OsStr::new(from_utf8(bytes).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, err)
    })?))
}

/// Convert a byte slice into a [`Path`].
#[doc(hidden)]
#[inline]
pub fn bytes_to_path(bytes: &[u8]) -> io::Result<&Path> {
    Ok(Path::new(bytes_to_os_str(bytes)?))
}

/// Convert a [`Path`] into a byte slice.
#[cfg(unix)]
#[inline]
pub(crate) fn path_to_bytes(path: &Path) -> io::Result<&[u8]> {
    Ok(path.as_os_str().as_bytes())
}

/// Convert a [`Path`] into a byte slice.
#[cfg(not(unix))]
#[inline]
pub(crate) fn path_to_bytes(path: &Path) -> io::Result<&[u8]> {
    let bytes = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "path is not valid Unicode"))?
        .as_bytes();
    Ok(bytes)
}

/// Reorder elements of `array` based on index information in `indices`.
fn reorder<T, U>(array: &mut [T], indices: Vec<(U, usize)>) {
    debug_assert_eq!(array.len(), indices.len());

    let mut indices = indices;
    // Sort the entries in `array` based on the indexes in `indices`
    // (second member).
    for i in 0..array.len() {
        while indices[i].1 != i {
            let () = array.swap(i, indices[i].1);
            let idx = indices[i].1;
            let () = indices.swap(i, idx);
        }
    }
}


/// Take a slice `slice` of unordered elements, sort them into a vector, then
/// invoke a function `handle` on the vector, take the result of this function
/// and "extract" a mutable reference to a slice, reordered this slice in such a
/// way that the original order of `slice` is preserved.
pub(crate) fn with_ordered_elems<T, U, E, H, R, Err>(
    slice: &[T],
    extract: E,
    handle: H,
) -> Result<R, Err>
where
    T: Copy + Ord,
    E: FnOnce(&mut R) -> &mut [U],
    H: FnOnce(iter::Map<slice::Iter<'_, (T, usize)>, fn(&(T, usize)) -> T>) -> Result<R, Err>,
{
    let mut vec = slice
        .iter()
        .enumerate()
        .map(|(idx, t)| (*t, idx))
        .collect::<Vec<_>>();
    let () = vec.sort_unstable();

    let mut result = handle(vec.iter().map(|(t, _idx)| *t))?;
    let () = reorder(extract(&mut result), vec);
    Ok(result)
}


#[doc(hidden)]
pub fn stat(path: &Path) -> io::Result<libc::stat> {
    let mut dst = MaybeUninit::uninit();
    let mut path = path_to_bytes(path)?.to_vec();
    let () = path.push(b'\0');

    let rc = unsafe { libc::stat(path.as_ptr().cast::<libc::c_char>(), dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `stat`.
    Ok(unsafe { dst.assume_init() })
}


#[cfg(linux)]
#[cfg(test)]
#[allow(clippy::absolute_paths)]
fn fstat(fd: std::os::unix::io::RawFd) -> io::Result<libc::stat> {
    let mut dst = MaybeUninit::uninit();
    let rc = unsafe { libc::fstat(fd, dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `fstat`.
    Ok(unsafe { dst.assume_init() })
}


#[cfg(linux)]
pub(crate) fn uname_release() -> io::Result<CString> {
    let mut dst = MaybeUninit::uninit();
    let rc = unsafe { libc::uname(dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `uname`.
    let uname = unsafe { dst.assume_init() };
    // SAFETY: `uname` ensures a NUL terminated string in `uname.release` on
    //         success.
    let release = unsafe { CStr::from_ptr(uname.release.as_ptr()) }.to_owned();
    Ok(release)
}

pub(crate) fn find_lowest_match_by<T, F>(slice: &[T], mut f: F) -> Option<usize>
where
    F: FnMut(&T) -> Ordering,
{
    let idx = slice.partition_point(|e| f(e).is_lt());
    if let Some(e) = slice.get(idx) {
        if f(e).is_eq() {
            return Some(idx)
        }
    }
    None
}

#[allow(dead_code)]
pub(crate) fn find_lowest_match_by_key<T, B, F>(slice: &[T], b: &B, mut f: F) -> Option<usize>
where
    F: FnMut(&T) -> B,
    B: Ord,
{
    find_lowest_match_by(slice, |k| f(k).cmp(b))
}

#[cfg(test)]
pub(crate) fn find_lowest_match<T>(slice: &[T], item: &T) -> Option<usize>
where
    T: Ord,
{
    find_lowest_match_by(slice, |elem| elem.cmp(item))
}

/// See `find_match_or_lower_bound`, but allow the user to pass in a comparison
/// function for increased flexibility.
pub(crate) fn find_match_or_lower_bound_by_key<T, U, F>(
    slice: &[T],
    item: U,
    mut f: F,
) -> Option<usize>
where
    U: Ord,
    F: FnMut(&T) -> U,
{
    let idx = slice.partition_point(|e| f(e) < item);

    // At this point `idx` references the first item greater or equal to the one
    // we are looking for.

    if let Some(e) = slice.get(idx) {
        // If the item at `idx` is equal to what we were looking for, we are
        // trivially done, as it's guaranteed to be the first one to match.
        if f(e) == item {
            return Some(idx)
        }
    }

    // Otherwise `idx` points to a "greater" item. Hence, we pick the previous
    // one, but then have to scan backwards for as long as we see this one item,
    // so that we end up reporting the index of the first of all equal ones.
    let idx = idx.checked_sub(1)?;
    let cmp_e = f(slice.get(idx)?);

    for i in (0..idx).rev() {
        let e = slice.get(i)?;
        if f(e) != cmp_e {
            return Some(i + 1)
        }
    }
    Some(idx)
}

/// Perform a binary search on a slice, returning the index of the match (if
/// found) or the one of the previous item (if any), taking into account
/// duplicates.
///
/// This functionality is useful for cases where we compare elements with a
/// size, such as ranges, and an address to search for can be covered by a range
/// whose start is before the item to search for.
#[cfg(test)]
fn find_match_or_lower_bound<T>(slice: &[T], item: T) -> Option<usize>
where
    T: Copy + Ord,
{
    find_match_or_lower_bound_by_key(slice, item, |e| *e)
}


/// A marker trait for "plain old data" data types.
///
/// # Safety
/// Only safe to implement for types that are valid for any bit pattern.
pub unsafe trait Pod: Clone {}

unsafe impl Pod for i8 {}
unsafe impl Pod for u8 {}
unsafe impl Pod for i16 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for i32 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for i64 {}
unsafe impl Pod for u64 {}
unsafe impl Pod for i128 {}
unsafe impl Pod for u128 {}

/// An trait providing utility functions for reading data from a byte buffer.
pub trait ReadRaw<'data> {
    /// Ensure that `len` bytes are available for consumption.
    fn ensure(&self, len: usize) -> Option<()>;

    /// Advance the read pointer by `cnt` bytes.
    fn advance(&mut self, cnt: usize) -> Option<()>;

    /// Align the read pointer to the next multiple of `align_to`.
    ///
    /// # Panics
    /// This method may panic if `align_to` is not a power of two.
    fn align(&mut self, align_to: usize) -> Option<()>;

    /// Consume and return `len` bytes.
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]>;

    /// Read a fixed size array of bytes without advancing the read
    /// pointer.
    fn peek_array<const N: usize>(&self) -> Option<[u8; N]>;

    /// Read a fixed size array of bytes.
    fn read_array<const N: usize>(&mut self) -> Option<[u8; N]>;

    /// Read a NUL terminated string.
    fn read_cstr(&mut self) -> Option<&'data CStr>;

    /// Read anything implementing `Pod`.
    #[inline]
    fn read_pod<T>(&mut self) -> Option<T>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>())?;
        // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
        //         is guaranteed to be valid and to point to memory of at least
        //         `sizeof(T)` bytes.
        let value = unsafe { data.as_ptr().cast::<T>().read_unaligned() };
        Some(value)
    }

    /// Read a reference to something implementing `Pod`.
    #[inline]
    fn read_pod_ref<T>(&mut self) -> Option<&'data T>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>())?;
        let ptr = data.as_ptr();

        if ptr.align_offset(align_of::<T>()) == 0 {
            // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
            //         is guaranteed to be valid and to point to memory of at least
            //         `sizeof(T)` bytes. We know it is properly aligned
            //         because we checked that.
            unsafe { ptr.cast::<T>().as_ref() }
        } else {
            None
        }
    }

    /// Read a reference to something implementing `Pod`.
    #[inline]
    fn read_pod_slice_ref<T>(&mut self, count: usize) -> Option<&'data [T]>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>().checked_mul(count)?)?;
        let ptr = data.as_ptr();

        if ptr.align_offset(align_of::<T>()) == 0 {
            // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
            //         is guaranteed to be valid and to point to memory of at least
            //         `sizeof(T)` bytes. We know it is properly aligned
            //         because we checked that.
            Some(unsafe { slice::from_raw_parts(ptr.cast::<T>(), count) })
        } else {
            None
        }
    }

    /// Read a `u8` value.
    #[inline]
    fn read_u8(&mut self) -> Option<u8> {
        self.read_pod::<u8>()
    }

    /// Read a `u16` value.
    #[inline]
    fn read_u16(&mut self) -> Option<u16> {
        self.read_pod::<u16>()
    }

    /// Read a `u32` value.
    #[inline]
    fn read_u32(&mut self) -> Option<u32> {
        self.read_pod::<u32>()
    }

    /// Read a `u64` value.
    #[inline]
    fn read_u64(&mut self) -> Option<u64> {
        self.read_pod::<u64>()
    }

    /// Read a `u64` encoded as unsigned variable length little endian base 128
    /// value.
    //
    // Slightly adjusted copy of `rustc` implementation:
    // https://github.com/rust-lang/rust/blob/7ebd2bdbf6d798e6e711a0100981b0ff029abf5f/compiler/rustc_serialize/src/leb128.rs#L54
    fn read_u64_leb128(&mut self) -> Option<u64> {
        // The first iteration of this loop is unpeeled. This is a
        // performance win because this code is hot and integer values less
        // than 128 are very common, typically occurring 50-80% or more of
        // the time, even for u64 and u128.
        let [byte] = self.read_array::<1>()?;
        if (byte & 0x80) == 0 {
            return Some(byte as u64);
        }
        let mut result = (byte & 0x7F) as u64;
        let mut shift = 7;
        loop {
            let [byte] = self.read_array::<1>()?;
            if (byte & 0x80) == 0 {
                result |= (byte as u64) << shift;
                return Some(result);
            } else {
                result |= ((byte & 0x7F) as u64) << shift;
            }
            shift += 7;
        }
    }

    /// Read a `u64` encoded as signed variable length little endian base 128
    /// value.
    fn read_i64_leb128(&mut self) -> Option<i64> {
        let mut result = 0;
        let mut shift = 0;
        let mut byte;

        loop {
            [byte] = self.read_array::<1>()?;
            result |= <i64>::from(byte & 0x7F) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                break;
            }
        }

        if (shift < <i64>::BITS) && ((byte & 0x40) != 0) {
            // sign extend
            result |= !0 << shift;
        }

        Some(result)
    }
}

impl<'data> ReadRaw<'data> for &'data [u8] {
    #[inline]
    fn ensure(&self, len: usize) -> Option<()> {
        if len > self.len() {
            return None
        }
        Some(())
    }

    #[inline]
    fn advance(&mut self, cnt: usize) -> Option<()> {
        let _ = self.read_slice(cnt)?;
        Some(())
    }

    #[inline]
    fn align(&mut self, align_to: usize) -> Option<()> {
        let offset = self.as_ptr().align_offset(align_to);
        let () = self.advance(offset)?;
        Some(())
    }

    #[inline]
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]> {
        self.ensure(len)?;
        let (a, b) = self.split_at(len);
        *self = b;
        Some(a)
    }

    #[inline]
    fn peek_array<const N: usize>(&self) -> Option<[u8; N]> {
        self.ensure(N)?;
        let slice = &self[..N];
        // SAFETY: We *know* that `a` has length `N`.
        let array = unsafe { <[u8; N]>::try_from(slice).unwrap_unchecked() };
        Some(array)
    }

    #[inline]
    fn read_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let array = self.peek_array::<N>()?;
        *self = &self[N..];
        Some(array)
    }

    #[inline]
    fn read_cstr(&mut self) -> Option<&'data CStr> {
        let idx = self.iter().position(|byte| *byte == b'\0')?;
        CStr::from_bytes_with_nul(self.read_slice(idx + 1)?).ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use std::hint::black_box;
    use std::mem::size_of_val;

    use tempfile::NamedTempFile;

    use test_tag::tag;

    #[cfg(feature = "nightly")]
    use test::Bencher;


    /// Exercise the `Debug` representation of various types.
    #[tag(miri)]
    #[test]
    fn debug_repr() {
        let addrs = [0x42, 0x1337];
        let hex = Hexify(&addrs);
        assert_eq!(format!("{hex:?}"), "[0x42, 0x1337]");
    }

    /// Check whether an iterator represents a sorted sequence.
    // Copy of iterator::is_sorted_by used while it is still unstable.
    fn is_sorted_by<I, F>(mut iter: I, compare: F) -> bool
    where
        I: Iterator,
        F: FnMut(&I::Item, &I::Item) -> Option<Ordering>,
    {
        #[inline]
        fn check<'a, T>(
            last: &'a mut T,
            mut compare: impl FnMut(&T, &T) -> Option<Ordering> + 'a,
        ) -> impl FnMut(T) -> bool + 'a {
            move |curr| {
                if let Some(Ordering::Greater) | None = compare(last, &curr) {
                    return false
                }
                *last = curr;
                true
            }
        }

        let mut last = match iter.next() {
            Some(e) => e,
            None => return true,
        };

        iter.all(check(&mut last, compare))
    }

    /// Check whether an iterator represents a sorted sequence.
    #[inline]
    fn is_sorted<I>(iter: I) -> bool
    where
        I: Iterator,
        I::Item: PartialOrd,
    {
        is_sorted_by(iter, PartialOrd::partial_cmp)
    }


    /// Make sure that we can detect sorted slices.
    #[tag(miri)]
    #[test]
    fn sorted_check() {
        assert!(is_sorted([1, 5, 6].iter()));
        assert!(!is_sorted([1, 5, 6, 0].iter()));
    }

    /// Check that our [`Dbg`] type does what it says on the tin.
    #[tag(miri)]
    #[test]
    fn debug_non_debug() {
        #[repr(transparent)]
        struct NonDebug(usize);

        let dbg = Dbg(NonDebug(42));
        assert_eq!(
            format!("{dbg:?}"),
            format!("{:?}", &dbg.0 .0 as *const usize)
        );
    }

    /// Check that we can reorder elements in an array as expected.
    #[tag(miri)]
    #[test]
    fn array_reordering() {
        let mut array = vec![];
        reorder::<usize, ()>(&mut array, vec![]);

        let mut array = vec![8];
        reorder(&mut array, vec![((), 0)]);
        assert_eq!(array, vec![8]);

        let mut array = vec![8, 1, 4, 0, 3];
        reorder(
            &mut array,
            [4, 1, 3, 0, 2].into_iter().map(|x| ((), x)).collect(),
        );
        assert_eq!(array, vec![0, 1, 3, 4, 8]);
    }

    /// Check that `with_ordered_elems` works as it should.
    #[tag(miri)]
    #[test]
    fn with_element_ordering() {
        let vec = vec![5u8, 0, 1, 99, 6, 2];
        let result = with_ordered_elems(
            &vec,
            |x: &mut Vec<u8>| x.as_mut_slice(),
            |iter| {
                let vec = iter.collect::<Vec<_>>();
                assert!(is_sorted(vec.iter()));
                io::Result::Ok(vec.into_iter().map(|x| x + 2).collect::<Vec<_>>())
            },
        )
        .unwrap();
        assert_eq!(result, vec.into_iter().map(|x| x + 2).collect::<Vec<_>>());
    }

    /// Check that we can retrieve meta-data about a file using `stat`
    /// and `fstat`.
    #[cfg(linux)]
    #[test]
    fn file_stating() {
        use std::os::fd::AsRawFd as _;

        let tmpfile = NamedTempFile::new().unwrap();
        let stat1 = stat(tmpfile.path()).unwrap();
        let stat2 = fstat(tmpfile.as_file().as_raw_fd()).unwrap();

        assert_eq!(stat1.st_dev, stat2.st_dev);
        assert_eq!(stat1.st_ino, stat2.st_ino);
        assert_eq!(stat1.st_mode, stat2.st_mode);
        assert_eq!(stat1.st_size, stat2.st_size);
        assert_eq!(stat1.st_ctime, stat2.st_ctime);
    }

    /// Make sure that `[u8]::ensure` works as expected.
    #[tag(miri)]
    #[test]
    fn u8_slice_len_ensurance() {
        let slice = [0u8; 0].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), None);

        let slice = [1u8].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), Some(()));
        assert_eq!(slice.ensure(2), None);
    }

    /// Check that we can align the read pointer on a `[u8]`.
    #[tag(miri)]
    #[test]
    fn u8_slice_align() {
        let mut buffer = [0u8; 64];
        let ptr = buffer.as_mut_ptr();

        // Make sure that we have an aligned pointer to begin with.
        let aligned_ptr = match ptr.align_offset(align_of::<u64>()) {
            offset if offset < size_of::<u64>() => unsafe { ptr.add(offset) },
            _ => unreachable!(),
        };

        let aligned = unsafe { slice::from_raw_parts(aligned_ptr, 16) };
        let mut data = aligned;

        let () = data.align(1).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(2).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(4).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(8).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        // After this read we are unaligned again.
        let _byte = data.read_u8();

        // Nothing should happen when attempting to align to 1 byte
        // boundary.
        let () = data.align(1).unwrap();
        assert_eq!(data.as_ptr(), unsafe { aligned.as_ptr().add(1) });

        // But once we align to a four byte boundary we the pointer
        // should move.
        let () = data.align(4).unwrap();
        assert_eq!(data.as_ptr(), unsafe { aligned.as_ptr().add(4) });
    }

    /// Check that we can read various integers from a slice.
    #[tag(miri)]
    #[test]
    fn pod_reading() {
        macro_rules! test {
            ($type:ty) => {{
                let max = <$type>::MAX.to_ne_bytes();
                let one = (1 as $type).to_ne_bytes();

                let mut data = Vec::new();
                let () = data.extend_from_slice(&max);
                let () = data.extend_from_slice(&one);
                let () = data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let mut raw = data.as_slice();
                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, <$type>::MAX);

                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, 1);
            }};
        }

        test!(i8);
        test!(u8);
        test!(i16);
        test!(u16);
        test!(i32);
        test!(u32);
        test!(i64);
        test!(u64);
        test!(i128);
        test!(u128);
    }

    /// Check that we can read references to `Pod`s.
    #[tag(miri)]
    #[test]
    fn pod_ref_reading() {
        // This test assumes that `u64`'s required alignment is greater
        // than 1.
        assert!(align_of::<u64>() > 1, "{}", align_of::<u64>());

        let mut buffer = [0u64; 2];
        // Write that data that we read back subsequently.
        buffer[0] = 1337;

        let buffer = unsafe {
            slice::from_raw_parts(
                buffer.as_ptr().cast::<u8>(),
                buffer.len() * size_of_val(&buffer[0]),
            )
        };

        let mut aligned = buffer;
        assert_eq!(aligned.read_pod_ref::<u64>(), Some(&1337));

        // Make sure that we fail if there is insufficient space.
        let mut aligned = &buffer[0..4];
        assert_eq!(aligned.read_pod_ref::<u64>(), None);

        // Now also try with an unaligned pointer. It is guaranteed to
        // be unaligned if we add a one byte offset.
        let mut unaligned = buffer;
        let () = unaligned.advance(1).unwrap();
        assert_eq!(unaligned.read_pod_ref::<u64>(), None);
    }

    /// Test reading of signed and unsigned 16 and 32 bit values against known
    /// results.
    #[tag(miri)]
    #[test]
    fn word_reading() {
        let data = 0xf936857fu32.to_ne_bytes();
        assert_eq!(data.as_slice().read_u16().unwrap(), 0x857f);
        assert_eq!(data.as_slice().read_u32().unwrap(), 0xf936857f);
    }

    /// Check that we can read an array from a slice as expected.
    #[tag(miri)]
    #[test]
    fn array_reading() {
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut data = data.as_slice();

        let read = data.peek_array::<1>().unwrap();
        assert_eq!(read, [0]);
        let read = data.peek_array::<1>().unwrap();
        assert_eq!(read, [0]);
        let read = data.read_array::<1>().unwrap();
        assert_eq!(read, [0]);

        let read = data.peek_array::<4>().unwrap();
        assert_eq!(read, [1, 2, 3, 4]);
        let read = data.read_array::<4>().unwrap();
        assert_eq!(read, [1, 2, 3, 4]);

        let result = data.peek_array::<20>();
        assert_eq!(result, None);
        let result = data.read_array::<20>();
        assert_eq!(result, None);

        let read = data.read_array::<3>().unwrap();
        assert_eq!(read, [5, 6, 7]);
    }

    /// Make sure that we can read leb128 encoded values.
    #[tag(miri)]
    #[test]
    fn leb128_reading() {
        let data = [0xf4, 0xf3, 0x75];
        let v = data.as_slice().read_u64_leb128().unwrap();
        assert_eq!(v, 0x1d79f4);

        let v = data.as_slice().read_i64_leb128().unwrap();
        assert_eq!(v, -165388);
    }

    /// Check that we can read a NUL terminated string from a slice.
    #[tag(miri)]
    #[test]
    fn cstr_reading() {
        let mut slice = b"abc\x001234".as_slice();

        let cstr = slice.read_cstr().unwrap();
        assert_eq!(cstr, CStr::from_bytes_with_nul(b"abc\0").unwrap());

        // No terminating NUL byte.
        let mut slice = b"abc".as_slice();
        assert_eq!(slice.read_cstr(), None);
    }

    /// Test that we correctly binary search for a lowest match.
    #[tag(miri)]
    #[test]
    fn search_lowest_match() {
        fn test(f: impl Fn(&[u16], &u16) -> Option<usize>) {
            let data = [];
            assert_eq!(f(&data, &0), None);

            let data = [5];
            assert_eq!(f(&data, &0), None);
            assert_eq!(f(&data, &1), None);
            assert_eq!(f(&data, &4), None);
            assert_eq!(f(&data, &5), Some(0));
            assert_eq!(f(&data, &6), None);

            let data = [5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [5, 5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [5, 5, 5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [4, 5, 5, 5, 5];
            assert_eq!(f(&data, &5), Some(1));

            let data = [1, 4, 42, 43, 99];
            assert_eq!(f(&data, &0), None);
            assert_eq!(f(&data, &1), Some(0));
            assert_eq!(f(&data, &4), Some(1));
            assert_eq!(f(&data, &5), None);
            assert_eq!(f(&data, &41), None);
            assert_eq!(f(&data, &98), None);
            assert_eq!(f(&data, &99), Some(4));
            assert_eq!(f(&data, &100), None);
            assert_eq!(f(&data, &1337), None);
        }

        test(find_lowest_match);
        test(|data, item| find_lowest_match_by_key(data, item, |elem| *elem));
    }

    /// Test that we correctly binary search for a match or a lower bound.
    #[tag(miri)]
    #[test]
    fn search_match_or_lower_bound() {
        let data = [];
        assert_eq!(find_match_or_lower_bound(&data, &0), None);

        let data = [5];
        assert_eq!(find_match_or_lower_bound(&data, 0), None);
        assert_eq!(find_match_or_lower_bound(&data, 1), None);
        assert_eq!(find_match_or_lower_bound(&data, 4), None);
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));
        assert_eq!(find_match_or_lower_bound(&data, 6), Some(0));

        let data = [5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [5, 5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [4, 5, 5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(1));

        let data = [1, 4, 42, 43, 99];
        assert_eq!(find_match_or_lower_bound(&data, 0), None);
        assert_eq!(find_match_or_lower_bound(&data, 1), Some(0));
        assert_eq!(find_match_or_lower_bound(&data, 4), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 41), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 98), Some(3));
        assert_eq!(find_match_or_lower_bound(&data, 99), Some(4));
        assert_eq!(find_match_or_lower_bound(&data, 100), Some(4));
        assert_eq!(find_match_or_lower_bound(&data, 1337), Some(4));
    }

    /// Benchmark the reading of LEB128 encoded `u64` values.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_u64_leb128_reading(b: &mut Bencher) {
        #[rustfmt::skip]
        let data = [
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], u64::MAX),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00], u64::MAX / 2),
            ([0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0x55, 0x00], u64::MAX / 3),
            ([0xb3, 0xe6, 0xcc, 0x99, 0xb3, 0xe6, 0xcc, 0x99, 0x33, 0x00], u64::MAX / 5),
            ([0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0x2a, 0x00], u64::MAX / 6),
            ([0x92, 0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x92, 0xc9, 0x24, 0x00], u64::MAX / 7),
            ([0xf1, 0xb8, 0x9c, 0x8e, 0xc7, 0xe3, 0xf1, 0xb8, 0x1c, 0x00], u64::MAX / 9),
            ([0x99, 0xb3, 0xe6, 0xcc, 0x99, 0xb3, 0xe6, 0xcc, 0x19, 0x00], u64::MAX / 10),
            ([0xd1, 0x8b, 0xdd, 0xe8, 0xc5, 0xae, 0xf4, 0xa2, 0x17, 0x00], u64::MAX / 11),
            ([0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0x15, 0x00], u64::MAX / 12),
            ([0xb1, 0xa7, 0xec, 0x89, 0xbb, 0xe2, 0xce, 0xd8, 0x13, 0x00], u64::MAX / 13),
            ([0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x12, 0x00], u64::MAX / 14),
            ([0x91, 0xa2, 0xc4, 0x88, 0x91, 0xa2, 0xc4, 0x88, 0x11, 0x00], u64::MAX / 15),
        ];

        for (data, expected) in data {
            let v = data.as_slice().read_u64_leb128().unwrap();
            assert_eq!(v, expected);
        }

        let () = b.iter(|| {
            for (data, _) in data {
                let mut slice = black_box(data.as_slice());
                let v = slice.read_u64_leb128().unwrap();
                black_box(v);
            }
        });
    }
}
