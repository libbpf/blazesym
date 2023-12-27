//! A copy of std::once::OnceCell.
// TODO: Remove this module once our minimum supported Rust version is greater
//       1.70 and/or `OnceCell::get_or_try_init` is stable.

use std::cell::UnsafeCell;
use std::convert::Infallible;
use std::fmt;
use std::hint::unreachable_unchecked;

/// A cell which can be written to only once.
///
/// This allows obtaining a shared `&T` reference to its inner value without
/// copying or replacing it (unlike [`Cell`]), and without runtime borrow checks
/// (unlike [`RefCell`]). However, only immutable references can be obtained
/// unless one has a mutable reference to the cell itself.
///
/// For a thread-safe version of this struct, see [`std::sync::OnceLock`].
///
/// [`RefCell`]: crate::cell::RefCell
/// [`Cell`]: crate::cell::Cell
/// [`std::sync::OnceLock`]: ../../std/sync/struct.OnceLock.html
pub struct OnceCell<T> {
    // Invariant: written to at most once.
    inner: UnsafeCell<Option<T>>,
}

impl<T> OnceCell<T> {
    /// Creates a new empty cell.
    #[inline]
    #[must_use]
    pub const fn new() -> OnceCell<T> {
        OnceCell {
            inner: UnsafeCell::new(None),
        }
    }

    /// Gets the reference to the underlying value.
    ///
    /// Returns `None` if the cell is empty.
    #[inline]
    pub fn get(&self) -> Option<&T> {
        // SAFETY: Safe due to `inner`'s invariant
        unsafe { &*self.inner.get() }.as_ref()
    }

    /// Sets the contents of the cell to `value`.
    ///
    /// # Errors
    ///
    /// This method returns `Ok(())` if the cell was empty and `Err(value)` if
    /// it was full.
    #[inline]
    pub fn set(&self, value: T) -> Result<(), T> {
        match self.try_insert(value) {
            Ok(_) => Ok(()),
            Err((_, value)) => Err(value),
        }
    }

    /// Sets the contents of the cell to `value` if the cell was empty, then
    /// returns a reference to it.
    ///
    /// # Errors
    ///
    /// This method returns `Ok(&value)` if the cell was empty and
    /// `Err(&current_value, value)` if it was full.
    #[inline]
    pub fn try_insert(&self, value: T) -> Result<&T, (&T, T)> {
        if let Some(old) = self.get() {
            return Err((old, value))
        }

        // SAFETY: This is the only place where we set the slot, no races
        // due to reentrancy/concurrency are possible, and we've
        // checked that slot is currently `None`, so this write
        // maintains the `inner`'s invariant.
        let slot = unsafe { &mut *self.inner.get() };
        Ok(slot.insert(value))
    }

    /// Gets the contents of the cell, initializing it with `f`
    /// if the cell was empty.
    ///
    /// # Panics
    ///
    /// If `f` panics, the panic is propagated to the caller, and the cell
    /// remains uninitialized.
    ///
    /// It is an error to reentrantly initialize the cell from `f`. Doing
    /// so results in a panic.
    #[inline]
    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        match self.get_or_try_init(|| Ok::<T, Infallible>(f())) {
            Ok(val) => val,
            Err(_) => unsafe { unreachable_unchecked() },
        }
    }

    /// Gets the contents of the cell, initializing it with `f` if
    /// the cell was empty. If the cell was empty and `f` failed, an
    /// error is returned.
    ///
    /// # Panics
    ///
    /// If `f` panics, the panic is propagated to the caller, and the cell
    /// remains uninitialized.
    ///
    /// It is an error to reentrantly initialize the cell from `f`. Doing
    /// so results in a panic.
    pub fn get_or_try_init<F, E>(&self, f: F) -> Result<&T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if let Some(val) = self.get() {
            return Ok(val)
        }
        /// Avoid inlining the initialization closure into the common path that
        /// fetches the already initialized value
        #[cold]
        fn outlined_call<F, T, E>(f: F) -> Result<T, E>
        where
            F: FnOnce() -> Result<T, E>,
        {
            f()
        }
        let val = outlined_call(f)?;
        // Note that *some* forms of reentrant initialization might lead to
        // UB (see `reentrant_init` test). I believe that just removing this
        // `panic`, while keeping `try_insert` would be sound, but it seems
        // better to panic, rather than to silently use an old value.
        if let Ok(val) = self.try_insert(val) {
            Ok(val)
        } else {
            panic!("reentrant init")
        }
    }
}

impl<T> Default for OnceCell<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple("OnceCell");
        match self.get() {
            Some(v) => d.field(v),
            None => d.field(&format_args!("<uninit>")),
        };
        d.finish()
    }
}

impl<T: Clone> Clone for OnceCell<T> {
    #[inline]
    fn clone(&self) -> OnceCell<T> {
        let res = OnceCell::new();
        if let Some(value) = self.get() {
            match res.set(value.clone()) {
                Ok(()) => (),
                Err(_) => unreachable!(),
            }
        }
        res
    }
}

impl<T: PartialEq> PartialEq for OnceCell<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<T: Eq> Eq for OnceCell<T> {}

impl<T> From<T> for OnceCell<T> {
    /// Creates a new `OnceCell<T>` which already contains the given `value`.
    #[inline]
    fn from(value: T) -> Self {
        OnceCell {
            inner: UnsafeCell::new(Some(value)),
        }
    }
}

// Just like for `Cell<T>` this isn't needed, but results in nicer error
// messages.
//impl<T> !Sync for OnceCell<T> {}
