use std::cell::RefCell;
use std::collections::hash_map;
use std::collections::HashMap;
use std::hash::Hash;

use crate::Result;


/// An insert-only map.
///
/// This map allows only for insertion, but not removal of values. It
/// does so behind an immutable interface.
#[derive(Debug)]
pub(crate) struct InsertMap<K, V> {
    /// A proxy member used for making sure that we do not borrow `map` mutably
    /// multiple times.
    refcell: RefCell<()>,
    /// The actual map containing key-value pairs.
    map: RefCell<HashMap<K, V>>,
}

impl<K, V> InsertMap<K, V> {
    /// Create a new, empty `InsertMap` instance.
    pub(crate) fn new() -> Self {
        Self {
            refcell: RefCell::new(()),
            map: RefCell::new(HashMap::new()),
        }
    }

    /// Retrieve a value mapping to a key, if already present, or insert
    /// it and return it then.
    ///
    /// # Panics
    /// The `init` function should not use functionality provided by the
    /// object this method operates on, recursively, or a runtime panic
    /// may be the result.
    pub(crate) fn get_or_try_insert<F>(&self, key: K, init: F) -> Result<&V>
    where
        K: Eq + Hash,
        F: FnOnce() -> Result<V>,
    {
        let _borrow = self.refcell.borrow_mut();
        // SAFETY: We are sure to not borrow mutably twice because the `_borrow`
        //         guard protects us.
        let map = unsafe { self.map.as_ptr().as_mut() }.unwrap();
        match map.entry(key) {
            hash_map::Entry::Occupied(occupied) => {
                let entry = occupied.into_mut();
                Ok(entry)
            }
            hash_map::Entry::Vacant(vacancy) => {
                let value = init()?;
                let entry = vacancy.insert(value);
                Ok(entry)
            }
        }
    }
}

impl<K, V> Default for InsertMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::Error;
    use crate::ErrorKind;


    /// Check that value insertion works as it should.
    #[test]
    fn insertion() {
        let map = InsertMap::<usize, &'static str>::new();

        let s = map
            .get_or_try_insert(42, || Ok("you win the price"))
            .unwrap();
        assert_eq!(s, &"you win the price");

        let s = map.get_or_try_insert(42, || panic!()).unwrap();
        assert_eq!(s, &"you win the price");

        let err = map
            .get_or_try_insert(31, || Err(Error::with_unsupported("unsupported")))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);

        let s = map.get_or_try_insert(31, || Ok("31 wins")).unwrap();
        assert_eq!(s, &"31 wins");
    }


    /// Make sure that `InsertMap` does not allow for recursive
    /// access as part of initialization.
    #[test]
    #[should_panic = "already borrowed"]
    fn recursive_access() {
        let map = InsertMap::<usize, &'static str>::new();
        let _value =
            map.get_or_try_insert(42, || map.get_or_try_insert(42, || Ok("foobar")).copied());
    }
}
