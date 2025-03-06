use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map;
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref as _;

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
    ///
    /// We need to heap allocate here to make sure that entries don't
    /// get invalidated if the hash map reallocates.
    map: RefCell<HashMap<K, Box<V>>>,
}

impl<K, V> InsertMap<K, V> {
    /// Create a new, empty `InsertMap` instance.
    pub(crate) fn new() -> Self {
        Self {
            refcell: RefCell::new(()),
            map: RefCell::new(HashMap::new()),
        }
    }

    /// Retrieve a value mapping to a key.
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Eq + Hash + Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let _borrow = self.refcell.borrow();
        // SAFETY: We are sure to not violate mutability rules because
        //         the `_borrow` guard protects us.
        let map = unsafe { self.map.as_ptr().as_ref() }.unwrap();
        map.get::<Q>(key).map(Box::deref)
    }

    /// Retrieve a value mapping to a key, if already present, or insert
    /// it and return it then.
    ///
    /// # Panics
    /// The `init` function should not use functionality provided by the
    /// object this method operates on, recursively, or a runtime panic
    /// may be the result.
    pub(crate) fn get_or_insert<F>(&self, key: K, init: F) -> &V
    where
        K: Eq + Hash,
        F: FnOnce() -> V,
    {
        let _borrow = self.map.borrow_mut();
        // SAFETY: We are sure to not borrow mutably twice because the `_borrow`
        //         guard protects us.
        let map = unsafe { self.map.as_ptr().as_mut() }.unwrap();
        match map.entry(key) {
            hash_map::Entry::Occupied(occupied) => occupied.into_mut(),
            hash_map::Entry::Vacant(vacancy) => vacancy.insert(Box::new(init())),
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
                let entry = vacancy.insert(Box::new(value));
                Ok(entry)
            }
        }
    }
}

impl<K, V> Default for InsertMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_tag::tag;

    use crate::Error;
    use crate::ErrorKind;


    /// Check that value insertion works as it should.
    #[tag(miri)]
    #[test]
    fn insertion_retrieval() {
        let map = InsertMap::<usize, &'static str>::new();

        assert_eq!(map.get(&42), None);

        let s = map
            .get_or_try_insert(42, || Ok("you win the price"))
            .unwrap();
        assert_eq!(s, &"you win the price");
        assert_eq!(map.get(&42).unwrap(), &"you win the price");

        let s = map.get_or_try_insert(42, || panic!()).unwrap();
        assert_eq!(s, &"you win the price");

        let err = map
            .get_or_try_insert(31, || Err(Error::with_unsupported("unsupported")))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(map.get(&31), None);

        let s = map.get_or_try_insert(31, || Ok("31 wins")).unwrap();
        assert_eq!(s, &"31 wins");
        assert_eq!(map.get(&31).unwrap(), &"31 wins");
    }

    /// Check that value insertion does not invalidate existing value
    /// references, even in the presence of hash map reallocations.
    #[tag(miri)]
    #[test]
    fn extensive_inserts() {
        let map = InsertMap::<usize, usize>::new();

        // Keep a reference to a value around while we insert more
        // values. Later access it again to make sure nothing fishy is
        // going on and it hasn't changed.
        let v = map.get_or_try_insert(42, || Ok(42)).unwrap();
        assert_eq!(v, &42);

        for i in 0..1024 {
            let x = map.get_or_try_insert(i, || Ok(i)).unwrap();
            assert_eq!(x, &i);
        }

        assert_eq!(v, &42);
    }

    /// Make sure that `InsertMap` does not allow for recursive
    /// access as part of initialization.
    #[tag(miri)]
    #[test]
    #[should_panic = "already borrowed"]
    fn recursive_access() {
        let map = InsertMap::<usize, &'static str>::default();
        let _value =
            map.get_or_try_insert(42, || map.get_or_try_insert(42, || Ok("foobar")).copied());
    }
}
