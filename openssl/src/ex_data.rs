use libc::c_int;
use std::marker::PhantomData;

/// A slot in a type's "extra data" structure.
///
/// It is parameterized over the type containing the extra data as well as the
/// type of the data in the slot.
pub struct Index<T, U>(c_int, PhantomData<(T, U)>);

impl<T, U> Copy for Index<T, U> {}

impl<T, U> Clone for Index<T, U> {
    fn clone(&self) -> Index<T, U> {
        *self
    }
}

impl<T, U> Index<T, U> {
    pub unsafe fn from_raw(idx: c_int) -> Index<T, U> {
        Index(idx, PhantomData)
    }

    pub fn as_raw(&self) -> c_int {
        self.0
    }
}
