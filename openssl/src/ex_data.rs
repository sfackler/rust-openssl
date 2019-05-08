use libc::{c_int, c_long, c_void};
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

pub unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        Box::<T>::from_raw(ptr as *mut T);
    }
}
