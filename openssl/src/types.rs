//! Items used by other types.

use std::cell::UnsafeCell;
use std::marker::PhantomData;

/// A type implemented by wrappers over OpenSSL types.
///
/// This should not be implemented by anything outside of this crate; new methods may be added at
/// any time.
pub unsafe trait OpenSslType {
    /// The raw C type.
    type CType;

    /// Constructs an instance of this type from its raw type.
    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self;

    /// Returns a pointer to its raw type.
    fn as_ptr(&self) -> *mut Self::CType;
}

/// A reference to an OpenSSL type.
pub struct Ref<T>(UnsafeCell<()>, PhantomData<T>);

impl<T: OpenSslType> Ref<T> {
    /// Constructs a shared reference to this type from its raw type.
    pub unsafe fn from_ptr<'a>(ptr: *mut T::CType) -> &'a Ref<T> {
        &*(ptr as *mut _)
    }

    /// Constructs a mutable reference to this type from its raw type.
    pub unsafe fn from_ptr_mut<'a>(ptr: *mut T::CType) -> &'a mut Ref<T> {
        &mut *(ptr as *mut _)
    }

    /// Returns a pointer to its raw type.
    pub fn as_ptr(&self) -> *mut T::CType {
        self as *const _ as *mut _
    }
}
