//! Items used by other types.

/// A type implemented by wrappers over OpenSSL types.
///
/// This should not be implemented by anything outside of this crate; new methods may be added at
/// any time.
pub trait OpenSslType: Sized {
    /// The raw C type.
    type CType;

    /// The type representing a reference to this type.
    type Ref: OpenSslTypeRef<CType = Self::CType>;

    /// Constructs an instance of this type from its raw type.
    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self;
}

/// A trait implemented by types which reference borrowed OpenSSL types.
///
/// This should not be implemented by anything outside of this crate; new methods may be added at
/// any time.
pub trait OpenSslTypeRef: Sized {
    /// The raw C type.
    type CType;

    /// Constructs a shared instance of this type from its raw type.
    unsafe fn from_ptr<'a>(ptr: *mut Self::CType) -> &'a Self {
        &*(ptr as *mut _)
    }

    /// Constructs a mutable reference of this type from its raw type.
    unsafe fn from_ptr_mut<'a>(ptr: *mut Self::CType) -> &'a mut Self {
        &mut *(ptr as *mut _)
    }

    /// Returns a raw pointer to the wrapped value.
    fn as_ptr(&self) -> *mut Self::CType {
        self as *const _ as *mut _
    }
}
