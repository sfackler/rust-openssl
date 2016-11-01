use std::cell::UnsafeCell;
use std::marker::PhantomData;

pub unsafe trait OpenSslType {
    type CType;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self;

    fn as_ptr(&self) -> *mut Self::CType;
}

pub struct Ref<T>(UnsafeCell<()>, PhantomData<T>);

impl<T: OpenSslType> Ref<T> {
    pub unsafe fn from_ptr<'a>(ptr: *mut T::CType) -> &'a Ref<T> {
        &*(ptr as *mut _)
    }

    pub unsafe fn from_ptr_mut<'a>(ptr: *mut T::CType) -> &'a mut Ref<T> {
        &mut *(ptr as *mut _)
    }

    pub fn as_ptr(&self) -> *mut T::CType {
        self as *const _ as *mut _
    }
}
