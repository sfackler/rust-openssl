use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::iter;
use std::borrow::Borrow;
use std::convert::AsRef;
use libc::c_int;

use ffi;
use types::{OpenSslType, Ref};

#[cfg(ossl10x)]
use ffi::{sk_pop as OPENSSL_sk_pop,sk_free as OPENSSL_sk_free, sk_num as OPENSSL_sk_num,
    sk_value as OPENSSL_sk_value};
#[cfg(ossl110)]
use ffi::{OPENSSL_sk_pop, OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_value};

/// Trait implemented by types which can be placed in a stack.
///
/// Like `OpenSslType`, it should not be implemented for any type outside
/// of this crate.
pub trait Stackable: OpenSslType {
    /// The C stack type for this element.
    ///
    /// Generally called `stack_st_{ELEMENT_TYPE}`, normally hidden by the
    /// `STACK_OF(ELEMENT_TYPE)` macro in the OpenSSL API.
    type StackType;
}

/// An owned stack of `T`.
pub struct Stack<T: Stackable>(*mut T::StackType);

impl<T: Stackable> Stack<T> {
    /// Return a new Stack<T>, taking ownership of the handle
    pub unsafe fn from_ptr(stack: *mut T::StackType) -> Stack<T> {
        Stack(stack)
    }
}

impl<T: Stackable> Drop for Stack<T> {
    fn drop(&mut self) {
        unsafe {
            loop {
                let ptr = OPENSSL_sk_pop(self.as_stack());

                if ptr.is_null() {
                    break;
                }

                // Build the owned version of the object just to run
                // its `drop` implementation and delete the item.
                T::from_ptr(ptr as *mut _);
            }

            OPENSSL_sk_free(self.0 as *mut _);
        }
    }
}

impl<T: Stackable> AsRef<Ref<Stack<T>>> for Stack<T> {
    fn as_ref(&self) -> &Ref<Stack<T>> {
        &*self
    }
}

impl<T: Stackable> Borrow<Ref<Stack<T>>> for Stack<T> {
    fn borrow(&self) -> &Ref<Stack<T>> {
        &*self
    }
}

unsafe impl<T: Stackable> OpenSslType for Stack<T> {
    type CType = T::StackType;

    unsafe fn from_ptr(ptr: *mut T::StackType) -> Stack<T> {
        Stack(ptr)
    }

    fn as_ptr(&self) -> *mut T::StackType {
        self.0
    }
}

impl<T: Stackable> Deref for Stack<T> {
    type Target = Ref<Stack<T>>;

    fn deref(&self) -> &Ref<Stack<T>> {
        unsafe { Ref::from_ptr(self.0) }
    }
}

impl<T: Stackable> DerefMut for Stack<T> {
    fn deref_mut(&mut self) -> &mut ::types::Ref<Stack<T>> {
        unsafe { Ref::from_ptr_mut(self.0) }
    }
}

impl<T: Stackable> Ref<Stack<T>> {
    /// OpenSSL stack types are just a (kinda) typesafe wrapper around
    /// a `_STACK` object. We can therefore safely cast it and access
    /// the `_STACK` members without having to worry about the real
    /// layout of `T::StackType`.
    ///
    /// If that sounds unsafe then keep in mind that's exactly how the
    /// OpenSSL 1.1.0 new C stack code works.
    #[cfg(ossl10x)]
    fn as_stack(&self) -> *mut ffi::_STACK {
        self.as_ptr() as *mut _
    }

    /// OpenSSL 1.1.0 replaced the stack macros with a functions and
    /// only exposes an opaque OPENSSL_STACK struct
    /// publicly.
    #[cfg(ossl110)]
    fn as_stack(&self) -> *mut ffi::OPENSSL_STACK {
        self.as_ptr() as *mut _
    }

    /// Returns the number of items in the stack
    pub fn len(&self) -> usize {
        unsafe { OPENSSL_sk_num(self.as_stack()) as usize }
    }

    pub fn iter(&self) -> Iter<T> {
        // Unfortunately we can't simply convert the stack into a
        // slice and use that because OpenSSL 1.1.0 doesn't directly
        // expose the stack data (we have to use `OPENSSL_sk_value`
        // instead). We have to rewrite the entire iteration framework
        // instead.

        Iter {
            stack: self,
            pos: 0,
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<T> {
        IterMut {
            stack: self,
            pos: 0,
        }
    }

    /// Returns a reference to the element at the given index in the
    /// stack or `None` if the index is out of bounds
    pub fn get(&self, idx: usize) -> Option<&Ref<T>> {
        if idx >= self.len() {
            return None;
        }

        unsafe {
            let r = Ref::from_ptr(self._get(idx));

            Some(r)
        }
    }

    /// Returns a mutable reference to the element at the given index in the
    /// stack or `None` if the index is out of bounds
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Ref<T>> {
        if idx >= self.len() {
            return None;
        }

        unsafe {
            Some(Ref::from_ptr_mut(self._get(idx)))
        }
    }

    unsafe fn _get(&self, idx: usize) -> *mut T::CType {
        assert!(idx <= c_int::max_value() as usize);
        OPENSSL_sk_value(self.as_stack(), idx as c_int) as *mut _
    }
}

impl<T: Stackable> Index<usize> for Ref<Stack<T>> {
    type Output = Ref<T>;

    fn index(&self, index: usize) -> &Ref<T> {
        self.get(index).unwrap()
    }
}

impl<T: Stackable> IndexMut<usize> for Ref<Stack<T>> {
    fn index_mut(&mut self, index: usize) -> &mut Ref<T> {
        self.get_mut(index).unwrap()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a Ref<Stack<T>> {
    type Item = &'a Ref<T>;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a mut Ref<Stack<T>> {
    type Item = &'a mut Ref<T>;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a Stack<T> {
    type Item = &'a Ref<T>;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a mut Stack<T> {
    type Item = &'a mut Ref<T>;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

/// An iterator over the stack's contents.
pub struct Iter<'a, T: Stackable>
    where T: 'a {
    stack: &'a Ref<Stack<T>>,
    pos: usize,
}

impl<'a, T: Stackable> iter::Iterator for Iter<'a, T> {
    type Item = &'a Ref<T>;

    fn next(&mut self) -> Option<&'a Ref<T>> {
        let n = self.stack.get(self.pos);

        if n.is_some() {
            self.pos += 1;
        }

        n
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.stack.len() - self.pos;

        (rem, Some(rem))
    }
}

impl<'a, T: Stackable> iter::ExactSizeIterator for Iter<'a, T> {
}

/// A mutable iterator over the stack's contents.
pub struct IterMut<'a, T: Stackable + 'a> {
    stack: &'a mut Ref<Stack<T>>,
    pos: usize,
}

impl<'a, T: Stackable> iter::Iterator for IterMut<'a, T> {
    type Item = &'a mut Ref<T>;

    fn next(&mut self) -> Option<&'a mut Ref<T>> {
        if self.pos >= self.stack.len() {
            None
        } else {
            // Rust won't allow us to get a mutable reference into
            // `stack` in this situation since it can't statically
            // guarantee that we won't return several references to
            // the same object, so we have to use unsafe code for
            // mutable iterators.
            let n = unsafe {
                Some(Ref::from_ptr_mut(self.stack._get(self.pos)))
            };

            self.pos += 1;

            n
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.stack.len() - self.pos;

        (rem, Some(rem))
    }
}

impl<'a, T: Stackable> iter::ExactSizeIterator for IterMut<'a, T> {
}
