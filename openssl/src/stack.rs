use foreign_types::{ForeignTypeRef, ForeignType};
use libc::c_int;
use std::borrow::Borrow;
use std::convert::AsRef;
use std::iter;
use std::marker::PhantomData;
use std::mem;
use ffi;

use {cvt, cvt_p};
use error::ErrorStack;
use std::ops::{Deref, DerefMut, Index, IndexMut};

use util::Opaque;

#[cfg(ossl10x)]
use ffi::{sk_pop as OPENSSL_sk_pop, sk_free as OPENSSL_sk_free, sk_num as OPENSSL_sk_num,
          sk_value as OPENSSL_sk_value, _STACK as OPENSSL_STACK,
          sk_new_null as OPENSSL_sk_new_null, sk_push as OPENSSL_sk_push};
#[cfg(ossl110)]
use ffi::{OPENSSL_sk_pop, OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_value, OPENSSL_STACK,
          OPENSSL_sk_new_null, OPENSSL_sk_push};

/// Trait implemented by types which can be placed in a stack.
///
/// It should not be implemented for any type outside of this crate.
pub trait Stackable: ForeignType {
    /// The C stack type for this element.
    ///
    /// Generally called `stack_st_{ELEMENT_TYPE}`, normally hidden by the
    /// `STACK_OF(ELEMENT_TYPE)` macro in the OpenSSL API.
    type StackType;
}

/// An owned stack of `T`.
pub struct Stack<T: Stackable>(*mut T::StackType);

impl<T: Stackable> Stack<T> {
    pub fn new() -> Result<Stack<T>, ErrorStack> {
        unsafe {
            ffi::init();
            let ptr = try!(cvt_p(OPENSSL_sk_new_null()));
            Ok(Stack(ptr as *mut _))
        }
    }
}

impl<T: Stackable> Drop for Stack<T> {
    fn drop(&mut self) {
        unsafe {
            while let Some(_) = self.pop() {}
            OPENSSL_sk_free(self.0 as *mut _);
        }
    }
}

impl<T: Stackable> iter::IntoIterator for Stack<T> {
    type IntoIter = IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> IntoIter<T> {
        let it = IntoIter {
            stack: self.0,
            idx: 0,
        };
        mem::forget(self);
        it
    }
}

impl<T: Stackable> AsRef<StackRef<T>> for Stack<T> {
    fn as_ref(&self) -> &StackRef<T> {
        &*self
    }
}

impl<T: Stackable> Borrow<StackRef<T>> for Stack<T> {
    fn borrow(&self) -> &StackRef<T> {
        &*self
    }
}

impl<T: Stackable> ForeignType for Stack<T> {
    type CType = T::StackType;
    type Ref = StackRef<T>;

    #[inline]
    unsafe fn from_ptr(ptr: *mut T::StackType) -> Stack<T> {
        assert!(!ptr.is_null(), "Must not instantiate a Stack from a null-ptr - use Stack::new() in \
                                 that case");
        Stack(ptr)
    }

    #[inline]
    fn as_ptr(&self) -> *mut T::StackType {
        self.0
    }
}

impl<T: Stackable> Deref for Stack<T> {
    type Target = StackRef<T>;

    fn deref(&self) -> &StackRef<T> {
        unsafe { StackRef::from_ptr(self.0) }
    }
}

impl<T: Stackable> DerefMut for Stack<T> {
    fn deref_mut(&mut self) -> &mut StackRef<T> {
        unsafe { StackRef::from_ptr_mut(self.0) }
    }
}

pub struct IntoIter<T: Stackable> {
    stack: *mut T::StackType,
    idx: c_int,
}

impl<T: Stackable> IntoIter<T> {
    fn stack_len(&self) -> c_int {
        unsafe { OPENSSL_sk_num(self.stack as *mut _) }
    }
}

impl<T: Stackable> Drop for IntoIter<T> {
    fn drop(&mut self) {
        unsafe {
            while let Some(_) = self.next() {}
            OPENSSL_sk_free(self.stack as *mut _);
        }
    }
}

impl<T: Stackable> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        unsafe {
            if self.idx == self.stack_len() {
                None
            } else {
                let ptr = OPENSSL_sk_value(self.stack as *mut _, self.idx);
                self.idx += 1;
                Some(T::from_ptr(ptr as *mut _))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = (self.stack_len() - self.idx) as usize;
        (size, Some(size))
    }
}

impl<T: Stackable> ExactSizeIterator for IntoIter<T> {}

pub struct StackRef<T: Stackable>(Opaque, PhantomData<T>);

impl<T: Stackable> ForeignTypeRef for StackRef<T> {
    type CType = T::StackType;
}

impl<T: Stackable> StackRef<T> {
    fn as_stack(&self) -> *mut OPENSSL_STACK {
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
    pub fn get(&self, idx: usize) -> Option<&T::Ref> {
        unsafe {
            if idx >= self.len() {
                return None;
            }

            Some(T::Ref::from_ptr(self._get(idx)))
        }
    }

    /// Returns a mutable reference to the element at the given index in the
    /// stack or `None` if the index is out of bounds
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T::Ref> {
        unsafe {
            if idx >= self.len() {
                return None;
            }

            Some(T::Ref::from_ptr_mut(self._get(idx)))
        }
    }

    /// Pushes a value onto the top of the stack.
    pub fn push(&mut self, data: T) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(OPENSSL_sk_push(self.as_stack(), data.as_ptr() as *mut _)));
            mem::forget(data);
            Ok(())
        }
    }

    /// Removes the last element from the stack and returns it.
    pub fn pop(&mut self) -> Option<T> {
        unsafe {
            let ptr = OPENSSL_sk_pop(self.as_stack());
            if ptr.is_null() {
                None
            } else {
                Some(T::from_ptr(ptr as *mut _))
            }
        }
    }

    unsafe fn _get(&self, idx: usize) -> *mut T::CType {
        OPENSSL_sk_value(self.as_stack(), idx as c_int) as *mut _
    }
}

impl<T: Stackable> Index<usize> for StackRef<T> {
    type Output = T::Ref;

    fn index(&self, index: usize) -> &T::Ref {
        self.get(index).unwrap()
    }
}

impl<T: Stackable> IndexMut<usize> for StackRef<T> {
    fn index_mut(&mut self, index: usize) -> &mut T::Ref {
        self.get_mut(index).unwrap()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a StackRef<T> {
    type Item = &'a T::Ref;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a mut StackRef<T> {
    type Item = &'a mut T::Ref;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a Stack<T> {
    type Item = &'a T::Ref;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Stackable> iter::IntoIterator for &'a mut Stack<T> {
    type Item = &'a mut T::Ref;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

/// An iterator over the stack's contents.
pub struct Iter<'a, T: Stackable>
    where T: 'a
{
    stack: &'a StackRef<T>,
    pos: usize,
}

impl<'a, T: Stackable> iter::Iterator for Iter<'a, T> {
    type Item = &'a T::Ref;

    fn next(&mut self) -> Option<&'a T::Ref> {
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

impl<'a, T: Stackable> iter::ExactSizeIterator for Iter<'a, T> {}

/// A mutable iterator over the stack's contents.
pub struct IterMut<'a, T: Stackable + 'a> {
    stack: &'a mut StackRef<T>,
    pos: usize,
}

impl<'a, T: Stackable> iter::Iterator for IterMut<'a, T> {
    type Item = &'a mut T::Ref;

    fn next(&mut self) -> Option<&'a mut T::Ref> {
        if self.pos >= self.stack.len() {
            None
        } else {
            // Rust won't allow us to get a mutable reference into
            // `stack` in this situation since it can't statically
            // guarantee that we won't return several references to
            // the same object, so we have to use unsafe code for
            // mutable iterators.
            let n = unsafe { Some(T::Ref::from_ptr_mut(self.stack._get(self.pos))) };

            self.pos += 1;

            n
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.stack.len() - self.pos;

        (rem, Some(rem))
    }
}

impl<'a, T: Stackable> iter::ExactSizeIterator for IterMut<'a, T> {}
