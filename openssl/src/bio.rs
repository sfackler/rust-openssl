use std::marker::PhantomData;
use std::ptr;
use std::slice;
use libc::c_int;
use ffi;

use error::ErrorStack;

pub struct MemBioSlice<'a>(*mut ffi::BIO, PhantomData<&'a [u8]>);

impl<'a> Drop for MemBioSlice<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl<'a> MemBioSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<MemBioSlice<'a>, ErrorStack> {
        ffi::init();

        assert!(buf.len() <= c_int::max_value() as usize);
        let bio = unsafe {
            try_ssl_null!(ffi::BIO_new_mem_buf(buf.as_ptr() as *const _, buf.len() as c_int))
        };

        Ok(MemBioSlice(bio, PhantomData))
    }

    pub fn get_handle(&self) -> *mut ffi::BIO {
        self.0
    }
}

pub struct MemBio(*mut ffi::BIO);

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl MemBio {
    pub fn new() -> Result<MemBio, ErrorStack> {
        ffi::init();

        let bio = unsafe {
            try_ssl_null!(ffi::BIO_new(ffi::BIO_s_mem()))
        };
        Ok(MemBio(bio))
    }

    pub fn get_handle(&self) -> *mut ffi::BIO {
        self.0
    }

    pub fn get_buf(&self) -> &[u8] {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = ffi::BIO_get_mem_data(self.0, &mut ptr);
            slice::from_raw_parts(ptr as *const _ as *const _, len as usize)
        }
    }
}
