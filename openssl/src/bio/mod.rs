use libc::{c_void, c_int};
use std::io;
use std::io::prelude::*;
use std::ptr;
use std::cmp;

use ffi;
use ssl::error::{SslError};

pub struct MemBio {
    bio: *mut ffi::BIO,
    owned: bool
}

impl Drop for MemBio {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                ffi::BIO_free_all(self.bio);
            }
        }
    }
}

impl MemBio {
    /// Creates a new owned memory based BIO
    pub fn new() -> Result<MemBio, SslError> {
        ffi::init();

        let bio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        try_ssl_null!(bio);

        Ok(MemBio {
            bio: bio,
            owned: true
        })
    }

    /// Returns a "borrow", i.e. it has no ownership
    pub fn borrowed(bio: *mut ffi::BIO) -> MemBio {
        MemBio {
            bio: bio,
            owned: false
        }
    }

    /// Consumes current bio and returns wrapped value
    /// Note that data ownership is lost and
    /// should be managed manually
    pub unsafe fn unwrap(mut self) -> *mut ffi::BIO {
        self.owned = false;
        self.bio
    }

    /// Temporarily gets wrapped value
    pub unsafe fn get_handle(&self) -> *mut ffi::BIO {
        self.bio
    }

    /// Sets the BIO's EOF state.
    pub fn set_eof(&self, eof: bool) {
        let v = if eof { 0 } else { -1 };
        unsafe { ffi::BIO_set_mem_eof_return(self.bio, v); }
    }
}

impl Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        let ret = unsafe {
            ffi::BIO_read(self.bio, buf.as_ptr() as *mut c_void, len)
        };

        if ret <= 0 {
            let is_eof = unsafe { ffi::BIO_eof(self.bio) };
            if is_eof != 0 {
                Ok(0)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, SslError::get()))
            }
        } else {
            Ok(ret as usize)
        }
    }
}

impl Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        let ret = unsafe {
            ffi::BIO_write(self.bio, buf.as_ptr() as *const c_void, len)
        };

        if ret < 0 {
            Err(io::Error::new(io::ErrorKind::Other, SslError::get()))
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
