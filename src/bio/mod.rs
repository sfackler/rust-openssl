use libc::{c_void, c_int};
use std::io::{IoResult, IoError, OtherIoError};
use std::io::{Reader, Writer};
use std::ptr;

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
    /// should be handled manually
    pub unsafe fn unwrap(mut self) -> *mut ffi::BIO {
        self.owned = false;
        self.bio
    }

    /// Temporarily gets wrapped value
    pub unsafe fn get_handle(&self) -> *mut ffi::BIO {
        self.bio
    }
}

impl Reader for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let ret = unsafe {
            ffi::BIO_read(self.bio, buf.as_ptr() as *mut c_void,
                          buf.len() as c_int)
        };

        if ret < 0 {
            // FIXME: provide details from OpenSSL
            Err(IoError{kind: OtherIoError, desc: "mem bio read error", detail: None})
        } else {
            Ok(ret as uint)
        }
    }
}

impl Writer for MemBio {
    fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        let ret = unsafe {
            ffi::BIO_write(self.bio, buf.as_ptr() as *const c_void,
                           buf.len() as c_int)
        };
        if buf.len() != ret as uint {
            // FIXME: provide details from OpenSSL
            Err(IoError{kind: OtherIoError, desc: "mem bio write error", detail: None})
        } else {
            Ok(())
        }
    }
}
