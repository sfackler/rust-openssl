use libc::{c_void, c_int};
use std::io;
use std::io::prelude::*;
use std::os::unix::io::RawFd;
use std::ptr;
use std::cmp;

use ffi;
use ssl::error::{SslError};

pub trait Bio {
    fn borrowed(bio: *mut ffi::BIO) -> Self;
    unsafe fn unwrap(mut self) -> *mut ffi::BIO;
    unsafe fn get_handle(&self) -> *mut ffi::BIO;

    fn is_eof(&self) -> bool {
        unsafe { ffi::BIO_eof(self.get_handle()) }
    }

    fn method_type(&self) -> c_int {
        unsafe { ffi::BIO_method_type(self.get_handle()) }
    }
}

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
}

impl Bio for MemBio {
    /// Returns a "borrow", i.e. it has no ownership
    fn borrowed(bio: *mut ffi::BIO) -> MemBio {
        MemBio {
            bio: bio,
            owned: false
        }
    }

    /// Consumes current bio and returns wrapped value
    /// Note that data ownership is lost and
    /// should be managed manually
    unsafe fn unwrap(mut self) -> *mut ffi::BIO {
        self.owned = false;
        self.bio
    }

    /// Temporarily gets wrapped value
    unsafe fn get_handle(&self) -> *mut ffi::BIO {
        self.bio
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
            if is_eof {
                Ok(0)
            } else {
                Err(io::Error::new(io::ErrorKind::Other,
                                   SslError::get()))
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
                Err(io::Error::new(io::ErrorKind::Other,
                                   SslError::get()))
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct SocketBio {
    bio: *mut ffi::BIO,
    owned: bool
}

impl Drop for SocketBio {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                ffi::BIO_free_all(self.bio);
            }
        }
    }
}

impl SocketBio {
    pub fn new(fd: RawFd) -> Result<SocketBio, SslError>
    {
        ffi::init();

        let bio = unsafe { ffi::BIO_new(ffi::BIO_s_fd()) };
//        let bio = unsafe { ffi::BIO_new(ffi::BIO_s_socket()) };
        //let bio = unsafe { ffi::BIO_new(ffi::BIO_s_datagram()) };
        //let bio = unsafe { ffi::BIO_new_dgram(fd, ffi::BIO_NOCLOSE as c_int) };

        try_ssl_null!(bio);

        /*let BIO_CTRL_DGRAM_SET_CONNECTED = 32;
        unsafe {
            ffi::BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, ptr::null_mut());
        }*/

        
        unsafe {
            ffi::BIO_set_fd(bio, fd, ffi::BIO_NOCLOSE)
        }
        
        Ok(SocketBio {
            bio: bio,
            owned: true
        })
    }

    pub fn flush(&self) -> bool {
        unsafe { ffi::BIO_flush(self.get_handle()) }
    }

    pub fn pending(&self) -> usize {
        unsafe {
            ffi::BIO_pending(self.get_handle()) as usize
        }
    }
}

impl Bio for SocketBio {
    /// Returns a "borrow", i.e. it has no ownership
    fn borrowed(bio: *mut ffi::BIO) -> SocketBio {
        SocketBio {
            bio: bio,
            owned: false
        }
    }

    /// Consumes current bio and returns wrapped value
    /// Note that data ownership is lost and
    /// should be managed manually
    unsafe fn unwrap(mut self) -> *mut ffi::BIO {
        self.owned = false;
        self.bio
    }

    /// Temporarily gets wrapped value
    unsafe fn get_handle(&self) -> *mut ffi::BIO {
        self.bio
    }
}

