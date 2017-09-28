//! Cryptographically strong random bytes.
//!
//! This module exposes functionality to put cryptographically strong
//! pseudo-random bytes into a buffer.
//!
//! # Examples
//!
//! To generate a buffer with cryptographically strong bytes:
//!
//! ```
//! let muf buf = [0; 256]
//! rand_bytes(&mut buf).unwrap();
//! ```
//!
//! # External OpenSSL Documentation
//!
//! [RAND_bytes](https://www.openssl.org/docs/man1.1.0/crypto/RAND_bytes.html)
use libc::c_int;
use ffi;

use cvt;
use error::ErrorStack;

/// Fills buffer with cryptographically strong pseudo-random bytes.
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        assert!(buf.len() <= c_int::max_value() as usize);
        cvt(ffi::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).unwrap();
    }
}
