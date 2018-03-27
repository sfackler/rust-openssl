//! Utilities for secure random number generation.
//!
//! # Examples
//!
//! To generate a buffer with cryptographically strong bytes:
//!
//! ```
//! use openssl::rand::rand_bytes;
//!
//! let mut buf = [0; 256];
//! rand_bytes(&mut buf).unwrap();
//! ```
use libc::c_int;
use ffi;

use cvt;
use error::ErrorStack;

/// Fill buffer with cryptographically strong pseudo-random bytes.
///
/// # Examples
///
/// To generate a buffer with cryptographically strong bytes:
///
/// ```
/// use openssl::rand::rand_bytes;
///
/// let mut buf = [0; 256];
/// rand_bytes(&mut buf).unwrap();
/// ```
///
/// # External OpenSSL Documentation
///
/// [RAND_bytes](https://www.openssl.org/docs/man1.1.0/crypto/RAND_bytes.html)
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
