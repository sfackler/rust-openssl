//! The SHA family of hashes.
use ffi;
use std::mem;

/// Computes the SHA1 hash of some data.
///
/// # Warning
///
/// SHA1 is known to be insecure - it should not be used unless required for
/// compatibility with existing systems.
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    unsafe {
        let mut hash: [u8; 20] = mem::uninitialized();
        ffi::SHA1(data.as_ptr(), data.len(), hash.as_mut_ptr());
        hash
    }
}

/// Computes the SHA224 hash of some data.
#[inline]
pub fn sha224(data: &[u8]) -> [u8; 28] {
    unsafe {
        let mut hash: [u8; 28] = mem::uninitialized();
        ffi::SHA224(data.as_ptr(), data.len(), hash.as_mut_ptr());
        hash
    }
}

/// Computes the SHA256 hash of some data.
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    unsafe {
        let mut hash: [u8; 32] = mem::uninitialized();
        ffi::SHA256(data.as_ptr(), data.len(), hash.as_mut_ptr());
        hash
    }
}

/// Computes the SHA384 hash of some data.
#[inline]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    unsafe {
        let mut hash: [u8; 48] = mem::uninitialized();
        ffi::SHA384(data.as_ptr(), data.len(), hash.as_mut_ptr());
        hash
    }
}

/// Computes the SHA512 hash of some data.
#[inline]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    unsafe {
        let mut hash: [u8; 64] = mem::uninitialized();
        ffi::SHA512(data.as_ptr(), data.len(), hash.as_mut_ptr());
        hash
    }
}

#[cfg(test)]
mod test {
    use hex::ToHex;

    use super::*;

    #[test]
    fn standalone_1() {
        let data = b"abc";
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";

        assert_eq!(sha1(data).to_hex(), expected);
    }

    #[test]
    fn standalone_224() {
        let data = b"abc";
        let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

        assert_eq!(sha224(data).to_hex(), expected);
    }

    #[test]
    fn standalone_256() {
        let data = b"abc";
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        assert_eq!(sha256(data).to_hex(), expected);
    }

    #[test]
    fn standalone_384() {
        let data = b"abc";
        let expected = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e\
                        7cc2358baeca134c825a7";

        assert_eq!((&sha384(data)[..]).to_hex(), expected);
    }

    #[test]
    fn standalone_512() {
        let data = b"abc";
        let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274\
                        fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

        assert_eq!((&sha512(data)[..]).to_hex(), expected);
    }
}
