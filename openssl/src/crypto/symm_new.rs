//! Symmetric encryption support
//!
//! # Examples
//!
//! * Zero copy API:
//!
//! ```rust
//! use openssl::crypto::symm_new::{Aes, Apply, PaddedFinish};
//! use openssl::crypto::symm_new::cbc::{CbcPadded};
//! let key = b"\xc3\xb3\xc4\x1f\x11\x3a\x31\xb7\x3d\x9a\x5c\xd4\x32\x10\x30\x69";
//! let iv = b"\x93\xfe\x7d\x9e\x9b\xfd\x10\x34\x8a\x56\x06\xe5\xca\xfa\x73\x54";
//! let pt = b"secret!";
//! let mut res = vec![0; 32];
//! let mut enc = CbcPadded::new_encrypt(Aes::Aes128, key);
//! enc.start(iv);
//! let mut len = enc.apply(pt, &mut res);
//! len += enc.finish(&mut res[len..]).unwrap();
//! assert!(&res[..len] == b"\x3a\x41\xfe\x79\xaa\x90\x77\x2a\x16\xa1\xc0\x92\x6d\x11\x82\xc4");
//! ```
//!
//! * `Writer` adapter
//!
//! ```rust
//! use openssl::crypto::symm_new::{Aes, Apply, PaddedFinish, PaddedFilter};
//! use openssl::crypto::symm_new::cbc::{CbcPadded};
//! let key = b"\xc3\xb3\xc4\x1f\x11\x3a\x31\xb7\x3d\x9a\x5c\xd4\x32\x10\x30\x69";
//! let iv = b"\x93\xfe\x7d\x9e\x9b\xfd\x10\x34\x8a\x56\x06\xe5\xca\xfa\x73\x54";
//! let ct = b"\x3a\x41\xfe\x79\xaa\x90\x77\x2a\x16\xa1\xc0\x92\x6d\x11\x82\xc4";
//! let mut res: Vec<u8> = Vec::new();
//! let mut dec = CbcPadded::new_decrypt(Aes::Aes128, key);
//! dec.start(iv);
//! {
//!     let mut w = PaddedFilter::new(&mut dec, &mut res);
//!     assert!(w.write_all(ct).is_ok());
//!     assert!(w.close().is_ok());
//! }
//! assert!(res == b"secret!");
//! ```

#![allow(unused_imports)]
use std::{error, fmt, mem, ptr};
use std::error::Error as StdError;
use libc::{c_int, c_void};
use std::old_io::{IoError, Writer};

use ffi;

#[derive(PartialEq, Copy)]
enum State {
    Reset,
    Updated,
    Finalized,
}

use self::State::*;

#[derive(Copy, PartialEq)]
enum Direction {
    Decrypt,
    Encrypt,
}

/// Selects AES key size
#[derive(Copy, PartialEq)]
pub enum Aes {
    Aes128,
    Aes256,
}

/// Indicates a symmetric cipher error
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The data doesn't end on a cipher block boundary as required by the mode
    IncompleteBlock,
    /// The padding at the end of data is malformed or missing
    InvalidPadding,
    /// Authentication of the data has failed. The data may have been altered.
    AuthFailed,
    /// Unspecified openssl error
    Unspecified,
    /// An external IO error
    IoError(Box<IoError>),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IoError(_) => "An external IO error",
            Error::IncompleteBlock => "Data length not a multiple of block length in raw mode",
            Error::InvalidPadding => "Malformed or missing padding at the end",
            Error::AuthFailed => "The supplied data has failed authentication.
                           Any cipher output should be discarded",
            Error::Unspecified => "Unspecified openssl error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if let Error::IoError(ref err) = *self {
            write!(fmt, "{}: {}", self.description(), err)
        }
        else {
            write!(fmt, "{}", self.description())
        }
    }
}

impl error::FromError<IoError> for Error {
    fn from_error(err: IoError) -> Error {
        Error::IoError(Box::new(err))
    }
}

macro_rules! chk {
    ($inp:expr) => (
        {
            let r = $inp;
            assert!(r == 1);
            r
        }
    );
}

/// A common cipher interface
struct Context {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    state: State,
}

/// A trait for ciphers that allow transcoding several chunks of data consecutively.
pub trait Apply {
    /// Transcode the `data` into the `buf`.
    ///
    /// The `buf` must have enough space to fit `data` (plus a cipher block length
    /// in ECB and CBC modes).
    fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize;
}

/// A trait for block mode ciphers that may not return the last bytes of data until finished.
pub trait PaddedFinish: Apply {
    fn finish(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/*
/// A cipher that works on large blocks (sectors)
trait SectorMode {
    fn apply(&mut self, iv: &[u8], data: &[u8], buf: &mut [u8]);
}
*/

/// An adapter for using ciphers as `Writer`s
// Subject to changes after std::io stabilization
pub struct Filter<'a, T: 'a> {
    cipher: &'a mut T,
    sink: &'a mut (Writer + 'a),
}

const FILTER_BUFFER_LEN: usize = 16384;

impl <'a, T> Filter<'a, T> {
    /// Create a `Writer` adapter for the `cipher`. The output is written
    /// to the `sink`.
    /// The `cipher` has to be `start`ed beforehand and `finish`ed after
    /// destroying the adapter.
    pub fn new(cipher: &'a mut T, sink: &'a mut (Writer + 'a))
          -> Filter<'a, T> {
        Filter { cipher: cipher, sink: sink }
    }
}

impl <'a, T: Apply> Writer for Filter<'a, T> {
    fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        let mut buf = [0; FILTER_BUFFER_LEN + ffi::EVP_MAX_BLOCK_LENGTH];
        for chunk in data.chunks(FILTER_BUFFER_LEN) {
            let len = self.cipher.apply(chunk, &mut buf);
            if len > 0 {
                try!(self.sink.write_all(&buf[..len]));
            }
        }
        Ok(())
    }
}

/// A `Writer` adapter that finishes the padded cipher after writing.
pub struct PaddedFilter<'a, T: 'a> {
    inner: Filter<'a, T>,
    closed: bool,
}

impl <'a, T: PaddedFinish> PaddedFilter<'a, T> {
    /// Create a `Writer` adapter that finishes the padded cipher after writing.
    /// The output is written to the `sink`.
    /// The cipher has to be `start`ed beforehand and is finished explicitly
    /// with `close` or implicitly when the adapter is destroyed (in which case
    /// the last bytes won't reach the sink).
    pub fn new(cipher: &'a mut T, sink: &'a mut (Writer + 'a))
          -> PaddedFilter<'a, T> {
        PaddedFilter { inner: Filter::new(cipher, sink), closed: false }
    }

    /// Finish the cipher and write the remaining data to the sink.
    pub fn close(mut self) -> Result<(), Error> {
        let mut buf = [0; ffi::EVP_MAX_BLOCK_LENGTH];
        self.closed = true;
        let len = try!(self.inner.cipher.finish(&mut buf));
        if len > 0 {
            try!(self.inner.sink.write_all(&buf[..len]));
        }
        Ok(())
    }
}

impl <'a, T: PaddedFinish> Writer for PaddedFilter<'a, T> {
    fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        self.inner.write_all(data)
    }
}

#[unsafe_destructor]
impl <'a, T: PaddedFinish> Drop for PaddedFilter<'a, T> {
    fn drop(&mut self) {
        if !self.closed {
            let mut buf = [0; ffi::EVP_MAX_BLOCK_LENGTH];
            let _ = self.inner.cipher.finish(&mut buf);
        }
    }
}

impl Context {
    fn new(cipher: *const ffi::EVP_CIPHER, dir: Direction, key: &[u8]) -> Context {
        ffi::init();

        let mut ctx;
        unsafe {
            ctx = ffi::EVP_CIPHER_CTX_new();
            assert!(!ctx.is_null());
            let enc = match dir {
                Direction::Decrypt => 0,
                Direction::Encrypt => 1,
            };
            chk!(ffi::EVP_CipherInit_ex(ctx, cipher, 0 as *const _,
                                        key.as_ptr(), 0 as *const _, enc));
        };

        Context { ctx: ctx, state: Finalized }
    }

    fn init(&mut self) {
        assert!(self.state == Finalized, "Illegal call order");
        unsafe {
            chk!(ffi::EVP_CipherInit_ex(self.ctx, 0 as *const _, 0 as *const _,
                                        0 as *const _, 0 as *const _, -1));
        }
        self.state = Reset;
    }

    unsafe fn init_with_iv(&mut self, iv: &[u8]) {
        assert!(self.state == Finalized, "Illegal call order");
        chk!(ffi::EVP_CipherInit_ex(self.ctx, 0 as *const _, 0 as *const _,
                                    0 as *const _, iv.as_ptr(), -1));
        self.state = Reset;
    }

    unsafe fn update(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
        assert!(self.state != Finalized, "Illegal call order");
        let mut len = 0;
        chk!(ffi::EVP_CipherUpdate(self.ctx, buf.as_mut_ptr(), &mut len,
                                   data.as_ptr(), data.len() as c_int));
        let len = len as usize;
        assert!(len <= buf.len());
        self.state = Updated;
        len
    }

    #[cfg(feature = "aes_gcm")]
    fn update_aad(&mut self, data: &[u8]) {
        assert!(self.state != Finalized, "Illegal call order");
        unsafe {
            let mut len = 0;
            chk!(ffi::EVP_CipherUpdate(self.ctx, ptr::null_mut(), &mut len,
                                       data.as_ptr(), data.len() as c_int));
        }
        self.state = Updated;
    }

    fn checked_update(&mut self, data: &[u8], buf: &mut [u8], block_len: usize) -> usize {
        assert!(buf.len() >= data.len() + block_len);
        unsafe { self.update(data, buf) }
    }

    unsafe fn finalize(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        assert!(self.state != Finalized, "Illegal call order");
        let mut len = 0;
        let res = ffi::EVP_CipherFinal_ex(self.ctx, buf.as_mut_ptr(), &mut len);
        self.state = Finalized;
        let len = len as usize;
        assert!(len <= buf.len());
        if res == 1 {
            Ok(len)
        }
        else {
            Err(())
        }
    }

    fn checked_finalize(&mut self, buf: &mut [u8], block_len: usize) -> Result<usize, ()> {
        assert!(buf.len() >= block_len);
        unsafe { self.finalize(buf) }
    }

    fn clean_finalize(&mut self) -> Result<(), ()> {
        assert!(self.state != Finalized, "Illegal call order");
        unsafe {
            let mut buf: [u8; ffi::EVP_MAX_BLOCK_LENGTH] = mem::uninitialized();
            match self.finalize(&mut buf) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        }
    }

    fn set_padding(&mut self, pad: bool) {
        unsafe {
            let p = match pad { true => 1, false => 0 };
            chk!(ffi::EVP_CIPHER_CTX_set_padding(self.ctx, p));
        }
    }

    #[cfg(feature = "aes_gcm")]
    fn get_tag(&mut self, buf: &mut [u8]) {
        assert!(self.state == Finalized, "Illegal call order");
        let len = buf.len() as c_int;
        assert!(len == 4 || len == 8 || 12 <= len && len <= 16);
        unsafe {
            chk!(ffi::EVP_CIPHER_CTX_ctrl(self.ctx, ffi::EVP_CTRL_GCM_GET_TAG,
                                          len, buf.as_mut_ptr() as *mut c_void));
        }
    }

    #[cfg(feature = "aes_gcm")]
    fn set_tag(&mut self, buf: &[u8]) {
        assert!(self.state == Reset, "Illegal call order");
        let len = buf.len() as c_int;
        assert!(len == 4 || len == 8 || 12 <= len && len <= 16);
        unsafe {
            chk!(ffi::EVP_CIPHER_CTX_ctrl(self.ctx, ffi::EVP_CTRL_GCM_SET_TAG,
                                          len, buf.as_ptr() as *mut c_void));
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.state != Finalized {
            let _ = self.clean_finalize();
        }
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

pub mod ecb{
    //! ECB mode
    //!
    //! This mode doesn't use IVs so is not supposed to be used.

    use super::{Aes, Apply, Context, Direction, Error, PaddedFinish};
    use ffi;

    fn evpc(algo: Aes) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Aes::Aes128 => ffi::EVP_aes_128_ecb(),
                Aes::Aes256 => ffi::EVP_aes_256_ecb(),
            }
        }
    }

    // We only support AES right now.
    const BLOCK_LENGTH: usize = 16;

    /// AES in ECB mode without padding.
    ///
    /// The data length needs to be a multiple of AES block length.
    pub struct EcbRaw {
        context: Context,
    }

    impl EcbRaw {
        /// Creates a new AES ECB unpadded encryptor.
        pub fn new_encrypt(algo: Aes, key: &[u8]) -> EcbRaw {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(false);
            EcbRaw { context: c }
        }

        /// Creates a new AES ECB unpadded decryptor.
        pub fn new_decrypt(algo: Aes, key: &[u8]) -> EcbRaw {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(false);
            EcbRaw { context: c }
        }

        /// Prepares the cipher for use.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self) {
            self.context.init();
        }

        /// Finishes the cipher.
        ///
        /// Returns an `IncompleteBlock` error if the data doesn't end on the block
        /// boundary.
        pub fn finish(&mut self) -> Result<(), Error> {
            if self.context.clean_finalize().is_ok() {
                Ok(())
            }
            else {
                Err(Error::IncompleteBlock)
            }
        }
    }

    impl Apply for EcbRaw {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, BLOCK_LENGTH);
            len
        }

    }

    /// AES in ECB mode with padding.
    pub struct EcbPadded {
        context: Context,
    }

    impl EcbPadded {
        /// Creates a new AES ECB padded encryptor.
        pub fn new_encrypt(algo: Aes, key: &[u8]) -> EcbPadded {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(true);
            EcbPadded { context: c }
        }

        /// Creates a new AES ECB padded decryptor.
        pub fn new_decrypt(algo: Aes, key: &[u8]) -> EcbPadded {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(true);
            EcbPadded { context: c }
        }

        /// Prepares the cipher for use.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self) {
            self.context.init();
        }
    }

    impl Apply for EcbPadded {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, BLOCK_LENGTH);
            len
        }
    }

    impl PaddedFinish for EcbPadded {
        fn finish(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            if let Ok(len) = self.context.checked_finalize(buf, BLOCK_LENGTH) {
                Ok(len)
            }
            else {
                Err(Error::InvalidPadding)
            }
        }
    }
}

pub mod cbc {
    //! CBC mode

    use super::{Aes, Apply, Context, Direction, Error, PaddedFinish};
    use ffi;

    fn evpc(algo: Aes) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Aes::Aes128 => ffi::EVP_aes_128_cbc(),
                Aes::Aes256 => ffi::EVP_aes_256_cbc(),
            }
        }
    }

    // We only support AES right now.
    const BLOCK_LENGTH: usize = 16;

    /// AES in CBC mode without padding.
    ///
    /// The data length needs to be a multiple of AES block length.
    pub struct CbcRaw {
        context: Context,
    }

    impl CbcRaw {
        /// Creates a new AES CBC unpadded encryptor.
        pub fn new_encrypt(algo: Aes, key: &[u8]) -> CbcRaw {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(false);
            CbcRaw { context: c }
        }

        /// Creates a new AES CBC unpadded decryptor.
        pub fn new_decrypt(algo: Aes, key: &[u8]) -> CbcRaw {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(false);
            CbcRaw { context: c }
        }

        /// Prepares the cipher for use.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self, iv: &[u8]) {
            unsafe { self.context.init_with_iv(iv); }
        }

        /// Finishes the cipher.
        ///
        /// Returns an `IncompleteBlock` error if the data doesn't end on the block
        /// boundary.
        pub fn finish(&mut self) -> Result<(), Error> {
            if self.context.clean_finalize().is_ok() {
                Ok(())
            }
            else {
                Err(Error::IncompleteBlock)
            }
        }
    }

    impl Apply for CbcRaw {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, BLOCK_LENGTH);
            len
        }
    }

    /// AES in CBC mode with padding.
    pub struct CbcPadded {
        context: Context,
    }

    impl CbcPadded {
        /// Creates a new AES CBC padded encryptor.
        pub fn new_encrypt(algo: Aes, key: &[u8]) -> CbcPadded {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(true);
            CbcPadded { context: c }
        }

        /// Creates a new AES CBC padded decryptor.
        pub fn new_decrypt(algo: Aes, key: &[u8]) -> CbcPadded {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(true);
            CbcPadded { context: c }
        }

        /// Prepares the cipher for use.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self, iv: &[u8]) {
            unsafe { self.context.init_with_iv(iv); }
        }
    }

    impl Apply for CbcPadded {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, BLOCK_LENGTH);
            len
        }
    }

    impl PaddedFinish for CbcPadded {
        fn finish(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            if let Ok(len) = self.context.checked_finalize(buf, BLOCK_LENGTH) {
                Ok(len)
            }
            else {
                Err(Error::InvalidPadding)
            }
        }
    }
}

#[cfg(feature = "aes_gcm")]
pub mod gcm {
    //! GCM mode

    use super::{Aes, Apply, Context, Direction, Error};
    use ffi;

    // GCM mode is defined for 128-bit block ciphers
    const BLOCK_LENGTH: usize = 16;

    fn evpc(algo: Aes) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Aes::Aes128 => ffi::EVP_aes_128_gcm(),
                Aes::Aes256 => ffi::EVP_aes_256_gcm(),
            }
        }
    }

    /// AES in GCM mode authenticated encryption.
    pub struct GcmEncrypt {
        context: Context,
    }

    impl GcmEncrypt {
        /// Creates a new AES GCM encryptor.
        pub fn new(algo: Aes, key: &[u8]) -> GcmEncrypt {
            GcmEncrypt {
                context: Context::new(evpc(algo), Direction::Encrypt, key),
            }
        }

        /// Prepares the encryptor for use.
        ///
        /// `aad` (additional authenticated data) is optional unencrypted
        /// data to authenticate.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self, iv: &[u8], aad: Option<&[u8]>) {
            unsafe {
                self.context.init_with_iv(iv);
                if let Some(aad) = aad {
                    self.context.update_aad(aad);
                }
            }
        }

        /// Finishes the cipher.
        ///
        /// Returns the authetication tag. It can be truncated if needed.
        pub fn finish(&mut self) -> Vec<u8> {
            assert!(self.context.clean_finalize().is_ok());
            let mut res = vec![0; BLOCK_LENGTH];
            self.context.get_tag(&mut res);
            res
        }
    }

    impl Apply for GcmEncrypt {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            assert!(buf.len() >= data.len());
            unsafe { self.context.update(data, buf); }
            data.len()
        }
    }

    /// AES in GCM mode authenticated decryption.
    pub struct GcmDecrypt {
        context: Context,
    }

    impl GcmDecrypt {
        /// Creates a new AES GCM decryptor.
        pub fn new(algo: Aes, key: &[u8]) -> GcmDecrypt {
            GcmDecrypt {
                context: Context::new(evpc(algo), Direction::Decrypt, key),
            }
        }

        /// Prepares the decryptor for use.
        ///
        /// `aad` (additional authenticated data) is optional unencrypted
        /// data to authenticate.
        ///
        /// `tag` is the authentication tag. Passing a truncated tag will not
        /// lead to authentication error. Allowed tag lengths
        /// are 4, 8, 12, 13, 14, 15 and 16 bytes.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self, iv: &[u8], aad: Option<&[u8]>, tag: &[u8]) {
            unsafe {
                self.context.init_with_iv(iv);
                self.context.set_tag(tag);
                if let Some(aad) = aad {
                    self.context.update_aad(aad);
                }
            }
        }

        /// Finishes the cipher.
        ///
        /// Returns AuthFailed if the data and AAD (if any) didn't match
        /// the authentication tag. In this case the data should be considered
        /// untrusted and discarded.
        pub fn finish(&mut self) -> Result<(), Error> {
            if self.context.clean_finalize().is_ok() {
                Ok(())
            }
            else {
                Err(Error::AuthFailed)
            }
        }
    }

    impl Apply for GcmDecrypt {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            assert!(buf.len() >= data.len());
            unsafe { self.context.update(data, buf); }
            data.len()
        }
    }
}

#[cfg(feature = "aes_ctr")]
pub mod ctr {
    //! CTR mode

    use std::mem;
    use std::num::Int;
    use super::{Aes, Apply, Context, Direction, Error};
    use ffi;

    // We only support AES right now
    const BLOCK_LENGTH: usize = 16;

    fn evpc(algo: Aes) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Aes::Aes128 => ffi::EVP_aes_128_ctr(),
                Aes::Aes256 => ffi::EVP_aes_256_ctr(),
            }
        }
    }

    /// AES in CTR mode.
    pub struct Ctr {
        context: Context,
        counter: u64,
        block_ofs: u8,
    }

    impl Ctr {
        /// Creates a new AES CTR en/decryptor (which are the same).
        ///
        /// Panics if counter overflow is detected.
        pub fn new(algo: Aes, key: &[u8]) -> Ctr {
            Ctr { context: Context::new(evpc(algo), Direction::Encrypt, key),
                  counter: 0, block_ofs: 0 }
        }

        /// Prepares the cipher for use.
        ///
        /// The cipher can only be operated between calls to `start` and `finish`.
        pub fn start(&mut self, iv: u64, initial_counter: u64) {
            unsafe {
                let buf: [u64; 2] = [iv.to_be(), initial_counter.to_be()];
                let buf: &[u8; 16] = mem::transmute(&buf);
                self.context.init_with_iv(buf);
            }
            self.counter = initial_counter;
            self.block_ofs = 0;
        }

        /// Finishes the cipher.
        ///
        /// Returns the next safe to use initial counter value.
        pub fn finish(&mut self) -> Result<u64, Error> {
            if self.context.clean_finalize().is_ok() {
                Ok(self.counter + if self.block_ofs > 0 { 1 } else { 0 })
            }
            else {
                Err(Error::Unspecified)
            }
        }
    }

    impl Apply for Ctr {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, 0);
            let len_with_carried = len + self.block_ofs as usize;
            self.counter = self.counter.checked_add((len_with_carried / BLOCK_LENGTH) as u64)
                .expect("Counter overflow");
            self.block_ofs = (len_with_carried % BLOCK_LENGTH) as u8;
            len
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Aes, Apply, PaddedFinish, Error, Filter, PaddedFilter};
    use super::Aes::*;
    use super::ecb::{EcbRaw, EcbPadded};
    use super::cbc::{CbcRaw, CbcPadded};
    use ffi;
    use std::iter::repeat;
    use std::cmp::max;
    use std::num::from_str_radix;
    use serialize::hex::FromHex;
    #[cfg(feature = "aes_ctr")]
    use super::ctr::{Ctr};
    #[cfg(feature = "aes_gcm")]
    use super::gcm::{GcmEncrypt, GcmDecrypt};

    fn unpack3<T: Copy>(tup: &(T, &str, &str, &str))
                       -> (T, Vec<u8>, Vec<u8>, Vec<u8>) {
        (tup.0, tup.1.from_hex().unwrap(), tup.2.from_hex().unwrap(),
         tup.3.from_hex().unwrap())
    }

    fn unpack4<T: Copy>(tup: &(T, &str, &str, &str, &str))
                       -> (T, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (tup.0, tup.1.from_hex().unwrap(), tup.2.from_hex().unwrap(),
         tup.3.from_hex().unwrap(), tup.4.from_hex().unwrap())
    }

    #[allow(dead_code)]
    fn unpack5<T: Copy>(tup: &(T, &str, &str, &str, &str, &str))
                       -> (T, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (tup.0, tup.1.from_hex().unwrap(), tup.2.from_hex().unwrap(),
         tup.3.from_hex().unwrap(), tup.4.from_hex().unwrap(),
         tup.5.from_hex().unwrap())
    }

    #[allow(dead_code)]
    fn unpack6<T: Copy>(tup: &(T, &str, &str, &str, &str, &str, &str))
                       -> (T, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (tup.0, tup.1.from_hex().unwrap(), tup.2.from_hex().unwrap(),
         tup.3.from_hex().unwrap(), tup.4.from_hex().unwrap(),
         tup.5.from_hex().unwrap(), tup.6.from_hex().unwrap())
    }

    const ECB_RAW_VEC: [(Aes, &'static str, &'static str, &'static str); 4] = [
        // One block
        (Aes128,                                // algo
         "99a5758d22880b01a4922f094dafceaa",    // key
         "d47b00a342faacdb9d7655c1bff4b8c3",    // plaintext
         "5e69f8b8b97ebbf7e2754a3d7fb9fa99"),   // ciphertext
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "00512f8c8717266aa0b91eec01604d7c"),
        // Two blocks
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "5cdd30b18d67d8a3670c0ed76913b5605e69f8b8b97ebbf7e2754a3d7fb9fa99"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "9d1001068827dd328ed86a540d4496b200512f8c8717266aa0b91eec01604d7c"),
    ];

    const ECB_PADDED_VEC: [(Aes, &'static str, &'static str, &'static str); 4] = [
        // One block
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "d47b00a342faacdb9d7655c1",
         "56ff92fb78bb6a00d0bd5165ae89b64d"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "d47b00a342faacdb9d7655c1",
         "80c1deb5f8a465f00daf7c2f67fc861d"),
        // Two blocks
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "5cdd30b18d67d8a3670c0ed76913b56056ff92fb78bb6a00d0bd5165ae89b64d"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "9d1001068827dd328ed86a540d4496b280c1deb5f8a465f00daf7c2f67fc861d"),
    ];

    const CBC_RAW_VEC: [(Aes, &'static str, &'static str, &'static str, &'static str); 4] = [
        // One block
        (Aes128,                                // algo
         "99a5758d22880b01a4922f094dafceaa",    // key
         "4002ddc1cd72650c32b895b026a3bda4",    // iv
         "d47b00a342faacdb9d7655c1bff4b8c3",    // plaintext
         "3a44bd0d547d82235effd2da38dbafc3"),   // ciphertext
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "7b9a09eabe4bd9eef5fb8af84c7ee8dd"),
        // Two blocks
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "698d24fa0a2fd282a3b724aafb8a1f547141be417fb40de785304c58452e713a"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "19a066de723ca454666290f8e8147a6d98288504b7ec8b80f3699954d1d930ff"),
    ];

    const CBC_PADDED_VEC: [(Aes, &'static str, &'static str, &'static str, &'static str); 4] = [
        // One block
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1",
         "b0dfa61dc8f7fd500d03899d875bbd2a"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1",
         "53fe2c0e77d663c454ffd9d3c53e2632"),
        // Two blocks
        (Aes128,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "698d24fa0a2fd282a3b724aafb8a1f5484046b796f05238ef8a6b551ab5fba66"),
        (Aes256,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "19a066de723ca454666290f8e8147a6ddde9fb1e6dbb8a52b5b09b24e228bc2d"),
    ];

    #[cfg(feature = "aes_gcm")]
    const GCM_VEC: [(Aes, &'static str, &'static str, &'static str,
                     &'static str, &'static str, &'static str); 12] = [
        (Aes128,                                // algo
         "7fddb57453c241d03efbed3ac44e371c",    // key
         "ee283a3fc75575e33efd4887",            // iv
         "",                                    // aad
         "d5de42b461646c255c87bd2962d3b9a2",    // plaintext
         "2ccda4a5415cb91e135c2a0f78c9b2fd",    // ciphertext
         "b36d1df9b9d5e596f83e8b7f52971cb3"),   // tag
        (Aes128,
         "c939cc13397c1d37de6ae0e1cb7c423c",
         "b3d8cc017cbb89b39e0f67e2",
         "24825602bd12a984e0092d3e448eda5f",
         "c3b3c41f113a31b73d9a5cd432103069",
         "93fe7d9e9bfd10348a5606e5cafa7354",
         "0032a1dc85f1c9786925a2e71d8272dd"),
         (Aes128,
          "93ae114052b7985d409a39a40df8c7ee",
          "8ad733a4a9b8330690238c42",
          "",
          "3f3bb0644eac878b97d990d257f5b36e1793490dbc13fea4efe9822cebba7444cce4dee5a7f5dfdf285f96785792812200c279",
          "bbb5b672a479afca2b11adb0a4c762b698dd565908fee1d101f6a01d63332c91b85d7f03ac48a477897d512b4572f9042cb7ea",
          "4d78bdcb1366fcba02fdccee57e1ff44"),
         (Aes128,
          "af57f42c60c0fc5a09adb81ab86ca1c3",
          "a2dc01871f37025dc0fc9a79",
          "41dc38988945fcb44faf2ef72d0061289ef8efd8",
          "3803a0727eeb0ade441e0ec107161ded2d425ec0d102f21f51bf2cf9947c7ec4aa72795b2f69b041596e8817d0a3c16f8fadeb",
          "b9a535864f48ea7b6b1367914978f9bfa087d854bb0e269bed8d279d2eea1210e48947338b22f9bad09093276a331e9c79c7f4",
          "4f71e72bde0018f555c5adcce062e005"),
         (Aes128,
          "2370e320d4344208e0ff5683f243b213",
          "04dbb82f044d30831c441228",
          "d43a8e5089eea0d026c03a85178b27da",
          "",
          "",
          "2a049c049d25aa95969b451d93c31c6e"),
         (Aes128,
          "762da58bb000f5d499818bc859989a30",
          "584c291ff1aa388a5112521e",
          "91f92e8bbda7b5ec967ade766f4f26e9189eaafad416f37b4891d3e37d70cb9a267aa843dd202858ade020261223dfce",
          "",
          "",
          "9ac7eb2d762facae06086c957959880e"),
         (Aes256,
          "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8",
          "473360e0ad24889959858995",
          "",
          "7789b41cb3ee548814ca0b388c10b343",
          "d2c78110ac7e8f107c0df0570bd7c90c",
          "c26a379b6d98ef2852ead8ce83a833a7"),
         (Aes256,
          "54e352ea1d84bfe64a1011096111fbe7668ad2203d902a01458c3bbd85bfce14",
          "df7c3bca00396d0c018495d9",
          "7e968d71b50c1f11fd001f3fef49d045",
          "85fc3dfad9b5a8d3258e4fc44571bd3b",
          "426e0efc693b7be1f3018db7ddbb7e4d",
          "ee8257795be6a1164d7e1d2d6cac77a7"),
         (Aes256,
          "4433db5fe066960bdd4e1d4d418b641c14bfcef9d574e29dcd0995352850f1eb",
          "0e396446655582838f27f72f",
          "",
          "d602c06b947abe06cf6aa2c5c1562e29062ad6220da9bc9c25d66a60bd85a80d4fbcc1fb4919b6566be35af9819aba836b8b47",
          "b0d254abe43bdb563ead669192c1e57e9a85c51dba0f1c8501d1ce92273f1ce7e140dcfac94757fabb128caad16912cead0607",
          "ffd0b02c92dbfcfbe9d58f7ff9e6f506"),
         (Aes256,
          "aeb3830cb9ce31cae7b1d47511bb2d3dcc2131714ace202b21b98820e7079792",
          "e7e87c45ec0a94c8e92353f1",
          "07d9bb1fa3aea7ceeefbedae87dcd713",
          "b4d0ecc410c430b61c11a1a42802858a0e9ee12f9a912f2f6b0570c99177f6de4bd79830cf9efb30759055e1f70d21e3f74957",
          "b20542b61b8fa6f847198334cb82fdbcb2311be855a6b2b3662bdb06ff0796238bea092a8ea21b585d38ace950378f41224269",
          "3bdd1d0cc2bbcefffe0ed2121aecbd00"),
         (Aes256,
          "6dfdafd6703c285c01f14fd10a6012862b2af950d4733abb403b2e745b26945d",
          "3749d0b3d5bacb71be06ade6",
          "c0d249871992e70302ae008193d1e89f",
          "",
          "",
          "4aa4cc69f84ee6ac16d9bfb4e05de500"),
         (Aes256,
          "752a9b3cc5f29bba64e773460c7396c13f911fe77de054097da5b682ea525d79",
          "f93e50fe23883216de85d3b4",
          "346dd8f25abaf85221fcbbccf794fe3c6794c0f16557e2ba14f9c03bffc99ee5539b9142d1952e66af35df91250e690b",
          "",
          "",
          "f02936676e36e7598258c37210b4470f"),
    ];

    #[cfg(feature = "aes_ctr")]
    const CTR_VEC: [(Aes, &'static str, &'static str, &'static str,
                     &'static str, &'static str); 4] = [
        (Aes128,                                        // algo
         "ba90370e3acbaf88e078634282702eb6",            // key
         "61c189f3f5b0b413",                            // iv
         "01",                                          // ctr in hex
         "36c9eabd56bc125814df3684ceffada4dc758782",    // plaintext
         "bc07dfa74afa44ae85ed4b02d47e0c036da21c21"),   // ciphertext
        (Aes128,
         "2b7e151628aed2a6abf7158809cf4f3c",
         "f0f1f2f3f4f5f6f7",
         "f8f9fafbfcfdfeff",
         "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
         "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"),
        (Aes256,
         "3baa31fe106c801ed56f88b600f64e70c4d9db48ca388a0702e9a92cc915b6b0",
         "61c189f3f5b0b413",
         "0100",
         "36c9eabd56bc125814df3684ceffada4dc758782",
         "c54f04aacf5b1229106f9a82a0170a0082120c18"),
        (Aes256,
         "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "f0f1f2f3f4f5f6f7",
         "f8f9fafbfcfdfeff",
         "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
         "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"),
    ];

    #[test]
    fn test_ecb_raw_apply() {
        let mut n = 0;
        for item in &ECB_RAW_VEC {
            let (algo, key, pt, ct) = unpack3(item);
            let mut res: Vec<u8> = repeat(0).take(
                max(pt.len(), ct.len()) + ffi::EVP_MAX_BLOCK_LENGTH).collect();

            let mut enc = EcbRaw::new_encrypt(algo, &key);
            enc.start();
            let len = enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == &res[..len], "vec #{}", n);

            let mut dec = EcbRaw::new_decrypt(algo, &key);
            dec.start();
            let len = dec.apply(&ct, &mut res);
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_padded_apply() {
        let mut n = 0;
        for item in &ECB_PADDED_VEC {
            let (algo, key, pt, ct) = unpack3(item);
            let mut res: Vec<u8> = repeat(0).take(
                max(pt.len(), ct.len()) + ffi::EVP_MAX_BLOCK_LENGTH).collect();

            let mut enc = EcbPadded::new_encrypt(algo, &key);
            enc.start();
            let mut len = enc.apply(&pt, &mut res);
            len += enc.finish(&mut res[len..]).unwrap();
            assert!(ct == &res[..len], "vec #{}", n);

            let mut dec = EcbPadded::new_decrypt(algo, &key);
            dec.start();
            let mut len = dec.apply(&ct, &mut res);
            len += dec.finish(&mut res[len..]).unwrap();
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_bad_padding() {
        let dummy = vec![0xcd; 23];
        let mut res = vec![0; 256];

        let mut enc = EcbRaw::new_encrypt(Aes::Aes128, &dummy[..16]);
        enc.start();
        enc.apply(&dummy, &mut res);
        assert!(enc.finish() == Err(Error::IncompleteBlock));

        let mut dec = EcbRaw::new_decrypt(Aes::Aes128, &dummy[..16]);
        dec.start();
        dec.apply(&dummy, &mut res);
        assert!(dec.finish() == Err(Error::IncompleteBlock));

        let mut dec = EcbPadded::new_decrypt(Aes::Aes128, &dummy[..16]);
        dec.start();
        dec.apply(&dummy, &mut res);
        assert!(dec.finish(&mut res) == Err(Error::InvalidPadding));
    }

    #[test]
    fn test_ecb_raw_recycle() {
        let dummy = vec![0xcd; 256];
        let mut res = vec![0; 512];
        let mut n;

        n = 0;
        for item in &ECB_RAW_VEC {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbRaw::new_encrypt(algo, &key);
            let mut dec = EcbRaw::new_decrypt(algo, &key);

            enc.start();
            enc.apply(&dummy, &mut res);
            let _ = enc.finish();
            dec.start();
            dec.apply(&dummy, &mut res);
            let _ = dec.finish();

            enc.start();
            let len = enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == &res[..len], "vec #{}", n);

            dec.start();
            let len = dec.apply(&ct, &mut res);
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_padded_recycle() {
        let dummy = vec![0xcd; 256];
        let mut res = vec![0; 512];
        let mut n;

        n = 0;
        for item in &ECB_PADDED_VEC {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbPadded::new_encrypt(algo, &key);
            let mut dec = EcbPadded::new_decrypt(algo, &key);

            enc.start();
            enc.apply(&dummy, &mut res);
            let _ = enc.finish(&mut res);
            dec.start();
            dec.apply(&dummy, &mut res);
            let _ = dec.finish(&mut res);

            enc.start();
            let mut len = enc.apply(&pt, &mut res);
            len += enc.finish(&mut res[len..]).unwrap();
            assert!(ct == &res[..len], "vec #{}", n);

            dec.start();
            let mut len = dec.apply(&ct, &mut res);
            len += dec.finish(&mut res[len..]).unwrap();
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_raw_write() {
        let mut n = 0;

        for item in &ECB_RAW_VEC {
            let (algo, key, pt, ct) = unpack3(item);
            let mut res: Vec<u8> = Vec::new();

            let mut enc = EcbRaw::new_encrypt(algo, &key);
            enc.start();
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = EcbRaw::new_decrypt(algo, &key);
            dec.start();
            {
                let mut w = Filter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_padded_write() {
        let mut n = 0;

        for item in &ECB_PADDED_VEC {
            let (algo, key, pt, ct) = unpack3(item);

            let mut res: Vec<u8> = Vec::new();

            let mut enc = EcbPadded::new_encrypt(algo, &key);
            enc.start();
            {
                let mut w = PaddedFilter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = EcbPadded::new_decrypt(algo, &key);
            dec.start();
            {
                let mut w = PaddedFilter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_padded_write_twice() {
        let mut n = 0;

        for item in &ECB_PADDED_VEC {
            let (algo, key, pt, ct) = unpack3(item);

            let mut res: Vec<u8> = Vec::new();

            let mut enc = EcbPadded::new_encrypt(algo, &key);
            enc.start();
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            {
                let w = PaddedFilter::new(&mut enc, &mut res);
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = EcbPadded::new_decrypt(algo, &key);
            dec.start();
            {
                let mut w = Filter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            {
                let w = PaddedFilter::new(&mut dec, &mut res);
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_raw_apply() {
        let mut n = 0;
        for item in &CBC_RAW_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);
            let mut res: Vec<u8> = repeat(0).take(
                max(pt.len(), ct.len()) + ffi::EVP_MAX_BLOCK_LENGTH).collect();

            let mut enc = CbcRaw::new_encrypt(algo, &key);
            enc.start(&iv);
            let len = enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == &res[..len], "vec #{}", n);

            let mut dec = CbcRaw::new_decrypt(algo, &key);
            dec.start(&iv);
            let len = dec.apply(&ct, &mut res);
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_padded_apply() {
        let mut n = 0;
        for item in &CBC_PADDED_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);
            let mut res: Vec<u8> = repeat(0).take(
                max(pt.len(), ct.len()) + ffi::EVP_MAX_BLOCK_LENGTH).collect();

            let mut enc = CbcPadded::new_encrypt(algo, &key);
            enc.start(&iv);
            let mut len = enc.apply(&pt, &mut res);
            len += enc.finish(&mut res[len..]).unwrap();
            assert!(ct == &res[..len], "vec #{}", n);

            let mut dec = CbcPadded::new_decrypt(algo, &key);
            dec.start(&iv);
            let mut len = dec.apply(&ct, &mut res);
            len += dec.finish(&mut res[len..]).unwrap();
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_bad_padding() {
        let dummy = vec![0xcd; 23];
        let mut res = vec![0; 256];

        let mut enc = CbcRaw::new_encrypt(Aes::Aes128, &dummy[..16]);
        enc.start(&dummy[..16]);
        enc.apply(&dummy, &mut res);
        assert!(enc.finish() == Err(Error::IncompleteBlock));

        let mut dec = CbcRaw::new_decrypt(Aes::Aes128, &dummy[..16]);
        dec.start(&dummy[..16]);
        dec.apply(&dummy, &mut res);
        assert!(dec.finish() == Err(Error::IncompleteBlock));

        let mut dec = CbcPadded::new_decrypt(Aes::Aes128, &dummy[..16]);
        dec.start(&dummy[..16]);
        dec.apply(&dummy, &mut res);
        assert!(dec.finish(&mut res) == Err(Error::InvalidPadding));
    }

    #[test]
    fn test_cbc_raw_recycle() {
        let dummy = vec![0xcd; 256];
        let mut res = vec![0; 512];
        let mut n;

        n = 0;
        for item in &CBC_RAW_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcRaw::new_encrypt(algo, &key);
            let mut dec = CbcRaw::new_decrypt(algo, &key);

            enc.start(&dummy[..16]);
            enc.apply(&dummy, &mut res);
            let _ = enc.finish();
            dec.start(&dummy[..16]);
            dec.apply(&dummy, &mut res);
            let _ = dec.finish();

            enc.start(&iv);
            let len = enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == &res[..len], "vec #{}", n);

            dec.start(&iv);
            let len = dec.apply(&ct, &mut res);
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_padded_recycle() {
        let dummy = vec![0xcd; 256];
        let mut res = vec![0; 512];
        let mut n;

        n = 0;
        for item in &CBC_PADDED_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcPadded::new_encrypt(algo, &key);
            let mut dec = CbcPadded::new_decrypt(algo, &key);

            enc.start(&dummy[..16]);
            enc.apply(&dummy, &mut res);
            let _ = enc.finish(&mut res);
            dec.start(&dummy[..16]);
            dec.apply(&dummy, &mut res);
            let _ = dec.finish(&mut res);

            enc.start(&iv);
            let mut len = enc.apply(&pt, &mut res);
            len += enc.finish(&mut res[len..]).unwrap();
            assert!(ct == &res[..len], "vec #{}", n);

            dec.start(&iv);
            let mut len = dec.apply(&ct, &mut res);
            len += dec.finish(&mut res[len..]).unwrap();
            assert!(pt == &res[..len], "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_raw_write() {
        let mut n = 0;

        for item in &CBC_RAW_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);
            let mut res: Vec<u8> = Vec::new();

            let mut enc = CbcRaw::new_encrypt(algo, &key);
            enc.start(&iv);
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            assert!(enc.finish().is_ok(), "vec #{}", n);
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = CbcRaw::new_decrypt(algo, &key);
            dec.start(&iv);
            {
                let mut w = Filter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            assert!(dec.finish().is_ok(), "vec #{}", n);
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_padded_write() {
        let mut n = 0;

        for item in &CBC_PADDED_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut res: Vec<u8> = Vec::new();

            let mut enc = CbcPadded::new_encrypt(algo, &key);
            enc.start(&iv);
            {
                let mut w = PaddedFilter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = CbcPadded::new_decrypt(algo, &key);
            dec.start(&iv);
            {
                let mut w = PaddedFilter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_padded_write_twice() {
        let mut n = 0;

        for item in &CBC_PADDED_VEC {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut res: Vec<u8> = Vec::new();

            let mut enc = CbcPadded::new_encrypt(algo, &key);
            enc.start(&iv);
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            {
                let w = PaddedFilter::new(&mut enc, &mut res);
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(ct == res, "vec #{}", n);

            res.truncate(0);
            let mut dec = CbcPadded::new_decrypt(algo, &key);
            dec.start(&iv);
            {
                let mut w = Filter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            {
                let w = PaddedFilter::new(&mut dec, &mut res);
                assert!(w.close().is_ok(), "vec #{}", n);
            }
            assert!(pt == res, "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_gcm")]
    fn test_gcm_apply() {
        let mut n = 0;
        for item in &GCM_VEC {
            let (algo, key, iv, aad, pt, ct, tag) = unpack6(item);
            let mut res: Vec<u8> = repeat(0).take(pt.len()).collect();

            let mut enc = GcmEncrypt::new(algo, &key);
            if aad.len() > 0 {
                enc.start(&iv, Some(&aad));
            }
            else {
                enc.start(&iv, None);
            }
            enc.apply(&pt, &mut res);
            let tag_res = enc.finish();
            assert!(ct == res, "vec #{}", n);
            assert!(tag == tag_res, "vec #{}", n);

            let mut dec = GcmDecrypt::new(algo, &key);
            if aad.len() > 0 {
                dec.start(&iv, Some(&aad), &tag);
            }
            else {
                dec.start(&iv, None, &tag);
            }
            dec.apply(&ct, &mut res);
            let auth = dec.finish();
            assert!(pt == res, "vec #{}", n);
            assert!(auth.is_ok(), "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_gcm")]
    fn test_gcm_write() {
        let mut n = 0;
        for item in &GCM_VEC {
            let (algo, key, iv, aad, pt, ct, tag) = unpack6(item);
            let mut res: Vec<u8> = Vec::new();

            let mut enc = GcmEncrypt::new(algo, &key);
            if aad.len() > 0 {
                enc.start(&iv, Some(&aad));
            }
            else {
                enc.start(&iv, None);
            }
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            let tag_res = enc.finish();
            assert!(ct == res, "vec #{}", n);
            assert!(tag == tag_res, "vec #{}", n);

            res.truncate(0);
            let mut dec = GcmDecrypt::new(algo, &key);
            if aad.len() > 0 {
                dec.start(&iv, Some(&aad), &tag);
            }
            else {
                dec.start(&iv, None, &tag);
            }
            {
                let mut w = Filter::new(&mut dec, &mut res);
                for byte in &ct {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            let auth = dec.finish();
            assert!(pt == res, "vec #{}", n);
            assert!(auth.is_ok(), "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_gcm")]
    fn test_gcm_recycle() {
        let dummy = vec![0xcd; 256];
        let mut dummy_res = vec![0; 256];
        let mut n = 0;
        for item in &GCM_VEC {
            let (algo, key, iv, aad, pt, ct, tag) = unpack6(item);
            let mut res: Vec<u8> = repeat(0).take(pt.len()).collect();

            let mut enc = GcmEncrypt::new(algo, &key);

            enc.start(&dummy[..12], None);
            enc.apply(&dummy, &mut dummy_res);
            enc.finish();

            if aad.len() > 0 {
                enc.start(&iv, Some(&aad));
            }
            else {
                enc.start(&iv, None);
            }
            enc.apply(&pt, &mut res);
            let tag_res = enc.finish();
            assert!(ct == res, "vec #{}", n);
            assert!(tag == tag_res, "vec #{}", n);

            let mut dec = GcmDecrypt::new(algo, &key);

            dec.start(&dummy[..12], None, &dummy[..16]);
            dec.apply(&dummy, &mut dummy_res);
            let _ = dec.finish();

            if aad.len() > 0 {
                dec.start(&iv, Some(&aad), &tag);
            }
            else {
                dec.start(&iv, None, &tag);
            }
            dec.apply(&ct, &mut res);
            let auth = dec.finish();
            assert!(pt == res, "vec #{}", n);
            assert!(auth.is_ok(), "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_gcm")]
    fn test_gcm_auth_fail() {
        let garbage = b"This is dummy invalid input";
        let mut n = 0;
        for item in &GCM_VEC {
            let (algo, key, iv, aad, pt, _, tag) = unpack6(item);
            let buf_len = max(pt.len(), garbage.len());
            let mut res: Vec<u8> = repeat(0).take(buf_len).collect();

            let mut dec = GcmDecrypt::new(algo, &key);
            if aad.len() > 0 {
                dec.start(&iv, None, &tag);
            }
            else {
                dec.start(&iv, Some(garbage), &tag);
            }
            dec.apply(&pt, &mut res);
            let auth = dec.finish();
            assert!(auth == Err(Error::AuthFailed), "vec #{}", n);

            let mut dec = GcmDecrypt::new(algo, &key);
            if aad.len() > 0 {
                dec.start(&iv, Some(&aad), &tag);
            }
            else {
                dec.start(&iv, None, &tag);
            }
            dec.apply(&garbage, &mut res);
            let auth = dec.finish();
            assert!(auth == Err(Error::AuthFailed), "vec #{}", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_gcm")]
    fn test_gcm_var_tag_len() {
        let test_lens = vec![4, 8, 12, 13, 14, 15, 16];
        let mut n = 0;
        for item in &GCM_VEC {
            let (algo, key, iv, aad, pt, ct, tag) = unpack6(item);
            let mut res: Vec<u8> = repeat(0).take(pt.len()).collect();
            let mut enc = GcmEncrypt::new(algo, &key);
            let mut dec = GcmDecrypt::new(algo, &key);

            for tag_len in &test_lens {
                let range = ..*tag_len;
                if aad.len() > 0 {
                    enc.start(&iv, Some(&aad));
                    dec.start(&iv, Some(&aad), &tag[range]);
                }
                else {
                    enc.start(&iv, None);
                    dec.start(&iv, None, &tag[range]);
                }
                enc.apply(&pt, &mut res);
                dec.apply(&ct, &mut res);

                let tag_res = enc.finish();
                let auth = dec.finish();
                assert!(tag[range] == tag_res[range], "vec #{}, len {}", n, tag_len);
                assert!(auth.is_ok(), "vec #{}, len {}", n, tag_len);
            }

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_ctr")]
    fn test_ctr_apply() {
        let mut n = 0;
        for item in &CTR_VEC {
            let (algo, key, _, _, pt, ct) = unpack5(item);
            let iv: u64 = from_str_radix(item.2, 16).unwrap();
            let ctr: u64 = from_str_radix(item.3, 16).unwrap();
            let mut res: Vec<u8> = repeat(0).take(pt.len()).collect();

            let mut enc = Ctr::new(algo, &key);
            enc.start(iv, ctr);
            enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "CTR_VEC[{}]", n);
            assert!(ct == res, "CTR_VEC[{}]", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_ctr")]
    fn test_ctr_recycle() {
        let dummy_iv = 0xcdcdcdcdabababab;
        let dummy = vec![0xcd; 23];
        let mut dummy_res = vec![0; 256];
        let mut n = 0;
        for item in &CTR_VEC {
            let (algo, key, _, _, pt, ct) = unpack5(item);
            let iv: u64 = from_str_radix(item.2, 16).unwrap();
            let ctr: u64 = from_str_radix(item.3, 16).unwrap();
            let mut res: Vec<u8> = repeat(0).take(pt.len()).collect();

            let mut enc = Ctr::new(algo, &key);
            enc.start(dummy_iv, dummy_iv);
            enc.apply(&dummy, &mut dummy_res);
            let _ = enc.finish();

            enc.start(iv, ctr);
            enc.apply(&pt, &mut res);
            assert!(enc.finish().is_ok(), "CTR_VEC[{}]", n);
            assert!(ct == res, "CTR_VEC[{}]", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_ctr")]
    fn test_ctr_write() {
        let mut n = 0;
        for item in &CTR_VEC {
            let (algo, key, _, _, pt, ct) = unpack5(item);
            let iv: u64 = from_str_radix(item.2, 16).unwrap();
            let ctr: u64 = from_str_radix(item.3, 16).unwrap();
            let mut res: Vec<u8> = Vec::new();

            let mut enc = Ctr::new(algo, &key);
            enc.start(iv, ctr);
            {
                let mut w = Filter::new(&mut enc, &mut res);
                for byte in &pt {
                    assert!(w.write_all(&[*byte]).is_ok(), "vec #{}", n);
                }
            }
            assert!(enc.finish().is_ok(), "CTR_VEC[{}]", n);
            assert!(ct == res, "CTR_VEC[{}]", n);

            n += 1;
        }
    }

    #[test]
    #[cfg(feature = "aes_ctr")]
    fn test_ctr_counter_arithmetic() {
        let dummy_iv = 0u64;
        let dummy = vec![0; 256];
        let mut res = vec![0; 256];
        let mut enc = Ctr::new(Aes128, &dummy[..16]);

        let mut test = |cnt: u64, len: usize| -> u64 {
            enc.start(dummy_iv, cnt);
            enc.apply(&dummy[..len], &mut res);
            enc.finish().unwrap()
        };

        assert!(test(0, 0) == 0);
        assert!(test(0, 1) == 1);
        assert!(test(0, 16) == 1);
        assert!(test(0, 17) == 2);
        assert!(test(0, 32) == 2);
        assert!(test(0, 33) == 3);
        assert!(test(100, 1) == 101);
    }

    #[test]
    #[should_fail]
    #[cfg(feature = "aes_ctr")]
    fn test_ctr_counter_overflow_panic() {
        let dummy_iv = 0u64;
        let ctr = -4i64 as u64;
        let dummy = vec![0; 256];
        let mut res = vec![0; 256];
        let mut enc = Ctr::new(Aes128, &dummy[..16]);
        enc.start(dummy_iv, ctr);
        enc.apply(&dummy, &mut res);
    }
}
