use libc::c_int;
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

#[derive(Copy, PartialEq)]
pub enum Algo {
    Aes128,
    Aes256,
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

const MAX_BLOCK_LEN: usize = 16;
const DEFAULT_BUF_LEN: usize = 16384;

/// A block mode cipher
trait BlockMode {
    fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize;
    fn finish(&mut self, buf: &mut [u8]) -> usize;
}

/// A stream(-like) mode cipher
trait StreamMode {
    fn apply(&mut self, data: &[u8], buf: &mut [u8]);
    fn finish(&mut self);
}

/// A cipher that works on large blocks (sectors)
trait SectorMode {
    fn apply(&mut self, iv: &[u8], data: &[u8], buf: &mut [u8]);
    fn finish(&mut self);
}

/// An authenticated stream(-like) mode cipher encryption
trait AuthStreamModeEncrypt {
    fn apply(&mut self, data: &[u8], buf: &mut [u8]);
    fn finish(&mut self) -> Vec<u8>;
}

/// An authenticated stream(-like) mode cipher decryption
trait AuthStreamModeDecrypt {
    fn apply(&mut self, data: &[u8], buf: &mut [u8]);
    fn finish(&mut self) -> bool;
}

/// Provides a way to use ciphers as `Writer`s
// Subject to changes after std::io stabilization
pub struct Filter<'a, T: 'a> {
    cipher: &'a mut T,
    sink: &'a mut (Writer + 'a),
}

impl <'a, T> Filter<'a, T> {
    /// Create a `Writer` adapter for the `cipher`. The `cipher` has to be `start`ed.
    pub fn new(cipher: &'a mut T, sink: &'a mut (Writer + 'a))
          -> Filter<'a, T> {
        Filter { cipher: cipher, sink: sink }
    }
}

impl <'a, T: BlockMode> Writer for Filter<'a, T> {
    fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        let mut buf = [0; DEFAULT_BUF_LEN + MAX_BLOCK_LEN];
        for chunk in data.chunks(DEFAULT_BUF_LEN) {
            let len = self.cipher.apply(chunk, &mut buf);
            if len > 0 {
                let _ = self.sink.write_all(&buf[..len]);
            }
        }
        Ok(())
    }
}

#[unsafe_destructor]
impl <'a, T: BlockMode> Drop for Filter<'a, T> {
    // this should've been close()
    fn drop(&mut self) {
        let mut buf = [0; MAX_BLOCK_LEN];
        // this could panic
        let len = self.cipher.finish(&mut buf);
        if len > 0 {
            let _ = self.sink.write_all(&buf[..len]);
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

    fn checked_update(&mut self, data: &[u8], buf: &mut [u8], block_len: usize) -> usize {
        assert!(buf.len() >= data.len() + block_len);
        unsafe { self.update(data, buf) }
    }

    unsafe fn finalize(&mut self, buf: &mut [u8]) -> usize {
        assert!(self.state != Finalized, "Illegal call order");
        let mut len = 0;
        chk!(ffi::EVP_CipherFinal_ex(self.ctx, buf.as_mut_ptr(), &mut len));
        let len = len as usize;
        assert!(len <= buf.len());
        self.state = Finalized;
        len
    }

    fn checked_finalize(&mut self, buf: &mut [u8], block_len: usize) -> usize {
        assert!(buf.len() >= block_len);
        unsafe { self.finalize(buf) }
    }

    fn set_padding(&mut self, pad: bool) {
        unsafe {
            let p = match pad { true => 1, false => 0 };
            chk!(ffi::EVP_CIPHER_CTX_set_padding(self.ctx, p));
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if self.state != Finalized {
                let mut buf: [u8; MAX_BLOCK_LEN] = ::std::mem::uninitialized();
                let mut l = 0;
                ffi::EVP_CipherFinal_ex(self.ctx, buf.as_mut_ptr(), &mut l);
            }
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

pub mod ecb{
    use super::{Algo, BlockMode, Context, Direction};
    use ffi;

    fn evpc(algo: Algo) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Algo::Aes128 => ffi::EVP_aes_128_ecb(),
                Algo::Aes256 => ffi::EVP_aes_256_ecb(),
            }
        }
    }

    pub struct EcbRaw {
        context: Context,
    }

    impl EcbRaw {
        pub fn new_encrypt(algo: Algo, key: &[u8]) -> EcbRaw {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(false);
            EcbRaw { context: c }
        }

        pub fn new_decrypt(algo: Algo, key: &[u8]) -> EcbRaw {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(false);
            EcbRaw { context: c }
        }

        pub fn start(&mut self) {
            self.context.init();
        }
    }

    impl BlockMode for EcbRaw {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, super::MAX_BLOCK_LEN);
            len
        }

        fn finish(&mut self, buf: &mut [u8]) -> usize {
            self.context.checked_finalize(buf, 0);
            0
        }
    }

    pub struct EcbPadded {
        context: Context,
    }

    impl EcbPadded {
        pub fn new_encrypt(algo: Algo, key: &[u8]) -> EcbPadded {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(true);
            EcbPadded { context: c }
        }

        pub fn new_decrypt(algo: Algo, key: &[u8]) -> EcbPadded {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(true);
            EcbPadded { context: c }
        }

        pub fn start(&mut self) {
            self.context.init();
        }
    }

    impl BlockMode for EcbPadded {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, super::MAX_BLOCK_LEN);
            len
        }

        fn finish(&mut self, buf: &mut [u8]) -> usize {
            let len = self.context.checked_finalize(buf, super::MAX_BLOCK_LEN);
            len
        }
    }
}

pub mod cbc {
    use super::{Algo, BlockMode, Context, Direction};
    use ffi;

    fn evpc(algo: Algo) -> *const ffi::EVP_CIPHER {
        unsafe {
            match algo {
                Algo::Aes128 => ffi::EVP_aes_128_cbc(),
                Algo::Aes256 => ffi::EVP_aes_256_cbc(),
            }
        }
    }

    pub struct CbcRaw {
        context: Context,
    }

    impl CbcRaw {
        pub fn new_encrypt(algo: Algo, key: &[u8]) -> CbcRaw {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(false);
            CbcRaw { context: c }
        }

        pub fn new_decrypt(algo: Algo, key: &[u8]) -> CbcRaw {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(false);
            CbcRaw { context: c }
        }

        pub fn start(&mut self, iv: &[u8]) {
            unsafe { self.context.init_with_iv(iv); }
        }
    }

    impl BlockMode for CbcRaw {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, super::MAX_BLOCK_LEN);
            len
        }

        fn finish(&mut self, buf: &mut [u8]) -> usize {
            self.context.checked_finalize(buf, 0);
            0
        }
    }

    pub struct CbcPadded {
        context: Context,
    }

    impl CbcPadded {
        pub fn new_encrypt(algo: Algo, key: &[u8]) -> CbcPadded {
            let mut c = Context::new(evpc(algo), Direction::Encrypt, key);
            c.set_padding(true);
            CbcPadded { context: c }
        }

        pub fn new_decrypt(algo: Algo, key: &[u8]) -> CbcPadded {
            let mut c = Context::new(evpc(algo), Direction::Decrypt, key);
            c.set_padding(true);
            CbcPadded { context: c }
        }

        pub fn start(&mut self, iv: &[u8]) {
            unsafe { self.context.init_with_iv(iv); }
        }
    }

    impl BlockMode for CbcPadded {
        fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
            let len = self.context.checked_update(data, buf, super::MAX_BLOCK_LEN);
            len
        }

        fn finish(&mut self, buf: &mut [u8]) -> usize {
            let len = self.context.checked_finalize(buf, super::MAX_BLOCK_LEN);
            len
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Algo, BlockMode, Filter};
    use super::Algo::*;
    use super::ecb::{EcbRaw, EcbPadded};
    use super::cbc::{CbcRaw, CbcPadded};
    use std::iter::repeat;
    use std::cmp::max;
    use serialize::hex::FromHex;

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

    const ECB_RAW_VEC: [(Algo, &'static str, &'static str, &'static str); 4] = [
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

    const ECB_PADDED_VEC: [(Algo, &'static str, &'static str, &'static str); 4] = [
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

    const CBC_RAW_VEC: [(Algo, &'static str, &'static str, &'static str, &'static str); 4] = [
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

    const CBC_PADDED_VEC: [(Algo, &'static str, &'static str, &'static str, &'static str); 4] = [
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

    fn test_block_mode_apply<T: BlockMode>(vec_name: &str, n: i32, pt: &[u8],
                                           ct: &[u8], enc: &mut T, dec: &mut T) {
        let buf_len = max(pt.len(), ct.len()) + super::MAX_BLOCK_LEN;
        let mut res: Vec<u8> = repeat(0).take(buf_len).collect();
        let mut len;

        len = enc.apply(pt, &mut *res);
        len += enc.finish(&mut res[len..]);
        assert!(ct == &res[..len], "{}[{}] encrypt", vec_name, n);

        len = dec.apply(ct, &mut *res);
        len += dec.finish(&mut res[len..]);
        assert!(pt == &res[..len], "{}[{}] decrypt", vec_name, n);
    }

    fn test_block_mode_write<T: BlockMode>(vec_name: &str, n: i32, pt: &[u8],
                                           ct: &[u8], enc: &mut T, dec: &mut T) {
        let mut res: Vec<u8> = Vec::new();

        {
            let mut w = Filter::new(enc, &mut res);
            for byte in pt.iter() {
                let _ = w.write_all(&[*byte]);
            }
        }
        assert!(ct == res, "{}[{}] encrypt", vec_name, n);

        res.truncate(0);

        {
            let mut w = Filter::new(dec, &mut res);
            for byte in ct.iter() {
                let _ = w.write_all(&[*byte]);
            }
        }
        assert!(pt == res, "{}[{}] decrypt", vec_name, n);
    }

    #[test]
    fn test_ecb_apply() {
        let mut n;

        n = 0;
        for item in ECB_RAW_VEC.iter() {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbRaw::new_encrypt(algo, &*key);
            enc.start();
            let mut dec = EcbRaw::new_decrypt(algo, &*key);
            dec.start();
            test_block_mode_apply("ECB_RAW_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }

        n = 0;
        for item in ECB_PADDED_VEC.iter() {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbPadded::new_encrypt(algo, &*key);
            enc.start();
            let mut dec = EcbPadded::new_decrypt(algo, &*key);
            dec.start();
            test_block_mode_apply("ECB_PADDED_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_write() {
        let mut n;

        n = 0;
        for item in ECB_RAW_VEC.iter() {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbRaw::new_encrypt(algo, &*key);
            enc.start();
            let mut dec = EcbRaw::new_decrypt(algo, &*key);
            dec.start();
            test_block_mode_write("ECB_RAW_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }

        n = 0;
        for item in ECB_PADDED_VEC.iter() {
            let (algo, key, pt, ct) = unpack3(item);

            let mut enc = EcbPadded::new_encrypt(algo, &*key);
            enc.start();
            let mut dec = EcbPadded::new_decrypt(algo, &*key);
            dec.start();
            test_block_mode_write("ECB_PADDED_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_apply() {
        let mut n;

        n = 0;
        for item in CBC_RAW_VEC.iter() {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcRaw::new_encrypt(algo, &*key);
            enc.start(&*iv);
            let mut dec = CbcRaw::new_decrypt(algo, &*key);
            dec.start(&*iv);
            test_block_mode_apply("CBC_RAW_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }

        n = 0;
        for item in CBC_PADDED_VEC.iter() {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcPadded::new_encrypt(algo, &*key);
            enc.start(&*iv);
            let mut dec = CbcPadded::new_decrypt(algo, &*key);
            dec.start(&*iv);
            test_block_mode_apply("CBC_PADDED_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_write() {
        let mut n;

        n = 0;
        for item in CBC_RAW_VEC.iter() {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcRaw::new_encrypt(algo, &*key);
            enc.start(&*iv);
            let mut dec = CbcRaw::new_decrypt(algo, &*key);
            dec.start(&*iv);
            test_block_mode_write("CBC_RAW_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }

        n = 0;
        for item in CBC_PADDED_VEC.iter() {
            let (algo, key, iv, pt, ct) = unpack4(item);

            let mut enc = CbcPadded::new_encrypt(algo, &*key);
            enc.start(&*iv);
            let mut dec = CbcPadded::new_decrypt(algo, &*key);
            dec.start(&*iv);
            test_block_mode_write("CBC_PADDED_VEC", n, &*pt, &*ct, &mut enc, &mut dec);

            n += 1;
        }
    }
}
