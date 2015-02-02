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

/// A cipher that {en|de}codes bytes from one buffer into another
trait Coder {
    fn apply(&mut self, data: &[u8], buf: &mut [u8]) -> usize;
    fn finish(&mut self, buf: &mut [u8]) -> usize;
}

/// Provides a way to use ciphers as `Writer`s
// Subject to changes after std::io stabilization
pub struct WriterAdapter<'a, T: 'a> {
    parent: &'a mut T,
    sink: &'a mut (Writer + 'a),
}

impl <'a, T: Coder> Writer for WriterAdapter<'a, T> {
    fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        let mut buf = [0; DEFAULT_BUF_LEN + MAX_BLOCK_LEN];
        for chunk in data.chunks(DEFAULT_BUF_LEN) {
            let len = self.parent.apply(chunk, &mut buf);
            if len > 0 {
                let _ = self.sink.write_all(&buf[..len]);
            }
        }
        Ok(())
    }
}

#[unsafe_destructor]
impl <'a, T: Coder> Drop for WriterAdapter<'a, T> {
    fn drop(&mut self) {
        let mut buf = [0; MAX_BLOCK_LEN];
        // this could panic
        let len = self.parent.finish(&mut buf);
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
    use super::{Coder, Context, Direction, WriterAdapter};
    use ffi;

    #[allow(non_camel_case_types)]
    #[derive(Copy, PartialEq, Debug)]
    pub enum Type {
        AES_128_PADDED,
        AES_256_PADDED,
        AES_128_RAW,
        AES_256_RAW,
    }

    impl Type {
        fn padding(&self) -> bool {
            use self::Type::*;
            match *self {
                AES_128_PADDED | AES_256_PADDED => true,
                AES_128_RAW | AES_256_RAW => false,
            }
        }

        fn evpc(&self) -> *const ffi::EVP_CIPHER {
            use self::Type::*;
            unsafe {
                match *self {
                    AES_128_PADDED | AES_128_RAW => ffi::EVP_aes_128_ecb(),
                    AES_256_PADDED | AES_256_RAW => ffi::EVP_aes_256_ecb(),
                }
            }
        }
    }

    pub struct ECB {
        context: Context,
    }

    impl ECB {
        pub fn new_encrypt(ty: Type, key: &[u8]) -> ECB {
            let mut c = Context::new(ty.evpc(), Direction::Encrypt, key);
            c.set_padding(ty.padding());
            ECB { context: c }
        }

        pub fn new_decrypt(ty: Type, key: &[u8]) -> ECB {
            let mut c = Context::new(ty.evpc(), Direction::Decrypt, key);
            c.set_padding(ty.padding());
            ECB { context: c }
        }

        pub fn start(&mut self) {
            self.context.init();
        }

        pub fn start_writer<'a>(&'a mut self, sink: &'a mut (Writer + 'a))
                    -> WriterAdapter<'a, ECB> {
            self.start();
            WriterAdapter { parent: self, sink: sink }
        }
    }

    impl Coder for ECB {
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
    use super::{Coder, Context, Direction, WriterAdapter};
    use ffi;

    #[allow(non_camel_case_types)]
    #[derive(Copy, PartialEq, Debug)]
    pub enum Type {
        AES_128_PADDED,
        AES_256_PADDED,
        AES_128_RAW,
        AES_256_RAW,
    }

    impl Type {
        fn padding(&self) -> bool {
            use self::Type::*;
            match *self {
                AES_128_PADDED | AES_256_PADDED => true,
                AES_128_RAW | AES_256_RAW => false,
            }
        }

        fn evpc(&self) -> *const ffi::EVP_CIPHER {
            use self::Type::*;
            unsafe {
                match *self {
                    AES_128_PADDED | AES_128_RAW => ffi::EVP_aes_128_cbc(),
                    AES_256_PADDED | AES_256_RAW => ffi::EVP_aes_256_cbc(),
                }
            }
        }
    }

    pub struct CBC {
        context: Context,
    }

    impl CBC {
        pub fn new_encrypt(ty: Type, key: &[u8]) -> CBC {
            let mut c = Context::new(ty.evpc(), Direction::Encrypt, key);
            c.set_padding(ty.padding());
            CBC { context: c }
        }

        pub fn new_decrypt(ty: Type, key: &[u8]) -> CBC {
            let mut c = Context::new(ty.evpc(), Direction::Decrypt, key);
            c.set_padding(ty.padding());
            CBC { context: c }
        }

        pub fn start(&mut self, iv: &[u8]) {
            unsafe { self.context.init_with_iv(iv); }
        }

        pub fn start_writer<'a>(&'a mut self, iv: &[u8], sink: &'a mut (Writer + 'a))
                    -> WriterAdapter<'a, CBC> {
            self.start(iv);
            WriterAdapter { parent: self, sink: sink }
        }
    }

    impl Coder for CBC {
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
    use super::Coder;
    use super::ecb::{self, ECB};
    use super::cbc::{self, CBC};
    use std::iter::repeat;
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

    const ECB_VEC: [(ecb::Type, &'static str, &'static str, &'static str); 8] = [
        // One block
        (ecb::Type::AES_128_RAW,
         "99a5758d22880b01a4922f094dafceaa",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "5e69f8b8b97ebbf7e2754a3d7fb9fa99"),
        (ecb::Type::AES_128_PADDED,
         "99a5758d22880b01a4922f094dafceaa",
         "d47b00a342faacdb9d7655c1",
         "56ff92fb78bb6a00d0bd5165ae89b64d"),
        (ecb::Type::AES_256_RAW,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "00512f8c8717266aa0b91eec01604d7c"),
        (ecb::Type::AES_256_PADDED,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "d47b00a342faacdb9d7655c1",
         "80c1deb5f8a465f00daf7c2f67fc861d"),
        // Two blocks
        (ecb::Type::AES_128_RAW,
         "99a5758d22880b01a4922f094dafceaa",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "5cdd30b18d67d8a3670c0ed76913b5605e69f8b8b97ebbf7e2754a3d7fb9fa99"),
        (ecb::Type::AES_128_PADDED,
         "99a5758d22880b01a4922f094dafceaa",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "5cdd30b18d67d8a3670c0ed76913b56056ff92fb78bb6a00d0bd5165ae89b64d"),
        (ecb::Type::AES_256_RAW,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "9d1001068827dd328ed86a540d4496b200512f8c8717266aa0b91eec01604d7c"),
        (ecb::Type::AES_256_PADDED,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "9d1001068827dd328ed86a540d4496b280c1deb5f8a465f00daf7c2f67fc861d"),
    ];

    const CBC_VEC: [(cbc::Type, &'static str, &'static str, &'static str, &'static str); 8] = [
        // One block
        (cbc::Type::AES_128_RAW,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "3a44bd0d547d82235effd2da38dbafc3"),
        (cbc::Type::AES_128_PADDED,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1",
         "b0dfa61dc8f7fd500d03899d875bbd2a"),
        (cbc::Type::AES_256_RAW,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1bff4b8c3",
         "7b9a09eabe4bd9eef5fb8af84c7ee8dd"),
        (cbc::Type::AES_256_PADDED,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "d47b00a342faacdb9d7655c1",
         "53fe2c0e77d663c454ffd9d3c53e2632"),
        // Two blocks
        (cbc::Type::AES_128_RAW,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "698d24fa0a2fd282a3b724aafb8a1f547141be417fb40de785304c58452e713a"),
        (cbc::Type::AES_128_PADDED,
         "99a5758d22880b01a4922f094dafceaa",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "698d24fa0a2fd282a3b724aafb8a1f5484046b796f05238ef8a6b551ab5fba66"),
        (cbc::Type::AES_256_RAW,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1bff4b8c3",
         "19a066de723ca454666290f8e8147a6d98288504b7ec8b80f3699954d1d930ff"),
        (cbc::Type::AES_256_PADDED,
         "16bd7e90a390f53e11cfe51c6c44cefbd6bcd87e1b1925fdc679edc21985f0de",
         "4002ddc1cd72650c32b895b026a3bda4",
         "707071c411335f0acfc5aea1698eaf2bd47b00a342faacdb9d7655c1",
         "19a066de723ca454666290f8e8147a6ddde9fb1e6dbb8a52b5b09b24e228bc2d"),
    ];

    #[test]
    fn test_ecb_apply() {
        let mut n = 0;
        for item in ECB_VEC.iter() {
            let (ty, key, pt, ct) = unpack3(item);

            let mut res_ct: Vec<u8> = repeat(0).take(pt.len() + super::MAX_BLOCK_LEN).collect();
            let mut c = ECB::new_encrypt(ty, &*key);
            c.start();
            let len = c.apply(&*pt, &mut *res_ct);
            let len2 = c.finish(&mut res_ct[len..]);
            res_ct.truncate(len + len2);
            assert!(ct == res_ct, "{:?} encrypt #{}", ty, n);

            let mut res_pt: Vec<u8> = repeat(0).take(res_ct.len() + super::MAX_BLOCK_LEN).collect();
            let mut d = ECB::new_decrypt(ty, &*key);
            d.start();
            let len = d.apply(&*res_ct, &mut *res_pt);
            let len2 = d.finish(&mut res_pt[len..]);
            res_pt.truncate(len + len2);
            assert!(pt == res_pt, "{:?} decrypt #{}", ty, n);

            n += 1;
        }
    }

    #[test]
    fn test_ecb_writer() {
        let mut n = 0;
        for item in ECB_VEC.iter() {
            let (ty, key, pt, ct) = unpack3(item);

            let mut res_ct = Vec::new();
            let mut c = ECB::new_encrypt(ty, &*key);
            {
                let mut w = c.start_writer(&mut res_ct);
                for byte in pt.iter() {
                    let _ = w.write_all(&[*byte]);
                }
            }
            assert!(ct == res_ct, "{:?} encrypt #{}", ty, n);

            let mut res_pt = Vec::new();
            let mut d = ECB::new_decrypt(ty, &*key);
            {
                let mut w = d.start_writer(&mut res_pt);
                for byte in res_ct.iter() {
                    let _ = w.write_all(&[*byte]);
                }
            }
            assert!(pt == res_pt, "{:?} decrypt #{}", ty, n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_apply() {
        let mut n = 0;
        for item in CBC_VEC.iter() {
            let (ty, key, iv, pt, ct) = unpack4(item);

            let mut res_ct: Vec<u8> = repeat(0).take(pt.len() + super::MAX_BLOCK_LEN).collect();
            let mut c = CBC::new_encrypt(ty, &*key);
            c.start(&*iv);
            let len = c.apply(&*pt, &mut *res_ct);
            let len2 = c.finish(&mut res_ct[len..]);
            res_ct.truncate(len + len2);
            assert!(ct == res_ct, "{:?} encrypt #{}", ty, n);

            let mut res_pt: Vec<u8> = repeat(0).take(res_ct.len() + super::MAX_BLOCK_LEN).collect();
            let mut d = CBC::new_decrypt(ty, &*key);
            d.start(&*iv);
            let len = d.apply(&*res_ct, &mut *res_pt);
            let len2 = d.finish(&mut res_pt[len..]);
            res_pt.truncate(len + len2);
            assert!(pt == res_pt, "{:?} decrypt #{}", ty, n);

            n += 1;
        }
    }

    #[test]
    fn test_cbc_writer() {
        let mut n = 0;
        for item in CBC_VEC.iter() {
            let (ty, key, iv, pt, ct) = unpack4(item);

            let mut res_ct = Vec::new();
            let mut c = CBC::new_encrypt(ty, &*key);
            {
                let mut w = c.start_writer(&*iv, &mut res_ct);
                for byte in pt.iter() {
                    let _ = w.write_all(&[*byte]);
                }
            }
            assert!(ct == res_ct, "{:?} encrypt #{}", ty, n);

            let mut res_pt = Vec::new();
            let mut d = CBC::new_decrypt(ty, &*key);
            {
                let mut w = d.start_writer(&*iv, &mut res_pt);
                for byte in res_ct.iter() {
                    let _ = w.write_all(&[*byte]);
                }
            }
            assert!(pt == res_pt, "{:?} decrypt #{}", ty, n);

            n += 1;
        }
    }
}
