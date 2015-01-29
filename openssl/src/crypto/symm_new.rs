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

struct Context {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    state: State,
}

const MAX_BLOCK_LEN: usize = 16;
const DEFAULT_BUF_LEN: usize = 16384;

trait Type {
    fn key_len(&self) -> usize;
    fn padding(&self) -> bool;
}

trait EVPC {
    fn evpc(&self) -> *const ffi::EVP_CIPHER;
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
        assert!(self.state == Finalized);
        unsafe {
            chk!(ffi::EVP_CipherInit_ex(self.ctx, 0 as *const _, 0 as *const _,
                                        0 as *const _, 0 as *const _, -1));
        }
        self.state = Reset;
    }

    /*
    unsafe fn init_with_iv(&mut self, iv: &[u8]) {
        assert!(self.state == Finalized);
        unsafe {
            chk!(ffi::EVP_CipherInit_ex(self.ctx, 0 as *const _, 0 as *const _,
                                        0 as *const _, iv.as_ptr(), -1));
        }
        self.state = Reset;
    }
    */

    unsafe fn update(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
        assert!(self.state != Finalized);
        let len = unsafe {
            let mut l = 0;
            chk!(ffi::EVP_CipherUpdate(self.ctx, buf.as_mut_ptr(), &mut l,
                                       data.as_ptr(), data.len() as c_int));
            l as usize
        };
        assert!(len <= buf.len());
        self.state = Updated;
        len
    }

    fn checked_update(&mut self, data: &[u8], buf: &mut [u8], block_len: usize) -> usize {
        assert!(buf.len() >= data.len() + block_len);
        unsafe { self.update(data, buf) }
    }

    unsafe fn finalize(&mut self, buf: &mut [u8]) -> usize {
        assert!(self.state != Finalized);
        let len = unsafe {
            let mut l = 0;
            chk!(ffi::EVP_CipherFinal_ex(self.ctx, buf.as_mut_ptr(), &mut l));
            l as usize
        };
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

#[allow(non_camel_case_types)]
#[derive(Copy)]
pub enum ECBType {
    AES_128_PADDED,
    AES_256_PADDED,
    AES_128_RAW,
    AES_256_RAW,
}

impl Type for ECBType {
    fn key_len(&self) -> usize {
        use self::ECBType::*;
        match *self {
            AES_128_PADDED | AES_128_RAW => 16,
            AES_256_PADDED | AES_256_RAW => 32,
        }
    }

    fn padding(&self) -> bool {
        use self::ECBType::*;
        match *self {
            AES_128_PADDED | AES_256_PADDED => true,
            AES_128_RAW | AES_256_RAW => false,
        }
    }
}

impl EVPC for ECBType {
    fn evpc(&self) -> *const ffi::EVP_CIPHER {
        use self::ECBType::*;
        unsafe {
            match *self {
                AES_128_PADDED | AES_128_RAW => ffi::EVP_aes_128_ecb(),
                AES_256_PADDED | AES_256_RAW => ffi::EVP_aes_256_ecb(),
            }
        }
    }
}

pub struct ECB<'a> {
    context: Context,
    sink: Option<&'a mut (Writer + 'a)>,
}

impl <'a> ECB<'a> {
    pub fn new_encrypt(ty: ECBType, key: &[u8]) -> ECB<'a> {
        let mut c = Context::new(ty.evpc(), Direction::Encrypt, key);
        c.set_padding(ty.padding());
        ECB { context: c, sink: None }
    }

    pub fn start(&mut self, sink: &'a mut (Writer + 'a)) {
        if self.context.state != Finalized {
            self.finish();
        }
        self.sink = Some(sink);
        self.context.init();
    }

    pub fn finish(&mut self) {
        assert!(self.context.state != Finalized);
        let mut sink = self.sink.as_mut().expect("start() never called");
        let mut buf = [0; MAX_BLOCK_LEN];
        let len = self.context.checked_finalize(&mut buf, MAX_BLOCK_LEN);
        if len > 0 {
            let _ = sink.write_all(&buf[..len]);
        }
    }
}

impl <'a> Writer for ECB<'a> {
    fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        if self.context.state == Finalized {
            self.context.init();
        }
        let mut sink = self.sink.as_mut().expect("start() never called");
        let mut buf = [0; DEFAULT_BUF_LEN + MAX_BLOCK_LEN];
        for chunk in data.chunks(DEFAULT_BUF_LEN) {
            let len = self.context.checked_update(chunk, &mut buf, MAX_BLOCK_LEN);
            if len > 0 {
                let _ = sink.write_all(&buf[..len]);
            }
        }
        Ok(())
    }
}

    #[test]
    fn test_symm_new_aes_256_ecb() {
        let k0 =
           vec!(0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8,
              0x08u8, 0x09u8, 0x0au8, 0x0bu8, 0x0cu8, 0x0du8, 0x0eu8, 0x0fu8,
              0x10u8, 0x11u8, 0x12u8, 0x13u8, 0x14u8, 0x15u8, 0x16u8, 0x17u8,
              0x18u8, 0x19u8, 0x1au8, 0x1bu8, 0x1cu8, 0x1du8, 0x1eu8, 0x1fu8);
        let p0 =
           vec!(0x00u8, 0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8,
              0x88u8, 0x99u8, 0xaau8, 0xbbu8, 0xccu8, 0xddu8, 0xeeu8, 0xffu8);
        let c0 =
           vec!(0x8eu8, 0xa2u8, 0xb7u8, 0xcau8, 0x51u8, 0x67u8, 0x45u8, 0xbfu8,
              0xeau8, 0xfcu8, 0x49u8, 0x90u8, 0x4bu8, 0x49u8, 0x60u8, 0x89u8);

        let mut r0 = Vec::new();
        {
            let mut c = ECB::new_encrypt(ECBType::AES_256_RAW, &*k0);
            c.start(&mut r0);
            let _ = ::std::old_io::util::copy(&mut &*p0, &mut c);
            c.finish();
        }
        assert!(r0 == c0);
    }
