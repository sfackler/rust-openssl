use std::ptr;

use libc::c_int;

use error::ErrorStack;
use ffi;
use hash::MessageDigest;
use {cvt, cvt_p};

pub struct Hkdf(*mut ffi::EVP_PKEY_CTX);

pub enum Mode {
    ExtractAndExpand,
    ExtractOnly,
    ExpandOnly,
}

unsafe impl Send for Hkdf {}

impl Hkdf {
    pub fn new(hash: MessageDigest) -> Result<Self, ErrorStack> {
        unsafe {
            let ret = cvt_p(ffi::EVP_PKEY_CTX_new_id(
                ffi::EVP_PKEY_HKDF,
                ptr::null_mut(),
            ))
            .map(Hkdf)
            .and_then(|ctx| cvt(ffi::EVP_PKEY_derive_init(ctx.0)).map(|_| ctx))?;

            cvt(ffi::EVP_PKEY_CTX_set_hkdf_md(ret.0, hash.as_ptr()))?;

            Ok(ret)
        }
    }

    pub fn set_mode(self, mode: Mode) -> Result<Self, ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_hkdf_mode(
                self.0,
                match mode {
                    Mode::ExtractAndExpand => ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
                    Mode::ExtractOnly => ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
                    Mode::ExpandOnly => ffi::EVP_PKEY_HKDEF_MODE_EXPAND_ONLY,
                },
            ))?;
        }

        Ok(self)
    }

    pub fn set_secret(self, secret: &[u8]) -> Result<Self, ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_key(
                self.0,
                secret.as_ptr() as *const _,
                secret.len() as c_int,
            ))?;
        }

        Ok(self)
    }

    pub fn set_salt(self, salt: Option<&[u8]>) -> Result<Self, ErrorStack> {
        let (ptr, len) = match salt {
            Some(salt) => (salt.as_ptr() as *const _, salt.len()),
            None => (ptr::null(), 0),
        };

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_salt(self.0, ptr, len as c_int))?;
        }

        Ok(self)
    }

    pub fn set_info(self, info: Option<&[u8]>) -> Result<Self, ErrorStack> {
        let (ptr, len) = match info {
            Some(info) => (info.as_ptr() as *const _, info.len()),
            None => (ptr::null(), 0),
        };

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_add1_hkdf_info(self.0, ptr, len as c_int))?;
        }

        Ok(self)
    }

    pub fn derive(&mut self, mut key_len: usize) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = Vec::new();
        buf.resize(key_len, 0);

        unsafe {
            cvt(ffi::EVP_PKEY_derive(self.0, buf.as_mut_ptr(), &mut key_len))?;
        }

        buf.truncate(key_len);

        Ok(buf)
    }
}

impl Drop for Hkdf {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.0);
        }
    }
}
