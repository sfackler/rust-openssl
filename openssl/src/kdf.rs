use std::error;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::ptr;
use std::str;

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::params::{Params, ParamsBuilder};
use crate::{cvt, cvt_cp, cvt_p};

#[derive(Debug)]
pub enum KDFError {
    Utf8Error(str::Utf8Error),
    NulError(NulError),
    NoSuchKDF,
    SSL(ErrorStack),
}

impl From<str::Utf8Error> for KDFError {
    fn from(e: str::Utf8Error) -> Self {
        KDFError::Utf8Error(e)
    }
}

impl From<NulError> for KDFError {
    fn from(e: NulError) -> Self {
        KDFError::NulError(e)
    }
}

impl From<ErrorStack> for KDFError {
    fn from(e: ErrorStack) -> Self {
        KDFError::SSL(e)
    }
}

impl fmt::Display for KDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use KDFError::*;
        match self {
            Utf8Error(ref e) => e.fmt(f),
            NulError(ref e) => e.fmt(f),
            NoSuchKDF => write!(f, "No such KDF"),
            SSL(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for KDFError {}

pub trait KDFParams {
    fn kdf_name(&self) -> String;
    fn to_params(&self) -> Result<Params, KDFError>;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    Counter,
    Feedback,
}

const COUNTER: &'static [u8] = b"counter\0";
const FEEDBACK: &'static [u8] = b"feedback\0";

impl Mode {
    fn to_param(&self) -> &'static [u8] {
        use Mode::*;
        match self {
            Counter => COUNTER,
            Feedback => FEEDBACK,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Mac {
    Hmac,
    Cmac,
}

const HMAC: &'static [u8] = b"HMAC\0";
const CMAC: &'static [u8] = b"CMAC\0";

impl Mac {
    fn to_param(&self) -> &'static [u8] {
        use Mac::*;
        match self {
            Hmac => HMAC,
            Cmac => CMAC,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct KBKDF {
    md: MessageDigest,
    mode: Mode,
    mac: Mac,
    salt: Vec<u8>,
    key: Vec<u8>,
    context: Vec<u8>,
    use_l: bool,
    use_separator: bool,
}

impl KBKDF {
    pub fn new(md: MessageDigest, salt: Vec<u8>, key: Vec<u8>) -> KBKDF {
        let mode = Mode::Counter;
        let mac = Mac::Hmac;
        let use_l = true;
        let use_separator = true;
        let context = Vec::new();

        KBKDF {
            md,
            salt,
            key,
            mode,
            context,
            mac,
            use_l,
            use_separator,
        }
    }

    pub fn set_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn set_mac(mut self, mac: Mac) -> Self {
        self.mac = mac;
        self
    }

    pub fn set_context(mut self, context: Vec<u8>) -> Self {
        self.context = context;
        self
    }

    pub fn set_l(mut self, l: bool) -> Self {
        self.use_l = l;
        self
    }

    pub fn set_separator(mut self, separator: bool) -> Self {
        self.use_separator = separator;
        self
    }
}

impl KDFParams for KBKDF {
    fn kdf_name(&self) -> String {
        String::from("KBKDF")
    }

    fn to_params(&self) -> Result<Params, KDFError> {
        let mut params = ParamsBuilder::with_capacity(8);
        let md_name = unsafe { cvt_cp(ffi::EVP_MD_name(self.md.as_ptr())) }?;
        let md_name = unsafe { CStr::from_ptr(md_name) }.to_bytes();

        params.add_string(ffi::OSSL_KDF_PARAM_DIGEST, md_name)?;
        params.add_string(ffi::OSSL_KDF_PARAM_MAC, self.mac.to_param())?;
        params.add_string(ffi::OSSL_KDF_PARAM_MODE, self.mode.to_param())?;
        params.add_slice(ffi::OSSL_KDF_PARAM_KEY, &self.key)?;
        params.add_slice(ffi::OSSL_KDF_PARAM_SALT, &self.salt)?;
        if self.context.len() > 0 {
            params.add_slice(ffi::OSSL_KDF_PARAM_INFO, &self.context)?;
        }
        if self.use_l {
            params.add_i32(ffi::OSSL_KDF_PARAM_KBKDF_USE_L, 1)?;
        } else {
            params.add_i32(ffi::OSSL_KDF_PARAM_KBKDF_USE_L, 0)?;
        }

        if self.use_separator {
            params.add_i32(ffi::OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, 1)?;
        } else {
            params.add_i32(ffi::OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, 0)?;
        }

        Ok(params.build())
    }
}

pub fn derive<P: KDFParams>(kdf: P, output: &mut [u8]) -> Result<(), KDFError> {
    ffi::init();

    let name = kdf.kdf_name();
    let name = CString::new(name.as_bytes())?;
    let name = name.as_bytes_with_nul();

    let kdf_ptr = unsafe {
        let ptr = ffi::EVP_KDF_fetch(ptr::null_mut(), name.as_ptr() as *const i8, ptr::null());
        if ptr.is_null() {
            Err(KDFError::NoSuchKDF)
        } else {
            Ok(ptr)
        }
    }?;

    let mut ctx = KDFContext::new(kdf_ptr)?;
    let mut params = kdf.to_params()?;
    unsafe {
        cvt(ffi::EVP_KDF_CTX_set_params(
            ctx.as_mut_ptr(),
            params.as_mut_ptr(),
        ))?
    };

    // TODO: Check EVP_KDF_CTX_get_kdf_size ?

    unsafe {
        cvt(ffi::EVP_KDF_derive(
            ctx.as_mut_ptr(),
            output.as_mut_ptr(),
            output.len(),
        ))?
    };

    Ok(())
}

struct KDFContext(*mut ffi::EVP_KDF_CTX);

impl KDFContext {
    fn new(kdf: *mut ffi::EVP_KDF) -> Result<Self, ErrorStack> {
        let ctx = unsafe { cvt_p(ffi::EVP_KDF_CTX_new(kdf))? };
        Ok(KDFContext(ctx))
    }
}

impl KDFContext {
    fn as_mut_ptr(&mut self) -> *mut ffi::EVP_KDF_CTX {
        self.0
    }
}

impl Drop for KDFContext {
    fn drop(&mut self) {
        unsafe { ffi::EVP_KDF_CTX_free(self.0) };
    }
}

#[cfg(test)]
mod tests {}
