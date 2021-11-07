use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, PKey, PKeyRef};
use crate::symm::{Cipher, Mode};
use crate::{cvt, cvt_p};
use cfg_if::cfg_if;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::convert::TryFrom;
use std::ptr;

cfg_if! {
    if #[cfg(ossl300)] {
        use ffi::EVP_CIPHER_CTX_get0_cipher;
    } else {
        use ffi::EVP_CIPHER_CTX_cipher as EVP_CIPHER_CTX_get0_cipher;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_CIPHER_CTX;
    fn drop = ffi::EVP_CIPHER_CTX_free;

    pub struct CipherCtx;
    pub struct CipherCtxRef;
}

impl CipherCtx {
    pub fn new() -> Result<Self, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            Ok(CipherCtx::from_ptr(ptr))
        }
    }
}

impl CipherCtxRef {
    pub fn cipher_init(
        &mut self,
        // FIXME CipherRef
        type_: Option<&Cipher>,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        mode: Mode,
    ) -> Result<(), ErrorStack> {
        if let Some(key) = key {
            if let Some(len) = self.key_length() {
                assert_eq!(len, key.len());
            }
        }

        if let Some(iv) = iv {
            if let Some(len) = self.iv_length() {
                assert_eq!(len, iv.len());
            }
        }

        let mode = match mode {
            Mode::Encrypt => 1,
            Mode::Decrypt => 0,
        };

        unsafe {
            cvt(ffi::EVP_CipherInit_ex(
                self.as_ptr(),
                type_.map_or(ptr::null(), Cipher::as_ptr),
                ptr::null_mut(),
                key.map_or(ptr::null(), |k| k.as_ptr()),
                iv.map_or(ptr::null(), |iv| iv.as_ptr()),
                mode,
            ))?;
        }

        Ok(())
    }

    pub fn seal_init<T>(
        &mut self,
        // FIXME CipherRef
        type_: Option<&Cipher>,
        pub_keys: &[PKey<T>],
        encrypted_keys: &mut [Vec<u8>],
        iv: Option<&mut [u8]>,
    ) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        assert_eq!(pub_keys.len(), encrypted_keys.len());
        let iv_len = type_.map_or_else(|| self.iv_length(), |c| c.iv_len());
        if let Some(iv_len) = iv_len {
            assert!(iv.as_ref().map_or(0, |b| b.len()) >= iv_len);
        }

        for (pub_key, buf) in pub_keys.iter().zip(&mut *encrypted_keys) {
            buf.resize(pub_key.size(), 0);
        }

        let mut keys = encrypted_keys
            .iter_mut()
            .map(|b| b.as_mut_ptr())
            .collect::<Vec<_>>();
        let mut key_lengths = vec![0; pub_keys.len()];
        let pub_keys_len = i32::try_from(pub_keys.len()).unwrap();

        unsafe {
            cvt(ffi::EVP_SealInit(
                self.as_ptr(),
                type_.map_or(ptr::null(), Cipher::as_ptr),
                keys.as_mut_ptr(),
                key_lengths.as_mut_ptr(),
                iv.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                pub_keys.as_ptr() as *mut _,
                pub_keys_len,
            ))?;
        }

        for (buf, len) in encrypted_keys.iter_mut().zip(key_lengths) {
            buf.truncate(len as usize);
        }

        Ok(())
    }

    pub fn open_init<T>(
        &mut self,
        type_: Option<&Cipher>,
        encrypted_key: &[u8],
        iv: Option<&[u8]>,
        priv_key: Option<&PKeyRef<T>>,
    ) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        let iv_len = type_.map_or_else(|| self.iv_length(), |c| c.iv_len());
        if let Some(iv_len) = iv_len {
            assert!(iv.map_or(0, |b| b.len()) >= iv_len);
        }

        let len = c_int::try_from(encrypted_key.len()).unwrap();
        unsafe {
            cvt(ffi::EVP_OpenInit(
                self.as_ptr(),
                type_.map_or(ptr::null(), Cipher::as_ptr),
                encrypted_key.as_ptr(),
                len,
                iv.map_or(ptr::null(), |b| b.as_ptr()),
                priv_key.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
            ))?;
        }

        Ok(())
    }

    fn assert_cipher(&self) {
        unsafe {
            assert!(!EVP_CIPHER_CTX_get0_cipher(self.as_ptr()).is_null());
        }
    }

    pub fn block_size(&self) -> Option<usize> {
        self.assert_cipher();

        unsafe {
            let r = ffi::EVP_CIPHER_CTX_block_size(self.as_ptr());
            if r > 0 {
                Some(r as usize)
            } else {
                None
            }
        }
    }

    pub fn key_length(&self) -> Option<usize> {
        self.assert_cipher();

        unsafe {
            let r = ffi::EVP_CIPHER_CTX_key_length(self.as_ptr());
            if r > 0 {
                Some(r as usize)
            } else {
                None
            }
        }
    }

    pub fn set_key_length(&mut self, len: usize) -> Result<(), ErrorStack> {
        self.assert_cipher();

        let len = c_int::try_from(len).unwrap();

        unsafe {
            cvt(ffi::EVP_CIPHER_CTX_set_key_length(self.as_ptr(), len))?;
        }

        Ok(())
    }

    pub fn iv_length(&self) -> Option<usize> {
        self.assert_cipher();

        unsafe {
            let r = ffi::EVP_CIPHER_CTX_iv_length(self.as_ptr());
            if r > 0 {
                Some(r as usize)
            } else {
                None
            }
        }
    }

    pub fn set_iv_length(&mut self, len: usize) -> Result<(), ErrorStack> {
        self.assert_cipher();

        let len = c_int::try_from(len).unwrap();

        unsafe {
            cvt(ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                ffi::EVP_CTRL_GCM_SET_IVLEN,
                len,
                ptr::null_mut(),
            ))?;
        }

        Ok(())
    }

    pub fn tag_length(&self) -> Option<usize> {
        self.assert_cipher();

        unsafe {
            let r = ffi::EVP_CIPHER_CTX_tag_length(self.as_ptr());
            if r > 0 {
                Some(r as usize)
            } else {
                None
            }
        }
    }

    pub fn tag(&self, tag: &mut [u8]) -> Result<(), ErrorStack> {
        let len = c_int::try_from(tag.len()).unwrap();

        unsafe {
            cvt(ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                ffi::EVP_CTRL_GCM_GET_TAG,
                len,
                tag.as_mut_ptr() as *mut _,
            ))?;
        }

        Ok(())
    }

    pub fn set_tag_length(&mut self, len: usize) -> Result<(), ErrorStack> {
        let len = c_int::try_from(len).unwrap();

        unsafe {
            cvt(ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                ffi::EVP_CTRL_GCM_SET_TAG,
                len,
                ptr::null_mut(),
            ))?;
        }

        Ok(())
    }

    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), ErrorStack> {
        let len = c_int::try_from(tag.len()).unwrap();

        unsafe {
            cvt(ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                ffi::EVP_CTRL_GCM_SET_TAG,
                len,
                tag.as_ptr() as *mut _,
            ))?;
        }

        Ok(())
    }

    pub fn set_padding(&mut self, padding: bool) {
        unsafe {
            ffi::EVP_CIPHER_CTX_set_padding(self.as_ptr(), padding as c_int);
        }
    }

    pub fn set_data_len(&mut self, len: usize) -> Result<(), ErrorStack> {
        let len = c_int::try_from(len).unwrap();

        unsafe {
            cvt(ffi::EVP_CipherUpdate(
                self.as_ptr(),
                ptr::null_mut(),
                &mut 0,
                ptr::null(),
                len,
            ))?;
        }

        Ok(())
    }

    pub fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let inlen = c_int::try_from(input.len()).unwrap();

        if let (Some(mut block_size), Some(output)) = (self.block_size(), &output) {
            if block_size == 1 {
                block_size = 0;
            }
            assert!(output.len() >= input.len() + block_size);
        }

        let mut outlen = 0;
        unsafe {
            cvt(ffi::EVP_CipherUpdate(
                self.as_ptr(),
                output.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut outlen,
                input.as_ptr(),
                inlen,
            ))?;
        }

        Ok(outlen as usize)
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
        if let Some(block_size) = self.block_size() {
            if block_size > 1 {
                assert!(output.len() >= block_size);
            }
        }

        let mut outl = 0;
        unsafe {
            cvt(ffi::EVP_CipherFinal(
                self.as_ptr(),
                output.as_mut_ptr(),
                &mut outl,
            ))?;
        }

        Ok(outl as usize)
    }
}
