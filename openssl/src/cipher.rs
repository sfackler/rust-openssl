//! Symmetric ciphers.

use crate::nid::Nid;
use cfg_if::cfg_if;
use foreign_types::{ForeignTypeRef, Opaque};

cfg_if! {
    if #[cfg(any(ossl110, libressl273))] {
        use ffi::{EVP_CIPHER_block_size, EVP_CIPHER_iv_length, EVP_CIPHER_key_length};
    } else {
        use libc::c_int;

        #[allow(bad_style)]
        pub unsafe fn EVP_CIPHER_iv_length(ptr: *const ffi::EVP_CIPHER) -> c_int {
            (*ptr).iv_len
        }

        #[allow(bad_style)]
        pub unsafe fn EVP_CIPHER_block_size(ptr: *const ffi::EVP_CIPHER) -> c_int {
            (*ptr).block_size
        }

        #[allow(bad_style)]
        pub unsafe fn EVP_CIPHER_key_length(ptr: *const ffi::EVP_CIPHER) -> c_int {
            (*ptr).key_len
        }
    }
}

cfg_if! {
    if #[cfg(ossl300)] {
        use foreign_types::ForeignType;
        use std::ops::{Deref, DerefMut};

        type Inner = *mut ffi::EVP_CIPHER;

        impl Drop for Cipher {
            #[inline]
            fn drop(&mut self) {
                unsafe {
                    ffi::EVP_CIPHER_free(self.as_ptr());
                }
            }
        }

        impl ForeignType for Cipher {
            type CType = ffi::EVP_CIPHER;
            type Ref = CipherRef;

            #[inline]
            unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
                Cipher(ptr)
            }

            #[inline]
            fn as_ptr(&self) -> *mut Self::CType {
                self.0
            }
        }

        impl Deref for Cipher {
            type Target = CipherRef;

            #[inline]
            fn deref(&self) -> &Self::Target {
                unsafe {
                    CipherRef::from_ptr(self.as_ptr())
                }
            }
        }

        impl DerefMut for Cipher {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                unsafe {
                    CipherRef::from_ptr_mut(self.as_ptr())
                }
            }
        }
    } else {
        enum Inner {}
    }
}

/// A symmetric cipher.
pub struct Cipher(Inner);

unsafe impl Sync for Cipher {}
unsafe impl Send for Cipher {}

impl Cipher {
    /// Looks up the cipher for a certain nid.
    ///
    /// This corresponds to [`EVP_get_cipherbynid`]
    ///
    /// [`EVP_get_cipherbynid`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_get_cipherbyname.html
    pub fn from_nid(nid: Nid) -> Option<&'static CipherRef> {
        unsafe {
            let ptr = ffi::EVP_get_cipherbyname(ffi::OBJ_nid2sn(nid.as_raw()));
            if ptr.is_null() {
                None
            } else {
                Some(CipherRef::from_ptr(ptr as *mut _))
            }
        }
    }

    pub fn aes_128_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_ecb() as *mut _) }
    }

    pub fn aes_128_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_cbc() as *mut _) }
    }

    pub fn aes_128_xts() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_xts() as *mut _) }
    }

    pub fn aes_128_ctr() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_ctr() as *mut _) }
    }

    pub fn aes_128_cfb1() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_cfb1() as *mut _) }
    }

    pub fn aes_128_cfb128() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_cfb128() as *mut _) }
    }

    pub fn aes_128_cfb8() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_cfb8() as *mut _) }
    }

    pub fn aes_128_gcm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_gcm() as *mut _) }
    }

    pub fn aes_128_ccm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_ccm() as *mut _) }
    }

    pub fn aes_128_ofb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_ofb() as *mut _) }
    }

    /// Requires OpenSSL 1.1.0 or newer.
    #[cfg(ossl110)]
    pub fn aes_128_ocb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_128_ocb() as *mut _) }
    }

    pub fn aes_192_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_ecb() as *mut _) }
    }

    pub fn aes_192_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_cbc() as *mut _) }
    }

    pub fn aes_192_ctr() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_ctr() as *mut _) }
    }

    pub fn aes_192_cfb1() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_cfb1() as *mut _) }
    }

    pub fn aes_192_cfb128() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_cfb128() as *mut _) }
    }

    pub fn aes_192_cfb8() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_cfb8() as *mut _) }
    }

    pub fn aes_192_gcm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_gcm() as *mut _) }
    }

    pub fn aes_192_ccm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_ccm() as *mut _) }
    }

    pub fn aes_192_ofb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_ofb() as *mut _) }
    }

    /// Requires OpenSSL 1.1.0 or newer.
    #[cfg(ossl110)]
    pub fn aes_192_ocb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_192_ocb() as *mut _) }
    }

    pub fn aes_256_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_ecb() as *mut _) }
    }

    pub fn aes_256_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_cbc() as *mut _) }
    }

    pub fn aes_256_ctr() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_ctr() as *mut _) }
    }

    pub fn aes_256_cfb1() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_cfb1() as *mut _) }
    }

    pub fn aes_256_cfb128() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_cfb128() as *mut _) }
    }

    pub fn aes_256_cfb8() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_cfb8() as *mut _) }
    }

    pub fn aes_256_gcm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_gcm() as *mut _) }
    }

    pub fn aes_256_ccm() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_ccm() as *mut _) }
    }

    pub fn aes_256_ofb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_ofb() as *mut _) }
    }

    /// Requires OpenSSL 1.1.0 or newer.
    #[cfg(ossl110)]
    pub fn aes_256_ocb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_aes_256_ocb() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
    pub fn bf_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_bf_cbc() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
    pub fn bf_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_bf_ecb() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
    pub fn bf_cfb64() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_bf_cfb64() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
    pub fn bf_ofb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_bf_ofb() as *mut _) }
    }

    pub fn des_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_des_cbc() as *mut _) }
    }

    pub fn des_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_des_ecb() as *mut _) }
    }

    pub fn des_ede3() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_des_ede3() as *mut _) }
    }

    pub fn des_ede3_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_des_ede3_cbc() as *mut _) }
    }

    pub fn des_ede3_cfb64() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_des_ede3_cfb64() as *mut _) }
    }

    pub fn rc4() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_rc4() as *mut _) }
    }

    #[cfg(all(ossl110, not(osslconf = "OPENSSL_NO_CHACHA")))]
    pub fn chacha20() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_chacha20() as *mut _) }
    }

    #[cfg(all(ossl110, not(osslconf = "OPENSSL_NO_CHACHA")))]
    pub fn chacha20_poly1305() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_chacha20_poly1305() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn seed_cbc() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_seed_cbc() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn seed_cfb128() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_seed_cfb128() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn seed_ecb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_seed_ecb() as *mut _) }
    }

    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn seed_ofb() -> &'static CipherRef {
        unsafe { CipherRef::from_ptr(ffi::EVP_seed_ofb() as *mut _) }
    }
}

/// A reference to a [`Cipher`].
pub struct CipherRef(Opaque);

impl ForeignTypeRef for CipherRef {
    type CType = ffi::EVP_CIPHER;
}

unsafe impl Sync for CipherRef {}
unsafe impl Send for CipherRef {}

impl CipherRef {
    /// Returns the cipher's Nid.
    ///
    /// This corresponds to [`EVP_CIPHER_nid`]
    ///
    /// [`EVP_CIPHER_nid`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_CIPHER_nid.html
    pub fn nid(&self) -> Nid {
        let nid = unsafe { ffi::EVP_CIPHER_nid(self.as_ptr()) };
        Nid::from_raw(nid)
    }

    /// Returns the length of keys used with this cipher.
    pub fn key_length(&self) -> usize {
        unsafe { EVP_CIPHER_key_length(self.as_ptr()) as usize }
    }

    /// Returns the length of the IV used with this cipher.
    ///
    /// # Note
    ///
    /// Ciphers that do not use an IV have an IV length of 0.
    pub fn iv_length(&self) -> usize {
        unsafe { EVP_CIPHER_iv_length(self.as_ptr()) as usize }
    }

    /// Returns the block size of the cipher.
    ///
    /// # Note
    ///
    /// Stream ciphers have a block size of 1.
    pub fn block_size(&self) -> usize {
        unsafe { EVP_CIPHER_block_size(self.as_ptr()) as usize }
    }
}
