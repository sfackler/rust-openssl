use libc::{c_void, c_char, c_int, size_t};
use std::ptr;
use std::mem;
use std::ffi::CString;
use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};

use {cvt, cvt_p};
use bio::MemBioSlice;
use dh::Dh;
use dsa::Dsa;
use ec::EcKey;
use rsa::{Rsa, Padding};
use error::ErrorStack;
use util::{CallbackState, invoke_passwd_cb, invoke_passwd_cb_old};

foreign_type! {
    type CType = ffi::EVP_PKEY;
    fn drop = ffi::EVP_PKEY_free;

    pub struct PKey;
    pub struct PKeyRef;
}

impl PKeyRef {
    /// Returns a copy of the internal RSA key.
    pub fn rsa(&self) -> Result<Rsa, ErrorStack> {
        unsafe {
            let rsa = try!(cvt_p(ffi::EVP_PKEY_get1_RSA(self.as_ptr())));
            Ok(Rsa::from_ptr(rsa))
        }
    }

    /// Returns a copy of the internal DSA key.
    pub fn dsa(&self) -> Result<Dsa, ErrorStack> {
        unsafe {
            let dsa = try!(cvt_p(ffi::EVP_PKEY_get1_DSA(self.as_ptr())));
            Ok(Dsa::from_ptr(dsa))
        }
    }

    /// Returns a copy of the internal DH key.
    pub fn dh(&self) -> Result<Dh, ErrorStack> {
        unsafe {
            let dh = try!(cvt_p(ffi::EVP_PKEY_get1_DH(self.as_ptr())));
            Ok(Dh::from_ptr(dh))
        }
    }

    /// Returns a copy of the internal elliptic curve key.
    pub fn ec_key(&self) -> Result<EcKey, ErrorStack> {
        unsafe {
            let ec_key = try!(cvt_p(ffi::EVP_PKEY_get1_EC_KEY(self.as_ptr())));
            Ok(EcKey::from_ptr(ec_key))
        }
    }

    public_key_to_pem!(ffi::PEM_write_bio_PUBKEY);
    private_key_to_pem!(ffi::PEM_write_bio_PKCS8PrivateKey);

    private_key_to_der!(ffi::i2d_PrivateKey);
    public_key_to_der!(ffi::i2d_PUBKEY);

    /// Returns the size of the key.
    ///
    /// This corresponds to the bit length of the modulus of an RSA key, and the bit length of the
    /// group order for an elliptic curve key, for example.
    pub fn bits(&self) -> u32 {
        unsafe { ffi::EVP_PKEY_bits(self.as_ptr()) as u32 }
    }

    /// Compares the public component of this key with another.
    pub fn public_eq(&self, other: &PKeyRef) -> bool {
        unsafe { ffi::EVP_PKEY_cmp(self.as_ptr(), other.as_ptr()) == 1 }
    }
}

unsafe impl Send for PKey {}
unsafe impl Sync for PKey {}

impl PKey {
    /// Creates a new `PKey` containing an RSA key.
    pub fn from_rsa(rsa: Rsa) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try!(cvt_p(ffi::EVP_PKEY_new()));
            let pkey = PKey(evp);
            try!(cvt(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_RSA, rsa.as_ptr() as *mut _)));
            mem::forget(rsa);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing a DSA key.
    pub fn from_dsa(dsa: Dsa) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try!(cvt_p(ffi::EVP_PKEY_new()));
            let pkey = PKey(evp);
            try!(cvt(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_DSA, dsa.as_ptr() as *mut _)));
            mem::forget(dsa);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing a Diffie-Hellman key.
    pub fn from_dh(dh: Dh) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try!(cvt_p(ffi::EVP_PKEY_new()));
            let pkey = PKey(evp);
            try!(cvt(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_DH, dh.as_ptr() as *mut _)));
            mem::forget(dh);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing an elliptic curve key.
    pub fn from_ec_key(ec_key: EcKey) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try!(cvt_p(ffi::EVP_PKEY_new()));
            let pkey = PKey(evp);
            try!(cvt(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_EC, ec_key.as_ptr() as *mut _)));
            mem::forget(ec_key);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing an HMAC key.
    ///
    /// # Note
    /// To compute HMAC values, use the `sign` module.
    pub fn hmac(key: &[u8]) -> Result<PKey, ErrorStack> {
        unsafe {
            assert!(key.len() <= c_int::max_value() as usize);
            let key = try!(cvt_p(ffi::EVP_PKEY_new_mac_key(ffi::EVP_PKEY_HMAC,
                                                           ptr::null_mut(),
                                                           key.as_ptr() as *const _,
                                                           key.len() as c_int)));
            Ok(PKey(key))
        }
    }

    private_key_from_pem!(PKey, ffi::PEM_read_bio_PrivateKey);
    public_key_from_pem!(PKey, ffi::PEM_read_bio_PUBKEY);
    public_key_from_der!(PKey, ffi::d2i_PUBKEY);

    /// Deserializes a DER-formatted PKCS#8 private key, using a callback to retrieve the password
    /// if the key is encrpyted.
    ///
    /// The callback should copy the password into the provided buffer and return the number of
    /// bytes written.
    pub fn private_key_from_pkcs8_callback<F>(der: &[u8], callback: F) -> Result<PKey, ErrorStack>
        where F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>
    {
        unsafe {
            ffi::init();
            let mut cb = CallbackState::new(callback);
            let bio = try!(MemBioSlice::new(der));
            cvt_p(ffi::d2i_PKCS8PrivateKey_bio(bio.as_ptr(),
                                               ptr::null_mut(),
                                               Some(invoke_passwd_cb::<F>),
                                               &mut cb as *mut _ as *mut _))
                .map(PKey)
        }
    }

    /// Deserializes a DER-formatted PKCS#8 private key, using the supplied password if the key is
    /// encrypted.
    ///
    /// # Panics
    ///
    /// Panics if `passphrase` contains an embedded null.
    pub fn private_key_from_pkcs8_passphrase(der: &[u8],
                                             passphrase: &[u8])
                                             -> Result<PKey, ErrorStack> {
        unsafe {
            ffi::init();
            let bio = try!(MemBioSlice::new(der));
            let passphrase = CString::new(passphrase).unwrap();
            cvt_p(ffi::d2i_PKCS8PrivateKey_bio(bio.as_ptr(),
                                               ptr::null_mut(),
                                               None,
                                               passphrase.as_ptr() as *const _ as *mut _))
                .map(PKey)
        }
    }

    #[deprecated(since = "0.9.2", note = "use private_key_from_pem_callback")]
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<PKey, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        ffi::init();
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let evp = try!(cvt_p(ffi::PEM_read_bio_PrivateKey(mem_bio.as_ptr(),
                                                              ptr::null_mut(),
                                                              Some(invoke_passwd_cb_old::<F>),
                                                              &mut cb as *mut _ as *mut c_void)));
            Ok(PKey::from_ptr(evp))
        }
    }
}

foreign_type! {
    type CType = ffi::EVP_PKEY_CTX;
    fn drop = ffi::EVP_PKEY_CTX_free;

    pub struct PKeyCtx;
    pub struct PKeyCtxRef;
}

unsafe impl Send for PKeyCtx {}
unsafe impl Sync for PKeyCtx {}

impl PKeyCtx {
    pub fn from_pkey(pkey: &PKeyRef) -> Result<PKeyCtx, ErrorStack> {
        unsafe {
            let evp = try!(cvt_p(ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut())));
            Ok(PKeyCtx(evp))
        }
    }
}

impl PKeyCtxRef {
    pub fn set_rsa_padding(&mut self, pad: Padding) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(self.as_ptr(), pad.as_raw())));
        }
        Ok(())
    }

    pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
        let mut pad: c_int = 0;
        unsafe {
            try!(cvt(ffi::EVP_PKEY_CTX_get_rsa_padding(self.as_ptr(), &mut pad)));
        };
        Ok(Padding::from_raw(pad))
    }

    pub fn derive_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(ffi::EVP_PKEY_derive_init(self.as_ptr())));
        }
        Ok(())
    }

    pub fn derive_set_peer(&mut self, peer: &PKeyRef) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(ffi::EVP_PKEY_derive_set_peer(self.as_ptr(), peer.as_ptr())));
        }
        Ok(())
    }

    pub fn derive(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut len: size_t = 0;
        unsafe { try!(cvt(ffi::EVP_PKEY_derive(self.as_ptr(), ptr::null_mut(), &mut len))); }

        let mut key = vec![0u8; len];
        unsafe { try!(cvt(ffi::EVP_PKEY_derive(self.as_ptr(), key.as_mut_ptr(), &mut len))); }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use symm::Cipher;
    use dh::Dh;
    use dsa::Dsa;
    use ec::{EcGroup, EcKey};
    use rsa::Rsa;
    use nid;

    use super::*;

    #[test]
    fn test_to_password() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pem = pkey.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar").unwrap();
        PKey::private_key_from_pem_passphrase(&pem, b"foobar").unwrap();
        assert!(PKey::private_key_from_pem_passphrase(&pem, b"fizzbuzz").is_err());
    }

    #[test]
    fn test_encrypted_pkcs8_passphrase() {
        let key = include_bytes!("../test/pkcs8.der");
        PKey::private_key_from_pkcs8_passphrase(key, b"mypass").unwrap();
    }

    #[test]
    fn test_encrypted_pkcs8_callback() {
        let mut password_queried = false;
        let key = include_bytes!("../test/pkcs8.der");
        PKey::private_key_from_pkcs8_callback(key, |password| {
                password_queried = true;
                password[..6].copy_from_slice(b"mypass");
                Ok(6)
            })
            .unwrap();
        assert!(password_queried);
    }

    #[test]
    fn test_private_key_from_pem() {
        let key = include_bytes!("../test/key.pem");
        PKey::private_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_public_key_from_pem() {
        let key = include_bytes!("../test/key.pem.pub");
        PKey::public_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_public_key_from_der() {
        let key = include_bytes!("../test/key.der.pub");
        PKey::public_key_from_der(key).unwrap();
    }

    #[test]
    fn test_pem() {
        let key = include_bytes!("../test/key.pem");
        let key = PKey::private_key_from_pem(key).unwrap();

        let priv_key = key.private_key_to_pem().unwrap();
        let pub_key = key.public_key_to_pem().unwrap();

        // As a super-simple verification, just check that the buffers contain
        // the `PRIVATE KEY` or `PUBLIC KEY` strings.
        assert!(priv_key.windows(11).any(|s| s == b"PRIVATE KEY"));
        assert!(pub_key.windows(10).any(|s| s == b"PUBLIC KEY"));
    }

    #[test]
    fn test_rsa_accessor() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        pkey.rsa().unwrap();
        assert!(pkey.dsa().is_err());
    }

    #[test]
    fn test_dsa_accessor() {
        let dsa = Dsa::generate(2048).unwrap();
        let pkey = PKey::from_dsa(dsa).unwrap();
        pkey.dsa().unwrap();
        assert!(pkey.rsa().is_err());
    }

    #[test]
    fn test_dh_accessor() {
        let dh = include_bytes!("../test/dhparams.pem");
        let dh = Dh::from_pem(dh).unwrap();
        let pkey = PKey::from_dh(dh).unwrap();
        pkey.dh().unwrap();
        assert!(pkey.rsa().is_err());
    }

    #[test]
    fn test_ec_key_accessor() {
        let ec_key = EcKey::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        pkey.ec_key().unwrap();
        assert!(pkey.rsa().is_err());
    }

    #[test]
    fn test_ec_key_derive() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let ec_key2 = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let pkey2 = PKey::from_ec_key(ec_key2).unwrap();
        let mut pkey_ctx = PKeyCtx::from_pkey(&pkey).unwrap();
        pkey_ctx.derive_init().unwrap();
        pkey_ctx.derive_set_peer(&pkey2).unwrap();
        let shared = pkey_ctx.derive().unwrap();
        assert!(!shared.is_empty());
    }
}
