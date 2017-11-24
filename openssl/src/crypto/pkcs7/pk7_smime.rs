use x509::{X509, X509Ref};
use x509::store::X509Store;
use ffi;
use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use stack::Stack;
use foreign_types::ForeignType;
use symm::Cipher;
use pkey::PKeyRef;
use libc::c_int;
use std::ptr::null_mut;
use foreign_types::ForeignTypeRef;

pub struct PKCS7(*mut ffi::pkcs7_st);

bitflags! {
    pub struct PKCS7Flags: c_int {
        const PKCS7_TEXT = ffi::PKCS7_TEXT;
        const PKCS7_NOCERTS = ffi::PKCS7_NOCERTS;
        const PKCS7_NOSIGS = ffi::PKCS7_NOSIGS;
        const PKCS7_NOCHAIN = ffi::PKCS7_NOCHAIN;
        const PKCS7_NOINTERN = ffi::PKCS7_NOINTERN;
        const PKCS7_NOVERIFY = ffi::PKCS7_NOVERIFY;
        const PKCS7_DETACHED = ffi::PKCS7_DETACHED;
        const PKCS7_BINARY = ffi::PKCS7_BINARY;
        const PKCS7_NOATTR = ffi::PKCS7_NOATTR;
        const PKCS7_NOSMIMECAP = ffi::PKCS7_NOSMIMECAP;
        const PKCS7_NOOLDMIMETYPE = ffi::PKCS7_NOOLDMIMETYPE;
        const PKCS7_CRLFEOL = ffi::PKCS7_CRLFEOL;
        const PKCS7_STREAM = ffi::PKCS7_STREAM;
        const PKCS7_NOCRL = ffi::PKCS7_NOCRL;
        const PKCS7_PARTIAL = ffi::PKCS7_PARTIAL;
        const PKCS7_REUSE_DIGEST = ffi::PKCS7_REUSE_DIGEST;
        #[cfg(not(any(ossl101, ossl102, libressl)))]
        const PKCS7_NO_DUAL_CONTENT = ffi::PKCS7_NO_DUAL_CONTENT;
    }
}

impl PKCS7 {
    pub fn smime_write(&self, input: &[u8], flags: PKCS7Flags) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();

        unsafe {
            let input_bio = MemBioSlice::new(input)?;

            let output = MemBio::new()?;

            if ffi::SMIME_write_PKCS7(output.as_ptr(), self.0, input_bio.as_ptr(), flags.bits) == 1 {
                Ok(output.get_buf().to_owned())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn smime_read(input: &[u8], bcount: &mut Vec<u8>) -> Result<PKCS7, ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;

        let mut bcount_bio = null_mut();

        let pkcs7 = unsafe { ffi::SMIME_read_PKCS7(input_bio.as_ptr(), &mut bcount_bio) };

        bcount.clear();

        if !bcount_bio.is_null() {
            let bcount_bio = MemBio::from_ptr(bcount_bio);
            bcount.append(&mut bcount_bio.get_buf().to_vec());
        }

        if pkcs7.is_null() {
            Err(ErrorStack::get())
        } else {
            Ok(PKCS7(pkcs7))
        }
    }

    pub fn decrypt(&self, pkey: &PKeyRef, cert: &X509Ref) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();

        let output = MemBio::new()?;

        unsafe {
            if ffi::PKCS7_decrypt(self.0, pkey.as_ptr(), cert.as_ptr(), output.as_ptr(), 0) == 1 {
                Ok(output.get_buf().to_owned())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn encrypt(certs: &Stack<X509>, input: &[u8], cypher: Cipher, flags: PKCS7Flags) -> Result<PKCS7, ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;

        let pkcs7 = unsafe { ffi::PKCS7_encrypt(certs.as_ptr(), input_bio.as_ptr(), cypher.as_ptr(), flags.bits) };

        if pkcs7.is_null() {
            Err(ErrorStack::get())
        } else {
            Ok(PKCS7(pkcs7))
        }
    }

    pub fn sign(signcert: &X509Ref, pkey: &PKeyRef, certs: &Stack<X509>, input: &[u8], flags: PKCS7Flags) -> Result<PKCS7, ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;

        let pkcs7 = unsafe { ffi::PKCS7_sign(signcert.as_ptr(), pkey.as_ptr(), certs.as_ptr(), input_bio.as_ptr(), flags.bits) };

        if pkcs7.is_null() {
            Err(ErrorStack::get())
        } else {
            Ok(PKCS7(pkcs7))
        }
    }

    pub fn verify(&self, certs: &Stack<X509>, store: &X509Store, indata: Option<&[u8]>, out: Option<&mut Vec<u8>>, flags: PKCS7Flags) -> Result<bool, ErrorStack> {
        ffi::init();
        
        let out_bio = MemBio::new()?;

        let result = match indata {
            Some(data) => {
                let indata_bio = MemBioSlice::new(data)?;
                unsafe { ffi::PKCS7_verify(self.0, certs.as_ptr(), store.as_ptr(), indata_bio.as_ptr(), out_bio.as_ptr(), flags.bits) }
            },
            None => unsafe { ffi::PKCS7_verify(self.0, certs.as_ptr(), store.as_ptr(), null_mut(), out_bio.as_ptr(), flags.bits) }
        };

        if let Some(data) = out {
            data.clear();
            data.append(&mut out_bio.get_buf().to_vec());
        }

        if result == 1 {
            Ok(true)
        } else {
            Err(ErrorStack::get())
        }
    }
}

#[cfg(test)]
mod tests {
    use x509::X509;
    use x509::store::X509StoreBuilder;
    use symm::Cipher;
    use crypto::pkcs7::pk7_smime::PKCS7_STREAM;
    use crypto::pkcs7::pk7_smime::PKCS7_DETACHED;
    use crypto::pkcs7::pk7_smime::PKCS7;
    use pkey::PKey;
    use stack::Stack;

    #[test]
    fn encrypt_decrypt_test() {
        let cert = include_bytes!("../../../test/certs.pem");
        let cert = X509::from_pem(cert).unwrap();
        let mut certs = Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let message: String = String::from("foo");
        let cypher = Cipher::des_ede3_cbc();
        let flags = PKCS7_STREAM;
        let pkey = include_bytes!("../../../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();

        let pkcs7 = PKCS7::encrypt(&certs, message.as_bytes(), cypher, flags).expect("should succeed");

        let encrypted = pkcs7.smime_write(message.as_bytes(), flags).expect("should succeed");

        let mut bcount = Vec::new();
        let pkcs7_decoded = PKCS7::smime_read(encrypted.as_slice(), &mut bcount).expect("should succeed");

        let decoded = pkcs7_decoded.decrypt(&pkey, &cert).expect("should succeed");

        assert_eq!(decoded, message.into_bytes());
    }

    #[test]
    fn sign_verify_test_detached() {
        let cert = include_bytes!("../../../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message: String = String::from("foo");
        let flags = PKCS7_STREAM | PKCS7_DETACHED;
        let pkey = include_bytes!("../../../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../../../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 = PKCS7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7.smime_write(message.as_bytes(), flags).expect("should succeed");

        let mut bcount = Vec::new();
        let pkcs7_decoded = PKCS7::smime_read(signed.as_slice(), &mut bcount).expect("should succeed");

        let mut output = Vec::new();
        let result = pkcs7_decoded.verify(&certs, &store, Some(message.as_bytes()), Some(&mut output), flags)
            .expect("should succeed");

        assert!(result);
        assert_eq!(message.clone().into_bytes(), output);
        assert_eq!(message.clone().into_bytes(), bcount);
    }

    #[test]
    fn sign_verify_test_normal() {
        let cert = include_bytes!("../../../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message: String = String::from("foo");
        let flags = PKCS7_STREAM;
        let pkey = include_bytes!("../../../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../../../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 = PKCS7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7.smime_write(message.as_bytes(), flags).expect("should succeed");

        let mut bcount = Vec::new();
        let pkcs7_decoded = PKCS7::smime_read(signed.as_slice(), &mut bcount).expect("should succeed");

        let mut output = Vec::new();
        let result = pkcs7_decoded.verify(&certs, &store, None, Some(&mut output), flags).expect("should succeed");

        assert!(result);
        assert_eq!(message.clone().into_bytes(), output);
        let empty: Vec<u8> = Vec::new();
        assert_eq!(empty, bcount);
    }

    #[test]
    fn invalid_smime_read() {
        let input = String::from("Invalid SMIME Message");
        let mut bcount = Vec::new();

        let result = PKCS7::smime_read(input.as_bytes(), &mut bcount);

        assert_eq!(result.is_err(), true)
    }
}
