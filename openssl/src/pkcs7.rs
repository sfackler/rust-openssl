use bitflags::bitflags;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_void};
use std::mem;
use std::ptr;

use crate::bio::{MemBio, MemBioSlice};
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, PKey, PKeyRef};
use crate::stack::{Stack, StackRef};
use crate::symm::Cipher;
use crate::x509::store::X509StoreRef;
use crate::x509::{X509Ref, X509, X509Attribute};
use crate::{cvt, cvt_p};
use crate::asn1::{Asn1Object, Asn1Type};
use openssl_macros::corresponds;
use crate::hash::MessageDigest;
use crate::nid::Nid;

foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS7_SIGNER_INFO;
    fn drop = ffi::PKCS7_SIGNER_INFO_free;

    /// A `PKCS_SIGNER_INFO` signer info strucuture
    pub struct Pkcs7SignerInfo;

    /// Reference to `PKCS7_SIGNER_INFO`.
    pub struct Pkcs7SignerInfoRef;
}

impl Pkcs7SignerInfo {
    pub fn as_ptr(&self)-> *mut ffi::PKCS7_SIGNER_INFO {
        &self.0 as *const _ as *mut _
    }
    pub fn free(slf: *mut ffi::PKCS7_SIGNER_INFO) {
        unsafe {
            ffi::PKCS7_SIGNER_INFO_free(slf)
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS7_SIGNED;
    fn drop = ffi::PKCS7_SIGNED_free;
    pub struct Pkcs7Signed;
    pub struct Pkcs7SignedRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS7;
    fn drop = ffi::PKCS7_free;

    /// A PKCS#7 structure.
    ///
    /// Contains signed and/or encrypted data.
    pub struct Pkcs7;

    /// Reference to `Pkcs7`
    pub struct Pkcs7Ref;
}

bitflags! {
    pub struct Pkcs7Flags: c_int {
        const TEXT = ffi::PKCS7_TEXT;
        const NOCERTS = ffi::PKCS7_NOCERTS;
        const NOSIGS = ffi::PKCS7_NOSIGS;
        const NOCHAIN = ffi::PKCS7_NOCHAIN;
        const NOINTERN = ffi::PKCS7_NOINTERN;
        const NOVERIFY = ffi::PKCS7_NOVERIFY;
        const DETACHED = ffi::PKCS7_DETACHED;
        const BINARY = ffi::PKCS7_BINARY;
        const NOATTR = ffi::PKCS7_NOATTR;
        const NOSMIMECAP = ffi::PKCS7_NOSMIMECAP;
        const NOOLDMIMETYPE = ffi::PKCS7_NOOLDMIMETYPE;
        const CRLFEOL = ffi::PKCS7_CRLFEOL;
        const STREAM = ffi::PKCS7_STREAM;
        const NOCRL = ffi::PKCS7_NOCRL;
        const PARTIAL = ffi::PKCS7_PARTIAL;
        const REUSE_DIGEST = ffi::PKCS7_REUSE_DIGEST;
        #[cfg(not(any(ossl101, ossl102, libressl)))]
        const NO_DUAL_CONTENT = ffi::PKCS7_NO_DUAL_CONTENT;
    }
}

impl Pkcs7 {
    /// Create a new an empty PKCS#7 object.
    ///
    #[corresponds(PKCS7_new)]
    pub fn new() -> Result<Pkcs7, ErrorStack> {
        unsafe {
            let pkcs7 = cvt_p(ffi::PKCS7_new()).map(Pkcs7)?;
            Ok(pkcs7)
        }
    }

    from_pem! {
        /// Deserializes a PEM-encoded PKCS#7 signature
        ///
        /// The input should have a header of `-----BEGIN PKCS7-----`.
        #[corresponds(PEM_read_bio_PKCS7)]
        from_pem,
        Pkcs7,
        ffi::PEM_read_bio_PKCS7
    }

    from_der! {
        /// Deserializes a DER-encoded PKCS#7 signature
        #[corresponds(d2i_PKCS7)]
        from_der,
        Pkcs7,
        ffi::d2i_PKCS7
    }

    /// Parses a message in S/MIME format.
    ///
    /// Returns the loaded signature, along with the cleartext message (if
    /// available).
    #[corresponds(SMIME_read_PKCS7)]
    pub fn from_smime(input: &[u8]) -> Result<(Pkcs7, Option<Vec<u8>>), ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;
        let mut bcont_bio = ptr::null_mut();
        unsafe {
            let pkcs7 =
                cvt_p(ffi::SMIME_read_PKCS7(input_bio.as_ptr(), &mut bcont_bio)).map(Pkcs7)?;
            let out = if !bcont_bio.is_null() {
                let bcont_bio = MemBio::from_ptr(bcont_bio);
                Some(bcont_bio.get_buf().to_vec())
            } else {
                None
            };
            Ok((pkcs7, out))
        }
    }

    /// Creates and returns a PKCS#7 `envelopedData` structure.
    ///
    /// `certs` is a list of recipient certificates. `input` is the content to be
    /// encrypted. `cipher` is the symmetric cipher to use. `flags` is an optional
    /// set of flags.
    #[corresponds(PKCS7_encrypt)]
    pub fn encrypt(
        certs: &StackRef<X509>,
        input: &[u8],
        cipher: Cipher,
        flags: Pkcs7Flags,
    ) -> Result<Pkcs7, ErrorStack> {
        let input_bio = MemBioSlice::new(input)?;

        unsafe {
            cvt_p(ffi::PKCS7_encrypt(
                certs.as_ptr(),
                input_bio.as_ptr(),
                cipher.as_ptr(),
                flags.bits,
            ))
            .map(Pkcs7)
        }
    }

    /// Creates and returns a PKCS#7 `signedData` structure.
    ///
    /// `signcert` is the certificate to sign with, `pkey` is the corresponding
    /// private key. `certs` is an optional additional set of certificates to
    /// include in the PKCS#7 structure (for example any intermediate CAs in the
    /// chain).
    #[corresponds(PKCS7_sign)]
    pub fn sign<PT>(
        signcert: &X509Ref,
        pkey: &PKeyRef<PT>,
        certs: &StackRef<X509>,
        input: &[u8],
        flags: Pkcs7Flags,
    ) -> Result<Pkcs7, ErrorStack>
    where
        PT: HasPrivate,
    {
        let input_bio = MemBioSlice::new(input)?;
        unsafe {
            cvt_p(ffi::PKCS7_sign(
                signcert.as_ptr(),
                pkey.as_ptr(),
                certs.as_ptr(),
                input_bio.as_ptr(),
                flags.bits,
            ))
            .map(Pkcs7)
        }
    }

    /// Set signed attributes in a PKCS#7 structure.
    ///
    /// `attributes` is a stack of the attributes to be added.
    ///
    #[corresponds(PKCS7_set_signed_attributes)]
    pub fn set_signed_attributes(
        signer_info: &Pkcs7SignerInfoRef,
        attributes: Stack<X509Attribute>
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(
                ffi::PKCS7_set_signed_attributes(
                    signer_info.as_ptr(),
                    attributes.as_ptr()
                )
            )?;
            mem::forget(attributes);
            Ok(())
        }
    }

    /// Add a signed attribute to a PKCS7_SIGNER_INFO structure
    ///
    /// `nid` is the Nid of the attribute, `atrtype` is the attribute's type (an ASN.1 tag
    /// value) and `value ` is
    ///
    ///
    /// Note: `value` is immutable, but the OpenSSL function takes a (non-const) void pointer. Thus,
    /// we have to cast to mutable in the unsafe block. Yes, that's dirty, but at least, the rust
    /// api is now correct.
    /// OpenSSL takes ownership of `value`.
    ///
    #[corresponds(PKCS7_add_signed_attribute)]
    pub fn add_signed_attribute(
        signer_info: &Pkcs7SignerInfoRef,
        nid: Nid,
        atrtype: Asn1Type,
        value: Asn1Object
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(
                ffi::PKCS7_add_signed_attribute(
                    signer_info.as_ptr(),
                    nid.as_raw(),
                    atrtype.as_raw(),
                    value.as_ptr() as *mut c_void
                )
            )?;
            mem::forget(value);
            Ok(())
        }
    }

    /// Get the certificates stored to a PKCS#7 structure
    ///
    /// Unfortunately, there is no corresponding function in openssl. Thus, we have to enter
    /// openssl's internal PKCS7 struct. This is also, what openssl does, when e.g.
    /// `openssl pkcs7 -in pkcs7.pem -print-certs` is called.
    pub fn certificates(&self) -> Result<Stack<X509>, ErrorStack> {
        unsafe {
            let pkcs7: *mut ffi::PKCS7 = self.0;
            let pkcs7_type: Asn1Object = Asn1Object::from_ptr((*pkcs7).type_);
            let pkcs7_certs: Stack<X509> = match pkcs7_type.nid() {
                Nid::PKCS7_SIGNED =>
                    Stack::from_ptr((*(*pkcs7).d.sign).cert),
                Nid::PKCS7_SIGNEDANDENVELOPED =>
                    Stack::from_ptr((*(*pkcs7).d.signed_and_enveloped).cert),
                _ => Stack::new()?,
            };
            let mut certs: Stack<X509> = Stack::new()?;
            for cert_ref in &pkcs7_certs {
                // Note: `to_owned()` increases the openssl reference count of the cert, so the
                // stack becomes an additional owner of the certs.
                let cert = cert_ref.to_owned();
                certs.push(cert)?;
            }
            mem::forget(pkcs7_certs);  // Otherwise, certs would be removed from self, when this method returns
            Ok(certs)
        }
    }

}

impl Pkcs7Ref {
    /// Converts PKCS#7 structure to S/MIME format
    #[corresponds(SMIME_write_PKCS7)]
    pub fn to_smime(&self, input: &[u8], flags: Pkcs7Flags) -> Result<Vec<u8>, ErrorStack> {
        let input_bio = MemBioSlice::new(input)?;
        let output = MemBio::new()?;
        unsafe {
            cvt(ffi::SMIME_write_PKCS7(
                output.as_ptr(),
                self.as_ptr(),
                input_bio.as_ptr(),
                flags.bits,
            ))
            .map(|_| output.get_buf().to_owned())
        }
    }

    to_pem! {
        /// Serializes the data into a PEM-encoded PKCS#7 structure.
        ///
        /// The output will have a header of `-----BEGIN PKCS7-----`.
        #[corresponds(PEM_write_bio_PKCS7)]
        to_pem,
        ffi::PEM_write_bio_PKCS7
    }

    to_der! {
        /// Serializes the data into a DER-encoded PKCS#7 structure.
        #[corresponds(i2d_PKCS7)]
        to_der,
        ffi::i2d_PKCS7
    }

    /// Decrypts data using the provided private key.
    ///
    /// `pkey` is the recipient's private key, and `cert` is the recipient's
    /// certificate.
    ///
    /// Returns the decrypted message.
    #[corresponds(PKCS7_decrypt)]
    pub fn decrypt<PT>(
        &self,
        pkey: &PKeyRef<PT>,
        cert: &X509Ref,
        flags: Pkcs7Flags,
    ) -> Result<Vec<u8>, ErrorStack>
    where
        PT: HasPrivate,
    {
        let output = MemBio::new()?;

        unsafe {
            cvt(ffi::PKCS7_decrypt(
                self.as_ptr(),
                pkey.as_ptr(),
                cert.as_ptr(),
                output.as_ptr(),
                flags.bits,
            ))
            .map(|_| output.get_buf().to_owned())
        }
    }

    /// Verifies the PKCS#7 `signedData` structure contained by `&self`.
    ///
    /// `certs` is a set of certificates in which to search for the signer's
    /// certificate. `store` is a trusted certificate store (used for chain
    /// verification). `indata` is the signed data if the content is not present
    /// in `&self`. The content is written to `out` if it is not `None`.
    #[corresponds(PKCS7_verify)]
    pub fn verify(
        &self,
        certs: &StackRef<X509>,
        store: &X509StoreRef,
        indata: Option<&[u8]>,
        out: Option<&mut Vec<u8>>,
        flags: Pkcs7Flags,
    ) -> Result<(), ErrorStack> {
        let out_bio = MemBio::new()?;

        let indata_bio = match indata {
            Some(data) => Some(MemBioSlice::new(data)?),
            None => None,
        };
        let indata_bio_ptr = indata_bio.as_ref().map_or(ptr::null_mut(), |p| p.as_ptr());

        unsafe {
            cvt(ffi::PKCS7_verify(
                self.as_ptr(),
                certs.as_ptr(),
                store.as_ptr(),
                indata_bio_ptr,
                out_bio.as_ptr(),
                flags.bits,
            ))
            .map(|_| ())?
        }

        if let Some(data) = out {
            data.clear();
            data.extend_from_slice(out_bio.get_buf());
        }

        Ok(())
    }

    /// Retrieve the signer's certificates from the PKCS#7 structure without verifying them.
    #[corresponds(PKCS7_get0_signers)]
    pub fn signers(
        &self,
        certs: &StackRef<X509>,
        flags: Pkcs7Flags,
    ) -> Result<Stack<X509>, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::PKCS7_get0_signers(
                self.as_ptr(),
                certs.as_ptr(),
                flags.bits,
            ))?;

            // The returned stack is owned by the caller, but the certs inside are not! Our stack interface can't deal
            // with that, so instead we just manually bump up the refcount of the certs so that the whole stack is properly
            // owned.
            let stack = Stack::<X509>::from_ptr(ptr);
            for cert in &stack {
                mem::forget(cert.to_owned());
            }

            Ok(stack)
        }
    }

    /// Set the type of a PKCS#7 structure
    ///
    /// `nid` is type's Nid. Allowed values are
    /// - Nid::PKCS7_SIGNED
    /// - Nid::PKCS7_DATA
    /// - Nid::PKCS7_SIGNEDANDENVELOPED
    /// - Nid::PKCS7_ENVELOPED
    /// - Nid::PKCS7_ENCRYPTED
    /// - Nid::PKCS7_DIGEST
    ///
    #[corresponds(PKCS7_set_type)]
    ///
    pub fn set_type(&self, nid: Nid) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::PKCS7_set_type(
                self.as_ptr(),
                nid.as_raw()
            )).map(|_| ())
        }
    }

    /// Add the signer certificate to a PKCS#7 structure
    ///
    /// `cert` is the signer's certificate.
    ///
    /// This method moves the ownership of `cert` to the PKCS7 structure.
    ///
    #[corresponds(PKCS7_add_certificate)]
    ///
    pub fn add_certificate(&self, cert: X509) -> Result<(), ErrorStack> {
        unsafe {
            cvt(
                ffi::PKCS7_add_certificate(
                    self.as_ptr(),
                    cert.as_ptr()
                )
            )?;
            mem::forget(cert);
            Ok(())
        }
    }

    /// Add signature information to the PKCS#7 structure.
    ///
    /// `cert` is the signer's certificate. `pkey` is the signer's (private) key. `algorithm` is
    /// the hash algorithm to be used.
    ///
    /// Returns a signer info structure, which can be used to add signed attributes. `cert` is not
    /// consumed by this method (actually by `PKCS7_add_signature`), but `pkey` is. Create a clone
    /// before calling `add_signature()`, if you need the key later.:
    /// ```
    /// use openssl::hash::MessageDigest;
    /// use openssl::pkcs7::Pkcs7;
    /// use openssl::pkey::PKey;
    /// use openssl::rsa::Rsa;
    /// use openssl::x509::X509;
    ///
    /// let cert = X509::from_pem("-----BEGIN CERTIFICATE-----\n\
    /// MIICsTCCAZmgAwIBAgIBADANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFJU0VD\n\
    /// IFRlc3QgUm9vdCBDQTAeFw0yMTEyMTUwOTM4MDVaFw0zMTEyMTMwOTM4MDVaMBwx\n\
    /// GjAYBgNVBAMMEUlTRUMgVGVzdCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\n\
    /// AQ8AMIIBCgKCAQEAt/0hnw55JtLXN4QjFhmkZ5mSSWQM3Zlz8+n9wq99jkDXEUJ8\n\
    /// YGoHxpBTb9vz4BXwVcR/3GWtdJ/h5VQinBYcZLwtz5iel4IC7pl40a8Kcco3hm6U\n\
    /// +qve9wz2YS8coQ1+zQ/pqKxDOLN60BYVkuxZeC4yrg8ovL5YftKzeVmFUjDJ/vdI\n\
    /// RyDScFpso2UoW6mklW/C94ciJH6O9m9dd2nWow1vUfHJlAEm8nPRxJRQH1bROxmc\n\
    /// 5hLHMjY5wFD/jo31jzxSeZxNhLTKDwn8nG1AGoHaudUNtAF25tzcU6nLKt6BIS+g\n\
    /// wqavL3kwp+1O/GwLPQb4xXmPs2+f2M08XMbVKwIDAQABMA0GCSqGSIb3DQEBCwUA\n\
    /// A4IBAQCKWDHBLlLPDmb1C5FOcJ/wqdwCzkbZEBs3qsiim5EDkt9+nqAfwyn0K+G8\n\
    /// BLJU+6kgeGW1Z0t3RqJdAq2r+7bfMVF8ubJ4zEu5xJAz9UppI4XZ8sZ8iS5rZ3hq\n\
    /// zjU+7G8Lnu9gEh18q5foi59Wx0jjMyIOWh8O9j3P0JjLxAR8v4rKlYp89/A+vWfb\n\
    /// TAj31LhWWTa0kiDP9Wd8cMWCjurv7Wq7U4K9gHMHpmUclxs1ByHtFdd61OXSdfBx\n\
    /// P1Te4tjxQpVo5zURkwOfZoOC6ikAOYoTAYNHP/qwsX2+KnL/JeGCcU4WtoWIp8mt\n\
    /// HkHgG5EBGoJmLFNFeQWB2yaqAhfD\n\
    /// -----END CERTIFICATE-----".as_bytes()).unwrap();
    /// let rsa = Rsa::generate(2048).unwrap();
    /// let signer_key = PKey::from_rsa(rsa).unwrap();
    /// let signer_key_clone = signer_key.clone();
    /// let pkcs7 = Pkcs7::new().unwrap();
    /// let signer_info = &pkcs7.add_signature(
    ///     &cert,
    ///     signer_key_clone,
    ///     MessageDigest::sha256()
    /// );
    ///  ```
    ///
    /// #[corresponds(PKCS7_add_signature)]
    ///
    pub fn add_signature<PT>(
        &self,
        cert: &X509Ref,
        pkey: PKey<PT>,
        algorithm: MessageDigest
    ) -> Result<Pkcs7SignerInfo, ErrorStack>
    where
        PT: HasPrivate,
    {
        unsafe {
            let signer_info = cvt_p(ffi::PKCS7_add_signature(
                self.as_ptr(),
                cert.as_ptr(),
                pkey.as_ptr(),
                algorithm.as_ptr()
            ));
            mem::forget(pkey);
            signer_info.map(Pkcs7SignerInfo)
        }
    }

    /// Add the payload to a PKCS#7 structure.
    /// The PKCS#7 structure must be either of type NID_pkcs7_signed or NID_pkcs7_digest.
    /// Finalize a PKCS#7 structure. If the structure's type is `Nid::PKCS7_SIGNED` or
    /// `Nid::PKCS7_SIGNEDANDENVELOPED`, it will be signed.
    ///
    /// The `content_type` must be a PKCS#7 typeAllowed values are
    /// - Nid::PKCS7_SIGNED
    /// - Nid::PKCS7_DATA
    /// - Nid::PKCS7_SIGNEDANDENVELOPED
    /// - Nid::PKCS7_ENVELOPED
    /// - Nid::PKCS7_ENCRYPTED
    /// - Nid::PKCS7_DIGEST
    /// `content` is the payload of type `content_type`.
    ///
    /// This uses the following OpenSSL functions: [`PKCS7_content_new`],
    /// [`PKCS7_dataInit`], [`BIO_write`]
    ///
    pub fn add_content(&self, content_type: Nid, content: &[u8]) -> Result<MemBio, ErrorStack> {
        unsafe {
            // Initialize content
            cvt(ffi::PKCS7_content_new(
                self.as_ptr(),
                content_type.as_raw()
            )).map(|_| ())?;
            // Write content
            let bcont_bio = ptr::null_mut();
            let bio = cvt_p(ffi::PKCS7_dataInit(self.as_ptr(), bcont_bio))
                .map(|bio| MemBio::from_ptr(bio))?;
            let content_length = content.len() as c_int;
            let len = ffi::BIO_write(
                bio.as_ptr(),
                content.as_ptr() as *const c_void,
                content_length
            );
            if len == content_length {
                Ok(bio)
            } else {
                return Err(ErrorStack::get());
            }
        }

    }

    /// Get the content of a PKCS#7 signed object (`pkcs7->d.sign->contents`).
    pub fn get_content(&self) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let buffer: [u8; 1024] = [0; 1024];
            let out_bio = MemBio::new()?;
            let bcont_bio = ptr::null_mut();
            let pkcs7_bio = cvt_p(ffi::PKCS7_dataInit(self.as_ptr(), bcont_bio))
                .map(|bio| MemBio::from_ptr(bio))?;
            loop {
                let bytes = ffi::BIO_read(
                    pkcs7_bio.as_ptr(),
                    buffer.as_ptr() as *mut c_void,
                    buffer.len() as i32);
                if bytes <= 0 { break; }
                let _len = ffi::BIO_write(
                    out_bio.as_ptr(),
                    buffer.as_ptr() as *const c_void,
                    bytes);
            }
            out_bio.flush()?;
            Ok(out_bio.get_buf().to_vec())
        }
    }

    /// Finalize a PKCS#7 structure. If the structure's type is `Nid::PKCS7_SIGNED` or
    /// `Nid::PKCS7_SIGNEDANDENVELOPED`, it will be signed.
    ///
    #[corresponds(PKCS7_dataFinal)]
    ///
    pub fn finalize(&self, bio: &MemBio) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::PKCS7_dataFinal(
                self.as_ptr(),
                bio.as_ptr()
            )).map(|_| ())
        }
    }

}

#[cfg(test)]
mod tests {
    use crate::asn1::{Asn1Integer, Asn1Time};
    use crate::bn::{BigNum, MsbOption};
    use crate::hash::MessageDigest;
    use crate::nid::Nid;
    use crate::pkcs7::{Pkcs7, Pkcs7Flags};
    use crate::pkey::PKey;
    use crate::rsa::Rsa;
    use crate::stack::Stack;
    use crate::symm::Cipher;
    use crate::x509::store::X509StoreBuilder;
    use crate::x509::{X509, X509Name, X509Req};
    use crate::x509::extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};

    #[test]
    fn encrypt_decrypt_test() {
        let cert = include_bytes!("../test/certs.pem");
        let cert = X509::from_pem(cert).unwrap();
        let mut certs = Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let message: String = String::from("foo");
        let cipher = Cipher::des_ede3_cbc();
        let flags = Pkcs7Flags::STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();

        let pkcs7 =
            Pkcs7::encrypt(&certs, message.as_bytes(), cipher, flags).expect("should succeed");

        let encrypted = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");

        let (pkcs7_decoded, _) = Pkcs7::from_smime(encrypted.as_slice()).expect("should succeed");

        let decoded = pkcs7_decoded
            .decrypt(&pkey, &cert, Pkcs7Flags::empty())
            .expect("should succeed");

        assert_eq!(decoded, message.into_bytes());
    }

    #[test]
    fn sign_verify_test_detached() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message = "foo";
        let flags = Pkcs7Flags::STREAM | Pkcs7Flags::DETACHED;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");
        println!("{:?}", String::from_utf8(signed.clone()).unwrap());
        let (pkcs7_decoded, content) =
            Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

        let mut output = Vec::new();
        pkcs7_decoded
            .verify(
                &certs,
                &store,
                Some(message.as_bytes()),
                Some(&mut output),
                flags,
            )
            .expect("should succeed");

        assert_eq!(output, message.as_bytes());
        assert_eq!(content.expect("should be non-empty"), message.as_bytes());
    }

    #[test]
    fn sign_verify_test_normal() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message = "foo";
        let flags = Pkcs7Flags::STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");

        let (pkcs7_decoded, content) =
            Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

        let mut output = Vec::new();
        pkcs7_decoded
            .verify(&certs, &store, None, Some(&mut output), flags)
            .expect("should succeed");

        assert_eq!(output, message.as_bytes());
        assert!(content.is_none());
    }

    #[test]
    fn signers() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let cert_digest = cert.digest(MessageDigest::sha256()).unwrap();
        let certs = Stack::new().unwrap();
        let message = "foo";
        let flags = Pkcs7Flags::STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");

        let (pkcs7_decoded, _) = Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

        let empty_certs = Stack::new().unwrap();
        let signer_certs = pkcs7_decoded
            .signers(&empty_certs, flags)
            .expect("should succeed");
        assert_eq!(empty_certs.len(), 0);
        assert_eq!(signer_certs.len(), 1);
        let signer_digest = signer_certs[0].digest(MessageDigest::sha256()).unwrap();
        assert_eq!(*cert_digest, *signer_digest);
    }

    #[test]
    fn invalid_from_smime() {
        let input = String::from("Invalid SMIME Message");
        let result = Pkcs7::from_smime(input.as_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn enveloped_pkcs7() {
        fn get_serial() -> Asn1Integer {
            let mut big_number = BigNum::new().unwrap();
            big_number.rand(128, MsbOption::MAYBE_ZERO, true).unwrap();
            let serial = Asn1Integer::from_bn(&big_number).unwrap();
            serial
        }

        // Create an X.509 certificate for encryption
        let days: u32 = 365 * 10;
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(days).unwrap();
        let serial = get_serial();
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Example Name").unwrap();
        name.append_entry_by_nid(Nid::COUNTRYNAME, "DE").unwrap();
        name.append_entry_by_nid(Nid::STATEORPROVINCENAME, "Example State").unwrap();
        name.append_entry_by_nid(Nid::LOCALITYNAME, "Example Town").unwrap();
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Example Company").unwrap();
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Example Unit").unwrap();
        name.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, "info@example.com").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap(); // 2 -> X509v3
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(not_before.as_ref()).unwrap();
        builder.set_not_after(not_after.as_ref()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let encryption_cert = builder.build();

        // Create a CSR
        let challenge_password = "chaIIenge-passsw0rd";
        let mut builder = X509Req::builder().unwrap();
        builder.set_version(0).unwrap(); // 0x00 -> Version: 1
        builder.set_subject_name(&name).unwrap();
        // set SANs
        // set KeyUsage to digital signature and key encipherment
        let extensions = {
            let context = builder.x509v3_context(None);
            let mut ext_stack = Stack::new().unwrap();
            ext_stack
                .push(
                    KeyUsage::new()
                        .digital_signature()
                        .key_encipherment()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            ext_stack
                .push(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap();
            ext_stack
                .push(
                    SubjectAlternativeName::new()
                        .dns("server.example.com")
                        .build(&context)
                        .unwrap(),
                )
                .unwrap();
            ext_stack
                .push(
                    SubjectAlternativeName::new()
                        .ip("127.0.0.1")
                        .build(&context)
                        .unwrap(),
                )
                .unwrap();
            ext_stack
                .push(
                    SubjectAlternativeName::new()
                        .ip("::1")
                        .build(&context)
                        .unwrap(),
                )
                .unwrap();
            ext_stack
        };
        builder.add_extensions(&extensions).unwrap();
        builder
            .add_attribute_by_nid(Nid::PKCS9_CHALLENGEPASSWORD, challenge_password)
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let csr = builder.build();

        // Create an enveloped PKCS #7 object
        let cipher = Cipher::aes_256_cbc();
        let mut encryption_certs: Stack<X509> = Stack::new().unwrap();
        encryption_certs.push(encryption_cert).unwrap();

        // Encrypt the CSR -> pkcsPKIEnvelope (PKCS#7 envelopedData)
        let enveloped_data: Pkcs7 = Pkcs7::encrypt(
            &encryption_certs,
            &csr.to_der().unwrap(),
            cipher,
            Pkcs7Flags::BINARY,
        )
            .unwrap();

        enveloped_data.to_pem().unwrap();
    }
}