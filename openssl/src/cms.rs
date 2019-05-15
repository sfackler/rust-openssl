//! SMIME implementation using CMS
//!
//! CMS (PKCS#7) is an encryption standard.  It allows signing and encrypting data using
//! X.509 certificates.  The OpenSSL implementation of CMS is used in email encryption
//! generated from a `Vec` of bytes.  This `Vec` follows the smime protocol standards.
//! Data accepted by this module will be smime type `enveloped-data`.

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;

use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use libc::c_uint;
use pkey::{HasPrivate, PKeyRef};
<<<<<<< HEAD
#[cfg(ossl110)]
use stack::{Stackable, StackRef};
use symm::Cipher;
use x509::{X509Ref, X509};
#[cfg(ossl110)]
use x509::X509NameRef;
use x509::store::{X509StoreRef, X509StoreRef};
use symm::Cipher;
use {cvt, cvt_n, cvt_p};

#[cfg(ossl110)]
pub use self::recipient_info::*;

bitflags! {
    pub struct CMSOptions : c_uint {
        const TEXT = ffi::CMS_TEXT;
        const CMS_NOCERTS = ffi::CMS_NOCERTS;
        const NO_CONTENT_VERIFY = ffi::CMS_NO_CONTENT_VERIFY;
        const NO_ATTR_VERIFY = ffi::CMS_NO_ATTR_VERIFY;
        const NOSIGS = ffi::CMS_NOSIGS;
        const NOINTERN = ffi::CMS_NOINTERN;
        const NO_SIGNER_CERT_VERIFY = ffi::CMS_NO_SIGNER_CERT_VERIFY;
        const NOVERIFY = ffi::CMS_NOVERIFY;
        const DETACHED = ffi::CMS_DETACHED;
        const BINARY = ffi::CMS_BINARY;
        const NOATTR = ffi::CMS_NOATTR;
        const NOSMIMECAP = ffi::CMS_NOSMIMECAP;
        const NOOLDMIMETYPE = ffi::CMS_NOOLDMIMETYPE;
        const CRLFEOL = ffi::CMS_CRLFEOL;
        const STREAM = ffi::CMS_STREAM;
        const NOCRL = ffi::CMS_NOCRL;
        const PARTIAL = ffi::CMS_PARTIAL;
        const REUSE_DIGEST = ffi::CMS_REUSE_DIGEST;
        const USE_KEYID = ffi::CMS_USE_KEYID;
        const DEBUG_DECRYPT = ffi::CMS_DEBUG_DECRYPT;
        #[cfg(all(not(libressl), not(ossl101)))]
        const KEY_PARAM = ffi::CMS_KEY_PARAM;
        #[cfg(all(not(libressl), not(ossl101), not(ossl102)))]
        const ASCIICRLF = ffi::CMS_ASCIICRLF;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::CMS_ContentInfo;
    fn drop = ffi::CMS_ContentInfo_free;

    /// High level CMS wrapper
    ///
    /// CMS supports nesting various types of data, including signatures, certificates,
    /// encrypted data, smime messages (encrypted email), and data digest.  The ContentInfo
    /// content type is the encapsulation of all those content types.  [`RFC 5652`] describes
    /// CMS and OpenSSL follows this RFC's implmentation.
    ///
    /// [`RFC 5652`]: https://tools.ietf.org/html/rfc5652#page-6
    pub struct CmsContentInfo;
    /// Reference to [`CMSContentInfo`]
    ///
    /// [`CMSContentInfo`]:struct.CmsContentInfo.html
    pub struct CmsContentInfoRef;
}

impl CmsContentInfoRef {
    /// Given the sender's private key, `pkey` and the recipient's certificiate, `cert`,
    /// decrypt the data in `self`.
    ///
    /// OpenSSL documentation at [`CMS_decrypt`]
    ///
    /// [`CMS_decrypt`]: https://www.openssl.org/docs/man1.1.0/crypto/CMS_decrypt.html
    pub fn decrypt<T>(&self, pkey: &PKeyRef<T>, cert: &X509) -> Result<Vec<u8>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let pkey = pkey.as_ptr();
            let cert = cert.as_ptr();
            let out = MemBio::new()?;
            let flags: u32 = 0;

            cvt(ffi::CMS_decrypt(
                self.as_ptr(),
                pkey,
                cert,
                ptr::null_mut(),
                out.as_ptr(),
                flags.into(),
            ))?;

            Ok(out.get_buf().to_owned())
        }
    }

    /// Verify the sender's signature given an optional sender's certificate `cert` and CA store
    /// `store`. If the signature is correct, signed data are returned, otherwise `None`.
    ///
    /// OpenSSL documentation at [`CMS_verify`]
    /// 
    /// [`CMS_verify`]: https://www.openssl.org/docs/manmaster/man3/CMS_verify.html
    pub fn verify(
        &self,
        certs: Option<&StackRef<X509>>,
        store: &X509StoreRef,
        flags: CMSOptions,
    ) -> Result<Option<Vec<u8>>, ErrorStack> {
        let mut out = MemBio::new()?;
        let is_valid = self._verify(certs, store, None, Some(&mut out), flags)?;
        if is_valid {
            Ok(Some(out.get_buf().to_owned()))
        } else {
            Ok(None)
        }
    }

    /// Verify the sender's signature given an optional sender's certificate `cert` and CA store
    /// `store`. If the signature is correct, returns `true`, otherwise `false`.
    /// This is the version for detached signatures.
    ///
    /// OpenSSL documentation at [`CMS_verify`]
    /// 
    /// [`CMS_verify`]: https://www.openssl.org/docs/manmaster/man3/CMS_verify.html
    pub fn verify_detached(
        &self,
        certs: Option<&StackRef<X509>>,
        store: &X509StoreRef,
        data: &[u8],
        flags: CMSOptions,
    ) -> Result<bool, ErrorStack> {
        let mut in_data = MemBioSlice::new(data)?;
        self._verify(certs, store, Some(&mut in_data), None, flags)
    }

    fn _verify(
        &self,
        certs: Option<&StackRef<X509>>,
        store: &X509StoreRef,
        data: Option<&mut MemBioSlice>,
        out: Option<&mut MemBio>,
        flags: CMSOptions,
    ) -> Result<bool, ErrorStack> {
        unsafe {
            let certs = match certs {
                Some(certs) => certs.as_ptr(),
                None => ptr::null_mut(),
            };
            let store = store.as_ptr();
            let in_ptr = match data {
                Some(in_ptr) => in_ptr.as_ptr(),
                None => ptr::null_mut(),
            };
            let out_ptr = match out {
                Some(out_ptr) => out_ptr.as_ptr(),
                None => ptr::null_mut(),
            };

            let is_valid = cvt_n(ffi::CMS_verify(
                self.as_ptr(),
                certs,
                store,
                in_ptr,
                out_ptr,
                flags.bits(),
            ))? == 1;

            Ok(is_valid)
        }
    }

    to_der! {
        /// Serializes this CmsContentInfo using DER.
        ///
        /// OpenSSL documentation at [`i2d_CMS_ContentInfo`]
        ///
        /// [`i2d_CMS_ContentInfo`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_CMS_ContentInfo.html
        to_der,
        ffi::i2d_CMS_ContentInfo
    }

    to_pem! {
        /// Serializes this CmsContentInfo using DER.
        ///
        /// OpenSSL documentation at [`PEM_write_bio_CMS`]
        ///
        /// [`PEM_write_bio_CMS`]: https://www.openssl.org/docs/man1.1.0/man3/PEM_write_bio_CMS.html
        to_pem,
        ffi::PEM_write_bio_CMS
    }
}

impl CmsContentInfo {
    /// Parses a smime formatted `vec` of bytes into a `CmsContentInfo`.
    ///
    /// OpenSSL documentation at [`SMIME_read_CMS`]
    ///
    /// [`SMIME_read_CMS`]: https://www.openssl.org/docs/man1.0.2/crypto/SMIME_read_CMS.html
    pub fn smime_read_cms(smime: &[u8]) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let bio = MemBioSlice::new(smime)?;

            let cms = cvt_p(ffi::SMIME_read_CMS(bio.as_ptr(), ptr::null_mut()))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }

    from_der! {
        /// Deserializes a DER-encoded ContentInfo structure.
        ///
        /// This corresponds to [`d2i_CMS_ContentInfo`].
        ///
        /// [`d2i_CMS_ContentInfo`]: https://www.openssl.org/docs/manmaster/man3/d2i_X509.html
        from_der,
        CmsContentInfo,
        ffi::d2i_CMS_ContentInfo
    }

    from_pem! {
        /// Deserializes a PEM-encoded ContentInfo structure.
        ///
        /// This corresponds to [`PEM_read_bio_CMS`].
        ///
        /// [`PEM_read_bio_CMS`]: https://www.openssl.org/docs/man1.1.0/man3/PEM_read_bio_CMS.html
        from_pem,
        CmsContentInfo,
        ffi::PEM_read_bio_CMS
    }

    /// Given a signing cert `signcert`, private key `pkey`, a certificate stack `certs`,
    /// data `data` and flags `flags`, create a CmsContentInfo struct.
    ///
    /// All arguments are optional.
    ///
    /// OpenSSL documentation at [`CMS_sign`]
    ///
    /// [`CMS_sign`]: https://www.openssl.org/docs/manmaster/man3/CMS_sign.html
    pub fn sign<T>(
        signcert: Option<&X509Ref>,
        pkey: Option<&PKeyRef<T>>,
        certs: Option<&StackRef<X509>>,
        data: Option<&[u8]>,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let signcert = signcert.map_or(ptr::null_mut(), |p| p.as_ptr());
            let pkey = pkey.map_or(ptr::null_mut(), |p| p.as_ptr());
            let data_bio = match data {
                Some(data) => Some(MemBioSlice::new(data)?),
                None => None,
            };
            let data_bio_ptr = data_bio.as_ref().map_or(ptr::null_mut(), |p| p.as_ptr());
            let certs = certs.map_or(ptr::null_mut(), |p| p.as_ptr());

            let cms = cvt_p(ffi::CMS_sign(
                signcert,
                pkey,
                certs,
                data_bio_ptr,
                flags.bits(),
            ))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }

    /// Given a certificate stack `certs`, data `data`, cipher `cipher` and flags `flags`,
    /// create a CmsContentInfo struct.
    ///
    /// OpenSSL documentation at [`CMS_encrypt`]
    ///
    /// [`CMS_encrypt`]: https://www.openssl.org/docs/manmaster/man3/CMS_encrypt.html
    pub fn encrypt(
        certs: &StackRef<X509>,
        data: &[u8],
        cipher: Cipher,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let data_bio = MemBioSlice::new(data)?;

            let cms = cvt_p(ffi::CMS_encrypt(
                certs.as_ptr(),
                data_bio.as_ptr(),
                cipher.as_ptr(),
                flags.bits(),
            ))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }
}

#[cfg(ossl110)]
mod recipient_info {
    use asn1::Asn1IntegerRef;
    use stack::Stackable;
    use x509::X509NameRef;
    use foreign_types::Opaque;
    use super::*;

    impl CmsContentInfoRef {
        /// Given that we're dealing with the `EnvelopedData`, returns the recipients of the message.
        ///
        /// OpenSSL documentation at [`CMS_get0_RecipientInfos`]
        ///
        /// [`CMS_get0_RecipientInfos`]: https://www.openssl.org/docs/manmaster/man3/CMS_RecipientInfo_decrypt.html
        pub fn get_recipient_infos(&self) -> Result<&StackRef<CmsRecipientInfo>, ErrorStack> {
            unsafe {
                let recipient_infos = cvt_p(ffi::CMS_get0_RecipientInfos(self.as_ptr()))?;
                Ok(StackRef::from_ptr(recipient_infos))
            }
        }
    }

    /// An owned version of [`CmsRecipientInfoRef`]
    ///
    /// [`CmsRecipientInfoRef`]:struct.CmsRecipientInfoRef.html
    pub struct CmsRecipientInfo(*mut ffi::CMS_RecipientInfo);


    impl ForeignType for CmsRecipientInfo {
        type CType = ffi::CMS_RecipientInfo;
        type Ref = CmsRecipientInfoRef;

        #[inline]
        unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
            CmsRecipientInfo(ptr)
        }

        #[inline]
        fn as_ptr(&self) -> *mut Self::CType {
            self.0
        }
    }

    /// Reference to a [`CMS_RecipientInfo`].
    ///
    /// [`CMS_RecipientInfo`]: https://www.openssl.org/docs/manmaster/man3/CMS_RecipientInfo_decrypt.html
    pub struct CmsRecipientInfoRef(Opaque);

    impl ForeignTypeRef for CmsRecipientInfoRef {
        type CType = ffi::CMS_RecipientInfo;
    }

    impl Stackable for CmsRecipientInfo {
        type StackType = ffi::stack_st_CMS_RecipientInfo;
    }

    /// The bindings to the openssl's type of `CMS_RecipientInfo` which can be extracted with
    /// openssl's `CMS_RecipientInfo_ktri_get0_singer_id()` function.
    pub enum RecipientInfo<'cms> {
        Identifier,
        Info {
            issuer: &'cms X509NameRef,
            serial_number: &'cms Asn1IntegerRef,
        },
    }

    impl CmsRecipientInfoRef {
        /// Implementation of [`CMS_RecipientInfo_ktri_get0_signer_id`].
        ///
        /// [`CMS_RecipientInfo_ktri_get0_signer_id`]: https://www.openssl.org/docs/manmaster/man3/CMS_RecipientInfo_decrypt.html
        pub fn get_recipient_info<'cms>(&self) -> Result<RecipientInfo<'cms>, ErrorStack> {
            unsafe {
                let mut key_id = ptr::null_mut();
                let mut issuer = ptr::null_mut();
                let mut serial_number = ptr::null_mut();
                cvt(ffi::CMS_RecipientInfo_ktri_get0_signer_id(
                    self.as_ptr(),
                    &mut key_id,
                    &mut issuer,
                    &mut serial_number,
                ))?;

                if !key_id.is_null() {
                    // TODO: Implement (ffi::ASN1_OCTET_STRING) bindings.
                    Ok(RecipientInfo::Identifier)
                } else {
                    Ok(RecipientInfo::Info {
                        issuer: X509NameRef::from_ptr(issuer),
                        serial_number: Asn1IntegerRef::from_ptr(serial_number),
                    })
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use stack::Stack;

        #[test]
        fn extract_recipient_info() {
            // load cert with public key only
            let pub_cert_bytes = include_bytes!("../test/cms_pubkey.der");
            let pub_cert = X509::from_der(pub_cert_bytes).expect("failed to load pub cert");

            // encrypt cms message using public key cert
            let input = String::from("My Message");
            let mut cert_stack = Stack::new().expect("failed to create stack");
            cert_stack.push(pub_cert.clone()).expect("failed to add pub cert to stack");

            let encrypt = CmsContentInfo::encrypt(&cert_stack, &input.as_bytes(), Cipher::des_ede3_cbc(), CMSOptions::empty())
                .expect("failed create encrypted cms");
            let encrypt = encrypt.to_der().expect("failed to create der from cms");

            // decrypt cms message using private key cert
            let enveloped_data = CmsContentInfo::from_der(&encrypt).expect("failed read cms from der");

            // extract the recipient's information
            let recipients = enveloped_data.get_recipient_infos().expect("failed to get recipient infos");
            assert_eq!(recipients.len(), 1);

            let recp = recipients.get(0).unwrap().get_recipient_info().expect("failed to get recipient info");
            match recp {
                RecipientInfo::Identifier => {
                panic!("wrong information inside the recipient data");
                }
                RecipientInfo::Info { issuer, serial_number } => {
                    // compare the serial numbers
                    let pub_cert_serial_number = pub_cert.serial_number()
                        .to_bn()
                        .expect("could not convert serial number to bn")
                        .to_string();
                    let recp_serial_number = serial_number
                        .to_bn()
                        .expect("could not convert recipient's serial number to bn")
                        .to_string();
                    assert_eq!(pub_cert_serial_number, recp_serial_number);

                    // compare issuers
                    for (cert, expected) in pub_cert.issuer_name().entries().zip(issuer.entries()) {
                        assert_eq!(cert.data().as_slice(), expected.data().as_slice());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pkcs12::Pkcs12;
    use stack::Stack;
    use x509::X509;
    use x509::store::X509StoreBuilder;

    #[test]
    fn cms_encrypt_decrypt() {
        // load cert with public key only
        let pub_cert_bytes = include_bytes!("../test/cms_pubkey.der");
        let pub_cert = X509::from_der(pub_cert_bytes).expect("failed to load pub cert");

        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert
            .parse("mypass")
            .expect("failed to parse priv cert");

        // encrypt cms message using public key cert
        let input = String::from("My Message");
        let mut cert_stack = Stack::new().expect("failed to create stack");
        cert_stack
            .push(pub_cert)
            .expect("failed to add pub cert to stack");

        let encrypt = CmsContentInfo::encrypt(
            &cert_stack,
            &input.as_bytes(),
            Cipher::des_ede3_cbc(),
            CMSOptions::empty(),
        )
        .expect("failed create encrypted cms");

        // decrypt cms message using private key cert (DER)
        {
            let encrypted_der = encrypt.to_der().expect("failed to create der from cms");
            let decrypt =
                CmsContentInfo::from_der(&encrypted_der).expect("failed read cms from der");
            let decrypt = decrypt
                .decrypt(&priv_cert.pkey, &priv_cert.cert)
                .expect("failed to decrypt cms");
            let decrypt =
                String::from_utf8(decrypt).expect("failed to create string from cms content");
            assert_eq!(input, decrypt);
        }

        // decrypt cms message using private key cert (PEM)
        {
            let encrypted_pem = encrypt.to_pem().expect("failed to create pem from cms");
            let decrypt =
                CmsContentInfo::from_pem(&encrypted_pem).expect("failed read cms from pem");
            let decrypt = decrypt
                .decrypt(&priv_cert.pkey, &priv_cert.cert)
                .expect("failed to decrypt cms");
            let decrypt =
                String::from_utf8(decrypt).expect("failed to create string from cms content");
            assert_eq!(input, decrypt);
        }
    }

    #[test]
    fn cms_sign_verify() {
        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert.parse("mypass").expect("failed to parse priv cert");

        // sign cms message using private key cert
        let input = String::from("My Message");
        let sign = CmsContentInfo::sign(Some(&priv_cert.cert), Some(&priv_cert.pkey), None, Some(&input.as_bytes()), CMSOptions::empty())
            .expect("failed create signed cms");
        let sign = sign.to_der().expect("failed to create der from cms");

        // verify signature on cms message
        let verify = CmsContentInfo::from_der(&sign).expect("failed read cms from der");

        let mut cert_stack = Stack::new().expect("failed to create stack");
        cert_stack.push(priv_cert.cert.clone()).expect("failed to add cert to stack");

        let mut store_builder = X509StoreBuilder::new().expect("failed to create store builder");
        store_builder.add_cert(priv_cert.cert.clone()).expect("failed to add certificate to store");
        let store = store_builder.build();

        let verify = verify.verify(Some(&cert_stack), &store, CMSOptions::empty()).expect("failed to verify cms");
        let verify = verify.expect("cms verification returned None");
        let verify = String::from_utf8(verify).expect("failed to create string from cms content");

        assert_eq!(input, verify);
    }

    #[test]
    fn cms_sign_verify_detached() {
        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert.parse("mypass").expect("failed to parse priv cert");

        // sign cms message using private key cert
        let input = String::from("My Message");
        let sign = CmsContentInfo::sign(Some(&priv_cert.cert), Some(&priv_cert.pkey), None, Some(&input.as_bytes()), CMSOptions::DETACHED)
            .expect("failed create signed cms");
        let sign = sign.to_der().expect("failed to create der from cms");

        // verify signature on cms message
        let verify = CmsContentInfo::from_der(&sign).expect("failed read cms from der");

        let mut cert_stack = Stack::new().expect("failed to create stack");
        cert_stack.push(priv_cert.cert.clone()).expect("failed to add cert to stack");

        let mut store_builder = X509StoreBuilder::new().expect("failed to create store builder");
        store_builder.add_cert(priv_cert.cert.clone()).expect("failed to add certificate to store");
        let store = store_builder.build();

        let verify = verify.verify_detached(Some(&cert_stack), &store, input.as_bytes(), CMSOptions::empty()).expect("failed to verify cms");
        assert!(verify);
    }
}
