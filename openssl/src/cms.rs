//! SMIME implementation using CMS
//!
//! CMS (PKCS#7) is an encyption standard.  It allows signing and ecrypting data using
//! X.509 certificates.  The OpenSSL implementation of CMS is used in email encryption
//! generated from a `Vec` of bytes.  This `Vec` follows the smime protocol standards.
//! Data accepted by this module will be smime type `enveloped-data`.

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;

use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use pkey::{HasPrivate, PKeyRef};
use stack::Stack;
use x509::X509;
use {cvt, cvt_p};

bitflags! {
    pub struct CMSOptions : u32 {
        const CMS_TEXT = 0x1;
        const CMS_NOCERTS = 0x2;
        const CMS_NO_CONTENT_VERIFY = 0x4;
        const CMS_NO_ATTR_VERIFY = 0x8;
        const CMS_NOSIGS = 0x4 | 0x8;
        const CMS_NOINTERN = 0x10;
        const CMS_NO_SIGNER_CERT_VERIFY = 0x20;
        const CMS_NOVERIFY = 0x20;
        const CMS_DETACHED = 0x40;
        const CMS_BINARY = 0x80;
        const CMS_NOATTR = 0x100;
        const CMS_NOSMIMECAP = 0x200;
        const CMS_NOOLDMIMETYPE = 0x400;
        const CMS_CRLFEOL = 0x800;
        const CMS_STREAM = 0x1000;
        const CMS_NOCRL = 0x2000;
        const CMS_PARTIAL = 0x4000;
        const CMS_REUSE_DIGEST = 0x8000;
        const CMS_USE_KEYID = 0x10000;
        const CMS_DEBUG_DECRYPT = 0x20000;
        const CMS_KEY_PARAM = 0x40000;
        const CMS_ASCIICRLF = 0x80000;
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

    to_der! {
    /// Serializes this CmsContentInfo using DER.
    ///
    /// OpenSSL documentation at [`i2d_CMS_ContentInfo`]
    ///
    /// [`i2d_CMS_ContentInfo`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_CMS_ContentInfo.html
    to_der,
    ffi::i2d_CMS_ContentInfo
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

    /// Given a signing cert `signcert`, private key `pkey`, a certificate stack `certs`,
    /// data `data` and flags `flags`, create a CmsContentInfo struct.
    ///
    /// All arguments are optional.
    ///
    /// OpenSSL documentation at [`CMS_sign`]
    ///
    /// [`CMS_sign`]: https://www.openssl.org/docs/manmaster/man3/CMS_sign.html
    pub fn sign<T: HasPrivate>(
        signcert: Option<&X509>,
        pkey: Option<&PKeyRef<T>>,
        certs: Option<&Stack<X509>>,
        data: Option<&[u8]>,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let signcert = match signcert {
                Some(cert) => cert.as_ptr(),
                None => ptr::null_mut(),
            };
            let pkey = match pkey {
                Some(pkey) => pkey.as_ptr(),
                None => ptr::null_mut(),
            };
            let data_bio_ptr = match data {
                Some(data) => MemBioSlice::new(data)?.as_ptr(),
                None => ptr::null_mut(),
            };
            let certs = match certs {
                Some(certs) => certs.as_ptr(),
                None => ptr::null_mut(),
            };

            let cms = cvt_p(ffi::CMS_sign(signcert, pkey, certs, data_bio_ptr, flags.bits()))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }
}
