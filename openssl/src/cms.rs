//! SMIME implementation using CMS
//!
//! CMS (PKCS#7) is an encyption standard.  It allows signing and ecrypting data using
//! X.509 certificates.  The OpenSSL implementation of CMS is used in email encryption
//! generated from a `Vec` of bytes.  This `Vec` follows the smime protocol standards.
//! Data accepted by this module will be smime type `enveloped-data`.

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use libc::c_void;
use std::ptr;

use asn1::Asn1Object;
use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use hash::MessageDigest;
use libc::c_uint;
use pkey::{HasPrivate, PKeyRef};
use stack::{Stack, StackRef};
use x509::store::X509Store;
use x509::{X509Ref, X509};
use {cvt, cvt_n, cvt_p};

pub struct CmsSignerInfoRef(Opaque);

impl ForeignTypeRef for CmsSignerInfoRef {
    type CType = ffi::CMS_SignerInfo;
}

pub struct CmsSignerInfo(*mut ffi::CMS_SignerInfo);

impl ForeignType for CmsSignerInfo {
    type CType = ffi::CMS_SignerInfo;
    type Ref = CmsSignerInfoRef;

    unsafe fn from_ptr(ptr: *mut ffi::CMS_SignerInfo) -> CmsSignerInfo {
        CmsSignerInfo(ptr)
    }

    fn as_ptr(&self) -> *mut ffi::CMS_SignerInfo {
        self.0
    }
}

impl CmsSignerInfo {
    pub fn add_attr(&mut self, obj: &Asn1Object, data_type: i32, data: &[u8]) -> i32 {
        unsafe {
            ffi::CMS_signed_add1_attr_by_OBJ(
                self.as_ptr(),
                obj.as_ptr(),
                data_type,
                data.as_ptr() as *const c_void,
                data.len() as i32,
            )
        }
    }

    pub fn sign(&mut self) -> i32 {
        unsafe { ffi::CMS_SignerInfo_sign(self.as_ptr()) }
    }
}

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

    to_der! {
    /// Serializes this CmsContentInfo using DER.
    ///
    /// OpenSSL documentation at [`i2d_CMS_ContentInfo`]
    ///
    /// [`i2d_CMS_ContentInfo`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_CMS_ContentInfo.html
    to_der,
    ffi::i2d_CMS_ContentInfo
    }

    from_der! {
    /// Deserializes this CmsContentInfo using DER.
    ///
    /// OpenSSL documentation at [`d2i_CMS_ContentInfo`]
    ///
    /// [`i2d_CMS_ContentInfo`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_CMS_ContentInfo.html
    from_der,
    CmsContentInfo,
    ffi::d2i_CMS_ContentInfo
    }

    pub fn add_signer<T: HasPrivate>(
        &mut self,
        signcert: &X509,
        pkey: &PKeyRef<T>,
        digest: Option<MessageDigest>,
        flags: CMSOptions,
    ) -> Result<CmsSignerInfo, ErrorStack> {
        let md_ptr = match digest {
            Some(md) => md.as_ptr(),
            None => ptr::null_mut(),
        };

        unsafe {
            Ok(ForeignType::from_ptr(cvt_p(ffi::CMS_add1_signer(
                self.as_ptr(),
                signcert.as_ptr(),
                pkey.as_ptr(),
                md_ptr,
                flags.bits(),
            ))?))
        }
    }

    pub fn finalize(
        &mut self,
        data: &[u8],
        dcont: Option<&MemBioSlice>,
        flags: CMSOptions,
    ) -> Result<(), ErrorStack> {
        unsafe {
            let bio = MemBioSlice::new(data)?;
            let dcont_ptr = match dcont {
                Some(p) => p.as_ptr(),
                None => ptr::null_mut(),
            };

            cvt(ffi::CMS_final(
                self.as_ptr(),
                bio.as_ptr(),
                dcont_ptr,
                flags.bits(),
            ))?;

            Ok(())
        }
    }

    pub fn verify(
        &mut self,
        certs: Option<&Stack<X509>>,
        store: Option<&X509Store>,
        data: Option<&[u8]>,
        output_data: Option<&mut Vec<u8>>,
        flags: CMSOptions,
    ) -> Result<bool, ErrorStack> {
        unsafe {
            let certs = match certs {
                Some(certs) => certs.as_ptr(),
                None => ptr::null_mut(),
            };
            let store = match store {
                Some(store) => store.as_ptr(),
                None => ptr::null_mut(),
            };
            let in_data = match data {
                Some(data) => MemBioSlice::new(data)?.as_ptr(),
                None => ptr::null_mut(),
            };
            let out_bio = MemBio::new()?;

            let is_valid = cvt_n(ffi::CMS_verify(
                self.as_ptr(),
                certs,
                store,
                in_data,
                out_bio.as_ptr(),
                flags.bits(),
            ))? == 1;

            if let Some(out_data) = output_data {
                out_data.clear();
                out_data.extend_from_slice(out_bio.get_buf());
            };

            Ok(is_valid)
        }
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

    pub fn partial(
        certs: Option<&Stack<X509>>,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack> {
        let certs = match certs {
            Some(certs) => certs.as_ptr(),
            None => ptr::null_mut(),
        };

        unsafe {
            Ok(CmsContentInfo::from_ptr(cvt_p(ffi::CMS_sign(
                ptr::null_mut(),
                ptr::null_mut(),
                certs,
                ptr::null_mut(),
                flags.bits(),
            ))?))
        }
    }
}
