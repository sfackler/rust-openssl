//! Partial interface to OpenSSL Time-Stamp Protocol (RFC 3161) implementation.
//!
//! This module provides a partial interface to OpenSSL's TSP implementation.
//! The aim is to provide enough functionality for a client to request and
//! verify timestamps returned by a Time Stamp Authority.
use bitflags::bitflags;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_uint};
use openssl_macros::corresponds;

use std::convert::TryFrom;
use std::ptr;

use crate::asn1::{Asn1IntegerRef, Asn1ObjectRef};
use crate::bio::MemBioSlice;
use crate::error::ErrorStack;
use crate::hash::{Hasher, MessageDigest};
use crate::pkey::{HasPrivate, PKeyRef};
use crate::x509::{X509Algorithm, X509AlgorithmRef, X509Ref};
use crate::{cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;

    /// A message imprint contains the hash of the data to be timestamped.
    pub struct TsMsgImprint;

    /// Reference to `TsMsgImprint`.
    pub struct TsMsgImprintRef;
}

impl TsMsgImprint {
    /// Creates a new message imprint.
    ///
    /// This corresponds to `TS_MSG_IMPRINT_new`.
    pub fn new() -> Result<TsMsgImprint, ErrorStack> {
        ffi::init();
        unsafe {
            let imprint = cvt_p(ffi::TS_MSG_IMPRINT_new())?;
            Ok(TsMsgImprint::from_ptr(imprint))
        }
    }

    /// Sets the algorithm identifier of the message digest algorithm.
    #[corresponds(TS_MSG_IMPRINT_set_algo)]
    pub fn set_algo(&mut self, algo: &X509AlgorithmRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_MSG_IMPRINT_set_algo(self.as_ptr(), algo.as_ptr())).map(|_| ()) }
    }

    /// Sets the message **digest** of the data to be timestamped.
    /// It is named this way to match the name in openssl itself
    #[corresponds(TS_MSG_IMPRINT_set_msg)]
    pub fn set_msg(&mut self, digest: &[u8]) -> Result<(), ErrorStack> {
        let len = if digest.len() > c_int::MAX as usize {
            panic!("digest length is too large");
        } else {
            digest.len() as c_int
        };

        unsafe {
            cvt(ffi::TS_MSG_IMPRINT_set_msg(
                self.as_ptr(),
                digest.as_ptr() as *mut _,
                len,
            ))
            .map(|_| ())
        }
    }

    /// Creates a ready-to-use message imprint from a message and a specified hash algorithm.
    pub fn from_message_with_algo(msg: &[u8], md: MessageDigest) -> Result<Self, ErrorStack> {
        let mut h = Hasher::new(md)?;
        h.update(msg)?;
        let hash = h.finish()?;
        Self::from_prehash_with_algo(&hash, md)
    }

    /// Creates a ready-to-use message imprint from the hash of a message and a specified hash algorithm.
    ///
    /// `hash` must have originated from the hash function specified by `md`.
    pub fn from_prehash_with_algo(hash: &[u8], md: MessageDigest) -> Result<Self, ErrorStack> {
        let mut algo = X509Algorithm::new()?;
        algo.set_md(md);

        let mut imprint = Self::new()?;
        imprint.set_algo(&algo)?;
        imprint.set_msg(hash)?;

        Ok(imprint)
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_REQ;
    fn drop = ffi::TS_REQ_free;

    /// A timestamp request.
    pub struct TsReq;

    /// Reference to `TsReq`.
    pub struct TsReqRef;
}

impl TsReq {
    from_der! {
        /// Deserializes a DER-encoded TimeStampReq structure.
        ///
        /// This corresponds to [`d2i_TS_REQ`].
        ///
        /// [`d2i_TS_REQ`]: https://www.openssl.org/docs/man1.1.0/man3/d2i_TS_REQ.html
        from_der,
        TsReq,
        ffi::d2i_TS_REQ
    }
}

impl TsReqRef {
    to_der! {
        /// Serializes the timestamp request into a DER-encoded TimeStampReq structure.
        ///
        /// This corresponds to [`i2d_TS_REQ`].
        ///
        /// [`i2d_TS_REQ`]: https://www.openssl.org/docs/man1.1.0/man3/i2d_TS_REQ.html
        to_der,
        ffi::i2d_TS_REQ
    }
}

impl TsReq {
    /// Creates a new timestamp request.
    ///
    /// This corresponds to `TS_REQ_new`.
    pub fn new() -> Result<TsReq, ErrorStack> {
        unsafe {
            ffi::init();
            let req: *mut ffi::TS_REQ = cvt_p(ffi::TS_REQ_new())?;
            Ok(TsReq::from_ptr(req))
        }
    }

    /// Set the version of the timestamp request.
    ///
    /// RFC 3161 requires this to be 1.
    ///
    /// This corresponds to `TS_REQ_set_version`.
    pub fn set_version(&mut self, version: c_long) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_REQ_set_version(self.as_ptr(), version)).map(|_| ()) }
    }

    /// Set the message imprint.
    ///
    /// This corresponds to `TS_REQ_set_msg_imprint`.
    pub fn set_msg_imprint(&mut self, imprint: &TsMsgImprintRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_REQ_set_msg_imprint(self.as_ptr(), imprint.as_ptr())).map(|_| ()) }
    }

    /// Sets the OID of the policy under which we're requesting the timestamp.
    ///
    /// This corresponds to `TS_REQ_set_policy_id`.
    pub fn set_policy_id(&mut self, policy: &Asn1ObjectRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_REQ_set_policy_id(self.as_ptr(), policy.as_ptr())).map(|_| ()) }
    }

    /// Sets the nonce.
    ///
    /// This corresopnds to `TS_REQ_set_nonce`.
    pub fn set_nonce(&mut self, nonce: &Asn1IntegerRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_REQ_set_nonce(self.as_ptr(), nonce.as_ptr())).map(|_| ()) }
    }

    /// Sets whether to request the public key certificate in the response.
    ///
    /// This corresponds to `TS_REQ_set_cert_req`.
    pub fn set_cert_req(&mut self, cert_req: bool) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_REQ_set_cert_req(self.as_ptr(), cert_req as c_int)).map(|_| ()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_RESP;
    fn drop = ffi::TS_RESP_free;

    /// A time-stamping response.
    pub struct TsResp;

    /// Reference to `TsResp`.
    pub struct TsRespRef;
}

impl TsResp {
    from_der! {
        /// Deserializes a DER-encoded TimeStampResp structure.
        ///
        /// This corresponds to [`d2i_TS_RESP`].
        ///
        /// [`d2i_TS_RESP`]: https://www.openssl.org/docs/man1.1.0/man3/d2i_TS_RESP.html
        from_der,
        TsResp,
        ffi::d2i_TS_RESP
    }
}

impl TsRespRef {
    to_der! {
        /// Serializes the timestamp request into a DER-encoded TimeStampResp structure.
        ///
        /// This corresponds to [`i2d_TS_RESP`].
        ///
        /// [`i2d_TS_RESP`]: https://www.openssl.org/docs/man1.1.0/man3/i2d_TS_RESP.html
        to_der,
        ffi::i2d_TS_RESP
    }

    /// Verifies a timestamp response.
    ///
    /// This corresponds to `TS_RESP_verify_response`.
    pub fn verify(&self, context: &TsVerifyContext) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::TS_RESP_verify_response(
                context.as_ptr(),
                self.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}

bitflags! {
    /// Flags controlling timestamp verification behaviour.
    pub struct VerifyFlags: c_uint {
        const SIGNATURE = ffi::TS_VFY_SIGNATURE;
        const VERSION = ffi::TS_VFY_VERSION;
        const POLICY = ffi::TS_VFY_POLICY;
        const IMPRINT = ffi::TS_VFY_IMPRINT;
        const DATA = ffi::TS_VFY_DATA;
        const NONCE = ffi::TS_VFY_NONCE;
        const SIGNER = ffi::TS_VFY_SIGNER;
        const TSA_NAME = ffi::TS_VFY_TSA_NAME;

        const ALL_IMPRINT = ffi::TS_VFY_ALL_IMPRINT;
        const ALL_DATA = ffi::TS_VFY_ALL_DATA;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_VERIFY_CTX;
    fn drop = ffi::TS_VERIFY_CTX_free;

    /// A context object specifying time-stamping response verification parameters.
    pub struct TsVerifyContext;

    /// Reference to `TsVerifyContext`.
    pub struct TsVerifyContextRef;
}

impl TsVerifyContext {
    /// Construct a verify context from a timestamping request.
    ///
    /// Corresponds to `TS_REQ_to_TS_VERIFY_CTX`.
    pub fn from_req(request: &TsReqRef) -> Result<TsVerifyContext, ErrorStack> {
        unsafe {
            let ctx = cvt_p(ffi::TS_REQ_to_TS_VERIFY_CTX(
                request.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(TsVerifyContext::from_ptr(ctx))
        }
    }
}

impl TryFrom<&TsReqRef> for TsVerifyContext {
    type Error = ErrorStack;

    fn try_from(value: &TsReqRef) -> Result<Self, Self::Error> {
        Self::from_req(value)
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_RESP_CTX;
    fn drop = ffi::TS_RESP_CTX_free;

    /// A context object used to sign timestamp requests.
    pub struct TsRespContext;

    /// Reference to `TsRespContext`.
    pub struct TsRespContextRef;
}

impl TsRespContextRef {
    /// Creates a signed timestamp response for the request.
    ///
    /// This corresponds to `TS_RESP_create_response`.
    pub fn create_response(&mut self, request: &TsReqRef) -> Result<TsResp, ErrorStack> {
        unsafe {
            let der = request.to_der()?;
            let bio = MemBioSlice::new(&der)?;
            let response = cvt_p(ffi::TS_RESP_create_response(self.as_ptr(), bio.as_ptr()))?;
            Ok(TsResp::from_ptr(response))
        }
    }
}

impl TsRespContext {
    /// Creates a new response context.
    ///
    /// This corresponds to `TS_RESP_CTX_new`.
    pub fn new() -> Result<TsRespContext, ErrorStack> {
        unsafe {
            ffi::init();
            let resp_context: *mut ffi::TS_RESP_CTX = cvt_p(ffi::TS_RESP_CTX_new())?;
            Ok(TsRespContext::from_ptr(resp_context))
        }
    }

    /// Sets the OID of the default policy used by the TSA.
    ///
    /// This corresponds to `TS_RESP_CTX_set_def_policy`.
    pub fn set_default_policy(&mut self, policy: &Asn1ObjectRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::TS_RESP_CTX_set_def_policy(
                self.as_ptr(),
                policy.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the certificate the TSA uses to sign the request.
    ///
    /// This corresponds to `TS_RESP_CTX_set_signer_cert`.
    pub fn set_signer_cert(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::TS_RESP_CTX_set_signer_cert(
                self.as_ptr(),
                cert.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the private key the TSA uses to sign the request.
    ///
    /// The private key match the X.509 certificate set by `set_signer_cert`.
    ///
    /// This corresponds to `TS_RESP_CTX_set_signer_key`.
    pub fn set_signer_key<T>(&mut self, pkey: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            cvt(ffi::TS_RESP_CTX_set_signer_key(
                self.as_ptr(),
                pkey.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the message digest algorithm to use for the signature.
    ///
    ///
    /// Requires OpenSSL 1.1.0 or newer.
    /// This corresponds to `TS_RESP_CTX_set_signer_digest`.
    #[cfg(ossl110)]
    pub fn set_signer_digest(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::TS_RESP_CTX_set_signer_digest(
                self.as_ptr(),
                md.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Add an accepted message digest algorithm.
    ///
    /// At least one accepted digest algorithm should be added to the context.
    ///
    /// This corresponds to `TS_RESP_CTX_add_md`.
    pub fn add_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::TS_RESP_CTX_add_md(self.as_ptr(), md.as_ptr())).map(|_| ()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::asn1::{Asn1Integer, Asn1Object};
    use crate::bn::BigNum;
    use crate::hash::MessageDigest;
    use crate::pkey::PKey;
    use crate::x509::X509;

    #[test]
    fn test_request() {
        let imprint =
            TsMsgImprint::from_message_with_algo(b"BLAHBLAHBLAH\n", MessageDigest::sha512())
                .unwrap();

        let mut request = TsReq::new().unwrap();
        request.set_version(1).unwrap();
        request.set_msg_imprint(&imprint).unwrap();
        request.set_cert_req(true).unwrap();
        let nonce =
            Asn1Integer::from_bn(&BigNum::from_hex_str("F3AA393032C93DC1").unwrap()).unwrap();
        request.set_nonce(&nonce).unwrap();

        let der = request.to_der().unwrap();

        let request = TsReq::from_der(&der).unwrap();
        assert_eq!(request.to_der().unwrap(), der);
    }

    #[test]
    fn test_response_der_serialization() {
        let original_der = include_bytes!("../test/ts-response.der").to_vec();
        let response = TsResp::from_der(&original_der).unwrap();
        let der = response.to_der().unwrap();
        assert_eq!(der, original_der);
    }

    #[test]
    fn test_verify() {
        let request = TsReq::from_der(include_bytes!("../test/ts-request.der")).unwrap();
        let response = TsResp::from_der(include_bytes!("../test/ts-response.der")).unwrap();

        let context = TsVerifyContext::from_req(&request).unwrap();
        response.verify(&context).unwrap();
    }

    #[test]
    fn test_response_context() {
        let mut response_context = TsRespContext::new().unwrap();
        response_context
            .set_default_policy(&Asn1Object::from_str("1.2.3.4").unwrap())
            .unwrap();
        let cert = X509::from_pem(include_bytes!("../test/ts-cert.pem")).unwrap();
        response_context.set_signer_cert(&cert).unwrap();
        let key = PKey::private_key_from_pem(include_bytes!("../test/ts-key.pem")).unwrap();
        response_context.set_signer_key(&key).unwrap();

        response_context.add_md(MessageDigest::sha512()).unwrap();

        let request = TsReq::from_der(include_bytes!("../test/ts-request.der")).unwrap();
        let response = response_context.create_response(&request).unwrap();

        let context = TsVerifyContext::from_req(&request).unwrap();
        response.verify(&context).unwrap();
    }
}
