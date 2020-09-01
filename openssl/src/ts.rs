//! Partial interface to OpenSSL Time-Stamp Protocol (RFC 3161) implementation.
//!
//! This module provides a partial interface to OpenSSL's TSP implementation.
//! The aim is to provide enough functionality for a client to request and
//! verify timestamps returned by a Time Stamp Authority.
use bitflags::bitflags;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_uint};

use std::ptr;

use crate::asn1::{Asn1IntegerRef, Asn1ObjectRef};
use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::x509::X509Algorithm;
use crate::{cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;

    /// A message imprint contains the has of the data to be timestamped.
    pub struct TsMsgImprint;

    /// Reference to `TsMsgImprint`.
    pub struct TsMsgImprintRef;
}

impl TsMsgImprint {
    /// Creates a new message imprint.
    ///
    /// This corresponds to `TS_MSG_IMPRINT_new`.
    pub fn new() -> Result<TsMsgImprint, ErrorStack> {
        unsafe {
            ffi::init();
            let imprint: *mut ffi::TS_MSG_IMPRINT = cvt_p(ffi::TS_MSG_IMPRINT_new())?;
            Ok(TsMsgImprint::from_ptr(imprint))
        }
    }

    /// Sets the algorithm identifier of the message digest algorithm.
    ///
    /// This corresponds to `TS_MSG_IMPRINT_set_algo`.
    pub fn set_algo(&mut self, digest: &MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            let algorithm = X509Algorithm::from_ptr(cvt_p(ffi::X509_ALGOR_new())?);
            ffi::X509_ALGOR_set_md(algorithm.as_ptr(), digest.as_ptr());
            cvt(ffi::TS_MSG_IMPRINT_set_algo(
                self.as_ptr(),
                algorithm.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the message digest of the data to be timestamped.
    ///
    /// This corresponds to `TS_MSG_IMPRINT_set_msg`.
    pub fn set_msg(&mut self, digest: &[u8]) -> Result<(), ErrorStack> {
        let length = convert_digest_length_to_int(digest.len());
        unsafe {
            cvt(ffi::TS_MSG_IMPRINT_set_msg(
                self.as_ptr(),
                digest.as_ptr() as *mut _,
                length,
            ))
            .map(|_| ())
        }
    }
}

fn convert_digest_length_to_int(len: usize) -> c_int {
    if len > std::i32::MAX as usize {
        panic!("Digest length is too large");
    } else {
        len as i32
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::asn1::Asn1Integer;
    use crate::bn::BigNum;
    use crate::sha::sha512;

    #[test]
    fn test_request() {
        let mut imprint = TsMsgImprint::new().unwrap();
        imprint.set_algo(&MessageDigest::sha512()).unwrap();
        imprint.set_msg(&sha512(b"BLAHBLAHBLAH\n")).unwrap();

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
}
