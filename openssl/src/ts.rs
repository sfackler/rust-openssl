use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::asn1::Asn1IntegerRef;
use crate::nid::Nid;
use crate::stack::StackRef;
use crate::x509::{X509ExtensionRef, X509Extension};
use crate::{asn1::Asn1ObjectRef, cvt_n, cvt_p, cvt_cp};
use crate::error::ErrorStack;

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_REQ;
    fn drop = ffi::TS_REQ_free;

    pub struct TSReq;

    pub struct TSReqRef;
}

impl TSReq {
    #[corresponds(TS_REQ_new)]
    pub fn new() -> Result<TSReq, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(ffi::TS_REQ_new())?;
            Ok(TSReq::from_ptr(ptr))
        }
    }

    from_der! {
        /// Deserializes a DER-encoded TS request.
        #[corresponds(d2i_TS_REQ)]
        from_der,
        TSReq,
        ffi::d2i_TS_REQ
    }
}

impl TSReqRef {
    to_der! {
        /// Serializes the request to its standard DER encoding.
        #[corresponds(i2d_TS_REQ)]
        to_der,
        ffi::i2d_TS_REQ
    }

    pub fn set_version(&self, version: i64) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_set_version(self.as_ptr(), version))
                .map(|_| ())
        }
    }

    pub fn get_version(&self) -> i64 {
        unsafe {
            ffi::TS_REQ_get_version(self.as_ptr())
        }
    }

    pub fn set_msg_imprint(&self, msg: &TSMsgImprintRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_set_msg_imprint(self.as_ptr(), msg.as_ptr()))
                .map(|_| ())
        }
    }

    pub fn get_msg_imprint(&self) -> Result<&TSMsgImprintRef, ErrorStack> {
        unsafe {
            cvt_p(ffi::TS_REQ_get_msg_imprint(self.as_ptr()))
                .map(|a| TSMsgImprintRef::from_ptr(a))
        }
    }

    pub fn set_policy_id(&self, policy: &Asn1ObjectRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_set_policy_id(self.as_ptr(), policy.as_ptr() as *const _))
                .map(|_| ())
        }
    }

    pub fn get_policy_id(&self) -> Result<&Asn1ObjectRef, ErrorStack> {
        unsafe {
            cvt_p(ffi::TS_REQ_get_policy_id(self.as_ptr()))
                .map(|a| Asn1ObjectRef::from_ptr(a))
        }
    }

    pub fn set_cert_req(&self, cert_req: i32) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_set_cert_req(self.as_ptr(), cert_req))
                .map(|_| ())
        }
    }

    pub fn get_cert_req(&self) -> i32 {
        unsafe {
            ffi::TS_REQ_get_cert_req(self.as_ptr())
        }
    }

    pub fn set_nonce(&self, nonce: &Asn1IntegerRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_set_nonce(self.as_ptr(), nonce.as_ptr() as *const _))
                .map(|_| ())
        }
    }

    pub fn get_nonce(&self) -> Result<&Asn1IntegerRef, ErrorStack> {
        unsafe {
            cvt_cp(ffi::TS_REQ_get_nonce(self.as_ptr() as *const _))
                .map(|a| Asn1IntegerRef::from_ptr(a as *mut _))
        }
    }

    pub fn get_ext_count(&self) -> i32 {
        unsafe {
            ffi::TS_REQ_get_ext_count(self.as_ptr())
        }
    }

    pub fn get_ext_by_nid(&self, nid: Nid) -> Result<i32, ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_get_ext_by_NID(self.as_ptr(), nid.as_raw(), -1))
                .map(|loc| loc)
        }
    }

    pub fn get_ext_by_obj(&self, obj: &Asn1ObjectRef) -> Result<i32, ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_get_ext_by_OBJ(self.as_ptr(), obj.as_ptr() as *const _, -1))
                .map(|loc| loc)
        }
    }

    pub fn get_ext_by_critical(&self, crit: i32) -> Result<i32, ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_get_ext_by_critical(self.as_ptr(), crit, -1))
                .map(|loc| loc)
        }
    }

    pub fn get_ext(&self, loc: i32) -> Result<&X509ExtensionRef, ErrorStack> {
        unsafe {
            cvt_p(ffi::TS_REQ_get_ext(self.as_ptr(), loc))
                .map(|ptr| X509ExtensionRef::from_ptr(ptr))
        }
    }

    pub fn delete_ext(&self, loc: i32) -> Result<&X509ExtensionRef, ErrorStack> {
        unsafe {
            cvt_p(ffi::TS_REQ_delete_ext(self.as_ptr(), loc))
                .map(|ptr| X509ExtensionRef::from_ptr(ptr))
        }
    }

    pub fn get_exts(&self) -> Result<&StackRef<X509Extension>, ErrorStack> {
        unsafe {
            cvt_p(ffi::TS_REQ_get_exts(self.as_ptr()))
                .map(|ptr| StackRef::from_ptr(ptr))
        }
    }

    pub fn add_ext(&self, ex: &X509ExtensionRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt_n(ffi::TS_REQ_add_ext(self.as_ptr(), ex.as_ptr(), -1))
                .map(|_| ())
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;

    pub struct TSMsgImprint;

    pub struct TSMsgImprintRef;
}
