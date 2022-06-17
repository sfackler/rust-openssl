use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::{cvt_n, cvt_p};
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
}
