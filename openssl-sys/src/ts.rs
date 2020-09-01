use libc::*;

#[allow(unused_imports)]
use *;

pub enum TS_MSG_IMPRINT {}
pub enum TS_REQ {}
pub enum TS_RESP {}

cfg_if! {
    if #[cfg(ossl110)] {
        pub enum TS_VERIFY_CTX {}
    } else {
        #[repr(C)]
        pub struct TS_VERIFY_CTX {
            flags: c_uint,
            store: *mut X509_STORE,
            certs: *mut stack_st_X509,
            policy: *mut ASN1_OBJECT,
            md_alg: *mut X509_ALGOR,
            imprint: *mut c_uchar,
            imprint_len: c_uint,
            data: *mut BIO,
            nonce: *mut ASN1_INTEGER,
            tsa_name: *mut GENERAL_NAME,
        }
    }
}

pub const TS_VFY_SIGNATURE: c_uint = 0x1;
pub const TS_VFY_VERSION: c_uint = 0x2;
pub const TS_VFY_POLICY: c_uint = 0x4;
pub const TS_VFY_IMPRINT: c_uint = 0x8;
pub const TS_VFY_DATA: c_uint = 0x10;
pub const TS_VFY_NONCE: c_uint = 0x20;
pub const TS_VFY_SIGNER: c_uint = 0x40;
pub const TS_VFY_TSA_NAME: c_uint = 0x80;

pub const TS_VFY_ALL_IMPRINT: c_uint = TS_VFY_SIGNATURE
    | TS_VFY_VERSION
    | TS_VFY_POLICY
    | TS_VFY_IMPRINT
    | TS_VFY_NONCE
    | TS_VFY_SIGNER
    | TS_VFY_TSA_NAME;
pub const TS_VFY_ALL_DATA: c_uint = TS_VFY_SIGNATURE
    | TS_VFY_VERSION
    | TS_VFY_POLICY
    | TS_VFY_DATA
    | TS_VFY_NONCE
    | TS_VFY_SIGNER
    | TS_VFY_TSA_NAME;

extern "C" {
    pub fn TS_MSG_IMPRINT_new() -> *mut TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_free(a: *mut TS_MSG_IMPRINT);
    pub fn TS_MSG_IMPRINT_set_algo(a: *mut TS_MSG_IMPRINT, alg: *mut X509_ALGOR) -> c_int;
    pub fn TS_MSG_IMPRINT_set_msg(a: *mut TS_MSG_IMPRINT, d: *mut c_uchar, length: c_int) -> c_int;

    pub fn TS_REQ_new() -> *mut TS_REQ;
    pub fn TS_REQ_free(a: *mut TS_REQ);
    pub fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const c_uchar, length: c_long) -> *mut TS_REQ;
    pub fn i2d_TS_REQ(a: *const TS_REQ, pp: *mut *mut c_uchar) -> c_int;
    pub fn TS_REQ_set_version(a: *mut TS_REQ, version: c_long) -> c_int;
    pub fn TS_REQ_set_msg_imprint(a: *mut TS_REQ, msg_imprint: *mut TS_MSG_IMPRINT) -> c_int;
    pub fn TS_REQ_set_nonce(a: *mut TS_REQ, nonce: *const ASN1_INTEGER) -> c_int;
    pub fn TS_REQ_set_cert_req(a: *mut TS_REQ, cert_req: c_int) -> c_int;

    pub fn TS_RESP_new() -> *mut TS_RESP;
    pub fn TS_RESP_free(a: *mut TS_RESP);
    pub fn d2i_TS_RESP(
        a: *mut *mut TS_RESP,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_RESP;
    pub fn i2d_TS_RESP(a: *const TS_RESP, pp: *mut *mut c_uchar) -> c_int;

    pub fn TS_VERIFY_CTX_new() -> *mut TS_VERIFY_CTX;
    pub fn TS_VERIFY_CTX_free(ctx: *mut TS_VERIFY_CTX);
    #[cfg(ossl110)]
    pub fn TS_VERIFY_CTX_set_imprint(
        ctx: *mut TS_VERIFY_CTX,
        hexstr: *mut c_uchar,
        length: c_long,
    ) -> *mut c_uchar;
    pub fn TS_RESP_verify_response(ctx: *mut TS_VERIFY_CTX, response: *mut TS_RESP) -> c_int;

    pub fn TS_REQ_to_TS_VERIFY_CTX(req: *mut TS_REQ, ctx: *mut TS_VERIFY_CTX)
        -> *mut TS_VERIFY_CTX;
}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn TS_REQ_set_policy_id(
                a: *mut TS_REQ,
                policy: *const ASN1_OBJECT
            ) -> c_int;
        }
    } else {
        extern "C" {
            pub fn TS_REQ_set_policy_id(
                a: *mut TS_REQ,
                policy: *mut ASN1_OBJECT
            ) -> c_int;
        }
    }
}
