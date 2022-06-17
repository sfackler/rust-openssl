use libc::*;
use *;

pub enum TS_REQ {}

extern "C" {
    pub fn TS_REQ_new() -> *mut TS_REQ;
    pub fn TS_REQ_free(a: *mut TS_REQ);

    pub fn TS_REQ_set_version(a: *mut TS_REQ, version: c_long) -> c_int;
    pub fn TS_REQ_get_version(a: *const TS_REQ) -> c_long;
    pub fn TS_REQ_set_msg_imprint(a: *mut TS_REQ, msg_imprint: *mut TS_MSG_IMPRINT) -> c_int;
    pub fn TS_REQ_get_msg_imprint(a: *mut TS_REQ) -> *mut TS_MSG_IMPRINT;
    pub fn TS_REQ_set_policy_id(a: *mut TS_REQ, policy: *const ASN1_OBJECT) -> c_int;
    pub fn TS_REQ_get_policy_id(a: *mut TS_REQ) -> *mut ASN1_OBJECT;
    pub fn TS_REQ_set_cert_req(a: *mut TS_REQ, cert_req: c_int) -> c_int;
    pub fn TS_REQ_get_cert_req(a: *const TS_REQ) -> c_int;
    pub fn TS_REQ_set_nonce(a: *mut TS_REQ, nonce: *const ASN1_INTEGER) -> c_int;
    pub fn TS_REQ_get_nonce(a: *const TS_REQ) -> *const ASN1_INTEGER;
    pub fn TS_REQ_get_ext_count(a: *mut TS_REQ) -> c_int;
    pub fn TS_REQ_get_ext_by_NID(a: *mut TS_REQ, nid: c_int, lastpos: c_int) -> c_int;
    pub fn TS_REQ_get_ext_by_OBJ(Ta: *mut TS_REQ, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int;
    pub fn TS_REQ_get_ext_by_critical(a: *mut TS_REQ, crit: c_int, lastpos: c_int) -> c_int;
    pub fn TS_REQ_get_ext(a: *mut TS_REQ, loc: c_int) -> *mut X509_EXTENSION;
    pub fn TS_REQ_delete_ext(a: *mut TS_REQ, loc: c_int) -> *mut X509_EXTENSION;
    pub fn TS_REQ_get_exts(a: *mut TS_REQ) -> *mut stack_st_X509_EXTENSION;
    pub fn i2d_TS_REQ(a: *const TS_REQ, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const c_uchar, length: c_long) -> *mut TS_REQ;

/*
void TS_REQ_ext_free(TS_REQ *a);
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);
*/
}

pub enum TS_RESP {}

pub enum TS_MSG_IMPRINT {}
