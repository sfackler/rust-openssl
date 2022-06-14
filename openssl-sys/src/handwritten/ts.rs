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

/*
pub fn i2d_TS_REQ(const TS_REQ *a, unsigned char **pp) -> c_int;
pub fn d2i_TS_REQ(TS_REQ **a, const unsigned char **pp, long length) -> *mut TS_REQ;

STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
void TS_REQ_ext_free(TS_REQ *a);
int TS_REQ_get_ext_count(TS_REQ *a);
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos);
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos);
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos);
X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc);
X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc);
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);

*/
}

pub enum TS_RESP {}

pub enum TS_MSG_IMPRINT {}
