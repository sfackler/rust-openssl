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
    pub fn TS_REQ_add_ext(a: *mut TS_REQ, ex: *mut X509_EXTENSION, loc: c_int) -> c_int;
    pub fn i2d_TS_REQ(a: *const TS_REQ, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const c_uchar, length: c_long) -> *mut TS_REQ;
    // void TS_REQ_ext_free(TS_REQ *a);
    // void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);
}

pub enum TS_RESP {}

extern "C" {
    pub fn TS_RESP_get_status_info(a: *mut TS_RESP) -> *mut TS_STATUS_INFO;
    pub fn TS_RESP_set_status_info(a: *mut TS_RESP, info: *mut TS_STATUS_INFO) -> c_int;
    pub fn TS_RESP_get_tst_info(a: *mut TS_RESP) -> *mut TS_TST_INFO;
    pub fn TS_RESP_set_tst_info(a: *mut TS_RESP, p7: *mut PKCS7, tst_info: *mut TS_TST_INFO);
    pub fn TS_RESP_print_bio(bio: *mut BIO, a: *mut TS_RESP) -> c_int;
    pub fn TS_RESP_get_token(a: *mut TS_RESP) -> *mut PKCS7;
    pub fn d2i_TS_RESP_bio(bio: *mut BIO, a: *mut *mut TS_RESP) -> *mut TS_RESP;
    pub fn i2d_TS_RESP_bio(bio: *mut BIO, a: *const TS_RESP) -> c_int;
    // int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response);
    // int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);
}

pub enum TS_MSG_IMPRINT {}

extern "C" {
    pub fn TS_MSG_IMPRINT_free(a: *mut TS_MSG_IMPRINT);
    // TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a);
    // int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg);
    // X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a);
    // int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len);
    // ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a);
    // int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
    // TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a);
    // int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *msg);
    pub fn d2i_TS_MSG_IMPRINT_bio(bio: *mut BIO, a: *mut *mut TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT;
    pub fn i2d_TS_MSG_IMPRINT_bio(bio: *mut BIO, a: *const TS_MSG_IMPRINT) -> c_int;
}

pub enum TS_STATUS_INFO {}

extern "C" {
    pub fn TS_STATUS_INFO_free(a: *mut TS_STATUS_INFO);
    // int TS_STATUS_INFO_set_status(TS_STATUS_INFO *a, int i);
    // const ASN1_INTEGER *TS_STATUS_INFO_get0_status(const TS_STATUS_INFO *a);
    // const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);
    // const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);
    // int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a);
}

pub enum TS_TST_INFO {}

extern "C" {
    pub fn TS_TST_INFO_free(a: *mut TS_TST_INFO);
    // TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token);
    // int TS_TST_INFO_set_version(TS_TST_INFO *a, long version);
    // long TS_TST_INFO_get_version(const TS_TST_INFO *a);
    // int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
    // ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);
    // int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
    // TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a);
    // int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial);
    // const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a);
    // int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime);
    // const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a);
    // int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy);
    // TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);
    // int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering);
    // int TS_TST_INFO_get_ordering(const TS_TST_INFO *a);
    // int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
    // const ASN1_INTEGER *TS_TST_INFO_get_nonce(const TS_TST_INFO *a);
    // int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa);
    // GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a);
    // STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
    // void TS_TST_INFO_ext_free(TS_TST_INFO *a);
    // int TS_TST_INFO_get_ext_count(TS_TST_INFO *a);
    // int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos);
    // int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, const ASN1_OBJECT *obj, int lastpos);
    // int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos);
    // X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc);
    // X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc);
    // int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
    // void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx);
    // TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx);
    // int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a);
    // TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bio, TS_TST_INFO **a);
    // int i2d_TS_TST_INFO_bio(BIO *bio, const TS_TST_INFO *a);
}

pub enum TS_ACCURACY {}

extern "C" {
    pub fn TS_ACCURACY_free(a: *mut TS_ACCURACY);
    // TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);
    // int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds);
    // const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);
    // int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
    // const ASN1_INTEGER *TS_ACCURACY_get_millis(const TS_ACCURACY *a);
    // int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros);
    // const ASN1_INTEGER *TS_ACCURACY_get_micros(const TS_ACCURACY *a);
}
