use libc::*;

use crate::{ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, GENERAL_NAME};
pub enum TS_MSG_IMPRINT {}
pub enum TS_REQ {}
pub enum TS_ACCURACY {}
pub enum TS_TST_INFO {}

extern "C" {
    pub fn i2d_TS_TST_INFO(a: *const TS_TST_INFO, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_TST_INFO(
        a: *mut *mut ::TS_TST_INFO,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::TS_TST_INFO;
    pub fn TS_TST_INFO_free(a: *mut ::TS_TST_INFO);
    pub fn TS_TST_INFO_dup(a: *mut TS_TST_INFO) -> *mut TS_TST_INFO;

    pub fn TS_TST_INFO_get_version(a: *const ::TS_TST_INFO) -> c_long;
    pub fn TS_TST_INFO_get_policy_id(a: *mut ::TS_TST_INFO) -> *mut ::ASN1_OBJECT;
    pub fn TS_TST_INFO_get_msg_imprint(a: *mut ::TS_TST_INFO) -> *mut ::TS_MSG_IMPRINT;
    pub fn TS_TST_INFO_get_serial(a: *const ::TS_TST_INFO) -> *const ::ASN1_INTEGER;
    pub fn TS_TST_INFO_get_time(a: *const ::TS_TST_INFO) -> *const ::ASN1_GENERALIZEDTIME;
    pub fn TS_TST_INFO_get_accuracy(a: *mut ::TS_TST_INFO) -> *mut ::TS_ACCURACY;
    pub fn TS_TST_INFO_get_ordering(a: *const ::TS_TST_INFO) -> c_int;
    pub fn TS_TST_INFO_get_nonce(a: *const ::TS_TST_INFO) -> *const ::ASN1_INTEGER;
    pub fn TS_TST_INFO_get_tsa(a: *mut ::TS_TST_INFO) -> *mut ::GENERAL_NAME;
    pub fn TS_TST_INFO_get_exts(a: *mut ::TS_TST_INFO) -> *mut ::stack_st_X509_EXTENSION;

    pub fn PKCS7_to_TS_TST_INFO(token: *mut ::PKCS7) -> *mut ::TS_TST_INFO;

    pub fn TS_MSG_IMPRINT_new() -> *mut ::TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_free(a: *mut ::TS_MSG_IMPRINT);
    pub fn i2d_TS_MSG_IMPRINT(a: *const ::TS_MSG_IMPRINT, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_MSG_IMPRINT(
        a: *mut *mut ::TS_MSG_IMPRINT,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_dup(a: *mut ::TS_MSG_IMPRINT) -> *mut ::TS_MSG_IMPRINT;

    pub fn TS_MSG_IMPRINT_get_algo(a: *mut ::TS_MSG_IMPRINT) -> *mut ::X509_ALGOR;
    pub fn TS_MSG_IMPRINT_get_msg(a: *mut ::TS_MSG_IMPRINT) -> *mut ::ASN1_OCTET_STRING;

    pub fn TS_ACCURACY_new() -> *mut ::TS_ACCURACY;
    pub fn TS_ACCURACY_free(a: *mut ::TS_ACCURACY);
    pub fn i2d_TS_ACCURACY(a: *const ::TS_ACCURACY, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_ACCURACY(
        a: *mut *mut ::TS_ACCURACY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::TS_ACCURACY;
    pub fn TS_ACCURACY_dup(a: *mut ::TS_ACCURACY) -> *mut ::TS_ACCURACY;

    pub fn TS_ACCURACY_get_seconds(a: *const ::TS_ACCURACY) -> *const ::ASN1_INTEGER;
    pub fn TS_ACCURACY_get_millis(a: *const ::TS_ACCURACY) -> *const ::ASN1_INTEGER;
    pub fn TS_ACCURACY_get_micros(a: *const ::TS_ACCURACY) -> *const ::ASN1_INTEGER;
}
