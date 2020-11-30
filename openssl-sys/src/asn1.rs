use libc::*;

use *;

// ASN.1 tag values
pub const V_ASN1_EOC: c_int = 0;
pub const V_ASN1_BOOLEAN: c_int = 1;
pub const V_ASN1_INTEGER: c_int = 2;
pub const V_ASN1_BIT_STRING: c_int = 3;
pub const V_ASN1_OCTET_STRING: c_int = 4;
pub const V_ASN1_NULL: c_int = 5;
pub const V_ASN1_OBJECT: c_int = 6;
pub const V_ASN1_OBJECT_DESCRIPTOR: c_int = 7;
pub const V_ASN1_EXTERNAL: c_int = 8;
pub const V_ASN1_REAL: c_int = 9;
pub const V_ASN1_ENUMERATED: c_int = 10;
pub const V_ASN1_UTF8STRING: c_int = 12;
pub const V_ASN1_SEQUENCE: c_int = 16;
pub const V_ASN1_SET: c_int = 17;
pub const V_ASN1_NUMERICSTRING: c_int = 18;
pub const V_ASN1_PRINTABLESTRING: c_int = 19;
pub const V_ASN1_T61STRING: c_int = 20;
pub const V_ASN1_TELETEXSTRING: c_int = 20; // alias
pub const V_ASN1_VIDEOTEXSTRING: c_int = 21;
pub const V_ASN1_IA5STRING: c_int = 22;
pub const V_ASN1_UTCTIME: c_int = 23;
pub const V_ASN1_GENERALIZEDTIME: c_int = 24;
pub const V_ASN1_GRAPHICSTRING: c_int = 25;
pub const V_ASN1_ISO64STRING: c_int = 26;
pub const V_ASN1_VISIBLESTRING: c_int = 26; // alias
pub const V_ASN1_GENERALSTRING: c_int = 27;
pub const V_ASN1_UNIVERSALSTRING: c_int = 28;
pub const V_ASN1_BMPSTRING: c_int = 30;

pub const MBSTRING_FLAG: c_int = 0x1000;
pub const MBSTRING_UTF8: c_int = MBSTRING_FLAG;
pub const MBSTRING_ASC: c_int = MBSTRING_FLAG | 1;
pub const MBSTRING_BMP: c_int = MBSTRING_FLAG | 2;
pub const MBSTRING_UNIV: c_int = MBSTRING_FLAG | 4;

#[repr(C)]
pub struct ASN1_ENCODING {
    pub enc: *mut c_uchar,
    pub len: c_long,
    pub modified: c_int,
}

extern "C" {
    pub fn ASN1_OBJECT_free(x: *mut ASN1_OBJECT);
}

stack!(stack_st_ASN1_OBJECT);

extern "C" {
    pub fn ASN1_STRING_type_new(ty: c_int) -> *mut ASN1_STRING;
    #[cfg(any(ossl110, libressl273))]
    pub fn ASN1_STRING_get0_data(x: *const ASN1_STRING) -> *const c_uchar;
    #[cfg(any(all(ossl101, not(ossl110)), libressl))]
    pub fn ASN1_STRING_data(x: *mut ASN1_STRING) -> *mut c_uchar;

    pub fn ASN1_BIT_STRING_free(x: *mut ASN1_BIT_STRING);

    pub fn ASN1_STRING_free(x: *mut ASN1_STRING);
    pub fn ASN1_STRING_length(x: *const ASN1_STRING) -> c_int;

    pub fn ASN1_GENERALIZEDTIME_free(tm: *mut ASN1_GENERALIZEDTIME);
    pub fn ASN1_GENERALIZEDTIME_print(b: *mut BIO, tm: *const ASN1_GENERALIZEDTIME) -> c_int;
    pub fn ASN1_TIME_new() -> *mut ASN1_TIME;
    #[cfg(ossl102)]
    pub fn ASN1_TIME_diff(
        pday: *mut c_int,
        psec: *mut c_int,
        from: *const ASN1_TIME,
        to: *const ASN1_TIME,
    ) -> c_int;
    pub fn ASN1_TIME_free(tm: *mut ASN1_TIME);
    pub fn ASN1_TIME_print(b: *mut BIO, tm: *const ASN1_TIME) -> c_int;
    pub fn ASN1_TIME_set(from: *mut ASN1_TIME, to: time_t) -> *mut ASN1_TIME;

    pub fn ASN1_INTEGER_free(x: *mut ASN1_INTEGER);
    pub fn ASN1_INTEGER_get(dest: *const ASN1_INTEGER) -> c_long;
    pub fn ASN1_INTEGER_set(dest: *mut ASN1_INTEGER, value: c_long) -> c_int;
    pub fn BN_to_ASN1_INTEGER(bn: *const BIGNUM, ai: *mut ASN1_INTEGER) -> *mut ASN1_INTEGER;
    pub fn ASN1_INTEGER_to_BN(ai: *const ASN1_INTEGER, bn: *mut BIGNUM) -> *mut BIGNUM;

    pub fn ASN1_TIME_set_string(s: *mut ASN1_TIME, str: *const c_char) -> c_int;
    #[cfg(ossl111)]
    pub fn ASN1_TIME_set_string_X509(s: *mut ASN1_TIME, str: *const c_char) -> c_int;
}

const_ptr_api! {
    extern "C" {
        pub fn ASN1_STRING_to_UTF8(out: *mut *mut c_uchar, s: #[const_ptr_if(any(ossl110, libressl280))] ASN1_STRING) -> c_int;
    }
}
