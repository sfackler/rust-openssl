use libc::*;

use *;

/* fatal error */
pub const ERR_R_FATAL: c_int = 64;
pub const ERR_R_MALLOC_FAILURE: c_int = 1 | ERR_R_FATAL;
pub const ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED: c_int = 2 | ERR_R_FATAL;
pub const ERR_R_PASSED_NULL_PARAMETER: c_int = 3 | ERR_R_FATAL;
pub const ERR_R_INTERNAL_ERROR: c_int = 4 | ERR_R_FATAL;
pub const ERR_R_DISABLED: c_int = 5 | ERR_R_FATAL;
pub const ERR_R_INIT_FAIL: c_int = 6 | ERR_R_FATAL;
pub const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 7;

pub const ERR_TXT_MALLOCED: c_int = 0x01;
pub const ERR_TXT_STRING: c_int = 0x02;

/* library */
pub const ERR_LIB_NONE: c_int = 1;
pub const ERR_LIB_SYS: c_int = 2;
pub const ERR_LIB_BN: c_int = 3;
pub const ERR_LIB_RSA: c_int = 4;
pub const ERR_LIB_DH: c_int = 5;
pub const ERR_LIB_EVP: c_int = 6;
pub const ERR_LIB_BUF: c_int = 7;
pub const ERR_LIB_OBJ: c_int = 8;
pub const ERR_LIB_PEM: c_int = 9;
pub const ERR_LIB_DSA: c_int = 10;
pub const ERR_LIB_X509: c_int = 11;
pub const ERR_LIB_METH: c_int = 12;
pub const ERR_LIB_ASN1: c_int = 13;
pub const ERR_LIB_CONF: c_int = 14;
pub const ERR_LIB_CRYPTO: c_int = 15;
pub const ERR_LIB_EC: c_int = 16;
pub const ERR_LIB_SSL: c_int = 20;
pub const ERR_LIB_SSL23: c_int = 21;
pub const ERR_LIB_SSL2: c_int = 22;
pub const ERR_LIB_SSL3: c_int = 23;
pub const ERR_LIB_RSAREF: c_int = 30;
pub const ERR_LIB_PROXY: c_int = 31;
pub const ERR_LIB_BIO: c_int = 32;
pub const ERR_LIB_PKCS7: c_int = 33;
pub const ERR_LIB_X509V3: c_int = 34;
pub const ERR_LIB_PKCS12: c_int = 35;
pub const ERR_LIB_RAND: c_int = 36;
pub const ERR_LIB_DSO: c_int = 37;
pub const ERR_LIB_ENGINE: c_int = 38;
pub const ERR_LIB_OCSP: c_int = 39;
pub const ERR_LIB_UI: c_int = 40;
pub const ERR_LIB_COMP: c_int = 41;
pub const ERR_LIB_ECDSA: c_int = 42;
pub const ERR_LIB_ECDH: c_int = 43;
pub const ERR_LIB_STORE: c_int = 44;
pub const ERR_LIB_FIPS: c_int = 45;
pub const ERR_LIB_CMS: c_int = 46;
pub const ERR_LIB_TS: c_int = 47;
pub const ERR_LIB_HMAC: c_int = 48;
pub const ERR_LIB_JPAKE: c_int = 49;
pub const ERR_LIB_CT: c_int = 50;
pub const ERR_LIB_ASYNC: c_int = 51;
pub const ERR_LIB_KDF: c_int = 52;

pub const ERR_LIB_USER: c_int = 128;

const_fn! {
    pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
        ((l as c_ulong & 0x0FF) << 24) |
        ((f as c_ulong & 0xFFF) << 12) |
        ((r as c_ulong & 0xFFF))
    }

    pub const fn ERR_GET_LIB(l: c_ulong) -> c_int {
        ((l >> 24) & 0x0FF) as c_int
    }

    pub const fn ERR_GET_FUNC(l: c_ulong) -> c_int {
        ((l >> 12) & 0xFFF) as c_int
    }

    pub const fn ERR_GET_REASON(l: c_ulong) -> c_int {
        (l & 0xFFF) as c_int
    }
}

#[repr(C)]
pub struct ERR_STRING_DATA {
    pub error: c_ulong,
    pub string: *const c_char,
}

extern "C" {
    pub fn ERR_put_error(lib: c_int, func: c_int, reason: c_int, file: *const c_char, line: c_int);
    pub fn ERR_set_error_data(data: *mut c_char, flags: c_int);

    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_get_error_line_data(
        file: *mut *const c_char,
        line: *mut c_int,
        data: *mut *const c_char,
        flags: *mut c_int,
    ) -> c_ulong;
    pub fn ERR_peek_last_error() -> c_ulong;
    pub fn ERR_clear_error();
    pub fn ERR_lib_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_func_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_reason_error_string(err: c_ulong) -> *const c_char;
    #[cfg(ossl110)]
    pub fn ERR_load_strings(lib: c_int, str: *mut ERR_STRING_DATA) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ERR_load_strings(lib: c_int, str: *mut ERR_STRING_DATA);
    #[cfg(not(ossl110))]
    pub fn ERR_load_crypto_strings();

    pub fn ERR_get_next_error_library() -> c_int;

    #[cfg(not(ossl110))]
    pub fn ERR_set_implementation(fns: *const ERR_FNS) -> c_int;
}
