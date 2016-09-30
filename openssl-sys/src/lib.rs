#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(dead_code, overflowing_literals)]
#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/v0.7.17")]

extern crate libc;

use libc::{c_void, c_int, c_char, c_ulong, c_long, c_uint, c_uchar, size_t, FILE};
use std::ptr;

#[cfg(any(ossl101, ossl102))]
mod ossl10x;
#[cfg(any(ossl101, ossl102))]
pub use ossl10x::*;

#[cfg(ossl110)]
mod ossl110;
#[cfg(ossl110)]
pub use ossl110::*;

pub enum ASN1_INTEGER {}
pub enum ASN1_STRING {}
pub enum ASN1_TIME {}
pub enum ASN1_TYPE {}
pub enum BN_CTX {}
pub enum BN_GENCB {}
pub enum COMP_METHOD {}
pub enum ENGINE {}
pub enum EVP_CIPHER_CTX {}
pub enum EVP_MD {}
pub enum EVP_PKEY_CTX {}
pub enum SSL {}
pub enum SSL_CIPHER {}
pub enum SSL_METHOD {}
pub enum X509_CRL {}
pub enum X509_EXTENSION {}
pub enum X509_NAME {}
pub enum X509_NAME_ENTRY {}
pub enum X509_REQ {}
pub enum X509_STORE_CTX {}
pub enum bio_st {}
pub enum PKCS12 {}
pub enum DH_METHOD {}

pub type bio_info_cb = Option<unsafe extern "C" fn(*mut BIO,
                                                   c_int,
                                                   *const c_char,
                                                   c_int,
                                                   c_long,
                                                   c_long)>;

pub enum RSA_METHOD {}
pub enum BN_MONT_CTX {}
pub enum BN_BLINDING {}
pub enum DSA_METHOD {}
pub enum EVP_PKEY_ASN1_METHOD {}

#[repr(C)]
pub struct GENERAL_NAME {
    pub type_: c_int,
    pub d: *mut c_void,
}

#[repr(C)]
pub struct X509V3_CTX {
    flags: c_int,
    issuer_cert: *mut c_void,
    subject_cert: *mut c_void,
    subject_req: *mut c_void,
    crl: *mut c_void,
    db_meth: *mut c_void,
    db: *mut c_void,
    // I like the last comment line, it is copied from OpenSSL sources:
    // Maybe more here
}

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = libc::c_ulonglong;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = c_uint;

pub type CRYPTO_EX_new = extern "C" fn(parent: *mut c_void, ptr: *mut c_void,
                                       ad: *const CRYPTO_EX_DATA, idx: c_int,
                                       argl: c_long, argp: *const c_void) -> c_int;
pub type CRYPTO_EX_dup = extern "C" fn(to: *mut CRYPTO_EX_DATA,
                                       from: *mut CRYPTO_EX_DATA, from_d: *mut c_void,
                                       idx: c_int, argl: c_long, argp: *mut c_void)
                                       -> c_int;
pub type CRYPTO_EX_free = extern "C" fn(parent: *mut c_void, ptr: *mut c_void,
                                        ad: *mut CRYPTO_EX_DATA, idx: c_int,
                                        argl: c_long, argp: *mut c_void);
pub type PasswordCallback = extern "C" fn(buf: *mut c_char, size: c_int,
                                          rwflag: c_int, user_data: *mut c_void)
                                          -> c_int;

pub const BIO_TYPE_NONE: c_int = 0;

pub const BIO_CTRL_EOF: c_int = 2;
pub const BIO_CTRL_INFO: c_int = 3;
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;

pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub const CRYPTO_LOCK: c_int = 1;

pub const EVP_MAX_MD_SIZE: c_uint = 64;
pub const EVP_PKEY_RSA: c_int = NID_rsaEncryption;

pub const MBSTRING_ASC:  c_int = MBSTRING_FLAG | 1;
pub const MBSTRING_BMP:  c_int = MBSTRING_FLAG | 2;
pub const MBSTRING_FLAG: c_int = 0x1000;
pub const MBSTRING_UNIV: c_int = MBSTRING_FLAG | 4;
pub const MBSTRING_UTF8: c_int = MBSTRING_FLAG;

pub const NID_rsaEncryption: c_int = 6;
pub const NID_ext_key_usage: c_int = 126;
pub const NID_key_usage:     c_int = 83;

pub const PKCS5_SALT_LEN: c_int = 8;

pub const RSA_F4: c_long = 0x10001;

pub const RSA_PKCS1_PADDING: c_int = 1;
pub const RSA_SSLV23_PADDING: c_int = 2;
pub const RSA_NO_PADDING: c_int = 3;
pub const RSA_PKCS1_OAEP_PADDING: c_int = 4;
pub const RSA_X931_PADDING: c_int = 5;

pub const SSL_CTRL_SET_TMP_DH: c_int = 3;
pub const SSL_CTRL_EXTRA_CHAIN_CERT: c_int = 14;
pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:  c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;

pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 2;
pub const SSL_MODE_AUTO_RETRY: c_long = 4;

pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;

#[cfg(not(ossl101))]
pub const SSL_OP_TLSEXT_PADDING: c_ulong =                          0x00000010;
pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: c_ulong =             0x00000800;
pub const SSL_OP_ALL: c_ulong =                                     0x80000BFF;
pub const SSL_OP_NO_QUERY_MTU: c_ulong =                            0x00001000;
pub const SSL_OP_COOKIE_EXCHANGE: c_ulong =                         0x00002000;
pub const SSL_OP_NO_TICKET: c_ulong =                               0x00004000;
pub const SSL_OP_CISCO_ANYCONNECT: c_ulong =                        0x00008000;
pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: c_ulong =  0x00010000;
pub const SSL_OP_NO_COMPRESSION: c_ulong =                          0x00020000;
pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_ulong =       0x00040000;
pub const SSL_OP_CIPHER_SERVER_PREFERENCE: c_ulong =                0x00400000;
pub const SSL_OP_TLS_ROLLBACK_BUG: c_ulong =                        0x00800000;
pub const SSL_OP_NO_SSLv3: c_ulong =                                0x02000000;
pub const SSL_OP_NO_TLSv1: c_ulong =                                0x04000000;

// Intentionally not bound since they conflict with SSL_OP_PKCS1_CHECK_1 and
// SSL_OP_PKCS1_CHECK_2 on 0.9.8 :(
/*
pub const SSL_OP_NO_TLSv1_2: c_long =                               0x08000000;
pub const SSL_OP_NO_TLSv1_1: c_long =                               0x10000000;
pub const SSL_OP_NO_DTLSv1: c_long =                                0x04000000;
pub const SSL_OP_NO_DTLSv1_2: c_long =                              0x08000000;
pub const SSL_OP_NO_SSL_MASK: c_long = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
*/

pub const TLSEXT_NAMETYPE_host_name: c_int = 0;

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

pub const OPENSSL_NPN_UNSUPPORTED: c_int = 0;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;
pub const OPENSSL_NPN_NO_OVERLAP: c_int = 2;

pub const V_ASN1_GENERALIZEDTIME: c_int = 24;
pub const V_ASN1_UTCTIME:         c_int = 23;

pub const X509_FILETYPE_ASN1: c_int = 2;
pub const X509_FILETYPE_DEFAULT: c_int = 3;
pub const X509_FILETYPE_PEM: c_int = 1;
pub const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
pub const X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
pub const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
pub const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
pub const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
pub const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
pub const X509_V_ERR_CERT_REJECTED: c_int = 28;
pub const X509_V_ERR_CERT_REVOKED: c_int = 23;
pub const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
pub const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
pub const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
pub const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
pub const X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
pub const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
pub const X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
pub const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
pub const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
pub const X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
pub const X509_V_ERR_INVALID_CA: c_int = 24;
pub const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
pub const X509_V_ERR_INVALID_NON_CA: c_int = 37;
pub const X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
pub const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
pub const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
pub const X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
pub const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
pub const X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
pub const X509_V_ERR_OUT_OF_MEM: c_int = 17;
pub const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
pub const X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
pub const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
pub const X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
pub const X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
pub const X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
pub const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
pub const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
pub const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
pub const X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
pub const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
pub const X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
pub const X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
pub const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
pub const X509_V_OK: c_int = 0;

pub const GEN_OTHERNAME: c_int = 0;
pub const GEN_EMAIL: c_int = 1;
pub const GEN_DNS: c_int = 2;
pub const GEN_X400: c_int = 3;
pub const GEN_DIRNAME: c_int = 4;
pub const GEN_EDIPARTY: c_int = 5;
pub const GEN_URI: c_int = 6;
pub const GEN_IPADD: c_int = 7;
pub const GEN_RID: c_int = 8;

// macros
pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    BIO_ctrl(b, BIO_CTRL_INFO, 0, pp as *mut c_void)
}

pub unsafe fn BIO_clear_retry_flags(b: *mut BIO) {
    BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_read(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_write(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_tmp_dh(ctx: *mut SSL_CTX, dh: *mut DH) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh as *mut c_void)
}

pub unsafe fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509 as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tlsext_servername_callback(ctx: *mut SSL_CTX,
                                                     cb: Option<extern "C" fn()>)
                                                     -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb)
}

pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *mut c_char) -> c_long {
    SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME,
             TLSEXT_NAMETYPE_host_name as c_long,
             name as *mut c_void)
}

extern {
    pub fn ASN1_INTEGER_set(dest: *mut ASN1_INTEGER, value: c_long) -> c_int;
    pub fn ASN1_STRING_type_new(ty: c_int) -> *mut ASN1_STRING;
    pub fn ASN1_TIME_free(tm: *mut ASN1_TIME);
    pub fn ASN1_TIME_print(b: *mut BIO, tm: *const ASN1_TIME) -> c_int;

    pub fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn BIO_free_all(b: *mut BIO);
    pub fn BIO_new_fp(stream: *mut FILE, close_flag: c_int) -> *mut BIO;
    pub fn BIO_new_socket(sock: c_int, close_flag: c_int) -> *mut BIO;
    pub fn BIO_read(b: *mut BIO, buf: *mut c_void, len: c_int) -> c_int;
    pub fn BIO_write(b: *mut BIO, buf: *const c_void, len: c_int) -> c_int;
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    pub fn BIO_set_flags(b: *mut BIO, flags: c_int);
    pub fn BIO_clear_flags(b: *mut BIO, flags: c_int);

    pub fn BN_new() -> *mut BIGNUM;
    pub fn BN_dup(n: *const BIGNUM) -> *mut BIGNUM;
    pub fn BN_clear_free(bn: *mut BIGNUM);

    pub fn BN_CTX_new() -> *mut BN_CTX;
    pub fn BN_CTX_free(ctx: *mut BN_CTX);

    pub fn BN_num_bits(bn: *const BIGNUM) -> c_int;
    pub fn BN_set_negative(bn: *mut BIGNUM, n: c_int);
    pub fn BN_set_word(bn: *mut BIGNUM, n: BN_ULONG) -> c_int;

    /* Arithmetic operations on BIGNUMs */
    pub fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    pub fn BN_div(dv: *mut BIGNUM, rem: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_gcd(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_inverse(r: *mut BIGNUM, a: *const BIGNUM, n: *const BIGNUM, ctx: *mut BN_CTX) -> *mut BIGNUM;
    pub fn BN_mod_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_sqr(r: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_nnmod(rem: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_add_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_sub_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_mul_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_div_word(r: *mut BIGNUM, w: BN_ULONG) -> BN_ULONG;
    pub fn BN_mod_word(r: *const BIGNUM, w: BN_ULONG) -> BN_ULONG;
    pub fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> c_int;

    /* Bit operations on BIGNUMs */
    pub fn BN_clear_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_is_bit_set(a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int;
    pub fn BN_mask_bits(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_set_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int;

    /* Comparisons on BIGNUMs */
    pub fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    pub fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;

    /* Prime handling */
    pub fn BN_generate_prime_ex(r: *mut BIGNUM, bits: c_int, safe: c_int, add: *const BIGNUM, rem: *const BIGNUM, cb: *mut BN_GENCB) -> c_int;
    pub fn BN_is_prime_ex(p: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int;
    pub fn BN_is_prime_fasttest_ex(p: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, do_trial_division: c_int, cb: *mut BN_GENCB) -> c_int;

    /* Random number handling */
    pub fn BN_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    pub fn BN_pseudo_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    pub fn BN_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int;
    pub fn BN_pseudo_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int;

    /* Conversion from/to binary representation */
    pub fn BN_bin2bn(s: *const u8, size: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    pub fn BN_bn2bin(a: *const BIGNUM, to: *mut u8) -> c_int;

    /* Conversion from/to decimal string representation */
    pub fn BN_dec2bn(a: *mut *mut BIGNUM, s: *const c_char) -> c_int;
    pub fn BN_bn2dec(a: *const BIGNUM) -> *mut c_char;

    /* Conversion from/to hexidecimal string representation */
    pub fn BN_hex2bn(a: *mut *mut BIGNUM, s: *const c_char) -> c_int;
    pub fn BN_bn2hex(a: *const BIGNUM) -> *mut c_char;

    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void,
                         len: size_t) -> c_int;

    pub fn DH_free(dh: *mut DH);

    #[cfg(not(ossl101))]
    pub fn DH_get_1024_160() -> *mut DH;
    #[cfg(not(ossl101))]
    pub fn DH_get_2048_224() -> *mut DH;
    #[cfg(not(ossl101))]
    pub fn DH_get_2048_256() -> *mut DH;

    pub fn ERR_get_error() -> c_ulong;

    pub fn ERR_lib_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_func_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_reason_error_string(err: c_ulong) -> *const c_char;

    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_ripemd160() -> *const EVP_MD;
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha224() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_sha512() -> *const EVP_MD;

    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    // fn EVP_aes_128_gcm() -> EVP_CIPHER;
    pub fn EVP_aes_128_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    // fn EVP_aes_256_gcm() -> EVP_CIPHER;
    pub fn EVP_aes_256_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_rc4() -> *const EVP_CIPHER;

    pub fn EVP_des_cbc() -> *const EVP_CIPHER;
    pub fn EVP_des_ecb() -> *const EVP_CIPHER;

    pub fn EVP_BytesToKey(typ: *const EVP_CIPHER, md: *const EVP_MD,
                          salt: *const u8, data: *const u8, datalen: c_int,
                          count: c_int, key: *mut u8, iv: *mut u8) -> c_int;

    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, padding: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);

    pub fn EVP_CipherInit(ctx: *mut EVP_CIPHER_CTX, evp: *const EVP_CIPHER,
                          key: *const u8, iv: *const u8, mode: c_int) -> c_int;
    pub fn EVP_CipherInit_ex(ctx: *mut EVP_CIPHER_CTX,
                             type_: *const EVP_CIPHER,
                             impl_: *mut ENGINE,
                             key: *const c_uchar,
                             iv: *const c_uchar,
                             enc: c_int) -> c_int;
    pub fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX, outbuf: *mut u8,
                            outlen: *mut c_int, inbuf: *const u8, inlen: c_int) -> c_int;
    pub fn EVP_CipherFinal(ctx: *mut EVP_CIPHER_CTX, res: *mut u8, len: *mut c_int) -> c_int;

    pub fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD) -> c_int;
    pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD, imple: *mut ENGINE) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, n: size_t) -> c_int;
    pub fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;

    #[cfg_attr(any(ossl101, ossl102), link_name = "EVP_MD_CTX_create")]
    pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    pub fn EVP_MD_CTX_copy_ex(dst: *mut EVP_MD_CTX, src: *const EVP_MD_CTX) -> c_int;
    #[cfg_attr(any(ossl101, ossl102), link_name = "EVP_MD_CTX_destroy")]
    pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);

    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    pub fn EVP_PKEY_free(k: *mut EVP_PKEY);
    pub fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, typ: c_int, key: *mut c_void) -> c_int;
    pub fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_get1_RSA(k: *mut EVP_PKEY) -> *mut RSA;
    pub fn EVP_PKEY_set1_RSA(k: *mut EVP_PKEY, r: *mut RSA) -> c_int;
    pub fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    pub fn HMAC_CTX_copy(dst: *mut HMAC_CTX, src: *mut HMAC_CTX) -> c_int;

    pub fn PEM_read_bio_DHparams(bio: *mut BIO, out: *mut *mut DH, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut DH;
    pub fn PEM_read_bio_X509(bio: *mut BIO, out: *mut *mut X509, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut X509;
    pub fn PEM_read_bio_X509_REQ(bio: *mut BIO, out: *mut *mut X509_REQ, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut X509_REQ;
    pub fn PEM_read_bio_PrivateKey(bio: *mut BIO, out: *mut *mut EVP_PKEY, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut EVP_PKEY;
    pub fn PEM_read_bio_PUBKEY(bio: *mut BIO, out: *mut *mut EVP_PKEY, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut EVP_PKEY;

    pub fn PEM_read_bio_RSAPrivateKey(bio: *mut BIO, rsa: *mut *mut RSA, callback: Option<PasswordCallback>, user_data: *mut c_void) -> *mut RSA;
    pub fn PEM_read_bio_RSA_PUBKEY(bio:    *mut BIO, rsa: *mut *mut RSA, callback: Option<PasswordCallback>, user_data: *mut c_void) -> *mut RSA;

    pub fn PEM_write_bio_PrivateKey(bio: *mut BIO, pkey: *mut EVP_PKEY, cipher: *const EVP_CIPHER,
                                    kstr: *mut c_uchar, klen: c_int,
                                    callback: Option<PasswordCallback>,
                                    user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_PUBKEY(bp: *mut BIO, x: *mut EVP_PKEY) -> c_int;
    pub fn PEM_write_bio_RSAPrivateKey(bp: *mut BIO, rsa: *mut RSA, cipher: *const EVP_CIPHER,
                                        kstr: *mut c_uchar, klen: c_int,
                                        callback: Option<PasswordCallback>,
                                        user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_RSAPublicKey(bp: *mut BIO, rsa: *const RSA) -> c_int;
    pub fn PEM_write_bio_RSA_PUBKEY(bp: *mut BIO, rsa: *mut RSA) -> c_int;

    pub fn PEM_read_bio_DSAPrivateKey(bp: *mut BIO, dsa: *mut *mut DSA, callback: Option<PasswordCallback>,
                                      user_data: *mut c_void) -> *mut DSA;
    pub fn PEM_read_bio_DSA_PUBKEY(bp: *mut BIO, dsa: *mut *mut DSA, callback: Option<PasswordCallback>,
                                   user_data: *mut c_void) -> *mut DSA;
    pub fn PEM_write_bio_DSAPrivateKey(bp: *mut BIO, dsa: *mut DSA, cipher: *const EVP_CIPHER,
                                       kstr: *mut c_uchar, klen: c_int, callback: Option<PasswordCallback>,
                                       user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_DSA_PUBKEY(bp: *mut BIO, dsa: *mut DSA) -> c_int;



    pub fn PEM_write_bio_X509(bio: *mut BIO, x509: *mut X509) -> c_int;
    pub fn PEM_write_bio_X509_REQ(bio: *mut BIO, x509: *mut X509_REQ) -> c_int;

    pub fn PKCS5_PBKDF2_HMAC_SHA1(pass: *const c_char, passlen: c_int,
                                  salt: *const u8, saltlen: c_int,
                                  iter: c_int, keylen: c_int,
                                  out: *mut u8) -> c_int;
    pub fn PKCS5_PBKDF2_HMAC(pass: *const c_char, passlen: c_int,
                             salt: *const c_uchar, saltlen: c_int,
                             iter: c_int, digest: *const EVP_MD, keylen: c_int,
                             out: *mut u8) -> c_int;

    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    pub fn RAND_status() -> c_int;

    pub fn RSA_new() -> *mut RSA;
    pub fn RSA_free(rsa: *mut RSA);
    pub fn RSA_generate_key_ex(rsa: *mut RSA, bits: c_int, e: *mut BIGNUM, cb: *mut BN_GENCB) -> c_int;
    pub fn RSA_private_decrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                               pad: c_int) -> c_int;
    pub fn RSA_public_decrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                               pad: c_int) -> c_int;
    pub fn RSA_private_encrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                              pad: c_int) -> c_int;
    pub fn RSA_public_encrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                              pad: c_int) -> c_int;
    pub fn RSA_sign(t: c_int, m: *const u8, mlen: c_uint, sig: *mut u8, siglen: *mut c_uint,
                    k: *mut RSA) -> c_int;
    pub fn RSA_size(k: *const RSA) -> c_int;
    pub fn RSA_verify(t: c_int, m: *const u8, mlen: c_uint, sig: *const u8, siglen: c_uint,
                      k: *mut RSA) -> c_int;

    pub fn DSA_new() -> *mut DSA;
    pub fn DSA_free(dsa: *mut DSA);
    pub fn DSA_size(dsa: *const DSA) -> c_int;
    pub fn DSA_generate_parameters_ex(dsa: *mut DSA, bits: c_int, seed: *const c_uchar, seed_len: c_int,
                                      counter_ref: *mut c_int, h_ret: *mut c_ulong,
                                      cb: *mut BN_GENCB) -> c_int;
    pub fn DSA_generate_key(dsa: *mut DSA) -> c_int;
    pub fn DSA_sign(dummy: c_int, dgst: *const c_uchar, len: c_int, sigret: *mut c_uchar,
                    siglen: *mut c_uint, dsa: *mut DSA) -> c_int;
    pub fn DSA_verify(dummy: c_int, dgst: *const c_uchar, len: c_int, sigbuf: *const c_uchar,
                      siglen: c_int, dsa: *mut DSA) -> c_int;

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    pub fn SSL_pending(ssl: *const SSL) -> c_int;
    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub fn SSL_get_rbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_wbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_accept(ssl: *mut SSL) -> c_int;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    pub fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long,
                    parg: *mut c_void) -> c_long;
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;
    pub fn SSL_set_SSL_CTX(ssl: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX;
    pub fn SSL_get_current_compression(ssl: *mut SSL) -> *const COMP_METHOD;
    pub fn SSL_get_peer_certificate(ssl: *const SSL) -> *mut X509;
    pub fn SSL_get_ssl_method(ssl: *mut SSL) -> *const SSL_METHOD;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string_long(ssl: *const SSL) -> *const c_char;
    pub fn SSL_set_verify(ssl: *mut SSL,
                          mode: c_int,
                          verify_callback: Option<extern fn(c_int, *mut X509_STORE_CTX) -> c_int>);
    pub fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;

    pub fn SSL_get_servername(ssl: *const SSL, name_type: c_int) -> *const c_char;

    pub fn SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char;

    pub fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;

    pub fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char;
    pub fn SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int;
    pub fn SSL_CIPHER_description(cipher: *const SSL_CIPHER, buf: *mut c_char, size: c_int) -> *mut c_char;

    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_callback_ctrl(ctx: *mut SSL_CTX, cmd: c_int, fp: Option<extern "C" fn()>) -> c_long;
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int,
                              verify_callback: Option<extern fn(c_int, *mut X509_STORE_CTX) -> c_int>);
    pub fn SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int);
    pub fn SSL_CTX_load_verify_locations(ctx: *mut SSL_CTX, CAfile: *const c_char,
                                         CApath: *const c_char) -> c_int;
    pub fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void)
                               -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void;
    pub fn SSL_CTX_set_session_id_context(ssl: *mut SSL_CTX, sid_ctx: *const c_uchar, sid_ctx_len: c_uint) -> c_int;

    pub fn SSL_CTX_use_certificate_file(ctx: *mut SSL_CTX, cert_file: *const c_char, file_type: c_int) -> c_int;
    pub fn SSL_CTX_use_certificate_chain_file(ctx: *mut SSL_CTX, cert_chain_file: *const c_char) -> c_int;
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, cert: *mut X509) -> c_int;

    pub fn SSL_CTX_use_PrivateKey_file(ctx: *mut SSL_CTX, key_file: *const c_char, file_type: c_int) -> c_int;
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, key: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;

    pub fn SSL_CTX_set_cipher_list(ssl: *mut SSL_CTX, s: *const c_char) -> c_int;

    pub fn SSL_CTX_set_next_protos_advertised_cb(ssl: *mut SSL_CTX,
                                                 cb: extern "C" fn(ssl: *mut SSL,
                                                                   out: *mut *const c_uchar,
                                                                   outlen: *mut c_uint,
                                                                   arg: *mut c_void) -> c_int,
                                                 arg: *mut c_void);
    pub fn SSL_CTX_set_next_proto_select_cb(ssl: *mut SSL_CTX,
                                            cb: extern "C" fn(ssl: *mut SSL,
                                                              out: *mut *mut c_uchar,
                                                              outlen: *mut c_uchar,
                                                              inbuf: *const c_uchar,
                                                              inlen: c_uint,
                                                              arg: *mut c_void) -> c_int,
                                            arg: *mut c_void);
    pub fn SSL_select_next_proto(out: *mut *mut c_uchar, outlen: *mut c_uchar,
                                 inbuf: *const c_uchar, inlen: c_uint,
                                 client: *const c_uchar, client_len: c_uint) -> c_int;
    pub fn SSL_get0_next_proto_negotiated(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);

    #[cfg(not(ossl101))]
    pub fn SSL_CTX_set_alpn_protos(s: *mut SSL_CTX, data: *const c_uchar, len: c_uint) -> c_int;

    #[cfg(not(ossl101))]
    pub fn SSL_set_alpn_protos(s: *mut SSL, data: *const c_uchar, len: c_uint) -> c_int;

    #[cfg(not(ossl101))]
    pub fn SSL_CTX_set_alpn_select_cb(ssl: *mut SSL_CTX,
                                      cb: extern fn(ssl: *mut SSL,
                                                    out: *mut *const c_uchar,
                                                    outlen: *mut c_uchar,
                                                    inbuf: *const c_uchar,
                                                    inlen: c_uint,
                                                    arg: *mut c_void) -> c_int,
                                      arg: *mut c_void);
    #[cfg(not(ossl101))]
    pub fn SSL_get0_alpn_selected(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);

    pub fn X509_add_ext(x: *mut X509, ext: *mut X509_EXTENSION, loc: c_int) -> c_int;
    pub fn X509_digest(x: *const X509, digest: *const EVP_MD, buf: *mut c_uchar, len: *mut c_uint) -> c_int;
    pub fn X509_free(x: *mut X509);
    pub fn X509_REQ_free(x: *mut X509_REQ);
    pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
    pub fn X509_gmtime_adj(time: *mut ASN1_TIME, adj: c_long) -> *mut ASN1_TIME;
    pub fn X509_new() -> *mut X509;
    pub fn X509_set_issuer_name(x: *mut X509, name: *mut X509_NAME) -> c_int;
    pub fn X509_set_version(x: *mut X509, version: c_long) -> c_int;
    pub fn X509_set_pubkey(x: *mut X509, pkey: *mut EVP_PKEY) -> c_int;
    pub fn X509_sign(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;
    pub fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;
    pub fn X509_to_X509_REQ(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> *mut X509_REQ;

    pub fn X509_EXTENSION_free(ext: *mut X509_EXTENSION);

    pub fn X509_NAME_add_entry_by_txt(x: *mut X509_NAME, field: *const c_char, ty: c_int, bytes: *const c_uchar, len: c_int, loc: c_int, set: c_int) -> c_int;
    pub fn X509_NAME_get_index_by_NID(n: *mut X509_NAME, nid: c_int, last_pos: c_int) ->c_int;

    pub fn ASN1_STRING_length(x: *const ASN1_STRING) -> c_int;

    pub fn X509_STORE_CTX_get_current_cert(ct: *mut X509_STORE_CTX) -> *mut X509;
    pub fn X509_STORE_CTX_get_error(ctx: *mut X509_STORE_CTX) -> c_int;
    pub fn X509_STORE_CTX_get_ex_data(ctx: *mut X509_STORE_CTX, idx: c_int) -> *mut c_void;
    pub fn X509_STORE_CTX_get_error_depth(ctx: *mut X509_STORE_CTX) -> c_int;

    pub fn X509V3_EXT_conf_nid(conf: *mut c_void, ctx: *mut X509V3_CTX, ext_nid: c_int, value: *mut c_char) -> *mut X509_EXTENSION;
    pub fn X509V3_EXT_conf(conf: *mut c_void, ctx: *mut X509V3_CTX, name: *mut c_char, value: *mut c_char) -> *mut X509_EXTENSION;
    pub fn X509V3_set_ctx(ctx: *mut X509V3_CTX, issuer: *mut X509, subject: *mut X509, req: *mut X509_REQ, crl: *mut X509_CRL, flags: c_int);

    pub fn X509_REQ_add_extensions(req: *mut X509_REQ, exts: *mut stack_st_X509_EXTENSION) -> c_int;
    pub fn X509_REQ_sign(x: *mut X509_REQ, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

    pub fn d2i_X509(a: *mut *mut X509, pp: *mut *const c_uchar, length: c_long) -> *mut X509;
    pub fn i2d_X509_bio(b: *mut BIO, x: *mut X509) -> c_int;
    pub fn i2d_X509_REQ_bio(b: *mut BIO, x: *mut X509_REQ) -> c_int;

    pub fn i2d_RSA_PUBKEY(k: *mut RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSA_PUBKEY(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;
    pub fn i2d_RSAPrivateKey(k: *const RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSAPrivateKey(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;

    pub fn d2i_PKCS12(a: *mut *mut PKCS12, pp: *mut *const u8, length: c_long) -> *mut PKCS12;
    pub fn PKCS12_parse(p12: *mut PKCS12,
                        pass: *const c_char,
                        pkey: *mut *mut EVP_PKEY,
                        cert: *mut *mut X509,
                        ca: *mut *mut stack_st_X509)
                        -> c_int;
    pub fn PKCS12_free(p12: *mut PKCS12);

    pub fn GENERAL_NAME_free(name: *mut GENERAL_NAME);

    pub fn HMAC_Init_ex(ctx: *mut HMAC_CTX,
                        key: *const c_void,
                        len: c_int,
                        md: *const EVP_MD,
                        impl_: *mut ENGINE) -> c_int;
    pub fn HMAC_Update(ctx: *mut HMAC_CTX,
                       data: *const c_uchar,
                       len: size_t) -> c_int;
    pub fn HMAC_Final(ctx: *mut HMAC_CTX,
                      md: *mut c_uchar,
                      len: *mut c_uint) -> c_int;
    pub fn DH_new() -> *mut DH;
}
