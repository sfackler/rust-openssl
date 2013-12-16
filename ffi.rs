#[doc(hidden)];

use std::libc::{c_int, c_void, c_long, c_ulong, c_char};

pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;
pub type SSL = c_void;
pub type BIO = c_void;
pub type BIO_METHOD = c_void;
pub type X509_STORE_CTX = c_void;
pub type X509 = c_void;
pub type X509_NAME = c_void;
pub type CRYPTO_EX_DATA = c_void;

pub type CRYPTO_EX_new = extern "C" fn(parent: *c_void, ptr: *c_void,
                                       ad: *CRYPTO_EX_DATA, idx: c_int,
                                       argl: c_long, argp: *c_void) -> c_int;
pub type CRYPTO_EX_dup = extern "C" fn(to: *CRYPTO_EX_DATA,
                                       from: *CRYPTO_EX_DATA, from_d: *c_void,
                                       idx: c_int, argl: c_long, argp: *c_void)
                                       -> c_int;
pub type CRYPTO_EX_free = extern "C" fn(parent: *c_void, ptr: *c_void,
                                        ad: *CRYPTO_EX_DATA, idx: c_int,
                                        argl: c_long, argp: *c_void);

pub static CRYPTO_LOCK: c_int = 1;

pub static SSL_ERROR_NONE: c_int = 0;
pub static SSL_ERROR_SSL: c_int = 1;
pub static SSL_ERROR_WANT_READ: c_int = 2;
pub static SSL_ERROR_WANT_WRITE: c_int = 3;
pub static SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub static SSL_ERROR_SYSCALL: c_int = 5;
pub static SSL_ERROR_ZERO_RETURN: c_int = 6;
pub static SSL_ERROR_WANT_CONNECT: c_int = 7;
pub static SSL_ERROR_WANT_ACCEPT: c_int = 8;

pub static SSL_VERIFY_NONE: c_int = 0;
pub static SSL_VERIFY_PEER: c_int = 1;

pub static X509_V_OK: c_int = 0;
pub static X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
pub static X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
pub static X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
pub static X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
pub static X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
pub static X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
pub static X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
pub static X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
pub static X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
pub static X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
pub static X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
pub static X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
pub static X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
pub static X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
pub static X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
pub static X509_V_ERR_OUT_OF_MEM: c_int = 17;
pub static X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
pub static X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
pub static X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
pub static X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
pub static X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
pub static X509_V_ERR_CERT_REVOKED: c_int = 23;
pub static X509_V_ERR_INVALID_CA: c_int = 24;
pub static X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
pub static X509_V_ERR_INVALID_PURPOSE: c_int = 26;
pub static X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
pub static X509_V_ERR_CERT_REJECTED: c_int = 28;
pub static X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
pub static X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
pub static X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
pub static X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
pub static X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
pub static X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
pub static X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
pub static X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
pub static X509_V_ERR_INVALID_NON_CA: c_int = 37;
pub static X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
pub static X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
pub static X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
pub static X509_V_ERR_INVALID_EXTENSION: c_int = 41;
pub static X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
pub static X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
pub static X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
pub static X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
pub static X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
pub static X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
pub static X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
pub static X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
pub static X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
pub static X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
pub static X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
pub static X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
pub static X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;

pub static XN_FLAG_RFC2253: c_ulong = 0x1110317;
pub static XN_FLAG_ONELINE: c_ulong = 0x82031f;
pub static XN_FLAG_MULTILINE: c_ulong = 0x2a40006;

#[link(name="ssl")]
#[link(name="crypto")]
extern "C" {
    pub fn CRYPTO_num_locks() -> c_int;
    pub fn CRYPTO_set_locking_callback(func: extern "C" fn(mode: c_int,
                                                           n: c_int,
                                                           file: *c_char,
                                                           line: c_int));

    pub fn ERR_get_error() -> c_ulong;

    pub fn SSL_library_init() -> c_int;

    pub fn SSLv3_method() -> *SSL_METHOD;
    pub fn TLSv1_method() -> *SSL_METHOD;
    pub fn SSLv23_method() -> *SSL_METHOD;

    pub fn SSL_CTX_new(method: *SSL_METHOD) -> *SSL_CTX;
    pub fn SSL_CTX_free(ctx: *SSL_CTX);
    pub fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int,
                              verify_callback: Option<extern "C" fn(c_int, *X509_STORE_CTX) -> c_int>);
    pub fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, CAfile: *c_char,
                                         CApath: *c_char) -> c_int;
    pub fn SSL_CTX_get_ex_new_index(argl: c_long, argp: *c_void,
                                    new_func: Option<CRYPTO_EX_new>,
                                    dup_func: Option<CRYPTO_EX_dup>,
                                    free_func: Option<CRYPTO_EX_free>)
                                    -> c_int;
    pub fn SSL_CTX_set_ex_data(ctx: *SSL_CTX, idx: c_int, data: *c_void)
                               -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *SSL_CTX, idx: c_int) -> *c_void;

    pub fn X509_STORE_CTX_get_ex_data(ctx: *X509_STORE_CTX, idx: c_int)
                                      -> *c_void;
    pub fn X509_STORE_CTX_get_current_cert(ct: *X509_STORE_CTX) -> *X509;
    pub fn X509_STORE_CTX_get_error(ctx: *X509_STORE_CTX) -> c_int;

    pub fn X509_get_subject_name(x: *X509) -> *X509_NAME;

    pub fn X509_NAME_print_ex(out: *BIO, nm: *X509_NAME, ident: c_int,
                              flags: c_ulong) -> c_int;

    pub fn SSL_new(ctx: *SSL_CTX) -> *SSL;
    pub fn SSL_free(ssl: *SSL);
    pub fn SSL_set_bio(ssl: *SSL, rbio: *BIO, wbio: *BIO);
    pub fn SSL_get_rbio(ssl: *SSL) -> *BIO;
    pub fn SSL_get_wbio(ssl: *SSL) -> *BIO;
    pub fn SSL_connect(ssl: *SSL) -> c_int;
    pub fn SSL_get_error(ssl: *SSL, ret: c_int) -> c_int;
    pub fn SSL_read(ssl: *SSL, buf: *c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *SSL, buf: *c_void, num: c_int) -> c_int;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_get_SSL_CTX(ssl: *SSL) -> *SSL_CTX;

    pub fn BIO_s_mem() -> *BIO_METHOD;
    pub fn BIO_new(type_: *BIO_METHOD) -> *BIO;
    pub fn BIO_free_all(a: *BIO);
    pub fn BIO_read(b: *BIO, buf: *c_void, len: c_int) -> c_int;
    pub fn BIO_write(b: *BIO, buf: *c_void, len: c_int) -> c_int;
}
