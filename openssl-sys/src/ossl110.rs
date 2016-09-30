use libc::{c_int, c_void, c_char, c_uchar, c_ulong, c_long};

pub enum stack_st_X509 {}
pub enum stack_st_X509_ATTRIBUTE {}
pub enum stack_st_X509_EXTENSION {}
pub enum stack_st_GENERAL_NAME {}
pub enum stack_st_void {}
pub enum _STACK {}
pub enum BIO_METHOD {}
pub enum RSA {}
pub enum DSA {}
pub enum EVP_PKEY {}
pub enum BIO {}
pub enum CRYPTO_EX_DATA {}
pub enum EVP_MD_CTX {}
pub enum EVP_CIPHER {}
pub enum HMAC_CTX {}
pub enum BIGNUM {}
pub enum OPENSSL_STACK {}
pub enum DH {}
pub enum X509 {}
pub enum SSL_CTX {}

pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_ulong =                   0x00000000;
pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_ulong =                  0x00000000;
pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_ulong =        0x00000000;
pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_ulong =              0x00000000;
pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_ulong =                0x00000000;
pub const SSL_OP_TLS_D5_BUG: c_ulong =                              0x00000000;
pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_ulong =                   0x00000000;
pub const SSL_OP_SINGLE_ECDH_USE: c_ulong =                         0x00000000;
pub const SSL_OP_SINGLE_DH_USE: c_ulong =                           0x00000000;
pub const SSL_OP_NO_SSLv2: c_ulong =                                0x00000000;

pub const OPENSSL_VERSION: c_int = 0;
pub const OPENSSL_CFLAGS: c_int = 1;
pub const OPENSSL_BUILT_ON: c_int = 2;
pub const OPENSSL_PLATFORM: c_int = 3;
pub const OPENSSL_DIR: c_int = 4;

pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;

pub fn init() {}

extern {
    pub fn BIO_new(type_: *const BIO_METHOD) -> *mut BIO;
    pub fn BIO_s_file() -> *const BIO_METHOD;
    pub fn BIO_s_mem() -> *const BIO_METHOD;
    pub fn CRYPTO_free(buf: *mut c_void, file: *const c_char, line: c_int);
    pub fn HMAC_CTX_new() -> *mut HMAC_CTX;
    pub fn HMAC_CTX_free(ctx: *mut HMAC_CTX);
    pub fn TLS_method() -> *const ::SSL_METHOD;
    pub fn DTLS_method() -> *const ::SSL_METHOD;
    pub fn SSL_CIPHER_get_version(cipher: *const ::SSL_CIPHER) -> *const c_char;
    pub fn X509_get_subject_name(x: *const ::X509) -> *mut ::X509_NAME;
    pub fn X509_set1_notAfter(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
    pub fn X509_set1_notBefore(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
    pub fn X509_get_ext_d2i(x: *const ::X509, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;
    pub fn X509_NAME_get_entry(n: *const ::X509_NAME, loc: c_int) -> *mut ::X509_NAME_ENTRY;
    pub fn X509_NAME_ENTRY_get_data(ne: *const ::X509_NAME_ENTRY) -> *mut ::ASN1_STRING;
    pub fn ASN1_STRING_to_UTF8(out: *mut *mut c_uchar, s: *const ::ASN1_STRING) -> c_int;
    pub fn BN_is_negative(b: *const ::BIGNUM) -> c_int;
    pub fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> c_int;
    pub fn EVP_CIPHER_block_size(cipher: *const EVP_CIPHER) -> c_int;
    pub fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> c_int;
    pub fn DSA_get0_pqg(d: *const ::DSA,
                        p: *mut *const ::BIGNUM,
                        q: *mut *const ::BIGNUM,
                        q: *mut *const ::BIGNUM);
    pub fn DSA_get0_key(d: *const ::DSA,
                        pub_key: *mut *const ::BIGNUM,
                        priv_key: *mut *const ::BIGNUM);
    pub fn RSA_get0_key(r: *const ::RSA,
                        n: *mut *const ::BIGNUM,
                        e: *mut *const ::BIGNUM,
                        d: *mut *const ::BIGNUM);
    pub fn RSA_get0_factors(r: *const ::RSA,
                            p: *mut *const ::BIGNUM,
                            q: *mut *const ::BIGNUM);
    pub fn RSA_set0_key(r: *mut ::RSA,
                        n: *mut ::BIGNUM,
                        e: *mut ::BIGNUM,
                        d: *mut ::BIGNUM) -> c_int;
    pub fn RSA_set0_factors(r: *mut ::RSA,
                            p: *mut ::BIGNUM,
                            q: *mut ::BIGNUM) -> c_int;
    pub fn RSA_set0_crt_params(r: *mut ::RSA,
                               dmp1: *mut ::BIGNUM,
                               dmq1: *mut ::BIGNUM,
                               iqmp: *mut ::BIGNUM) -> c_int;
    pub fn ASN1_STRING_get0_data(x: *const ::ASN1_STRING) -> *const c_uchar;
    pub fn OPENSSL_sk_num(stack: *const ::OPENSSL_STACK) -> c_int;
    pub fn OPENSSL_sk_value(stack: *const ::OPENSSL_STACK,
                            idx: c_int) -> *mut c_void;
    pub fn SSL_CTX_get_options(ctx: *const ::SSL_CTX) -> c_ulong;
    pub fn SSL_CTX_set_options(ctx: *mut ::SSL_CTX, op: c_ulong) -> c_ulong;
    pub fn SSL_CTX_clear_options(ctx: *mut ::SSL_CTX, op: c_ulong) -> c_ulong;
    pub fn X509_getm_notAfter(x: *const ::X509) -> *mut ::ASN1_TIME;
    pub fn X509_getm_notBefore(x: *const ::X509) -> *mut ::ASN1_TIME;
    pub fn DH_set0_pqg(dh: *mut ::DH,
                       p: *mut ::BIGNUM,
                       q: *mut ::BIGNUM,
                       g: *mut ::BIGNUM) -> c_int;
    pub fn BIO_set_init(a: *mut ::BIO, init: c_int);
    pub fn BIO_set_data(a: *mut ::BIO, data: *mut c_void);
    pub fn BIO_get_data(a: *mut ::BIO) -> *mut c_void;
    pub fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut ::BIO_METHOD;
    pub fn BIO_meth_free(biom: *mut ::BIO_METHOD);
    pub fn BIO_meth_set_write(biom: *mut ::BIO_METHOD,
                              write: unsafe extern fn(*mut ::BIO,
                                                      *const c_char,
                                                      c_int) -> c_int) -> c_int;
    pub fn BIO_meth_set_read(biom: *mut ::BIO_METHOD,
                             read: unsafe extern fn(*mut ::BIO,
                                                    *mut c_char,
                                                    c_int) -> c_int) -> c_int;
    pub fn BIO_meth_set_puts(biom: *mut ::BIO_METHOD,
                             read: unsafe extern fn(*mut ::BIO,
                                                    *const c_char) -> c_int) -> c_int;
    pub fn BIO_meth_set_ctrl(biom: *mut ::BIO_METHOD,
                             read: unsafe extern fn(*mut ::BIO,
                                                    c_int,
                                                    c_long,
                                                    *mut c_void) -> c_long) -> c_int;
    pub fn BIO_meth_set_create(biom: *mut ::BIO_METHOD,
                               create: unsafe extern fn(*mut ::BIO) -> c_int) -> c_int;
    pub fn BIO_meth_set_destroy(biom: *mut ::BIO_METHOD,
                                destroy: unsafe extern fn(*mut ::BIO) -> c_int) -> c_int;
    pub fn CRYPTO_get_ex_new_index(class_index: c_int,
                                   argl: c_long,
                                   argp: *mut c_void,
                                   new_func: Option<::CRYPTO_EX_new>,
                                   dup_func: Option<::CRYPTO_EX_dup>,
                                   free_func: Option<::CRYPTO_EX_free>)
                                   -> c_int;
    pub fn X509_up_ref(x: *mut X509) -> c_int;
    pub fn SSL_CTX_up_ref(x: *mut SSL_CTX) -> c_int;
    pub fn X509_get0_extensions(req: *const ::X509) -> *const stack_st_X509_EXTENSION;

    pub fn OpenSSL_version_num() -> c_ulong;
    pub fn OpenSSL_version(key: c_int) -> *const c_char;
    pub fn OPENSSL_sk_free(st: *mut _STACK);
    pub fn OPENSSL_sk_pop_free(st: *mut _STACK, free: Option<unsafe extern "C" fn (*mut c_void)>);
    pub fn OPENSSL_sk_pop(st: *mut _STACK) -> *mut c_void;
}
