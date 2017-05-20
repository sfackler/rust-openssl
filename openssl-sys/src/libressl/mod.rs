use std::sync::{Mutex, MutexGuard};
use std::sync::{Once, ONCE_INIT};
use std::mem;
use std::ptr;

#[cfg(libressl250)]
pub use libressl::v250::*;
#[cfg(not(libressl250))]
pub use libressl::v25x::*;

use libc::{c_int, c_char, c_void, c_long, c_uchar, size_t, c_uint, c_ulong};

#[cfg(libressl250)]
mod v250;
#[cfg(not(libressl250))]
mod v25x;

#[repr(C)]
pub struct stack_st_ASN1_OBJECT {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_X509 {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_X509_NAME {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_X509_ATTRIBUTE {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_X509_EXTENSION {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_GENERAL_NAME {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_void {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_SSL_CIPHER {
    pub stack: _STACK,
}

#[repr(C)]
pub struct stack_st_OPENSSL_STRING {
    pub stack: _STACK,
}

#[repr(C)]
pub struct _STACK {
    pub num: c_int,
    pub data: *mut *mut c_char,
    pub sorted: c_int,
    pub num_alloc: c_int,
    pub comp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
}

#[repr(C)]
pub struct BIO_METHOD {
    pub type_: c_int,
    pub name: *const c_char,
    pub bwrite: Option<unsafe extern "C" fn(*mut ::BIO, *const c_char, c_int) -> c_int>,
    pub bread: Option<unsafe extern "C" fn(*mut ::BIO, *mut c_char, c_int) -> c_int>,
    pub bputs: Option<unsafe extern "C" fn(*mut ::BIO, *const c_char) -> c_int>,
    pub bgets: Option<unsafe extern "C" fn(*mut ::BIO, *mut c_char, c_int) -> c_int>,
    pub ctrl: Option<unsafe extern "C" fn(*mut ::BIO, c_int, c_long, *mut c_void) -> c_long>,
    pub create: Option<unsafe extern "C" fn(*mut ::BIO) -> c_int>,
    pub destroy: Option<unsafe extern "C" fn(*mut ::BIO) -> c_int>,
    pub callback_ctrl: Option<unsafe extern "C" fn(*mut ::BIO, c_int, ::bio_info_cb) -> c_long>,
}

#[repr(C)]
pub struct RSA {
    pub pad: c_int,
    pub version: c_long,
    pub meth: *const ::RSA_METHOD,

    pub engine: *mut ::ENGINE,
    pub n: *mut ::BIGNUM,
    pub e: *mut ::BIGNUM,
    pub d: *mut ::BIGNUM,
    pub p: *mut ::BIGNUM,
    pub q: *mut ::BIGNUM,
    pub dmp1: *mut ::BIGNUM,
    pub dmq1: *mut ::BIGNUM,
    pub iqmp: *mut ::BIGNUM,

    pub ex_data: ::CRYPTO_EX_DATA,
    pub references: c_int,
    pub flags: c_int,

    pub _method_mod_n: *mut ::BN_MONT_CTX,
    pub _method_mod_p: *mut ::BN_MONT_CTX,
    pub _method_mod_q: *mut ::BN_MONT_CTX,

    pub blinding: *mut ::BN_BLINDING,
    pub mt_blinding: *mut ::BN_BLINDING,
}

#[repr(C)]
pub struct DSA {
    pub pad: c_int,
    pub version: c_long,
    pub write_params: c_int,

    pub p: *mut ::BIGNUM,
    pub q: *mut ::BIGNUM,
    pub g: *mut ::BIGNUM,
    pub pub_key: *mut ::BIGNUM,
    pub priv_key: *mut ::BIGNUM,
    pub kinv: *mut ::BIGNUM,
    pub r: *mut ::BIGNUM,

    pub flags: c_int,
    pub method_mont_p: *mut ::BN_MONT_CTX,
    pub references: c_int,
    pub ex_data: ::CRYPTO_EX_DATA,
    pub meth: *const ::DSA_METHOD,
    pub engine: *mut ::ENGINE,
}

#[repr(C)]
pub struct EVP_PKEY {
    pub type_: c_int,
    pub save_type: c_int,
    pub references: c_int,
    pub ameth: *const ::EVP_PKEY_ASN1_METHOD,
    pub engine: *mut ::ENGINE,
    pub pkey: *mut c_void,
    pub save_parameters: c_int,
    pub attributes: *mut stack_st_X509_ATTRIBUTE,
}

#[repr(C)]
pub struct BIO {
    pub method: *mut ::BIO_METHOD,
    pub callback: Option<unsafe extern "C" fn(*mut ::BIO,
                                              c_int,
                                              *const c_char,
                                              c_int,
                                              c_long,
                                              c_long)
                                              -> c_long>,
    pub cb_arg: *mut c_char,
    pub init: c_int,
    pub shutdown: c_int,
    pub flags: c_int,
    pub retry_reason: c_int,
    pub num: c_int,
    pub ptr: *mut c_void,
    pub next_bio: *mut ::BIO,
    pub prev_bio: *mut ::BIO,
    pub references: c_int,
    pub num_read: c_ulong,
    pub num_write: c_ulong,
    pub ex_data: ::CRYPTO_EX_DATA,
}

#[repr(C)]
pub struct CRYPTO_EX_DATA {
    pub sk: *mut ::stack_st_void,
}

#[repr(C)]
pub struct EVP_MD_CTX {
    digest: *mut ::EVP_MD,
    engine: *mut ::ENGINE,
    flags: c_ulong,
    md_data: *mut c_void,
    pctx: *mut ::EVP_PKEY_CTX,
    update: *mut c_void,
}

#[repr(C)]
pub struct EVP_CIPHER {
    pub nid: c_int,
    pub block_size: c_int,
    pub key_len: c_int,
    pub iv_len: c_int,
    pub flags: c_ulong,
    pub init: Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX,
                                          *const c_uchar,
                                          *const c_uchar,
                                          c_int)
                                          -> c_int>,
    pub do_cipher: Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX,
                                               *mut c_uchar,
                                               *const c_uchar,
                                               size_t)
                                               -> c_int>,
    pub cleanup: Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX) -> c_int>,
    pub ctx_size: c_int,
    pub set_asn1_parameters:
        Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX, *mut ::ASN1_TYPE) -> c_int>,
    pub get_asn1_parameters:
        Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX, *mut ::ASN1_TYPE) -> c_int>,
    pub ctrl: Option<unsafe extern "C" fn(*mut ::EVP_CIPHER_CTX, c_int, c_int, *mut c_void) -> c_int>,
    pub app_data: *mut c_void,
}

#[repr(C)]
pub struct HMAC_CTX {
    md: *mut ::EVP_MD,
    md_ctx: ::EVP_MD_CTX,
    i_ctx: ::EVP_MD_CTX,
    o_ctx: ::EVP_MD_CTX,
    key_length: c_uint,
    key: [c_uchar; 128],
}

#[repr(C)]
pub struct BIGNUM {
    pub d: *mut ::BN_ULONG,
    pub top: c_int,
    pub dmax: c_int,
    pub neg: c_int,
    pub flags: c_int,
}

#[repr(C)]
pub struct DH {
    pub pad: c_int,
    pub version: c_int,
    pub p: *mut ::BIGNUM,
    pub g: *mut ::BIGNUM,
    pub length: c_long,
    pub pub_key: *mut ::BIGNUM,
    pub priv_key: *mut ::BIGNUM,
    pub flags: c_int,
    pub method_mont_p: *mut ::BN_MONT_CTX,
    pub q: *mut ::BIGNUM,
    pub j: *mut ::BIGNUM,
    pub seed: *mut c_uchar,
    pub seedlen: c_int,
    pub counter: *mut ::BIGNUM,
    pub references: c_int,
    pub ex_data: ::CRYPTO_EX_DATA,
    pub meth: *const ::DH_METHOD,
    pub engine: *mut ::ENGINE,
}

#[repr(C)]
pub struct X509 {
    pub cert_info: *mut X509_CINF,
    pub sig_alg: *mut ::X509_ALGOR,
    pub signature: *mut ::ASN1_BIT_STRING,
    pub valid: c_int,
    pub references: c_int,
    pub name: *mut c_char,
    pub ex_data: ::CRYPTO_EX_DATA,
    pub ex_pathlen: c_long,
    pub ex_pcpathlen: c_long,
    pub ex_flags: c_ulong,
    pub ex_kusage: c_ulong,
    pub ex_xkusage: c_ulong,
    pub ex_nscert: c_ulong,
    skid: *mut c_void,
    akid: *mut c_void,
    policy_cache: *mut c_void,
    crldp: *mut c_void,
    altname: *mut c_void,
    nc: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_SHA"))]
    sha1_hash: [c_uchar; 20],
    aux: *mut c_void,
}

#[repr(C)]
pub struct X509_CINF {
    version: *mut c_void,
    serialNumber: *mut c_void,
    signature: *mut c_void,
    issuer: *mut c_void,
    pub validity: *mut X509_VAL,
    subject: *mut c_void,
    key: *mut c_void,
    issuerUID: *mut c_void,
    subjectUID: *mut c_void,
    pub extensions: *mut stack_st_X509_EXTENSION,
    enc: ASN1_ENCODING,
}

#[repr(C)]
pub struct X509_ALGOR {
    pub algorithm: *mut ::ASN1_OBJECT,
    parameter: *mut c_void,
}

#[repr(C)]
pub struct ASN1_ENCODING {
    pub enc: *mut c_uchar,
    pub len: c_long,
    pub modified: c_int,
}

#[repr(C)]
pub struct X509_VAL {
    pub notBefore: *mut ::ASN1_TIME,
    pub notAfter: *mut ::ASN1_TIME,
}

#[repr(C)]
pub struct X509_REQ_INFO {
    pub enc: ASN1_ENCODING,
    pub version: *mut ::ASN1_INTEGER,
    pub subject: *mut ::X509_NAME,
    pubkey: *mut c_void,
    pub attributes: *mut stack_st_X509_ATTRIBUTE,
}

#[repr(C)]
pub struct X509_REQ {
    pub req_info: *mut X509_REQ_INFO,
    sig_alg: *mut c_void,
    signature: *mut c_void,
    references: c_int,
}

pub enum X509_VERIFY_PARAM_ID {}
pub enum PKCS12 {}

pub const SSL_CTRL_GET_SESSION_REUSED: c_int = 8;
pub const SSL_CTRL_OPTIONS: c_int = 32;
pub const SSL_CTRL_CLEAR_OPTIONS: c_int = 77;
pub const SSL_CTRL_SET_ECDH_AUTO: c_int = 94;

pub const SSL_OP_ALL: c_ulong = 0x80000014;
pub const SSL_OP_CISCO_ANYCONNECT: c_ulong = 0x0;
pub const SSL_OP_NO_COMPRESSION: c_ulong = 0x0;
pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_ulong = 0x0;
pub const SSL_OP_NO_SSLv3: c_ulong = 0x0;
pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_ulong = 0x0;
pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_ulong = 0x0;
pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_ulong = 0x0;
pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_ulong = 0x0;
pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_ulong = 0x0;
pub const SSL_OP_TLS_D5_BUG: c_ulong = 0x0;
pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_ulong = 0x0;
pub const SSL_OP_SINGLE_ECDH_USE: c_ulong = 0x00080000;
pub const SSL_OP_SINGLE_DH_USE: c_ulong = 0x00100000;
pub const SSL_OP_NO_SSLv2: c_ulong = 0x0;

pub const SSL_MAX_SSL_SESSION_ID_LENGTH: c_int = 32;
pub const SSL_MAX_SID_CTX_LENGTH: c_int = 32;
pub const SSL_MAX_MASTER_KEY_LENGTH: c_int = 48;

pub const SSLEAY_VERSION: c_int = 0;
pub const SSLEAY_CFLAGS: c_int = 2;
pub const SSLEAY_BUILT_ON: c_int = 3;
pub const SSLEAY_PLATFORM: c_int = 4;
pub const SSLEAY_DIR: c_int = 5;

pub const CRYPTO_LOCK_X509: c_int = 3;
pub const CRYPTO_LOCK_SSL_CTX: c_int = 12;
pub const CRYPTO_LOCK_SSL_SESSION: c_int = 14;

static mut MUTEXES: *mut Vec<Mutex<()>> = 0 as *mut Vec<Mutex<()>>;
static mut GUARDS: *mut Vec<Option<MutexGuard<'static, ()>>> =
    0 as *mut Vec<Option<MutexGuard<'static, ()>>>;

unsafe extern "C" fn locking_function(mode: c_int, n: c_int, _file: *const c_char, _line: c_int) {
    let mutex = &(*MUTEXES)[n as usize];

    if mode & ::CRYPTO_LOCK != 0 {
        (*GUARDS)[n as usize] = Some(mutex.lock().unwrap());
    } else {
        &(*GUARDS)[n as usize]
             .take()
             .expect("lock already unlocked");
    }
}

pub fn init() {
    static INIT: Once = ONCE_INIT;

    INIT.call_once(|| unsafe {
                       SSL_library_init();
                       SSL_load_error_strings();
                       OPENSSL_add_all_algorithms_noconf();

                       let num_locks = ::CRYPTO_num_locks();
                       let mut mutexes = Box::new(Vec::new());
                       for _ in 0..num_locks {
                           mutexes.push(Mutex::new(()));
                       }
                       MUTEXES = mem::transmute(mutexes);
                       let guards: Box<Vec<Option<MutexGuard<()>>>> =
                           Box::new((0..num_locks).map(|_| None).collect());
                       GUARDS = mem::transmute(guards);

                       CRYPTO_set_locking_callback(locking_function);
                       set_id_callback();
                   })
}

#[cfg(unix)]
fn set_id_callback() {
    unsafe extern "C" fn thread_id() -> c_ulong {
        ::libc::pthread_self() as c_ulong
    }

    unsafe {
        CRYPTO_set_id_callback(thread_id);
    }
}

#[cfg(not(unix))]
fn set_id_callback() {}

// macros

pub unsafe fn SSL_CTX_set_ecdh_auto(ctx: *mut SSL_CTX, onoff: c_int) -> c_int {
    ::SSL_CTX_ctrl(ctx,
                   SSL_CTRL_SET_ECDH_AUTO,
                   onoff as c_long,
                   ptr::null_mut()) as c_int
}

pub unsafe fn SSL_set_ecdh_auto(ssl: *mut ::SSL, onoff: c_int) -> c_int {
    ::SSL_ctrl(ssl,
               SSL_CTRL_SET_ECDH_AUTO,
               onoff as c_long,
               ptr::null_mut()) as c_int
}

pub unsafe fn SSL_session_reused(ssl: *mut ::SSL) -> c_int {
    ::SSL_ctrl(ssl, SSL_CTRL_GET_SESSION_REUSED, 0, ptr::null_mut()) as c_int
}

extern "C" {
    pub fn BIO_new(type_: *mut BIO_METHOD) -> *mut BIO;
    pub fn BIO_s_file() -> *mut BIO_METHOD;
    pub fn BIO_s_mem() -> *mut BIO_METHOD;

    pub fn get_rfc2409_prime_768(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc2409_prime_1024(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_1536(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_2048(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_3072(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_4096(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_6144(bn: *mut BIGNUM) -> *mut BIGNUM;
    pub fn get_rfc3526_prime_8192(bn: *mut BIGNUM) -> *mut BIGNUM;

    pub fn CRYPTO_malloc(num: c_int, file: *const c_char, line: c_int) -> *mut c_void;
    pub fn CRYPTO_free(buf: *mut c_void);
    pub fn CRYPTO_num_locks() -> c_int;
    pub fn CRYPTO_set_locking_callback(func: unsafe extern "C" fn(mode: c_int,
                                                                  n: c_int,
                                                                  file: *const c_char,
                                                                  line: c_int));
    pub fn CRYPTO_set_id_callback(func: unsafe extern "C" fn() -> c_ulong);

    pub fn ERR_load_crypto_strings();

    pub fn RSA_generate_key(modsz: c_int,
                            e: c_ulong,
                            cb: Option<extern "C" fn(c_int, c_int, *mut c_void)>,
                            cbarg: *mut c_void)
                            -> *mut RSA;

    pub fn OCSP_cert_to_id(dgst: *const ::EVP_MD,
                           subject: *mut ::X509,
                           issuer: *mut ::X509)
                           -> *mut ::OCSP_CERTID;

    pub fn PKCS12_create(pass: *mut c_char,
                         friendly_name: *mut c_char,
                         pkey: *mut EVP_PKEY,
                         cert: *mut X509,
                         ca: *mut stack_st_X509,
                         nid_key: c_int,
                         nid_cert: c_int,
                         iter: c_int,
                         mac_iter: c_int,
                         keytype: c_int)
                         -> *mut PKCS12;

    pub fn SSL_library_init() -> c_int;
    pub fn SSL_load_error_strings();
    pub fn OPENSSL_add_all_algorithms_noconf();
    pub fn HMAC_CTX_init(ctx: *mut ::HMAC_CTX);
    pub fn HMAC_CTX_cleanup(ctx: *mut ::HMAC_CTX);
    pub fn TLSv1_method() -> *const ::SSL_METHOD;
    pub fn SSLv23_method() -> *const ::SSL_METHOD;
    pub fn TLSv1_1_method() -> *const ::SSL_METHOD;
    pub fn TLSv1_2_method() -> *const ::SSL_METHOD;
    pub fn DTLSv1_method() -> *const ::SSL_METHOD;
    pub fn SSL_get_ex_new_index(argl: c_long,
                                argp: *mut c_void,
                                new_func: Option<::CRYPTO_EX_new>,
                                dup_func: Option<::CRYPTO_EX_dup>,
                                free_func: Option<::CRYPTO_EX_free>)
                                -> c_int;
    pub fn SSL_set_tmp_ecdh_callback(ssl: *mut ::SSL,
                                     ecdh: unsafe extern "C" fn(ssl: *mut ::SSL,
                                                                is_export: c_int,
                                                                keylength: c_int)
                                                                -> *mut ::EC_KEY);
    pub fn SSL_CIPHER_get_version(cipher: *const ::SSL_CIPHER) -> *mut c_char;
    pub fn SSL_CTX_get_ex_new_index(argl: c_long,
                                    argp: *mut c_void,
                                    new_func: Option<::CRYPTO_EX_new>,
                                    dup_func: Option<::CRYPTO_EX_dup>,
                                    free_func: Option<::CRYPTO_EX_free>)
                                    -> c_int;
    pub fn SSL_CTX_set_tmp_ecdh_callback(ctx: *mut ::SSL_CTX,
                                         ecdh: unsafe extern "C" fn(ssl: *mut ::SSL,
                                                                    is_export: c_int,
                                                                    keylength: c_int)
                                                                    -> *mut ::EC_KEY);
    pub fn X509_get_subject_name(x: *mut ::X509) -> *mut ::X509_NAME;
    pub fn X509_set_notAfter(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
    pub fn X509_set_notBefore(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
    pub fn X509_get_ext_d2i(x: *mut ::X509,
                            nid: c_int,
                            crit: *mut c_int,
                            idx: *mut c_int)
                            -> *mut c_void;
    pub fn X509_NAME_add_entry_by_NID(x: *mut ::X509_NAME,
                                      field: c_int,
                                      ty: c_int,
                                      bytes: *mut c_uchar,
                                      len: c_int,
                                      loc: c_int,
                                      set: c_int)
                                      -> c_int;
    pub fn X509_NAME_get_entry(n: *mut ::X509_NAME, loc: c_int) -> *mut ::X509_NAME_ENTRY;
    pub fn X509_NAME_ENTRY_get_data(ne: *mut ::X509_NAME_ENTRY) -> *mut ::ASN1_STRING;
    pub fn X509_STORE_CTX_get_chain(ctx: *mut ::X509_STORE_CTX) -> *mut stack_st_X509;
    pub fn X509V3_EXT_nconf_nid(conf: *mut ::CONF,
                                ctx: *mut ::X509V3_CTX,
                                ext_nid: c_int,
                                value: *mut c_char)
                                -> *mut ::X509_EXTENSION;
    pub fn X509V3_EXT_nconf(conf: *mut ::CONF,
                            ctx: *mut ::X509V3_CTX,
                            name: *mut c_char,
                            value: *mut c_char)
                            -> *mut ::X509_EXTENSION;
    pub fn ASN1_STRING_to_UTF8(out: *mut *mut c_uchar, s: *mut ::ASN1_STRING) -> c_int;
    pub fn ASN1_STRING_data(x: *mut ::ASN1_STRING) -> *mut c_uchar;
    pub fn CRYPTO_add_lock(pointer: *mut c_int,
                           amount: c_int,
                           type_: c_int,
                           file: *const c_char,
                           line: c_int)
                           -> c_int;
    pub fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
    pub fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);
    pub fn EVP_PKEY_bits(key: *mut EVP_PKEY) -> c_int;

    pub fn sk_new_null() -> *mut _STACK;
    pub fn sk_num(st: *const _STACK) -> c_int;
    pub fn sk_value(st: *const _STACK, n: c_int) -> *mut c_void;
    pub fn sk_free(st: *mut _STACK);
    pub fn sk_push(st: *mut _STACK, data: *mut c_void) -> c_int;
    pub fn sk_pop_free(st: *mut _STACK, free: Option<unsafe extern "C" fn(*mut c_void)>);
    pub fn sk_pop(st: *mut _STACK) -> *mut c_void;

    pub fn SSLeay() -> c_ulong;
    pub fn SSLeay_version(key: c_int) -> *const c_char;
}
