use libc::{c_int, c_char, c_void, c_long, c_uchar, size_t, c_uint, c_ulong, time_t};

use super::*;

#[repr(C)]
pub struct SSL {
    version: c_int,
    method: *const ::SSL_METHOD,
    rbio: *mut ::BIO,
    wbio: *mut ::BIO,
    bbio: *mut ::BIO,
    pub server: c_int,
    s3: *mut c_void,
    d1: *mut c_void,
    param: *mut c_void,
    cipher_list: *mut stack_st_SSL_CIPHER,
    cert: *mut c_void,
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; ::SSL_MAX_SID_CTX_LENGTH as usize],
    session: *mut ::SSL_SESSION,
    verify_mode: c_int,
    error: c_int,
    error_code: c_int,
    ctx: *mut ::SSL_CTX,
    verify_result: c_long,
    references: c_int,
    client_version: c_int,
    max_send_fragment: c_uint,
    tlsext_hostname: *mut c_char,
    tlsext_status_type: c_int,
    initial_ctx: *mut ::SSL_CTX,
    enc_read_ctx: *mut ::EVP_CIPHER_CTX,
    read_hash: *mut EVP_MD_CTX,
    internal: *mut c_void,
}

#[repr(C)]
pub struct SSL_CTX {
    method: *const ::SSL_METHOD,
    cipher_list: *mut stack_st_SSL_CIPHER,
    cert_store: *mut c_void,
    session_timeout: c_long,
    pub references: c_int,
    extra_certs: *mut stack_st_X509,
    verify_mode: c_int,
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; ::SSL_MAX_SID_CTX_LENGTH as usize],
    param: *mut ::X509_VERIFY_PARAM,
    default_passwd_callback: *mut c_void,
    default_passwd_callback_userdata: *mut c_void,
    internal: *mut c_void,
}

#[repr(C)]
pub struct SSL_SESSION {
    ssl_version: c_int,
    pub master_key_length: c_int,
    pub master_key: [c_uchar; 48],
    session_id_length: c_uint,
    session_id: [c_uchar; ::SSL_MAX_SSL_SESSION_ID_LENGTH as usize],
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; ::SSL_MAX_SID_CTX_LENGTH as usize],
    peer: *mut ::X509,
    verify_result: c_long,
    timeout: c_long,
    time: time_t,
    pub references: c_int,
    cipher: *const ::SSL_CIPHER,
    cipher_id: c_long,
    ciphers: *mut stack_st_SSL_CIPHER,
    tlsext_hostname: *mut c_char,
    tlsext_tick: *mut c_uchar,
    tlsext_ticklen: size_t,
    tlsext_tick_lifetime_int: c_long,
    internal: *mut c_void,
}

#[repr(C)]
pub struct X509_VERIFY_PARAM {
    pub name: *mut c_char,
    pub check_time: time_t,
    pub inh_flags: c_ulong,
    pub flags: c_ulong,
    pub purpose: c_int,
    pub trust: c_int,
    pub depth: c_int,
    policies: *mut stack_st_ASN1_OBJECT,
    id: *mut c_void,
}
