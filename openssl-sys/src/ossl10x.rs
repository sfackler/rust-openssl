use std::sync::{Mutex, MutexGuard};
use std::sync::{Once, ONCE_INIT};
use std::mem;
use std::ptr;

use libc::{c_int, c_char, c_void, c_long, c_uchar, size_t, c_uint, c_ulong};
#[cfg(not(ossl101))]
use libc::time_t;

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

    pub bignum_data: *mut c_char,
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
    pub dummy: c_int,
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
    #[cfg(not(osslconf = "OPENSSL_NO_RFC3779"))]
    rfc3779_addr: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_RFC3779"))]
    rfc3779_asid: *mut c_void,
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

#[repr(C)]
pub struct SSL {
    version: c_int,
    type_: c_int,
    method: *const ::SSL_METHOD,
    rbio: *mut c_void,
    wbio: *mut c_void,
    bbio: *mut c_void,
    rwstate: c_int,
    in_handshake: c_int,
    handshake_func: Option<unsafe extern "C" fn(*mut SSL) -> c_int>,
    pub server: c_int,
    new_session: c_int,
    quiet_session: c_int,
    shutdown: c_int,
    state: c_int,
    rstate: c_int,
    init_buf: *mut c_void,
    init_msg: *mut c_void,
    init_num: c_int,
    init_off: c_int,
    packet: *mut c_uchar,
    packet_length: c_uint,
    s2: *mut c_void,
    s3: *mut c_void,
    d1: *mut c_void,
    read_ahead: c_int,
    msg_callback: Option<unsafe extern "C" fn(c_int,
                                              c_int,
                                              c_int,
                                              *const c_void,
                                              size_t,
                                              *mut SSL,
                                              *mut c_void)>,
    msg_callback_arg: *mut c_void,
    hit: c_int,
    param: *mut c_void,
    cipher_list: *mut stack_st_SSL_CIPHER,
    cipher_list_by_id: *mut stack_st_SSL_CIPHER,
    mac_flags: c_int,
    enc_read_ctx: *mut ::EVP_CIPHER_CTX,
    read_hash: *mut ::EVP_MD_CTX,
    expand: *mut c_void,
    enc_write_ctx: *mut ::EVP_CIPHER_CTX,
    write_hash: *mut ::EVP_MD_CTX,
    compress: *mut c_void,
    cert: *mut c_void,
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; ::SSL_MAX_SID_CTX_LENGTH as usize],
    session: *mut ::SSL_SESSION,
    generate_session_id: ::GEN_SESSION_CB,
    verify_mode: c_int,
    verify_callback: Option<unsafe extern "C" fn(c_int, *mut ::X509_STORE_CTX) -> c_int>,
    info_callback: Option<unsafe extern "C" fn(*mut SSL, c_int, c_int)>,
    error: c_int,
    error_code: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_KRB5"))]
    kssl_ctx: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_client_callback: Option<unsafe extern "C" fn(*mut SSL,
                                                         *const c_char,
                                                         *mut c_char,
                                                         c_uint,
                                                         *mut c_uchar,
                                                         c_uint)
                                                         -> c_uint>,
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_server_callback:
        Option<unsafe extern "C" fn(*mut SSL, *const c_char, *mut c_uchar, c_uint) -> c_uint>,
    ctx: *mut ::SSL_CTX,
    debug: c_int,
    verify_result: c_long,
    ex_data: ::CRYPTO_EX_DATA,
    client_CA: *mut stack_st_X509_NAME,
    references: c_int,
    options: c_ulong,
    mode: c_ulong,
    max_cert_list: c_long,
    first_packet: c_int,
    client_version: c_int,
    max_send_fragment: c_uint,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_debug_cb:
        Option<unsafe extern "C" fn(*mut SSL, c_int, c_int, *mut c_uchar, c_int, *mut c_void)>,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_debug_arg: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_hostname: *mut c_char,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    servername_done: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_status_type: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_status_expected: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ocsp_ids: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ocsp_exts: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ocsp_resp: *mut c_uchar,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ocsp_resplen: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ticket_expected: c_int,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ecpointformatlist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ecpointformatlist: *mut c_uchar,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ellipticcurvelist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ellipticcurvelist: *mut c_uchar,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_opaque_prf_input: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_opaque_prf_input_len: size_t,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_session_ticket: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_session_ticket_ext_cb: ::tls_session_ticket_ext_cb_fn,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tls_session_ticket_ext_cb_arg: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tls_session_secret_cb: ::tls_session_secret_cb_fn,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tls_session_secret_cb_arg: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    initial_ctx: *mut ::SSL_CTX,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_proto_negotiated: *mut c_uchar,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_proto_negotiated_len: c_uchar,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    srtp_profiles: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    srtp_profile: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_heartbeat: c_uint,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_hb_pending: c_uint,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_hb_seq: c_uint,
    renegotiate: c_int,
    #[cfg(not(osslconf = "OPENSSL_NO_SRP"))]
    srp_ctx: ::SRP_CTX,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_client_proto_list: *mut c_uchar,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_client_proto_list_len: c_uint,
}

#[repr(C)]
pub struct SSL_CTX {
    method: *mut c_void,
    cipher_list: *mut c_void,
    cipher_list_by_id: *mut c_void,
    cert_store: *mut c_void,
    sessions: *mut c_void,
    session_cache_size: c_ulong,
    session_cache_head: *mut c_void,
    session_cache_tail: *mut c_void,
    session_cache_mode: c_int,
    session_timeout: c_long,
    new_session_cb: *mut c_void,
    remove_session_cb: *mut c_void,
    get_session_cb: *mut c_void,
    stats: [c_int; 11],
    pub references: c_int,
    app_verify_callback: *mut c_void,
    app_verify_arg: *mut c_void,
    default_passwd_callback: *mut c_void,
    default_passwd_callback_userdata: *mut c_void,
    client_cert_cb: *mut c_void,
    app_gen_cookie_cb: *mut c_void,
    app_verify_cookie_cb: *mut c_void,
    ex_dat: ::CRYPTO_EX_DATA,
    rsa_md5: *mut c_void,
    md5: *mut c_void,
    sha1: *mut c_void,
    extra_certs: *mut c_void,
    comp_methods: *mut c_void,
    info_callback: *mut c_void,
    client_CA: *mut c_void,
    options: c_ulong,
    mode: c_ulong,
    max_cert_list: c_long,
    cert: *mut c_void,
    read_ahead: c_int,
    msg_callback: *mut c_void,
    msg_callback_arg: *mut c_void,
    verify_mode: c_int,
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; 32],
    default_verify_callback: *mut c_void,
    generate_session_id: *mut c_void,
    param: *mut c_void,
    quiet_shutdown: c_int,
    max_send_fragment: c_uint,

    #[cfg(not(osslconf = "OPENSSL_NO_ENGINE"))]
    client_cert_engine: *mut c_void,

    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_servername_callback: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsect_servername_arg: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_tick_key_name: [c_uchar; 16],
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_tick_hmac_key: [c_uchar; 16],
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_tick_aes_key: [c_uchar; 16],
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ticket_key_cb: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_status_cb: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_status_arg: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_opaque_prf_input_callback: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_opaque_prf_input_callback_arg: *mut c_void,

    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_identity_hint: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_client_callback: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_server_callback: *mut c_void,

    #[cfg(not(osslconf = "OPENSSL_NO_BUF_FREELISTS"))]
    freelist_max_len: c_uint,
    #[cfg(not(osslconf = "OPENSSL_NO_BUF_FREELISTS"))]
    wbuf_freelist: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_BUF_FREELISTS"))]
    rbuf_freelist: *mut c_void,

    #[cfg(not(osslconf = "OPENSSL_NO_SRP"))]
    srp_ctx: SRP_CTX,

    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_protos_advertised_cb: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_protos_advertised_cb_arg: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_proto_select_cb: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_NEXTPROTONEG")))]
    next_proto_select_cb_arg: *mut c_void,

    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl101))]
    srtp_profiles: *mut c_void,

    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    srtp_profiles: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_select_cb: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_select_cb_arg: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_client_proto_list: *mut c_void,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), ossl102))]
    alpn_client_proto_list_len: c_uint,

    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC"), ossl102))]
    tlsext_ecpointformatlist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC"), ossl102))]
    tlsext_ecpointformatlist: *mut c_uchar,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC"), ossl102))]
    tlsext_ellipticcurvelist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC"), ossl102))]
    tlsext_ellipticcurvelist: *mut c_uchar,
}

#[repr(C)]
pub struct SSL_SESSION {
    ssl_version: c_int,
    key_arg_length: c_uint,
    key_arg: [c_uchar; SSL_MAX_KEY_ARG_LENGTH as usize],
    pub master_key_length: c_int,
    pub master_key: [c_uchar; 48],
    session_id_length: c_uint,
    session_id: [c_uchar; SSL_MAX_SSL_SESSION_ID_LENGTH as usize],
    sid_ctx_length: c_uint,
    sid_ctx: [c_uchar; SSL_MAX_SID_CTX_LENGTH as usize],
    #[cfg(not(osslconf = "OPENSSL_NO_KRB5"))]
    krb5_client_princ_len: c_uint,
    #[cfg(not(osslconf = "OPENSSL_NO_KRB5"))]
    krb5_client_princ: [c_uchar; SSL_MAX_KRB5_PRINCIPAL_LENGTH as usize],
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_identity_hint: *mut c_char,
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    psk_identity: *mut c_char,
    not_resumable: c_int,
    sess_cert: *mut c_void,
    peer: *mut X509,
    verify_result: c_long,
    pub references: c_int,
    timeout: c_long,
    time: c_long,
    compress_meth: c_uint,
    cipher: *const c_void,
    cipher_id: c_ulong,
    ciphers: *mut c_void,
    ex_data: ::CRYPTO_EX_DATA,
    prev: *mut c_void,
    next: *mut c_void,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_hostname: *mut c_char,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ecpointformatlist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ecpointformatlist: *mut c_uchar,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ellipticcurvelist_length: size_t,
    #[cfg(all(not(osslconf = "OPENSSL_NO_TLSEXT"), not(osslconf = "OPENSSL_NO_EC")))]
    tlsext_ellipticcurvelist: *mut c_uchar,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_tick: *mut c_uchar,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_ticklen: size_t,
    #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
    tlsext_tick_lifetime_hint: c_long,
    #[cfg(not(osslconf = "OPENSSL_NO_SRP"))]
    srp_username: *mut c_char,
}

#[repr(C)]
pub struct SRP_CTX {
    SRP_cb_arg: *mut c_void,
    TLS_ext_srp_username_callback: *mut c_void,
    SRP_verify_param_callback: *mut c_void,
    SRP_give_srp_client_pwd_callback: *mut c_void,
    login: *mut c_void,
    N: *mut c_void,
    g: *mut c_void,
    s: *mut c_void,
    B: *mut c_void,
    A: *mut c_void,
    a: *mut c_void,
    b: *mut c_void,
    v: *mut c_void,
    info: *mut c_void,
    stringth: c_int,
    srp_Mask: c_ulong,
}

#[repr(C)]
#[cfg(not(ossl101))]
pub struct X509_VERIFY_PARAM {
    pub name: *mut c_char,
    pub check_time: time_t,
    pub inh_flags: c_ulong,
    pub flags: c_ulong,
    pub purpose: c_int,
    pub trust: c_int,
    pub depth: c_int,
    pub policies: *mut stack_st_ASN1_OBJECT,
    pub id: *mut X509_VERIFY_PARAM_ID,
}

#[cfg(not(ossl101))]
pub enum X509_VERIFY_PARAM_ID {}
pub enum PKCS12 {}

pub const SSL_CTRL_GET_SESSION_REUSED: c_int = 8;
pub const SSL_CTRL_OPTIONS: c_int = 32;
pub const SSL_CTRL_CLEAR_OPTIONS: c_int = 77;
#[cfg(ossl102)]
pub const SSL_CTRL_SET_ECDH_AUTO: c_int = 94;

pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_ulong = 0x00000001;
pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_ulong = 0x00000002;
pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_ulong = 0x00000008;
pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_ulong = 0x00000020;
pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_ulong = 0x00000080;
pub const SSL_OP_TLS_D5_BUG: c_ulong = 0x00000100;
pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_ulong = 0x00000200;
pub const SSL_OP_SINGLE_ECDH_USE: c_ulong = 0x00080000;
pub const SSL_OP_SINGLE_DH_USE: c_ulong = 0x00100000;
pub const SSL_OP_NO_SSLv2: c_ulong = 0x01000000;

pub const SSL_MAX_SSL_SESSION_ID_LENGTH: c_int = 32;
pub const SSL_MAX_SID_CTX_LENGTH: c_int = 32;
pub const SSL_MAX_KEY_ARG_LENGTH: c_int = 8;
pub const SSL_MAX_MASTER_KEY_LENGTH: c_int = 48;
pub const SSL_MAX_KRB5_PRINCIPAL_LENGTH: c_int = 256;

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

#[cfg(ossl102)]
pub unsafe fn SSL_CTX_set_ecdh_auto(ctx: *mut SSL_CTX, onoff: c_int) -> c_int {
    ::SSL_CTX_ctrl(ctx,
                   SSL_CTRL_SET_ECDH_AUTO,
                   onoff as c_long,
                   ptr::null_mut()) as c_int
}

#[cfg(ossl102)]
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
    #[cfg(not(osslconf = "OPENSSL_NO_SSL3_METHOD"))]
    pub fn SSLv3_method() -> *const ::SSL_METHOD;
    pub fn TLSv1_method() -> *const ::SSL_METHOD;
    pub fn SSLv23_method() -> *const ::SSL_METHOD;
    pub fn TLSv1_1_method() -> *const ::SSL_METHOD;
    pub fn TLSv1_2_method() -> *const ::SSL_METHOD;
    pub fn DTLSv1_method() -> *const ::SSL_METHOD;
    #[cfg(ossl102)]
    pub fn DTLSv1_2_method() -> *const ::SSL_METHOD;
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
    #[cfg(not(ossl101))]
    pub fn X509_get0_signature(psig: *mut *mut ::ASN1_BIT_STRING,
                               palg: *mut *mut ::X509_ALGOR,
                               x: *const ::X509);
    #[cfg(not(ossl101))]
    pub fn X509_get_signature_nid(x: *const X509) -> c_int;
    #[cfg(not(ossl101))]
    pub fn X509_ALGOR_get0(paobj: *mut *mut ::ASN1_OBJECT,
                           pptype: *mut c_int,
                           ppval: *mut *mut c_void,
                           alg: *mut ::X509_ALGOR);
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
