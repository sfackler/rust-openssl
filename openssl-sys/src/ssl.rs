use libc::*;
use std::ptr;

use *;

#[cfg(not(any(libressl, ossl110)))]
pub const SSL_MAX_KRB5_PRINCIPAL_LENGTH: c_int = 256;

#[cfg(not(ossl110))]
pub const SSL_MAX_SSL_SESSION_ID_LENGTH: c_int = 32;
#[cfg(not(ossl110))]
pub const SSL_MAX_SID_CTX_LENGTH: c_int = 32;

#[cfg(not(any(libressl, ossl110)))]
pub const SSL_MAX_KEY_ARG_LENGTH: c_int = 8;
#[cfg(not(ossl110))]
pub const SSL_MAX_MASTER_KEY_LENGTH: c_int = 48;

pub const SSL_SENT_SHUTDOWN: c_int = 1;
pub const SSL_RECEIVED_SHUTDOWN: c_int = 2;

pub const SSL_FILETYPE_PEM: c_int = X509_FILETYPE_PEM;
pub const SSL_FILETYPE_ASN1: c_int = X509_FILETYPE_ASN1;

pub enum SSL_METHOD {}
pub enum SSL_CIPHER {}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        pub enum SSL_SESSION {}
    } else if #[cfg(libressl251)] {
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
    } else if #[cfg(libressl)] {
        #[repr(C)]
        pub struct SSL_SESSION {
            ssl_version: c_int,
            pub master_key_length: c_int,
            pub master_key: [c_uchar; 48],
            session_id_length: c_uint,
            session_id: [c_uchar; SSL_MAX_SSL_SESSION_ID_LENGTH as usize],
            sid_ctx_length: c_uint,
            sid_ctx: [c_uchar; SSL_MAX_SID_CTX_LENGTH as usize],
            not_resumable: c_int,
            sess_cert: *mut c_void,
            peer: *mut X509,
            verify_result: c_long,
            timeout: c_long,
            time: time_t,
            pub references: c_int,
            cipher: *const c_void,
            cipher_id: c_ulong,
            ciphers: *mut c_void,
            ex_data: ::CRYPTO_EX_DATA,
            prev: *mut c_void,
            next: *mut c_void,
            tlsext_hostname: *mut c_char,
            tlsext_ecpointformatlist_length: size_t,
            tlsext_ecpointformatlist: *mut u8,
            tlsext_ellipticcurvelist_length: size_t,
            tlsext_ellipticcurvelist: *mut u16,
            tlsext_tick: *mut c_uchar,
            tlsext_ticklen: size_t,
            tlsext_tick_lifetime_hint: c_long,
        }
    } else {
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
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ecpointformatlist_length: size_t,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ecpointformatlist: *mut c_uchar,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ellipticcurvelist_length: size_t,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
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
    }
}

stack!(stack_st_SSL_CIPHER);

#[repr(C)]
pub struct SRTP_PROTECTION_PROFILE {
    pub name: *const c_char,
    pub id: c_ulong,
}

stack!(stack_st_SRTP_PROTECTION_PROFILE);

pub type tls_session_ticket_ext_cb_fn =
    Option<unsafe extern "C" fn(*mut SSL, *const c_uchar, c_int, *mut c_void) -> c_int>;
pub type tls_session_secret_cb_fn = Option<
    unsafe extern "C" fn(
        *mut SSL,
        *mut c_void,
        *mut c_int,
        *mut stack_st_SSL_CIPHER,
        *mut *mut SSL_CIPHER,
        *mut c_void,
    ) -> c_int,
>;

#[cfg(ossl111)]
pub const SSL_EXT_TLS_ONLY: c_uint = 0x0001;
/* This extension is only allowed in DTLS */
#[cfg(ossl111)]
pub const SSL_EXT_DTLS_ONLY: c_uint = 0x0002;
/* Some extensions may be allowed in DTLS but we don't implement them for it */
#[cfg(ossl111)]
pub const SSL_EXT_TLS_IMPLEMENTATION_ONLY: c_uint = 0x0004;
/* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is */
#[cfg(ossl111)]
pub const SSL_EXT_SSL3_ALLOWED: c_uint = 0x0008;
/* Extension is only defined for TLS1.2 and below */
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_2_AND_BELOW_ONLY: c_uint = 0x0010;
/* Extension is only defined for TLS1.3 and above */
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_ONLY: c_uint = 0x0020;
/* Ignore this extension during parsing if we are resuming */
#[cfg(ossl111)]
pub const SSL_EXT_IGNORE_ON_RESUMPTION: c_uint = 0x0040;
#[cfg(ossl111)]
pub const SSL_EXT_CLIENT_HELLO: c_uint = 0x0080;
/* Really means TLS1.2 or below */
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_2_SERVER_HELLO: c_uint = 0x0100;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_SERVER_HELLO: c_uint = 0x0200;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS: c_uint = 0x0400;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST: c_uint = 0x0800;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_CERTIFICATE: c_uint = 0x1000;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_NEW_SESSION_TICKET: c_uint = 0x2000;
#[cfg(ossl111)]
pub const SSL_EXT_TLS1_3_CERTIFICATE_REQUEST: c_uint = 0x4000;

#[cfg(ossl111)]
pub type SSL_custom_ext_add_cb_ex = Option<
    unsafe extern "C" fn(
        ssl: *mut ::SSL,
        ext_type: c_uint,
        context: c_uint,
        out: *mut *const c_uchar,
        outlen: *mut size_t,
        x: *mut ::X509,
        chainidx: size_t,
        al: *mut c_int,
        add_arg: *mut c_void,
    ) -> c_int,
>;

#[cfg(ossl111)]
pub type SSL_custom_ext_free_cb_ex = Option<
    unsafe extern "C" fn(
        ssl: *mut ::SSL,
        ext_type: c_uint,
        context: c_uint,
        out: *mut *const c_uchar,
        add_arg: *mut c_void,
    ),
>;

#[cfg(ossl111)]
pub type SSL_custom_ext_parse_cb_ex = Option<
    unsafe extern "C" fn(
        ssl: *mut ::SSL,
        ext_type: c_uint,
        context: c_uint,
        input: *const c_uchar,
        inlen: size_t,
        x: *mut ::X509,
        chainidx: size_t,
        al: *mut c_int,
        parse_arg: *mut c_void,
    ) -> c_int,
>;

cfg_if! {
    if #[cfg(ossl300)] {
        macro_rules! ssl_op_type {
            () => {u64};
        }
    } else {
        macro_rules! ssl_op_type {
            () => {c_ulong};
        }
    }
}

pub const SSL_OP_LEGACY_SERVER_CONNECT: ssl_op_type!() = 0x00000004;
cfg_if! {
    if #[cfg(libressl261)] {
        pub const SSL_OP_TLSEXT_PADDING: ssl_op_type!() = 0x0;
    } else if #[cfg(any(ossl102, libressl))] {
        pub const SSL_OP_TLSEXT_PADDING: ssl_op_type!() = 0x10;
    }
}
#[cfg(ossl101)]
pub const SSL_OP_SAFARI_ECDHE_ECDSA_BUG: ssl_op_type!() = 0x00000040;

pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: ssl_op_type!() = 0x00000800;

pub const SSL_OP_NO_QUERY_MTU: ssl_op_type!() = 0x00001000;
pub const SSL_OP_COOKIE_EXCHANGE: ssl_op_type!() = 0x00002000;
pub const SSL_OP_NO_TICKET: ssl_op_type!() = 0x00004000;
cfg_if! {
    if #[cfg(ossl101)] {
        pub const SSL_OP_CISCO_ANYCONNECT: ssl_op_type!() = 0x00008000;
    } else {
        pub const SSL_OP_CISCO_ANYCONNECT: ssl_op_type!() = 0x0;
    }
}

pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: ssl_op_type!() = 0x00010000;
cfg_if! {
    if #[cfg(ossl101)] {
        pub const SSL_OP_NO_COMPRESSION: ssl_op_type!() = 0x00020000;
        pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: ssl_op_type!() = 0x00040000;
    } else {
        pub const SSL_OP_NO_COMPRESSION: ssl_op_type!() = 0x0;
        pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: ssl_op_type!() = 0x0;
    }
}

#[cfg(ossl111)]
pub const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: ssl_op_type!() = 0x00100000;

pub const SSL_OP_CIPHER_SERVER_PREFERENCE: ssl_op_type!() = 0x00400000;
cfg_if! {
    if #[cfg(libressl280)] {
        pub const SSL_OP_TLS_ROLLBACK_BUG: ssl_op_type!() = 0;
    } else {
        pub const SSL_OP_TLS_ROLLBACK_BUG: ssl_op_type!() = 0x00800000;
    }
}

cfg_if! {
    if #[cfg(ossl101)] {
        pub const SSL_OP_NO_SSLv3: ssl_op_type!() = 0x02000000;
    } else {
        pub const SSL_OP_NO_SSLv3: ssl_op_type!() = 0x0;
    }
}
pub const SSL_OP_NO_TLSv1_1: ssl_op_type!() = 0x10000000;
pub const SSL_OP_NO_TLSv1_2: ssl_op_type!() = 0x08000000;

pub const SSL_OP_NO_TLSv1: ssl_op_type!() = 0x04000000;
cfg_if! {
    if #[cfg(ossl102)] {
        pub const SSL_OP_NO_DTLSv1: ssl_op_type!() = 0x04000000;
        pub const SSL_OP_NO_DTLSv1_2: ssl_op_type!() = 0x08000000;
    } else if #[cfg(libressl332)] {
        pub const SSL_OP_NO_DTLSv1: ssl_op_type!() = 0x40000000;
        pub const SSL_OP_NO_DTLSv1_2: ssl_op_type!() = 0x80000000;
    }
}
#[cfg(ossl111)]
pub const SSL_OP_NO_TLSv1_3: ssl_op_type!() = 0x20000000;

#[cfg(ossl110h)]
pub const SSL_OP_NO_RENEGOTIATION: ssl_op_type!() = 0x40000000;

cfg_if! {
    if #[cfg(ossl111)] {
        pub const SSL_OP_NO_SSL_MASK: ssl_op_type!() = SSL_OP_NO_SSLv2
            | SSL_OP_NO_SSLv3
            | SSL_OP_NO_TLSv1
            | SSL_OP_NO_TLSv1_1
            | SSL_OP_NO_TLSv1_2
            | SSL_OP_NO_TLSv1_3;
    } else if #[cfg(ossl102)] {
        pub const SSL_OP_NO_SSL_MASK: ssl_op_type!() =
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
    }
}

cfg_if! {
    if #[cfg(libressl261)] {
        pub const SSL_OP_CRYPTOPRO_TLSEXT_BUG: ssl_op_type!() = 0x0;
    } else {
        pub const SSL_OP_CRYPTOPRO_TLSEXT_BUG: ssl_op_type!() = 0x80000000;
    }
}

cfg_if! {
    if #[cfg(ossl300)] {
        pub const SSL_OP_ALL: ssl_op_type!() = SSL_OP_CRYPTOPRO_TLSEXT_BUG
            | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            | SSL_OP_TLSEXT_PADDING
            | SSL_OP_SAFARI_ECDHE_ECDSA_BUG;
    } else if #[cfg(ossl110f)] {
        pub const SSL_OP_ALL: ssl_op_type!() = SSL_OP_CRYPTOPRO_TLSEXT_BUG
            | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            | SSL_OP_LEGACY_SERVER_CONNECT
            | SSL_OP_TLSEXT_PADDING
            | SSL_OP_SAFARI_ECDHE_ECDSA_BUG;
    } else if #[cfg(libressl261)] {
        pub const SSL_OP_ALL: ssl_op_type!() = 0x4;
    } else if #[cfg(libressl)] {
        pub const SSL_OP_ALL: ssl_op_type!() = 0x80000014;
    } else {
        pub const SSL_OP_ALL: ssl_op_type!() = 0x80000BFF;
    }
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_TLS_D5_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_SINGLE_ECDH_USE: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_SINGLE_DH_USE: ssl_op_type!() = 0x00000000;
        pub const SSL_OP_NO_SSLv2: ssl_op_type!() = 0x00000000;
    } else if #[cfg(ossl101)] {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: ssl_op_type!() = 0x00000001;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: ssl_op_type!() = 0x00000002;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: ssl_op_type!() = 0x00000008;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: ssl_op_type!() = 0x00000020;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: ssl_op_type!() = 0x00000080;
        pub const SSL_OP_TLS_D5_BUG: ssl_op_type!() = 0x00000100;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: ssl_op_type!() = 0x00000200;
        pub const SSL_OP_SINGLE_ECDH_USE: ssl_op_type!() = 0x00080000;
        pub const SSL_OP_SINGLE_DH_USE: ssl_op_type!() = 0x00100000;
        pub const SSL_OP_NO_SSLv2: ssl_op_type!() = 0x01000000;
    } else {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: ssl_op_type!() = 0x0;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: ssl_op_type!() = 0x0;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: ssl_op_type!() = 0x0;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: ssl_op_type!() = 0x0;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: ssl_op_type!() = 0x0;
        pub const SSL_OP_TLS_D5_BUG: ssl_op_type!() = 0x0;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: ssl_op_type!() = 0x0;
        #[cfg(libressl261)]
        pub const SSL_OP_SINGLE_ECDH_USE: ssl_op_type!() = 0x0;
        #[cfg(not(libressl261))]
        pub const SSL_OP_SINGLE_ECDH_USE: ssl_op_type!() = 0x00080000;
        pub const SSL_OP_SINGLE_DH_USE: ssl_op_type!() = 0x00100000;
        pub const SSL_OP_NO_SSLv2: ssl_op_type!() = 0x0;
    }
}

pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x2;
pub const SSL_MODE_AUTO_RETRY: c_long = 0x4;
pub const SSL_MODE_NO_AUTO_CHAIN: c_long = 0x8;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x10;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_CLIENTHELLO_TIME: c_long = 0x20;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_SERVERHELLO_TIME: c_long = 0x40;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_FALLBACK_SCSV: c_long = 0x80;

pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, ptr::null_mut())
}

#[cfg(ossl111)]
pub const SSL_COOKIE_LENGTH: c_int = 4096;

cfg_if! {
    if #[cfg(ossl300)] {
        extern "C" {
            pub fn SSL_CTX_get_options(ctx: *const SSL_CTX) -> u64;
            pub fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64;
            pub fn SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: u64) -> u64;
        }
    } else if #[cfg(ossl110)] {
        extern "C" {
            pub fn SSL_CTX_get_options(ctx: *const SSL_CTX) -> c_ulong;
            pub fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: c_ulong) -> c_ulong;
            pub fn SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: c_ulong) -> c_ulong;
        }
    } else {
        pub unsafe fn SSL_CTX_get_options(ctx: *const SSL_CTX) -> c_ulong {
            SSL_CTX_ctrl(ctx as *mut _, SSL_CTRL_OPTIONS, 0, ptr::null_mut()) as c_ulong
        }

        pub unsafe fn SSL_CTX_set_options(ctx: *const SSL_CTX, op: c_ulong) -> c_ulong {
            SSL_CTX_ctrl(
                ctx as *mut _,
                SSL_CTRL_OPTIONS,
                op as c_long,
                ptr::null_mut(),
            ) as c_ulong
        }

        pub unsafe fn SSL_CTX_clear_options(ctx: *const SSL_CTX, op: c_ulong) -> c_ulong {
            SSL_CTX_ctrl(
                ctx as *mut _,
                SSL_CTRL_CLEAR_OPTIONS,
                op as c_long,
                ptr::null_mut(),
            ) as c_ulong
        }
    }
}

pub unsafe fn SSL_set_mtu(ssl: *mut SSL, mtu: c_long) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_SET_MTU, mtu, ptr::null_mut())
}

#[cfg(ossl110)]
pub unsafe fn SSL_get_extms_support(ssl: *mut SSL) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_GET_EXTMS_SUPPORT, 0, ptr::null_mut())
}

pub type GEN_SESSION_CB =
    Option<unsafe extern "C" fn(*const SSL, *mut c_uchar, *mut c_uint) -> c_int>;

pub const SSL_SESS_CACHE_OFF: c_long = 0x0;
pub const SSL_SESS_CACHE_CLIENT: c_long = 0x1;
pub const SSL_SESS_CACHE_SERVER: c_long = 0x2;
pub const SSL_SESS_CACHE_BOTH: c_long = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_long = 0x80;
pub const SSL_SESS_CACHE_NO_INTERNAL_LOOKUP: c_long = 0x100;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_long = 0x200;
pub const SSL_SESS_CACHE_NO_INTERNAL: c_long =
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE;

extern "C" {
    pub fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SSL_CTX,
        new_session_cb: Option<unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> c_int>,
    );
    pub fn SSL_CTX_sess_set_remove_cb(
        ctx: *mut SSL_CTX,
        remove_session_cb: Option<unsafe extern "C" fn(*mut SSL_CTX, *mut SSL_SESSION)>,
    );
}
cfg_if! {
    // const change in passed function pointer signature
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn SSL_CTX_sess_set_get_cb(
                ctx: *mut ::SSL_CTX,
                get_session_cb: Option<
                    unsafe extern "C" fn(*mut ::SSL, *const c_uchar, c_int, *mut c_int) -> *mut SSL_SESSION,
                >,
            );
        }
    } else {
        extern "C" {
            pub fn SSL_CTX_sess_set_get_cb(
                ctx: *mut ::SSL_CTX,
                get_session_cb: Option<
                    unsafe extern "C" fn(*mut ::SSL, *mut c_uchar, c_int, *mut c_int) -> *mut SSL_SESSION,
                >,
            );
        }
    }
}
extern "C" {
    // FIXME change to unsafe extern "C" fn
    pub fn SSL_CTX_set_cookie_generate_cb(
        s: *mut SSL_CTX,
        cb: Option<
            extern "C" fn(ssl: *mut SSL, cookie: *mut c_uchar, cookie_len: *mut c_uint) -> c_int,
        >,
    );
}

cfg_if! {
    // const change in passed function pointer signature
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn SSL_CTX_set_cookie_verify_cb(
                s: *mut SSL_CTX,
                cb: Option<
                    extern "C" fn(ssl: *mut SSL, cookie: *const c_uchar, cookie_len: c_uint) -> c_int,
                >,
            );
        }
    } else {
        extern "C" {
            pub fn SSL_CTX_set_cookie_verify_cb(
                s: *mut SSL_CTX,
                cb: Option<extern "C" fn(ssl: *mut SSL, cookie: *mut c_uchar, cookie_len: c_uint) -> c_int>,
            );
        }
    }
}

extern "C" {
    #[cfg(ossl111)]
    pub fn SSL_CTX_set_stateless_cookie_generate_cb(
        s: *mut SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut SSL,
                cookie: *mut c_uchar,
                cookie_len: *mut size_t,
            ) -> c_int,
        >,
    );
    #[cfg(ossl111)]
    pub fn SSL_CTX_set_stateless_cookie_verify_cb(
        s: *mut SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut SSL,
                cookie: *const c_uchar,
                cookie_len: size_t,
            ) -> c_int,
        >,
    );

    pub fn SSL_CTX_set_next_protos_advertised_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *const c_uchar,
            outlen: *mut c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    pub fn SSL_CTX_set_next_proto_select_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *mut c_uchar,
            outlen: *mut c_uchar,
            inbuf: *const c_uchar,
            inlen: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    pub fn SSL_get0_next_proto_negotiated(
        s: *const SSL,
        data: *mut *const c_uchar,
        len: *mut c_uint,
    );

    pub fn SSL_select_next_proto(
        out: *mut *mut c_uchar,
        outlen: *mut c_uchar,
        inbuf: *const c_uchar,
        inlen: c_uint,
        client: *const c_uchar,
        client_len: c_uint,
    ) -> c_int;
}

pub const OPENSSL_NPN_UNSUPPORTED: c_int = 0;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;
pub const OPENSSL_NPN_NO_OVERLAP: c_int = 2;

extern "C" {
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_CTX_set_alpn_protos(s: *mut SSL_CTX, data: *const c_uchar, len: c_uint) -> c_int;
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_set_alpn_protos(s: *mut SSL, data: *const c_uchar, len: c_uint) -> c_int;
    // FIXME should take an Option<unsafe extern "C" fn>
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_CTX_set_alpn_select_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *const c_uchar,
            outlen: *mut c_uchar,
            inbuf: *const c_uchar,
            inlen: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_get0_alpn_selected(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
extern "C" {
    pub fn SSL_CTX_set_psk_client_callback(
        ssl: *mut SSL_CTX,
        psk_client_cb: Option<
            extern "C" fn(
                *mut SSL,
                *const c_char,
                *mut c_char,
                c_uint,
                *mut c_uchar,
                c_uint,
            ) -> c_uint,
        >,
    );
    pub fn SSL_CTX_set_psk_server_callback(
        ssl: *mut SSL_CTX,
        psk_server_cb: Option<
            extern "C" fn(*mut SSL, *const c_char, *mut c_uchar, c_uint) -> c_uint,
        >,
    );
}

extern "C" {
    #[cfg(ossl111)]
    pub fn SSL_CTX_add_custom_ext(
        ctx: *mut ::SSL_CTX,
        ext_type: c_uint,
        context: c_uint,
        add_cb: SSL_custom_ext_add_cb_ex,
        free_cb: SSL_custom_ext_free_cb_ex,
        add_arg: *mut c_void,
        parse_cb: SSL_custom_ext_parse_cb_ex,
        parse_arg: *mut c_void,
    ) -> c_int;

    #[cfg(ossl102)]
    pub fn SSL_extension_supported(ext_type: c_uint) -> c_int;
}

#[cfg(ossl111)]
pub type SSL_CTX_keylog_cb_func =
    Option<unsafe extern "C" fn(ssl: *const SSL, line: *const c_char)>;

extern "C" {
    #[cfg(ossl111)]
    pub fn SSL_CTX_set_keylog_callback(ctx: *mut SSL_CTX, cb: SSL_CTX_keylog_cb_func);

    #[cfg(ossl111)]
    pub fn SSL_CTX_set_max_early_data(ctx: *mut SSL_CTX, max_early_data: u32) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_CTX_get_max_early_data(ctx: *const SSL_CTX) -> u32;
    #[cfg(ossl111)]
    pub fn SSL_set_max_early_data(ctx: *mut SSL, max_early_data: u32) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_get_max_early_data(ctx: *const SSL) -> u32;

    pub fn SSL_get_finished(s: *const SSL, buf: *mut c_void, count: size_t) -> size_t;
    pub fn SSL_get_peer_finished(s: *const SSL, buf: *mut c_void, count: size_t) -> size_t;

    pub fn SSL_CTX_get_verify_mode(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_get_verify_mode(s: *const SSL) -> c_int;
}

const_ptr_api! {
    extern "C" {
        #[cfg(ossl110)]
        pub fn SSL_is_init_finished(s: #[const_ptr_if(ossl111)] SSL) -> c_int;
    }
}

pub const SSL_AD_ILLEGAL_PARAMETER: c_int = SSL3_AD_ILLEGAL_PARAMETER;
pub const SSL_AD_DECODE_ERROR: c_int = TLS1_AD_DECODE_ERROR;
pub const SSL_AD_UNRECOGNIZED_NAME: c_int = TLS1_AD_UNRECOGNIZED_NAME;
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
#[cfg(ossl111)]
pub const SSL_ERROR_WANT_CLIENT_HELLO_CB: c_int = 11;
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
pub const SSL_CTRL_SET_TMP_DH: c_int = 3;
pub const SSL_CTRL_SET_TMP_ECDH: c_int = 4;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_GET_SESSION_REUSED: c_int = 8;
pub const SSL_CTRL_EXTRA_CHAIN_CERT: c_int = 14;
pub const SSL_CTRL_SET_MTU: c_int = 17;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_OPTIONS: c_int = 32;
pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
pub const SSL_CTRL_SET_SESS_CACHE_SIZE: c_int = 42;
pub const SSL_CTRL_GET_SESS_CACHE_SIZE: c_int = 43;
pub const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB: c_int = 63;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG: c_int = 64;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE: c_int = 65;
pub const SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP: c_int = 70;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP: c_int = 71;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_CLEAR_OPTIONS: c_int = 77;
pub const SSL_CTRL_GET_EXTRA_CHAIN_CERTS: c_int = 82;
#[cfg(ossl111)]
pub const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
#[cfg(any(libressl, all(ossl102, not(ossl110))))]
pub const SSL_CTRL_SET_ECDH_AUTO: c_int = 94;
#[cfg(ossl102)]
pub const SSL_CTRL_SET_SIGALGS_LIST: c_int = 98;
#[cfg(ossl102)]
pub const SSL_CTRL_SET_VERIFY_CERT_STORE: c_int = 106;
#[cfg(ossl110)]
pub const SSL_CTRL_GET_EXTMS_SUPPORT: c_int = 122;
#[cfg(ossl110)]
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
#[cfg(ossl110)]
pub const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
#[cfg(ossl110g)]
pub const SSL_CTRL_GET_MIN_PROTO_VERSION: c_int = 130;
#[cfg(ossl110g)]
pub const SSL_CTRL_GET_MAX_PROTO_VERSION: c_int = 131;

pub unsafe fn SSL_CTX_set_tmp_dh(ctx: *mut SSL_CTX, dh: *mut DH) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tmp_ecdh(ctx: *mut SSL_CTX, key: *mut EC_KEY) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, key as *mut c_void)
}

pub unsafe fn SSL_set_tmp_dh(ssl: *mut SSL, dh: *mut DH) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_SET_TMP_DH, 0, dh as *mut c_void)
}

pub unsafe fn SSL_set_tmp_ecdh(ssl: *mut SSL, key: *mut EC_KEY) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH, 0, key as *mut c_void)
}

pub unsafe fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509 as *mut c_void)
}

pub unsafe fn SSL_CTX_get_extra_chain_certs(
    ctx: *mut SSL_CTX,
    chain: *mut *mut stack_st_X509,
) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, chain as *mut c_void)
}

#[cfg(ossl102)]
pub unsafe fn SSL_CTX_set0_verify_cert_store(ctx: *mut SSL_CTX, st: *mut X509_STORE) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st as *mut c_void)
}

#[cfg(ossl111)]
pub unsafe fn SSL_CTX_set1_groups_list(ctx: *mut SSL_CTX, s: *const c_char) -> c_long {
    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_GROUPS_LIST,
        0,
        s as *const c_void as *mut c_void,
    )
}

#[cfg(ossl102)]
pub unsafe fn SSL_CTX_set1_sigalgs_list(ctx: *mut SSL_CTX, s: *const c_char) -> c_long {
    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_SIGALGS_LIST,
        0,
        s as *const c_void as *mut c_void,
    )
}

#[cfg(any(libressl, all(ossl102, not(ossl110))))]
pub unsafe fn SSL_CTX_set_ecdh_auto(ctx: *mut SSL_CTX, onoff: c_int) -> c_int {
    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_ECDH_AUTO,
        onoff as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[cfg(any(libress, all(ossl102, not(ossl110))))]
pub unsafe fn SSL_set_ecdh_auto(ssl: *mut ::SSL, onoff: c_int) -> c_int {
    SSL_ctrl(
        ssl,
        SSL_CTRL_SET_ECDH_AUTO,
        onoff as c_long,
        ptr::null_mut(),
    ) as c_int
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: c_int) -> c_int {
            SSL_CTX_ctrl(
                ctx,
                SSL_CTRL_SET_MIN_PROTO_VERSION,
                version as c_long,
                ptr::null_mut(),
            ) as c_int
        }

        pub unsafe fn SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: c_int) -> c_int {
            SSL_CTX_ctrl(
                ctx,
                SSL_CTRL_SET_MAX_PROTO_VERSION,
                version as c_long,
                ptr::null_mut(),
            ) as c_int
        }
    } else if #[cfg(libressl261)] {
        extern "C" {
            pub fn SSL_CTX_set_min_proto_version(ctx: *mut ::SSL_CTX, version: u16) -> c_int;
            pub fn SSL_CTX_set_max_proto_version(ctx: *mut ::SSL_CTX, version: u16) -> c_int;
        }
    }
}

cfg_if! {
    if #[cfg(ossl110g)] {
        pub unsafe fn SSL_CTX_get_min_proto_version(ctx: *mut SSL_CTX) -> c_int {
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, ptr::null_mut()) as c_int
        }

        pub unsafe fn SSL_CTX_get_max_proto_version(ctx: *mut SSL_CTX) -> c_int {
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, ptr::null_mut()) as c_int
        }
    } else if #[cfg(libressl270)] {
        extern "C" {
            pub fn SSL_CTX_get_min_proto_version(ctx: *mut ::SSL_CTX) -> c_int;
            pub fn SSL_CTX_get_max_proto_version(ctx: *mut ::SSL_CTX) -> c_int;
        }
    }
}

#[cfg(ossl110)]
pub unsafe fn SSL_set_min_proto_version(s: *mut SSL, version: c_int) -> c_int {
    SSL_ctrl(
        s,
        SSL_CTRL_SET_MIN_PROTO_VERSION,
        version as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[cfg(ossl110)]
pub unsafe fn SSL_set_max_proto_version(s: *mut SSL, version: c_int) -> c_int {
    SSL_ctrl(
        s,
        SSL_CTRL_SET_MAX_PROTO_VERSION,
        version as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[cfg(ossl110g)]
pub unsafe fn SSL_get_min_proto_version(s: *mut SSL) -> c_int {
    SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, ptr::null_mut()) as c_int
}

#[cfg(ossl110g)]
pub unsafe fn SSL_get_max_proto_version(s: *mut SSL) -> c_int {
    SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, ptr::null_mut()) as c_int
}

extern "C" {
    pub fn SSL_CTX_set_cipher_list(ssl: *mut SSL_CTX, s: *const c_char) -> c_int;
    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    #[cfg(any(ossl110, libressl273))]
    pub fn SSL_CTX_up_ref(x: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_get_cert_store(ctx: *const SSL_CTX) -> *mut X509_STORE;
    pub fn SSL_CTX_set_cert_store(ctx: *mut SSL_CTX, store: *mut X509_STORE);

    pub fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;
    pub fn SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int;
}
const_ptr_api! {
    extern "C" {
        pub fn SSL_CIPHER_get_version(cipher: *const SSL_CIPHER) -> #[const_ptr_if(any(ossl110, libressl280))] c_char;
    }
}
extern "C" {
    #[cfg(ossl111)]
    pub fn SSL_CIPHER_get_handshake_digest(cipher: *const ::SSL_CIPHER) -> *const ::EVP_MD;
    pub fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char;
    #[cfg(ossl111)]
    pub fn SSL_CIPHER_standard_name(cipher: *const SSL_CIPHER) -> *const c_char;
    #[cfg(ossl111)]
    pub fn OPENSSL_cipher_name(rfc_name: *const c_char) -> *const c_char;

    pub fn SSL_pending(ssl: *const SSL) -> c_int;
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub fn SSL_get_rbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_wbio(ssl: *const SSL) -> *mut BIO;
    #[cfg(ossl111)]
    pub fn SSL_CTX_set_ciphersuites(ctx: *mut SSL_CTX, str: *const c_char) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_set_ciphersuites(ssl: *mut ::SSL, str: *const c_char) -> c_int;
    pub fn SSL_set_verify(
        ssl: *mut SSL,
        mode: c_int,
        // FIXME should be unsafe
        verify_callback: Option<extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, key: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, cert: *mut X509) -> c_int;

    pub fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX,
        key_file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    pub fn SSL_CTX_use_certificate_file(
        ctx: *mut SSL_CTX,
        cert_file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    pub fn SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX,
        cert_chain_file: *const c_char,
    ) -> c_int;
    pub fn SSL_load_client_CA_file(file: *const c_char) -> *mut stack_st_X509_NAME;

    #[cfg(not(ossl110))]
    pub fn SSL_load_error_strings();
    pub fn SSL_state_string(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string_long(ssl: *const SSL) -> *const c_char;

    pub fn SSL_SESSION_get_time(s: *const SSL_SESSION) -> c_long;
    pub fn SSL_SESSION_get_timeout(s: *const SSL_SESSION) -> c_long;
    #[cfg(ossl110)]
    pub fn SSL_SESSION_get_protocol_version(s: *const SSL_SESSION) -> c_int;

    #[cfg(ossl111)]
    pub fn SSL_SESSION_set_max_early_data(ctx: *mut SSL_SESSION, max_early_data: u32) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_SESSION_get_max_early_data(ctx: *const SSL_SESSION) -> u32;

    pub fn SSL_SESSION_get_id(s: *const SSL_SESSION, len: *mut c_uint) -> *const c_uchar;
    #[cfg(any(ossl110, libressl273))]
    pub fn SSL_SESSION_up_ref(ses: *mut SSL_SESSION) -> c_int;
    pub fn SSL_SESSION_free(s: *mut SSL_SESSION);
}
const_ptr_api! {
    extern "C" {
        pub fn i2d_SSL_SESSION(s: #[const_ptr_if(ossl300)] SSL_SESSION, pp: *mut *mut c_uchar) -> c_int;
    }
}
extern "C" {
    pub fn SSL_set_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int;
    pub fn SSL_CTX_add_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int;
    pub fn SSL_CTX_remove_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int;
    pub fn d2i_SSL_SESSION(
        a: *mut *mut SSL_SESSION,
        pp: *mut *const c_uchar,
        len: c_long,
    ) -> *mut SSL_SESSION;

    #[cfg(not(ossl300))]
    pub fn SSL_get_peer_certificate(ssl: *const SSL) -> *mut X509;
    #[cfg(ossl300)]
    pub fn SSL_get1_peer_certificate(ssl: *const SSL) -> *mut X509;

    pub fn SSL_get_peer_cert_chain(ssl: *const SSL) -> *mut stack_st_X509;

    pub fn SSL_CTX_set_verify(
        ctx: *mut SSL_CTX,
        mode: c_int,
        verify_callback: Option<extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    pub fn SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int);

    #[cfg(ossl111)]
    pub fn SSL_CTX_set_post_handshake_auth(ctx: *mut SSL_CTX, val: c_int);

    pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;

    pub fn SSL_CTX_set_session_id_context(
        ssl: *mut SSL_CTX,
        sid_ctx: *const c_uchar,
        sid_ctx_len: c_uint,
    ) -> c_int;

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_CTX_get0_param(ctx: *mut SSL_CTX) -> *mut X509_VERIFY_PARAM;

    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;
}

#[cfg(ossl111)]
pub const SSL_CLIENT_HELLO_SUCCESS: c_int = 1;
#[cfg(ossl111)]
pub const SSL_CLIENT_HELLO_ERROR: c_int = 0;
#[cfg(ossl111)]
pub const SSL_CLIENT_HELLO_RETRY: c_int = -1;

#[cfg(ossl111)]
pub type SSL_client_hello_cb_fn =
    Option<unsafe extern "C" fn(s: *mut SSL, al: *mut c_int, arg: *mut c_void) -> c_int>;
extern "C" {
    #[cfg(ossl111)]
    pub fn SSL_CTX_set_client_hello_cb(
        c: *mut SSL_CTX,
        cb: SSL_client_hello_cb_fn,
        arg: *mut c_void,
    );
    #[cfg(ossl111)]
    pub fn SSL_client_hello_isv2(s: *mut SSL) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_legacy_version(s: *mut SSL) -> c_uint;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_random(s: *mut SSL, out: *mut *const c_uchar) -> size_t;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_session_id(s: *mut SSL, out: *mut *const c_uchar) -> size_t;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_ciphers(s: *mut SSL, out: *mut *const c_uchar) -> size_t;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_compression_methods(
        s: *mut SSL,
        out: *mut *const c_uchar,
    ) -> size_t;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get1_extensions_present(
        s: *mut SSL,
        out: *mut *mut c_int,
        outlen: *mut size_t,
    ) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_client_hello_get0_ext(
        s: *mut SSL,
        type_: c_uint,
        out: *mut *const c_uchar,
        outlen: *mut size_t,
    ) -> c_int;

    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_accept(ssl: *mut SSL) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_stateless(s: *mut SSL) -> c_int;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_peek(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_read_early_data(
        s: *mut ::SSL,
        buf: *mut c_void,
        num: size_t,
        readbytes: *mut size_t,
    ) -> c_int;
}

#[cfg(ossl111)]
pub const SSL_READ_EARLY_DATA_ERROR: c_int = 0;
#[cfg(ossl111)]
pub const SSL_READ_EARLY_DATA_SUCCESS: c_int = 1;
#[cfg(ossl111)]
pub const SSL_READ_EARLY_DATA_FINISH: c_int = 2;

extern "C" {
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    #[cfg(ossl111)]
    pub fn SSL_write_early_data(
        s: *mut SSL,
        buf: *const c_void,
        num: size_t,
        written: *mut size_t,
    ) -> c_int;
    pub fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_callback_ctrl(
        ctx: *mut SSL_CTX,
        cmd: c_int,
        fp: Option<extern "C" fn()>,
    ) -> c_long;
}

cfg_if! {
    if #[cfg(any(ossl110, libressl291))] {
        extern "C" {
            pub fn TLS_method() -> *const SSL_METHOD;

            pub fn DTLS_method() -> *const SSL_METHOD;

            pub fn TLS_server_method() -> *const SSL_METHOD;

            pub fn TLS_client_method() -> *const SSL_METHOD;
        }
    } else {
        extern "C" {
            #[cfg(not(osslconf = "OPENSSL_NO_SSL3_METHOD"))]
            pub fn SSLv3_method() -> *const SSL_METHOD;

            pub fn SSLv23_method() -> *const SSL_METHOD;

            pub fn SSLv23_client_method() -> *const SSL_METHOD;

            pub fn SSLv23_server_method() -> *const SSL_METHOD;

            pub fn TLSv1_method() -> *const SSL_METHOD;

            pub fn TLSv1_1_method() -> *const SSL_METHOD;

            pub fn TLSv1_2_method() -> *const SSL_METHOD;

            pub fn DTLSv1_method() -> *const SSL_METHOD;

            #[cfg(ossl102)]
            pub fn DTLSv1_2_method() -> *const SSL_METHOD;
        }
    }
}

extern "C" {
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;

    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;

    pub fn SSL_CTX_set_client_CA_list(ctx: *mut SSL_CTX, list: *mut stack_st_X509_NAME);

    #[cfg(not(libressl))]
    pub fn SSL_CTX_add_client_CA(ctx: *mut SSL_CTX, cacert: *mut X509) -> c_int;

    pub fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        CAfile: *const c_char,
        CApath: *const c_char,
    ) -> c_int;
}

const_ptr_api! {
    extern "C" {
        pub fn SSL_get_ssl_method(ssl: #[const_ptr_if(ossl111b)] SSL) -> *const SSL_METHOD;
    }
}

extern "C" {
    pub fn SSL_set_connect_state(s: *mut SSL);
    pub fn SSL_set_accept_state(s: *mut SSL);

    #[cfg(not(ossl110))]
    pub fn SSL_library_init() -> c_int;

    pub fn SSL_CIPHER_description(
        cipher: *const SSL_CIPHER,
        buf: *mut c_char,
        size: c_int,
    ) -> *mut c_char;

    pub fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
}
const_ptr_api! {
    extern "C" {
        pub fn SSL_get_privatekey(ssl: #[const_ptr_if(any(ossl102, libressl280))] SSL) -> *mut EVP_PKEY;
    }
}

extern "C" {
    #[cfg(ossl102)]
    pub fn SSL_CTX_get0_certificate(ctx: *const SSL_CTX) -> *mut X509;
    #[cfg(ossl102)]
    pub fn SSL_CTX_get0_privatekey(ctx: *const SSL_CTX) -> *mut EVP_PKEY;

    pub fn SSL_set_shutdown(ss: *mut SSL, mode: c_int);
    pub fn SSL_get_shutdown(ssl: *const SSL) -> c_int;
    pub fn SSL_version(ssl: *const SSL) -> c_int;
    pub fn SSL_get_session(s: *const SSL) -> *mut SSL_SESSION;
    pub fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;
    pub fn SSL_set_SSL_CTX(ssl: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX;

    pub fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
    #[cfg(ossl110)]
    pub fn SSL_get0_verified_chain(ssl: *const SSL) -> *mut stack_st_X509;

    #[cfg(ossl110)]
    pub fn SSL_get_client_random(ssl: *const SSL, out: *mut c_uchar, len: size_t) -> size_t;
    #[cfg(ossl110)]
    pub fn SSL_get_server_random(ssl: *const SSL, out: *mut c_uchar, len: size_t) -> size_t;
    #[cfg(any(ossl110, libressl273))]
    pub fn SSL_SESSION_get_master_key(
        session: *const SSL_SESSION,
        out: *mut c_uchar,
        outlen: size_t,
    ) -> size_t;
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub unsafe fn SSL_get_ex_new_index(
            l: c_long,
            p: *mut c_void,
            newf: Option<CRYPTO_EX_new>,
            dupf: Option<CRYPTO_EX_dup>,
            freef: Option<CRYPTO_EX_free>,
        ) -> c_int {
            CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, l, p, newf, dupf, freef)
        }
    } else {
        extern "C" {
            pub fn SSL_get_ex_new_index(
                argl: c_long,
                argp: *mut c_void,
                new_func: Option<CRYPTO_EX_new>,
                dup_func: Option<CRYPTO_EX_dup>,
                free_func: Option<CRYPTO_EX_free>,
            ) -> c_int;
        }
    }
}
extern "C" {
    pub fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;
}
cfg_if! {
    if #[cfg(ossl110)] {
        pub unsafe fn SSL_CTX_get_ex_new_index(
            l: c_long,
            p: *mut c_void,
            newf: Option<CRYPTO_EX_new>,
            dupf: Option<CRYPTO_EX_dup>,
            freef: Option<CRYPTO_EX_free>,
        ) -> c_int {
            CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, l, p, newf, dupf, freef)
        }
    } else {
        extern "C" {
            pub fn SSL_CTX_get_ex_new_index(
                argl: c_long,
                argp: *mut c_void,
                new_func: Option<::CRYPTO_EX_new>,
                dup_func: Option<::CRYPTO_EX_dup>,
                free_func: Option<::CRYPTO_EX_free>,
            ) -> c_int;
        }
    }
}
extern "C" {
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void;

    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
}

pub unsafe fn SSL_CTX_sess_set_cache_size(ctx: *mut SSL_CTX, t: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, ptr::null_mut())
}

pub unsafe fn SSL_CTX_sess_get_cache_size(ctx: *mut SSL_CTX) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_session_cache_mode(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, ptr::null_mut())
}

extern "C" {
    // FIXME should take an option
    pub fn SSL_CTX_set_tmp_dh_callback(
        ctx: *mut SSL_CTX,
        dh: unsafe extern "C" fn(ssl: *mut SSL, is_export: c_int, keylength: c_int) -> *mut DH,
    );
    // FIXME should take an option
    pub fn SSL_set_tmp_dh_callback(
        ctx: *mut SSL,
        dh: unsafe extern "C" fn(ssl: *mut SSL, is_export: c_int, keylength: c_int) -> *mut DH,
    );
    // FIXME should take an option
    #[cfg(not(ossl110))]
    pub fn SSL_CTX_set_tmp_ecdh_callback(
        ctx: *mut ::SSL_CTX,
        ecdh: unsafe extern "C" fn(
            ssl: *mut ::SSL,
            is_export: c_int,
            keylength: c_int,
        ) -> *mut ::EC_KEY,
    );
    // FIXME should take an option
    #[cfg(not(ossl110))]
    pub fn SSL_set_tmp_ecdh_callback(
        ssl: *mut SSL,
        ecdh: unsafe extern "C" fn(
            ssl: *mut SSL,
            is_export: c_int,
            keylength: c_int,
        ) -> *mut EC_KEY,
    );
}

cfg_if! {
    if #[cfg(libressl)] {
        extern "C" {
            pub fn SSL_get_current_compression(ssl: *mut SSL) -> *const libc::c_void;
        }
    } else if #[cfg(not(osslconf = "OPENSSL_NO_COMP"))] {
        const_ptr_api! {
            extern "C" {
                pub fn SSL_get_current_compression(ssl: #[const_ptr_if(ossl111b)] SSL) -> *const COMP_METHOD;
            }
        }
    }
}
cfg_if! {
    if #[cfg(libressl)] {
        extern "C" {
            pub fn SSL_COMP_get_name(comp: *const libc::c_void) -> *const c_char;
        }
    } else if #[cfg(not(osslconf = "OPENSSL_NO_COMP"))] {
        extern "C" {
            pub fn SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char;
        }
    }
}

#[cfg(not(osslconf = "OPENSSL_NO_COMP"))]
extern "C" {
    #[cfg(ossl110)]
    pub fn COMP_get_type(meth: *const COMP_METHOD) -> i32;
}

extern "C" {
    #[cfg(ossl110)]
    pub fn SSL_CIPHER_get_cipher_nid(c: *const SSL_CIPHER) -> c_int;
    #[cfg(ossl110)]
    pub fn SSL_CIPHER_get_digest_nid(c: *const SSL_CIPHER) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        const_ptr_api! {
            extern "C" {
                pub fn SSL_session_reused(ssl: #[const_ptr_if(ossl111c)] SSL) -> c_int;
            }
        }
    } else {
        pub unsafe fn SSL_session_reused(ssl: *mut SSL) -> c_int {
            SSL_ctrl(ssl, SSL_CTRL_GET_SESSION_REUSED, 0, ptr::null_mut()) as c_int
        }
    }
}
const_ptr_api! {
    extern "C" {
        #[cfg(any(ossl102, libressl273))]
        pub fn SSL_is_server(s: #[const_ptr_if(any(ossl110f, libressl273))] SSL) -> c_int;
    }
}

#[cfg(ossl110)]
pub const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x00200000;
#[cfg(ossl111b)]
pub const OPENSSL_INIT_NO_ATEXIT: u64 = 0x00080000;

extern "C" {
    #[cfg(ossl110)]
    pub fn OPENSSL_init_ssl(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int;
}
