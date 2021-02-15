use libc::*;
use std::mem;
use std::ptr;

use *;

pub const TLS1_VERSION: c_int = 0x301;
pub const TLS1_1_VERSION: c_int = 0x302;
pub const TLS1_2_VERSION: c_int = 0x303;
#[cfg(ossl111)]
pub const TLS1_3_VERSION: c_int = 0x304;

pub const TLS1_AD_DECODE_ERROR: c_int = 50;
pub const TLS1_AD_UNRECOGNIZED_NAME: c_int = 112;

pub const TLSEXT_NAMETYPE_host_name: c_int = 0;
pub const TLSEXT_STATUSTYPE_ocsp: c_int = 1;

extern "C" {
    pub fn SSL_get_servername(ssl: *const SSL, name_type: c_int) -> *const c_char;

    pub fn SSL_export_keying_material(
        s: *mut SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
        use_context: c_int,
    ) -> c_int;

    #[cfg(ossl111)]
    pub fn SSL_export_keying_material_early(
        s: *mut ::SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
    ) -> c_int;
}

pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *mut c_char) -> c_long {
    SSL_ctrl(
        s,
        SSL_CTRL_SET_TLSEXT_HOSTNAME,
        TLSEXT_NAMETYPE_host_name as c_long,
        name as *mut c_void,
    )
}

pub unsafe fn SSL_set_tlsext_status_type(s: *mut SSL, type_: c_int) -> c_long {
    SSL_ctrl(
        s,
        SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
        type_ as c_long,
        ptr::null_mut(),
    )
}

pub unsafe fn SSL_get_tlsext_status_ocsp_resp(
    ssl: *mut SSL,
    resp: *mut *mut c_uchar,
) -> c_long {
    SSL_ctrl(
        ssl,
        SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,
        0,
        resp as *mut c_void,
    )
}

pub unsafe fn SSL_set_tlsext_status_ocsp_resp(
    ssl: *mut SSL,
    resp: *mut c_uchar,
    len: c_long,
) -> c_long {
    SSL_ctrl(
        ssl,
        SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,
        len,
        resp as *mut c_void,
    )
}

pub unsafe fn SSL_CTX_set_tlsext_servername_callback(
    ctx: *mut SSL_CTX,
    // FIXME should have the right signature
    cb: Option<extern "C" fn()>,
) -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb)
}

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

pub unsafe fn SSL_CTX_set_tlsext_servername_arg(
    ctx: *mut SSL_CTX,
    arg: *mut c_void,
) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, arg)
}

pub unsafe fn SSL_CTX_set_tlsext_status_cb(
    ctx: *mut SSL_CTX,
    cb: Option<unsafe extern "C" fn(*mut SSL, *mut c_void) -> c_int>,
) -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, mem::transmute(cb))
}

pub unsafe fn SSL_CTX_set_tlsext_status_arg(
    ctx: *mut SSL_CTX,
    arg: *mut c_void,
) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, arg)
}

/* PSK ciphersuites from 4279 */
pub const TLS1_CK_PSK_WITH_RC4_128_SHA: c_int = 0x0300008A;
pub const TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300008B;
pub const TLS1_CK_PSK_WITH_AES_128_CBC_SHA: c_int = 0x0300008C;
pub const TLS1_CK_PSK_WITH_AES_256_CBC_SHA: c_int = 0x0300008D;
pub const TLS1_CK_DHE_PSK_WITH_RC4_128_SHA: c_int = 0x0300008E;
pub const TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300008F;
pub const TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA: c_int = 0x03000090;
pub const TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA: c_int = 0x03000091;
pub const TLS1_CK_RSA_PSK_WITH_RC4_128_SHA: c_int = 0x03000092;
pub const TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 0x03000093;
pub const TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA: c_int = 0x03000094;
pub const TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA: c_int = 0x03000095;

/* PSK ciphersuites from 5487 */
pub const TLS1_CK_PSK_WITH_AES_128_GCM_SHA256: c_int = 0x030000A8;
pub const TLS1_CK_PSK_WITH_AES_256_GCM_SHA384: c_int = 0x030000A9;
pub const TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256: c_int = 0x030000AA;
pub const TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384: c_int = 0x030000AB;
pub const TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256: c_int = 0x030000AC;
pub const TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384: c_int = 0x030000AD;
pub const TLS1_CK_PSK_WITH_AES_128_CBC_SHA256: c_int = 0x030000AE;
pub const TLS1_CK_PSK_WITH_AES_256_CBC_SHA384: c_int = 0x030000AF;
pub const TLS1_CK_PSK_WITH_NULL_SHA256: c_int = 0x030000B0;
pub const TLS1_CK_PSK_WITH_NULL_SHA384: c_int = 0x030000B1;
pub const TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256: c_int = 0x030000B2;
pub const TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384: c_int = 0x030000B3;
pub const TLS1_CK_DHE_PSK_WITH_NULL_SHA256: c_int = 0x030000B4;
pub const TLS1_CK_DHE_PSK_WITH_NULL_SHA384: c_int = 0x030000B5;
pub const TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256: c_int = 0x030000B6;
pub const TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384: c_int = 0x030000B7;
pub const TLS1_CK_RSA_PSK_WITH_NULL_SHA256: c_int = 0x030000B8;
pub const TLS1_CK_RSA_PSK_WITH_NULL_SHA384: c_int = 0x030000B9;

/* NULL PSK ciphersuites from RFC4785 */
pub const TLS1_CK_PSK_WITH_NULL_SHA: c_int = 0x0300002C;
pub const TLS1_CK_DHE_PSK_WITH_NULL_SHA: c_int = 0x0300002D;
pub const TLS1_CK_RSA_PSK_WITH_NULL_SHA: c_int = 0x0300002E;

/* AES ciphersuites from RFC3268 */
pub const TLS1_CK_RSA_WITH_AES_128_SHA: c_int = 0x0300002F;
pub const TLS1_CK_DH_DSS_WITH_AES_128_SHA: c_int = 0x03000030;
pub const TLS1_CK_DH_RSA_WITH_AES_128_SHA: c_int = 0x03000031;
pub const TLS1_CK_DHE_DSS_WITH_AES_128_SHA: c_int = 0x03000032;
pub const TLS1_CK_DHE_RSA_WITH_AES_128_SHA: c_int = 0x03000033;
pub const TLS1_CK_ADH_WITH_AES_128_SHA: c_int = 0x03000034;
pub const TLS1_CK_RSA_WITH_AES_256_SHA: c_int = 0x03000035;
pub const TLS1_CK_DH_DSS_WITH_AES_256_SHA: c_int = 0x03000036;
pub const TLS1_CK_DH_RSA_WITH_AES_256_SHA: c_int = 0x03000037;
pub const TLS1_CK_DHE_DSS_WITH_AES_256_SHA: c_int = 0x03000038;
pub const TLS1_CK_DHE_RSA_WITH_AES_256_SHA: c_int = 0x03000039;
pub const TLS1_CK_ADH_WITH_AES_256_SHA: c_int = 0x0300003A;

/* TLS v1.2 ciphersuites */
pub const TLS1_CK_RSA_WITH_NULL_SHA256: c_int = 0x0300003B;
pub const TLS1_CK_RSA_WITH_AES_128_SHA256: c_int = 0x0300003C;
pub const TLS1_CK_RSA_WITH_AES_256_SHA256: c_int = 0x0300003D;
pub const TLS1_CK_DH_DSS_WITH_AES_128_SHA256: c_int = 0x0300003E;
pub const TLS1_CK_DH_RSA_WITH_AES_128_SHA256: c_int = 0x0300003F;
pub const TLS1_CK_DHE_DSS_WITH_AES_128_SHA256: c_int = 0x03000040;

/* Camellia ciphersuites from RFC4132 */
pub const TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000041;
pub const TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000042;
pub const TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000043;
pub const TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000044;
pub const TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000045;
pub const TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA: c_int = 0x03000046;

/* TLS v1.2 ciphersuites */
pub const TLS1_CK_DHE_RSA_WITH_AES_128_SHA256: c_int = 0x03000067;
pub const TLS1_CK_DH_DSS_WITH_AES_256_SHA256: c_int = 0x03000068;
pub const TLS1_CK_DH_RSA_WITH_AES_256_SHA256: c_int = 0x03000069;
pub const TLS1_CK_DHE_DSS_WITH_AES_256_SHA256: c_int = 0x0300006A;
pub const TLS1_CK_DHE_RSA_WITH_AES_256_SHA256: c_int = 0x0300006B;
pub const TLS1_CK_ADH_WITH_AES_128_SHA256: c_int = 0x0300006C;
pub const TLS1_CK_ADH_WITH_AES_256_SHA256: c_int = 0x0300006D;

/* Camellia ciphersuites from RFC4132 */
pub const TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000084;
pub const TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000085;
pub const TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000086;
pub const TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000087;
pub const TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000088;
pub const TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA: c_int = 0x03000089;

/* SEED ciphersuites from RFC4162 */
pub const TLS1_CK_RSA_WITH_SEED_SHA: c_int = 0x03000096;
pub const TLS1_CK_DH_DSS_WITH_SEED_SHA: c_int = 0x03000097;
pub const TLS1_CK_DH_RSA_WITH_SEED_SHA: c_int = 0x03000098;
pub const TLS1_CK_DHE_DSS_WITH_SEED_SHA: c_int = 0x03000099;
pub const TLS1_CK_DHE_RSA_WITH_SEED_SHA: c_int = 0x0300009A;
pub const TLS1_CK_ADH_WITH_SEED_SHA: c_int = 0x0300009B;

/* TLS v1.2 GCM ciphersuites from RFC5288 */
pub const TLS1_CK_RSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300009C;
pub const TLS1_CK_RSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300009D;
pub const TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300009E;
pub const TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300009F;
pub const TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256: c_int = 0x030000A0;
pub const TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384: c_int = 0x030000A1;
pub const TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256: c_int = 0x030000A2;
pub const TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384: c_int = 0x030000A3;
pub const TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256: c_int = 0x030000A4;
pub const TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384: c_int = 0x030000A5;
pub const TLS1_CK_ADH_WITH_AES_128_GCM_SHA256: c_int = 0x030000A6;
pub const TLS1_CK_ADH_WITH_AES_256_GCM_SHA384: c_int = 0x030000A7;

/* CCM ciphersuites from RFC6655 */
pub const TLS1_CK_RSA_WITH_AES_128_CCM: c_int = 0x0300C09C;
pub const TLS1_CK_RSA_WITH_AES_256_CCM: c_int = 0x0300C09D;
pub const TLS1_CK_DHE_RSA_WITH_AES_128_CCM: c_int = 0x0300C09E;
pub const TLS1_CK_DHE_RSA_WITH_AES_256_CCM: c_int = 0x0300C09F;
pub const TLS1_CK_RSA_WITH_AES_128_CCM_8: c_int = 0x0300C0A0;
pub const TLS1_CK_RSA_WITH_AES_256_CCM_8: c_int = 0x0300C0A1;
pub const TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8: c_int = 0x0300C0A2;
pub const TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8: c_int = 0x0300C0A3;
pub const TLS1_CK_PSK_WITH_AES_128_CCM: c_int = 0x0300C0A4;
pub const TLS1_CK_PSK_WITH_AES_256_CCM: c_int = 0x0300C0A5;
pub const TLS1_CK_DHE_PSK_WITH_AES_128_CCM: c_int = 0x0300C0A6;
pub const TLS1_CK_DHE_PSK_WITH_AES_256_CCM: c_int = 0x0300C0A7;
pub const TLS1_CK_PSK_WITH_AES_128_CCM_8: c_int = 0x0300C0A8;
pub const TLS1_CK_PSK_WITH_AES_256_CCM_8: c_int = 0x0300C0A9;
pub const TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8: c_int = 0x0300C0AA;
pub const TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8: c_int = 0x0300C0AB;

/* CCM ciphersuites from RFC7251 */
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM: c_int = 0x0300C0AC;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM: c_int = 0x0300C0AD;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8: c_int = 0x0300C0AE;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8: c_int = 0x0300C0AF;

/* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
pub const TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BA;
pub const TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BB;
pub const TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BC;
pub const TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BD;
pub const TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BE;
pub const TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x030000BF;

pub const TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C0;
pub const TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C1;
pub const TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C2;
pub const TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C3;
pub const TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C4;
pub const TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256: c_int = 0x030000C5;

/* ECC ciphersuites from RFC4492 */
pub const TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA: c_int = 0x0300C001;
pub const TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA: c_int = 0x0300C002;
pub const TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA: c_int = 0x0300C003;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA: c_int = 0x0300C004;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA: c_int = 0x0300C005;

pub const TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA: c_int = 0x0300C006;
pub const TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA: c_int = 0x0300C007;
pub const TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA: c_int = 0x0300C008;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: c_int = 0x0300C009;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: c_int = 0x0300C00A;

pub const TLS1_CK_ECDH_RSA_WITH_NULL_SHA: c_int = 0x0300C00B;
pub const TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA: c_int = 0x0300C00C;
pub const TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA: c_int = 0x0300C00D;
pub const TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA: c_int = 0x0300C00E;
pub const TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA: c_int = 0x0300C00F;

pub const TLS1_CK_ECDHE_RSA_WITH_NULL_SHA: c_int = 0x0300C010;
pub const TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA: c_int = 0x0300C011;
pub const TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA: c_int = 0x0300C012;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA: c_int = 0x0300C013;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA: c_int = 0x0300C014;

pub const TLS1_CK_ECDH_anon_WITH_NULL_SHA: c_int = 0x0300C015;
pub const TLS1_CK_ECDH_anon_WITH_RC4_128_SHA: c_int = 0x0300C016;
pub const TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA: c_int = 0x0300C017;
pub const TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA: c_int = 0x0300C018;
pub const TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA: c_int = 0x0300C019;

/* SRP ciphersuites from RFC 5054 */
pub const TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300C01A;
pub const TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300C01B;
pub const TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300C01C;
pub const TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA: c_int = 0x0300C01D;
pub const TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA: c_int = 0x0300C01E;
pub const TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA: c_int = 0x0300C01F;
pub const TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA: c_int = 0x0300C020;
pub const TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA: c_int = 0x0300C021;
pub const TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA: c_int = 0x0300C022;

/* ECDH HMAC based ciphersuites from RFC5289 */
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256: c_int = 0x0300C023;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384: c_int = 0x0300C024;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256: c_int = 0x0300C025;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384: c_int = 0x0300C026;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256: c_int = 0x0300C027;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384: c_int = 0x0300C028;
pub const TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256: c_int = 0x0300C029;
pub const TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384: c_int = 0x0300C02A;

/* ECDH GCM based ciphersuites from RFC5289 */
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300C02B;
pub const TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300C02C;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300C02D;
pub const TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300C02E;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300C02F;
pub const TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300C030;
pub const TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256: c_int = 0x0300C031;
pub const TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384: c_int = 0x0300C032;

/* ECDHE PSK ciphersuites from RFC5489 */
pub const TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA: c_int = 0x0300C033;
pub const TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 0x0300C034;
pub const TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA: c_int = 0x0300C035;
pub const TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA: c_int = 0x0300C036;

pub const TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256: c_int = 0x0300C037;
pub const TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384: c_int = 0x0300C038;

/* NULL PSK ciphersuites from RFC4785 */
pub const TLS1_CK_ECDHE_PSK_WITH_NULL_SHA: c_int = 0x0300C039;
pub const TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256: c_int = 0x0300C03A;
pub const TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384: c_int = 0x0300C03B;

/* Camellia-CBC ciphersuites from RFC6367 */
pub const TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C072;
pub const TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C073;
pub const TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C074;
pub const TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C075;
pub const TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C076;
pub const TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C077;
pub const TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C078;
pub const TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C079;

pub const TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C094;
pub const TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C095;
pub const TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C096;
pub const TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C097;
pub const TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C098;
pub const TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C099;
pub const TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 0x0300C09A;
pub const TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 0x0300C09B;

/* draft-ietf-tls-chacha20-poly1305-03 */
pub const TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305: c_int = 0x0300CCA8;
pub const TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: c_int = 0x0300CCA9;
pub const TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305: c_int = 0x0300CCAA;
pub const TLS1_CK_PSK_WITH_CHACHA20_POLY1305: c_int = 0x0300CCAB;
pub const TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305: c_int = 0x0300CCAC;
pub const TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305: c_int = 0x0300CCAD;
pub const TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305: c_int = 0x0300CCAE;

/* TLS v1.3 ciphersuites */
pub const TLS1_3_CK_AES_128_GCM_SHA256: c_int = 0x03001301;
pub const TLS1_3_CK_AES_256_GCM_SHA384: c_int = 0x03001302;
pub const TLS1_3_CK_CHACHA20_POLY1305_SHA256: c_int = 0x03001303;
pub const TLS1_3_CK_AES_128_CCM_SHA256: c_int = 0x03001304;
pub const TLS1_3_CK_AES_128_CCM_8_SHA256: c_int = 0x03001305;

/* Aria ciphersuites from RFC6209 */
pub const TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C050;
pub const TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C051;
pub const TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C052;
pub const TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C053;
pub const TLS1_CK_DH_RSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C054;
pub const TLS1_CK_DH_RSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C055;
pub const TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C056;
pub const TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C057;
pub const TLS1_CK_DH_DSS_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C058;
pub const TLS1_CK_DH_DSS_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C059;
pub const TLS1_CK_DH_anon_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C05A;
pub const TLS1_CK_DH_anon_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C05B;
pub const TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C05C;
pub const TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C05D;
pub const TLS1_CK_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C05E;
pub const TLS1_CK_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C05F;
pub const TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C060;
pub const TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C061;
pub const TLS1_CK_ECDH_RSA_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C062;
pub const TLS1_CK_ECDH_RSA_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C063;
pub const TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C06A;
pub const TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C06B;
pub const TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C06C;
pub const TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C06D;
pub const TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256: c_int = 0x0300C06E;
pub const TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384: c_int = 0x0300C06F;

pub const TLS_MD_MAX_CONST_SIZE: c_int = 22;

pub const TLS_MD_CLIENT_FINISH_CONST: *const c_char =
    "client finished\0".as_ptr() as *const _;
pub const TLS_MD_CLIENT_FINISH_CONST_SIZE: c_int = 15;

pub const TLS_MD_SERVER_FINISH_CONST: *const c_char =
    "server finished\0".as_ptr() as *const _;
pub const TLS_MD_SERVER_FINISH_CONST_SIZE: c_int = 15;

pub const TLS_MD_KEY_EXPANSION_CONST: *const c_char =
    "key expansion\0".as_ptr() as *const _;
pub const TLS_MD_KEY_EXPANSION_CONST_SIZE: c_int = 13;

pub const TLS_MD_CLIENT_WRITE_KEY_CONST: *const c_char =
    "client write key\0".as_ptr() as *const _;
pub const TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE: c_int = 16;

pub const TLS_MD_SERVER_WRITE_KEY_CONST: *const c_char =
    "server write key\0".as_ptr() as *const _;
pub const TLS_MD_SERVER_WRITE_KEY_CONST_SIZE: c_int = 16;

pub const TLS_MD_IV_BLOCK_CONST: *const c_char = "IV block\0".as_ptr() as *const _;
pub const TLS_MD_IV_BLOCK_CONST_SIZE: c_int = 8;

pub const TLS_MD_MASTER_SECRET_CONST: *const c_char =
    "master secret\0".as_ptr() as *const _;
pub const TLS_MD_MASTER_SECRET_CONST_SIZE: c_int = 13;

pub const TLS_MD_EXTENDED_MASTER_SECRET_CONST: *const c_char =
    "extended master secret\0".as_ptr() as *const _;
pub const TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE: c_int = 22;
