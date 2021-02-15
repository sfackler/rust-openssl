use libc::*;

pub const SSL3_VERSION: c_int = 0x300;

pub const SSL3_AD_ILLEGAL_PARAMETER: c_int = 47;

/*
 * Signalling cipher suite value from RFC 5746
 * (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
 */
pub const SSL3_CK_SCSV: c_int = 0x030000FF;

/*
 * Signalling cipher suite value from draft-ietf-tls-downgrade-scsv-00
 * (TLS_FALLBACK_SCSV)
 */
pub const SSL3_CK_FALLBACK_SCSV: c_int = 0x03005600;

pub const SSL3_CK_RSA_NULL_MD5: c_int = 0x03000001;
pub const SSL3_CK_RSA_NULL_SHA: c_int = 0x03000002;
pub const SSL3_CK_RSA_RC4_40_MD5: c_int = 0x03000003;
pub const SSL3_CK_RSA_RC4_128_MD5: c_int = 0x03000004;
pub const SSL3_CK_RSA_RC4_128_SHA: c_int = 0x03000005;
pub const SSL3_CK_RSA_RC2_40_MD5: c_int = 0x03000006;
pub const SSL3_CK_RSA_IDEA_128_SHA: c_int = 0x03000007;
pub const SSL3_CK_RSA_DES_40_CBC_SHA: c_int = 0x03000008;
pub const SSL3_CK_RSA_DES_64_CBC_SHA: c_int = 0x03000009;
pub const SSL3_CK_RSA_DES_192_CBC3_SHA: c_int = 0x0300000A;

pub const SSL3_CK_DH_DSS_DES_40_CBC_SHA: c_int = 0x0300000B;
pub const SSL3_CK_DH_DSS_DES_64_CBC_SHA: c_int = 0x0300000C;
pub const SSL3_CK_DH_DSS_DES_192_CBC3_SHA: c_int = 0x0300000D;
pub const SSL3_CK_DH_RSA_DES_40_CBC_SHA: c_int = 0x0300000E;
pub const SSL3_CK_DH_RSA_DES_64_CBC_SHA: c_int = 0x0300000F;
pub const SSL3_CK_DH_RSA_DES_192_CBC3_SHA: c_int = 0x03000010;

pub const SSL3_CK_DHE_DSS_DES_40_CBC_SHA: c_int = 0x03000011;
pub const SSL3_CK_EDH_DSS_DES_40_CBC_SHA: c_int = SSL3_CK_DHE_DSS_DES_40_CBC_SHA;
pub const SSL3_CK_DHE_DSS_DES_64_CBC_SHA: c_int = 0x03000012;
pub const SSL3_CK_EDH_DSS_DES_64_CBC_SHA: c_int = SSL3_CK_DHE_DSS_DES_64_CBC_SHA;
pub const SSL3_CK_DHE_DSS_DES_192_CBC3_SHA: c_int = 0x03000013;
pub const SSL3_CK_EDH_DSS_DES_192_CBC3_SHA: c_int = SSL3_CK_DHE_DSS_DES_192_CBC3_SHA;
pub const SSL3_CK_DHE_RSA_DES_40_CBC_SHA: c_int = 0x03000014;
pub const SSL3_CK_EDH_RSA_DES_40_CBC_SHA: c_int = SSL3_CK_DHE_RSA_DES_40_CBC_SHA;
pub const SSL3_CK_DHE_RSA_DES_64_CBC_SHA: c_int = 0x03000015;
pub const SSL3_CK_EDH_RSA_DES_64_CBC_SHA: c_int = SSL3_CK_DHE_RSA_DES_64_CBC_SHA;
pub const SSL3_CK_DHE_RSA_DES_192_CBC3_SHA: c_int = 0x03000016;
pub const SSL3_CK_EDH_RSA_DES_192_CBC3_SHA: c_int = SSL3_CK_DHE_RSA_DES_192_CBC3_SHA;

pub const SSL3_CK_ADH_RC4_40_MD5: c_int = 0x03000017;
pub const SSL3_CK_ADH_RC4_128_MD5: c_int = 0x03000018;
pub const SSL3_CK_ADH_DES_40_CBC_SHA: c_int = 0x03000019;
pub const SSL3_CK_ADH_DES_64_CBC_SHA: c_int = 0x0300001A;
pub const SSL3_CK_ADH_DES_192_CBC_SHA: c_int = 0x0300001B;
