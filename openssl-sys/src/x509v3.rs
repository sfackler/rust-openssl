use libc::*;

use *;

pub enum CONF_METHOD {}

pub const GEN_OTHERNAME: c_int = 0;
pub const GEN_EMAIL: c_int = 1;
pub const GEN_DNS: c_int = 2;
pub const GEN_X400: c_int = 3;
pub const GEN_DIRNAME: c_int = 4;
pub const GEN_EDIPARTY: c_int = 5;
pub const GEN_URI: c_int = 6;
pub const GEN_IPADD: c_int = 7;
pub const GEN_RID: c_int = 8;

#[repr(C)]
pub struct GENERAL_NAME {
    pub type_: c_int,
    // FIXME should be a union
    pub d: *mut c_void,
}

stack!(stack_st_GENERAL_NAME);

extern "C" {
    pub fn GENERAL_NAME_free(name: *mut GENERAL_NAME);
}

#[repr(C)]
pub struct ACCESS_DESCRIPTION {
    pub method: *mut ASN1_OBJECT,
    pub location: *mut GENERAL_NAME,
}

stack!(stack_st_ACCESS_DESCRIPTION);

extern "C" {
    pub fn ACCESS_DESCRIPTION_free(ad: *mut ACCESS_DESCRIPTION);
}

#[repr(C)]
pub struct AUTHORITY_KEYID {
    pub keyid: *mut ASN1_OCTET_STRING,
    pub issuer: *mut stack_st_GENERAL_NAME,
    pub serial: *mut ASN1_INTEGER,
}

extern "C" {
    pub fn AUTHORITY_KEYID_free(akid: *mut AUTHORITY_KEYID);
}

#[cfg(any(ossl102, libressl261))]
pub const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT: c_uint = 0x1;
#[cfg(any(ossl102, libressl261))]
pub const X509_CHECK_FLAG_NO_WILDCARDS: c_uint = 0x2;
#[cfg(any(ossl102, libressl261))]
pub const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS: c_uint = 0x4;
#[cfg(any(ossl102, libressl261))]
pub const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS: c_uint = 0x8;
#[cfg(any(ossl102, libressl261))]
pub const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS: c_uint = 0x10;
#[cfg(ossl110)]
pub const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: c_uint = 0x20;

const_ptr_api! {
    extern "C" {
        pub fn X509V3_EXT_nconf_nid(
            conf: *mut CONF,
            ctx: *mut X509V3_CTX,
            ext_nid: c_int,
            value: #[const_ptr_if(any(ossl110, libressl280))] c_char,
        ) -> *mut X509_EXTENSION;
        pub fn X509V3_EXT_nconf(
            conf: *mut CONF,
            ctx: *mut X509V3_CTX,
            name: #[const_ptr_if(any(ossl110, libressl280))] c_char,
            value: #[const_ptr_if(any(ossl110, libressl280))] c_char,
        ) -> *mut X509_EXTENSION;
    }
}

extern "C" {
    pub fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> c_int;
    pub fn X509_verify(req: *mut X509, pkey: *mut EVP_PKEY) -> c_int;

    pub fn X509V3_set_nconf(ctx: *mut X509V3_CTX, conf: *mut CONF);

    pub fn X509V3_set_ctx(
        ctx: *mut X509V3_CTX,
        issuer: *mut X509,
        subject: *mut X509,
        req: *mut X509_REQ,
        crl: *mut X509_CRL,
        flags: c_int,
    );

    pub fn X509_get1_ocsp(x: *mut X509) -> *mut stack_st_OPENSSL_STRING;
}

const_ptr_api! {
    extern "C" {
        pub fn X509V3_get_d2i(
            x: #[const_ptr_if(any(ossl110, libressl280))] stack_st_X509_EXTENSION,
            nid: c_int,
            crit: *mut c_int,
            idx: *mut c_int,
        ) -> *mut c_void;
        pub fn X509V3_extensions_print(out: *mut BIO, title: #[const_ptr_if(any(ossl110, libressl280))] c_char, exts: #[const_ptr_if(any(ossl110, libressl280))] stack_st_X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int;
    }
}

// X509V3_add1_i2d (and *_add1_ext_i2d)
pub const X509V3_ADD_DEFAULT: c_ulong = 0;
pub const X509V3_ADD_APPEND: c_ulong = 1;
pub const X509V3_ADD_REPLACE: c_ulong = 2;
pub const X509V3_ADD_REPLACE_EXISTING: c_ulong = 3;
pub const X509V3_ADD_KEEP_EXISTING: c_ulong = 4;
pub const X509V3_ADD_DELETE: c_ulong = 5;
pub const X509V3_ADD_SILENT: c_ulong = 0x10;

// X509_get_extension_flags
pub const EXFLAG_BCONS: u32 = 0x1;
pub const EXFLAG_KUSAGE: u32 = 0x2;
pub const EXFLAG_XKUSAGE: u32 = 0x4;
pub const EXFLAG_NSCERT: u32 = 0x8;
pub const EXFLAG_CA: u32 = 0x10;
pub const EXFLAG_SI: u32 = 0x20;
pub const EXFLAG_V1: u32 = 0x40;
pub const EXFLAG_INVALID: u32 = 0x80;
pub const EXFLAG_SET: u32 = 0x100;
pub const EXFLAG_CRITICAL: u32 = 0x200;
pub const EXFLAG_PROXY: u32 = 0x400;
pub const EXFLAG_INVALID_POLICY: u32 = 0x800;
pub const EXFLAG_FRESHEST: u32 = 0x1000;
// before ossl102 / libressl260 EXFLAG_SS was 0x20 (the same as EXFLAG_SI); probably not useful semantic
#[cfg(any(ossl102, libressl261))]
pub const EXFLAG_SS: u32 = 0x2000;
/*
cfg_if! {
    // probably gonna be in openssl-3.0.0-alpha7
    if #[cfg(any(ossl300))] {
        pub const EXFLAG_BCONS_CRITICAL: u32 = 0x10000;
        pub const EXFLAG_AKID_CRITICAL: u32 = 0x20000;
        pub const EXFLAG_SKID_CRITICAL: u32 = 0x40000;
        pub const EXFLAG_SAN_CRITICAL: u32 = 0x80000;
    }
}
*/

// X509_get_key_usage
pub const X509v3_KU_DIGITAL_SIGNATURE: u32 = 0x0080;
pub const X509v3_KU_NON_REPUDIATION: u32 = 0x0040;
pub const X509v3_KU_KEY_ENCIPHERMENT: u32 = 0x0020;
pub const X509v3_KU_DATA_ENCIPHERMENT: u32 = 0x0010;
pub const X509v3_KU_KEY_AGREEMENT: u32 = 0x0008;
pub const X509v3_KU_KEY_CERT_SIGN: u32 = 0x0004;
pub const X509v3_KU_CRL_SIGN: u32 = 0x0002;
pub const X509v3_KU_ENCIPHER_ONLY: u32 = 0x0001;
pub const X509v3_KU_DECIPHER_ONLY: u32 = 0x8000;
pub const X509v3_KU_UNDEF: u32 = 0xffff;

// X509_get_extended_key_usage
pub const XKU_SSL_SERVER: u32 = 0x1;
pub const XKU_SSL_CLIENT: u32 = 0x2;
pub const XKU_SMIME: u32 = 0x4;
pub const XKU_CODE_SIGN: u32 = 0x8;
pub const XKU_SGC: u32 = 0x10;
pub const XKU_OCSP_SIGN: u32 = 0x20;
pub const XKU_TIMESTAMP: u32 = 0x40;
pub const XKU_DVCS: u32 = 0x80;
#[cfg(ossl110)]
pub const XKU_ANYEKU: u32 = 0x100;

extern "C" {
    pub fn X509V3_EXT_d2i(ext: *mut X509_EXTENSION) -> *mut c_void;
    pub fn X509V3_EXT_i2d(ext_nid: c_int, crit: c_int, ext: *mut c_void) -> *mut X509_EXTENSION;
    pub fn X509V3_add1_i2d(
        x: *mut *mut stack_st_X509_EXTENSION,
        nid: c_int,
        value: *mut c_void,
        crit: c_int,
        flags: c_ulong,
    ) -> c_int;
    pub fn X509V3_EXT_print(
        out: *mut BIO,
        ext: *mut X509_EXTENSION,
        flag: c_ulong,
        indent: c_int,
    ) -> c_int;

    #[cfg(ossl110)]
    pub fn X509_get_extension_flags(x: *mut X509) -> u32;
    #[cfg(ossl110)]
    pub fn X509_get_key_usage(x: *mut X509) -> u32;
    #[cfg(ossl110)]
    pub fn X509_get_extended_key_usage(x: *mut X509) -> u32;
}
