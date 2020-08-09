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

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509V3_EXT_nconf_nid(
                conf: *mut CONF,
                ctx: *mut X509V3_CTX,
                ext_nid: c_int,
                value: *const c_char,
            ) -> *mut X509_EXTENSION;
            pub fn X509V3_EXT_nconf(
                conf: *mut CONF,
                ctx: *mut X509V3_CTX,
                name: *const c_char,
                value: *const c_char,
            ) -> *mut X509_EXTENSION;
        }
    } else {
        extern "C" {
            pub fn X509V3_EXT_nconf_nid(
                conf: *mut CONF,
                ctx: *mut X509V3_CTX,
                ext_nid: c_int,
                value: *mut c_char,
            ) -> *mut X509_EXTENSION;
            pub fn X509V3_EXT_nconf(
                conf: *mut CONF,
                ctx: *mut X509V3_CTX,
                name: *mut c_char,
                value: *mut c_char,
            ) -> *mut X509_EXTENSION;
        }
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

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509V3_get_d2i(
                x: *const stack_st_X509_EXTENSION,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
            pub fn X509V3_extensions_print(out: *mut BIO, title: *const c_char, exts: *const stack_st_X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int;
        }
    } else {
        extern "C" {
            pub fn X509V3_get_d2i(
                x: *mut stack_st_X509_EXTENSION,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
            pub fn X509V3_extensions_print(out: *mut BIO, title: *mut c_char, exts: *mut stack_st_X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int;
        }
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
}
