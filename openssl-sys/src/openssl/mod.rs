use libc::{c_int, c_long, c_uchar, c_uint, c_ulong};

#[cfg(not(ossl110))]
mod v10x;
#[cfg(not(ossl110))]
pub use openssl::v10x::*;

#[cfg(ossl110)]
mod v110;
#[cfg(ossl110)]
pub use openssl::v110::*;

#[cfg(ossl111)]
mod v111;
#[cfg(ossl111)]
pub use openssl::v111::*;

#[cfg(ossl102)]
pub const SSL_CTRL_SET_VERIFY_CERT_STORE: c_int = 106;

pub const SSL_MODE_SEND_CLIENTHELLO_TIME: c_long = 0x20;
pub const SSL_MODE_SEND_SERVERHELLO_TIME: c_long = 0x40;
pub const SSL_MODE_SEND_FALLBACK_SCSV: c_long = 0x80;

pub const SSL_OP_SAFARI_ECDHE_ECDSA_BUG: c_ulong = 0x00000040;

pub const SSL_OP_CISCO_ANYCONNECT: c_ulong = 0x00008000;
pub const SSL_OP_NO_COMPRESSION: c_ulong = 0x00020000;
pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_ulong = 0x00040000;
pub const SSL_OP_NO_SSLv3: c_ulong = 0x02000000;
#[cfg(ossl102)]
pub const SSL_OP_NO_DTLSv1: c_ulong = 0x04000000;
#[cfg(ossl102)]
pub const SSL_OP_NO_DTLSv1_2: c_ulong = 0x08000000;

pub const X509_V_ERR_UNSPECIFIED: c_int = 1;

pub const CMS_TEXT: c_uint = 0x1;
pub const CMS_NOCERTS: c_uint = 0x2;
pub const CMS_NO_CONTENT_VERIFY: c_uint = 0x4;
pub const CMS_NO_ATTR_VERIFY: c_uint = 0x8;
pub const CMS_NOSIGS: c_uint = 0x4 | 0x8;
pub const CMS_NOINTERN: c_uint = 0x10;
pub const CMS_NO_SIGNER_CERT_VERIFY: c_uint = 0x20;
pub const CMS_NOVERIFY: c_uint = 0x20;
pub const CMS_DETACHED: c_uint = 0x40;
pub const CMS_BINARY: c_uint = 0x80;
pub const CMS_NOATTR: c_uint = 0x100;
pub const CMS_NOSMIMECAP: c_uint = 0x200;
pub const CMS_NOOLDMIMETYPE: c_uint = 0x400;
pub const CMS_CRLFEOL: c_uint = 0x800;
pub const CMS_STREAM: c_uint = 0x1000;
pub const CMS_NOCRL: c_uint = 0x2000;
pub const CMS_PARTIAL: c_uint = 0x4000;
pub const CMS_REUSE_DIGEST: c_uint = 0x8000;
pub const CMS_USE_KEYID: c_uint = 0x10000;
pub const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
#[cfg(ossl102)]
pub const CMS_KEY_PARAM: c_uint = 0x40000;

extern "C" {
    pub fn CMS_decrypt(
        cms: *mut ::CMS_ContentInfo,
        pkey: *mut ::EVP_PKEY,
        cert: *mut ::X509,
        dcont: *mut ::BIO,
        out: *mut ::BIO,
        flags: c_uint,
    ) -> c_int;
    pub fn SMIME_read_CMS(bio: *mut ::BIO, bcont: *mut *mut ::BIO) -> *mut ::CMS_ContentInfo;
    pub fn CMS_ContentInfo_free(cms: *mut ::CMS_ContentInfo);
    pub fn CMS_sign(
        signcert: *mut ::X509,
        pkey: *mut ::EVP_PKEY,
        certs: *mut ::stack_st_X509,
        data: *mut ::BIO,
        flags: c_uint,
    ) -> *mut ::CMS_ContentInfo;
    pub fn i2d_CMS_ContentInfo(a: *mut ::CMS_ContentInfo, pp: *mut *mut c_uchar) -> c_int;

    pub fn FIPS_mode_set(onoff: c_int) -> c_int;
    pub fn FIPS_mode() -> c_int;
}
