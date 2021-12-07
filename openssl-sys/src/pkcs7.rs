use libc::*;

use *;

use ossl_typ::{BIO, EVP_CIPHER, EVP_MD, EVP_PKEY, X509, X509_STORE};
use x509::stack_st_X509;
use x509_attr::stack_st_X509_ATTRIBUTE;

pub enum PKCS7_SIGNED {}
pub enum PKCS7_ENVELOPE {}
pub enum PKCS7_SIGN_ENVELOPE {}
pub enum PKCS7_DIGEST {}
pub enum PKCS7_ENCRYPT {}
pub enum PKCS7 {}
pub enum PKCS7_SIGNER_INFO {}

pub const PKCS7_TEXT: c_int = 0x1;
pub const PKCS7_NOCERTS: c_int = 0x2;
pub const PKCS7_NOSIGS: c_int = 0x4;
pub const PKCS7_NOCHAIN: c_int = 0x8;
pub const PKCS7_NOINTERN: c_int = 0x10;
pub const PKCS7_NOVERIFY: c_int = 0x20;
pub const PKCS7_DETACHED: c_int = 0x40;
pub const PKCS7_BINARY: c_int = 0x80;
pub const PKCS7_NOATTR: c_int = 0x100;
pub const PKCS7_NOSMIMECAP: c_int = 0x200;
pub const PKCS7_NOOLDMIMETYPE: c_int = 0x400;
pub const PKCS7_CRLFEOL: c_int = 0x800;
pub const PKCS7_STREAM: c_int = 0x1000;
pub const PKCS7_NOCRL: c_int = 0x2000;
pub const PKCS7_PARTIAL: c_int = 0x4000;
pub const PKCS7_REUSE_DIGEST: c_int = 0x8000;
#[cfg(not(any(ossl101, ossl102, libressl)))]
pub const PKCS7_NO_DUAL_CONTENT: c_int = 0x10000;

extern "C" {
    pub fn PKCS7_SIGNER_INFO_free(info: *mut PKCS7_SIGNER_INFO);
}

extern "C" {
    pub fn d2i_PKCS7(a: *mut *mut PKCS7, pp: *mut *const c_uchar, length: c_long) -> *mut PKCS7;
}

const_ptr_api! {
    extern "C" {
        pub fn i2d_PKCS7(a: #[const_ptr_if(ossl300)] PKCS7, buf: *mut *mut u8) -> c_int;
    }
}

extern "C" {
    pub fn PKCS7_encrypt(
        certs: *mut stack_st_X509,
        b: *mut BIO,
        cipher: *const EVP_CIPHER,
        flags: c_int,
    ) -> *mut PKCS7;

    pub fn PKCS7_verify(
        pkcs7: *mut PKCS7,
        certs: *mut stack_st_X509,
        store: *mut X509_STORE,
        indata: *mut BIO,
        out: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn PKCS7_get0_signers(
        pkcs7: *mut PKCS7,
        certs: *mut stack_st_X509,
        flags: c_int,
    ) -> *mut stack_st_X509;

    pub fn PKCS7_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_int,
    ) -> *mut PKCS7;

    pub fn PKCS7_decrypt(
        pkcs7: *mut PKCS7,
        pkey: *mut EVP_PKEY,
        cert: *mut X509,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn PKCS7_free(pkcs7: *mut PKCS7);

    pub fn SMIME_write_PKCS7(
        out: *mut BIO,
        pkcs7: *mut PKCS7,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn SMIME_read_PKCS7(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut PKCS7;

    pub fn PKCS7_new() -> *mut PKCS7;
    pub fn PKCS7_set_type(p7: *mut PKCS7, nid_pkcs7: c_int) -> c_int;
    pub fn PKCS7_add_certificate(p7: *mut PKCS7, x509: *mut X509) -> c_int;
    pub fn PKCS7_add_signature(
        p7: *mut PKCS7,
        x509: *mut X509,
        pkey: *mut EVP_PKEY,
        digest: *const EVP_MD
    ) -> *mut PKCS7_SIGNER_INFO;
    pub fn PKCS7_set_signed_attributes(
        p7si: *mut PKCS7_SIGNER_INFO,
        attributes: *mut stack_st_X509_ATTRIBUTE
    ) -> c_int;
    pub fn PKCS7_add_signed_attribute(
        p7si: *mut PKCS7_SIGNER_INFO,
        nid: c_int,
        attrtype: c_int,
        data: *mut c_void
    ) -> c_int;
    pub fn PKCS7_content_new(p7: *mut PKCS7, nid_pkcs7: c_int) -> c_int;
    pub fn PKCS7_dataInit(p7: *mut PKCS7, bio: *mut BIO) -> *mut BIO;
    pub fn PKCS7_dataFinal(p7: *mut PKCS7, bio: *mut BIO) -> c_int;
    pub fn i2d_PKCS7_bio(bio: *mut BIO, p7: *mut PKCS7) -> c_int;
}
