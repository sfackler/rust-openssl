use libc::*;
use *;

pub enum CMS_ContentInfo {}
pub enum CMS_SignerInfo {}

stack!(stack_st_CMS_SignerInfo);

extern "C" {
    #[cfg(ossl101)]
    pub fn CMS_ContentInfo_free(cms: *mut ::CMS_ContentInfo);
    #[cfg(ossl101)]
    pub fn i2d_CMS_ContentInfo(a: *mut ::CMS_ContentInfo, pp: *mut *mut c_uchar) -> c_int;

    #[cfg(ossl101)]
    pub fn d2i_CMS_ContentInfo(
        a: *mut *mut ::CMS_ContentInfo,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::CMS_ContentInfo;
}

#[cfg(ossl101)]
pub const CMS_TEXT: c_uint = 0x1;
#[cfg(ossl101)]
pub const CMS_NOCERTS: c_uint = 0x2;
#[cfg(ossl101)]
pub const CMS_NO_CONTENT_VERIFY: c_uint = 0x4;
#[cfg(ossl101)]
pub const CMS_NO_ATTR_VERIFY: c_uint = 0x8;
#[cfg(ossl101)]
pub const CMS_NOSIGS: c_uint = 0x4 | 0x8;
#[cfg(ossl101)]
pub const CMS_NOINTERN: c_uint = 0x10;
#[cfg(ossl101)]
pub const CMS_NO_SIGNER_CERT_VERIFY: c_uint = 0x20;
#[cfg(ossl101)]
pub const CMS_NOVERIFY: c_uint = 0x20;
#[cfg(ossl101)]
pub const CMS_DETACHED: c_uint = 0x40;
#[cfg(ossl101)]
pub const CMS_BINARY: c_uint = 0x80;
#[cfg(ossl101)]
pub const CMS_NOATTR: c_uint = 0x100;
#[cfg(ossl101)]
pub const CMS_NOSMIMECAP: c_uint = 0x200;
#[cfg(ossl101)]
pub const CMS_NOOLDMIMETYPE: c_uint = 0x400;
#[cfg(ossl101)]
pub const CMS_CRLFEOL: c_uint = 0x800;
#[cfg(ossl101)]
pub const CMS_STREAM: c_uint = 0x1000;
#[cfg(ossl101)]
pub const CMS_NOCRL: c_uint = 0x2000;
#[cfg(ossl101)]
pub const CMS_PARTIAL: c_uint = 0x4000;
#[cfg(ossl101)]
pub const CMS_REUSE_DIGEST: c_uint = 0x8000;
#[cfg(ossl101)]
pub const CMS_USE_KEYID: c_uint = 0x10000;
#[cfg(ossl101)]
pub const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
#[cfg(ossl102)]
pub const CMS_KEY_PARAM: c_uint = 0x40000;
#[cfg(ossl110)]
pub const CMS_ASCIICRLF: c_uint = 0x80000;

extern "C" {
    #[cfg(ossl101)]
    pub fn SMIME_read_CMS(bio: *mut ::BIO, bcont: *mut *mut ::BIO) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_sign(
        signcert: *mut ::X509,
        pkey: *mut ::EVP_PKEY,
        certs: *mut ::stack_st_X509,
        data: *mut ::BIO,
        flags: c_uint,
    ) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_encrypt(
        certs: *mut stack_st_X509,
        data: *mut ::BIO,
        cipher: *const EVP_CIPHER,
        flags: c_uint,
    ) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_decrypt(
        cms: *mut ::CMS_ContentInfo,
        pkey: *mut ::EVP_PKEY,
        cert: *mut ::X509,
        dcont: *mut ::BIO,
        out: *mut ::BIO,
        flags: c_uint,
    ) -> c_int;

    #[cfg(ossl101)]
    pub fn CMS_verify(
        cms: *mut ::CMS_ContentInfo,
        certs: *mut stack_st_X509,
        store: *mut X509_STORE,
        indata: *mut ::BIO,
        out: *mut ::BIO,
        flags: c_uint,
    ) -> c_int;

    #[cfg(ossl101)]
    pub fn CMS_get0_SignerInfos(cms: *mut ::CMS_ContentInfo) -> *mut stack_st_CMS_SignerInfo;

    #[cfg(ossl101)]
    pub fn CMS_SignerInfo_get0_algs(
        si: *mut CMS_SignerInfo,
        pkey: *mut *mut EVP_PKEY,
        signer: *mut *mut X509,
        pdig: *mut *mut X509_ALGOR,
        psig: *mut *mut X509_ALGOR,
    );

    #[cfg(ossl101)]
    pub fn CMS_get0_signers(cms: *mut ::CMS_ContentInfo) -> *mut stack_st_X509;

    #[cfg(ossl101)]
    pub fn CMS_signed_get_attr_by_NID(
        si: *const CMS_SignerInfo,
        nid: c_int,
        lastpos: c_int,
    ) -> c_int;

    #[cfg(ossl101)]
    pub fn CMS_signed_get_attr(si: *mut CMS_SignerInfo, index: c_int) -> *mut X509_ATTRIBUTE;
}

pub fn CMS_SignerInfo_free(_si: *mut ::CMS_SignerInfo) {
    panic!("SingerInfo is handles as reference onyl and should never be freed!");
}
