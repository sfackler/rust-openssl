use libc::*;

use *;

pub type pem_password_cb = Option<
    unsafe extern "C" fn(
        buf: *mut c_char,
        size: c_int,
        rwflag: c_int,
        user_data: *mut c_void,
    ) -> c_int,
>;

extern "C" {
    pub fn PEM_read_bio_X509(
        bio: *mut BIO,
        out: *mut *mut X509,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut X509;
    pub fn PEM_write_bio_X509(bio: *mut BIO, x509: *mut X509) -> c_int;
    pub fn PEM_read_bio_X509_REQ(
        bio: *mut BIO,
        out: *mut *mut X509_REQ,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut X509_REQ;
    pub fn PEM_write_bio_X509_REQ(bio: *mut BIO, x509: *mut X509_REQ) -> c_int;
    pub fn PEM_read_bio_RSAPrivateKey(
        bio: *mut BIO,
        rsa: *mut *mut RSA,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut RSA;
    pub fn PEM_write_bio_RSAPrivateKey(
        bp: *mut BIO,
        rsa: *mut RSA,
        cipher: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn PEM_read_bio_RSAPublicKey(
        bio: *mut BIO,
        rsa: *mut *mut RSA,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut RSA;
    pub fn PEM_write_bio_RSAPublicKey(bp: *mut BIO, rsa: *const RSA) -> c_int;
    pub fn PEM_read_bio_RSA_PUBKEY(
        bio: *mut BIO,
        rsa: *mut *mut RSA,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut RSA;
    pub fn PEM_write_bio_RSA_PUBKEY(bp: *mut BIO, rsa: *mut RSA) -> c_int;
    pub fn PEM_read_bio_DSAPrivateKey(
        bp: *mut BIO,
        dsa: *mut *mut DSA,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut DSA;
    pub fn PEM_write_bio_DSAPrivateKey(
        bp: *mut BIO,
        dsa: *mut DSA,
        cipher: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn PEM_read_bio_DSA_PUBKEY(
        bp: *mut BIO,
        dsa: *mut *mut DSA,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut DSA;
    pub fn PEM_write_bio_DSA_PUBKEY(bp: *mut BIO, dsa: *mut DSA) -> c_int;
    pub fn PEM_read_bio_ECPrivateKey(
        bio: *mut BIO,
        key: *mut *mut EC_KEY,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut EC_KEY;
    pub fn PEM_write_bio_ECPrivateKey(
        bio: *mut BIO,
        key: *mut EC_KEY,
        cipher: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn PEM_read_bio_EC_PUBKEY(
        bp: *mut BIO,
        ec: *mut *mut EC_KEY,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut EC_KEY;
    pub fn PEM_write_bio_EC_PUBKEY(bp: *mut BIO, ec: *mut EC_KEY) -> c_int;
    pub fn PEM_read_bio_DHparams(
        bio: *mut BIO,
        out: *mut *mut DH,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut DH;
    pub fn PEM_write_bio_DHparams(bio: *mut BIO, x: *const DH) -> c_int;
    pub fn PEM_read_bio_PrivateKey(
        bio: *mut BIO,
        out: *mut *mut EVP_PKEY,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn PEM_write_bio_PrivateKey(
        bio: *mut BIO,
        pkey: *mut EVP_PKEY,
        cipher: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn PEM_read_bio_PUBKEY(
        bio: *mut BIO,
        out: *mut *mut EVP_PKEY,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn PEM_write_bio_PUBKEY(bp: *mut BIO, x: *mut EVP_PKEY) -> c_int;

    pub fn PEM_write_bio_PKCS8PrivateKey(
        bio: *mut BIO,
        pkey: *mut EVP_PKEY,
        cipher: *const EVP_CIPHER,
        kstr: *mut c_char,
        klen: c_int,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn d2i_PKCS8PrivateKey_bio(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn d2i_PKCS8_PRIV_KEY_INFO(
        k: *mut *mut PKCS8_PRIV_KEY_INFO,
        buf: *mut *const u8,
        length: c_long,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
    pub fn PKCS8_PRIV_KEY_INFO_free(p8inf: *mut PKCS8_PRIV_KEY_INFO);

    pub fn PEM_read_bio_PKCS7(
        bio: *mut BIO,
        out: *mut *mut PKCS7,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut PKCS7;

    pub fn PEM_write_bio_PKCS7(bp: *mut BIO, x: *mut PKCS7) -> c_int;

    #[cfg(ossl101)]
    pub fn PEM_read_bio_CMS(
        bio: *mut BIO,
        out: *mut *mut CMS_ContentInfo,
        callback: pem_password_cb,
        user_data: *mut c_void,
    ) -> *mut CMS_ContentInfo;
    #[cfg(ossl101)]
    pub fn PEM_write_bio_CMS(bio: *mut BIO, cms: *const CMS_ContentInfo) -> c_int;
}

pub const PEM_R_NO_START_LINE: c_int = 108;
