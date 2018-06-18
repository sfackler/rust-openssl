use libc::{c_char, c_int, c_long, c_uchar, c_void, size_t};

extern "C" {
    pub fn ASN1_STRING_get0_data(x: *const ::ASN1_STRING) -> *const c_uchar;

    pub fn BIO_set_init(a: *mut ::BIO, init: c_int);
    pub fn BIO_set_data(a: *mut ::BIO, data: *mut c_void);
    pub fn BIO_get_data(a: *mut ::BIO) -> *mut c_void;
    pub fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut ::BIO_METHOD;
    pub fn BIO_meth_free(biom: *mut ::BIO_METHOD);
    // FIXME should wrap in Option
    pub fn BIO_meth_set_write(
        biom: *mut ::BIO_METHOD,
        write: unsafe extern "C" fn(*mut ::BIO, *const c_char, c_int) -> c_int,
    ) -> c_int;
    pub fn BIO_meth_set_read(
        biom: *mut ::BIO_METHOD,
        read: unsafe extern "C" fn(*mut ::BIO, *mut c_char, c_int) -> c_int,
    ) -> c_int;
    pub fn BIO_meth_set_puts(
        biom: *mut ::BIO_METHOD,
        read: unsafe extern "C" fn(*mut ::BIO, *const c_char) -> c_int,
    ) -> c_int;
    pub fn BIO_meth_set_ctrl(
        biom: *mut ::BIO_METHOD,
        read: unsafe extern "C" fn(*mut ::BIO, c_int, c_long, *mut c_void) -> c_long,
    ) -> c_int;
    pub fn BIO_meth_set_create(
        biom: *mut ::BIO_METHOD,
        create: unsafe extern "C" fn(*mut ::BIO) -> c_int,
    ) -> c_int;
    pub fn BIO_meth_set_destroy(
        biom: *mut ::BIO_METHOD,
        destroy: unsafe extern "C" fn(*mut ::BIO) -> c_int,
    ) -> c_int;

    pub fn DH_set0_pqg(
        dh: *mut ::DH,
        p: *mut ::BIGNUM,
        q: *mut ::BIGNUM,
        g: *mut ::BIGNUM,
    ) -> c_int;

    pub fn DSA_get0_pqg(
        d: *const ::DSA,
        p: *mut *const ::BIGNUM,
        q: *mut *const ::BIGNUM,
        q: *mut *const ::BIGNUM,
    );
    pub fn DSA_set0_pqg(
        d: *mut ::DSA,
        p: *mut ::BIGNUM,
        q: *mut ::BIGNUM,
        q: *mut ::BIGNUM,
    ) -> c_int;
    pub fn DSA_get0_key(
        d: *const ::DSA,
        pub_key: *mut *const ::BIGNUM,
        priv_key: *mut *const ::BIGNUM,
    );
    pub fn DSA_set0_key(
        d: *mut ::DSA,
        pub_key: *mut ::BIGNUM,
        priv_key: *mut ::BIGNUM,
    ) -> c_int;

    pub fn ECDSA_SIG_get0(
        sig: *const ::ECDSA_SIG,
        pr: *mut *const ::BIGNUM,
        ps: *mut *const ::BIGNUM,
    );
    pub fn ECDSA_SIG_set0(sig: *mut ::ECDSA_SIG, pr: *mut ::BIGNUM, ps: *mut ::BIGNUM) -> c_int;

    pub fn EVP_CIPHER_key_length(cipher: *const ::EVP_CIPHER) -> c_int;
    pub fn EVP_CIPHER_block_size(cipher: *const ::EVP_CIPHER) -> c_int;
    pub fn EVP_CIPHER_iv_length(cipher: *const ::EVP_CIPHER) -> c_int;

    pub fn RSA_get0_key(
        r: *const ::RSA,
        n: *mut *const ::BIGNUM,
        e: *mut *const ::BIGNUM,
        d: *mut *const ::BIGNUM,
    );
    pub fn RSA_get0_factors(r: *const ::RSA, p: *mut *const ::BIGNUM, q: *mut *const ::BIGNUM);
    pub fn RSA_get0_crt_params(
        r: *const ::RSA,
        dmp1: *mut *const ::BIGNUM,
        dmq1: *mut *const ::BIGNUM,
        iqmp: *mut *const ::BIGNUM,
    );
    pub fn RSA_set0_key(
        r: *mut ::RSA,
        n: *mut ::BIGNUM,
        e: *mut ::BIGNUM,
        d: *mut ::BIGNUM,
    ) -> c_int;
    pub fn RSA_set0_factors(r: *mut ::RSA, p: *mut ::BIGNUM, q: *mut ::BIGNUM) -> c_int;
    pub fn RSA_set0_crt_params(
        r: *mut ::RSA,
        dmp1: *mut ::BIGNUM,
        dmq1: *mut ::BIGNUM,
        iqmp: *mut ::BIGNUM,
    ) -> c_int;

    pub fn SSL_CTX_up_ref(x: *mut ::SSL_CTX) -> c_int;

    pub fn SSL_SESSION_get_master_key(
        session: *const ::SSL_SESSION,
        out: *mut c_uchar,
        outlen: size_t,
    ) -> size_t;
    pub fn SSL_SESSION_up_ref(ses: *mut ::SSL_SESSION) -> c_int;

    pub fn X509_getm_notAfter(x: *const ::X509) -> *mut ::ASN1_TIME;
    pub fn X509_getm_notBefore(x: *const ::X509) -> *mut ::ASN1_TIME;
    pub fn X509_get0_signature(
        psig: *mut *const ::ASN1_BIT_STRING,
        palg: *mut *const ::X509_ALGOR,
        x: *const ::X509,
    );
    pub fn X509_up_ref(x: *mut ::X509) -> c_int;
}
