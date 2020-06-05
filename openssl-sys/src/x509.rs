use libc::*;

use *;

pub const X509_FILETYPE_PEM: c_int = 1;
pub const X509_FILETYPE_ASN1: c_int = 2;
pub const X509_FILETYPE_DEFAULT: c_int = 3;

#[repr(C)]
pub struct X509_VAL {
    pub notBefore: *mut ASN1_TIME,
    pub notAfter: *mut ASN1_TIME,
}

pub enum X509_NAME_ENTRY {}

stack!(stack_st_X509_NAME);

pub enum X509_EXTENSION {}

stack!(stack_st_X509_EXTENSION);

stack!(stack_st_X509_ATTRIBUTE);

cfg_if! {
    if #[cfg(ossl110)] {
        pub enum X509_REQ_INFO {}
    } else {
        #[repr(C)]
        pub struct X509_REQ_INFO {
            pub enc: ASN1_ENCODING,
            pub version: *mut ::ASN1_INTEGER,
            pub subject: *mut ::X509_NAME,
            pubkey: *mut c_void,
            pub attributes: *mut stack_st_X509_ATTRIBUTE,
        }
    }
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub enum X509_REQ {}
    } else {
        #[repr(C)]
        pub struct X509_REQ {
            pub req_info: *mut X509_REQ_INFO,
            sig_alg: *mut c_void,
            signature: *mut c_void,
            references: c_int,
        }
    }
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub enum X509_CINF {}
    } else {
        #[repr(C)]
        pub struct X509_CINF {
            version: *mut c_void,
            serialNumber: *mut c_void,
            signature: *mut c_void,
            issuer: *mut c_void,
            pub validity: *mut X509_VAL,
            subject: *mut c_void,
            key: *mut c_void,
            issuerUID: *mut c_void,
            subjectUID: *mut c_void,
            pub extensions: *mut stack_st_X509_EXTENSION,
            enc: ASN1_ENCODING,
        }
    }
}

stack!(stack_st_X509);

cfg_if! {
    if #[cfg(not(ossl110))] {
        pub const X509_LU_FAIL: c_int = 0;
        pub const X509_LU_X509: c_int = 1;
        pub const X509_LU_CRL: c_int = 2;
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl270))] {
        pub enum X509_OBJECT {}
    } else {
        #[repr(C)]
        pub struct X509_OBJECT {
            pub type_: c_int,
            pub data: X509_OBJECT_data,
        }
        #[repr(C)]
        pub union X509_OBJECT_data {
            pub ptr: *mut c_char,
            pub x509: *mut X509,
            pub crl: *mut X509_CRL,
            pub pkey: *mut EVP_PKEY,
        }
    }
}

stack!(stack_st_X509_OBJECT);

pub enum X509_LOOKUP {}

stack!(stack_st_X509_LOOKUP);

extern "C" {
    pub fn X509_verify_cert_error_string(n: c_long) -> *const c_char;

    pub fn X509_sign(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

    pub fn X509_digest(
        x: *const X509,
        digest: *const EVP_MD,
        buf: *mut c_uchar,
        len: *mut c_uint,
    ) -> c_int;

    pub fn X509_REQ_sign(x: *mut X509_REQ, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

    pub fn i2d_X509_bio(b: *mut BIO, x: *mut X509) -> c_int;
    pub fn i2d_X509_REQ_bio(b: *mut BIO, x: *mut X509_REQ) -> c_int;
    pub fn i2d_PrivateKey_bio(b: *mut BIO, x: *mut EVP_PKEY) -> c_int;
    pub fn i2d_PUBKEY_bio(b: *mut BIO, x: *mut EVP_PKEY) -> c_int;

    pub fn i2d_PUBKEY(k: *mut EVP_PKEY, buf: *mut *mut u8) -> c_int;
    pub fn d2i_PUBKEY(k: *mut *mut EVP_PKEY, buf: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    pub fn d2i_RSA_PUBKEY(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;
    pub fn i2d_RSA_PUBKEY(k: *mut RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_DSA_PUBKEY(k: *mut *mut DSA, pp: *mut *const c_uchar, length: c_long) -> *mut DSA;
    pub fn i2d_DSA_PUBKEY(a: *mut DSA, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_EC_PUBKEY(
        a: *mut *mut EC_KEY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut EC_KEY;
    pub fn i2d_EC_PUBKEY(a: *mut EC_KEY, pp: *mut *mut c_uchar) -> c_int;
    pub fn i2d_PrivateKey(k: *mut EVP_PKEY, buf: *mut *mut u8) -> c_int;

    pub fn d2i_ECPrivateKey(
        k: *mut *mut EC_KEY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut EC_KEY;
    pub fn i2d_ECPrivateKey(ec_key: *mut EC_KEY, pp: *mut *mut c_uchar) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn X509_ALGOR_get0(
                paobj: *mut *const ASN1_OBJECT,
                pptype: *mut c_int,
                ppval: *mut *const c_void,
                alg: *const X509_ALGOR,
            );
        }
    } else if #[cfg(ossl102)] {
        extern "C" {
            pub fn X509_ALGOR_get0(
                paobj: *mut *mut ASN1_OBJECT,
                pptype: *mut c_int,
                ppval: *mut *mut c_void,
                alg: *mut X509_ALGOR,
            );
        }
    }
}

extern "C" {
    pub fn X509_gmtime_adj(time: *mut ASN1_TIME, adj: c_long) -> *mut ASN1_TIME;

    pub fn X509_to_X509_REQ(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> *mut X509_REQ;

    pub fn X509_ALGOR_free(x: *mut X509_ALGOR);

    pub fn X509_REQ_new() -> *mut X509_REQ;
    pub fn X509_REQ_free(x: *mut X509_REQ);
    pub fn d2i_X509_REQ(
        a: *mut *mut X509_REQ,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut X509_REQ;
    pub fn i2d_X509_REQ(x: *mut X509_REQ, buf: *mut *mut u8) -> c_int;
}

cfg_if! {
    if #[cfg(any(ossl110, libressl273))] {
        extern "C" {
            pub fn X509_get0_signature(
                psig: *mut *const ASN1_BIT_STRING,
                palg: *mut *const X509_ALGOR,
                x: *const X509,
            );
        }
    } else if #[cfg(ossl102)] {
        extern "C" {
            pub fn X509_get0_signature(
                psig: *mut *mut ASN1_BIT_STRING,
                palg: *mut *mut X509_ALGOR,
                x: *const X509,
            );
        }
    }
}
extern "C" {
    #[cfg(ossl102)]
    pub fn X509_get_signature_nid(x: *const X509) -> c_int;

    pub fn X509_EXTENSION_free(ext: *mut X509_EXTENSION);

    pub fn X509_NAME_ENTRY_free(x: *mut X509_NAME_ENTRY);

    pub fn X509_NAME_new() -> *mut X509_NAME;
    pub fn X509_NAME_free(x: *mut X509_NAME);

    pub fn X509_new() -> *mut X509;
    pub fn X509_free(x: *mut X509);
    pub fn i2d_X509(x: *mut X509, buf: *mut *mut u8) -> c_int;
    pub fn d2i_X509(a: *mut *mut X509, pp: *mut *const c_uchar, length: c_long) -> *mut X509;

    pub fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;

    pub fn X509_set_version(x: *mut X509, version: c_long) -> c_int;
    pub fn X509_set_serialNumber(x: *mut X509, sn: *mut ASN1_INTEGER) -> c_int;
    pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
    pub fn X509_set_issuer_name(x: *mut X509, name: *mut X509_NAME) -> c_int;
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509_get_issuer_name(x: *const ::X509) -> *mut ::X509_NAME;
        }
    } else {
        extern "C" {
            pub fn X509_get_issuer_name(x: *mut ::X509) -> *mut ::X509_NAME;
        }
    }
}
extern "C" {
    pub fn X509_set_subject_name(x: *mut X509, name: *mut X509_NAME) -> c_int;
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509_get_subject_name(x: *const ::X509) -> *mut ::X509_NAME;
        }
    } else {
        extern "C" {
            pub fn X509_get_subject_name(x: *mut ::X509) -> *mut ::X509_NAME;
        }
    }
}
cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn X509_set1_notBefore(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
            pub fn X509_set1_notAfter(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
        }
    } else {
        extern "C" {
            pub fn X509_set_notBefore(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
            pub fn X509_set_notAfter(x: *mut ::X509, tm: *const ::ASN1_TIME) -> c_int;
        }
    }
}
extern "C" {
    #[cfg(ossl110)]
    pub fn X509_REQ_get_version(req: *const X509_REQ) -> c_long;
    pub fn X509_REQ_set_version(req: *mut X509_REQ, version: c_long) -> c_int;
    #[cfg(ossl110)]
    pub fn X509_REQ_get_subject_name(req: *const X509_REQ) -> *mut X509_NAME;
    pub fn X509_REQ_set_subject_name(req: *mut X509_REQ, name: *mut X509_NAME) -> c_int;
    pub fn X509_REQ_set_pubkey(req: *mut X509_REQ, pkey: *mut EVP_PKEY) -> c_int;
    pub fn X509_REQ_get_pubkey(req: *mut X509_REQ) -> *mut EVP_PKEY;
    pub fn X509_REQ_get_extensions(req: *mut X509_REQ) -> *mut stack_st_X509_EXTENSION;
    pub fn X509_REQ_add_extensions(req: *mut X509_REQ, exts: *mut stack_st_X509_EXTENSION)
        -> c_int;
    pub fn X509_set_pubkey(x: *mut X509, pkey: *mut EVP_PKEY) -> c_int;
    pub fn X509_REQ_verify(req: *mut X509_REQ, pkey: *mut EVP_PKEY) -> c_int;
    #[cfg(any(ossl110, libressl273))]
    pub fn X509_getm_notBefore(x: *const X509) -> *mut ASN1_TIME;
    #[cfg(any(ossl110, libressl273))]
    pub fn X509_getm_notAfter(x: *const X509) -> *mut ASN1_TIME;
    #[cfg(any(ossl110, libressl273))]
    pub fn X509_up_ref(x: *mut X509) -> c_int;

    #[cfg(ossl110)]
    pub fn X509_get0_extensions(req: *const ::X509) -> *const stack_st_X509_EXTENSION;
}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509_NAME_entry_count(n: *const X509_NAME) -> c_int;
        }
    } else {
        extern "C" {
            pub fn X509_NAME_entry_count(n: *mut X509_NAME) -> c_int;
        }
    }
}

cfg_if! {
    if #[cfg(libressl280)] {
        extern "C" {
            pub fn X509_NAME_get_index_by_NID(n: *const X509_NAME, nid: c_int, last_pos: c_int) -> c_int;
        }
    } else {
        extern "C" {
            pub fn X509_NAME_get_index_by_NID(n: *mut X509_NAME, nid: c_int, last_pos: c_int) -> c_int;
        }
    }
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509_NAME_get_entry(n: *const X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY;
            pub fn X509_NAME_add_entry_by_NID(
                x: *mut X509_NAME,
                field: c_int,
                ty: c_int,
                bytes: *const c_uchar,
                len: c_int,
                loc: c_int,
                set: c_int,
            ) -> c_int;
            pub fn X509_NAME_ENTRY_get_object(ne: *const X509_NAME_ENTRY) -> *mut ASN1_OBJECT;
            pub fn X509_NAME_ENTRY_get_data(ne: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
        }
    } else {
        extern "C" {
            pub fn X509_NAME_get_entry(n: *mut X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY;
            pub fn X509_NAME_add_entry_by_NID(
                x: *mut X509_NAME,
                field: c_int,
                ty: c_int,
                bytes: *mut c_uchar,
                len: c_int,
                loc: c_int,
                set: c_int,
            ) -> c_int;
            pub fn X509_NAME_ENTRY_get_object(ne: *mut X509_NAME_ENTRY) -> *mut ASN1_OBJECT;
            pub fn X509_NAME_ENTRY_get_data(ne: *mut X509_NAME_ENTRY) -> *mut ASN1_STRING;
        }
    }
}
extern "C" {
    pub fn X509_NAME_add_entry_by_txt(
        x: *mut X509_NAME,
        field: *const c_char,
        ty: c_int,
        bytes: *const c_uchar,
        len: c_int,
        loc: c_int,
        set: c_int,
    ) -> c_int;

    pub fn X509_add_ext(x: *mut X509, ext: *mut X509_EXTENSION, loc: c_int) -> c_int;
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn X509_get_ext_d2i(
                x: *const ::X509,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
        }
    } else {
        extern "C" {
            pub fn X509_get_ext_d2i(
                x: *mut ::X509,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
        }
    }
}

extern "C" {
    pub fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> c_int;
}

#[cfg(any(ossl110, libressl270))]
extern "C" {
    pub fn X509_STORE_get0_objects(ctx: *mut X509_STORE) -> *mut stack_st_X509_OBJECT;
    pub fn X509_OBJECT_get0_X509(x: *const X509_OBJECT) -> *mut X509;
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn X509_OBJECT_free(a: *mut X509_OBJECT);
        }
    } else {
        extern "C" {
            pub fn X509_OBJECT_free_contents(a: *mut X509_OBJECT);
        }
    }
}
