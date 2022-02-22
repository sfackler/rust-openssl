use libc::*;

use *;

pub const X509_FILETYPE_PEM: c_int = 1;
pub const X509_FILETYPE_ASN1: c_int = 2;
pub const X509_FILETYPE_DEFAULT: c_int = 3;

pub const ASN1_R_HEADER_TOO_LONG: c_int = 123;

cfg_if! {
    if #[cfg(not(ossl110))] {
        pub const X509_LU_FAIL: c_int = 0;
        pub const X509_LU_X509: c_int = 1;
        pub const X509_LU_CRL: c_int = 2;
    }
}

cfg_if! {
    if #[cfg(not(ossl110))] {
        pub unsafe fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509_PUBKEY {
            (*(*x).cert_info).key
        }

        pub unsafe fn X509_REQ_get_X509_PUBKEY(req: *mut X509_REQ) -> *mut X509_PUBKEY {
            (*(*req).req_info).pubkey
        }
    }
}
