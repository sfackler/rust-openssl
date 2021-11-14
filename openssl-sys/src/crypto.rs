use libc::*;
use *;

#[cfg(ossl110)]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_malloc(num: usize) -> *mut c_void {
    CRYPTO_malloc(
        num,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(not(ossl110))]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_malloc(num: c_int) -> *mut c_void {
    CRYPTO_malloc(
        num,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(ossl110)]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_free(addr: *mut c_void) {
    CRYPTO_free(
        addr,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(not(ossl110))]
#[inline]
pub unsafe fn OPENSSL_free(addr: *mut c_void) {
    CRYPTO_free(addr)
}

#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_X509: c_int = 3;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_EVP_PKEY: c_int = 10;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_CTX: c_int = 12;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_SESSION: c_int = 14;

stack!(stack_st_void);

cfg_if! {
    if #[cfg(ossl110)] {
        pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
        pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
    } else if #[cfg(libressl)] {
        pub const CRYPTO_EX_INDEX_SSL: c_int = 1;
        pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 2;
    }
}
cfg_if! {
    if #[cfg(any(ossl110, libressl271))] {
        extern "C" {
            pub fn OpenSSL_version_num() -> c_ulong;
            pub fn OpenSSL_version(key: c_int) -> *const c_char;
        }
        pub const OPENSSL_VERSION: c_int = 0;
        pub const OPENSSL_CFLAGS: c_int = 1;
        pub const OPENSSL_BUILT_ON: c_int = 2;
        pub const OPENSSL_PLATFORM: c_int = 3;
        pub const OPENSSL_DIR: c_int = 4;
    } else {
        extern "C" {
            pub fn SSLeay() -> c_ulong;
            pub fn SSLeay_version(key: c_int) -> *const c_char;
        }
        pub const SSLEAY_VERSION: c_int = 0;
        pub const SSLEAY_CFLAGS: c_int = 2;
        pub const SSLEAY_BUILT_ON: c_int = 3;
        pub const SSLEAY_PLATFORM: c_int = 4;
        pub const SSLEAY_DIR: c_int = 5;
    }
}

// FIXME should be options
pub type CRYPTO_EX_new = unsafe extern "C" fn(
    parent: *mut c_void,
    ptr: *mut c_void,
    ad: *const CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: *const c_void,
) -> c_int;
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    to: *mut CRYPTO_EX_DATA,
    from: *mut CRYPTO_EX_DATA,
    from_d: *mut c_void,
    idx: c_int,
    argl: c_long,
    argp: *mut c_void,
) -> c_int;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    parent: *mut c_void,
    ptr: *mut c_void,
    ad: *mut CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: *mut c_void,
);
extern "C" {
    #[cfg(any(ossl110, libressl))]
    pub fn CRYPTO_get_ex_new_index(
        class_index: c_int,
        argl: c_long,
        argp: *mut c_void,
        new_func: Option<CRYPTO_EX_new>,
        dup_func: Option<CRYPTO_EX_dup>,
        free_func: Option<CRYPTO_EX_free>,
    ) -> c_int;
}

pub const CRYPTO_LOCK: c_int = 1;

extern "C" {
    #[cfg(not(ossl110))]
    pub fn CRYPTO_num_locks() -> c_int;
    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_locking_callback(
        func: unsafe extern "C" fn(mode: c_int, n: c_int, file: *const c_char, line: c_int),
    );

    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_id_callback(func: unsafe extern "C" fn() -> c_ulong);

    #[cfg(not(ossl110))]
    pub fn CRYPTO_add_lock(
        pointer: *mut c_int,
        amount: c_int,
        type_: c_int,
        file: *const c_char,
        line: c_int,
    ) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn CRYPTO_malloc(num: size_t, file: *const c_char, line: c_int) -> *mut c_void;
            pub fn CRYPTO_free(buf: *mut c_void, file: *const c_char, line: c_int);
        }
    } else {
        extern "C" {
            pub fn CRYPTO_malloc(num: c_int, file: *const c_char, line: c_int) -> *mut c_void;
            pub fn CRYPTO_free(buf: *mut c_void);
        }
    }
}

extern "C" {
    #[cfg(all(ossl101, not(ossl300)))]
    pub fn FIPS_mode() -> c_int;
    #[cfg(all(ossl101, not(ossl300)))]
    pub fn FIPS_mode_set(onoff: c_int) -> c_int;

    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: size_t) -> c_int;

    #[cfg(ossl300)]
    pub fn OSSL_LIB_CTX_new() -> *mut OSSL_LIB_CTX;
    #[cfg(ossl300)]
    pub fn OSSL_LIB_CTX_free(libcts: *mut OSSL_LIB_CTX);
}
