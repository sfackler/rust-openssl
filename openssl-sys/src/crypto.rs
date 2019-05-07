use libc::*;

use *;

#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_X509: c_int = 3;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_CTX: c_int = 12;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_SESSION: c_int = 14;

stack!(stack_st_void);

cfg_if! {
    if #[cfg(ossl110)] {
        pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
        pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
        pub const CRYPTO_EX_INDEX_SSL_SESSION: c_int = 2;
        pub const CRYPTO_EX_INDEX_X509: c_int = 3;
        pub const CRYPTO_EX_INDEX_X509_STORE: c_int = 4;
        pub const CRYPTO_EX_INDEX_X509_STORE_CTX: c_int = 5;
        pub const CRYPTO_EX_INDEX_DH: c_int = 6;
        pub const CRYPTO_EX_INDEX_DSA: c_int = 7;
        pub const CRYPTO_EX_INDEX_EC_KEY: c_int = 8;
        pub const CRYPTO_EX_INDEX_RSA: c_int = 9;
        pub const CRYPTO_EX_INDEX_ENGINE: c_int = 10;
        pub const CRYPTO_EX_INDEX_UI: c_int = 11;
        pub const CRYPTO_EX_INDEX_BIO: c_int = 12;
        pub const CRYPTO_EX_INDEX_APP: c_int = 13;
        pub const CRYPTO_EX_INDEX_UI_METHOD: c_int = 14;
        pub const CRYPTO_EX_INDEX_DRBG: c_int = 15;
        pub const CRYPTO_EX_INDEX__COUNT: c_int = 16;

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
pub type CRYPTO_EX_new = Option<
    unsafe extern "C" fn(
        parent: *mut c_void,
        ptr: *mut c_void,
        ad: *const CRYPTO_EX_DATA,
        idx: c_int,
        argl: c_long,
        argp: *const c_void,
    ) -> c_int,
>;
pub type CRYPTO_EX_dup = Option<
    unsafe extern "C" fn(
        to: *mut CRYPTO_EX_DATA,
        from: *mut CRYPTO_EX_DATA,
        from_d: *mut c_void,
        idx: c_int,
        argl: c_long,
        argp: *mut c_void,
    ) -> c_int,
>;
pub type CRYPTO_EX_free = Option<
    unsafe extern "C" fn(
        parent: *mut c_void,
        ptr: *mut c_void,
        ad: *mut CRYPTO_EX_DATA,
        idx: c_int,
        argl: c_long,
        argp: *mut c_void,
    ),
>;

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
        #[must_use]
            pub fn CRYPTO_get_ex_new_index(
                class_index: c_int,
                argl: c_long,
                argp: *mut c_void,
                new_func: CRYPTO_EX_new,
                dup_func: CRYPTO_EX_dup,
                free_func: CRYPTO_EX_free,
            ) -> c_int;

            pub fn CRYPTO_free_ex_index(class_index: c_int, idx: c_int) -> c_int;
        }
    } else {
        pub struct crypto_ex_data_func_st {
            argl: c_long,
            argp: *mut c_void,
            new_func: CRYPTO_EX_new,
            dup_func: CRYPTO_EX_dup,
            free_func: CRYPTO_EX_free,
        }

        pub type CRYPTO_EX_DATA_FUNCS = crypto_ex_data_func_st;

        stack!(stack_st_CRYPTO_EX_DATA_FUNCS);
    }
}

pub const CRYPTO_LOCK: c_int = 1;

extern "C" {
    #[cfg(not(ossl110))]
    pub fn CRYPTO_num_locks() -> c_int;
    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_locking_callback(
        func: Option<unsafe extern "C" fn(mode: c_int, n: c_int, file: *const c_char, line: c_int)>,
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

    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_add_lock_callback(
        func: Option<
            unsafe extern "C" fn(
                num: *mut c_int,
                mount: c_int,
                _type: c_int,
                file: *const c_char,
                line: c_int,
            ) -> c_int,
        >,
    );

    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_dynlock_create_callback(
        dyn_create_function: Option<
            unsafe extern "C" fn(file: *const c_char, line: c_int) -> *mut CRYPTO_dynlock_value,
        >,
    );
    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_dynlock_lock_callback(
        dyn_lock_function: Option<
            unsafe extern "C" fn(
                mode: c_int,
                l: *mut CRYPTO_dynlock_value,
                file: *const c_char,
                line: c_int,
            ),
        >,
    );
    #[cfg(not(ossl110))]
    pub fn CRYPTO_set_dynlock_destroy_callback(
        dyn_destroy_function: Option<
            unsafe extern "C" fn(l: *mut CRYPTO_dynlock_value, file: *const c_char, line: c_int),
        >,
    );
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn CRYPTO_malloc(num: size_t, file: *const c_char, line: c_int) -> *mut c_void;
            pub fn CRYPTO_free(buf: *mut c_void, file: *const c_char, line: c_int);

            pub fn CRYPTO_set_mem_functions(
                m: Option<unsafe extern "C" fn(num: size_t, file: *const c_char, line: c_int) -> *mut c_void>,
                r: Option<unsafe extern "C" fn(buf: *mut c_void, num: size_t, file: *const c_char, line: c_int) -> *mut c_void>,
                f: Option<unsafe extern "C" fn(buf:*mut c_void, file: *const c_char, line: c_int)>,
            ) -> c_int;
        }
    } else {
        extern "C" {
            pub fn CRYPTO_malloc(num: c_int, file: *const c_char, line: c_int) -> *mut c_void;
            pub fn CRYPTO_free(buf: *mut c_void);

            pub fn CRYPTO_set_mem_functions(
                m: Option<unsafe extern "C" fn(num: size_t) -> *mut c_void>,
                r: Option<unsafe extern "C" fn(buf: *mut c_void, num: size_t) -> *mut c_void>,
                f: Option<unsafe extern "C" fn(buf: *mut c_void)>,
            ) -> c_int;
        }
    }
}

extern "C" {
    #[cfg(ossl101)]
    pub fn FIPS_mode() -> c_int;
    #[cfg(ossl101)]
    pub fn FIPS_mode_set(onoff: c_int) -> c_int;

    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: size_t) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub const OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS: u64 = 0x00000001;
        pub const OPENSSL_INIT_LOAD_CRYPTO_STRINGS: u64 = 0x00000002;
        pub const OPENSSL_INIT_ADD_ALL_CIPHERS: u64 = 0x00000004;
        pub const OPENSSL_INIT_ADD_ALL_DIGESTS: u64 = 0x00000008;
        pub const OPENSSL_INIT_NO_ADD_ALL_CIPHERS: u64 = 0x00000010;
        pub const OPENSSL_INIT_NO_ADD_ALL_DIGESTS: u64 = 0x00000020;
        pub const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x00000040;
        pub const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x00000080;
        pub const OPENSSL_INIT_ASYNC: u64 = 0x00000100;
        pub const OPENSSL_INIT_ENGINE_RDRAND: u64 = 0x00000200;
        pub const OPENSSL_INIT_ENGINE_DYNAMIC: u64 = 0x00000400;
        pub const OPENSSL_INIT_ENGINE_OPENSSL: u64 = 0x00000800;
        pub const OPENSSL_INIT_ENGINE_CRYPTODEV: u64 = 0x00001000;
        pub const OPENSSL_INIT_ENGINE_CAPI: u64 = 0x00002000;
        pub const OPENSSL_INIT_ENGINE_PADLOCK: u64 = 0x00004000;
        pub const OPENSSL_INIT_ENGINE_AFALG: u64 = 0x00008000;
        //pub const OPENSSL_INIT_ZLIB: u64 = 0x00010000;
        #[cfg(ossl111)]
        pub const OPENSSL_INIT_ATFORK: u64 = 0x00020000;
        //pub const OPENSSL_INIT_BASE_ONLY: u64 = 0x00040000;
        pub const OPENSSL_INIT_NO_ATEXIT: u64 = 0x00080000;
        pub const OPENSSL_INIT_ENGINE_ALL_BUILTIN: u64 = OPENSSL_INIT_ENGINE_RDRAND
            | OPENSSL_INIT_ENGINE_DYNAMIC
            | OPENSSL_INIT_ENGINE_CRYPTODEV
            | OPENSSL_INIT_ENGINE_CAPI
            | OPENSSL_INIT_ENGINE_PADLOCK;

        extern "C" {
            pub fn OPENSSL_cleanup();
            pub fn OPENSSL_init_crypto(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int;
            pub fn OPENSSL_atexit(handler: unsafe extern "C" fn()) -> c_int;
            pub fn OPENSSL_thread_stop();

            pub fn OPENSSL_INIT_new() -> *mut OPENSSL_INIT_SETTINGS;
            #[cfg(ossl111)]
            pub fn OPENSSL_INIT_set_config_filename(
                settings: *mut OPENSSL_INIT_SETTINGS,
                config_filename: *const c_char,
            ) -> c_int;
            #[cfg(ossl111)]
            pub fn OPENSSL_INIT_set_config_file_flags(settings: *mut OPENSSL_INIT_SETTINGS, flags: c_ulong);
            pub fn OPENSSL_INIT_set_config_appname(
                settings: *mut OPENSSL_INIT_SETTINGS,
                config_file: *const c_char,
            ) -> c_int;
            pub fn OPENSSL_INIT_free(settings: *mut OPENSSL_INIT_SETTINGS);
        }
    } else {
        pub enum CRYPTO_dynlock_value {}
        pub enum CRYPTO_EX_DATA_IMPL {}

        extern "C" {
            pub fn CRYPTO_set_ex_data_implementation(i: *const CRYPTO_EX_DATA_IMPL) -> c_int;
        }
    }
}
