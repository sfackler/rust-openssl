use std::ptr;

use libc::*;

use *;

pub const ENGINE_METHOD_RSA: u32 = 0x0001;
pub const ENGINE_METHOD_DSA: u32 = 0x0002;
pub const ENGINE_METHOD_DH: u32 = 0x0004;
pub const ENGINE_METHOD_RAND: u32 = 0x0008;
#[cfg(not(ossl110))]
pub const ENGINE_METHOD_ECDH: u32 = 0x0010;
#[cfg(not(ossl110))]
pub const ENGINE_METHOD_ECDSA: u32 = 0x0020;
pub const ENGINE_METHOD_CIPHERS: u32 = 0x0040;
pub const ENGINE_METHOD_DIGESTS: u32 = 0x0080;
#[cfg(not(ossl110))]
pub const ENGINE_METHOD_STORE: u32 = 0x0100;
pub const ENGINE_METHOD_PKEY_METHS: u32 = 0x0200;
pub const ENGINE_METHOD_PKEY_ASN1_METHS: u32 = 0x0400;
#[cfg(ossl110)]
pub const ENGINE_METHOD_EC: u32 = 0x0800;
pub const ENGINE_METHOD_ALL: u32 = 0xFFFF;
pub const ENGINE_METHOD_NONE: u32 = 0x0000;

pub const ENGINE_TABLE_FLAG_NOINIT: u32 = 0x0001;
pub const ENGINE_FLAGS_MANUAL_CMD_CTRL: u32 = 0x0002;
pub const ENGINE_FLAGS_BY_ID_COPY: u32 = 0x0004;
pub const ENGINE_FLAGS_NO_REGISTER_ALL: u32 = 0x0008;

pub const ENGINE_CMD_FLAG_NUMERIC: u32 = 0x0001;
pub const ENGINE_CMD_FLAG_STRING: u32 = 0x0002;
pub const ENGINE_CMD_FLAG_NO_INPUT: u32 = 0x0004;
pub const ENGINE_CMD_FLAG_INTERNAL: u32 = 0x0008;

pub const ENGINE_CTRL_SET_LOGSTREAM: u32 = 1;
pub const ENGINE_CTRL_SET_PASSWORD_CALLBACK: u32 = 2;
pub const ENGINE_CTRL_HUP: u32 = 3;
pub const ENGINE_CTRL_SET_USER_INTERFACE: u32 = 4;
pub const ENGINE_CTRL_SET_CALLBACK_DATA: u32 = 5;
pub const ENGINE_CTRL_LOAD_CONFIGURATION: u32 = 6;
pub const ENGINE_CTRL_LOAD_SECTION: u32 = 7;
pub const ENGINE_CTRL_HAS_CTRL_FUNCTION: u32 = 10;
pub const ENGINE_CTRL_GET_FIRST_CMD_TYPE: u32 = 11;
pub const ENGINE_CTRL_GET_NEXT_CMD_TYPE: u32 = 12;
pub const ENGINE_CTRL_GET_CMD_FROM_NAME: u32 = 13;
pub const ENGINE_CTRL_GET_NAME_LEN_FROM_CMD: u32 = 14;
pub const ENGINE_CTRL_GET_NAME_FROM_CMD: u32 = 15;
pub const ENGINE_CTRL_GET_DESC_LEN_FROM_CMD: u32 = 16;
pub const ENGINE_CTRL_GET_DESC_FROM_CMD: u32 = 17;
pub const ENGINE_CTRL_GET_CMD_FLAGS: u32 = 18;
pub const ENGINE_CMD_BASE: u32 = 200;
#[cfg(not(libressl))]
pub const ENGINE_CTRL_CHIL_SET_FORKCHECK: u32 = 100;
#[cfg(not(libressl))]
pub const ENGINE_CTRL_CHIL_NO_LOCKING: u32 = 101;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ENGINE_CMD_DEFN {
    pub cmd_num: c_uint,
    pub cmd_name: *const c_char,
    pub cmd_desc: *const c_char,
    pub cmd_flags: c_uint,
}

pub type ENGINE_GEN_FUNC_PTR = Option<unsafe extern "C" fn() -> c_int>;
pub type ENGINE_GEN_INT_FUNC_PTR = Option<unsafe extern "C" fn(arg1: *mut ENGINE) -> c_int>;
pub type ENGINE_CTRL_FUNC_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: c_int,
        arg3: c_long,
        arg4: *mut c_void,
        f: Option<unsafe extern "C" fn()>,
    ) -> c_int,
>;
pub type ENGINE_LOAD_KEY_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY,
>;
pub type ENGINE_SSL_CLIENT_CERT_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        ssl: *mut SSL,
        ca_dn: *mut stack_st_X509_NAME,
        pcert: *mut *mut X509,
        pkey: *mut *mut EVP_PKEY,
        pother: *mut *mut stack_st_X509,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> c_int,
>;
pub type ENGINE_CIPHERS_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: *mut *const EVP_CIPHER,
        arg3: *mut *const c_int,
        arg4: c_int,
    ) -> c_int,
>;
pub type ENGINE_DIGESTS_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: *mut *const EVP_MD,
        arg3: *mut *const c_int,
        arg4: c_int,
    ) -> c_int,
>;
pub type ENGINE_PKEY_METHS_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: *mut *mut EVP_PKEY_METHOD,
        arg3: *mut *const c_int,
        arg4: c_int,
    ) -> c_int,
>;
pub type ENGINE_PKEY_ASN1_METHS_PTR = Option<
    unsafe extern "C" fn(
        arg1: *mut ENGINE,
        arg2: *mut *mut EVP_PKEY_ASN1_METHOD,
        arg3: *mut *const c_int,
        arg4: c_int,
    ) -> c_int,
>;

extern "C" {
    pub fn ENGINE_get_first() -> *mut ENGINE;
    pub fn ENGINE_get_last() -> *mut ENGINE;
    pub fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;
    pub fn ENGINE_get_prev(e: *mut ENGINE) -> *mut ENGINE;
    pub fn ENGINE_add(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_remove(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;

    pub fn ENGINE_load_builtin_engines();

    pub fn ENGINE_get_table_flags() -> c_uint;
    pub fn ENGINE_set_table_flags(flags: c_uint);

    pub fn ENGINE_register_RSA(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_RSA(e: *mut ENGINE);
    pub fn ENGINE_register_all_RSA();

    pub fn ENGINE_register_DSA(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_DSA(e: *mut ENGINE);
    pub fn ENGINE_register_all_DSA();

    pub fn ENGINE_register_DH(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_DH(e: *mut ENGINE);
    pub fn ENGINE_register_all_DH();

    pub fn ENGINE_register_RAND(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_RAND(e: *mut ENGINE);
    pub fn ENGINE_register_all_RAND();

    pub fn ENGINE_register_ciphers(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_ciphers(e: *mut ENGINE);
    pub fn ENGINE_register_all_ciphers();

    pub fn ENGINE_register_digests(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_digests(e: *mut ENGINE);
    pub fn ENGINE_register_all_digests();

    pub fn ENGINE_register_pkey_meths(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_pkey_meths(e: *mut ENGINE);
    pub fn ENGINE_register_all_pkey_meths();

    pub fn ENGINE_register_pkey_asn1_meths(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_unregister_pkey_asn1_meths(e: *mut ENGINE);
    pub fn ENGINE_register_all_pkey_asn1_meths();

    pub fn ENGINE_register_complete(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_register_all_complete() -> c_int;

    pub fn ENGINE_ctrl(
        e: *mut ENGINE,
        cmd: c_int,
        i: c_long,
        p: *mut c_void,
        f: Option<unsafe extern "C" fn()>,
    ) -> c_int;

    pub fn ENGINE_cmd_is_executable(e: *mut ENGINE, cmd: c_int) -> c_int;

    pub fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        i: c_long,
        p: *mut c_void,
        f: Option<unsafe extern "C" fn()>,
        cmd_optional: c_int,
    ) -> c_int;

    pub fn ENGINE_ctrl_cmd_string(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        arg: *const c_char,
        cmd_optional: c_int,
    ) -> c_int;

    pub fn ENGINE_new() -> *mut ENGINE;
    pub fn ENGINE_free(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_up_ref(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_id(e: *mut ENGINE, id: *const c_char) -> c_int;
    pub fn ENGINE_set_name(e: *mut ENGINE, name: *const c_char) -> c_int;
    pub fn ENGINE_set_RSA(e: *mut ENGINE, rsa_meth: *const RSA_METHOD) -> c_int;
    pub fn ENGINE_set_DSA(e: *mut ENGINE, dsa_meth: *const DSA_METHOD) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ENGINE_set_ECDH(e: *mut ENGINE, ecdh_meth: *const ECDH_METHOD) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ENGINE_set_ECDSA(e: *mut ENGINE, ecdsa_meth: *const ECDSA_METHOD) -> c_int;
    #[cfg(ossl110)]
    pub fn ENGINE_set_EC(e: *mut ENGINE, ecdsa_meth: *const EC_KEY_METHOD) -> c_int;
    pub fn ENGINE_set_DH(e: *mut ENGINE, dh_meth: *const DH_METHOD) -> c_int;
    pub fn ENGINE_set_RAND(e: *mut ENGINE, rand_meth: *const RAND_METHOD) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ENGINE_set_STORE(e: *mut ENGINE, store_meth: *const STORE_METHOD) -> c_int;
    pub fn ENGINE_set_destroy_function(e: *mut ENGINE, destroy_f: ENGINE_GEN_INT_FUNC_PTR)
        -> c_int;
    pub fn ENGINE_set_init_function(e: *mut ENGINE, init_f: ENGINE_GEN_INT_FUNC_PTR) -> c_int;
    pub fn ENGINE_set_finish_function(e: *mut ENGINE, finish_f: ENGINE_GEN_INT_FUNC_PTR) -> c_int;
    pub fn ENGINE_set_ctrl_function(e: *mut ENGINE, ctrl_f: ENGINE_CTRL_FUNC_PTR) -> c_int;
    pub fn ENGINE_set_load_privkey_function(
        e: *mut ENGINE,
        loadpriv_f: ENGINE_LOAD_KEY_PTR,
    ) -> c_int;
    pub fn ENGINE_set_load_pubkey_function(e: *mut ENGINE, loadpub_f: ENGINE_LOAD_KEY_PTR)
        -> c_int;
    pub fn ENGINE_set_load_ssl_client_cert_function(
        e: *mut ENGINE,
        loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR,
    ) -> c_int;
    pub fn ENGINE_set_ciphers(e: *mut ENGINE, f: ENGINE_CIPHERS_PTR) -> c_int;
    pub fn ENGINE_set_digests(e: *mut ENGINE, f: ENGINE_DIGESTS_PTR) -> c_int;
    pub fn ENGINE_set_pkey_meths(e: *mut ENGINE, f: ENGINE_PKEY_METHS_PTR) -> c_int;
    pub fn ENGINE_set_pkey_asn1_meths(e: *mut ENGINE, f: ENGINE_PKEY_ASN1_METHS_PTR) -> c_int;
    pub fn ENGINE_set_flags(e: *mut ENGINE, flags: c_int) -> c_int;
    pub fn ENGINE_set_cmd_defns(e: *mut ENGINE, defns: *const ENGINE_CMD_DEFN) -> c_int;
    pub fn ENGINE_set_ex_data(e: *mut ENGINE, idx: c_int, arg: *mut c_void) -> c_int;
    pub fn ENGINE_get_ex_data(e: *const ENGINE, idx: c_int) -> *mut c_void;

    pub fn ENGINE_get_id(e: *const ENGINE) -> *const c_char;
    pub fn ENGINE_get_name(e: *const ENGINE) -> *const c_char;
    pub fn ENGINE_get_RSA(e: *const ENGINE) -> *const RSA_METHOD;
    pub fn ENGINE_get_DSA(e: *const ENGINE) -> *const DSA_METHOD;
    #[cfg(not(ossl110))]
    pub fn ENGINE_get_ECDH(e: *const ENGINE) -> *const ECDH_METHOD;
    #[cfg(not(ossl110))]
    pub fn ENGINE_get_ECDSA(e: *const ENGINE) -> *const ECDSA_METHOD;
    #[cfg(ossl110)]
    pub fn ENGINE_get_EC(e: *const ENGINE) -> *const EC_KEY_METHOD;
    pub fn ENGINE_get_DH(e: *const ENGINE) -> *const DH_METHOD;
    pub fn ENGINE_get_RAND(e: *const ENGINE) -> *const RAND_METHOD;
    #[cfg(not(ossl110))]
    pub fn ENGINE_get_STORE(e: *const ENGINE) -> *const STORE_METHOD;
    pub fn ENGINE_get_destroy_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;
    pub fn ENGINE_get_init_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;
    pub fn ENGINE_get_finish_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;
    pub fn ENGINE_get_ctrl_function(e: *const ENGINE) -> ENGINE_CTRL_FUNC_PTR;
    pub fn ENGINE_get_load_privkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR;
    pub fn ENGINE_get_load_pubkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR;
    pub fn ENGINE_get_ssl_client_cert_function(e: *const ENGINE) -> ENGINE_SSL_CLIENT_CERT_PTR;
    pub fn ENGINE_get_ciphers(e: *const ENGINE) -> ENGINE_CIPHERS_PTR;
    pub fn ENGINE_get_digests(e: *const ENGINE) -> ENGINE_DIGESTS_PTR;
    pub fn ENGINE_get_pkey_meths(e: *const ENGINE) -> ENGINE_PKEY_METHS_PTR;
    pub fn ENGINE_get_pkey_asn1_meths(e: *const ENGINE) -> ENGINE_PKEY_ASN1_METHS_PTR;
    pub fn ENGINE_get_cipher(e: *mut ENGINE, nid: c_int) -> *const EVP_CIPHER;
    pub fn ENGINE_get_digest(e: *mut ENGINE, nid: c_int) -> *const EVP_MD;
    pub fn ENGINE_get_pkey_meth(e: *mut ENGINE, nid: c_int) -> *const EVP_PKEY_METHOD;
    pub fn ENGINE_get_pkey_asn1_meth(e: *mut ENGINE, nid: c_int) -> *const EVP_PKEY_ASN1_METHOD;
    pub fn ENGINE_get_pkey_asn1_meth_str(
        e: *mut ENGINE,
        str: *const c_char,
        len: c_int,
    ) -> *const EVP_PKEY_ASN1_METHOD;
    pub fn ENGINE_pkey_asn1_find_str(
        pe: *mut *mut ENGINE,
        str: *const c_char,
        len: c_int,
    ) -> *const EVP_PKEY_ASN1_METHOD;
    pub fn ENGINE_get_cmd_defns(e: *const ENGINE) -> *const ENGINE_CMD_DEFN;
    pub fn ENGINE_get_flags(e: *const ENGINE) -> c_int;

    pub fn ENGINE_init(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_load_private_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn ENGINE_load_public_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn ENGINE_load_ssl_client_cert(
        e: *mut ENGINE,
        s: *mut SSL,
        ca_dn: *mut stack_st_X509_NAME,
        pcert: *mut *mut X509,
        ppkey: *mut *mut EVP_PKEY,
        pother: *mut *mut stack_st_X509,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> c_int;

    pub fn ENGINE_get_default_RSA() -> *mut ENGINE;
    pub fn ENGINE_get_default_DSA() -> *mut ENGINE;
    #[cfg(not(ossl110))]
    pub fn ENGINE_get_default_ECDH() -> *mut ENGINE;
    #[cfg(not(ossl110))]
    pub fn ENGINE_get_default_ECDSA() -> *mut ENGINE;
    #[cfg(ossl110)]
    pub fn ENGINE_get_default_EC() -> *mut ENGINE;
    pub fn ENGINE_get_default_DH() -> *mut ENGINE;
    pub fn ENGINE_get_default_RAND() -> *mut ENGINE;

    pub fn ENGINE_get_cipher_engine(nid: c_int) -> *mut ENGINE;
    pub fn ENGINE_get_digest_engine(nid: c_int) -> *mut ENGINE;
    pub fn ENGINE_get_pkey_meth_engine(nid: c_int) -> *mut ENGINE;
    pub fn ENGINE_get_pkey_asn1_meth_engine(nid: c_int) -> *mut ENGINE;

    pub fn ENGINE_set_default_RSA(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_string(e: *mut ENGINE, def_list: *const c_char) -> c_int;
    pub fn ENGINE_set_default_DSA(e: *mut ENGINE) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ENGINE_set_default_ECDH(e: *mut ENGINE) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ENGINE_set_default_ECDSA(e: *mut ENGINE) -> c_int;
    #[cfg(ossl110)]
    pub fn ENGINE_set_default_EC(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_DH(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_RAND(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_ciphers(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_digests(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_pkey_meths(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_pkey_asn1_meths(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int;
    pub fn ENGINE_add_conf_module();
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub unsafe fn ENGINE_load_openssl() {
            OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, ptr::null());
        }
        pub unsafe fn ENGINE_load_dynamic() {
            OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, ptr::null());
        }
        pub unsafe fn ENGINE_load_cryptodev() {
            OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CRYPTODEV, ptr::null());
        }
        pub unsafe fn ENGINE_load_rdrand() {
            OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_RDRAND, ptr::null());
        }

        pub unsafe fn ENGINE_get_ex_new_index(
            argl: c_long,
            argp: *mut c_void,
            new_func: CRYPTO_EX_new,
            dup_func: CRYPTO_EX_dup,
            free_func: CRYPTO_EX_free,
        ) -> c_int {
            CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, argl, argp, Some(new_func), Some(dup_func), Some(free_func))
        }
        /// This function previously cleaned up anything that needs it.
        /// Auto-deinit will now take care of it so it is no longer required to call this function.
        pub fn ENGINE_cleanup() {}

        extern "C" {
            pub fn ENGINE_register_EC(e: *mut ENGINE) -> c_int;
            pub fn ENGINE_unregister_EC(e: *mut ENGINE);
            pub fn ENGINE_register_all_EC();

            #[cfg(not(ossl111))]
            pub fn ERR_load_ENGINE_strings() -> c_int;
        }

        pub const OSSL_DYNAMIC_VERSION: c_ulong = 0x00030000;
        pub const OSSL_DYNAMIC_OLDEST: c_ulong = 0x00030000;
    } else {
        extern "C" {
            pub fn ENGINE_load_openssl();
            pub fn ENGINE_load_dynamic();
            #[cfg(not(libressl))]
            pub fn ENGINE_load_cryptodev();
            #[cfg(not(libressl))]
            pub fn ENGINE_load_rdrand();

            pub fn ENGINE_get_ex_new_index(
                argl: c_long,
                argp: *mut c_void,
                new_func: CRYPTO_EX_new,
                dup_func: CRYPTO_EX_dup,
                free_func: CRYPTO_EX_free,
            ) -> c_int;

            /// This function cleans up anything that needs it. Eg. the ENGINE_add()
            /// function automatically ensures the list cleanup function is registered to
            /// be called from ENGINE_cleanup(). Similarly, all ENGINE_register_***
            /// functions ensure ENGINE_cleanup() will clean up after them.
            pub fn ENGINE_cleanup();

            pub fn ENGINE_register_ECDH(e: *mut ENGINE) -> c_int;
            pub fn ENGINE_unregister_ECDH(e: *mut ENGINE);
            pub fn ENGINE_register_all_ECDH();

            pub fn ENGINE_register_ECDSA(e: *mut ENGINE) -> c_int;
            pub fn ENGINE_unregister_ECDSA(e: *mut ENGINE);
            pub fn ENGINE_register_all_ECDSA();

            pub fn ENGINE_register_STORE(e: *mut ENGINE) -> c_int;
            pub fn ENGINE_unregister_STORE(e: *mut ENGINE);
            pub fn ENGINE_register_all_STORE();

            pub fn ERR_load_ENGINE_strings();
        }


        pub const OSSL_DYNAMIC_VERSION: c_ulong = 0x00020000;
        pub const OSSL_DYNAMIC_OLDEST: c_ulong = 0x00020000;
    }
}

pub type dynamic_v_check_fn = Option<unsafe extern "C" fn(ossl_version: c_ulong) -> c_ulong>;

#[macro_export]
macro_rules! IMPLEMENT_DYNAMIC_CHECK_FN {
    () => {
        #[no_mangle]
        pub extern "C" fn v_check(v: ::std::os::raw::c_ulong) -> ::std::os::raw::c_ulong {
            if v >= OSSL_DYNAMIC_OLDEST {
                OSSL_DYNAMIC_VERSION
            } else {
                0
            }
        }
    };
}

pub type dynamic_bind_engine = Option<
    unsafe extern "C" fn(e: *mut ENGINE, id: *const c_char, fns: *const dynamic_fns) -> c_int,
>;

cfg_if! {
    if #[cfg(ossl110)] {
        pub type dyn_MEM_malloc_fn =
            Option<unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void>;
        pub type dyn_MEM_realloc_fn = Option<
            unsafe extern "C" fn(
                 *mut c_void,
                 usize,
                 *const c_char,
                 c_int
            ) -> *mut c_void,
        >;
        pub type dyn_MEM_free_fn =
            Option<unsafe extern "C" fn(arg1: *mut c_void, *const c_char, c_int)>;
        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct st_dynamic_MEM_fns {
            pub malloc_fn: dyn_MEM_malloc_fn,
            pub realloc_fn: dyn_MEM_realloc_fn,
            pub free_fn: dyn_MEM_free_fn,
        }
        pub type dynamic_MEM_fns = st_dynamic_MEM_fns;

        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct st_dynamic_fns {
            pub static_state: *mut c_void,
            pub mem_fns: dynamic_MEM_fns,
        }
        pub type dynamic_fns = st_dynamic_fns;

        #[macro_export]
        macro_rules! IMPLEMENT_DYNAMIC_BIND_FN {
            ($fn:ident) => {
                #[no_mangle]
                pub extern "C" fn bind_engine(
                    e: *mut ENGINE,
                    id: *const c_char,
                    fns: *const dynamic_fns,
                ) -> c_int {
                    unsafe {
                        let fns = fns.as_ref().unwrap();

                        if ENGINE_get_static_state() != fns.static_state {
                            CRYPTO_set_mem_functions(
                                fns.mem_fns.malloc_fn,
                                fns.mem_fns.realloc_fn,
                                fns.mem_fns.free_fn,
                            );
                        }

                        $fn(e, id)
                    }
                }
            };
        }
    } else {
        pub type dyn_MEM_malloc_cb =
            Option<unsafe extern "C" fn(arg1: usize) -> *mut c_void>;
        pub type dyn_MEM_realloc_cb = Option<
            unsafe extern "C" fn(
                arg1: *mut c_void,
                arg2: usize,
            ) -> *mut c_void,
        >;
        pub type dyn_MEM_free_cb =
            Option<unsafe extern "C" fn(arg1: *mut c_void)>;
        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct st_dynamic_MEM_fns {
            pub malloc_cb: dyn_MEM_malloc_cb,
            pub realloc_cb: dyn_MEM_realloc_cb,
            pub free_cb: dyn_MEM_free_cb,
        }
        pub type dynamic_MEM_fns = st_dynamic_MEM_fns;

        pub type dyn_lock_locking_cb = Option<
            unsafe extern "C" fn(
                arg1: c_int,
                arg2: c_int,
                arg3: *const c_char,
                arg4: c_int,
            ),
        >;
        pub type dyn_lock_add_lock_cb = Option<
            unsafe extern "C" fn(
                arg1: *mut c_int,
                arg2: c_int,
                arg3: c_int,
                arg4: *const c_char,
                arg5: c_int,
            ) -> c_int,
        >;
        pub type dyn_dynlock_create_cb = Option<
            unsafe extern "C" fn(
                arg1: *const c_char,
                arg2: c_int,
            ) -> *mut CRYPTO_dynlock_value,
        >;
        pub type dyn_dynlock_lock_cb = Option<
            unsafe extern "C" fn(
                arg1: c_int,
                arg2: *mut CRYPTO_dynlock_value,
                arg3: *const c_char,
                arg4: c_int,
            ),
        >;
        pub type dyn_dynlock_destroy_cb = Option<
            unsafe extern "C" fn(
                arg1: *mut CRYPTO_dynlock_value,
                arg2: *const c_char,
                arg3: c_int,
            ),
        >;
        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct st_dynamic_LOCK_fns {
            pub lock_locking_cb: dyn_lock_locking_cb,
            pub lock_add_lock_cb: dyn_lock_add_lock_cb,
            pub dynlock_create_cb: dyn_dynlock_create_cb,
            pub dynlock_lock_cb: dyn_dynlock_lock_cb,
            pub dynlock_destroy_cb: dyn_dynlock_destroy_cb,
        }
        pub type dynamic_LOCK_fns = st_dynamic_LOCK_fns;

        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct st_dynamic_fns {
            pub static_state: *mut c_void,
            pub err_fns: *const ERR_FNS,
            pub ex_data_fns: *const CRYPTO_EX_DATA_IMPL,
            pub mem_fns: dynamic_MEM_fns,
            pub lock_fns: dynamic_LOCK_fns,
        }
        pub type dynamic_fns = st_dynamic_fns;

        #[macro_export]
        macro_rules! IMPLEMENT_DYNAMIC_BIND_FN {
            ($fn:ident) => {
                #[no_mangle]
                pub extern "C" fn bind_engine(
                    e: *mut ENGINE,
                    id: *const c_char,
                    fns: *const dynamic_fns,
                ) -> c_int {
                    unsafe {
                        let fns = fns.as_ref().unwrap();

                        if ENGINE_get_static_state() != fns.static_state {
                            if 0 == CRYPTO_set_mem_functions(
                                fns.mem_fns.malloc_cb,
                                fns.mem_fns.realloc_cb,
                                fns.mem_fns.free_cb,
                            ) {
                                return 0;
                            }

                            CRYPTO_set_locking_callback(fns.lock_fns.lock_locking_cb);
                            CRYPTO_set_add_lock_callback(fns.lock_fns.lock_add_lock_cb);
                            CRYPTO_set_dynlock_create_callback(fns.lock_fns.dynlock_create_cb);
                            CRYPTO_set_dynlock_lock_callback(fns.lock_fns.dynlock_lock_cb);
                            CRYPTO_set_dynlock_destroy_callback(fns.lock_fns.dynlock_destroy_cb);

                            if 0 == CRYPTO_set_ex_data_implementation(fns.ex_data_fns) {
                                return 0;
                            }
                            if 0 == ERR_set_implementation(fns.err_fns) {
                                return 0;
                            }
                        }

                        $fn(e, id)
                    }
                }
            };
        }
    }
}

extern "C" {
    pub fn ENGINE_get_static_state() -> *mut c_void;
}

// Error codes for the ENGINE functions. */
// Function codes.
#[cfg(ossl111)]
pub const ENGINE_F_DIGEST_UPDATE: u32 = 198;
pub const ENGINE_F_DYNAMIC_CTRL: u32 = 180;
pub const ENGINE_F_DYNAMIC_GET_DATA_CTX: u32 = 181;
pub const ENGINE_F_DYNAMIC_LOAD: u32 = 182;
pub const ENGINE_F_DYNAMIC_SET_DATA_CTX: u32 = 183;
pub const ENGINE_F_ENGINE_ADD: u32 = 105;
pub const ENGINE_F_ENGINE_BY_ID: u32 = 106;
pub const ENGINE_F_ENGINE_CMD_IS_EXECUTABLE: u32 = 170;
pub const ENGINE_F_ENGINE_CTRL: u32 = 142;
pub const ENGINE_F_ENGINE_CTRL_CMD: u32 = 178;
pub const ENGINE_F_ENGINE_CTRL_CMD_STRING: u32 = 171;
pub const ENGINE_F_ENGINE_FINISH: u32 = 107;
#[cfg(not(ossl110))]
pub const ENGINE_F_ENGINE_FREE_UTIL: u32 = 108;
pub const ENGINE_F_ENGINE_GET_CIPHER: u32 = 185;
#[cfg(not(ossl110))]
pub const ENGINE_F_ENGINE_GET_DEFAULT_TYPE: u32 = 177;
pub const ENGINE_F_ENGINE_GET_DIGEST: u32 = 186;
#[cfg(ossl110)]
pub const ENGINE_F_ENGINE_GET_FIRST: u32 = 195;
#[cfg(ossl110)]
pub const ENGINE_F_ENGINE_GET_LAST: u32 = 196;
pub const ENGINE_F_ENGINE_GET_NEXT: u32 = 115;
pub const ENGINE_F_ENGINE_GET_PKEY_ASN1_METH: u32 = 193;
pub const ENGINE_F_ENGINE_GET_PKEY_METH: u32 = 192;
pub const ENGINE_F_ENGINE_GET_PREV: u32 = 116;
pub const ENGINE_F_ENGINE_INIT: u32 = 119;
pub const ENGINE_F_ENGINE_LIST_ADD: u32 = 120;
pub const ENGINE_F_ENGINE_LIST_REMOVE: u32 = 121;
pub const ENGINE_F_ENGINE_LOAD_PRIVATE_KEY: u32 = 150;
pub const ENGINE_F_ENGINE_LOAD_PUBLIC_KEY: u32 = 151;
pub const ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT: u32 = 194;
pub const ENGINE_F_ENGINE_NEW: u32 = 122;
#[cfg(ossl110)]
pub const ENGINE_F_ENGINE_PKEY_ASN1_FIND_STR: u32 = 197;
pub const ENGINE_F_ENGINE_REMOVE: u32 = 123;
pub const ENGINE_F_ENGINE_SET_DEFAULT_STRING: u32 = 189;
#[cfg(not(ossl110))]
pub const ENGINE_F_ENGINE_SET_DEFAULT_TYPE: u32 = 126;
pub const ENGINE_F_ENGINE_SET_ID: u32 = 129;
pub const ENGINE_F_ENGINE_SET_NAME: u32 = 130;
pub const ENGINE_F_ENGINE_TABLE_REGISTER: u32 = 184;
#[cfg(not(ossl110))]
pub const ENGINE_F_ENGINE_UNLOAD_KEY: u32 = 152;
pub const ENGINE_F_ENGINE_UNLOCKED_FINISH: u32 = 191;
pub const ENGINE_F_ENGINE_UP_REF: u32 = 190;
#[cfg(ossl111)]
pub const ENGINE_F_INT_CLEANUP_ITEM: u32 = 199;
pub const ENGINE_F_INT_CTRL_HELPER: u32 = 172;
pub const ENGINE_F_INT_ENGINE_CONFIGURE: u32 = 188;
pub const ENGINE_F_INT_ENGINE_MODULE_INIT: u32 = 187;
#[cfg(not(ossl110))]
pub const ENGINE_F_LOG_MESSAGE: u32 = 141;
#[cfg(ossl111)]
pub const ENGINE_F_OSSL_HMAC_INIT: u32 = 200;

// Reason codes.
pub const ENGINE_R_ALREADY_LOADED: u32 = 100;
pub const ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER: u32 = 133;
pub const ENGINE_R_CMD_NOT_EXECUTABLE: u32 = 134;
pub const ENGINE_R_COMMAND_TAKES_INPUT: u32 = 135;
pub const ENGINE_R_COMMAND_TAKES_NO_INPUT: u32 = 136;
pub const ENGINE_R_CONFLICTING_ENGINE_ID: u32 = 103;
pub const ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED: u32 = 119;
#[cfg(not(ossl110))]
pub const ENGINE_R_DH_NOT_IMPLEMENTED: u32 = 139;
#[cfg(not(ossl110))]
pub const ENGINE_R_DSA_NOT_IMPLEMENTED: u32 = 140;
pub const ENGINE_R_DSO_FAILURE: u32 = 104;
pub const ENGINE_R_DSO_NOT_FOUND: u32 = 132;
pub const ENGINE_R_ENGINES_SECTION_ERROR: u32 = 148;
pub const ENGINE_R_ENGINE_CONFIGURATION_ERROR: u32 = 102;
pub const ENGINE_R_ENGINE_IS_NOT_IN_LIST: u32 = 105;
pub const ENGINE_R_ENGINE_SECTION_ERROR: u32 = 149;
pub const ENGINE_R_FAILED_LOADING_PRIVATE_KEY: u32 = 128;
pub const ENGINE_R_FAILED_LOADING_PUBLIC_KEY: u32 = 129;
pub const ENGINE_R_FINISH_FAILED: u32 = 106;
#[cfg(not(ossl110))]
pub const ENGINE_R_GET_HANDLE_FAILED: u32 = 107;
pub const ENGINE_R_ID_OR_NAME_MISSING: u32 = 108;
pub const ENGINE_R_INIT_FAILED: u32 = 109;
pub const ENGINE_R_INTERNAL_LIST_ERROR: u32 = 110;
pub const ENGINE_R_INVALID_ARGUMENT: u32 = 143;
pub const ENGINE_R_INVALID_CMD_NAME: u32 = 137;
pub const ENGINE_R_INVALID_CMD_NUMBER: u32 = 138;
pub const ENGINE_R_INVALID_INIT_VALUE: u32 = 151;
pub const ENGINE_R_INVALID_STRING: u32 = 150;
pub const ENGINE_R_NOT_INITIALISED: u32 = 117;
pub const ENGINE_R_NOT_LOADED: u32 = 112;
pub const ENGINE_R_NO_CONTROL_FUNCTION: u32 = 120;
pub const ENGINE_R_NO_INDEX: u32 = 144;
pub const ENGINE_R_NO_LOAD_FUNCTION: u32 = 125;
pub const ENGINE_R_NO_REFERENCE: u32 = 130;
pub const ENGINE_R_NO_SUCH_ENGINE: u32 = 116;
#[cfg(not(ossl110))]
pub const ENGINE_R_NO_UNLOAD_FUNCTION: u32 = 126;
#[cfg(not(ossl110))]
pub const ENGINE_R_PROVIDE_PARAMETERS: u32 = 113;
#[cfg(not(ossl110))]
pub const ENGINE_R_RSA_NOT_IMPLEMENTED: u32 = 141;
pub const ENGINE_R_UNIMPLEMENTED_CIPHER: u32 = 146;
pub const ENGINE_R_UNIMPLEMENTED_DIGEST: u32 = 147;
pub const ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD: u32 = 101;
pub const ENGINE_R_VERSION_INCOMPATIBILITY: u32 = 145;
