use super::super::*;
use libc::*;

pub enum RSA_METHOD {}
pub enum DSA_METHOD {}
pub enum DH_METHOD {}
pub enum RAND_METHOD {}

pub enum ENGINE_GEN_INT_FUNC_PTR {}
pub enum ENGINE_CIPHERS_PTR {}
pub enum ENGINE_DIGESTS_PTR {}
pub enum ENGINE_CMD_DEFN {}
pub enum ENGINE_CTRL_FUNC_PTR {}
pub enum ENGINE_LOAD_KEY_PTR {}
pub enum UI_METHOD {}

pub const ENGINE_METHOD_RSA: u32 = 0x0001;
pub const ENGINE_METHOD_DSA: u32 = 0x0002;
pub const ENGINE_METHOD_DH: u32 = 0x0004;
pub const ENGINE_METHOD_RAND: u32 = 0x0008;
pub const ENGINE_METHOD_CIPHERS: u32 = 0x0040;
pub const ENGINE_METHOD_DIGESTS: u32 = 0x0080;
pub const ENGINE_METHOD_PKEY_METHS: u32 = 0x0200;
pub const ENGINE_METHOD_PKEY_ASN1_METHS: u32 = 0x0400;
pub const ENGINE_METHOD_EC: u32 = 0x0800;

pub const ENGINE_METHOD_ALL: u32 = 0xffff;
pub const ENGINE_METHOD_NONE: u32 = 0xffff;

#[cfg(all(ossl110, not(ossl300)))]
extern "C" {
    pub fn ENGINE_get_first() -> *mut ENGINE;

    pub fn ENGINE_get_last() -> *mut ENGINE;

    pub fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;

    pub fn ENGINE_get_prev(e: *mut ENGINE) -> *mut ENGINE;

    pub fn ENGINE_add(e: *mut ENGINE) -> c_int;

    pub fn ENGINE_remove(e: *mut ENGINE) -> c_int;

    pub fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;

    pub fn ENGINE_init(e: *mut ENGINE) -> c_int;

    pub fn ENGINE_finish(e: *mut ENGINE) -> c_int;

    pub fn ENGINE_load_builtin_engines();

    pub fn ENGINE_get_default_RSA() -> *mut ENGINE;
    pub fn ENGINE_get_default_DSA() -> *mut ENGINE;
    pub fn ENGINE_get_default_DH() -> *mut ENGINE;
    pub fn ENGINE_get_default_RAND() -> *mut ENGINE;
    pub fn ENGINE_get_cipher_engine(nid: c_int) -> *mut ENGINE;
    pub fn ENGINE_get_digest_engine(nid: c_int) -> *mut ENGINE;

    pub fn ENGINE_set_default_RSA(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_DSA(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_DH(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_RAND(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_ciphers(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_digests(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_string(e: *mut ENGINE, list: *const c_char) -> c_int;

    pub fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int;

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

    pub fn ENGINE_register_complete(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_register_all_complete() -> c_int;

    pub fn ENGINE_ctrl(
        e: *mut ENGINE,
        cmd: c_int,
        i: c_long,
        p: *mut c_void,
        f: extern "C" fn(),
    ) -> c_int;

    pub fn ENGINE_cmd_is_executable(e: *mut ENGINE, cmd: c_int) -> c_int;

    pub fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        i: c_long,
        p: *mut c_void,
        f: extern "C" fn(),
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

    pub fn ENGINE_set_DSA(e: *mut ENGINE, DSA_meth: *const DSA_METHOD) -> c_int;

    pub fn ENGINE_set_DH(e: *mut ENGINE, DH_meth: *const DH_METHOD) -> c_int;

    pub fn ENGINE_set_RAND(e: *mut ENGINE, RAND_meth: *const RAND_METHOD) -> c_int;

    pub fn ENGINE_set_destroy_function(
        e: *mut ENGINE,
        destroy_f: extern "C" fn(*mut ENGINE) -> c_int,
    ) -> c_int;

    pub fn ENGINE_set_init_function(
        e: *mut ENGINE,
        init_f: extern "C" fn(*mut ENGINE) -> c_int,
    ) -> c_int;

    pub fn ENGINE_set_finish_function(
        e: *mut ENGINE,
        finish_f: extern "C" fn(*mut ENGINE) -> c_int,
    ) -> c_int;

    pub fn ENGINE_set_ctrl_function(
        e: *mut ENGINE,
        ctrl_f: extern "C" fn(*mut ENGINE, c_int, c_long, *mut c_void, extern "C" fn()) -> c_int,
    ) -> c_int;

    pub fn ENGINE_set_load_privkey_function(
        e: *mut ENGINE,
        loadpriv_f: extern "C" fn(
            *mut ENGINE,
            *const c_char,
            *mut UI_METHOD,
            *mut c_void,
        ) -> *mut EVP_PKEY,
    ) -> c_int;

    pub fn ENGINE_set_load_pubkey_function(
        e: *mut ENGINE,
        loadpub_f: unsafe extern "C" fn(
            *mut ENGINE,
            *const c_char,
            *mut UI_METHOD,
            *mut c_void,
        ) -> *mut EVP_PKEY,
    ) -> c_int;

    pub fn ENGINE_set_ciphers(e: *mut ENGINE, f: ENGINE_CIPHERS_PTR) -> c_int;

    pub fn ENGINE_set_digests(e: *mut ENGINE, f: ENGINE_DIGESTS_PTR) -> c_int;

    pub fn ENGINE_set_cmd_defns(e: *mut ENGINE, defns: *const ENGINE_CMD_DEFN) -> c_int;

    pub fn ENGINE_get_id(e: *const ENGINE) -> *const c_char;

    pub fn ENGINE_get_name(e: *const ENGINE) -> *const c_char;

    pub fn ENGINE_get_RSA(e: *const ENGINE) -> *const RSA_METHOD;

    pub fn ENGINE_get_DSA(e: *const ENGINE) -> *const DSA_METHOD;

    pub fn ENGINE_get_DH(e: *const ENGINE) -> *const DH_METHOD;

    pub fn ENGINE_get_RAND(e: *const ENGINE) -> *const RAND_METHOD;

    pub fn ENGINE_get_destroy_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;

    pub fn ENGINE_get_init_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;

    pub fn ENGINE_get_finish_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR;

    pub fn ENGINE_get_ctrl_function(e: *const ENGINE) -> ENGINE_CTRL_FUNC_PTR;

    pub fn ENGINE_get_load_privkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR;

    pub fn ENGINE_get_load_pubkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR;

    pub fn ENGINE_get_ciphers(e: *const ENGINE) -> ENGINE_CIPHERS_PTR;

    pub fn ENGINE_get_digests(e: *const ENGINE) -> ENGINE_DIGESTS_PTR;

    pub fn ENGINE_get_cipher(e: *mut ENGINE, nid: c_int) -> *const EVP_CIPHER;

    pub fn ENGINE_get_digest(e: *mut ENGINE, nid: c_int) -> *const EVP_MD;

    pub fn ENGINE_get_flags(e: *const ENGINE) -> c_int;

    pub fn ENGINE_get_cmd_defns(e: *const ENGINE) -> *const ENGINE_CMD_DEFN;

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

}

extern "C" {
    #[cfg(any(ossl100))]
    pub fn ENGINE_cleanup();
}
