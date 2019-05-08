#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate lazy_static;
extern crate foreign_types;
extern crate libc;
extern crate openssl;
extern crate openssl_sys as ffi;

use std::mem;
use std::ptr;
use std::sync::{Once, ONCE_INIT};

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::*;

use ffi::*;
use openssl::{
    engine::{self, Engine, EngineRef},
    error::ErrorStack,
    ex_data::Index,
    pkey::Private,
    rsa::{Rsa, RsaMethod, RsaRef},
};

const TRUE: c_int = 1;
const FALSE: c_int = 0;

const ENGINE_KEYLESS_ID: &str = "keyless";
const ENGINE_KEYLESS_NAME: &str = "Keyless engine support";

cfg_if! {
    if #[cfg(crate_type = "cdylib")] {
        IMPLEMENT_DYNAMIC_CHECK_FN!();
        IMPLEMENT_DYNAMIC_BIND_FN!(bind_helper);

        unsafe fn bind_helper(e: *mut ENGINE, id: *const c_char) -> c_int {
            if id.is_null() || CStr::from_ptr(id).to_str() != Ok(ENGINE_KEYLESS_ID) {
                FALSE
            } else {
                bind_keyless(e).map_or_else(FALSE, |_| TRUE)
            }
        }
    } else {
        #[no_mangle]
        pub extern "C" fn engine_keyless() -> *mut ENGINE {
            let engine = Engine::new();

            if bind_keyless(&engine).is_ok() {
                engine.into_ptr()
            } else {
                ptr::null_mut()
            }
        }

        #[no_mangle]
        pub extern "C" fn ENGINE_load_keyless() {
            let e = Engine::new();

            if bind_keyless(&e).is_ok() {
                engine::add(&e).unwrap();
                unsafe{ ERR_clear_error(); }
            }
        }
    }
}

fn bind_keyless(e: &EngineRef) -> Result<(), ErrorStack> {
    e.set_id(ENGINE_KEYLESS_ID)?;
    e.set_name(ENGINE_KEYLESS_NAME)?;
    e.set_flags(engine::Flags::NO_REGISTER_ALL)?;
    e.set_init_function(Some(keyless_init))?;
    e.set_finish_function(Some(keyless_finish))?;
    e.set_destroy_function(Some(keyless_destroy))?;
    e.set_rsa(Some(&**KEYLESS_RSA_METHOD))?;
    e.set_cmd_defns(KEYLESS_CMD_DEFNS.as_slice())?;
    e.set_ctrl_function(Some(keyless_ctrl))?;

    Ok(())
}

lazy_static! {
    static ref KEYLESS_RSA_METHOD: RsaMethod = RsaMethod::new("Keyless RSA method");
    static ref KEYLESS_CMD_DEFNS: Vec<ffi::ENGINE_CMD_DEFN> = vec![unsafe { mem::zeroed() },];
    static ref KEYLESS_ENGINE_CONTEXT_INDEX: Index<Engine, EngineContext> =
        Engine::new_ex_index().unwrap();
    static ref KEYLESS_RSA_CONTEXT_INDEX: Index<Rsa<Private>, RsaContext> =
        Rsa::new_ex_index().unwrap();
}

struct EngineContext {}

struct RsaContext {}

static INIT: Once = ONCE_INIT;

unsafe extern "C" fn keyless_init(e: *mut ENGINE) -> c_int {
    let e = EngineRef::from_ptr(e);

    INIT.call_once(|| {
        let ossl_rsa_meth = RsaMethod::openssl();

        KEYLESS_RSA_METHOD
            .set_pub_enc(ossl_rsa_meth.pub_enc())
            .unwrap();
        KEYLESS_RSA_METHOD
            .set_pub_dec(ossl_rsa_meth.pub_dec())
            .unwrap();
        KEYLESS_RSA_METHOD
            .set_priv_enc(ossl_rsa_meth.priv_enc())
            .unwrap();
        KEYLESS_RSA_METHOD
            .set_priv_dec(Some(keyless_rsa_priv_dec))
            .unwrap();
        KEYLESS_RSA_METHOD
            .set_mod_exp(ossl_rsa_meth.mod_exp())
            .unwrap();
        KEYLESS_RSA_METHOD
            .set_bn_mod_exp(ossl_rsa_meth.bn_mod_exp())
            .unwrap();
        KEYLESS_RSA_METHOD.set_sign(Some(keyless_rsa_sign)).unwrap();
    });

    TRUE
}

unsafe extern "C" fn keyless_rsa_priv_dec(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut RSA,
    padding: c_int,
) -> c_int {
    let rsa = RsaRef::from_ptr(rsa);
    let ctx = rsa.ex_data(*KEYLESS_RSA_CONTEXT_INDEX).unwrap();

    TRUE
}

unsafe extern "C" fn keyless_rsa_sign(
    meth: c_int,
    m: *const c_uchar,
    m_length: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *const RSA,
) -> c_int {
    let rsa = RsaRef::from_ptr(rsa as *mut _);
    let ctx = rsa.ex_data(*KEYLESS_RSA_CONTEXT_INDEX).unwrap();

    TRUE
}

unsafe extern "C" fn keyless_finish(e: *mut ENGINE) -> c_int {
    let e = EngineRef::from_ptr(e);
    let ctx = e.ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX).unwrap();

    TRUE
}

unsafe extern "C" fn keyless_destroy(e: *mut ENGINE) -> c_int {
    let e = EngineRef::from_ptr(e);
    let ctx = e.ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX).unwrap();

    TRUE
}

unsafe extern "C" fn keyless_ctrl(
    e: *mut ENGINE,
    i: c_int,
    l: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> c_int {
    let e = EngineRef::from_ptr(e);
    let ctx = e.ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX).unwrap();

    TRUE
}
