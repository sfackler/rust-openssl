#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate openssl;
extern crate openssl_sys as ffi;

use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use libc::*;

use ffi::*;
use openssl::{
    engine::{self, Engine, EngineRef},
    error::ErrorStack,
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
    e.set_rsa(unsafe { KEYLESS_RSA_METHOD.load(Ordering::Relaxed).as_ref() })?;
    e.set_cmd_defns(KEYLESS_CMD_DEFNS.as_slice())?;
    e.set_ctrl_function(Some(keyless_ctrl))?;

    Ok(())
}

lazy_static! {
    static ref KEYLESS_RSA_METHOD: AtomicPtr<ffi::RSA_METHOD> = Default::default();

    static ref KEYLESS_CMD_DEFNS: Vec<ffi::ENGINE_CMD_DEFN> = vec![unsafe { mem::zeroed() },];
}

unsafe extern "C" fn keyless_init(_e: *mut ENGINE) -> c_int {
    TRUE
}

unsafe extern "C" fn keyless_finish(_e: *mut ENGINE) -> c_int {
    TRUE
}

unsafe extern "C" fn keyless_destroy(_e: *mut ENGINE) -> c_int {
    TRUE
}

unsafe extern "C" fn keyless_ctrl(
    e: *mut ENGINE,
    i: c_int,
    l: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> c_int {
    TRUE
}
