extern crate libc;
extern crate openssl;
extern crate openssl_sys as ffi;

use std::ffi::{CStr, CString};

use libc::*;

use ffi::*;

const TRUE: c_int = 1;
const FALSE: c_int = 0;

const ENGINE_KEYLESS_ID: &str = "keyless";
const ENGINE_KEYLESS_NAME: &str = "Keyless engine support";

IMPLEMENT_DYNAMIC_CHECK_FN!();
IMPLEMENT_DYNAMIC_BIND_FN!(bind_helper);

unsafe fn bind_helper(e: *mut ENGINE, id: *const c_char) -> c_int {
    if id.is_null() || CStr::from_ptr(id).to_string_lossy() != ENGINE_KEYLESS_ID {
        FALSE
    } else {
        bind_keyless(e)
    }
}

#[no_mangle]
pub extern "C" fn engine_keyless() -> *mut ENGINE {
    let engine = unsafe { ENGINE_new() };

    if !engine.is_null() {
        if FALSE == bind_keyless(engine) {
            unsafe {
                ENGINE_free(engine);
            }
        }
    }

    engine
}

#[no_mangle]
pub extern "C" fn ENGINE_load_keyless() {
    unsafe {
        let toadd = engine_keyless();
        if !toadd.is_null() {
            return;
        }
        ENGINE_add(toadd);
        ENGINE_free(toadd);
        ERR_clear_error();
    }
}

fn bind_keyless(e: *mut ENGINE) -> c_int {
    unsafe {
        if 0 == ENGINE_set_id(e, CString::new(ENGINE_KEYLESS_ID).unwrap().as_ptr())
            || 0 == ENGINE_set_name(e, CString::new(ENGINE_KEYLESS_NAME).unwrap().as_ptr())
            || 0 == ENGINE_set_destroy_function(e, Some(keyless_destroy))
            || 0 == ENGINE_set_init_function(e, Some(keyless_init))
            || 0 == ENGINE_set_finish_function(e, Some(keyless_finish))
        {
            FALSE
        } else {
            TRUE
        }
    }
}

#[no_mangle]
pub extern "C" fn keyless_init(_e: *mut ENGINE) -> c_int {
    TRUE
}

#[no_mangle]
pub extern "C" fn keyless_finish(_e: *mut ENGINE) -> c_int {
    TRUE
}

#[no_mangle]
pub extern "C" fn keyless_destroy(_e: *mut ENGINE) -> c_int {
    TRUE
}
