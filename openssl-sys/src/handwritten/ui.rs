use super::super::*;
use libc::*;

pub enum UI {}

pub enum UI_STRING {}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        pub enum UI_METHOD {}
    } else {
        #[repr(C)]
        pub struct UI_METHOD {
            pub name: *const c_char,
            pub ui_open_session: Option<extern "C" fn(ui: *mut UI) -> c_int>,
            pub ui_write_string: Option<extern "C" fn(ui: *mut UI, uis: *mut UI_STRING) -> c_int>,
            pub ui_flush: Option<extern "C" fn(ui: *mut UI) -> c_int>,
            pub ui_read_string: Option<extern "C" fn(ui: *mut UI, uis: *mut UI_STRING) -> c_int>,
            pub ui_close_session: Option<extern "C" fn(ui: *mut UI) -> c_int>,
            pub ui_duplicate_data: Option<extern "C" fn(ui: *mut UI, ui_data: *mut c_void) -> *mut c_void>,
            pub ui_destroy_data: Option<extern "C" fn(ui: *mut UI, ui_data: *mut c_void)>,
            pub ui_construct_prompt: Option<extern "C" fn(
                ui: *mut UI,
                object_desc: *const c_char,
                object_name: *const c_char,
            ) -> *mut c_char>,
            pub ex_data: CRYPTO_EX_DATA,
        }
    }
}

#[repr(C)]
pub enum UI_string_types {
    UIT_NONE = 0,
    UIT_PROMPT,
    UIT_VERIFY,
    UIT_BOOLEAN,
    UIT_INFO,
    UIT_ERROR,
}
