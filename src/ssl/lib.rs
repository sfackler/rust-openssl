
mod ffi {
    use std::libc::{c_int};

    #[link_args = "-lssl"]
    extern "C" {
        fn SSL_library_init() -> c_int;
        fn SSL_load_error_strings();
    }
}

#[fixed_stack_segment]
pub fn init() {
    unsafe {
        ffi::SSL_library_init();
        ffi::SSL_load_error_strings();
    }
}
