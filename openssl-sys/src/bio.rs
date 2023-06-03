use libc::*;

use super::*;

pub const BIO_TYPE_NONE: c_int = 0;

pub const BIO_CTRL_EOF: c_int = 2;
pub const BIO_CTRL_INFO: c_int = 3;
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_CTRL_DGRAM_QUERY_MTU: c_int = 40;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;

pub unsafe fn BIO_set_retry_read(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_write(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_clear_retry_flags(b: *mut BIO) {
    BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)
}

pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    BIO_ctrl(b, BIO_CTRL_INFO, 0, pp as *mut c_void)
}

// These symbols were originally bound with the wrong signatures. They were then
// deprecated in favor of `__fixed_rust`-suffixed versions. The unsuffixed
// symbols are now fixed, so the suffixed ones are deprecated aliases.
#[deprecated(note = "use BIO_meth_set_write instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_write__fixed_rust(
    biom: *mut BIO_METHOD,
    write: Option<unsafe extern "C" fn(*mut BIO, *const c_char, c_int) -> c_int>,
) -> c_int {
    BIO_meth_set_write(biom, write)
}
#[deprecated(note = "use BIO_meth_set_read instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_read__fixed_rust(
    biom: *mut BIO_METHOD,
    read: Option<unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int>,
) -> c_int {
    BIO_meth_set_read(biom, read)
}
#[deprecated(note = "use BIO_meth_set_puts instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_puts__fixed_rust(
    biom: *mut BIO_METHOD,
    puts: Option<unsafe extern "C" fn(*mut BIO, *const c_char) -> c_int>,
) -> c_int {
    BIO_meth_set_puts(biom, puts)
}
#[deprecated(note = "use BIO_meth_set_ctrl instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_ctrl__fixed_rust(
    biom: *mut BIO_METHOD,
    ctrl: Option<unsafe extern "C" fn(*mut BIO, c_int, c_long, *mut c_void) -> c_long>,
) -> c_int {
    BIO_meth_set_ctrl(biom, ctrl)
}
#[deprecated(note = "use BIO_meth_set_create instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_create__fixed_rust(
    biom: *mut BIO_METHOD,
    create: Option<unsafe extern "C" fn(*mut BIO) -> c_int>,
) -> c_int {
    BIO_meth_set_create(biom, create)
}
#[deprecated(note = "use BIO_meth_set_destroy instead")]
#[cfg(any(ossl110, libressl273))]
pub unsafe fn BIO_meth_set_destroy__fixed_rust(
    biom: *mut BIO_METHOD,
    destroy: Option<unsafe extern "C" fn(*mut BIO) -> c_int>,
) -> c_int {
    BIO_meth_set_destroy(biom, destroy)
}
