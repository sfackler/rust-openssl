use libc::*;

extern "C" {
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    pub fn RAND_status() -> c_int;
}
