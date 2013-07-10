use std::libc::c_int;
use std::vec;

#[link_args = "-lcrypto"]
#[abi = "cdecl"]
extern {
    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
}

pub fn rand_bytes(len: uint) -> ~[u8] {
    let mut out = vec::with_capacity(len);

    do out.as_mut_buf |out_buf, len| {
        unsafe {
            let r = RAND_bytes(out_buf, len as c_int);
            if r != 1 as c_int { fail!() }
        }
    }

    unsafe { vec::raw::set_len(&mut out, len); }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_bytes() {
        let bytes = rand_bytes(32u);
        println(fmt!("%?", bytes));
    }
}
