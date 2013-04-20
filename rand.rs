use core::libc::c_int;

#[link_name = "crypto"]
#[abi = "cdecl"]
extern mod libcrypto {
    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
}

pub fn rand_bytes(len: uint) -> ~[u8] {
    let mut out = vec::with_capacity(len);

    do vec::as_mut_buf(out) |out_buf, len| {
        unsafe {
            let r = libcrypto::RAND_bytes(out_buf, len as c_int);
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
        io::println(fmt!("%?", bytes));
    }
}
