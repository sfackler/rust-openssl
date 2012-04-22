import libc::{c_uchar, c_int};

#[link_name = "crypto"]
#[abi = "cdecl"]
native mod _native {
    fn RAND_bytes(buf: *c_uchar, num: c_int) -> c_int;
}

fn rand_bytes(len: uint) -> [u8] {
    let mut out = [];
    vec::reserve(out, len);

    vec::as_buf(out) { |out_buf|
        let r = _native::RAND_bytes(out_buf, len as c_int);
        if r != 1 as c_int { fail }

        unsafe { vec::unsafe::set_len(out, len); }
        out
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rand_bytes() {
        let _bytes = rand_bytes(5u);
    }
}
