use libc::c_int;
use ffi;

pub fn rand_bytes(len: usize) -> Vec<u8> {
    unsafe {
        let mut out = Vec::with_capacity(len);

        ffi::init();
        let r = ffi::RAND_bytes(out.as_mut_ptr(), len as c_int);
        if r != 1 as c_int { panic!() }

        out.set_len(len);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let bytes = rand_bytes(32);
        println!("{:?}", bytes);
    }
}
