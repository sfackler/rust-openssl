use libc::c_int;
use ffi;
use error::ErrorStack;

pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        assert!(buf.len() <= c_int::max_value() as usize);
        try_ssl_if!(ffi::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int) != 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).unwrap();
    }
}
