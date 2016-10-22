use libc::size_t;
use ffi;

/// Returns `true` iff `a` and `b` contain the same bytes.
///
/// This operation takes an amount of time dependent on the length of the two
/// arrays given, but is independent of the contents of a and b.
///
/// # Failure
///
/// This function will panic the current task if `a` and `b` do not have the same
/// length.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    assert!(a.len() == b.len());
    let ret = unsafe {
        ffi::CRYPTO_memcmp(a.as_ptr() as *const _,
                           b.as_ptr() as *const _,
                           a.len() as size_t)
    };
    ret == 0
}

#[cfg(test)]
mod tests {
    use super::eq;

    #[test]
    fn test_eq() {
        assert!(eq(&[], &[]));
        assert!(eq(&[1], &[1]));
        assert!(!eq(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    #[should_panic]
    fn test_diff_lens() {
        eq(&[], &[1]);
    }
}
