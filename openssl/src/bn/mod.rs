use libc::{c_int, c_ulong, c_void};
use std::ffi::{CStr, CString};
use std::cmp::Ordering;
use std::{fmt, ptr, mem};

use ffi;
use ssl::error::SslError;

/// A signed arbitrary-precision integer.
///
/// `BigNum` provides wrappers around OpenSSL's checked arithmetic functions. Additionally, it
/// implements the standard operators (`std::ops`), which perform unchecked arithmetic, unwrapping
/// the returned `Result` of the checked operations.
pub struct BigNum(*mut ffi::BIGNUM);

/// Specifies the desired properties of a randomly generated `BigNum`.
#[derive(Copy, Clone)]
#[repr(C)]
pub enum RNGProperty {
    /// The most significant bit of the number is allowed to be 0.
    MsbMaybeZero = -1,
    /// The MSB should be set to 1.
    MsbOne = 0,
    /// The two most significant bits of the number will be set to 1, so that the product of two
    /// such random numbers will always have `2 * bits` length.
    TwoMsbOne = 1,
}

macro_rules! with_ctx(
    ($name:ident, $action:block) => ({
        let $name = ffi::BN_CTX_new();
        if ($name).is_null() {
            Err(SslError::get())
        } else {
            let r = $action;
            ffi::BN_CTX_free($name);
            r
        }
    });
);

macro_rules! with_bn(
    ($name:ident, $action:block) => ({
        let tmp = BigNum::new();
        match tmp {
            Ok($name) => {
                if $action {
                    Ok($name)
                } else {
                    Err(SslError::get())
                }
            },
            Err(err) => Err(err),
        }
    });
);

macro_rules! with_bn_in_ctx(
    ($name:ident, $ctx_name:ident, $action:block) => ({
        let tmp = BigNum::new();
        match tmp {
            Ok($name) => {
                let $ctx_name = ffi::BN_CTX_new();
                if ($ctx_name).is_null() {
                    Err(SslError::get())
                } else {
                    let r =
                        if $action {
                            Ok($name)
                        } else {
                            Err(SslError::get())
                        };
                    ffi::BN_CTX_free($ctx_name);
                    r
                }
            },
            Err(err) => Err(err),
        }
    });
);

impl BigNum {
    /// Creates a new `BigNum` with the value 0.
    pub fn new() -> Result<BigNum, SslError> {
        unsafe {
            ffi::init();

            let v = try_ssl_null!(ffi::BN_new());
            Ok(BigNum(v))
        }
    }

    /// Creates a new `BigNum` with the given value.
    pub fn new_from(n: u64) -> Result<BigNum, SslError> {
        BigNum::new().and_then(|v| unsafe {
            try_ssl!(ffi::BN_set_word(v.raw(), n as c_ulong));
            Ok(v)
        })
    }

    /// Creates a `BigNum` from a decimal string.
    pub fn from_dec_str(s: &str) -> Result<BigNum, SslError> {
        BigNum::new().and_then(|v| unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            try_ssl!(ffi::BN_dec2bn(v.raw_ptr(), c_str.as_ptr() as *const _));
            Ok(v)
        })
    }

    /// Creates a `BigNum` from a hexadecimal string.
    pub fn from_hex_str(s: &str) -> Result<BigNum, SslError> {
        BigNum::new().and_then(|v| unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            try_ssl!(ffi::BN_hex2bn(v.raw_ptr(), c_str.as_ptr() as *const _));
            Ok(v)
        })
    }

    pub unsafe fn new_from_ffi(orig: *mut ffi::BIGNUM) -> Result<BigNum, SslError> {
        if orig.is_null() {
            panic!("Null Pointer was supplied to BigNum::new_from_ffi");
        }
        let r = ffi::BN_dup(orig);
        if r.is_null() {
            Err(SslError::get())
        } else {
            Ok(BigNum(r))
        }
    }

    /// Creates a new `BigNum` from an unsigned, big-endian encoded number of arbitrary length.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let bignum = BigNum::new_from_slice(&[0x12, 0x00, 0x34]).unwrap();
    ///
    /// assert_eq!(bignum, BigNum::new_from(0x120034).unwrap());
    /// ```
    pub fn new_from_slice(n: &[u8]) -> Result<BigNum, SslError> {
        BigNum::new().and_then(|v| unsafe {
            try_ssl_null!(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, v.raw()));
            Ok(v)
        })
    }

    /// Returns the square of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let ref n = BigNum::new_from(10).unwrap();
    /// let squared = BigNum::new_from(100).unwrap();
    ///
    /// assert_eq!(n.checked_sqr().unwrap(), squared);
    /// assert_eq!(n * n, squared);
    /// ```
    pub fn checked_sqr(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_sqr(r.raw(), self.raw(), ctx) == 1
            })
        }
    }

    /// Returns the unsigned remainder of the division `self / n`.
    pub fn checked_nnmod(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_nnmod(r.raw(), self.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Equivalent to `(self + a) mod n`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let ref s = BigNum::new_from(10).unwrap();
    /// let ref a = BigNum::new_from(20).unwrap();
    /// let ref n = BigNum::new_from(29).unwrap();
    /// let result = BigNum::new_from(1).unwrap();
    ///
    /// assert_eq!(s.checked_mod_add(a, n).unwrap(), result);
    /// ```
    pub fn checked_mod_add(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_add(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Equivalent to `(self - a) mod n`.
    pub fn checked_mod_sub(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_sub(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Equivalent to `(self * a) mod n`.
    pub fn checked_mod_mul(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_mul(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Equivalent to `self² mod n`.
    pub fn checked_mod_sqr(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_sqr(r.raw(), self.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Raises `self` to the `p`th power.
    pub fn checked_exp(&self, p: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_exp(r.raw(), self.raw(), p.raw(), ctx) == 1
            })
        }
    }

    /// Equivalent to `self.checked_exp(p) mod n`.
    pub fn checked_mod_exp(&self, p: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_exp(r.raw(), self.raw(), p.raw(), n.raw(), ctx) == 1
            })
        }
    }

    /// Calculates the modular multiplicative inverse of `self` modulo `n`, that is, an integer `r`
    /// such that `(self * r) % n == 1`.
    pub fn checked_mod_inv(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                !ffi::BN_mod_inverse(r.raw(), self.raw(), n.raw(), ctx).is_null()
            })
        }
    }

    /// Add an `unsigned long` to `self`. This is more efficient than adding a `BigNum`.
    pub fn add_word(&mut self, w: c_ulong) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_add_word(self.raw(), w) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn sub_word(&mut self, w: c_ulong) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_sub_word(self.raw(), w) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn mul_word(&mut self, w: c_ulong) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_mul_word(self.raw(), w) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn div_word(&mut self, w: c_ulong) -> Result<c_ulong, SslError> {
        unsafe {
            let result = ffi::BN_div_word(self.raw(), w);
            if result != !0 as c_ulong {
                Ok(result)
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn mod_word(&self, w: c_ulong) -> Result<c_ulong, SslError> {
        unsafe {
            let result = ffi::BN_mod_word(self.raw(), w);
            if result != !0 as c_ulong {
                Ok(result)
            } else {
                Err(SslError::get())
            }
        }
    }

    /// Computes the greatest common denominator of `self` and `a`.
    pub fn checked_gcd(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_gcd(r.raw(), self.raw(), a.raw(), ctx) == 1
            })
        }
    }

    /// Generates a prime number.
    ///
    /// # Parameters
    ///
    /// * `bits`: The length of the prime in bits (lower bound).
    /// * `safe`: If true, returns a "safe" prime `p` so that `(p-1)/2` is also prime.
    /// * `add`/`rem`: If `add` is set to `Some(add)`, `p % add == rem` will hold, where `p` is the
    ///   generated prime and `rem` is `1` if not specified (`None`).
    pub fn checked_generate_prime(bits: i32,
                                  safe: bool,
                                  add: Option<&BigNum>,
                                  rem: Option<&BigNum>)
                                  -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                let add_arg = add.map(|a| a.raw()).unwrap_or(ptr::null_mut());
                let rem_arg = rem.map(|r| r.raw()).unwrap_or(ptr::null_mut());

                ffi::BN_generate_prime_ex(r.raw(),
                                          bits as c_int,
                                          safe as c_int,
                                          add_arg,
                                          rem_arg,
                                          ptr::null()) == 1
            })
        }
    }

    /// Checks whether `self` is prime.
    ///
    /// Performs a Miller-Rabin probabilistic primality test with `checks` iterations.
    ///
    /// # Return Value
    ///
    /// Returns `true` if `self` is prime with an error probability of less than `0.25 ^ checks`.
    pub fn is_prime(&self, checks: i32) -> Result<bool, SslError> {
        unsafe {
            with_ctx!(ctx, {
                Ok(ffi::BN_is_prime_ex(self.raw(), checks as c_int, ctx, ptr::null()) == 1)
            })
        }
    }

    /// Checks whether `self` is prime with optional trial division.
    ///
    /// If `do_trial_division` is `true`, first performs trial division by a number of small primes.
    /// Then, like `is_prime`, performs a Miller-Rabin probabilistic primality test with `checks`
    /// iterations.
    ///
    /// # Return Value
    ///
    /// Returns `true` if `self` is prime with an error probability of less than `0.25 ^ checks`.
    pub fn is_prime_fast(&self, checks: i32, do_trial_division: bool) -> Result<bool, SslError> {
        unsafe {
            with_ctx!(ctx, {
                Ok(ffi::BN_is_prime_fasttest_ex(self.raw(),
                                                checks as c_int,
                                                ctx,
                                                do_trial_division as c_int,
                                                ptr::null()) == 1)
            })
        }
    }

    /// Generates a cryptographically strong pseudo-random `BigNum`.
    ///
    /// # Parameters
    ///
    /// * `bits`: Length of the number in bits.
    /// * `prop`: The desired properties of the number.
    /// * `odd`: If `true`, the generated number will be odd.
    pub fn checked_new_random(bits: i32, prop: RNGProperty, odd: bool) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_rand(r.raw(), bits as c_int, prop as c_int, odd as c_int) == 1
            })
        }
    }

    /// The cryptographically weak counterpart to `checked_new_random`.
    pub fn checked_new_pseudo_random(bits: i32,
                                     prop: RNGProperty,
                                     odd: bool)
                                     -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_pseudo_rand(r.raw(), bits as c_int, prop as c_int, odd as c_int) == 1
            })
        }
    }

    /// Generates a cryptographically strong pseudo-random `BigNum` `r` in the range
    /// `0 <= r < self`.
    pub fn checked_rand_in_range(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_rand_range(r.raw(), self.raw()) == 1
            })
        }
    }

    /// The cryptographically weak counterpart to `checked_rand_in_range`.
    pub fn checked_pseudo_rand_in_range(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_pseudo_rand_range(r.raw(), self.raw()) == 1
            })
        }
    }

    /// Sets bit `n`. Equivalent to `self |= (1 << n)`.
    ///
    /// When setting a bit outside of `self`, it is expanded.
    pub fn set_bit(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_set_bit(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    /// Clears bit `n`, setting it to 0. Equivalent to `self &= ~(1 << n)`.
    ///
    /// When clearing a bit outside of `self`, an error is returned.
    pub fn clear_bit(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_clear_bit(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    /// Returns `true` if the `n`th bit of `self` is set to 1, `false` otherwise.
    pub fn is_bit_set(&self, n: i32) -> bool {
        unsafe { ffi::BN_is_bit_set(self.raw(), n as c_int) == 1 }
    }

    /// Truncates `self` to the lowest `n` bits.
    ///
    /// An error occurs if `self` is already shorter than `n` bits.
    pub fn mask_bits(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if ffi::BN_mask_bits(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    /// Returns `self`, shifted left by 1 bit. `self` may be negative.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let ref s = BigNum::new_from(0b0100).unwrap();
    /// let result = BigNum::new_from(0b1000).unwrap();
    ///
    /// assert_eq!(s.checked_shl1().unwrap(), result);
    /// ```
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let ref s = -BigNum::new_from(8).unwrap();
    /// let result = -BigNum::new_from(16).unwrap();
    ///
    /// // (-8) << 1 == -16
    /// assert_eq!(s.checked_shl1().unwrap(), result);
    /// ```
    pub fn checked_shl1(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_lshift1(r.raw(), self.raw()) == 1
            })
        }
    }

    /// Returns `self`, shifted right by 1 bit. `self` may be negative.
    pub fn checked_shr1(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_rshift1(r.raw(), self.raw()) == 1
            })
        }
    }

    pub fn checked_add(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_add(r.raw(), self.raw(), a.raw()) == 1
            })
        }
    }

    pub fn checked_sub(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_sub(r.raw(), self.raw(), a.raw()) == 1
            })
        }
    }

    pub fn checked_mul(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mul(r.raw(), self.raw(), a.raw(), ctx) == 1
            })
        }
    }

    pub fn checked_div(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_div(r.raw(), ptr::null_mut(), self.raw(), a.raw(), ctx) == 1
            })
        }
    }

    pub fn checked_mod(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_div(ptr::null_mut(), r.raw(), self.raw(), a.raw(), ctx) == 1
            })
        }
    }

    pub fn checked_shl(&self, a: &i32) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_lshift(r.raw(), self.raw(), *a as c_int) == 1
            })
        }
    }

    pub fn checked_shr(&self, a: &i32) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, {
                ffi::BN_rshift(r.raw(), self.raw(), *a as c_int) == 1
            })
        }
    }

    /// Inverts the sign of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let mut s = BigNum::new_from(8).unwrap();
    ///
    /// s.negate();
    /// assert_eq!(s, -BigNum::new_from(8).unwrap());
    /// s.negate();
    /// assert_eq!(s, BigNum::new_from(8).unwrap());
    /// ```
    pub fn negate(&mut self) {
        unsafe { ffi::BN_set_negative(self.raw(), !self.is_negative() as c_int) }
    }

    /// Compare the absolute values of `self` and `oth`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// # use std::cmp::Ordering;
    /// let s = -BigNum::new_from(8).unwrap();
    /// let o = BigNum::new_from(8).unwrap();
    ///
    /// assert_eq!(s.abs_cmp(o), Ordering::Equal);
    /// ```
    pub fn abs_cmp(&self, oth: BigNum) -> Ordering {
        unsafe {
            let res = ffi::BN_ucmp(self.raw(), oth.raw()) as i32;
            if res < 0 {
                Ordering::Less
            } else if res > 0 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        unsafe { (*self.raw()).neg == 1 }
    }

    /// Returns the number of significant bits in `self`.
    pub fn num_bits(&self) -> i32 {
        unsafe { ffi::BN_num_bits(self.raw()) as i32 }
    }

    /// Returns the size of `self` in bytes.
    pub fn num_bytes(&self) -> i32 {
        (self.num_bits() + 7) / 8
    }

    pub unsafe fn raw(&self) -> *mut ffi::BIGNUM {
        let BigNum(n) = *self;
        n
    }

    pub unsafe fn raw_ptr(&self) -> *const *mut ffi::BIGNUM {
        let BigNum(ref n) = *self;
        n
    }

    pub fn into_raw(self) -> *mut ffi::BIGNUM {
        let mut me = self;
        mem::replace(&mut me.0, ptr::null_mut())
    }

    /// Returns a big-endian byte vector representation of the absolute value of `self`.
    ///
    /// `self` can be recreated by using `new_from_slice`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::new_from(4543).unwrap();
    /// let r = BigNum::new_from(4543).unwrap();
    ///
    /// let s_vec = s.to_vec();
    /// assert_eq!(BigNum::new_from_slice(&s_vec).unwrap(), r);
    /// ```
    pub fn to_vec(&self) -> Vec<u8> {
        let size = self.num_bytes() as usize;
        let mut v = Vec::with_capacity(size);
        unsafe {
            ffi::BN_bn2bin(self.raw(), v.as_mut_ptr());
            v.set_len(size);
        }
        v
    }

    /// Returns a decimal string representation of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::new_from(12345).unwrap();
    ///
    /// assert_eq!(s.to_dec_str(), "-12345");
    /// ```
    pub fn to_dec_str(&self) -> String {
        unsafe {
            let buf = ffi::BN_bn2dec(self.raw());
            assert!(!buf.is_null());
            let str = String::from_utf8(CStr::from_ptr(buf as *const _).to_bytes().to_vec())
                          .unwrap();
            ffi::CRYPTO_free(buf as *mut c_void);
            str
        }
    }

    /// Returns a hexadecimal string representation of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::new_from(0x99ff).unwrap();
    ///
    /// assert_eq!(s.to_hex_str(), "-99FF");
    /// ```
    pub fn to_hex_str(&self) -> String {
        unsafe {
            let buf = ffi::BN_bn2hex(self.raw());
            assert!(!buf.is_null());
            let str = String::from_utf8(CStr::from_ptr(buf as *const _).to_bytes().to_vec())
                          .unwrap();
            ffi::CRYPTO_free(buf as *mut c_void);
            str
        }
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl Eq for BigNum {}
impl PartialEq for BigNum {
    fn eq(&self, oth: &BigNum) -> bool {
        unsafe { ffi::BN_cmp(self.raw(), oth.raw()) == 0 }
    }
}

impl Ord for BigNum {
    fn cmp(&self, oth: &BigNum) -> Ordering {
        self.partial_cmp(oth).unwrap()
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        unsafe {
            let v = ffi::BN_cmp(self.raw(), oth.raw());
            let ret = if v == 0 {
                Ordering::Equal
            } else if v < 0 {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            Some(ret)
        }
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe {
            if !self.raw().is_null() {
                ffi::BN_clear_free(self.raw());
            }
        }
    }
}

#[doc(hidden)]      // This module only contains impls, so it's empty when generating docs
pub mod unchecked {
    use std::ops::{Add, Div, Mul, Neg, Rem, Shl, Shr, Sub};
    use ffi;
    use super::BigNum;

    impl<'a> Add<&'a BigNum> for &'a BigNum {
        type Output = BigNum;

        fn add(self, oth: &'a BigNum) -> BigNum {
            self.checked_add(oth).unwrap()
        }
    }

    impl<'a> Sub<&'a BigNum> for &'a BigNum {
        type Output = BigNum;

        fn sub(self, oth: &'a BigNum) -> BigNum {
            self.checked_sub(oth).unwrap()
        }
    }

    impl<'a> Mul<&'a BigNum> for &'a BigNum {
        type Output = BigNum;

        fn mul(self, oth: &'a BigNum) -> BigNum {
            self.checked_mul(oth).unwrap()
        }
    }

    impl<'a> Div<&'a BigNum> for &'a BigNum {
        type Output = BigNum;

        fn div(self, oth: &'a BigNum) -> BigNum {
            self.checked_div(oth).unwrap()
        }
    }

    impl<'a> Rem<&'a BigNum> for &'a BigNum {
        type Output = BigNum;

        fn rem(self, oth: &'a BigNum) -> BigNum {
            self.checked_mod(oth).unwrap()
        }
    }

    impl<'a> Shl<i32> for &'a BigNum {
        type Output = BigNum;

        fn shl(self, n: i32) -> BigNum {
            self.checked_shl(&n).unwrap()
        }
    }

    impl<'a> Shr<i32> for &'a BigNum {
        type Output = BigNum;

        fn shr(self, n: i32) -> BigNum {
            self.checked_shr(&n).unwrap()
        }
    }

    impl Clone for BigNum {
        fn clone(&self) -> BigNum {
            unsafe {
                let r = ffi::BN_dup(self.raw());
                if r.is_null() {
                    panic!("Unexpected null pointer from BN_dup(..)")
                } else {
                    BigNum(r)
                }
            }
        }
    }

    impl Neg for BigNum {
        type Output = BigNum;

        fn neg(self) -> BigNum {
            let mut n = self.clone();
            n.negate();
            n
        }
    }
}

#[cfg(test)]
mod tests {
    use bn::BigNum;

    #[test]
    fn test_to_from_slice() {
        let v0 = BigNum::new_from(10203004_u64).unwrap();
        let vec = v0.to_vec();
        let v1 = BigNum::new_from_slice(&vec).unwrap();

        assert!(v0 == v1);
    }

    #[test]
    fn test_negation() {
        let a = BigNum::new_from(909829283_u64).unwrap();

        assert!(!a.is_negative());
        assert!((-a).is_negative());
    }


    #[test]
    fn test_prime_numbers() {
        let a = BigNum::new_from(19029017_u64).unwrap();
        let p = BigNum::checked_generate_prime(128, true, None, Some(&a)).unwrap();

        assert!(p.is_prime(100).unwrap());
        assert!(p.is_prime_fast(100, true).unwrap());
    }
}
