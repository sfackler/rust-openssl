use libc::{c_int, c_void};
use std::ffi::{CStr, CString};
use std::cmp::Ordering;
use std::{fmt, ptr};
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Rem, Shl, Shr, Sub, Deref, DerefMut};

use ffi;
use error::ErrorStack;

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
            Err(ErrorStack::get())
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
                    Err(ErrorStack::get())
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
                    Err(ErrorStack::get())
                } else {
                    let r =
                        if $action {
                            Ok($name)
                        } else {
                            Err(ErrorStack::get())
                        };
                    ffi::BN_CTX_free($ctx_name);
                    r
                }
            },
            Err(err) => Err(err),
        }
    });
);

/// A borrowed, signed, arbitrary-precision integer.
#[derive(Copy, Clone)]
pub struct BigNumRef<'a>(*mut ffi::BIGNUM, PhantomData<&'a ()>);


impl<'a> BigNumRef<'a> {
    pub unsafe fn from_ptr(handle: *mut ffi::BIGNUM) -> BigNumRef<'a> {
        BigNumRef(handle, PhantomData)
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
    pub fn checked_sqr(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_sqr(r.as_ptr(), self.as_ptr(), ctx) == 1
            })
        }
    }

    /// Returns the unsigned remainder of the division `self / n`.
    pub fn checked_nnmod(&self, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_nnmod(r.as_ptr(), self.as_ptr(), n.as_ptr(), ctx) == 1
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
    pub fn checked_mod_add(&self, a: &BigNumRef, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_add(r.as_ptr(), self.as_ptr(), a.as_ptr(), n.as_ptr(), ctx) == 1
            })
        }
    }

    /// Equivalent to `(self - a) mod n`.
    pub fn checked_mod_sub(&self, a: &BigNumRef, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_sub(r.as_ptr(), self.as_ptr(), a.as_ptr(), n.as_ptr(), ctx) == 1
            })
        }
    }

    /// Equivalent to `(self * a) mod n`.
    pub fn checked_mod_mul(&self, a: &BigNumRef, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_mul(r.as_ptr(), self.as_ptr(), a.as_ptr(), n.as_ptr(), ctx) == 1
            })
        }
    }

    /// Equivalent to `self² mod n`.
    pub fn checked_mod_sqr(&self, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_sqr(r.as_ptr(), self.as_ptr(), n.as_ptr(), ctx) == 1
            })
        }
    }

    /// Raises `self` to the `p`th power.
    pub fn checked_exp(&self, p: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_exp(r.as_ptr(), self.as_ptr(), p.as_ptr(), ctx) == 1
            })
        }
    }

    /// Equivalent to `self.checked_exp(p) mod n`.
    pub fn checked_mod_exp(&self, p: &BigNumRef, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mod_exp(r.as_ptr(), self.as_ptr(), p.as_ptr(), n.as_ptr(), ctx) == 1
            })
        }
    }

    /// Calculates the modular multiplicative inverse of `self` modulo `n`, that is, an integer `r`
    /// such that `(self * r) % n == 1`.
    pub fn checked_mod_inv(&self, n: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                !ffi::BN_mod_inverse(r.as_ptr(), self.as_ptr(), n.as_ptr(), ctx).is_null()
            })
        }
    }

    /// Add a `u32` to `self`. This is more efficient than adding a
    /// `BigNum`.
    pub fn add_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_add_word(self.as_ptr(), w as ffi::BN_ULONG) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn sub_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_sub_word(self.as_ptr(), w as ffi::BN_ULONG) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn mul_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_mul_word(self.as_ptr(), w as ffi::BN_ULONG) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn div_word(&mut self, w: u32) -> Result<u64, ErrorStack> {
        unsafe {
            let result = ffi::BN_div_word(self.as_ptr(), w as ffi::BN_ULONG);
            if result != !0 {
                Ok(result.into())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    pub fn mod_word(&self, w: u32) -> Result<u64, ErrorStack> {
        unsafe {
            let result = ffi::BN_mod_word(self.as_ptr(), w as ffi::BN_ULONG);
            if result != !0 {
                Ok(result as u64)
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Computes the greatest common denominator of `self` and `a`.
    pub fn checked_gcd(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_gcd(r.as_ptr(), self.as_ptr(), a.as_ptr(), ctx) == 1
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
    pub fn is_prime(&self, checks: i32) -> Result<bool, ErrorStack> {
        unsafe {
            with_ctx!(ctx, {
                Ok(ffi::BN_is_prime_ex(self.as_ptr(),
                                       checks as c_int,
                                       ctx,
                                       ptr::null_mut()) == 1)
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
    pub fn is_prime_fast(&self, checks: i32, do_trial_division: bool) -> Result<bool, ErrorStack> {
        unsafe {
            with_ctx!(ctx, {
                Ok(ffi::BN_is_prime_fasttest_ex(self.as_ptr(),
                                                checks as c_int,
                                                ctx,
                                                do_trial_division as c_int,
                                                ptr::null_mut()) == 1)
            })
        }
    }

    /// Generates a cryptographically strong pseudo-random `BigNum` `r` in the range
    /// `0 <= r < self`.
    pub fn checked_rand_in_range(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_rand_range(r.as_ptr(), self.as_ptr()) == 1
            })
        }
    }

    /// The cryptographically weak counterpart to `checked_rand_in_range`.
    pub fn checked_pseudo_rand_in_range(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_pseudo_rand_range(r.as_ptr(), self.as_ptr()) == 1
            })
        }
    }

    /// Sets bit `n`. Equivalent to `self |= (1 << n)`.
    ///
    /// When setting a bit outside of `self`, it is expanded.
    pub fn set_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_set_bit(self.as_ptr(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Clears bit `n`, setting it to 0. Equivalent to `self &= ~(1 << n)`.
    ///
    /// When clearing a bit outside of `self`, an error is returned.
    pub fn clear_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_clear_bit(self.as_ptr(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Returns `true` if the `n`th bit of `self` is set to 1, `false` otherwise.
    pub fn is_bit_set(&self, n: i32) -> bool {
        unsafe { ffi::BN_is_bit_set(self.as_ptr(), n as c_int) == 1 }
    }

    /// Truncates `self` to the lowest `n` bits.
    ///
    /// An error occurs if `self` is already shorter than `n` bits.
    pub fn mask_bits(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::BN_mask_bits(self.as_ptr(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
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
    pub fn checked_shl1(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_lshift1(r.as_ptr(), self.as_ptr()) == 1
            })
        }
    }

    /// Returns `self`, shifted right by 1 bit. `self` may be negative.
    pub fn checked_shr1(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_rshift1(r.as_ptr(), self.as_ptr()) == 1
            })
        }
    }

    pub fn checked_add(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_add(r.as_ptr(), self.as_ptr(), a.as_ptr()) == 1
            })
        }
    }

    pub fn checked_sub(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_sub(r.as_ptr(), self.as_ptr(), a.as_ptr()) == 1
            })
        }
    }

    pub fn checked_mul(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_mul(r.as_ptr(), self.as_ptr(), a.as_ptr(), ctx) == 1
            })
        }
    }

    pub fn checked_div(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_div(r.as_ptr(), ptr::null_mut(), self.as_ptr(), a.as_ptr(), ctx) == 1
            })
        }
    }

    pub fn checked_mod(&self, a: &BigNumRef) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_div(ptr::null_mut(), r.as_ptr(), self.as_ptr(), a.as_ptr(), ctx) == 1
            })
        }
    }

    pub fn checked_shl(&self, a: &i32) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_lshift(r.as_ptr(), self.as_ptr(), *a as c_int) == 1
            })
        }
    }

    pub fn checked_shr(&self, a: &i32) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn!(r, {
                ffi::BN_rshift(r.as_ptr(), self.as_ptr(), *a as c_int) == 1
            })
        }
    }

    pub fn to_owned(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            let r = try_ssl_null!(ffi::BN_dup(self.as_ptr()));
            Ok(BigNum::from_ptr(r))
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
        unsafe { ffi::BN_set_negative(self.as_ptr(), !self.is_negative() as c_int) }
    }

    /// Compare the absolute values of `self` and `oth`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// # use std::cmp::Ordering;
    /// let s = -BigNum::new_from(8).unwrap();
    /// let o = BigNum::new_from(8).unwrap();
    ///
    /// assert_eq!(s.abs_cmp(&o), Ordering::Equal);
    /// ```
    pub fn abs_cmp(&self, oth: &BigNumRef) -> Ordering {
        unsafe {
            let res = ffi::BN_ucmp(self.as_ptr(), oth.as_ptr()) as i32;
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
        self._is_negative()
    }

    #[cfg(ossl10x)]
    fn _is_negative(&self) -> bool {
        unsafe { (*self.as_ptr()).neg == 1 }
    }

    #[cfg(ossl110)]
    fn _is_negative(&self) -> bool {
        unsafe { ffi::BN_is_negative(self.as_ptr()) == 1 }
    }

    /// Returns the number of significant bits in `self`.
    pub fn num_bits(&self) -> i32 {
        unsafe { ffi::BN_num_bits(self.as_ptr()) as i32 }
    }

    /// Returns the size of `self` in bytes.
    pub fn num_bytes(&self) -> i32 {
        (self.num_bits() + 7) / 8
    }

    pub fn as_ptr(&self) -> *mut ffi::BIGNUM {
        self.0
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
            ffi::BN_bn2bin(self.as_ptr(), v.as_mut_ptr());
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
            let buf = ffi::BN_bn2dec(self.as_ptr());
            assert!(!buf.is_null());
            let str = String::from_utf8(CStr::from_ptr(buf as *const _).to_bytes().to_vec())
                          .unwrap();
            CRYPTO_free!(buf as *mut c_void);
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
            let buf = ffi::BN_bn2hex(self.as_ptr());
            assert!(!buf.is_null());
            let str = String::from_utf8(CStr::from_ptr(buf as *const _).to_bytes().to_vec())
                          .unwrap();
            CRYPTO_free!(buf as *mut c_void);
            str
        }
    }
}

/// An owned, signed, arbitrary-precision integer.
///
/// `BigNum` provides wrappers around OpenSSL's checked arithmetic functions.
/// Additionally, it implements the standard operators (`std::ops`), which
/// perform unchecked arithmetic, unwrapping the returned `Result` of the
/// checked operations.
pub struct BigNum(BigNumRef<'static>);

impl BigNum {
    /// Creates a new `BigNum` with the value 0.
    pub fn new() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            let v = try_ssl_null!(ffi::BN_new());
            Ok(BigNum::from_ptr(v))
        }
    }

    /// Creates a new `BigNum` with the given value.
    pub fn new_from(n: u32) -> Result<BigNum, ErrorStack> {
        BigNum::new().and_then(|v| unsafe {
            try_ssl!(ffi::BN_set_word(v.as_ptr(), n as ffi::BN_ULONG));
            Ok(v)
        })
    }

    /// Creates a `BigNum` from a decimal string.
    pub fn from_dec_str(s: &str) -> Result<BigNum, ErrorStack> {
        BigNum::new().and_then(|mut v| unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            try_ssl!(ffi::BN_dec2bn(&mut (v.0).0, c_str.as_ptr() as *const _));
            Ok(v)
        })
    }

    /// Creates a `BigNum` from a hexadecimal string.
    pub fn from_hex_str(s: &str) -> Result<BigNum, ErrorStack> {
        BigNum::new().and_then(|mut v| unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            try_ssl!(ffi::BN_hex2bn(&mut (v.0).0, c_str.as_ptr() as *const _));
            Ok(v)
        })
    }

    pub unsafe fn from_ptr(handle: *mut ffi::BIGNUM) -> BigNum {
        BigNum(BigNumRef::from_ptr(handle))
    }

    /// Creates a new `BigNum` from an unsigned, big-endian encoded number of arbitrary length.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let bignum = BigNum::new_from_slice(&[0x12, 0x00, 0x34]).unwrap();
    ///
    /// assert_eq!(bignum, BigNum::new_from(0x120034).unwrap());
    /// ```
    pub fn new_from_slice(n: &[u8]) -> Result<BigNum, ErrorStack> {
        BigNum::new().and_then(|v| unsafe {
            try_ssl_null!(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, v.as_ptr()));
            Ok(v)
        })
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
                                  -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                let add_arg = add.map(|a| a.as_ptr()).unwrap_or(ptr::null_mut());
                let rem_arg = rem.map(|r| r.as_ptr()).unwrap_or(ptr::null_mut());

                ffi::BN_generate_prime_ex(r.as_ptr(),
                                          bits as c_int,
                                          safe as c_int,
                                          add_arg,
                                          rem_arg,
                                          ptr::null_mut()) == 1
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
    pub fn checked_new_random(bits: i32, prop: RNGProperty, odd: bool) -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_rand(r.as_ptr(), bits as c_int, prop as c_int, odd as c_int) == 1
            })
        }
    }

    /// The cryptographically weak counterpart to `checked_new_random`.
    pub fn checked_new_pseudo_random(bits: i32,
                                     prop: RNGProperty,
                                     odd: bool)
                                     -> Result<BigNum, ErrorStack> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                ffi::BN_pseudo_rand(r.as_ptr(), bits as c_int, prop as c_int, odd as c_int) == 1
            })
        }
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe { ffi::BN_clear_free(self.as_ptr()); }
    }
}

impl Deref for BigNum {
    type Target = BigNumRef<'static>;

    fn deref(&self) -> &BigNumRef<'static> {
        &self.0
    }
}

impl DerefMut for BigNum {
    fn deref_mut(&mut self) -> &mut BigNumRef<'static> {
        &mut self.0
    }
}

impl AsRef<BigNumRef<'static>> for BigNum {
    fn as_ref(&self) -> &BigNumRef<'static> {
        self.deref()
    }
}

impl<'a> fmt::Debug for BigNumRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl<'a> fmt::Display for BigNumRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl<'a, 'b> PartialEq<BigNumRef<'b>> for BigNumRef<'a> {
    fn eq(&self, oth: &BigNumRef) -> bool {
        unsafe { ffi::BN_cmp(self.as_ptr(), oth.as_ptr()) == 0 }
    }
}

impl<'a> PartialEq<BigNum> for BigNumRef<'a> {
    fn eq(&self, oth: &BigNum) -> bool {
        self.eq(oth.deref())
    }
}

impl<'a> Eq for BigNumRef<'a> {}

impl PartialEq for BigNum {
    fn eq(&self, oth: &BigNum) -> bool {
        self.deref().eq(oth)
    }
}

impl<'a> PartialEq<BigNumRef<'a>> for BigNum {
    fn eq(&self, oth: &BigNumRef) -> bool {
        self.deref().eq(oth)
    }
}

impl Eq for BigNum {}

impl<'a, 'b> PartialOrd<BigNumRef<'b>> for BigNumRef<'a> {
    fn partial_cmp(&self, oth: &BigNumRef) -> Option<Ordering> {
        Some(self.cmp(oth))
    }
}

impl<'a> PartialOrd<BigNum> for BigNumRef<'a> {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        Some(self.cmp(oth.deref()))
    }
}

impl<'a> Ord for BigNumRef<'a> {
    fn cmp(&self, oth: &BigNumRef) -> Ordering {
        unsafe { ffi::BN_cmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        self.deref().partial_cmp(oth.deref())
    }
}

impl<'a> PartialOrd<BigNumRef<'a>> for BigNum {
    fn partial_cmp(&self, oth: &BigNumRef) -> Option<Ordering> {
        self.deref().partial_cmp(oth)
    }
}

impl Ord for BigNum {
    fn cmp(&self, oth: &BigNum) -> Ordering {
        self.deref().cmp(oth.deref())
    }
}

impl<'a, 'b> Add<&'b BigNumRef<'b>> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn add(self, oth: &BigNumRef) -> BigNum {
        self.checked_add(oth).unwrap()
    }
}

impl<'a, 'b> Sub<&'b BigNumRef<'b>> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn sub(self, oth: &BigNumRef) -> BigNum {
        self.checked_sub(oth).unwrap()
    }
}

impl<'a, 'b> Sub<&'b BigNum> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn sub(self, oth: &BigNum) -> BigNum {
        self.checked_sub(oth).unwrap()
    }
}

impl<'a, 'b> Sub<&'b BigNum> for &'a BigNum {
    type Output = BigNum;

    fn sub(self, oth: &BigNum) -> BigNum {
        self.checked_sub(oth).unwrap()
    }
}

impl<'a, 'b> Sub<&'b BigNumRef<'b>> for &'a BigNum {
    type Output = BigNum;

    fn sub(self, oth: &BigNumRef) -> BigNum {
        self.checked_sub(oth).unwrap()
    }
}

impl<'a, 'b> Mul<&'b BigNumRef<'b>> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn mul(self, oth: &BigNumRef) -> BigNum {
        self.checked_mul(oth).unwrap()
    }
}

impl<'a, 'b> Mul<&'b BigNum> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn mul(self, oth: &BigNum) -> BigNum {
        self.checked_mul(oth).unwrap()
    }
}

impl<'a, 'b> Mul<&'b BigNum> for &'a BigNum {
    type Output = BigNum;

    fn mul(self, oth: &BigNum) -> BigNum {
        self.checked_mul(oth).unwrap()
    }
}

impl<'a, 'b> Mul<&'b BigNumRef<'b>> for &'a BigNum {
    type Output = BigNum;

    fn mul(self, oth: &BigNumRef) -> BigNum {
        self.checked_mul(oth).unwrap()
    }
}

impl<'a, 'b> Div<&'b BigNumRef<'b>> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn div(self, oth: &'b BigNumRef<'b>) -> BigNum {
        self.checked_div(oth).unwrap()
    }
}

impl<'a, 'b> Div<&'b BigNum> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn div(self, oth: &'b BigNum) -> BigNum {
        self.checked_div(oth).unwrap()
    }
}

impl<'a, 'b> Div<&'b BigNum> for &'a BigNum {
    type Output = BigNum;

    fn div(self, oth: &'b BigNum) -> BigNum {
        self.checked_div(oth).unwrap()
    }
}

impl<'a, 'b> Div<&'b BigNumRef<'b>> for &'a BigNum {
    type Output = BigNum;

    fn div(self, oth: &'b BigNumRef<'b>) -> BigNum {
        self.checked_div(oth).unwrap()
    }
}

impl<'a, 'b> Rem<&'b BigNumRef<'b>> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn rem(self, oth: &'b BigNumRef<'b>) -> BigNum {
        self.checked_mod(oth).unwrap()
    }
}

impl<'a, 'b> Rem<&'b BigNum> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn rem(self, oth: &'b BigNum) -> BigNum {
        self.checked_mod(oth).unwrap()
    }
}

impl<'a, 'b> Rem<&'b BigNumRef<'b>> for &'a BigNum {
    type Output = BigNum;

    fn rem(self, oth: &'b BigNumRef<'b>) -> BigNum {
        self.checked_mod(oth).unwrap()
    }
}

impl<'a, 'b> Rem<&'b BigNum> for &'a BigNum {
    type Output = BigNum;

    fn rem(self, oth: &'b BigNum) -> BigNum {
        self.checked_mod(oth).unwrap()
    }
}

impl<'a> Shl<i32> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        self.checked_shl(&n).unwrap()
    }
}

impl<'a> Shl<i32> for &'a BigNum {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        self.checked_shl(&n).unwrap()
    }
}

impl<'a> Shr<i32> for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        self.checked_shr(&n).unwrap()
    }
}

impl<'a> Shr<i32> for &'a BigNum {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        self.checked_shr(&n).unwrap()
    }
}

impl<'a> Neg for &'a BigNumRef<'a> {
    type Output = BigNum;

    fn neg(self) -> BigNum {
        let mut n = self.to_owned().unwrap();
        n.negate();
        n
    }
}

impl<'a> Neg for &'a BigNum {
    type Output = BigNum;

    fn neg(self) -> BigNum {
        let mut n = self.deref().to_owned().unwrap();
        n.negate();
        n
    }
}

impl Neg for BigNum {
    type Output = BigNum;

    fn neg(mut self) -> BigNum {
        self.negate();
        self
    }
}

#[cfg(test)]
mod tests {
    use bn::BigNum;

    #[test]
    fn test_to_from_slice() {
        let v0 = BigNum::new_from(10203004).unwrap();
        let vec = v0.to_vec();
        let v1 = BigNum::new_from_slice(&vec).unwrap();

        assert!(v0 == v1);
    }

    #[test]
    fn test_negation() {
        let a = BigNum::new_from(909829283).unwrap();

        assert!(!a.is_negative());
        assert!((-a).is_negative());
    }


    #[test]
    fn test_prime_numbers() {
        let a = BigNum::new_from(19029017).unwrap();
        let p = BigNum::checked_generate_prime(128, true, None, Some(&a)).unwrap();

        assert!(p.is_prime(100).unwrap());
        assert!(p.is_prime_fast(100, true).unwrap());
    }
}
