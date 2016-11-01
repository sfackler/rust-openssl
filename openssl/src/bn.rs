use ffi;
use libc::c_int;
use std::cmp::Ordering;
use std::ffi::CString;
use std::{fmt, ptr};
use std::ops::{Add, Div, Mul, Neg, Rem, Shl, Shr, Sub, Deref};

use {cvt, cvt_p, cvt_n};
use crypto::CryptoString;
use error::ErrorStack;
use types::{Ref, OpenSslType};

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

type_!(BnCtx, ffi::BN_CTX, ffi::BN_CTX_free);

impl BnCtx {
    /// Returns a new `BnCtx`.
    pub fn new() -> Result<BnCtx, ErrorStack> {
        unsafe { cvt_p(ffi::BN_CTX_new()).map(BnCtx) }
    }

    /// Places the result of `a * b` in `r`.
    pub fn mul(&mut self,
               r: &mut Ref<BigNum>,
               a: &Ref<BigNum>,
               b: &Ref<BigNum>)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_mul(r.as_ptr(), a.as_ptr(), b.as_ptr(), self.as_ptr())).map(|_| ()) }
    }

    /// Places the result of `a / b` in `dv` and `a mod b` in `rem`.
    pub fn div(&mut self,
               dv: Option<&mut Ref<BigNum>>,
               rem: Option<&mut Ref<BigNum>>,
               a: &Ref<BigNum>,
               b: &Ref<BigNum>)
               -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_div(dv.map(|b| b.as_ptr()).unwrap_or(ptr::null_mut()),
                            rem.map(|b| b.as_ptr()).unwrap_or(ptr::null_mut()),
                            a.as_ptr(),
                            b.as_ptr(),
                            self.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a²` in `r`.
    pub fn sqr(&mut self, r: &mut Ref<BigNum>, a: &Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_sqr(r.as_ptr(), a.as_ptr(), self.as_ptr())).map(|_| ()) }
    }

    /// Places the result of `a mod m` in `r`.
    pub fn nnmod(&mut self,
                 r: &mut Ref<BigNum>,
                 a: &Ref<BigNum>,
                 m: &Ref<BigNum>)
                 -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_nnmod(r.as_ptr(), a.as_ptr(), m.as_ptr(), self.0)).map(|_| ()) }
    }

    /// Places the result of `(a + b) mod m` in `r`.
    pub fn mod_add(&mut self,
                   r: &mut Ref<BigNum>,
                   a: &Ref<BigNum>,
                   b: &Ref<BigNum>,
                   m: &Ref<BigNum>)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_add(r.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), self.0)).map(|_| ())
        }
    }

    /// Places the result of `(a - b) mod m` in `r`.
    pub fn mod_sub(&mut self,
                   r: &mut Ref<BigNum>,
                   a: &Ref<BigNum>,
                   b: &Ref<BigNum>,
                   m: &Ref<BigNum>)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_sub(r.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), self.0)).map(|_| ())
        }
    }

    /// Places the result of `(a * b) mod m` in `r`.
    pub fn mod_mul(&mut self,
                   r: &mut Ref<BigNum>,
                   a: &Ref<BigNum>,
                   b: &Ref<BigNum>,
                   m: &Ref<BigNum>)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_mul(r.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), self.0)).map(|_| ())
        }
    }

    /// Places the result of `a² mod m` in `r`.
    pub fn mod_sqr(&mut self,
                   r: &mut Ref<BigNum>,
                   a: &Ref<BigNum>,
                   m: &Ref<BigNum>)
                   -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_mod_sqr(r.as_ptr(), a.as_ptr(), m.as_ptr(), self.0)).map(|_| ()) }
    }

    /// Places the result of `a^p` in `r`.
    pub fn exp(&mut self,
               r: &mut Ref<BigNum>,
               a: &Ref<BigNum>,
               p: &Ref<BigNum>)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_exp(r.as_ptr(), a.as_ptr(), p.as_ptr(), self.0)).map(|_| ()) }
    }

    /// Places the result of `a^p mod m` in `r`.
    pub fn mod_exp(&mut self,
                   r: &mut Ref<BigNum>,
                   a: &Ref<BigNum>,
                   p: &Ref<BigNum>,
                   m: &Ref<BigNum>)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_exp(r.as_ptr(), a.as_ptr(), p.as_ptr(), m.as_ptr(), self.0)).map(|_| ())
        }
    }

    /// Places the inverse of `a` modulo `n` in `r`.
    pub fn mod_inverse(&mut self,
                       r: &mut Ref<BigNum>,
                       a: &Ref<BigNum>,
                       n: &Ref<BigNum>)
                       -> Result<(), ErrorStack> {
        unsafe {
            cvt_p(ffi::BN_mod_inverse(r.as_ptr(), a.as_ptr(), n.as_ptr(), self.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the greatest common denominator of `a` and `b` in `r`.
    pub fn gcd(&mut self,
               r: &mut Ref<BigNum>,
               a: &Ref<BigNum>,
               b: &Ref<BigNum>)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_gcd(r.as_ptr(), a.as_ptr(), b.as_ptr(), self.as_ptr())).map(|_| ()) }
    }

    /// Checks whether `p` is prime.
    ///
    /// Performs a Miller-Rabin probabilistic primality test with `checks` iterations.
    ///
    /// Returns `true` if `p` is prime with an error probability of less than `0.25 ^ checks`.
    pub fn is_prime(&mut self, p: &Ref<BigNum>, checks: i32) -> Result<bool, ErrorStack> {
        unsafe {
            cvt_n(ffi::BN_is_prime_ex(p.as_ptr(), checks.into(), self.as_ptr(), ptr::null_mut()))
                .map(|r| r != 0)
        }
    }

    /// Checks whether `p` is prime with optional trial division.
    ///
    /// If `do_trial_division` is `true`, first performs trial division by a number of small primes.
    /// Then, like `is_prime`, performs a Miller-Rabin probabilistic primality test with `checks`
    /// iterations.
    ///
    /// # Return Value
    ///
    /// Returns `true` if `p` is prime with an error probability of less than `0.25 ^ checks`.
    pub fn is_prime_fasttest(&mut self,
                             p: &Ref<BigNum>,
                             checks: i32,
                             do_trial_division: bool)
                             -> Result<bool, ErrorStack> {
        unsafe {
            cvt_n(ffi::BN_is_prime_fasttest_ex(p.as_ptr(),
                                               checks.into(),
                                               self.as_ptr(),
                                               do_trial_division as c_int,
                                               ptr::null_mut()))
                .map(|r| r != 0)
        }
    }

    /// Generates a cryptographically strong pseudo-random `BigNum`, placing it in `r`.
    ///
    /// # Parameters
    ///
    /// * `bits`: Length of the number in bits.
    /// * `prop`: The desired properties of the number.
    /// * `odd`: If `true`, the generated number will be odd.
    pub fn rand(r: &mut Ref<BigNum>,
                bits: i32,
                prop: RNGProperty,
                odd: bool)
                -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_rand(r.as_ptr(), bits.into(), prop as c_int, odd as c_int)).map(|_| ())
        }
    }

    /// The cryptographically weak counterpart to `checked_new_random`.
    pub fn pseudo_rand(r: &mut Ref<BigNum>,
                       bits: i32,
                       prop: RNGProperty,
                       odd: bool)
                       -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_pseudo_rand(r.as_ptr(), bits.into(), prop as c_int, odd as c_int))
                .map(|_| ())
        }
    }
}

impl Ref<BigNum> {
    /// Adds a `u32` to `self`.
    pub fn add_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_add_word(self.as_ptr(), w as ffi::BN_ULONG)).map(|_| ()) }
    }

    /// Subtracts a `u32` from `self`.
    pub fn sub_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_sub_word(self.as_ptr(), w as ffi::BN_ULONG)).map(|_| ()) }
    }

    /// Multiplies a `u32` by `self`.
    pub fn mul_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_mul_word(self.as_ptr(), w as ffi::BN_ULONG)).map(|_| ()) }
    }

    /// Divides `self` by a `u32`, returning the remainder.
    pub fn div_word(&mut self, w: u32) -> Result<u64, ErrorStack> {
        unsafe {
            let r = ffi::BN_div_word(self.as_ptr(), w.into());
            if r == ffi::BN_ULONG::max_value() {
                Err(ErrorStack::get())
            } else {
                Ok(r.into())
            }
        }
    }

    /// Returns the result of `self` modulo `w`.
    pub fn mod_word(&self, w: u32) -> Result<u64, ErrorStack> {
        unsafe {
            let r = ffi::BN_mod_word(self.as_ptr(), w.into());
            if r == ffi::BN_ULONG::max_value() {
                Err(ErrorStack::get())
            } else {
                Ok(r.into())
            }
        }
    }

    /// Places a cryptographically-secure pseudo-random number nonnegative
    /// number less than `self` in `rnd`.
    pub fn rand_in_range(&self, rnd: &mut Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rand_range(self.as_ptr(), rnd.as_ptr())).map(|_| ()) }
    }

    /// The cryptographically weak counterpart to `rand_in_range`.
    pub fn pseudo_rand_in_range(&self, rnd: &mut Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_pseudo_rand_range(self.as_ptr(), rnd.as_ptr())).map(|_| ()) }
    }

    /// Sets bit `n`. Equivalent to `self |= (1 << n)`.
    ///
    /// When setting a bit outside of `self`, it is expanded.
    pub fn set_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_set_bit(self.as_ptr(), n.into())).map(|_| ()) }
    }

    /// Clears bit `n`, setting it to 0. Equivalent to `self &= ~(1 << n)`.
    ///
    /// When clearing a bit outside of `self`, an error is returned.
    pub fn clear_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_clear_bit(self.as_ptr(), n.into())).map(|_| ()) }
    }

    /// Returns `true` if the `n`th bit of `self` is set to 1, `false` otherwise.
    pub fn is_bit_set(&self, n: i32) -> bool {
        unsafe { ffi::BN_is_bit_set(self.as_ptr(), n.into()) == 1 }
    }

    /// Truncates `self` to the lowest `n` bits.
    ///
    /// An error occurs if `self` is already shorter than `n` bits.
    pub fn mask_bits(&mut self, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_mask_bits(self.as_ptr(), n.into())).map(|_| ()) }
    }

    /// Places `self << 1` in `r`.
    pub fn lshift1(&self, r: &mut Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_lshift1(r.as_ptr(), self.as_ptr())).map(|_| ()) }
    }

    /// Places `self >> 1` in `r`.
    pub fn rshift1(&self, r: &mut Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rshift1(r.as_ptr(), self.as_ptr())).map(|_| ()) }
    }

    /// Places `self + b` in `r`.
    pub fn add(&self, r: &mut Ref<BigNum>, b: &Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_add(r.as_ptr(), self.as_ptr(), b.as_ptr())).map(|_| ()) }
    }

    /// Places `self - b` in `r`.
    pub fn sub(&self, r: &mut Ref<BigNum>, b: &Ref<BigNum>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_sub(r.as_ptr(), self.as_ptr(), b.as_ptr())).map(|_| ()) }
    }

    /// Places `self << n` in `r`.
    pub fn lshift(&self, r: &mut Ref<BigNum>, b: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_lshift(r.as_ptr(), self.as_ptr(), b.into())).map(|_| ()) }
    }

    /// Places `self >> n` in `r`.
    pub fn rshift(&self, r: &mut Ref<BigNum>, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rshift(r.as_ptr(), self.as_ptr(), n.into())).map(|_| ()) }
    }

    pub fn to_owned(&self) -> Result<BigNum, ErrorStack> {
        unsafe { cvt_p(ffi::BN_dup(self.as_ptr())).map(|b| BigNum::from_ptr(b)) }
    }

    /// Sets the sign of `self`.
    pub fn set_negative(&mut self, negative: bool) {
        unsafe { ffi::BN_set_negative(self.as_ptr(), negative as c_int) }
    }

    /// Compare the absolute values of `self` and `oth`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// # use std::cmp::Ordering;
    /// let s = -BigNum::from_u32(8).unwrap();
    /// let o = BigNum::from_u32(8).unwrap();
    ///
    /// assert_eq!(s.ucmp(&o), Ordering::Equal);
    /// ```
    pub fn ucmp(&self, oth: &Ref<BigNum>) -> Ordering {
        unsafe { ffi::BN_ucmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
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

    /// Returns a big-endian byte vector representation of the absolute value of `self`.
    ///
    /// `self` can be recreated by using `new_from_slice`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::from_u32(4543).unwrap();
    /// let r = BigNum::from_u32(4543).unwrap();
    ///
    /// let s_vec = s.to_vec();
    /// assert_eq!(BigNum::from_slice(&s_vec).unwrap(), r);
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
    /// let s = -BigNum::from_u32(12345).unwrap();
    ///
    /// assert_eq!(&*s.to_dec_str().unwrap(), "-12345");
    /// ```
    pub fn to_dec_str(&self) -> Result<CryptoString, ErrorStack> {
        unsafe {
            let buf = try!(cvt_p(ffi::BN_bn2dec(self.as_ptr())));
            Ok(CryptoString::from_null_terminated(buf))
        }
    }

    /// Returns a hexadecimal string representation of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::from_u32(0x99ff).unwrap();
    ///
    /// assert_eq!(&*s.to_hex_str().unwrap(), "-99FF");
    /// ```
    pub fn to_hex_str(&self) -> Result<CryptoString, ErrorStack> {
        unsafe {
            let buf = try!(cvt_p(ffi::BN_bn2hex(self.as_ptr())));
            Ok(CryptoString::from_null_terminated(buf))
        }
    }
}

type_!(BigNum, ffi::BIGNUM, ffi::BN_clear_free);

impl BigNum {
    /// Creates a new `BigNum` with the value 0.
    pub fn new() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            let v = try!(cvt_p(ffi::BN_new()));
            Ok(BigNum::from_ptr(v))
        }
    }

    /// Creates a new `BigNum` with the given value.
    pub fn from_u32(n: u32) -> Result<BigNum, ErrorStack> {
        BigNum::new().and_then(|v| unsafe {
            cvt(ffi::BN_set_word(v.as_ptr(), n as ffi::BN_ULONG)).map(|_| v)
        })
    }

    /// Creates a `BigNum` from a decimal string.
    pub fn from_dec_str(s: &str) -> Result<BigNum, ErrorStack> {
        unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            let mut bn = ptr::null_mut();
            try!(cvt(ffi::BN_dec2bn(&mut bn, c_str.as_ptr() as *const _)));
            Ok(BigNum::from_ptr(bn))
        }
    }

    /// Creates a `BigNum` from a hexadecimal string.
    pub fn from_hex_str(s: &str) -> Result<BigNum, ErrorStack> {
        unsafe {
            let c_str = CString::new(s.as_bytes()).unwrap();
            let mut bn = ptr::null_mut();
            try!(cvt(ffi::BN_hex2bn(&mut bn, c_str.as_ptr() as *const _)));
            Ok(BigNum::from_ptr(bn))
        }
    }

    /// Creates a new `BigNum` from an unsigned, big-endian encoded number of arbitrary length.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let bignum = BigNum::from_slice(&[0x12, 0x00, 0x34]).unwrap();
    ///
    /// assert_eq!(bignum, BigNum::from_u32(0x120034).unwrap());
    /// ```
    pub fn from_slice(n: &[u8]) -> Result<BigNum, ErrorStack> {
        unsafe {
            assert!(n.len() <= c_int::max_value() as usize);
            cvt_p(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, ptr::null_mut()))
                .map(|p| BigNum::from_ptr(p))
        }
    }

    /// Generates a prime number, placing it in `r`.
    ///
    /// # Parameters
    ///
    /// * `bits`: The length of the prime in bits (lower bound).
    /// * `safe`: If true, returns a "safe" prime `p` so that `(p-1)/2` is also prime.
    /// * `add`/`rem`: If `add` is set to `Some(add)`, `p % add == rem` will hold, where `p` is the
    ///   generated prime and `rem` is `1` if not specified (`None`).
    pub fn generate_prime(r: &mut Ref<BigNum>,
                          bits: i32,
                          safe: bool,
                          add: Option<&Ref<BigNum>>,
                          rem: Option<&Ref<BigNum>>)
                          -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_generate_prime_ex(r.as_ptr(),
                                          bits as c_int,
                                          safe as c_int,
                                          add.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut()),
                                          rem.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut()),
                                          ptr::null_mut()))
                .map(|_| ())
        }
    }
}

impl AsRef<Ref<BigNum>> for BigNum {
    fn as_ref(&self) -> &Ref<BigNum> {
        self.deref()
    }
}

impl fmt::Debug for Ref<BigNum> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for Ref<BigNum> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl PartialEq<Ref<BigNum>> for Ref<BigNum> {
    fn eq(&self, oth: &Ref<BigNum>) -> bool {
        self.cmp(oth) == Ordering::Equal
    }
}

impl PartialEq<BigNum> for Ref<BigNum> {
    fn eq(&self, oth: &BigNum) -> bool {
        self.eq(oth.deref())
    }
}

impl Eq for Ref<BigNum> {}

impl PartialEq for BigNum {
    fn eq(&self, oth: &BigNum) -> bool {
        self.deref().eq(oth)
    }
}

impl PartialEq<Ref<BigNum>> for BigNum {
    fn eq(&self, oth: &Ref<BigNum>) -> bool {
        self.deref().eq(oth)
    }
}

impl Eq for BigNum {}

impl PartialOrd<Ref<BigNum>> for Ref<BigNum> {
    fn partial_cmp(&self, oth: &Ref<BigNum>) -> Option<Ordering> {
        Some(self.cmp(oth))
    }
}

impl PartialOrd<BigNum> for Ref<BigNum> {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        Some(self.cmp(oth.deref()))
    }
}

impl Ord for Ref<BigNum> {
    fn cmp(&self, oth: &Ref<BigNum>) -> Ordering {
        unsafe { ffi::BN_cmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        self.deref().partial_cmp(oth.deref())
    }
}

impl PartialOrd<Ref<BigNum>> for BigNum {
    fn partial_cmp(&self, oth: &Ref<BigNum>) -> Option<Ordering> {
        self.deref().partial_cmp(oth)
    }
}

impl Ord for BigNum {
    fn cmp(&self, oth: &BigNum) -> Ordering {
        self.deref().cmp(oth.deref())
    }
}

macro_rules! delegate {
    ($t:ident, $m:ident) => {
        impl<'a, 'b> $t<&'b BigNum> for &'a Ref<BigNum> {
            type Output = BigNum;

            fn $m(self, oth: &BigNum) -> BigNum {
                $t::$m(self, oth.deref())
            }
        }

        impl<'a, 'b> $t<&'b Ref<BigNum>> for &'a BigNum {
            type Output = BigNum;

            fn $m(self, oth: &Ref<BigNum>) -> BigNum {
                $t::$m(self.deref(), oth)
            }
        }

        impl<'a, 'b> $t<&'b BigNum> for &'a BigNum {
            type Output = BigNum;

            fn $m(self, oth: &BigNum) -> BigNum {
                $t::$m(self.deref(), oth.deref())
            }
        }
    }
}

impl<'a, 'b> Add<&'b Ref<BigNum>> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn add(self, oth: &Ref<BigNum>) -> BigNum {
        let mut r = BigNum::new().unwrap();
        self.add(&mut r, oth).unwrap();
        r
    }
}

delegate!(Add, add);

impl<'a, 'b> Sub<&'b Ref<BigNum>> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn sub(self, oth: &Ref<BigNum>) -> BigNum {
        let mut r = BigNum::new().unwrap();
        self.sub(&mut r, oth).unwrap();
        r
    }
}

delegate!(Sub, sub);

impl<'a, 'b> Mul<&'b Ref<BigNum>> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn mul(self, oth: &Ref<BigNum>) -> BigNum {
        let mut ctx = BnCtx::new().unwrap();
        let mut r = BigNum::new().unwrap();
        ctx.mul(&mut r, self, oth).unwrap();
        r
    }
}

delegate!(Mul, mul);

impl<'a, 'b> Div<&'b Ref<BigNum>> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn div(self, oth: &'b Ref<BigNum>) -> BigNum {
        let mut ctx = BnCtx::new().unwrap();
        let mut dv = BigNum::new().unwrap();
        ctx.div(Some(&mut dv), None, self, oth).unwrap();
        dv
    }
}

delegate!(Div, div);

impl<'a, 'b> Rem<&'b Ref<BigNum>> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn rem(self, oth: &'b Ref<BigNum>) -> BigNum {
        let mut ctx = BnCtx::new().unwrap();
        let mut rem = BigNum::new().unwrap();
        ctx.div(None, Some(&mut rem), self, oth).unwrap();
        rem
    }
}

delegate!(Rem, rem);

impl<'a> Shl<i32> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        let mut r = BigNum::new().unwrap();
        self.lshift(&mut r, n).unwrap();
        r
    }
}

impl<'a> Shl<i32> for &'a BigNum {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        self.deref().shl(n)
    }
}

impl<'a> Shr<i32> for &'a Ref<BigNum> {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        let mut r = BigNum::new().unwrap();
        self.rshift(&mut r, n).unwrap();
        r
    }
}

impl<'a> Shr<i32> for &'a BigNum {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        self.deref().shl(n)
    }
}

impl<'a> Neg for &'a Ref<BigNum> {
    type Output = BigNum;

    fn neg(self) -> BigNum {
        self.to_owned().unwrap().neg()
    }
}

impl<'a> Neg for &'a BigNum {
    type Output = BigNum;

    fn neg(self) -> BigNum {
        self.deref().neg()
    }
}

impl Neg for BigNum {
    type Output = BigNum;

    fn neg(mut self) -> BigNum {
        let negative = self.is_negative();
        self.set_negative(!negative);
        self
    }
}

#[cfg(test)]
mod tests {
    use bn::{BnCtx, BigNum};

    #[test]
    fn test_to_from_slice() {
        let v0 = BigNum::from_u32(10203004).unwrap();
        let vec = v0.to_vec();
        let v1 = BigNum::from_slice(&vec).unwrap();

        assert!(v0 == v1);
    }

    #[test]
    fn test_negation() {
        let a = BigNum::from_u32(909829283).unwrap();

        assert!(!a.is_negative());
        assert!((-a).is_negative());
    }

    #[test]
    fn test_prime_numbers() {
        let a = BigNum::from_u32(19029017).unwrap();
        let mut p = BigNum::new().unwrap();
        BigNum::generate_prime(&mut p, 128, true, None, Some(&a)).unwrap();

        let mut ctx = BnCtx::new().unwrap();
        assert!(ctx.is_prime(&p, 100).unwrap());
        assert!(ctx.is_prime_fasttest(&p, 100, true).unwrap());
    }
}
