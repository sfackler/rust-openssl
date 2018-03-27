use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::cmp::Ordering;
use std::ffi::CString;
use std::{fmt, ptr};
use std::ops::{Add, Div, Mul, Neg, Rem, Shl, Shr, Sub, Deref};

use {cvt, cvt_p, cvt_n};
use asn1::Asn1Integer;
use error::ErrorStack;
use string::OpensslString;

#[cfg(ossl10x)]
use ffi::{get_rfc2409_prime_768 as BN_get_rfc2409_prime_768,
          get_rfc2409_prime_1024 as BN_get_rfc2409_prime_1024,
          get_rfc3526_prime_1536 as BN_get_rfc3526_prime_1536,
          get_rfc3526_prime_2048 as BN_get_rfc3526_prime_2048,
          get_rfc3526_prime_3072 as BN_get_rfc3526_prime_3072,
          get_rfc3526_prime_4096 as BN_get_rfc3526_prime_4096,
          get_rfc3526_prime_6144 as BN_get_rfc3526_prime_6144,
          get_rfc3526_prime_8192 as BN_get_rfc3526_prime_8192};

#[cfg(ossl110)]
use ffi::{BN_get_rfc2409_prime_768, BN_get_rfc2409_prime_1024, BN_get_rfc3526_prime_1536,
    BN_get_rfc3526_prime_2048, BN_get_rfc3526_prime_3072, BN_get_rfc3526_prime_4096,
    BN_get_rfc3526_prime_6144, BN_get_rfc3526_prime_8192};

/// Options for the most significant bits of a randomly generated `BigNum`.
pub struct MsbOption(c_int);

/// The most significant bit of the number may be 0.
pub const MSB_MAYBE_ZERO: MsbOption = MsbOption(-1);

/// The most significant bit of the number must be 1.
pub const MSB_ONE: MsbOption = MsbOption(0);

/// The most significant two bits of the number must be 1.
///
/// The number of bits in the product of two such numbers will always be exactly twice the number
/// of bits in the original numbers.
pub const TWO_MSB_ONE: MsbOption = MsbOption(1);

foreign_type! {
    type CType = ffi::BN_CTX;
    fn drop = ffi::BN_CTX_free;

    pub struct BigNumContext;
    pub struct BigNumContextRef;
}

impl BigNumContext {
    /// Returns a new `BigNumContext`.
    pub fn new() -> Result<BigNumContext, ErrorStack> {
        unsafe { cvt_p(ffi::BN_CTX_new()).map(BigNumContext) }
    }
}

impl BigNumRef {
    /// Erases the memory used by this `BigNum`, resetting its value to 0.
    ///
    /// This can be used to destroy sensitive data such as keys when they are no longer needed.
    pub fn clear(&mut self) {
        unsafe { ffi::BN_clear(self.as_ptr()) }
    }

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
    pub fn rand_range(&self, rnd: &mut BigNumRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rand_range(self.as_ptr(), rnd.as_ptr())).map(|_| ()) }
    }

    /// The cryptographically weak counterpart to `rand_in_range`.
    pub fn pseudo_rand_range(&self, rnd: &mut BigNumRef) -> Result<(), ErrorStack> {
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

    /// Places `a << 1` in `self`.
    pub fn lshift1(&mut self, a: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_lshift1(self.as_ptr(), a.as_ptr())).map(|_| ()) }
    }

    /// Places `a >> 1` in `self`.
    pub fn rshift1(&mut self, a: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rshift1(self.as_ptr(), a.as_ptr())).map(|_| ()) }
    }

    /// Places `a + b` in `self`.
    pub fn checked_add(&mut self, a: &BigNumRef, b: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_add(self.as_ptr(), a.as_ptr(), b.as_ptr())).map(|_| ()) }
    }

    /// Places `a - b` in `self`.
    pub fn checked_sub(&mut self, a: &BigNumRef, b: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_sub(self.as_ptr(), a.as_ptr(), b.as_ptr())).map(|_| ()) }
    }

    /// Places `a << n` in `self`.
    pub fn lshift(&mut self, a: &BigNumRef, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_lshift(self.as_ptr(), a.as_ptr(), n.into())).map(|_| ()) }
    }

    /// Places `a >> n` in `self`.
    pub fn rshift(&mut self, a: &BigNumRef, n: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rshift(self.as_ptr(), a.as_ptr(), n.into())).map(|_| ()) }
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
    pub fn ucmp(&self, oth: &BigNumRef) -> Ordering {
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

    /// Generates a cryptographically strong pseudo-random `BigNum`, placing it in `self`.
    ///
    /// # Parameters
    ///
    /// * `bits`: Length of the number in bits.
    /// * `msb`: The desired properties of the number.
    /// * `odd`: If `true`, the generated number will be odd.
    pub fn rand(&mut self, bits: i32, msb: MsbOption, odd: bool) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_rand(self.as_ptr(), bits.into(), msb.0, odd as c_int)).map(|_| ()) }
    }

    /// The cryptographically weak counterpart to `rand`.
    pub fn pseudo_rand(&mut self, bits: i32, msb: MsbOption, odd: bool) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_pseudo_rand(self.as_ptr(), bits.into(), msb.0, odd as c_int)).map(|_| ())
        }
    }

    /// Generates a prime number, placing it in `self`.
    ///
    /// # Parameters
    ///
    /// * `bits`: The length of the prime in bits (lower bound).
    /// * `safe`: If true, returns a "safe" prime `p` so that `(p-1)/2` is also prime.
    /// * `add`/`rem`: If `add` is set to `Some(add)`, `p % add == rem` will hold, where `p` is the
    ///   generated prime and `rem` is `1` if not specified (`None`).
    pub fn generate_prime(&mut self,
                          bits: i32,
                          safe: bool,
                          add: Option<&BigNumRef>,
                          rem: Option<&BigNumRef>)
                          -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_generate_prime_ex(self.as_ptr(),
                                          bits as c_int,
                                          safe as c_int,
                                          add.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut()),
                                          rem.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut()),
                                          ptr::null_mut()))
                .map(|_| ())
        }
    }

    /// Places the result of `a * b` in `self`.
    pub fn checked_mul(&mut self,
               a: &BigNumRef,
               b: &BigNumRef,
               ctx: &mut BigNumContextRef)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_mul(self.as_ptr(), a.as_ptr(), b.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Places the result of `a / b` in `self`.
    pub fn checked_div(&mut self,
                       a: &BigNumRef,
                       b: &BigNumRef,
                       ctx: &mut BigNumContextRef)
                       -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_div(self.as_ptr(),
                            ptr::null_mut(),
                            a.as_ptr(),
                            b.as_ptr(),
                            ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a % b` in `self`.
    pub fn checked_rem(&mut self,
                       a: &BigNumRef,
                       b: &BigNumRef,
                       ctx: &mut BigNumContextRef)
                       -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_div(ptr::null_mut(),
                            self.as_ptr(),
                            a.as_ptr(),
                            b.as_ptr(),
                            ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a / b` in `self` and `a % b` in `rem`.
    pub fn div_rem(&mut self,
                   rem: &mut BigNumRef,
                   a: &BigNumRef,
                   b: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_div(self.as_ptr(),
                            rem.as_ptr(),
                            a.as_ptr(),
                            b.as_ptr(),
                            ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a²` in `self`.
    pub fn sqr(&mut self, a: &BigNumRef, ctx: &mut BigNumContextRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_sqr(self.as_ptr(), a.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Places the result of `a mod m` in `self`.
    pub fn nnmod(&mut self,
                 a: &BigNumRef,
                 m: &BigNumRef,
                 ctx: &mut BigNumContextRef)
                 -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_nnmod(self.as_ptr(), a.as_ptr(), m.as_ptr(), ctx.as_ptr())).map(|_| ())
        }
    }

    /// Places the result of `(a + b) mod m` in `self`.
    pub fn mod_add(&mut self,
                   a: &BigNumRef,
                   b: &BigNumRef,
                   m: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_add(self.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `(a - b) mod m` in `self`.
    pub fn mod_sub(&mut self,
                   a: &BigNumRef,
                   b: &BigNumRef,
                   m: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_sub(self.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `(a * b) mod m` in `self`.
    pub fn mod_mul(&mut self,
                   a: &BigNumRef,
                   b: &BigNumRef,
                   m: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_mul(self.as_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a² mod m` in `self`.
    pub fn mod_sqr(&mut self,
                   a: &BigNumRef,
                   m: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_sqr(self.as_ptr(), a.as_ptr(), m.as_ptr(), ctx.as_ptr())).map(|_| ())
        }
    }

    /// Places the result of `a^p` in `self`.
    pub fn exp(&mut self,
               a: &BigNumRef,
               p: &BigNumRef,
               ctx: &mut BigNumContextRef)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_exp(self.as_ptr(), a.as_ptr(), p.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Places the result of `a^p mod m` in `self`.
    pub fn mod_exp(&mut self,
                   a: &BigNumRef,
                   p: &BigNumRef,
                   m: &BigNumRef,
                   ctx: &mut BigNumContextRef)
                   -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_exp(self.as_ptr(), a.as_ptr(), p.as_ptr(), m.as_ptr(), ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the result of `a^p mod m` in `a`.
    pub fn mod_exp_mut(
        &mut self,
        p: &BigNumRef,
        m: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::BN_mod_exp(
                self.as_ptr(),
                self.as_ptr(),
                p.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Places the inverse of `a` modulo `n` in `self`.
    pub fn mod_inverse(&mut self,
                       a: &BigNumRef,
                       n: &BigNumRef,
                       ctx: &mut BigNumContextRef)
                       -> Result<(), ErrorStack> {
        unsafe {
            cvt_p(ffi::BN_mod_inverse(self.as_ptr(), a.as_ptr(), n.as_ptr(), ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the greatest common denominator of `a` and `b` in `self`.
    pub fn gcd(&mut self,
               a: &BigNumRef,
               b: &BigNumRef,
               ctx: &mut BigNumContextRef)
               -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::BN_gcd(self.as_ptr(), a.as_ptr(), b.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Checks whether `self` is prime.
    ///
    /// Performs a Miller-Rabin probabilistic primality test with `checks` iterations.
    ///
    /// Returns `true` if `self` is prime with an error probability of less than `0.25 ^ checks`.
    pub fn is_prime(&self, checks: i32, ctx: &mut BigNumContextRef) -> Result<bool, ErrorStack> {
        unsafe {
            cvt_n(ffi::BN_is_prime_ex(self.as_ptr(), checks.into(), ctx.as_ptr(), ptr::null_mut()))
                .map(|r| r != 0)
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
    pub fn is_prime_fasttest(&self,
                             checks: i32,
                             ctx: &mut BigNumContextRef,
                             do_trial_division: bool)
                             -> Result<bool, ErrorStack> {
        unsafe {
            cvt_n(ffi::BN_is_prime_fasttest_ex(self.as_ptr(),
                                               checks.into(),
                                               ctx.as_ptr(),
                                               do_trial_division as c_int,
                                               ptr::null_mut()))
                .map(|r| r != 0)
        }
    }

    /// Returns a big-endian byte vector representation of the absolute value of `self`.
    ///
    /// `self` can be recreated by using `from_slice`.
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
    /// assert_eq!(&**s.to_dec_str().unwrap(), "-12345");
    /// ```
    pub fn to_dec_str(&self) -> Result<OpensslString, ErrorStack> {
        unsafe {
            let buf = try!(cvt_p(ffi::BN_bn2dec(self.as_ptr())));
            Ok(OpensslString::from_ptr(buf))
        }
    }

    /// Returns a hexadecimal string representation of `self`.
    ///
    /// ```
    /// # use openssl::bn::BigNum;
    /// let s = -BigNum::from_u32(0x99ff).unwrap();
    ///
    /// assert_eq!(&**s.to_hex_str().unwrap(), "-99FF");
    /// ```
    pub fn to_hex_str(&self) -> Result<OpensslString, ErrorStack> {
        unsafe {
            let buf = try!(cvt_p(ffi::BN_bn2hex(self.as_ptr())));
            Ok(OpensslString::from_ptr(buf))
        }
    }

    /// Returns an `Asn1Integer` containing the value of `self`.
    pub fn to_asn1_integer(&self) -> Result<Asn1Integer, ErrorStack> {
        unsafe {
            cvt_p(ffi::BN_to_ASN1_INTEGER(self.as_ptr(), ptr::null_mut()))
                .map(|p| Asn1Integer::from_ptr(p))
        }
    }
}

foreign_type! {
    type CType = ffi::BIGNUM;
    fn drop = ffi::BN_free;

    pub struct BigNum;
    pub struct BigNumRef;
}

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
            ffi::init();
            let c_str = CString::new(s.as_bytes()).unwrap();
            let mut bn = ptr::null_mut();
            try!(cvt(ffi::BN_dec2bn(&mut bn, c_str.as_ptr() as *const _)));
            Ok(BigNum::from_ptr(bn))
        }
    }

    /// Creates a `BigNum` from a hexadecimal string.
    pub fn from_hex_str(s: &str) -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            let c_str = CString::new(s.as_bytes()).unwrap();
            let mut bn = ptr::null_mut();
            try!(cvt(ffi::BN_hex2bn(&mut bn, c_str.as_ptr() as *const _)));
            Ok(BigNum::from_ptr(bn))
        }
    }

    pub fn get_rfc2409_prime_768() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc2409_prime_768(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc2409_prime_1024() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc2409_prime_1024(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_1536() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_1536(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_2048() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_2048(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_3072() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_3072(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_4096() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_4096(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_6144() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_6144(ptr::null_mut())).map(BigNum)
        }
    }

    pub fn get_rfc3526_prime_8192() -> Result<BigNum, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(BN_get_rfc3526_prime_8192(ptr::null_mut())).map(BigNum)
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
            ffi::init();
            assert!(n.len() <= c_int::max_value() as usize);
            cvt_p(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, ptr::null_mut()))
                .map(|p| BigNum::from_ptr(p))
        }
    }
}

impl AsRef<BigNumRef> for BigNum {
    fn as_ref(&self) -> &BigNumRef {
        self.deref()
    }
}

impl fmt::Debug for BigNumRef {
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

impl fmt::Display for BigNumRef {
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

impl PartialEq<BigNumRef> for BigNumRef {
    fn eq(&self, oth: &BigNumRef) -> bool {
        self.cmp(oth) == Ordering::Equal
    }
}

impl PartialEq<BigNum> for BigNumRef {
    fn eq(&self, oth: &BigNum) -> bool {
        self.eq(oth.deref())
    }
}

impl Eq for BigNumRef {}

impl PartialEq for BigNum {
    fn eq(&self, oth: &BigNum) -> bool {
        self.deref().eq(oth)
    }
}

impl PartialEq<BigNumRef> for BigNum {
    fn eq(&self, oth: &BigNumRef) -> bool {
        self.deref().eq(oth)
    }
}

impl Eq for BigNum {}

impl PartialOrd<BigNumRef> for BigNumRef {
    fn partial_cmp(&self, oth: &BigNumRef) -> Option<Ordering> {
        Some(self.cmp(oth))
    }
}

impl PartialOrd<BigNum> for BigNumRef {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        Some(self.cmp(oth.deref()))
    }
}

impl Ord for BigNumRef {
    fn cmp(&self, oth: &BigNumRef) -> Ordering {
        unsafe { ffi::BN_cmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        self.deref().partial_cmp(oth.deref())
    }
}

impl PartialOrd<BigNumRef> for BigNum {
    fn partial_cmp(&self, oth: &BigNumRef) -> Option<Ordering> {
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
        impl<'a, 'b> $t<&'b BigNum> for &'a BigNumRef {
            type Output = BigNum;

            fn $m(self, oth: &BigNum) -> BigNum {
                $t::$m(self, oth.deref())
            }
        }

        impl<'a, 'b> $t<&'b BigNumRef> for &'a BigNum {
            type Output = BigNum;

            fn $m(self, oth: &BigNumRef) -> BigNum {
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

impl<'a, 'b> Add<&'b BigNumRef> for &'a BigNumRef {
    type Output = BigNum;

    fn add(self, oth: &BigNumRef) -> BigNum {
        let mut r = BigNum::new().unwrap();
        r.checked_add(self, oth).unwrap();
        r
    }
}

delegate!(Add, add);

impl<'a, 'b> Sub<&'b BigNumRef> for &'a BigNumRef {
    type Output = BigNum;

    fn sub(self, oth: &BigNumRef) -> BigNum {
        let mut r = BigNum::new().unwrap();
        r.checked_sub(self, oth).unwrap();
        r
    }
}

delegate!(Sub, sub);

impl<'a, 'b> Mul<&'b BigNumRef> for &'a BigNumRef {
    type Output = BigNum;

    fn mul(self, oth: &BigNumRef) -> BigNum {
        let mut ctx = BigNumContext::new().unwrap();
        let mut r = BigNum::new().unwrap();
        r.checked_mul(self, oth, &mut ctx).unwrap();
        r
    }
}

delegate!(Mul, mul);

impl<'a, 'b> Div<&'b BigNumRef> for &'a BigNumRef {
    type Output = BigNum;

    fn div(self, oth: &'b BigNumRef) -> BigNum {
        let mut ctx = BigNumContext::new().unwrap();
        let mut r = BigNum::new().unwrap();
        r.checked_div(self, oth, &mut ctx).unwrap();
        r
    }
}

delegate!(Div, div);

impl<'a, 'b> Rem<&'b BigNumRef> for &'a BigNumRef {
    type Output = BigNum;

    fn rem(self, oth: &'b BigNumRef) -> BigNum {
        let mut ctx = BigNumContext::new().unwrap();
        let mut r = BigNum::new().unwrap();
        r.checked_rem(self, oth, &mut ctx).unwrap();
        r
    }
}

delegate!(Rem, rem);

impl<'a> Shl<i32> for &'a BigNumRef {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        let mut r = BigNum::new().unwrap();
        r.lshift(self, n).unwrap();
        r
    }
}

impl<'a> Shl<i32> for &'a BigNum {
    type Output = BigNum;

    fn shl(self, n: i32) -> BigNum {
        self.deref().shl(n)
    }
}

impl<'a> Shr<i32> for &'a BigNumRef {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        let mut r = BigNum::new().unwrap();
        r.rshift(self, n).unwrap();
        r
    }
}

impl<'a> Shr<i32> for &'a BigNum {
    type Output = BigNum;

    fn shr(self, n: i32) -> BigNum {
        self.deref().shr(n)
    }
}

impl<'a> Neg for &'a BigNumRef {
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
    use bn::{BigNumContext, BigNum};
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn test_shift() {
        let a = BigNum::from_u32(909829283).unwrap();
        use std::ops::{Shl, Shr};

        assert!(a == a.shl(1).shr(1));
    }

    #[test]
    fn test_prime_numbers() {
        let a = BigNum::from_u32(19029017).unwrap();
        let mut p = BigNum::new().unwrap();
        p.generate_prime(128, true, None, Some(&a)).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        assert!(p.is_prime(100, &mut ctx).unwrap());
        assert!(p.is_prime_fasttest(100, &mut ctx, true).unwrap());
    }

    #[test]
    fn test_exponentiation_time() {
        let modulus = BigNum::from_dec_str("3204629348400311894981147889064213475911502950610822910497794640539580108252311103815602649702091072442089016826192705629222534383850640976103541074965825911439481511841669818218556523699545667979238433531950872370285535430396347665030321087803912182039011247460768098263564546879241877558066260767468387251243972651463237193324761892342299558684399419909028079667195672054655387173203038107042778744649155842364672936664532754000715885900524415403622527226575507346822066350920781137340258848229685505555558665781467456342659911415599377043489979596237979941386501264463874766166877146485965674900595259972161874714381016252770855749700706860768647580178487242906896883599546187195495868346449603306725234279605044720570340541521141682943069084999263530360914420274990375408153529679146137934097158741957518183323298580558730909779698051995609396227449697670716584357361212378371486020465912177797480071144296559699016912326564059836301570632836543118917475972178423287627710340103368809606657431184660768586693677060010145686280797896075497757615632909442703186036300871183851569319692562563918216157762976445282183184528709786306196550055260857987968870798605413506633826598403862811608523439523945519737279157633473140586034211201").unwrap();
        let element_size = 1500;
        let mut accumulator = BigNum::from_dec_str("1915182769368569486963976668657418846122016471585262452138689064979880063217142171230525667406114297912997697884669760718181148903891406258652154564474937314809392827351229074850339882653085906709452763512017926382658040877860425398565313118206001571983057266861433787870120516963262872556160137632986790799637800187327525373894833699998137974425675888510468704041321563743266953919273330110447213516904474856325884904918747921700098338253140217925656078220294833113261362981479227102302139442862538529417112227112104830922667359007109709204936925922862592053626140248383988977967399826184116697852122995719423774656923017777301713520425580745782097460248899329835740441429284020663186635354571333690692107185946297929772630086928323118606594588790915139339431940489511850279806818826143040378319619062305629273497273725721368157955512179352674013822087432127910233025333571203452180390613181846035364105352384024395662959142236311712295552933323767329374261596612060957502167831080774021620823718240397211269873903737841346862215246685242302847894894907938934985950908016181737929997451061016202494801606490097096889822976223609532834237496884730642312786447889763148272139117981855545441295507862786712405210727374768044118436617961").unwrap();
        let total = 2000;
        let mut primes = Vec::new();
        let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        for _ in 0..total {
            let mut p = BigNum::new().unwrap();
            p.generate_prime(element_size, false, None, None).unwrap();
            primes.push(p);
        }
        let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        println!("Generating {} primes takes {} seconds", total, end_since_the_epoch.as_secs()-start_since_the_epoch.as_secs());
        let mut bn_ctx = BigNumContext::new().unwrap();
        let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        for i in 0..total {
            /*let start_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");*/
            accumulator.mod_exp_mut(&primes[i], &modulus, &mut bn_ctx).unwrap();
            /*let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards");*/
        }
        let end_since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        println!("mod_exp: Time to generate and exponentiate {} primes is {:?}", total, end_since_the_epoch.as_secs()-start_since_the_epoch.as_secs());
    }
}
