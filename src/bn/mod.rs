
use libc::{c_void, c_int, c_ulong, c_char};
use std::{fmt, ptr};
use std::c_str::CString;
use std::num::{One, Zero};

use ssl::error::SslError;

#[allow(dead_code)]
#[repr(C)]
struct BIGNUM {
    d: *mut c_void,
    top: c_int,
    dmax: c_int,
    neg: c_int,
    flags: c_int,
}

#[allow(non_camel_case_types)]
type BN_CTX = *mut c_void;

#[link(name = "crypto")]
extern {
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(bn: *mut BIGNUM);

    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);

    fn BN_set_word(bn: *mut BIGNUM, n: c_ulong) -> c_int;
    fn BN_set_negative(bn: *mut BIGNUM, n: c_int);
    fn BN_num_bits(bn: *mut BIGNUM) -> c_int;

    /* Arithmetic operations on BIGNUMs */
    fn BN_add(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM) -> c_int;
    fn BN_sub(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM) -> c_int;
    fn BN_mul(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_sqr(r: *mut BIGNUM, a: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_div(dv: *mut BIGNUM, rem: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_nnmod(rem: *mut BIGNUM, a: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_add(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_sub(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_mul(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_sqr(r: *mut BIGNUM, a: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_exp(r: *mut BIGNUM, a: *mut BIGNUM, p: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_exp(r: *mut BIGNUM, a: *mut BIGNUM, p: *mut BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;
    fn BN_mod_inverse(r: *mut BIGNUM, a: *mut BIGNUM, n: *mut BIGNUM, ctx: *mut BN_CTX) -> *const BIGNUM;
    fn BN_mod_word(r: *mut BIGNUM, w: c_ulong) -> c_ulong;
    fn BN_gcd(r: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int;

    /* Bit operations on BIGNUMs */
    fn BN_set_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_clear_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_is_bit_set(a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_mask_bits(a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_lshift1(r: *mut BIGNUM, a: *mut BIGNUM) -> c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *mut BIGNUM, n: c_int) -> c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *mut BIGNUM) -> c_int;

    /* Comparisons on BIGNUMs */
    fn BN_cmp(a: *mut BIGNUM, b: *mut BIGNUM) -> c_int;
    fn BN_ucmp(a: *mut BIGNUM, b: *mut BIGNUM) -> c_int;
    fn BN_is_zero(a: *mut BIGNUM) -> c_int;

    /* Prime handling */
    fn BN_generate_prime_ex(r: *mut BIGNUM, bits: c_int, safe: c_int, add: *mut BIGNUM, rem: *mut BIGNUM, cb: *const c_void) -> c_int;
    fn BN_is_prime_ex(p: *mut BIGNUM, checks: c_int, ctx: *mut BN_CTX, cb: *const c_void) -> c_int;
    fn BN_is_prime_fasttest_ex(p: *mut BIGNUM, checks: c_int, ctx: *mut BN_CTX, do_trial_division: c_int, cb: *const c_void) -> c_int;

    /* Random number handling */
    fn BN_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    fn BN_pseudo_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    fn BN_rand_range(r: *mut BIGNUM, range: *mut BIGNUM) -> c_int;
    fn BN_pseudo_rand_range(r: *mut BIGNUM, range: *mut BIGNUM) -> c_int;

    /* Conversion from/to binary representation */
    fn BN_bn2bin(a: *mut BIGNUM, to: *mut u8) -> c_int;
    fn BN_bin2bn(s: *const u8, size: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;

    /* Conversion from/to string representation */
    fn BN_bn2dec(a: *mut BIGNUM) -> *const c_char;
    fn CRYPTO_free(buf: *const c_char);
}

pub struct BigNum(*mut BIGNUM);

#[repr(C)]
pub enum RNGProperty {
    MsbMaybeZero = -1,
    MsbOne = 0,
    TwoMsbOne = 1,
}

macro_rules! with_ctx(
    ($name:ident, $action:block) => ({
        let $name = BN_CTX_new();
        if ($name).is_null() {
            Err(SslError::get())
        } else {
            let r = $action;
            BN_CTX_free($name);
            r
        }
    });
)

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
)

macro_rules! with_bn_in_ctx(
    ($name:ident, $ctx_name:ident, $action:block) => ({
        let tmp = BigNum::new();
        match tmp {
            Ok($name) => {
                let $ctx_name = BN_CTX_new();
                if ($ctx_name).is_null() {
                    Err(SslError::get())
                } else {
                    let r =
                        if $action {
                            Ok($name)
                        } else {
                            Err(SslError::get())
                        };
                    BN_CTX_free($ctx_name);
                    r
                }
            },
            Err(err) => Err(err),
        }
    });
)

impl BigNum {
    pub fn new() -> Result<BigNum, SslError> {
        unsafe {
            let v = BN_new();
            if v.is_null() {
                Err(SslError::get())
            } else {
                Ok(BigNum(v))
            }
        }
    }

    pub fn new_from(n: u64) -> Result<BigNum, SslError> {
        unsafe {
            let bn = BN_new();
            if bn.is_null() || BN_set_word(bn, n as c_ulong) == 0 {
                Err(SslError::get())
            } else {
                Ok(BigNum(bn))
            }
        }
    }

    pub fn new_from_slice(n: &[u8]) -> Result<BigNum, SslError> {
        unsafe {
            let bn = BN_new();
            if bn.is_null() || BN_bin2bn(n.as_ptr(), n.len() as c_int, bn).is_null() {
                Err(SslError::get())
            } else {
                Ok(BigNum(bn))
            }
        }
    }

    pub fn checked_sqr(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_sqr(r.raw(), self.raw(), ctx) == 1 })
        }
    }

    pub fn checked_nnmod(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_nnmod(r.raw(), self.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_add(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mod_add(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_sub(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mod_sub(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_mul(&self, a: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mod_mul(r.raw(), self.raw(), a.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_sqr(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mod_sqr(r.raw(), self.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_exp(&self, p: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_exp(r.raw(), self.raw(), p.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_exp(&self, p: &BigNum, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mod_exp(r.raw(), self.raw(), p.raw(), n.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod_inv(&self, n: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { !BN_mod_inverse(r.raw(), self.raw(), n.raw(), ctx).is_null() })
        }
    }

    pub fn mod_word(&self, w: c_ulong) -> c_ulong {
        unsafe {
            return BN_mod_word(self.raw(), w);
        }
    }

    pub fn checked_gcd(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_gcd(r.raw(), self.raw(), a.raw(), ctx) == 1 })
        }
    }

    pub fn checked_generate_prime(bits: i32, safe: bool, add: Option<&BigNum>, rem: Option<&BigNum>) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, {
                let add_arg = add.map(|a| a.raw()).unwrap_or(ptr::mut_null());
                let rem_arg = rem.map(|r| r.raw()).unwrap_or(ptr::mut_null());

                BN_generate_prime_ex(r.raw(), bits as c_int, safe as c_int, add_arg, rem_arg, ptr::null()) == 1
            })
        }
    }

    pub fn is_prime(&self, checks: i32) -> Result<bool, SslError> {
        unsafe {
            with_ctx!(ctx, {
                Ok(BN_is_prime_ex(self.raw(), checks as c_int, ctx, ptr::null()) == 1)
            })
        }
    }

    pub fn is_prime_fast(&self, checks: i32, do_trial_division: bool) -> Result<bool, SslError> {
        unsafe {
            with_ctx!(ctx, {
                Ok(BN_is_prime_fasttest_ex(self.raw(), checks as c_int, ctx, do_trial_division as c_int, ptr::null()) == 1)
            })
        }
    }

    pub fn checked_new_random(bits: i32, prop: RNGProperty, odd: bool) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_rand(r.raw(), bits as c_int, prop as c_int, odd as c_int) == 1 })
        }
    }

    pub fn checked_new_pseudo_random(bits: i32, prop: RNGProperty, odd: bool) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_pseudo_rand(r.raw(), bits as c_int, prop as c_int, odd as c_int) == 1 })
        }
    }

    pub fn checked_rand_in_range(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_rand_range(r.raw(), self.raw()) == 1 })
        }
    }

    pub fn checked_pseudo_rand_in_range(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_pseudo_rand_range(r.raw(), self.raw()) == 1 })
        }
    }

    pub fn set_bit(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if BN_set_bit(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn clear_bit(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if BN_clear_bit(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn is_bit_set(&self, n: i32) -> bool {
        unsafe {
            BN_is_bit_set(self.raw(), n as c_int) == 1
        }
    }

    pub fn mask_bits(&mut self, n: i32) -> Result<(), SslError> {
        unsafe {
            if BN_mask_bits(self.raw(), n as c_int) == 1 {
                Ok(())
            } else {
                Err(SslError::get())
            }
        }
    }

    pub fn checked_shl1(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_lshift1(r.raw(), self.raw()) == 1 })
        }
    }

    pub fn checked_shr1(&self) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_rshift1(r.raw(), self.raw()) == 1 })
        }
    }

    pub fn checked_add(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_add(r.raw(), self.raw(), a.raw()) == 1 })
        }
    }

    pub fn checked_sub(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_sub(r.raw(), self.raw(), a.raw()) == 1 })
        }
    }

    pub fn checked_mul(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_mul(r.raw(), self.raw(), a.raw(), ctx) == 1 })
        }
    }

    pub fn checked_div(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_div(r.raw(), ptr::mut_null(), self.raw(), a.raw(), ctx) == 1 })
        }
    }

    pub fn checked_mod(&self, a: &BigNum) -> Result<BigNum, SslError> {
        unsafe {
            with_bn_in_ctx!(r, ctx, { BN_div(ptr::mut_null(), r.raw(), self.raw(), a.raw(), ctx) == 1 })
        }
    }

    pub fn checked_shl(&self, a: &i32) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_lshift(r.raw(), self.raw(), *a as c_int) == 1 })
        }
    }

    pub fn checked_shr(&self, a: &i32) -> Result<BigNum, SslError> {
        unsafe {
            with_bn!(r, { BN_rshift(r.raw(), self.raw(), *a as c_int) == 1 })
        }
    }

    pub fn negate(&mut self) {
        unsafe {
            BN_set_negative(self.raw(), !self.is_negative() as c_int)
        }
    }

    pub fn abs_cmp(&self, oth: BigNum) -> Ordering {
        unsafe {
            let res = BN_ucmp(self.raw(), oth.raw()) as i32;
            if res < 0 {
                Less
            } else if res > 0 {
                Greater
            } else {
                Equal
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        unsafe {
            (*self.raw()).neg == 1
        }
    }

    pub fn num_bits(&self) -> i32 {
        unsafe {
            BN_num_bits(self.raw()) as i32
        }
    }

    pub fn num_bytes(&self) -> i32 {
        (self.num_bits() + 7) / 8
    }

    unsafe fn raw(&self) -> *mut BIGNUM {
        let BigNum(n) = *self;
        n
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let size = self.num_bytes() as uint;
        let mut v = Vec::with_capacity(size);
        unsafe {
            BN_bn2bin(self.raw(), v.as_mut_ptr());
            v.set_len(size);
        }
        v
    }

    pub fn to_dec_str(&self) -> String {
        unsafe {
            let buf = BN_bn2dec(self.raw());
            assert!(!buf.is_null());
            let c_str = CString::new(buf, false);
            let str = c_str.as_str().unwrap().to_string();
            CRYPTO_free(buf);
            str
        }
    }
}

impl fmt::Show for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_dec_str())
    }
}

impl One for BigNum {
    fn one() -> BigNum {
        BigNum::new_from(1).unwrap()
    }
}

impl Zero for BigNum {
    fn zero() -> BigNum {
        BigNum::new_from(0).unwrap()
    }
    fn is_zero(&self) -> bool {
        unsafe {
            BN_is_zero(self.raw()) == 1
        }
    }
}

impl Eq for BigNum { }
impl PartialEq for BigNum {
    fn eq(&self, oth: &BigNum) -> bool {
        unsafe {
            BN_cmp(self.raw(), oth.raw()) == 0
        }
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
            let v = BN_cmp(self.raw(), oth.raw());
            let ret =
                if v == 0 {
                    Equal
                } else if v < 0 {
                    Less
                } else {
                    Greater
                };
            Some(ret)
        }
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe {
            if !self.raw().is_null() {
                BN_clear_free(self.raw());
            }
        }
    }
}

pub mod unchecked {
    use super::{BIGNUM, BigNum};

    extern {
        fn BN_dup(n: *mut BIGNUM) -> *mut BIGNUM;
    }

    impl Add<BigNum, BigNum> for BigNum {
        fn add(&self, oth: &BigNum) -> BigNum {
            self.checked_add(oth).unwrap()
        }
    }

    impl Sub<BigNum, BigNum> for BigNum {
        fn sub(&self, oth: &BigNum) -> BigNum {
            self.checked_sub(oth).unwrap()
        }
    }

    impl Mul<BigNum, BigNum> for BigNum {
        fn mul(&self, oth: &BigNum) -> BigNum {
            self.checked_mul(oth).unwrap()
        }
    }

    impl Div<BigNum, BigNum> for BigNum {
        fn div(&self, oth: &BigNum) -> BigNum {
            self.checked_div(oth).unwrap()
        }
    }

    impl Rem<BigNum, BigNum> for BigNum {
        fn rem(&self, oth: &BigNum) -> BigNum {
            self.checked_mod(oth).unwrap()
        }
    }

    impl Shl<i32, BigNum> for BigNum {
        fn shl(&self, n: &i32) -> BigNum {
            self.checked_shl(n).unwrap()
        }
    }

    impl Shr<i32, BigNum> for BigNum {
        fn shr(&self, n: &i32) -> BigNum {
            self.checked_shr(n).unwrap()
        }
    }

    impl Clone for BigNum {
        fn clone(&self) -> BigNum {
            unsafe {
                let r = BN_dup(self.raw());
                if r.is_null() {
                    fail!("Unexpected null pointer from BN_dup(..)")
                } else {
                    BigNum(r)
                }
            }
        }
    }

    impl Neg<BigNum> for BigNum {
        fn neg(&self) -> BigNum {
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
        let v1 = BigNum::new_from_slice(vec.as_slice()).unwrap();

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
