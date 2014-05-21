use std::num::{Zero, One};
use num::bigint::{BigUint, BigInt, ToBigInt};
use num::Integer;

fn extgcd(a: &mut BigInt, b: &mut BigInt) -> (BigInt, BigInt) {
    let zero  : BigInt  = Zero::zero();
    let one   : BigInt  = One::one();
    let minus : BigInt  = zero.sub(&one.clone());

    let ( mut q, mut r, mut xx, mut yy): (BigInt, BigInt, BigInt, BigInt);
    let ( mut xs0, mut xs1, mut ys0, mut ys1) = (one.clone(), zero.clone(), zero.clone(), one.clone());
    let mut is_plus = true;

    if (*a).lt(&b.clone()) {
        let c = a.clone();
        *a = b.clone();
        *b = c.clone();
    }

    while !zero.eq(&b.clone()) {
        r = (*a).mod_floor(&b.clone());
        q = (*a).div(&b.clone());
        *a = b.clone();
        *b = r.clone();
        xx = xs1.clone();
        yy = ys1.clone();
        xs1 = q.mul(&xs1.clone()).add(&xs0.clone());
        ys1 = q.mul(&ys1.clone()).add(&ys0.clone());
        xs0 = xx.clone();
        ys0 = yy.clone();
        is_plus = !is_plus;
    }

    let (mut x, mut y): (BigInt, BigInt);
    if is_plus {
        x = xs0;
        y = ys0.mul(&minus);
    }
    else {
        x = xs0.mul(&minus);
        y = ys0;
    }
    return (x.to_bigint().unwrap(), y.to_bigint().unwrap());
}

pub fn mod_mult(a : &mut BigUint, b : &mut BigUint, m : &BigUint) -> BigUint {
    let zero: BigUint = Zero::zero();
    let mut res: BigUint = Zero::zero();
    *a = a.mod_floor(m);

    while zero.lt(b) {
        if b.is_odd() {
            res = res.add(a);
            if m.lt(&res) {
                res = res.sub(m);
            }
        }
        *a = a.shl(&1u);
        if m.lt(a) {
            *a = a.sub(m);
        }
        *b = b.shr(&1u);
    }

    return res;
}

pub fn mod_exp(n : &mut BigUint, e : &mut BigUint, m : &BigUint) -> BigUint {
    let zero: BigUint = Zero::zero();
    let mut res: BigUint = One::one();

    *n = n.mod_floor(m);
    while zero.lt(e) {
        if e.is_odd() {
            res = mod_mult(&mut res.clone(), &mut n.clone(), m);
        }
        *n = mod_mult(&mut n.clone(), &mut n.clone(), m);
        *e = e.shr(&1u);
    }
    return res;
}

pub fn inv_mod(a: &mut BigUint, m: &BigUint) -> BigUint {
    let zero: BigInt = Zero::zero();
    // The first element don't use. We know about x in "-my + ax = 1 mod(m)".
    let ( _, mut x) = extgcd(&mut a.to_bigint().unwrap(), &mut m.to_bigint().unwrap());
    if x.lt(&zero.clone()) {
        let mi = m.to_bigint().unwrap();
        x = x.add(&mi.clone());
    }
    return x.to_biguint().unwrap();
}

#[cfg(test)]
mod tests {
    use std::num::One;
    use num::bigint::ToBigUint;
    use crypto::mod_operations::{mod_mult, mod_exp, inv_mod};

    #[test]
    fn test_mod_mult() {
        let a   = (7u).to_biguint().unwrap();
        let b   = (11u).to_biguint().unwrap();
        let m   = (5u).to_biguint().unwrap();
        let ans = (2u).to_biguint().unwrap();
        let res = mod_mult(&mut a.clone(), &mut b.clone(), & m.clone());
        assert!(ans == res)
    }
    #[test]
    fn test_mod_exp() {
        let a   = (3u).to_biguint().unwrap();
        let b   = (5u).to_biguint().unwrap();
        let m   = (7u).to_biguint().unwrap();
        let ans = (5u).to_biguint().unwrap();
        let res = mod_exp(&mut a.clone(), &mut b.clone(), & m.clone());
        assert!(ans == res)
    }
    #[test]
    fn test_mod_inv() {
        let m   = (13u).to_biguint().unwrap();
        let a   = (7u).to_biguint().unwrap();
        let x = inv_mod(&mut a.clone(), &mut m.clone());
        let res = mod_mult(&mut a.clone(), &mut x.clone(), & m.clone());
        assert!(res == One::one());
    }
}