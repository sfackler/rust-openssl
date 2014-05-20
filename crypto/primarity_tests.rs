use num::bigint::BigUint;
use num::bigint::ToBigUint;
use num::bigint::BigInt;
use num::bigint::ToBigInt;
use num::Integer;
use rand;
use rand::Rng;

fn mod_mult(a : &mut BigUint, b : &mut BigUint, m : &BigUint) -> BigUint {
    let mut res = (0u).to_biguint().unwrap();
    *a = a.mod_floor(m);

    let zero = (0u).to_biguint().unwrap();
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
    let zero = (0u).to_biguint().unwrap();
    let mut res = (1u).to_biguint().unwrap();

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

fn extgcd(a: &mut BigInt, b: &mut BigInt) -> (BigInt, BigInt) {
    if (*a).lt(&b.clone()) {
        let c = a.clone();
        *a = b.clone();
        *b = c.clone();
    }
    let zero    = (0u).to_bigint().unwrap();
    let one     = (1u).to_bigint().unwrap();
    let minus   = (-1i32).to_bigint().unwrap();

    let ( mut q, mut r, mut xx, mut yy) = (zero.clone(), zero.clone(), zero.clone(), zero.clone());
    let ( mut xs0, mut xs1, mut ys0, mut ys1) = (one.clone(), zero.clone(), zero.clone(), one.clone());
    let mut is_plus = true;

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

    let (mut x, mut y) = (zero.clone(), zero.clone());
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

pub fn inv_mod(a: &mut BigUint, m: &BigUint) -> BigUint {
    let zero = (0u).to_bigint().unwrap();
    let (mut y,mut x) = extgcd(&mut a.to_bigint().unwrap(), &mut m.to_bigint().unwrap());
    if x.lt(&zero.clone()) {
        let mi = m.to_bigint().unwrap();
        x = x.add(&mi.clone());
    }
    return x.to_biguint().unwrap();
}

pub fn fetmat_test(a: &mut BigUint, p: &mut BigUint) -> bool {
    let one = (1u).to_biguint().unwrap();
    return mod_exp(a, &mut p.sub(&one), p).eq(&one);
}

pub fn miller_rabin(n :BigUint, t:uint) -> bool {
    let one = (1u).to_biguint().unwrap();
    let two = (2u).to_biguint().unwrap();
    if n.lt(&two) {
        return false;
    }
    else if n.eq(&two) {
        return true;
    }
    else if n.is_even() {
        return false;
    }

    let phi_n = n.sub(&one);
    let rng_lim = phi_n.sub(&two);
    let mut q = n.sub(&one);
    let mut k : i32 = 0;
    while q.is_odd() {
        k += 1;
        q = q.shr(&1u);
    }
    let mut rng = rand::task_rng();
    for i in range(0u,t) {
        let mut a = ( rng.gen::<uint>() ).to_biguint().unwrap();
        a = a.mod_floor(&rng_lim).add(&two);
        let mut x = mod_exp( &mut a.clone(), &mut q.clone(), &n.clone());
        if x.eq(&one) {
            continue;
        }
        let mut found : bool = false;
        for j in range(0,k) {
            if x.eq(&phi_n) {
                found = true;
                break;
            }
            x = (x.mul(&x)).mod_floor(&n);
        }
        if found {
            continue;
        }
        return false;
    }
    return true;
}