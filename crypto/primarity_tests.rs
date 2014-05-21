use std::num::One;
use num::bigint::{BigUint, ToBigUint};
use num::Integer;
use rand;
use rand::Rng;
use crypto::mod_operations::mod_exp;

pub fn fermat_test(a: &mut BigUint, p: &mut BigUint) -> bool {
    let one: BigUint = One::one();
    return mod_exp(a, &mut p.sub(&one), p).eq(&one);
}

pub fn miller_rabin(n : &mut BigUint, t:uint) -> bool {
    let one: BigUint = One::one();
    let two = one.add(&one);
    if (*n).lt(&two) {
        return false;
    }
    else if (*n).eq(&two) {
        return true;
    }
    else if (*n).is_even() {
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

    let mut test_cnt = t.clone();
    while test_cnt > 0 {
        test_cnt -= 1;
        let mut a = ( rng.gen::<uint>() ).to_biguint().unwrap();
        a = a.mod_floor(&rng_lim).add(&two);
        let mut x = mod_exp( &mut a.clone(), &mut q.clone(), &n.clone());
        if x.eq(&one) {
            continue;
        }
        let mut found : bool = false;
        let mut check_cnt = k.clone();
        while check_cnt > 0 {
            check_cnt -= 1;
            if x.eq(&phi_n) {
                found = true;
                break;
            }
            x = (x.mul(&x)).mod_floor(n);
        }
        if found {
            continue;
        }
        return false;
    }
    return true;
}

#[cfg(test)]
mod tests {
    use num::bigint::ToBigUint;
    use crypto::primarity_tests::{fermat_test, miller_rabin};

    #[test]
    fn test_fermat_test_prime() {
        let a = (3u).to_biguint().unwrap();
        let p = (13u).to_biguint().unwrap();
        let res = fermat_test(&mut a.clone(), &mut p.clone());
        assert!(res == true);
    }
    #[test]
    fn test_fermat_test_carmichael_number() {
        /* 561 is Carmichael number */
        let a = (5u).to_biguint().unwrap();
        let p = (561u).to_biguint().unwrap();
        let res = fermat_test(&mut a.clone(), &mut p.clone());
        assert!(res == true);
    }
    #[test]
    fn test_fermat_test_composite() {
        let a = (3u).to_biguint().unwrap();
        let p = (49u).to_biguint().unwrap();
        let res = fermat_test(&mut a.clone(), &mut p.clone());
        assert!(res == false);
    }
    #[test]
    fn test_miller_rabin_prime() {
        let p = (71u).to_biguint().unwrap();
        let res = miller_rabin(&mut p.clone(), 50u);
        assert!(res == true);
    }
    #[test]
    fn test_miller_rabin_carmichael_number() {
        let p = (561u).to_biguint().unwrap();
        let res = miller_rabin(&mut p.clone(), 50u);
        assert!(res == false);
    }
    #[test]
    fn test_miller_rabin_composite() {
        let p = (303u).to_biguint().unwrap();
        let res = miller_rabin(&mut p.clone(), 50u);
        assert!(res == false);
    }
}