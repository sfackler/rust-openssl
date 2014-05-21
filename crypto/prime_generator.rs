use std::num::One;
use num::bigint::{BigUint, ToBigUint, RandBigInt};
use rand;
use crypto::primarity_tests::{fermat_test, miller_rabin};

fn generate_random_byte(primeLength: uint) -> BigUint {
    let mut rng = rand::task_rng();
    let mut res: BigUint = rng.gen_biguint(primeLength);

    let one:  BigUint   = One::one();
    let msb:  BigUint   = one.shl(&primeLength);
    let nmsb: BigUint   = msb.shr(&1u);
    res = res.bitor(&one).bitor(&msb).bitor(&nmsb);
    return res;
}

fn get_number_test(primeLength: uint) -> uint {
    /* values taken from table 4.4, HandBook of Applied Cryptography */
    let num_tests: uint;
    if primeLength >= 1300 {
        num_tests = 2;
    } else if primeLength >= 850 {
        num_tests = 3;
    } else if primeLength >= 650 {
        num_tests = 4;
    } else if primeLength >= 550 {
        num_tests = 5;
    } else if primeLength >= 450 {
        num_tests = 6;
    } else if primeLength >= 400 {
        num_tests = 7;
    } else if primeLength >= 350 {
        num_tests = 8;
    } else if primeLength >= 300 {
        num_tests = 9;
    } else if primeLength >= 250 {
        num_tests = 12;
    } else if primeLength >= 200 {
        num_tests = 15;
    } else if primeLength >= 150 {
        num_tests = 18;
    } else if primeLength >= 100 {
        num_tests = 27;
    } else {
        num_tests = 50;
    }
    return num_tests;
}

pub fn generate_prime_random_choice(primeLength: uint) -> BigUint {
    let num_tests = get_number_test(primeLength);
    let two = (2u).to_biguint().unwrap();

    loop {
        let prime_candidate = generate_random_byte(primeLength);

        if !fermat_test( &mut two.clone(), &mut prime_candidate.clone() ) {
            continue;
        }

        if miller_rabin(&mut prime_candidate.clone(), num_tests) {
            return prime_candidate;
        }
    }
}