use num::bigint::BigUint;
use num::bigint::ToBigUint;
use rand;
use rand::Rng;
use crypto::primarity_tests::{fetmat_test, miller_rabin};

fn generate_random_byte(primeLength: uint) -> BigUint {
    let zero = (0u).to_biguint().unwrap();
    let one  = (1u).to_biguint().unwrap();

    let mut result = (0u).to_biguint().unwrap();
    let mut rng = rand::task_rng();
    for bit in range(0,primeLength) {
        let mut i_bit = if rng.gen::<uint>()&1 == 1 { one.clone() } else { zero.clone() };
        if bit == 0 {
            //To ensure generated number is odd
            i_bit = one.clone();
        }
        else if bit >= primeLength-2 {
            //To ensure gerated number is enough big
            i_bit = one.clone();
        }
        else if bit >= primeLength-4 {
            //To ensure gerated number is enough small to avoid overflow
            //when use Incremental Search method to generate prime number.
            i_bit = zero.clone();
        }

        result = result.add(&i_bit.shl(&bit));
    }
    return result;
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

        if !fetmat_test( &mut two.clone(), &mut prime_candidate.clone() ) {
            continue;
        }

        if miller_rabin(prime_candidate.clone(), num_tests) {
            return prime_candidate;
        }
    }
}

pub fn generate_prime_incremental_search(primeLength: uint) -> BigUint {
    let num_tests = get_number_test(primeLength);

    let mut prime_candidate = generate_random_byte(primeLength);
    let two = (2u).to_biguint().unwrap();
    loop {
        prime_candidate = prime_candidate.add(&two.clone());
        if !fetmat_test( &mut two.clone(), &mut prime_candidate.clone() ) {
            continue;
        }
        if miller_rabin(prime_candidate.clone(), num_tests) {
            return prime_candidate;
        }
    }
}