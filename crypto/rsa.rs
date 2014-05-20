use num::bigint::BigUint;
use num::bigint::ToBigUint;
use num::Integer;
use crypto::prime_number_generator::generate_prime_random_choice;
use crypto::primarity_tests::{inv_mod, mod_exp};

fn byte2biguint(number:&str) -> BigUint {
    let mut res = (0i).to_biguint().unwrap();
    for ch in number.chars().rev() {
        res = res.shl(&8u);
        let value = (ch as u8).to_biguint().unwrap();
        res = res.add(&value);
    }
    return res;
}

fn biguint2byte(number: &mut BigUint) -> ~str {
    let mut res = StrBuf::new();

    let zero = (0u).to_biguint().unwrap();
    let m = (256u).to_biguint().unwrap();
    while zero.lt(number) {
        let ch = number.mod_floor(&m);
        res.push_char( (ch.to_u64().unwrap() as u8) as char );
        *number = number.shr(&8u);
    }
    return res.into_owned();
}

pub struct RSAKey {
    modulus : BigUint, /* n */
    prime1  : BigUint, /* p */
    prime2  : BigUint, /* q */
    publicExponent : BigUint, /* e */
    privateExponent : BigUint, /* d */
}

fn load_public_key(pkey: &RSAKey) -> RSAKey {
    let zero = (1u).to_biguint().unwrap();
    return RSAKey {
        modulus         : pkey.modulus.clone(),
        prime1          : zero.clone(),
        prime2          : zero.clone(),
        publicExponent  : pkey.publicExponent.clone(),
        privateExponent : zero.clone()
    };
}

pub fn RSA_generate_key(primeLength: uint, publicExponent: BigUint) -> RSAKey {
    let one  = (1u).to_biguint().unwrap();

    let p = generate_prime_random_choice(primeLength);
    let q = generate_prime_random_choice(primeLength);
    let n = p.mul(&q);
    let e = publicExponent;

    // phi = (p-1)*(q-1)
    let phi = p.sub(&one.clone()).mul(&q.sub(&one.clone()));
    // Compute d = e**-1 mod(phi) to d*e = 1 mod(phi)
    let d = inv_mod(&mut e.clone(), &mut phi.clone());

    return RSAKey {
        modulus         : n,
        prime1          : p,
        prime2          : q,
        publicExponent  : e,
        privateExponent : d
    };
}

pub fn RSA_public_encrypt(ms: &str, pkey: &RSAKey) -> BigUint {
    let mut m = byte2biguint(ms);
    let mut e = pkey.publicExponent.clone();
    let n = pkey.modulus.clone();
    return mod_exp(&mut m, &mut e, &n);
}

pub fn RSA_private_decrypt(c: BigUint, pkey: &RSAKey) -> ~str {
    let mut d = pkey.privateExponent.clone();
    let n = pkey.modulus.clone();
    let mut m = mod_exp(&mut c.clone(), &mut d, &n);
    return biguint2byte(&mut m);
}

#[test]
fn test_encrypt() {
    let k0 = &RSA_generate_key(128u, (65537u).to_biguint().unwrap());
    let k1 = &load_public_key(k0.clone());

    let msg = "RSA";
    let emsg = RSA_public_encrypt(msg, k1);
    let dmsg = RSA_private_decrypt(emsg, k0);
    assert!(msg == dmsg)
}