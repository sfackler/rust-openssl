use std::libc::c_int;
use std::{vec,str};

#[link_args = "-lcrypto"]
#[abi = "cdecl"]
extern {
    fn PKCS5_PBKDF2_HMAC_SHA1(pass: *u8, passlen: c_int,
                            salt: *u8, saltlen: c_int,
                            iter: c_int, keylen: c_int,
                            out: *mut u8) -> c_int;
}

#[doc = "
Derives a key from a password and salt using the PBKDF2-HMAC-SHA1 algorithm.
"]
pub fn pbkdf2_hmac_sha1(pass: &str, salt: &[u8], iter: uint,
                        keylen: uint) -> ~[u8] {
    assert!(iter >= 1u);
    assert!(keylen >= 1u);

    do str::as_buf(pass) |pass_buf, pass_len| {
        do salt.as_imm_buf |salt_buf, salt_len| {
            let mut out = vec::with_capacity(keylen);

            do out.as_mut_buf |out_buf, _out_len| {
                unsafe {
                    let r = PKCS5_PBKDF2_HMAC_SHA1(
                        pass_buf, pass_len as c_int,
                        salt_buf, salt_len as c_int,
                        iter as c_int, keylen as c_int,
                        out_buf);

                    if r != 1 as c_int { fail!(); }
                }
            }

            unsafe { vec::raw::set_len(&mut out, keylen); }

            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from
    // http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
    #[test]
    fn test_pbkdf2_hmac_sha1() {
        assert!(pbkdf2_hmac_sha1(
            "password",
            "salt".as_bytes(),
            1u,
            20u
        ) == ~[
            0x0c_u8, 0x60_u8, 0xc8_u8, 0x0f_u8, 0x96_u8, 0x1f_u8, 0x0e_u8,
            0x71_u8, 0xf3_u8, 0xa9_u8, 0xb5_u8, 0x24_u8, 0xaf_u8, 0x60_u8,
            0x12_u8, 0x06_u8, 0x2f_u8, 0xe0_u8, 0x37_u8, 0xa6_u8
        ]);

        assert!(pbkdf2_hmac_sha1(
            "password",
            "salt".as_bytes(),
            2u,
            20u
        ) == ~[
            0xea_u8, 0x6c_u8, 0x01_u8, 0x4d_u8, 0xc7_u8, 0x2d_u8, 0x6f_u8,
            0x8c_u8, 0xcd_u8, 0x1e_u8, 0xd9_u8, 0x2a_u8, 0xce_u8, 0x1d_u8,
            0x41_u8, 0xf0_u8, 0xd8_u8, 0xde_u8, 0x89_u8, 0x57_u8
        ]);

        assert!(pbkdf2_hmac_sha1(
            "password",
            "salt".as_bytes(),
            4096u,
            20u
        ) == ~[
            0x4b_u8, 0x00_u8, 0x79_u8, 0x01_u8, 0xb7_u8, 0x65_u8, 0x48_u8,
            0x9a_u8, 0xbe_u8, 0xad_u8, 0x49_u8, 0xd9_u8, 0x26_u8, 0xf7_u8,
            0x21_u8, 0xd0_u8, 0x65_u8, 0xa4_u8, 0x29_u8, 0xc1_u8
        ]);

        assert!(pbkdf2_hmac_sha1(
            "password",
            "salt".as_bytes(),
            16777216u,
            20u
        ) == ~[
            0xee_u8, 0xfe_u8, 0x3d_u8, 0x61_u8, 0xcd_u8, 0x4d_u8, 0xa4_u8,
            0xe4_u8, 0xe9_u8, 0x94_u8, 0x5b_u8, 0x3d_u8, 0x6b_u8, 0xa2_u8,
            0x15_u8, 0x8c_u8, 0x26_u8, 0x34_u8, 0xe9_u8, 0x84_u8
        ]);

        assert!(pbkdf2_hmac_sha1(
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes(),
            4096u,
            25u
        ) == ~[
            0x3d_u8, 0x2e_u8, 0xec_u8, 0x4f_u8, 0xe4_u8, 0x1c_u8, 0x84_u8,
            0x9b_u8, 0x80_u8, 0xc8_u8, 0xd8_u8, 0x36_u8, 0x62_u8, 0xc0_u8,
            0xe4_u8, 0x4a_u8, 0x8b_u8, 0x29_u8, 0x1a_u8, 0x96_u8, 0x4c_u8,
            0xf2_u8, 0xf0_u8, 0x70_u8, 0x38_u8
        ]);

        assert!(pbkdf2_hmac_sha1(
            "pass\x00word",
            "sa\x00lt".as_bytes(),
            4096u,
            16u
        ) == ~[
            0x56_u8, 0xfa_u8, 0x6a_u8, 0xa7_u8, 0x55_u8, 0x48_u8, 0x09_u8,
            0x9d_u8, 0xcc_u8, 0x37_u8, 0xd7_u8, 0xf0_u8, 0x34_u8, 0x25_u8,
            0xe0_u8, 0xc3_u8
        ]);
    }
}
