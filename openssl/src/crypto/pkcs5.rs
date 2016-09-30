use libc::c_int;
use std::ptr;
use ffi;

use HashTypeInternals;
use crypto::hash;
use crypto::symm;
use error::ErrorStack;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct KeyIvPair {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Derives a key and an IV from various parameters.
///
/// If specified `salt` must be 8 bytes in length.
///
/// If the total key and IV length is less than 16 bytes and MD5 is used then
/// the algorithm is compatible with the key derivation algorithm from PKCS#5
/// v1.5 or PBKDF1 from PKCS#5 v2.0.
///
/// New applications should not use this and instead use `pbkdf2_hmac_sha1` or
/// another more modern key derivation algorithm.
pub fn evp_bytes_to_key_pbkdf1_compatible(typ: symm::Type,
                                          message_digest_type: hash::Type,
                                          data: &[u8],
                                          salt: Option<&[u8]>,
                                          count: u32)
                                          -> Result<KeyIvPair, ErrorStack> {
    unsafe {
        let salt_ptr = match salt {
            Some(salt) => {
                assert_eq!(salt.len(), ffi::PKCS5_SALT_LEN as usize);
                salt.as_ptr()
            }
            None => ptr::null(),
        };

        ffi::init();

        let typ = typ.as_ptr();
        let message_digest_type = message_digest_type.evp_md();

        let len = ffi::EVP_BytesToKey(typ,
                                      message_digest_type,
                                      salt_ptr,
                                      data.as_ptr(),
                                      data.len() as c_int,
                                      count as c_int,
                                      ptr::null_mut(),
                                      ptr::null_mut());
        if len == 0 {
            return Err(ErrorStack::get());
        }

        let mut key = vec![0; len as usize];
        let mut iv = vec![0; len as usize];

        try_ssl!(ffi::EVP_BytesToKey(typ,
                                     message_digest_type,
                                     salt_ptr,
                                     data.as_ptr(),
                                     data.len() as c_int,
                                     count as c_int,
                                     key.as_mut_ptr(),
                                     iv.as_mut_ptr()));

        Ok(KeyIvPair { key: key, iv: iv })
    }
}

/// Derives a key from a password and salt using the PBKDF2-HMAC-SHA1 algorithm.
pub fn pbkdf2_hmac_sha1(pass: &[u8],
                        salt: &[u8],
                        iter: usize,
                        keylen: usize)
                        -> Result<Vec<u8>, ErrorStack> {
    unsafe {
        let mut out = vec![0; keylen];

        ffi::init();

        try_ssl!(ffi::PKCS5_PBKDF2_HMAC_SHA1(pass.as_ptr() as *const _,
                                             pass.len() as c_int,
                                             salt.as_ptr(),
                                             salt.len() as c_int,
                                             iter as c_int,
                                             keylen as c_int,
                                             out.as_mut_ptr()));
        Ok(out)
    }
}

/// Derives a key from a password and salt using the PBKDF2-HMAC algorithm with a digest function.
pub fn pbkdf2_hmac(pass: &[u8],
                   salt: &[u8],
                   iter: usize,
                   hash: hash::Type,
                   keylen: usize)
                   -> Result<Vec<u8>, ErrorStack> {
    unsafe {
        let mut out = vec![0; keylen];
        ffi::init();
        try_ssl!(ffi::PKCS5_PBKDF2_HMAC(pass.as_ptr() as *const _,
                                        pass.len() as c_int,
                                        salt.as_ptr(),
                                        salt.len() as c_int,
                                        iter as c_int,
                                        hash.evp_md(),
                                        keylen as c_int,
                                        out.as_mut_ptr()));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crypto::hash;
    use crypto::symm;

    // Test vectors from
    // http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
    #[test]
    fn test_pbkdf2_hmac_sha1() {
        assert_eq!(super::pbkdf2_hmac_sha1(b"password", b"salt", 1, 20).unwrap(),
                   vec![0x0c_u8, 0x60_u8, 0xc8_u8, 0x0f_u8, 0x96_u8, 0x1f_u8, 0x0e_u8, 0x71_u8,
                        0xf3_u8, 0xa9_u8, 0xb5_u8, 0x24_u8, 0xaf_u8, 0x60_u8, 0x12_u8, 0x06_u8,
                        0x2f_u8, 0xe0_u8, 0x37_u8, 0xa6_u8]);

        assert_eq!(super::pbkdf2_hmac_sha1(b"password", b"salt", 2, 20).unwrap(),
                   vec![0xea_u8, 0x6c_u8, 0x01_u8, 0x4d_u8, 0xc7_u8, 0x2d_u8, 0x6f_u8, 0x8c_u8,
                        0xcd_u8, 0x1e_u8, 0xd9_u8, 0x2a_u8, 0xce_u8, 0x1d_u8, 0x41_u8, 0xf0_u8,
                        0xd8_u8, 0xde_u8, 0x89_u8, 0x57_u8]);

        assert_eq!(super::pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20).unwrap(),
                   vec![0x4b_u8, 0x00_u8, 0x79_u8, 0x01_u8, 0xb7_u8, 0x65_u8, 0x48_u8, 0x9a_u8,
                        0xbe_u8, 0xad_u8, 0x49_u8, 0xd9_u8, 0x26_u8, 0xf7_u8, 0x21_u8, 0xd0_u8,
                        0x65_u8, 0xa4_u8, 0x29_u8, 0xc1_u8]);

        assert_eq!(super::pbkdf2_hmac_sha1(b"password", b"salt", 16777216, 20).unwrap(),
                   vec![0xee_u8, 0xfe_u8, 0x3d_u8, 0x61_u8, 0xcd_u8, 0x4d_u8, 0xa4_u8, 0xe4_u8,
                        0xe9_u8, 0x94_u8, 0x5b_u8, 0x3d_u8, 0x6b_u8, 0xa2_u8, 0x15_u8, 0x8c_u8,
                        0x26_u8, 0x34_u8, 0xe9_u8, 0x84_u8]);

        assert_eq!(super::pbkdf2_hmac_sha1(b"passwordPASSWORDpassword",
                                           b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                           4096,
                                           25).unwrap(),
                   vec![0x3d_u8, 0x2e_u8, 0xec_u8, 0x4f_u8, 0xe4_u8, 0x1c_u8, 0x84_u8, 0x9b_u8,
                        0x80_u8, 0xc8_u8, 0xd8_u8, 0x36_u8, 0x62_u8, 0xc0_u8, 0xe4_u8, 0x4a_u8,
                        0x8b_u8, 0x29_u8, 0x1a_u8, 0x96_u8, 0x4c_u8, 0xf2_u8, 0xf0_u8, 0x70_u8,
                        0x38_u8]);

        assert_eq!(super::pbkdf2_hmac_sha1(b"pass\x00word", b"sa\x00lt", 4096, 16).unwrap(),
                   vec![0x56_u8, 0xfa_u8, 0x6a_u8, 0xa7_u8, 0x55_u8, 0x48_u8, 0x09_u8, 0x9d_u8,
                        0xcc_u8, 0x37_u8, 0xd7_u8, 0xf0_u8, 0x34_u8, 0x25_u8, 0xe0_u8, 0xc3_u8]);
    }

    // Test vectors from
    // https://git.lysator.liu.se/nettle/nettle/blob/nettle_3.1.1_release_20150424/testsuite/pbkdf2-test.c
    #[test]
    fn test_pbkdf2_hmac_sha256() {
        assert_eq!(super::pbkdf2_hmac(b"passwd", b"salt", 1, hash::Type::SHA256, 16).unwrap(),
                   vec![0x55_u8, 0xac_u8, 0x04_u8, 0x6e_u8, 0x56_u8, 0xe3_u8, 0x08_u8, 0x9f_u8,
                        0xec_u8, 0x16_u8, 0x91_u8, 0xc2_u8, 0x25_u8, 0x44_u8, 0xb6_u8, 0x05_u8]);

        assert_eq!(super::pbkdf2_hmac(b"Password", b"NaCl", 80000, hash::Type::SHA256, 16).unwrap(),
                   vec![0x4d_u8, 0xdc_u8, 0xd8_u8, 0xf6_u8, 0x0b_u8, 0x98_u8, 0xbe_u8, 0x21_u8,
                        0x83_u8, 0x0c_u8, 0xee_u8, 0x5e_u8, 0xf2_u8, 0x27_u8, 0x01_u8, 0xf9_u8]);
    }

    // Test vectors from
    // https://git.lysator.liu.se/nettle/nettle/blob/nettle_3.1.1_release_20150424/testsuite/pbkdf2-test.c
    #[test]
    fn test_pbkdf2_hmac_sha512() {
        assert_eq!(super::pbkdf2_hmac(b"password", b"NaCL", 1, hash::Type::SHA512, 64).unwrap(),
                   vec![0x73_u8, 0xde_u8, 0xcf_u8, 0xa5_u8, 0x8a_u8, 0xa2_u8, 0xe8_u8, 0x4f_u8,
                        0x94_u8, 0x77_u8, 0x1a_u8, 0x75_u8, 0x73_u8, 0x6b_u8, 0xb8_u8, 0x8b_u8,
                        0xd3_u8, 0xc7_u8, 0xb3_u8, 0x82_u8, 0x70_u8, 0xcf_u8, 0xb5_u8, 0x0c_u8,
                        0xb3_u8, 0x90_u8, 0xed_u8, 0x78_u8, 0xb3_u8, 0x05_u8, 0x65_u8, 0x6a_u8,
                        0xf8_u8, 0x14_u8, 0x8e_u8, 0x52_u8, 0x45_u8, 0x2b_u8, 0x22_u8, 0x16_u8,
                        0xb2_u8, 0xb8_u8, 0x09_u8, 0x8b_u8, 0x76_u8, 0x1f_u8, 0xc6_u8, 0x33_u8,
                        0x60_u8, 0x60_u8, 0xa0_u8, 0x9f_u8, 0x76_u8, 0x41_u8, 0x5e_u8, 0x9f_u8,
                        0x71_u8, 0xea_u8, 0x47_u8, 0xf9_u8, 0xe9_u8, 0x06_u8, 0x43_u8, 0x06_u8]);

        assert_eq!(super::pbkdf2_hmac(b"pass\0word", b"sa\0lt", 1, hash::Type::SHA512, 64).unwrap(),
                   vec![0x71_u8, 0xa0_u8, 0xec_u8, 0x84_u8, 0x2a_u8, 0xbd_u8, 0x5c_u8, 0x67_u8,
                        0x8b_u8, 0xcf_u8, 0xd1_u8, 0x45_u8, 0xf0_u8, 0x9d_u8, 0x83_u8, 0x52_u8,
                        0x2f_u8, 0x93_u8, 0x36_u8, 0x15_u8, 0x60_u8, 0x56_u8, 0x3c_u8, 0x4d_u8,
                        0x0d_u8, 0x63_u8, 0xb8_u8, 0x83_u8, 0x29_u8, 0x87_u8, 0x10_u8, 0x90_u8,
                        0xe7_u8, 0x66_u8, 0x04_u8, 0xa4_u8, 0x9a_u8, 0xf0_u8, 0x8f_u8, 0xe7_u8,
                        0xc9_u8, 0xf5_u8, 0x71_u8, 0x56_u8, 0xc8_u8, 0x79_u8, 0x09_u8, 0x96_u8,
                        0xb2_u8, 0x0f_u8, 0x06_u8, 0xbc_u8, 0x53_u8, 0x5e_u8, 0x5a_u8, 0xb5_u8,
                        0x44_u8, 0x0d_u8, 0xf7_u8, 0xe8_u8, 0x78_u8, 0x29_u8, 0x6f_u8, 0xa7_u8]);

        assert_eq!(super::pbkdf2_hmac(b"passwordPASSWORDpassword",
                                      b"salt\0\0\0",
                                      50,
                                      hash::Type::SHA512,
                                      64).unwrap(),
                   vec![0x01_u8, 0x68_u8, 0x71_u8, 0xa4_u8, 0xc4_u8, 0xb7_u8, 0x5f_u8, 0x96_u8,
                        0x85_u8, 0x7f_u8, 0xd2_u8, 0xb9_u8, 0xf8_u8, 0xca_u8, 0x28_u8, 0x02_u8,
                        0x3b_u8, 0x30_u8, 0xee_u8, 0x2a_u8, 0x39_u8, 0xf5_u8, 0xad_u8, 0xca_u8,
                        0xc8_u8, 0xc9_u8, 0x37_u8, 0x5f_u8, 0x9b_u8, 0xda_u8, 0x1c_u8, 0xcd_u8,
                        0x1b_u8, 0x6f_u8, 0x0b_u8, 0x2f_u8, 0xc3_u8, 0xad_u8, 0xda_u8, 0x50_u8,
                        0x54_u8, 0x12_u8, 0xe7_u8, 0x9d_u8, 0x89_u8, 0x00_u8, 0x56_u8, 0xc6_u8,
                        0x2e_u8, 0x52_u8, 0x4c_u8, 0x7d_u8, 0x51_u8, 0x15_u8, 0x4b_u8, 0x1a_u8,
                        0x85_u8, 0x34_u8, 0x57_u8, 0x5b_u8, 0xd0_u8, 0x2d_u8, 0xee_u8, 0x39_u8]);
    }
    #[test]
    fn test_evp_bytes_to_key_pbkdf1_compatible() {
        let salt = [16_u8, 34_u8, 19_u8, 23_u8, 141_u8, 4_u8, 207_u8, 221_u8];

        let data = [143_u8, 210_u8, 75_u8, 63_u8, 214_u8, 179_u8, 155_u8, 241_u8, 242_u8, 31_u8,
                    154_u8, 56_u8, 198_u8, 145_u8, 192_u8, 64_u8, 2_u8, 245_u8, 167_u8, 220_u8,
                    55_u8, 119_u8, 233_u8, 136_u8, 139_u8, 27_u8, 71_u8, 242_u8, 119_u8, 175_u8,
                    65_u8, 207_u8];



        let expected_key = vec![249_u8, 115_u8, 114_u8, 97_u8, 32_u8, 213_u8, 165_u8, 146_u8,
                                58_u8, 87_u8, 234_u8, 3_u8, 43_u8, 250_u8, 97_u8, 114_u8, 26_u8,
                                98_u8, 245_u8, 246_u8, 238_u8, 177_u8, 229_u8, 161_u8, 183_u8,
                                224_u8, 174_u8, 3_u8, 6_u8, 244_u8, 236_u8, 255_u8];
        let expected_iv = vec![4_u8, 223_u8, 153_u8, 219_u8, 28_u8, 142_u8, 234_u8, 68_u8, 227_u8,
                               69_u8, 98_u8, 107_u8, 208_u8, 14_u8, 236_u8, 60_u8, 0_u8, 0_u8,
                               0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8,
                               0_u8, 0_u8, 0_u8];

        assert_eq!(super::evp_bytes_to_key_pbkdf1_compatible(symm::Type::AES_256_CBC,
                                                             hash::Type::SHA1,
                                                             &data,
                                                             Some(&salt),
                                                             1).unwrap(),
                   super::KeyIvPair {
                       key: expected_key,
                       iv: expected_iv,
                   });
    }
}
