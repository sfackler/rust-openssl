use libc::c_void;
use std::ffi::CStr;
use std::ptr;

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

/// Derives a key using the argon2id algorithm.
///
/// Requires OpenSSL 3.2.0 or newer.
#[allow(clippy::too_many_arguments)]
pub fn argon2id(
    pass: &[u8],
    salt: &[u8],
    ad: Option<&[u8]>,
    secret: Option<&[u8]>,
    mut iter: u32,
    mut threads: u32,
    mut lanes: u32,
    mut memcost: u32,
    out: &mut [u8],
) -> Result<(), ErrorStack> {
    // We only support single-threaded operation for now since rust-openssl doesn't
    // bind OSSL_set_max_threads
    assert!(threads == 1);
    let pass_field = CStr::from_bytes_with_nul(b"pass\0").unwrap();
    let salt_field = CStr::from_bytes_with_nul(b"salt\0").unwrap();
    let ad_field = CStr::from_bytes_with_nul(b"ad\0").unwrap();
    let secret_field = CStr::from_bytes_with_nul(b"secret\0").unwrap();
    let iter_field = CStr::from_bytes_with_nul(b"iter\0").unwrap();
    let size_field = CStr::from_bytes_with_nul(b"size\0").unwrap();
    let threads_field = CStr::from_bytes_with_nul(b"threads\0").unwrap();
    let lanes_field = CStr::from_bytes_with_nul(b"lanes\0").unwrap();
    let memcost_field = CStr::from_bytes_with_nul(b"memcost\0").unwrap();
    unsafe {
        ffi::init();
        let mut params = vec![];
        let param_pass = ffi::OSSL_PARAM_construct_octet_string(
            pass_field.as_ptr(),
            pass.as_ptr() as *mut c_void,
            pass.len(),
        );
        params.push(param_pass);
        let param_salt = ffi::OSSL_PARAM_construct_octet_string(
            salt_field.as_ptr(),
            salt.as_ptr() as *mut c_void,
            salt.len(),
        );
        params.push(param_salt);
        if let Some(ad) = ad {
            let param_ad = ffi::OSSL_PARAM_construct_octet_string(
                ad_field.as_ptr(),
                ad.as_ptr() as *mut c_void,
                ad.len(),
            );
            params.push(param_ad);
        }
        if let Some(secret) = secret {
            let param_secret = ffi::OSSL_PARAM_construct_octet_string(
                secret_field.as_ptr(),
                secret.as_ptr() as *mut c_void,
                secret.len(),
            );
            params.push(param_secret);
        }
        let param_threads = ffi::OSSL_PARAM_construct_uint(threads_field.as_ptr(), &mut threads);
        params.push(param_threads);
        let param_lanes = ffi::OSSL_PARAM_construct_uint(lanes_field.as_ptr(), &mut lanes);
        params.push(param_lanes);
        let param_memcost = ffi::OSSL_PARAM_construct_uint(memcost_field.as_ptr(), &mut memcost);
        params.push(param_memcost);
        let param_iter = ffi::OSSL_PARAM_construct_uint(iter_field.as_ptr(), &mut iter);
        params.push(param_iter);
        let mut size = out.len() as u32;
        let param_size = ffi::OSSL_PARAM_construct_uint(size_field.as_ptr(), &mut size);
        params.push(param_size);
        let param_end = ffi::OSSL_PARAM_construct_end();
        params.push(param_end);

        let argon2id_field = CStr::from_bytes_with_nul(b"ARGON2ID\0").unwrap();
        let argon2 = cvt_p(ffi::EVP_KDF_fetch(
            ptr::null_mut(),
            argon2id_field.as_ptr(),
            ptr::null(),
        ))?; // This needs to be freed
        let ctx = cvt_p(ffi::EVP_KDF_CTX_new(argon2))?; // this also needs to be freed
        cvt(ffi::EVP_KDF_derive(
            ctx,
            out.as_mut_ptr(),
            out.len(),
            params.as_ptr(),
        ))
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn argon2id() {
        // RFC 9106 test vector for argon2id
        let pass = hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let secret = hex::decode("0303030303030303").unwrap();
        let ad = hex::decode("040404040404040404040404").unwrap();
        let expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

        let mut actual = [0 as u8; 32];
        super::argon2id(
            &pass,
            &salt,
            Some(&ad),
            Some(&secret),
            3,
            1,
            4,
            32,
            &mut actual,
        )
        .unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }

    #[test]
    fn argon2id_no_ad_secret() {
        // Test vector from OpenSSL
        let pass = "";
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let expected = "0a34f1abde67086c82e785eaf17c68382259a264f4e61b91cd2763cb75ac189a";

        let mut actual = [0 as u8; 32];
        super::argon2id(
            &pass.as_bytes(),
            &salt,
            None,
            None,
            3,
            1,
            4,
            32,
            &mut actual,
        )
        .unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }
}
