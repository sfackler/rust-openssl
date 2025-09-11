#[cfg(ossl320)]
struct EvpKdf(*mut ffi::EVP_KDF);

#[cfg(ossl320)]
impl Drop for EvpKdf {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_KDF_free(self.0);
        }
    }
}

#[cfg(ossl320)]
struct EvpKdfCtx(*mut ffi::EVP_KDF_CTX);

#[cfg(ossl320)]
impl Drop for EvpKdfCtx {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_KDF_CTX_free(self.0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ARGON2")))] {
        use std::cmp;
        use std::ffi::CStr;
        use std::ptr;
        use foreign_types::ForeignTypeRef;
        use libc::c_char;
        use crate::{cvt, cvt_p};
        use crate::lib_ctx::LibCtxRef;
        use crate::error::ErrorStack;
        use crate::ossl_param::OsslParamBuilder;

        cstr_const!(OSSL_KDF_PARAM_PASSWORD, b"pass\0");
        cstr_const!(OSSL_KDF_PARAM_SALT, b"salt\0");
        cstr_const!(OSSL_KDF_PARAM_SECRET, b"secret\0");
        cstr_const!(OSSL_KDF_PARAM_ITER, b"iter\0");
        cstr_const!(OSSL_KDF_PARAM_SIZE, b"size\0");
        cstr_const!(OSSL_KDF_PARAM_THREADS, b"threads\0");
        cstr_const!(OSSL_KDF_PARAM_ARGON2_AD, b"ad\0");
        cstr_const!(OSSL_KDF_PARAM_ARGON2_LANES, b"lanes\0");
        cstr_const!(OSSL_KDF_PARAM_ARGON2_MEMCOST, b"memcost\0");

        cstr_const!(KDF_ARGON2D, b"ARGON2D\0");
        cstr_const!(KDF_ARGON2I, b"ARGON2I\0");
        cstr_const!(KDF_ARGON2ID, b"ARGON2ID\0");

        #[allow(clippy::too_many_arguments)]
        pub fn argon2d(
            ctx: Option<&LibCtxRef>,
            pass: &[u8],
            salt: &[u8],
            ad: Option<&[u8]>,
            secret: Option<&[u8]>,
            iter: u32,
            lanes: u32,
            memcost: u32,
            out: &mut [u8],
        ) -> Result<(), ErrorStack> {
            argon2_helper(KDF_ARGON2D, ctx, pass, salt, ad, secret, iter, lanes, memcost, out)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn argon2i(
            ctx: Option<&LibCtxRef>,
            pass: &[u8],
            salt: &[u8],
            ad: Option<&[u8]>,
            secret: Option<&[u8]>,
            iter: u32,
            lanes: u32,
            memcost: u32,
            out: &mut [u8],
        ) -> Result<(), ErrorStack> {
            argon2_helper(KDF_ARGON2I, ctx, pass, salt, ad, secret, iter, lanes, memcost, out)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn argon2id(
            ctx: Option<&LibCtxRef>,
            pass: &[u8],
            salt: &[u8],
            ad: Option<&[u8]>,
            secret: Option<&[u8]>,
            iter: u32,
            lanes: u32,
            memcost: u32,
            out: &mut [u8],
        ) -> Result<(), ErrorStack> {
            argon2_helper(KDF_ARGON2ID, ctx, pass, salt, ad, secret, iter, lanes, memcost, out)
        }

        /// Derives a key using the argon2* algorithms.
        ///
        /// To use multiple cores to process the lanes in parallel you must
        /// set a global max thread count using `OSSL_set_max_threads`. On
        /// builds with no threads all lanes will be processed sequentially.
        ///
        /// Requires OpenSSL 3.2.0 or newer.
        fn argon2_helper(
            kdf_identifier: &CStr,
            ctx: Option<&LibCtxRef>,
            pass: &[u8],
            salt: &[u8],
            ad: Option<&[u8]>,
            secret: Option<&[u8]>,
            iter: u32,
            lanes: u32,
            memcost: u32,
            out: &mut [u8],
        ) -> Result<(), ErrorStack> {
            let libctx = ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr);
            let max_threads = unsafe {
                ffi::init();
                ffi::OSSL_get_max_threads(libctx)
            };
            let mut threads = 1;
            // If max_threads is 0, then this isn't a threaded build.
            // If max_threads is > u32::MAX we need to clamp since
            // argon2id's threads parameter is a u32.
            if max_threads > 0 {
                threads = cmp::min(lanes, cmp::min(max_threads, u32::MAX as u64) as u32);
            }
            let mut bld = OsslParamBuilder::new()?;
            bld.add_octet_string(OSSL_KDF_PARAM_PASSWORD, pass)?;
            bld.add_octet_string(OSSL_KDF_PARAM_SALT, salt)?;
            bld.add_uint(OSSL_KDF_PARAM_THREADS, threads)?;
            bld.add_uint(OSSL_KDF_PARAM_ARGON2_LANES, lanes)?;
            bld.add_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, memcost)?;
            bld.add_uint(OSSL_KDF_PARAM_ITER, iter)?;
            let size = out.len() as u32;
            bld.add_uint(OSSL_KDF_PARAM_SIZE, size)?;
            if let Some(ad) = ad {
                bld.add_octet_string(OSSL_KDF_PARAM_ARGON2_AD, ad)?;
            }
            if let Some(secret) = secret {
                bld.add_octet_string(OSSL_KDF_PARAM_SECRET, secret)?;
            }
            let params = bld.to_param()?;
            unsafe {
                let argon2 = EvpKdf(cvt_p(ffi::EVP_KDF_fetch(
                    libctx,
                    kdf_identifier.as_ptr() as *const c_char,
                    ptr::null(),
                ))?);
                let ctx = EvpKdfCtx(cvt_p(ffi::EVP_KDF_CTX_new(argon2.0))?);
                cvt(ffi::EVP_KDF_derive(
                    ctx.0,
                    out.as_mut_ptr(),
                    out.len(),
                    params.as_ptr(),
                ))
                .map(|_| ())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ARGON2")))]
    fn argon2id() {
        // RFC 9106 test vector for argon2id
        let pass = hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let secret = hex::decode("0303030303030303").unwrap();
        let ad = hex::decode("040404040404040404040404").unwrap();
        let expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

        let mut actual = [0u8; 32];
        super::argon2id(
            None,
            &pass,
            &salt,
            Some(&ad),
            Some(&secret),
            3,
            4,
            32,
            &mut actual,
        )
        .unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }

    #[test]
    #[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ARGON2")))]
    fn argon2d() {
        // RFC 9106 test vector for argon2d
        let pass = hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let secret = hex::decode("0303030303030303").unwrap();
        let ad = hex::decode("040404040404040404040404").unwrap();
        let expected = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";

        let mut actual = [0u8; 32];
        super::argon2d(
            None,
            &pass,
            &salt,
            Some(&ad),
            Some(&secret),
            3,
            4,
            32,
            &mut actual,
        )
        .unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }

    #[test]
    #[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ARGON2")))]
    fn argon2i() {
        // RFC 9106 test vector for argon2i
        let pass = hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let secret = hex::decode("0303030303030303").unwrap();
        let ad = hex::decode("040404040404040404040404").unwrap();
        let expected = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8";

        let mut actual = [0u8; 32];
        super::argon2i(
            None,
            &pass,
            &salt,
            Some(&ad),
            Some(&secret),
            3,
            4,
            32,
            &mut actual,
        )
        .unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }

    #[test]
    #[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ARGON2")))]
    fn argon2id_no_ad_secret() {
        // Test vector from OpenSSL
        let pass = b"";
        let salt = hex::decode("02020202020202020202020202020202").unwrap();
        let expected = "0a34f1abde67086c82e785eaf17c68382259a264f4e61b91cd2763cb75ac189a";

        let mut actual = [0u8; 32];
        super::argon2id(None, pass, &salt, None, None, 3, 4, 32, &mut actual).unwrap();
        assert_eq!(hex::encode(&actual[..]), expected);
    }
}
