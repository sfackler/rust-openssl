use ffi;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::ptr;

use HashTypeInternals;
use crypto::hash::Type;
use crypto::pkey::PKey;
use error::ErrorStack;

#[cfg(ossl110)]
use ffi::{EVP_MD_CTX_new, EVP_MD_CTX_free};
#[cfg(any(ossl101, ossl102))]
use ffi::{EVP_MD_CTX_create as EVP_MD_CTX_new, EVP_MD_CTX_destroy as EVP_MD_CTX_free};

pub struct Signer<'a>(*mut ffi::EVP_MD_CTX, PhantomData<&'a PKey>);

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.0);
        }
    }
}

impl<'a> Signer<'a> {
    pub fn new(type_: Type, pkey: &'a PKey) -> Result<Signer<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = try_ssl_null!(EVP_MD_CTX_new());
            let r = ffi::EVP_DigestSignInit(ctx,
                                            ptr::null_mut(),
                                            type_.evp_md(),
                                            ptr::null_mut(),
                                            pkey.as_ptr());
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            Ok(Signer(ctx, PhantomData))
        }
    }

    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            try_ssl_if!(ffi::EVP_DigestUpdate(self.0, buf.as_ptr() as *const _, buf.len()) != 1);
            Ok(())
        }
    }

    pub fn finish(&self) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let mut len = 0;
            try_ssl_if!(ffi::EVP_DigestSignFinal(self.0, ptr::null_mut(), &mut len) != 1);
            let mut buf = vec![0; len];
            try_ssl_if!(ffi::EVP_DigestSignFinal(self.0, buf.as_mut_ptr() as *mut _, &mut len)
                    != 1);
            Ok(buf)
        }
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.update(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Verifier<'a>(*mut ffi::EVP_MD_CTX, PhantomData<&'a PKey>);

impl<'a> Drop for Verifier<'a> {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.0);
        }
    }
}

impl<'a> Verifier<'a> {
    pub fn new(type_: Type, pkey: &'a PKey) -> Result<Verifier<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = try_ssl_null!(EVP_MD_CTX_new());
            let r = ffi::EVP_DigestVerifyInit(ctx,
                                              ptr::null_mut(),
                                              type_.evp_md(),
                                              ptr::null_mut(),
                                              pkey.as_ptr());
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            Ok(Verifier(ctx, PhantomData))
        }
    }

    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            try_ssl_if!(ffi::EVP_DigestUpdate(self.0, buf.as_ptr() as *const _, buf.len()) != 1);
            Ok(())
        }
    }

    pub fn finish(&self, signature: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            try_ssl_if!(ffi::EVP_DigestVerifyFinal(self.0,
                                                   signature.as_ptr() as *const _,
                                                   signature.len()) != 1);
            Ok(())
        }
    }
}

impl<'a> Write for Verifier<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.update(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crypto::hash::Type;
    use crypto::sign::{Signer, Verifier};
    use crypto::rsa::RSA;
    use crypto::pkey::PKey;

    static INPUT: &'static [u8] =
        &[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74, 57,
             46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48,
             75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107,
             122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76, 121,
             57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83, 57, 112, 99,
             49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81];

    static SIGNATURE: &'static [u8] =
        &[112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174,
             27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60,
             150, 238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237,
             16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
             61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7, 16, 141, 178, 129,
             96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249, 217, 46, 10, 231, 111,
             36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18,
             142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129,
             253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 139, 93, 163,
             204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18, 115, 160, 95, 35,
             185, 232, 56, 250, 175, 132, 157, 105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195,
             212, 14, 96, 69, 34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202,
             234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160,
             112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238, 251, 71];

    #[test]
    fn test_sign() {
        let key = include_bytes!("../../test/rsa.pem");
        let private_key = RSA::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(Type::SHA256, &pkey).unwrap();
        signer.update(INPUT).unwrap();
        let result = signer.finish().unwrap();

        assert_eq!(result, SIGNATURE);
    }

    #[test]
    fn test_verify_ok() {
        let key = include_bytes!("../../test/rsa.pem");
        let private_key = RSA::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(Type::SHA256, &pkey).unwrap();
        verifier.update(INPUT).unwrap();
        verifier.finish(SIGNATURE).unwrap();
    }

    #[test]
    fn test_verify_err() {
        let key = include_bytes!("../../test/rsa.pem");
        let private_key = RSA::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(Type::SHA256, &pkey).unwrap();
        verifier.update(INPUT).unwrap();
        verifier.update(b"foobar").unwrap();
        assert!(verifier.finish(SIGNATURE).is_err());
    }
}
