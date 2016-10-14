//! PKCS #12 archives.

use ffi;
use libc::{c_long, c_uchar};
use std::cmp;
use std::ptr;
use std::ffi::CString;

use crypto::pkey::PKey;
use error::ErrorStack;
use x509::X509;

/// A PKCS #12 archive.
pub struct Pkcs12(*mut ffi::PKCS12);

impl Drop for Pkcs12 {
    fn drop(&mut self) {
        unsafe { ffi::PKCS12_free(self.0); }
    }
}

impl Pkcs12 {
    /// Deserializes a `Pkcs12` structure from DER-encoded data.
    pub fn from_der(der: &[u8]) -> Result<Pkcs12, ErrorStack> {
        unsafe {
            ffi::init();
            let mut ptr = der.as_ptr() as *const c_uchar;
            let length = cmp::min(der.len(), c_long::max_value() as usize) as c_long;
            let p12 = try_ssl_null!(ffi::d2i_PKCS12(ptr::null_mut(), &mut ptr, length));
            Ok(Pkcs12(p12))
        }
    }

    /// Extracts the contents of the `Pkcs12`.
    pub fn parse(&self, pass: &str) -> Result<ParsedPkcs12, ErrorStack> {
        unsafe {
            let pass = CString::new(pass).unwrap();

            let mut pkey = ptr::null_mut();
            let mut cert = ptr::null_mut();
            let mut chain = ptr::null_mut();

            try_ssl!(ffi::PKCS12_parse(self.0, pass.as_ptr(), &mut pkey, &mut cert, &mut chain));

            let pkey = PKey::from_ptr(pkey);
            let cert = X509::from_ptr(cert);
            let chain = chain as *mut _;

            let mut chain_out = vec![];
            for i in 0..compat::OPENSSL_sk_num(chain) {
                let x509 = compat::OPENSSL_sk_value(chain, i);
                chain_out.push(X509::from_ptr(x509 as *mut _));
            }
            compat::OPENSSL_sk_free(chain as *mut _);

            Ok(ParsedPkcs12 {
                pkey: pkey,
                cert: cert,
                chain: chain_out,
                _p: (),
            })
        }
    }
}

pub struct ParsedPkcs12 {
    pub pkey: PKey,
    pub cert: X509,
    pub chain: Vec<X509>,
    _p: (),
}

#[cfg(ossl110)]
mod compat {
    pub use ffi::OPENSSL_sk_free;
    pub use ffi::OPENSSL_sk_num;
    pub use ffi::OPENSSL_sk_value;
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use libc::{c_int, c_void};
    use ffi;

    pub use ffi::sk_free as OPENSSL_sk_free;

    pub unsafe fn OPENSSL_sk_num(stack: *mut ffi::_STACK) -> c_int {
        (*stack).num
    }

    pub unsafe fn OPENSSL_sk_value(stack: *const ffi::_STACK, idx: c_int)
                                   -> *mut c_void {
        *(*stack).data.offset(idx as isize) as *mut c_void
    }
}

#[cfg(test)]
mod test {
    use crypto::hash::Type::SHA1;
    use serialize::hex::ToHex;

    use super::*;

    #[test]
    fn parse() {
        let der = include_bytes!("../../test/identity.p12");
        let pkcs12 = Pkcs12::from_der(der).unwrap();
        let parsed = pkcs12.parse("mypass").unwrap();

        assert_eq!(parsed.cert.fingerprint(SHA1).unwrap().to_hex(),
                   "59172d9313e84459bcff27f967e79e6e9217e584");

        assert_eq!(parsed.chain.len(), 1);
        assert_eq!(parsed.chain[0].fingerprint(SHA1).unwrap().to_hex(),
                   "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875");
    }
}
