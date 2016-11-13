//! PKCS #12 archives.

use ffi;
use std::ptr;
use std::ffi::CString;

use cvt;
use pkey::PKey;
use error::ErrorStack;
use x509::X509;
use types::{OpenSslType, OpenSslTypeRef};
use stack::Stack;

type_!(Pkcs12, Pkcs12Ref, ffi::PKCS12, ffi::PKCS12_free);

impl Pkcs12Ref {
    /// Extracts the contents of the `Pkcs12`.
    // FIXME should take an &[u8]
    pub fn parse(&self, pass: &str) -> Result<ParsedPkcs12, ErrorStack> {
        unsafe {
            let pass = CString::new(pass).unwrap();

            let mut pkey = ptr::null_mut();
            let mut cert = ptr::null_mut();
            let mut chain = ptr::null_mut();

            try!(cvt(ffi::PKCS12_parse(self.as_ptr(),
                                       pass.as_ptr(),
                                       &mut pkey,
                                       &mut cert,
                                       &mut chain)));

            let pkey = PKey::from_ptr(pkey);
            let cert = X509::from_ptr(cert);
            let chain = Stack::from_ptr(chain);

            Ok(ParsedPkcs12 {
                pkey: pkey,
                cert: cert,
                chain: chain,
            })
        }
    }
}

impl Pkcs12 {
    from_der!(Pkcs12, ffi::d2i_PKCS12);
}

pub struct ParsedPkcs12 {
    pub pkey: PKey,
    pub cert: X509,
    pub chain: Stack<X509>,
}

#[cfg(test)]
mod test {
    use hash::MessageDigest;
    use hex::ToHex;

    use super::*;

    #[test]
    fn parse() {
        let der = include_bytes!("../test/identity.p12");
        let pkcs12 = Pkcs12::from_der(der).unwrap();
        let parsed = pkcs12.parse("mypass").unwrap();

        assert_eq!(parsed.cert.fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
                   "59172d9313e84459bcff27f967e79e6e9217e584");

        assert_eq!(parsed.chain.len(), 1);
        assert_eq!(parsed.chain[0].fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
                   "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875");
    }
}
