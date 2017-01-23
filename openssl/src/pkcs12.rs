//! PKCS #12 archives.

use ffi;
use libc::c_int;
use std::ptr;
use std::ffi::CString;

use cvt;
use pkey::{PKey, PKeyRef};
use error::ErrorStack;
use x509::X509;
use types::{OpenSslType, OpenSslTypeRef};
use stack::{Stack, StackRef};
use nid;

type_!(Pkcs12, Pkcs12Ref, ffi::PKCS12, ffi::PKCS12_free);

impl Pkcs12Ref {
    to_der!(ffi::i2d_PKCS12);

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

    /// Creates a new builder for a protected pkcs12 certificate.
    ///
    /// This uses the defaults from the OpenSSL library:
    ///
    /// * `nid_key` - `nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC`
    /// * `nid_cert` - `nid::PBE_WITHSHA1AND40BITRC2_CBC`
    /// * `iter` - `2048`
    /// * `mac_iter` - `2048`
    ///
    /// # Arguments
    ///
    /// * `password` - the password used to encrypt the key and certificate
    /// * `friendly_name` - user defined name for the certificate
    /// * `pkey` - key to store
    /// * `cert` - certificate to store
    pub fn builder<'a, 'b, 'c, 'd>(password: &'a str,
                                   friendly_name: &'b str,
                                   pkey: &'c PKeyRef,
                                   cert: &'d X509) -> Pkcs12Builder<'a, 'b, 'c, 'd> {
        ffi::init();

        Pkcs12Builder {
            password: password,
            friendly_name: friendly_name,
            pkey: pkey,
            cert: cert,
            chain: None,
            nid_key: nid::UNDEF, //nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC,
            nid_cert: nid::UNDEF, //nid::PBE_WITHSHA1AND40BITRC2_CBC,
            iter: ffi::PKCS12_DEFAULT_ITER as usize, // 2048
            mac_iter: ffi::PKCS12_DEFAULT_ITER as usize, // 2048
        }
    }
}

pub struct ParsedPkcs12 {
    pub pkey: PKey,
    pub cert: X509,
    pub chain: Stack<X509>,
}

pub struct Pkcs12Builder<'a, 'b, 'c, 'd> {
    password: &'a str,
    friendly_name: &'b str,
    pkey: &'c PKeyRef,
    cert: &'d X509,
    chain: Option<StackRef<X509>>,
    nid_key: nid::Nid,
    nid_cert: nid::Nid,
    iter: usize,
    mac_iter: usize,
}

// TODO: add chain option
impl<'a, 'b, 'c, 'd> Pkcs12Builder<'a, 'b, 'c, 'd> {
    /// The encryption algorithm that should be used for the key
    pub fn nid_key(&mut self, nid: nid::Nid) {
        self.nid_key = nid;
    }

    /// The encryption algorithm that should be used for the cert
    pub fn nid_cert(&mut self, nid: nid::Nid) {
        self.nid_cert = nid;
    }

    /// Key iteration count, default is 2048 as of this writing
    pub fn iter(&mut self, iter: usize) {
        self.iter = iter;
    }

    /// Mac iteration count, default is the same as key_iter default.
    ///
    /// Old implementation don't understand mac iterations greater than 1, (pre 1.0.1?), if such
    /// compatibility is required this should be set to 1
    pub fn mac_iter(&mut self, mac_iter: usize) {
        self.mac_iter = mac_iter;
    }

    pub fn build(self) -> Result<Pkcs12, ErrorStack> {
        unsafe {
            let pass = CString::new(self.password).unwrap();
            let friendly_name = CString::new(self.friendly_name).unwrap();
            let pkey = self.pkey.as_ptr();
            let cert = self.cert.as_ptr();
            let ca = self.chain.map(|ca| ca.as_ptr()).unwrap_or(ptr::null_mut());
            let nid_key = self.nid_key.as_raw();
            let nid_cert = self.nid_cert.as_raw();

            // According to the OpenSSL docs, keytype is a non-standard extension for MSIE,
            // It's values are KEY_SIG or KEY_EX, see the OpenSSL docs for more information:
            // https://www.openssl.org/docs/man1.0.2/crypto/PKCS12_create.html
            let keytype = 0;

            let pkcs12_ptr = ffi::PKCS12_create(pass.as_ptr(),
                                                friendly_name.as_ptr(),
                                                pkey,
                                                cert,
                                                ca,
                                                nid_key,
                                                nid_cert,
                                                self.iter as c_int,
                                                self.mac_iter as c_int,
                                                keytype);

            if pkcs12_ptr.is_null() {
                Err(ErrorStack::get())
            } else {
                Ok(Pkcs12::from_ptr(pkcs12_ptr))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use hash::MessageDigest;
    use hex::ToHex;

    use ::rsa::Rsa;
    use ::pkey::*;
    use ::x509::*;
    use ::x509::extension::*;

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

    #[test]
    fn create() {
        let subject_name = "ns.example.com";
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let gen = X509Generator::new()
                               .set_valid_period(365*2)
                               .add_name("CN".to_owned(), subject_name.to_string())
                               .set_sign_hash(MessageDigest::sha256())
                               .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));

        let cert = gen.sign(&pkey).unwrap();

        let pkcs12_builder = Pkcs12::builder("mypass", subject_name, &pkey, &cert);
        let pkcs12 = pkcs12_builder.build().unwrap();
        let der = pkcs12.to_der().unwrap();

        let pkcs12 = Pkcs12::from_der(&der).unwrap();
        let parsed = pkcs12.parse("mypass").unwrap();

        assert_eq!(parsed.cert.fingerprint(MessageDigest::sha1()).unwrap(), cert.fingerprint(MessageDigest::sha1()).unwrap());
        assert!(parsed.pkey.public_eq(&pkey));
    }
}
