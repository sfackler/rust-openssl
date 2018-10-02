use x509::{X509, X509Ref};
use x509::store::X509Store;
use ffi;
use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use stack::Stack;
use foreign_types::ForeignType;
use symm::Cipher;
use pkey::{HasPrivate, Public, PKeyRef};
use libc::c_int;
use std::ptr::null_mut;
use foreign_types::ForeignTypeRef;
use {cvt, cvt_p};

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS7;
    fn drop = ffi::PKCS7_free;

    /// A PKCS#7 structure.
    ///
    /// Contains signed and/or encrypted data.
    pub struct Pkcs7<T>;

    /// Reference to `Pkcs7`
    pub struct Pkcs7Ref<T>;
}

bitflags! {
    pub struct PKCS7Flags: c_int {
        const PKCS7_TEXT = ffi::PKCS7_TEXT;
        const PKCS7_NOCERTS = ffi::PKCS7_NOCERTS;
        const PKCS7_NOSIGS = ffi::PKCS7_NOSIGS;
        const PKCS7_NOCHAIN = ffi::PKCS7_NOCHAIN;
        const PKCS7_NOINTERN = ffi::PKCS7_NOINTERN;
        const PKCS7_NOVERIFY = ffi::PKCS7_NOVERIFY;
        const PKCS7_DETACHED = ffi::PKCS7_DETACHED;
        const PKCS7_BINARY = ffi::PKCS7_BINARY;
        const PKCS7_NOATTR = ffi::PKCS7_NOATTR;
        const PKCS7_NOSMIMECAP = ffi::PKCS7_NOSMIMECAP;
        const PKCS7_NOOLDMIMETYPE = ffi::PKCS7_NOOLDMIMETYPE;
        const PKCS7_CRLFEOL = ffi::PKCS7_CRLFEOL;
        const PKCS7_STREAM = ffi::PKCS7_STREAM;
        const PKCS7_NOCRL = ffi::PKCS7_NOCRL;
        const PKCS7_PARTIAL = ffi::PKCS7_PARTIAL;
        const PKCS7_REUSE_DIGEST = ffi::PKCS7_REUSE_DIGEST;
        #[cfg(not(any(ossl101, ossl102, libressl)))]
        const PKCS7_NO_DUAL_CONTENT = ffi::PKCS7_NO_DUAL_CONTENT;
    }
}

impl Pkcs7<Public> {
    /// Converts PKCS#7 structure to S/MIME format
    ///
    /// This corresponds to [`SMIME_write_PKCS7`].
    ///
    /// [`SMIME_write_PKCS7`]: https://www.openssl.org/docs/man1.1.0/crypto/SMIME_write_PKCS7.html
    pub fn to_smime(
        &self,
        input: &[u8],
        flags: PKCS7Flags
    ) -> Result<Vec<u8>, ErrorStack>
    {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;
        let output = MemBio::new()?;
        unsafe {
            cvt(
                ffi::SMIME_write_PKCS7(
                    output.as_ptr(),
                    self.0,
                    input_bio.as_ptr(),
                    flags.bits)
            ).and(
                Ok(output.get_buf().to_owned())
            )
        }
    }

    /// Parses a message in S/MIME format.
    ///
    /// This corresponds to [`SMIME_read_PKCS7`].
    ///
    /// [`SMIME_read_PKCS7`]: https://www.openssl.org/docs/man1.1.0/crypto/SMIME_read_PKCS7.html
    pub fn from_smime(input: &[u8], bcont: &mut Vec<u8>) -> Result<Self, ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;
        let mut bcount_bio = null_mut();
        let pkcs7 = unsafe {
            cvt_p(ffi::SMIME_read_PKCS7(input_bio.as_ptr(), &mut bcount_bio))?
        };
        bcont.clear();
        if !bcount_bio.is_null() {
            let bcount_bio = MemBio::from_ptr(bcount_bio);
            bcont.append(&mut bcount_bio.get_buf().to_vec());
        }
        unsafe {
            Ok(Pkcs7::from_ptr(pkcs7))
        }
    }

    to_pem! {
        /// Serializes the data into a PEM-encoded PKCS#7 structure.
        ///
        /// The output will have a header of `-----BEGIN PKCS7-----`.
        ///
        /// This corresponds to [`PEM_write_bio_PKCS7`].
        ///
        /// [`PEM_write_bio_PKCS7`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS7.html
        to_pem,
        ffi::PEM_write_bio_PKCS7
    }

    from_pem! {
        /// Deserializes a PEM-encoded PKCS#7 signature
        ///
        /// The input should have a header of `-----BEGIN PKCS7-----`.
        ///
        /// This corresponds to [`PEM_read_bio_PKCS7`].
        ///
        /// [`PEM_read_bio_PKCS7`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_PKCS7.html
        from_pem,
        Pkcs7<Public>,
        ffi::PEM_read_bio_PKCS7
    }

    /// Decrypts data using the provided private key.
    ///
    /// `pkey` is the recipient's private key, and `cert` is the recipient's
    /// certificate.
    ///
    /// Returns the decrypted message.
    ///
    /// This corresponds to [`PKCS7_decrypt`].
    ///
    /// [`PKCS7_decrypt`]: https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_decrypt.html
    pub fn decrypt<PT>(&self, pkey: &PKeyRef<PT>, cert: &X509Ref) -> Result<Vec<u8>, ErrorStack>
        where
            PT: HasPrivate
    {
        ffi::init();

        let output = MemBio::new()?;

        unsafe {
            cvt(ffi::PKCS7_decrypt(self.0, pkey.as_ptr(), cert.as_ptr(), output.as_ptr(), 0))
                .and(Ok(output.get_buf().to_owned()))
        }
    }

    /// Creates and returns a PKCS#7 `envelopedData` structure.
    ///
    /// `certs` is a list of recipient certificates. `input` is the content to be
    /// encrypted. `cipher` is the symmetric cipher to use. `flags` is an optional
    /// set of flags.
    ///
    /// This corresponds to [`PKCS7_encrypt`].
    ///
    /// [`PKCS7_encrypt`]: https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_encrypt.html
    pub fn encrypt(certs: &Stack<X509>, input: &[u8], cipher: Cipher, flags: PKCS7Flags) -> Result<Self, ErrorStack> {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;

        unsafe {
            cvt_p(ffi::PKCS7_encrypt(
                certs.as_ptr(),
                input_bio.as_ptr(),
                cipher.as_ptr(),
                flags.bits)
            ).map(|p| Pkcs7::from_ptr(p))
        }
    }

    /// Creates and returns a PKCS#7 `signedData` structure.
    ///
    /// `signcert` is the certificate to sign with, `pkey` is the corresponding
    /// private key. `certs` is an optional additional set of certificates to
    /// include in the PKCS#7 structure (for example any intermediate CAs in the
    /// chain).
    ///
    /// This corresponds to [`PKCS7_sign`].
    ///
    /// [`PKCS7_sign`]: https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_sign.html
    pub fn sign<PT>(
        signcert: &X509Ref,
        pkey: &PKeyRef<PT>,
        certs: &Stack<X509>,
        input: &[u8],
        flags: PKCS7Flags
    ) -> Result<Self, ErrorStack>
    where
        PT: HasPrivate
    {
        ffi::init();

        let input_bio = MemBioSlice::new(input)?;
        unsafe {
            cvt_p(ffi::PKCS7_sign(
                signcert.as_ptr(),
                pkey.as_ptr(),
                certs.as_ptr(),
                input_bio.as_ptr(),
                flags.bits)
            ).map(|p| Pkcs7::from_ptr(p))
        }
    }

    /// Verifies the PKCS#7 `signedData` structure contained by `&self`.
    ///
    /// `certs` is a set of certificates in which to search for the signer's
    /// certificate. `store` is a trusted certificate store (used for chain
    /// verification). `indata` is the signed data if the content is not present
    /// in `&self`. The content is written to `out` if it is not `None`.
    ///
    /// This corresponds to [`PKCS7_verify`].
    ///
    /// [`PKCS7_verify`]: https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_verify.html
    pub fn verify(
        &self,
        certs: &Stack<X509>,
        store: &X509Store,
        indata: Option<&[u8]>,
        out: Option<&mut Vec<u8>>,
        flags: PKCS7Flags
    ) -> Result<bool, ErrorStack> {
        ffi::init();

        let out_bio = MemBio::new()?;

        let indata_bio = match indata {
            Some(data) => Some(MemBioSlice::new(data)?),
            None => None,
        };
        let indata_bio_ptr = indata_bio.as_ref().map_or(null_mut(), |p| p.as_ptr());

        let result = unsafe {
            cvt(ffi::PKCS7_verify(
                self.0,
                certs.as_ptr(),
                store.as_ptr(),
                indata_bio_ptr,
                out_bio.as_ptr(),
                flags.bits))
            .map(|r| r == 1)
        };

        if let Some(data) = out {
            data.clear();
            data.append(&mut out_bio.get_buf().to_vec());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use x509::X509;
    use x509::store::X509StoreBuilder;
    use symm::Cipher;
    use pkcs7::{Pkcs7, PKCS7Flags};
    use pkey::{PKey, Public};
    use stack::Stack;

    #[test]
    fn encrypt_decrypt_test() {
        let cert = include_bytes!("../test/certs.pem");
        let cert = X509::from_pem(cert).unwrap();
        let mut certs = Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let message: String = String::from("foo");
        let cypher = Cipher::des_ede3_cbc();
        let flags = PKCS7Flags::PKCS7_STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();

        let pkcs7 = Pkcs7::encrypt(&certs, message.as_bytes(), cypher, flags).expect("should succeed");

        let encrypted = pkcs7.to_smime(message.as_bytes(), flags).expect("should succeed");

        let mut bcount = Vec::new();
        let pkcs7_decoded = Pkcs7::from_smime(encrypted.as_slice(), &mut bcount).expect("should succeed");

        let decoded = pkcs7_decoded.decrypt(&pkey, &cert).expect("should succeed");

        assert_eq!(decoded, message.into_bytes());
    }

    #[test]
    fn sign_verify_test_detached() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message: String = String::from("foo");
        let flags = PKCS7Flags::PKCS7_STREAM | PKCS7Flags::PKCS7_DETACHED;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 = Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7.to_smime(message.as_bytes(), flags).expect("should succeed");
        println!("{:?}", String::from_utf8(signed.clone()).unwrap());
        let mut bcount = Vec::new();
        let pkcs7_decoded = Pkcs7::from_smime(signed.as_slice(), &mut bcount).expect("should succeed");

        let mut output = Vec::new();
        let result = pkcs7_decoded.verify(&certs, &store, Some(message.as_bytes()), Some(&mut output), flags)
            .expect("should succeed");

        assert!(result);
        assert_eq!(message.clone().into_bytes(), output);
        assert_eq!(message.clone().into_bytes(), bcount);
    }

    #[test]
    fn sign_verify_test_normal() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message: String = String::from("foo");
        let flags = PKCS7Flags::PKCS7_STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 = Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7.to_smime(message.as_bytes(), flags).expect("should succeed");

        let mut bcount = Vec::new();
        let pkcs7_decoded = Pkcs7::<Public>::from_smime(signed.as_slice(), &mut bcount).expect("should succeed");

        let mut output = Vec::new();
        let result = pkcs7_decoded.verify(&certs, &store, None, Some(&mut output), flags).expect("should succeed");

        assert!(result);
        assert_eq!(message.clone().into_bytes(), output);
        let empty: Vec<u8> = Vec::new();
        assert_eq!(empty, bcount);
    }

    #[test]
    fn invalid_from_smime() {
        let input = String::from("Invalid SMIME Message");
        let mut bcount = Vec::new();

        let result = Pkcs7::from_smime(input.as_bytes(), &mut bcount);

        assert_eq!(result.is_err(), true)
    }
}
