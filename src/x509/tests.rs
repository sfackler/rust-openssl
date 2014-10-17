use serialize::hex::FromHex;
use std::io::{File, Open, Read};
use std::io::util::NullWriter;

use crypto::hash::{SHA256};
use x509::{X509, X509Generator, DigitalSignature, KeyEncipherment, ClientAuth, ServerAuth};

#[test]
fn test_cert_gen() {
    let gen = X509Generator::new()
        .set_bitlength(2048)
        .set_valid_period(365*2)
        .set_CN("test_me")
        .set_sign_hash(SHA256)
        .set_usage([DigitalSignature, KeyEncipherment])
        .set_ext_usage([ClientAuth, ServerAuth]);

    let res = gen.generate();
    assert!(res.is_ok());

    let (cert, pkey) = res.unwrap();

    let mut writer = NullWriter;
    assert!(cert.write_pem(&mut writer).is_ok());
    assert!(pkey.write_pem(&mut writer).is_ok());

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters
}

#[test]
fn test_cert_loading() {
    let cert_path = Path::new("test/cert.pem");
    let mut file = File::open_mode(&cert_path, Open, Read)
        .ok()
        .expect("Failed to open `test/cert.pem`");

    let cert = X509::from_pem(&mut file).ok().expect("Failed to load PEM");
    let fingerprint = cert.fingerprint(SHA256).unwrap();

    // Hash was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let hash_str = "6204f6617e1af7495394250655f43600cd483e2dfc2005e92d0fe439d0723c34";
    let hash_vec = hash_str.from_hex().unwrap();

    assert_eq!(fingerprint.as_slice(), hash_vec.as_slice());
}
