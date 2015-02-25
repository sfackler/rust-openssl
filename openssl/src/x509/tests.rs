use serialize::hex::FromHex;
use std::io;
use std::path::Path;
use std::fs::File;

use crypto::hash::Type::{SHA256};
use x509::{X509, X509Generator};
use x509::KeyUsage::{DigitalSignature, KeyEncipherment};
use x509::ExtKeyUsage::{ClientAuth, ServerAuth};

#[test]
fn test_cert_gen() {
    let gen = X509Generator::new()
        .set_bitlength(2048)
        .set_valid_period(365*2)
        .set_CN("test_me")
        .set_sign_hash(SHA256)
        .set_usage(&[DigitalSignature, KeyEncipherment])
        .set_ext_usage(&[ClientAuth, ServerAuth]);

    let res = gen.generate();
    assert!(res.is_ok());

    let (cert, pkey) = res.unwrap();

    assert!(cert.write_pem(&mut io::sink()).is_ok());
    assert!(pkey.write_pem(&mut io::sink()).is_ok());

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters
}

#[test]
fn test_cert_loading() {
    let cert_path = Path::new("test/cert.pem");
    let mut file = File::open(&cert_path)
        .ok()
        .expect("Failed to open `test/cert.pem`");

    let cert = X509::from_pem(&mut file).ok().expect("Failed to load PEM");
    let fingerprint = cert.fingerprint(SHA256).unwrap();

    // Hash was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let hash_str = "46e3f1a6d17a41ce70d0c66ef51cee2ab4ba67cac8940e23f10c1f944b49fb5c";
    let hash_vec = hash_str.from_hex().unwrap();

    assert_eq!(fingerprint.as_slice(), hash_vec.as_slice());
}
