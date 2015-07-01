use serialize::hex::FromHex;
use std::io;
use std::path::Path;
use std::fs::File;

use crypto::hash::Type::{SHA256};
use x509::{X509, X509Generator};
use x509::KeyUsage::{DigitalSignature, KeyEncipherment};
use x509::ExtKeyUsage::{ClientAuth, ServerAuth};
use nid::Nid;

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

    assert_eq!(pkey.save_pub(), cert.public_key().save_pub());
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
    let hash_str = "db400bb62f1b1f29c3b8f323b8f7d9dea724fdcd67104ef549c772ae3749655b";
    let hash_vec = hash_str.from_hex().unwrap();

    assert_eq!(fingerprint, hash_vec);
}

#[test]
fn test_subject_read_cn() {
    let cert_path = Path::new("test/cert.pem");
    let mut file = File::open(&cert_path)
        .ok()
        .expect("Failed to open `test/cert.pem`");

    let cert = X509::from_pem(&mut file).ok().expect("Failed to load PEM");
    let subject = cert.subject_name();
    let cn = match subject.text_by_nid(Nid::CN) {
        Some(x) => x,
        None => panic!("Failed to read CN from cert")
    };

    assert_eq!(&cn as &str, "test_cert")
}

#[test]
fn test_nid_values() {
    let cert_path = Path::new("test/nid_test_cert.pem");
    let mut file = File::open(&cert_path)
        .ok()
        .expect("Failed to open `test/nid_test_cert.pem`");

    let cert = X509::from_pem(&mut file).ok().expect("Failed to load PEM");
    let subject = cert.subject_name();

    let cn = match subject.text_by_nid(Nid::CN) {
        Some(x) => x,
        None => panic!("Failed to read CN from cert")
    };
    assert_eq!(&cn as &str, "example.com");

    let email = match subject.text_by_nid(Nid::Email) {
        Some(x) => x,
        None => panic!("Failed to read subject email address from cert")
    };
    assert_eq!(&email as &str, "test@example.com");

    let friendly = match subject.text_by_nid(Nid::FriendlyName) {
        Some(x) => x,
        None => panic!("Failed to read subject friendly name from cert")
    };
    assert_eq!(&friendly as &str, "Example");
}
