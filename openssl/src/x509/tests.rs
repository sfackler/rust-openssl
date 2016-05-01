use serialize::hex::FromHex;
use std::io;
use std::path::Path;
use std::fs::File;

use crypto::hash::Type::SHA256;
use crypto::pkey::PKey;
use x509::{X509, X509Generator};
use x509::extension::Extension::{KeyUsage, ExtKeyUsage, SubjectAltName, OtherNid, OtherStr};
use x509::extension::AltNameOption as SAN;
use x509::extension::KeyUsageOption::{DigitalSignature, KeyEncipherment};
use x509::extension::ExtKeyUsageOption::{self, ClientAuth, ServerAuth};
use nid::Nid;

fn get_generator() -> X509Generator {
    X509Generator::new()
        .set_bitlength(2048)
        .set_valid_period(365 * 2)
        .add_name("CN".to_string(), "test_me".to_string())
        .set_sign_hash(SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature, KeyEncipherment]))
        .add_extension(ExtKeyUsage(vec![ClientAuth,
                                        ServerAuth,
                                        ExtKeyUsageOption::Other("2.999.1".to_owned())]))
        .add_extension(SubjectAltName(vec![(SAN::DNS, "example.com".to_owned())]))
        .add_extension(OtherNid(Nid::BasicConstraints, "critical,CA:TRUE".to_owned()))
        .add_extension(OtherStr("2.999.2".to_owned(), "ASN1:UTF8:example value".to_owned()))
}

#[test]
fn test_cert_gen() {
    let (cert, pkey) = get_generator().generate().unwrap();
    cert.write_pem(&mut io::sink()).unwrap();
    pkey.write_pem(&mut io::sink()).unwrap();

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters

    assert_eq!(pkey.save_pub(), cert.public_key().save_pub());
}

/// SubjectKeyIdentifier must be added before AuthorityKeyIdentifier or OpenSSL
/// is "unable to get issuer keyid." This test ensures the order of insertion
/// for extensions is preserved when the cert is signed.
#[test]
fn test_cert_gen_extension_ordering() {
    get_generator()
        .add_extension(OtherNid(Nid::SubjectKeyIdentifier, "hash".to_owned()))
        .add_extension(OtherNid(Nid::AuthorityKeyIdentifier, "keyid:always".to_owned()))
        .generate()
        .expect("Failed to generate cert with order-dependent extensions");
}

/// Proves that a passing result from `test_cert_gen_extension_ordering` is
/// deterministic by reversing the order of extensions and asserting failure.
#[test]
fn test_cert_gen_extension_bad_ordering() {
    let result = get_generator()
        .add_extension(OtherNid(Nid::AuthorityKeyIdentifier, "keyid:always".to_owned()))
        .add_extension(OtherNid(Nid::SubjectKeyIdentifier, "hash".to_owned()))
        .generate();

    assert!(result.is_err());
}

#[test]
fn test_req_gen() {
    let mut pkey = PKey::new();
    pkey.gen(512);

    let req = get_generator().request(&pkey).unwrap();
    req.write_pem(&mut io::sink()).unwrap();

    // FIXME: check data in result to be correct, needs implementation
    // of X509_REQ getters
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
        None => panic!("Failed to read CN from cert"),
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
        None => panic!("Failed to read CN from cert"),
    };
    assert_eq!(&cn as &str, "example.com");

    let email = match subject.text_by_nid(Nid::Email) {
        Some(x) => x,
        None => panic!("Failed to read subject email address from cert"),
    };
    assert_eq!(&email as &str, "test@example.com");

    let friendly = match subject.text_by_nid(Nid::FriendlyName) {
        Some(x) => x,
        None => panic!("Failed to read subject friendly name from cert"),
    };
    assert_eq!(&friendly as &str, "Example");
}

#[test]
fn test_nid_uid_value() {
    let cert_path = Path::new("test/nid_uid_test_cert.pem");
    let mut file = File::open(&cert_path)
                       .ok()
                       .expect("Failed to open `test/nid_uid_test_cert.pem`");

    let cert = X509::from_pem(&mut file).ok().expect("Failed to load PEM");
    let subject = cert.subject_name();

    let cn = match subject.text_by_nid(Nid::UserId) {
        Some(x) => x,
        None => panic!("Failed to read UID from cert"),
    };
    assert_eq!(&cn as &str, "this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let mut file = File::open("test/alt_name_cert.pem").unwrap();
    let cert = X509::from_pem(&mut file).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(3, subject_alt_names.len());
    assert_eq!(Some("foobar.com"), subject_alt_names.get(0).dns());
    assert_eq!(subject_alt_names.get(1).ipadd(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names.get(2).ipadd(), Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
}

#[test]
fn test_subject_alt_name_iter() {
    let mut file = File::open("test/alt_name_cert.pem").unwrap();
    let cert = X509::from_pem(&mut file).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(subject_alt_names_iter.next().unwrap().dns(), Some("foobar.com"));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipadd(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipadd(), Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
    assert!(subject_alt_names_iter.next().is_none());
}
