use serialize::hex::FromHex;

use crypto::hash::Type::SHA1;
use crypto::pkey::PKey;
use crypto::rsa::RSA;
use x509::{X509, X509Generator};
use x509::extension::Extension::{KeyUsage, ExtKeyUsage, SubjectAltName, OtherNid, OtherStr};
use x509::extension::AltNameOption as SAN;
use x509::extension::KeyUsageOption::{DigitalSignature, KeyEncipherment};
use x509::extension::ExtKeyUsageOption::{self, ClientAuth, ServerAuth};
use nid::Nid;

fn get_generator() -> X509Generator {
    X509Generator::new()
        .set_valid_period(365 * 2)
        .add_name("CN".to_string(), "test_me".to_string())
        .set_sign_hash(SHA1)
        .add_extension(KeyUsage(vec![DigitalSignature, KeyEncipherment]))
        .add_extension(ExtKeyUsage(vec![ClientAuth,
                                        ServerAuth,
                                        ExtKeyUsageOption::Other("2.999.1".to_owned())]))
        .add_extension(SubjectAltName(vec![(SAN::DNS, "example.com".to_owned())]))
        .add_extension(OtherNid(Nid::BasicConstraints, "critical,CA:TRUE".to_owned()))
        .add_extension(OtherStr("2.999.2".to_owned(), "ASN1:UTF8:example value".to_owned()))
}

fn pkey() -> PKey {
    let rsa = RSA::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_cert_gen() {
    let pkey = pkey();
    let cert = get_generator().sign(&pkey).unwrap();

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters

    assert_eq!(pkey.public_key_to_pem().unwrap(),
               cert.public_key().unwrap().public_key_to_pem().unwrap());
}

/// SubjectKeyIdentifier must be added before AuthorityKeyIdentifier or OpenSSL
/// is "unable to get issuer keyid." This test ensures the order of insertion
/// for extensions is preserved when the cert is signed.
#[test]
fn test_cert_gen_extension_ordering() {
    let pkey = pkey();
    get_generator()
        .add_extension(OtherNid(Nid::SubjectKeyIdentifier, "hash".to_owned()))
        .add_extension(OtherNid(Nid::AuthorityKeyIdentifier, "keyid:always".to_owned()))
        .sign(&pkey)
        .expect("Failed to generate cert with order-dependent extensions");
}

/// Proves that a passing result from `test_cert_gen_extension_ordering` is
/// deterministic by reversing the order of extensions and asserting failure.
#[test]
fn test_cert_gen_extension_bad_ordering() {
    let pkey = pkey();
    let result = get_generator()
                     .add_extension(OtherNid(Nid::AuthorityKeyIdentifier,
                                             "keyid:always".to_owned()))
                     .add_extension(OtherNid(Nid::SubjectKeyIdentifier, "hash".to_owned()))
                     .sign(&pkey);

    assert!(result.is_err());
}

#[test]
fn test_req_gen() {
    let pkey = pkey();

    let req = get_generator().request(&pkey).unwrap();
    req.to_pem().unwrap();

    // FIXME: check data in result to be correct, needs implementation
    // of X509_REQ getters
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let fingerprint = cert.fingerprint(SHA1).unwrap();

    let hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let hash_vec = hash_str.from_hex().unwrap();

    assert_eq!(fingerprint, hash_vec);
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 14 17:00:03 2016 GMT");
    assert_eq!(not_after, "Aug 12 17:00:03 2026 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let subject = cert.subject_name();
    let cn = match subject.text_by_nid(Nid::CN) {
        Some(x) => x,
        None => panic!("Failed to read CN from cert"),
    };

    assert_eq!(&cn as &str, "foobar.com")
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
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
    let cert = include_bytes!("../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let subject = cert.subject_name();

    let cn = match subject.text_by_nid(Nid::UserId) {
        Some(x) => x,
        None => panic!("Failed to read UID from cert"),
    };
    assert_eq!(&cn as &str, "this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(3, subject_alt_names.len());
    assert_eq!(Some("foobar.com"), subject_alt_names.get(0).dnsname());
    assert_eq!(subject_alt_names.get(1).ipaddress(),
               Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names.get(2).ipaddress(),
               Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(subject_alt_names_iter.next().unwrap().dnsname(),
               Some("foobar.com"));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipaddress(),
               Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipaddress(),
               Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
    assert!(subject_alt_names_iter.next().is_none());
}
