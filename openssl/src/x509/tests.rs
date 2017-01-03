use hex::{FromHex, ToHex};

use hash::MessageDigest;
use pkey::PKey;
use rsa::Rsa;
use x509::{X509, X509Generator};
use x509::extension::Extension::{KeyUsage, ExtKeyUsage, SubjectAltName, OtherNid, OtherStr};
use x509::extension::AltNameOption as SAN;
use x509::extension::KeyUsageOption::{DigitalSignature, KeyEncipherment};
use x509::extension::ExtKeyUsageOption::{self, ClientAuth, ServerAuth};
use nid;

fn get_generator() -> X509Generator {
    X509Generator::new()
        .set_valid_period(365 * 2)
        .add_name("CN".to_string(), "test_me".to_string())
        .set_sign_hash(MessageDigest::sha1())
        .add_extension(KeyUsage(vec![DigitalSignature, KeyEncipherment]))
        .add_extension(ExtKeyUsage(vec![ClientAuth,
                                        ServerAuth,
                                        ExtKeyUsageOption::Other("2.999.1".to_owned())]))
        .add_extension(SubjectAltName(vec![(SAN::DNS, "example.com".to_owned())]))
        .add_extension(OtherNid(nid::BASIC_CONSTRAINTS, "critical,CA:TRUE".to_owned()))
        .add_extension(OtherStr("2.999.2".to_owned(), "ASN1:UTF8:example value".to_owned()))
}

fn pkey() -> PKey {
    let rsa = Rsa::generate(2048).unwrap();
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
        .add_extension(OtherNid(nid::SUBJECT_KEY_IDENTIFIER, "hash".to_owned()))
        .add_extension(OtherNid(nid::AUTHORITY_KEY_IDENTIFIER, "keyid:always".to_owned()))
        .sign(&pkey)
        .expect("Failed to generate cert with order-dependent extensions");
}

/// Proves that a passing result from `test_cert_gen_extension_ordering` is
/// deterministic by reversing the order of extensions and asserting failure.
#[test]
fn test_cert_gen_extension_bad_ordering() {
    let pkey = pkey();
    let result = get_generator()
        .add_extension(OtherNid(nid::AUTHORITY_KEY_IDENTIFIER, "keyid:always".to_owned()))
        .add_extension(OtherNid(nid::SUBJECT_KEY_IDENTIFIER, "hash".to_owned()))
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
    let fingerprint = cert.fingerprint(MessageDigest::sha1()).unwrap();

    let hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let hash_vec = Vec::from_hex(hash_str).unwrap();

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
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com")
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject.entries_by_nid(nid::PKCS9_EMAILADDRESS).next().unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(&*friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(3, subject_alt_names.len());
    assert_eq!(Some("foobar.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(),
               Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names[2].ipaddress(),
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

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
        "59172d9313e84459bcff27f967e79e6e9217e584");
    assert_eq!(certs[1].fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
        "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875");
}
